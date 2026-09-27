package dev.vigil.inspector.vpn

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import dev.vigil.inspector.R
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.engine.EngineConfig
import dev.vigil.inspector.engine.EngineHandle
import dev.vigil.inspector.engine.EngineJson
import dev.vigil.inspector.engine.FeedSummary
import dev.vigil.inspector.engine.PlatformBridge
import dev.vigil.inspector.engine.VigilNative
import dev.vigil.inspector.processing.AlertNotifier
import dev.vigil.inspector.processing.EventProcessor
import dev.vigil.inspector.ui.MainActivity
import dev.vigil.inspector.ui.formatCount
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The local-loopback VPN. It owns the TUN interface and the native engine
 * for one "session" (from establish() to teardown) and wires engine events
 * into the rest of the app.
 *
 * vigil excludes itself from its own VPN (`addDisallowedApplication`), so the
 * engine's relay sockets, feed downloads and SIEM export all use the
 * underlying network directly; `protect()` is additionally applied to every
 * relay socket as a second guard against routing loops.
 */
class VigilVpnService : android.net.VpnService() {
    private val app get() = application as VigilApp
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lifecycle = Mutex()
    private var tun: ParcelFileDescriptor? = null
    private var engine: EngineHandle? = null
    private var sessionJob: Job? = null
    private var sessionExcludeLan: Boolean? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            scope.launch {
                stopSession()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            return START_NOT_STICKY
        }
        // ACTION_START, or null / SERVICE_INTERFACE when started as always-on VPN.
        goForeground(buildNotification(null))
        scope.launch { startSession() }
        return START_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over, or the user revoked consent.
        scope.launch {
            stopSession()
            ServiceState.status.value = VpnStatus.Stopped
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onDestroy() {
        scope.launch(NonCancellable) {
            stopSession()
            scope.cancel()
        }
        super.onDestroy()
    }

    private suspend fun startSession() = lifecycle.withLock {
        if (engine != null) return@withLock
        if (prepare(this) != null) {
            fail("VPN permission required. Open vigil to grant it.")
            return@withLock
        }
        ServiceState.status.value = VpnStatus.Starting
        val settings = app.settings.value
        val builder = Builder()
            .setSession("vigil")
            .setMtu(EngineConfig.MTU)
            .setBlocking(false)
            .addAddress(EngineConfig.TUN_V4, 24)
            .addAddress(EngineConfig.TUN_V6, 64)
            .addDnsServer(EngineConfig.VIRTUAL_DNS_V4)
            .addDnsServer(EngineConfig.VIRTUAL_DNS_V6)
            .setMetered(false)
            .setUnderlyingNetworks(null)
            .setConfigureIntent(
                PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE),
            )
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "could not exclude self from VPN; relying on protect()", e)
        }
        VpnRoutes.ipv4(settings.excludeLan).forEach { builder.addRoute(it.address, it.prefix) }
        VpnRoutes.ipv6(settings.excludeLan).forEach { builder.addRoute(it.address, it.prefix) }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish failed", e)
            null
        }
        if (pfd == null) {
            fail("Could not create the VPN interface.")
            return@withLock
        }
        val session = System.currentTimeMillis()
        val networkDns = refreshNetworkInfo()
        val config = ConfigFactory.build(settings, networkDns, app.apps.uidsFor(settings.blockedPackages))
        val handle = VigilNative.nativeStart(pfd.fd, config.toJson(), PlatformBridge(this, connectivity))
        if (handle == 0L) {
            pfd.close()
            fail("The inspection engine failed to start.")
            return@withLock
        }
        val eng = EngineHandle(handle)
        tun = pfd
        engine = eng
        sessionExcludeLan = settings.excludeLan
        ServiceState.loadedFeeds.value = emptyMap()
        app.db.flows().closeStale(session)

        val processor = EventProcessor(app.db, app.apps, app.settings, app.foreground, app.exporter, app.notifier, session)
        sessionJob = scope.launch {
            launch { pump(eng, processor) }
            launch { syncFeeds(eng) }
            launch { applyConfigChanges(eng) }
            launch { updateNotification() }
        }
        registerNetworkCallback()
        ServiceState.status.value = VpnStatus.Running(session)
        Log.i(TAG, "session $session started (engine ${VigilNative.nativeVersion()})")
    }

    private suspend fun stopSession() = lifecycle.withLock {
        sessionJob?.cancelAndJoin()
        sessionJob = null
        networkCallback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        networkCallback = null
        engine?.close()
        engine = null
        runCatching { tun?.close() }
        tun = null
        ServiceState.stats.value = null
        ServiceState.loadedFeeds.value = emptyMap()
        if (ServiceState.status.value !is VpnStatus.Failed) ServiceState.status.value = VpnStatus.Stopped
    }

    private fun fail(message: String) {
        Log.e(TAG, message)
        ServiceState.status.value = VpnStatus.Failed(message)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private suspend fun pump(eng: EngineHandle, processor: EventProcessor) {
        val ctx = kotlin.coroutines.coroutineContext
        while (ctx.isActive && eng.isOpen) {
            val json = eng.use { VigilNative.nativePollEvents(it, 512, 500) } ?: continue
            try {
                processor.process(json)
            } catch (e: Exception) {
                Log.e(TAG, "event processing failed", e)
            }
        }
    }

    /** Keeps the engine's loaded feeds in sync with the enabled feed set. */
    private suspend fun syncFeeds(eng: EngineHandle) {
        app.feeds.feeds.collect { feeds ->
            val wanted = feeds.filter { it.enabled && app.feeds.fileFor(it.id).exists() }.associateBy { it.id }
            val loaded = ServiceState.loadedFeeds.value.toMutableMap()
            for (id in loaded.keys - wanted.keys) {
                eng.use { VigilNative.nativeRemoveFeed(it, id) }
                loaded.remove(id)
            }
            for ((id, feed) in wanted) {
                val version = feed.lastUpdated ?: 0L
                if (loaded[id] == version) continue
                val summary = eng.use { VigilNative.nativeLoadFeedFile(it, id, feed.category, app.feeds.fileFor(id).absolutePath) }
                if (summary != null) {
                    val s = EngineJson.json.decodeFromString(FeedSummary.serializer(), summary)
                    Log.i(TAG, "feed $id: ${s.domains} domains, ${s.ipRanges} ranges")
                    loaded[id] = version
                }
            }
            ServiceState.loadedFeeds.value = loaded
        }
    }

    @OptIn(FlowPreview::class)
    private suspend fun applyConfigChanges(eng: EngineHandle) {
        combine(app.settings.flow, ServiceState.network) { s, net -> s to net }
            .debounce(300)
            .map { (s, net) -> Triple(s.excludeLan, ConfigFactory.build(s, net.upstreamDns, app.apps.uidsFor(s.blockedPackages)), s) }
            .distinctUntilChanged()
            .drop(1)
            .collect { (excludeLan, config, _) ->
                if (excludeLan != sessionExcludeLan) {
                    // Routes can only change by re-establishing the interface.
                    scope.launch { restart() }
                } else {
                    eng.use { VigilNative.nativeUpdateConfig(it, config.toJson()) }
                }
            }
    }

    private suspend fun restart() {
        stopSession()
        startSession()
    }

    private suspend fun updateNotification() {
        val nm = getSystemService(android.app.NotificationManager::class.java)
        while (true) {
            delay(15_000)
            nm.notify(NOTIFICATION_ID, buildNotification(ServiceState.stats.value))
        }
    }

    private fun refreshNetworkInfo(network: Network? = connectivity.activeNetwork, lp: LinkProperties? = null): List<String> {
        val props = lp ?: network?.let { connectivity.getLinkProperties(it) }
        val virtual = setOf(EngineConfig.VIRTUAL_DNS_V4, EngineConfig.VIRTUAL_DNS_V6)
        val dns = props?.dnsServers.orEmpty()
            .filter { !it.isLoopbackAddress && !it.isAnyLocalAddress && it.hostAddress !in virtual }
            .mapNotNull(ConfigFactory::formatResolver)
        ServiceState.network.value = NetworkInfo(
            upstreamDns = dns,
            privateDnsStrictHost = props?.privateDnsServerName,
            privateDnsActive = props?.isPrivateDnsActive == true,
        )
        return dns
    }

    private fun registerNetworkCallback() {
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                refreshNetworkInfo(network, linkProperties)
            }
        }
        // vigil is excluded from its own VPN, so its default network is the
        // underlying Wi-Fi/cellular network.
        runCatching { connectivity.registerDefaultNetworkCallback(cb) }.onSuccess { networkCallback = cb }
    }

    private fun buildNotification(stats: dev.vigil.inspector.engine.StatsEvent?): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(
            this, 1, Intent(this, VigilVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        val text = stats?.let {
            "${formatCount(it.flowsTotal)} connections · ${formatCount(it.blocked)} blocked · ${formatCount(it.dnsQueries)} lookups"
        } ?: "Inspecting device traffic on-device"
        return NotificationCompat.Builder(this, AlertNotifier.CHANNEL_SERVICE)
            .setSmallIcon(R.drawable.ic_stat_vigil)
            .setContentTitle("vigil is inspecting traffic")
            .setContentText(text)
            .setContentIntent(open)
            .addAction(0, "Stop", stop)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun goForeground(n: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }

    companion object {
        private const val TAG = "vigil.vpn"
        private const val NOTIFICATION_ID = 1
        const val ACTION_START = "dev.vigil.inspector.START"
        const val ACTION_STOP = "dev.vigil.inspector.STOP"

        /** Caller must have obtained VPN consent via [android.net.VpnService.prepare]. */
        fun start(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, VigilVpnService::class.java).setAction(ACTION_START))
        }

        fun stop(context: Context) {
            context.startService(Intent(context, VigilVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}
