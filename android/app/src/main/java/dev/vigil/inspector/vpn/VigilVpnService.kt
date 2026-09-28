package dev.vigil.inspector.vpn

import android.Manifest
import android.app.Notification
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import dev.vigil.inspector.BuildConfig
import dev.vigil.inspector.R
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.data.Settings
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.coroutineContext

/**
 * The local-loopback VPN. It owns the TUN interface and the native engine
 * for one "session" (from establish() to teardown) and wires engine events
 * into the rest of the app.
 *
 * Every lifecycle change (start, stop, revoke, restart, engine error, crash,
 * destroy) is a [Command] handled in order by one coroutine, so they can
 * never interleave, and `stopSelf(startId)` only stops the service when no
 * newer start request is pending.
 *
 * vigil excludes itself from its own VPN (`addDisallowedApplication`), so the
 * engine's relay sockets, feed downloads and SIEM export all use the
 * underlying network directly; `protect()` is additionally applied to every
 * relay socket as a second guard against routing loops.
 */
class VigilVpnService : android.net.VpnService() {
    private val app get() = application as VigilApp
    private val commands = Channel<Command>(Channel.UNLIMITED)
    private val crashHandler = CoroutineExceptionHandler { _, e ->
        Log.e(TAG, "uncaught error in the service", e)
        commands.trySend(Command.Crash(e.message ?: e.javaClass.simpleName))
    }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + crashHandler)
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    private val notifications by lazy { getSystemService(android.app.NotificationManager::class.java) }

    // Owned by the command loop.
    private var current: Session? = null
    private var handledStartId = 0
    private val restarts = RestartBudget()

    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var packageReceiver: BroadcastReceiver? = null
    /** Bumped when packages are installed/removed, so blocked UIDs are recomputed. */
    private val packagesChanged = MutableStateFlow(0)

    private sealed interface Command {
        data class Start(val startId: Int) : Command
        data class Stop(val startId: Int) : Command
        data object Revoke : Command
        data class Restart(val sessionId: Long, val reason: String) : Command
        data class EngineError(val sessionId: Long, val message: String) : Command
        data class Crash(val message: String) : Command
        data object Destroy : Command

        /** Debug builds only: simulates an engine error in the current session. */
        data object InjectEngineError : Command
    }

    private class Session(
        val id: Long,
        val tun: ParcelFileDescriptor,
        val engine: EngineHandle,
        val processor: EventProcessor,
        val excludeLan: Boolean,
        /** App excluded from the VPN as the SOCKS5 proxy (e.g. Orbot). */
        val excludedPackage: String?,
        /** The configuration the engine currently runs with. */
        @Volatile var applied: EngineConfig,
    ) {
        @Volatile var draining = false
        var pump: Job? = null
        var side: Job? = null
    }

    override fun onCreate() {
        super.onCreate()
        scope.launch { commandLoop() }
        registerNetworkCallback()
        registerPackageReceiver()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            commands.trySend(Command.Stop(startId))
            return START_NOT_STICKY
        }
        if (BuildConfig.DEBUG && intent?.action == ACTION_INJECT_ENGINE_ERROR) {
            // Test hook for scripts/android-lifecycle.sh; not compiled into release logic.
            commands.trySend(Command.InjectEngineError)
            return START_NOT_STICKY
        }
        // ACTION_START, or null / SERVICE_INTERFACE when started as always-on VPN.
        if (!goForeground(buildNotification(null))) {
            ServiceState.status.value = VpnStatus.Failed("Android did not allow vigil to start in the background. Open vigil to start it.")
            stopSelf(startId)
            return START_NOT_STICKY
        }
        commands.trySend(Command.Start(startId))
        return START_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over, or the user revoked consent.
        commands.trySend(Command.Revoke)
    }

    override fun onDestroy() {
        networkCallback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        networkCallback = null
        packageReceiver?.let { runCatching { unregisterReceiver(it) } }
        packageReceiver = null
        commands.trySend(Command.Destroy)
        super.onDestroy()
    }

    private suspend fun commandLoop() {
        for (cmd in commands) {
            try {
                handle(cmd)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "command $cmd failed", e)
                if (cmd != Command.Destroy) {
                    runCatching { handle(Command.Crash(e.message ?: e.javaClass.simpleName)) }.onFailure { Log.e(TAG, "recovery failed", it) }
                }
            }
            if (cmd == Command.Destroy) break
        }
        scope.cancel()
    }

    private suspend fun handle(cmd: Command) {
        when (cmd) {
            is Command.Start -> {
                handledStartId = cmd.startId
                restarts.reset()
                val s = current
                when {
                    s == null -> startFresh()
                    ServiceState.status.value == VpnStatus.Running(s.id) && s.engine.isOpen -> Unit // already healthy
                    else -> restart("start requested while not healthy")
                }
            }
            is Command.Stop -> {
                handledStartId = cmd.startId
                val s = current
                current = null
                s?.let { teardown(it) }
                markStopped(s, explicit = true)
                stopServiceFor(cmd.startId)
            }
            Command.Revoke -> {
                val s = current
                current = null
                s?.let { teardown(it) }
                markStopped(s, explicit = true)
                stopServiceFor(handledStartId)
            }
            is Command.Restart -> if (current?.id == cmd.sessionId) restart(cmd.reason)
            is Command.EngineError -> {
                if (current?.id != cmd.sessionId) return
                val backoff = restarts.onFailure(System.currentTimeMillis())
                if (backoff == null) {
                    giveUp("The inspection engine failed repeatedly (${cmd.message}). Inspection was stopped; open vigil to start it again.")
                } else {
                    Log.w(TAG, "engine error in session ${cmd.sessionId}: ${cmd.message}; restarting in $backoff ms")
                    ServiceState.status.value = VpnStatus.Starting
                    delay(backoff)
                    if (current?.id == cmd.sessionId) restart("engine error: ${cmd.message}")
                }
            }
            Command.InjectEngineError -> current?.let { handle(Command.EngineError(it.id, "injected by test")) }
            is Command.Crash -> giveUp("vigil hit an internal error (${cmd.message}). Inspection was stopped; open vigil to start it again.")
            Command.Destroy -> {
                val s = current
                current = null
                if (s != null) {
                    teardown(s)
                    markStopped(s, explicit = false)
                }
            }
        }
    }

    private suspend fun startFresh() {
        ServiceState.status.value = VpnStatus.Starting
        val new = createSession(previousId = null).getOrElse {
            fail(it.message ?: "Could not start inspection.")
            return
        }
        app.db.flows().closeStale(new.id)
        activate(new)
    }

    /**
     * Replaces the running session. The new interface is established and the
     * new engine started before the old ones are shut down, so traffic never
     * leaks around the VPN in between. The old engine's final events are still
     * processed (and exported) under the old session id.
     */
    private suspend fun restart(reason: String) {
        Log.i(TAG, "restarting: $reason")
        val old = current
        val new = createSession(previousId = old?.id).getOrElse {
            current = null
            old?.let { o -> teardown(o) }
            fail(it.message ?: "Could not restart inspection.")
            return
        }
        old?.side?.cancelAndJoin()
        activate(new)
        if (old != null) teardown(old)
        app.db.flows().closeStale(new.id)
    }

    private fun activate(s: Session) {
        current = s
        ServiceState.loadedFeeds.value = emptyMap()
        ServiceState.configError.value = null
        s.pump = scope.launch { pump(s) }
        s.side = scope.launch {
            launch { syncFeeds(s) }
            launch { applyConfigChanges(s) }
            launch { updateNotification() }
        }
        ServiceState.status.value = VpnStatus.Running(s.id)
        Log.i(TAG, "session ${s.id} started (engine ${VigilNative.nativeVersion()})")
    }

    private fun createSession(previousId: Long?): Result<Session> {
        if (prepare(this) != null) return Result.failure(IllegalStateException("VPN permission required. Open vigil to grant it."))
        val settings = app.settings.value
        val net = refreshNetworkInfo()
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
        // A proxy app (e.g. Orbot) must reach the internet itself, not loop
        // back through vigil into its own proxy.
        val excluded = settings.upstream.excludedPackage
        excluded?.let { pkg ->
            try {
                builder.addDisallowedApplication(pkg)
            } catch (e: Exception) {
                Log.w(TAG, "could not exclude proxy app $pkg from the VPN", e)
            }
        }
        VpnRoutes.ipv4(settings.excludeLan).forEach { builder.addRoute(it.address, it.prefix) }
        VpnRoutes.ipv6(settings.excludeLan, net.nat64Prefixes).forEach { builder.addRoute(it.address, it.prefix) }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish failed", e)
            null
        } ?: return Result.failure(IllegalStateException("Could not create the VPN interface."))

        // Ids are start times; keep them strictly increasing across quick restarts.
        val id = maxOf(System.currentTimeMillis(), (previousId ?: 0L) + 1)
        val config = buildConfig(settings, net)
        val handle = VigilNative.nativeStart(pfd.fd, config.toJson(), PlatformBridge(this, connectivity))
        if (handle == 0L) {
            runCatching { pfd.close() }
            return Result.failure(IllegalStateException("The inspection engine failed to start (configuration rejected?)."))
        }
        val processor = EventProcessor(app.db, app.apps, app.settings, app.foreground, app.exporter, app.notifier, id) { message ->
            commands.trySend(Command.EngineError(id, message))
        }
        return Result.success(Session(id, pfd, EngineHandle(handle), processor, settings.excludeLan, excluded, config))
    }

    /**
     * Shuts a session down: stops the engine (which queues `flow_end` for all
     * open flows), lets the pump drain and process those final events, then
     * frees the engine and closes the interface.
     */
    private suspend fun teardown(s: Session) = withContext(NonCancellable) {
        s.side?.cancelAndJoin()
        val graceful = s.engine.shutdown()
        s.draining = true
        val pump = s.pump
        if (pump != null && withTimeoutOrNull(if (graceful) DRAIN_TIMEOUT_MS else 1_000L) { pump.join() } == null) {
            Log.w(TAG, "session ${s.id}: event drain timed out")
            pump.cancelAndJoin()
        }
        runCatching { s.processor.finishSession() }.onFailure { Log.w(TAG, "finishing session ${s.id} failed", it) }
        s.engine.close()
        runCatching { s.tun.close() }
        Log.i(TAG, "session ${s.id} stopped")
    }

    /**
     * Writes Stopped only if this instance actually owned the visible state,
     * so the late onDestroy of an old instance cannot overwrite a newer
     * session's Running.
     */
    private fun markStopped(tornDown: Session?, explicit: Boolean) {
        val st = ServiceState.status.value
        val mine = tornDown != null && (st == VpnStatus.Running(tornDown.id) || st == VpnStatus.Starting)
        if (mine || (explicit && st !is VpnStatus.Running)) ServiceState.status.value = VpnStatus.Stopped
        if (mine || explicit) {
            ServiceState.stats.value = null
            ServiceState.loadedFeeds.value = emptyMap()
        }
    }

    private suspend fun giveUp(message: String) {
        val s = current
        current = null
        s?.let { teardown(it) }
        ServiceState.stats.value = null
        ServiceState.loadedFeeds.value = emptyMap()
        postProblem(NOTIFICATION_FAILED_ID, "vigil stopped inspecting", message, AlertNotifier.CHANNEL_ALERTS)
        fail(message)
    }

    private fun fail(message: String) {
        Log.e(TAG, message)
        ServiceState.status.value = VpnStatus.Failed(message)
        stopServiceFor(handledStartId)
    }

    private fun stopServiceFor(startId: Int) {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf(startId)
    }

    private suspend fun pump(s: Session) {
        while (true) {
            coroutineContext.ensureActive()
            if (s.draining) {
                drain(s)
                return
            }
            val json = s.engine.use { VigilNative.nativePollEvents(it, 512, 500) }
            if (json == null) {
                if (!s.engine.isOpen) return
                continue
            }
            processSafely(s, json)
        }
    }

    /** After shutdown: processes what is left in the engine's queue. */
    private suspend fun drain(s: Session) {
        repeat(MAX_DRAIN_BATCHES) {
            val json = s.engine.use { VigilNative.nativePollEvents(it, 512, 0) } ?: return
            val batch = EngineJson.parseBatch(json)
            if (batch.isEmpty()) return
            try {
                s.processor.process(batch)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "event processing failed", e)
            }
        }
    }

    private suspend fun processSafely(s: Session, json: String) {
        try {
            s.processor.process(json)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "event processing failed", e)
        }
    }

    /** Keeps the engine's loaded feeds in sync with the enabled feed set. */
    private suspend fun syncFeeds(s: Session) {
        val loaded = mutableMapOf<String, Long>()
        app.feeds.feeds.collect { feeds ->
            val wanted = feeds.filter { it.enabled && app.feeds.fileFor(it.id).exists() }.associateBy { it.id }
            for (id in loaded.keys - wanted.keys) {
                s.engine.use { VigilNative.nativeRemoveFeed(it, id) }
                loaded.remove(id)
            }
            for ((id, feed) in wanted) {
                val version = feed.lastUpdated ?: 0L
                if (loaded[id] == version) continue
                val summary = s.engine.use { VigilNative.nativeLoadFeedFile(it, id, feed.category, app.feeds.fileFor(id).absolutePath) }
                if (summary != null) {
                    val fs = EngineJson.json.decodeFromString(FeedSummary.serializer(), summary)
                    Log.i(TAG, "feed $id: ${fs.domains} domains, ${fs.ipRanges} ranges")
                    loaded[id] = version
                }
            }
            ServiceState.loadedFeeds.value = loaded.toMap()
        }
    }

    private fun buildConfig(s: Settings, net: NetworkInfo): EngineConfig =
        ConfigFactory.build(s, net.upstreamDns, app.apps.uidsFor(s.blockedPackages), net.nat64Prefixes, net.networkId)

    /**
     * Pushes engine-relevant setting, network and package changes into the
     * running engine. Compared against the config the engine actually runs
     * with (not the first emission), so no change is lost; settings that do
     * not affect the engine (export, retention...) produce an equal config
     * and are ignored.
     */
    @OptIn(FlowPreview::class)
    private suspend fun applyConfigChanges(s: Session) {
        combine(app.settings.flow, ServiceState.network, packagesChanged) { st, net, _ -> st to net }
            .debounce(300)
            .map { (st, net) -> Triple(st.excludeLan, st.upstream.excludedPackage, buildConfig(st, net)) }
            .distinctUntilChanged()
            .collect { (excludeLan, excludedPackage, config) ->
                if (excludeLan != s.excludeLan || excludedPackage != s.excludedPackage) {
                    // Routes and excluded apps can only change by
                    // re-establishing the interface.
                    commands.trySend(Command.Restart(s.id, "VPN routes or excluded apps changed"))
                    return@collect
                }
                // The upstream path (direct/WireGuard/SOCKS5) changes in place:
                // the engine rebuilds its dialer; open connections keep theirs.
                if (config == s.applied) return@collect
                val ok = s.engine.use { VigilNative.nativeUpdateConfig(it, config.toJson()) } ?: return@collect
                if (ok) {
                    s.applied = config
                    ServiceState.configError.value = null
                    notifications.cancel(NOTIFICATION_CONFIG_ID)
                } else {
                    val msg = "The engine rejected the new settings; the previous settings stay active."
                    Log.e(TAG, "$msg ${config.toLogJson()}")
                    ServiceState.configError.value = msg
                    postProblem(NOTIFICATION_CONFIG_ID, "Settings not applied", msg, AlertNotifier.CHANNEL_SERVICE)
                }
            }
    }

    private suspend fun updateNotification() {
        while (true) {
            delay(15_000)
            notifications.notify(NOTIFICATION_ID, buildNotification(ServiceState.stats.value))
        }
    }

    private fun refreshNetworkInfo(network: Network? = connectivity.activeNetwork, lp: LinkProperties? = null): NetworkInfo {
        val props = lp ?: network?.let { connectivity.getLinkProperties(it) }
        val virtual = setOf(EngineConfig.VIRTUAL_DNS_V4, EngineConfig.VIRTUAL_DNS_V6)
        val dns = props?.dnsServers.orEmpty()
            .filter { !it.isLoopbackAddress && !it.isAnyLocalAddress && it.hostAddress.orEmpty() !in virtual }
            .mapNotNull(ConfigFactory::formatResolver)
        val nat64 = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            listOfNotNull(props?.nat64Prefix?.let { "${it.address.hostAddress}/${it.prefixLength}" })
        } else {
            emptyList()
        }
        val info = NetworkInfo(
            upstreamDns = dns,
            privateDnsStrictHost = props?.privateDnsServerName,
            privateDnsActive = props?.isPrivateDnsActive == true,
            nat64Prefixes = nat64,
            networkId = network?.networkHandle?.toString().orEmpty(),
        )
        ServiceState.network.value = info
        return info
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

    /** Installs and removals change UID ↔ app mapping and the blocked UID list. */
    private fun registerPackageReceiver() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                app.apps.invalidate()
                packagesChanged.update { it + 1 }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        // System broadcasts are delivered to non-exported receivers too.
        ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        packageReceiver = receiver
    }

    private fun postProblem(id: Int, title: String, text: String, channel: String) {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val n = NotificationCompat.Builder(this, channel)
            .setSmallIcon(R.drawable.ic_stat_vigil)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .build()
        notifications.notify(id, n)
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

    /** False if Android refused (e.g. ForegroundServiceStartNotAllowedException on API 31+). */
    private fun goForeground(n: Notification): Boolean = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
        true
    } catch (e: IllegalStateException) {
        // ForegroundServiceStartNotAllowedException extends IllegalStateException.
        Log.e(TAG, "startForeground refused", e)
        false
    } catch (e: SecurityException) {
        Log.e(TAG, "startForeground refused", e)
        false
    }

    companion object {
        private const val TAG = "vigil.vpn"
        private const val NOTIFICATION_ID = 1
        private const val NOTIFICATION_FAILED_ID = 2
        private const val NOTIFICATION_CONFIG_ID = 3
        private const val DRAIN_TIMEOUT_MS = 5_000L
        private const val MAX_DRAIN_BATCHES = 200
        const val ACTION_START = "dev.vigil.inspector.START"
        const val ACTION_STOP = "dev.vigil.inspector.STOP"
        const val ACTION_INJECT_ENGINE_ERROR = "dev.vigil.inspector.INJECT_ENGINE_ERROR"

        /** Caller must have obtained VPN consent via [android.net.VpnService.prepare]. */
        fun start(context: Context) {
            ContextCompat.startForegroundService(context, Intent(context, VigilVpnService::class.java).setAction(ACTION_START))
        }

        fun stop(context: Context) {
            context.startService(Intent(context, VigilVpnService::class.java).setAction(ACTION_STOP))
        }
    }
}
