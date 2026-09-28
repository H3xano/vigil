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
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import dev.vigil.inspector.BuildConfig
import dev.vigil.inspector.R
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.data.AppRules
import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.engine.DeviceState
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
import kotlinx.coroutines.ExperimentalCoroutinesApi
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
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
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

    /**
     * Newest start id passed to onStartCommand. Main thread only: foreground
     * changes are made on the main thread too, so a start request that
     * arrives while a stop is being handled can never lose the foreground
     * state it just acquired.
     */
    private var latestStartId = 0
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }

    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var packageReceiver: BroadcastReceiver? = null
    private var screenReceiver: BroadcastReceiver? = null
    /** Type of the underlying default network, for per-app Wi-Fi / mobile data rules. */
    private val networkType = MutableStateFlow(DeviceState.NETWORK_OTHER)
    /** Screen on (interactive), for per-app screen-off and background rules. */
    private val screenOn = MutableStateFlow(true)
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
        /** Routes installed at establish(); a change needs a new interface. */
        val routes: List<VpnRoutes.Cidr>,
        /** App excluded from the VPN as the SOCKS5 proxy (e.g. Orbot). */
        val excludedPackage: String?,
        /** The configuration the engine currently runs with (without the start-only feed list). */
        @Volatile var applied: EngineConfig,
        /** Feeds passed in the start config: id → FeedEntity.lastUpdated (0 if never). */
        val preloaded: Map<String, Long>,
        /** The device state the engine has (for per-app conditions). */
        @Volatile var deviceState: DeviceState,
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
        registerScreenReceiver()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = maxOf(latestStartId, startId)
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
        screenReceiver?.let { runCatching { unregisterReceiver(it) } }
        screenReceiver = null
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
                    // Already healthy. Always-on toggles arrive as start requests: re-check lockdown.
                    ServiceState.status.value == VpnStatus.Running(s.id) && s.engine.isOpen -> refreshUpstreamWarning(s)
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
        ServiceState.loadedFeeds.value = s.preloaded
        ServiceState.configError.value = null
        refreshUpstreamWarning(s, notify = false)
        // Normally a no-op (onStartCommand made the service foreground), but it
        // guarantees the running VPN is never left in a plain started service,
        // and it shows the current warning at once.
        val n = buildNotification(ServiceState.stats.value)
        mainHandler.post { if (!goForeground(n)) Log.w(TAG, "could not re-enter the foreground for session ${s.id}") }
        s.pump = scope.launch { pump(s) }
        s.side = scope.launch {
            launch { syncFeeds(s) }
            launch { applyConfigChanges(s) }
            launch { pushDeviceState(s) }
            launch { updateNotification(s) }
        }
        ServiceState.status.value = VpnStatus.Running(s.id)
        Log.i(TAG, "session ${s.id} started (engine ${VigilNative.nativeVersion()})")
    }

    /**
     * Always-on lockdown with the SOCKS5 proxy app excluded from the VPN
     * leaves the proxy without network ([ServicePolicy.lockdownWarning]).
     * Android does not tell the VPN app when lockdown is toggled, so this is
     * re-checked with every notification refresh.
     */
    private fun refreshUpstreamWarning(s: Session, notify: Boolean = true) {
        val pkg = s.excludedPackage
        val lockdown = pkg != null && runCatching { isLockdownEnabled }.getOrDefault(false)
        val warning = ServicePolicy.lockdownWarning(pkg, lockdown, pkg?.let(::appLabel))
        if (warning != ServiceState.upstreamWarning.value) {
            ServiceState.upstreamWarning.value = warning
            if (warning != null) Log.w(TAG, "always-on lockdown is on and the proxy app $pkg is excluded from the VPN: it has no network")
            if (notify) notifications.notify(NOTIFICATION_ID, buildNotification(ServiceState.stats.value))
        }
    }

    private fun appLabel(pkg: String): String? = runCatching {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
    }.getOrNull()

    private suspend fun createSession(previousId: Long?): Result<Session> {
        if (prepare(this) != null) return Result.failure(IllegalStateException("VPN permission required. Open vigil to grant it."))
        // Unreadable settings that configured a tunnel or proxy: fail closed.
        app.settings.loadProblem.value?.let { return Result.failure(IllegalStateException(it)) }
        val settings = app.settings.value
        val net = refreshNetworkInfo()
        // Read before establish(), so a slow database cannot delay the interface.
        val feeds = ConfigFactory.loadableFeeds(app.feeds.feeds.first()) { app.feeds.fileFor(it).exists() }
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
        val routes = VpnRoutes.all(settings.excludeLan, net.nat64Prefixes)
        routes.forEach { builder.addRoute(it.address, it.prefix) }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish failed", e)
            null
        } ?: return Result.failure(IllegalStateException("Could not create the VPN interface."))

        // Ids are start times; keep them strictly increasing across quick restarts.
        val id = maxOf(System.currentTimeMillis(), (previousId ?: 0L) + 1)
        val config = buildConfig(settings, net)
        // The engine loads the feeds before it processes the first packet, so
        // blocking and threat alerts cover the session from its start.
        val state = currentDeviceState(settings)
        val startConfig = ConfigFactory.startConfig(config, feeds, state) { app.feeds.fileFor(it).absolutePath }
        val handle = VigilNative.nativeStart(pfd.fd, startConfig.toJson(), PlatformBridge(this, connectivity))
        if (handle == 0L) {
            runCatching { pfd.close() }
            return Result.failure(IllegalStateException("The inspection engine failed to start (configuration rejected?)."))
        }
        val processor = EventProcessor(app.db, app.apps, app.settings, app.foreground, app.exporter, app.notifier, id, app.exfil) { message ->
            commands.trySend(Command.EngineError(id, message))
        }
        val preloaded = feeds.associate { it.id to (it.lastUpdated ?: 0L) }
        return Result.success(Session(id, pfd, EngineHandle(handle), processor, routes, excluded, config, preloaded, state))
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
            ServiceState.upstreamWarning.value = null
        }
    }

    private suspend fun giveUp(message: String) {
        val s = current
        current = null
        s?.let { teardown(it) }
        ServiceState.stats.value = null
        ServiceState.loadedFeeds.value = emptyMap()
        ServiceState.upstreamWarning.value = null
        postProblem(NOTIFICATION_FAILED_ID, "vigil stopped inspecting", message, AlertNotifier.CHANNEL_ALERTS)
        fail(message)
    }

    private fun fail(message: String) {
        Log.e(TAG, message)
        ServiceState.status.value = VpnStatus.Failed(message)
        stopServiceFor(handledStartId)
    }

    /**
     * Stops the service unless a newer start request is pending. On the main
     * thread, like onStartCommand: if a newer Start was received (it is
     * queued behind this command), the service stays in the foreground for
     * the VPN that Start brings up; `stopSelf(startId)` is then a no-op.
     */
    private fun stopServiceFor(startId: Int) {
        mainHandler.post {
            if (ServicePolicy.mayLeaveForeground(startId, latestStartId)) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                Log.i(TAG, "start request $latestStartId pending; staying in the foreground")
            }
            stopSelf(startId)
        }
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

    /**
     * Keeps the engine's loaded feeds in sync with the enabled feed set. The
     * feeds of the start config are already loaded, so only feeds changed
     * since (another download, enabled or disabled) are loaded or removed.
     */
    private suspend fun syncFeeds(s: Session) {
        val loaded = s.preloaded.toMutableMap()
        app.feeds.feeds.collect { feeds ->
            val wanted = ConfigFactory.loadableFeeds(feeds) { app.feeds.fileFor(it).exists() }.associateBy { it.id }
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
        ConfigFactory.build(s, net.upstreamDns, app.apps.uidsFor(s.blockedPackages), net.nat64Prefixes, net.networkId, app.apps::uidFor)

    /** The device state for per-app conditions (PackageManager and usage-stats calls). */
    private fun currentDeviceState(s: Settings): DeviceState = AppRules.deviceState(
        network = networkType.value,
        screenOn = screenOn.value,
        needsForeground = AppRules.needsForeground(s),
        foregroundPackage = { app.foreground.foregroundPackage(FOREGROUND_POLL_MS) },
        uidOf = app.apps::uidFor,
    )

    /**
     * Keeps the engine's device state current: the network type and screen
     * state are pushed when they change; the foreground app is polled every
     * [FOREGROUND_POLL_MS] only while some app has a background rule and
     * the screen is on (usage stats have no change callback). Only changes
     * reach the engine, which then cuts connections that became blocked.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun pushDeviceState(s: Session) {
        val needsForeground = app.settings.flow.map { AppRules.needsForeground(it) }.distinctUntilChanged()
        combine(needsForeground, screenOn, networkType, packagesChanged) { fg, screen, _, _ -> fg && screen }
            .collectLatest { poll ->
                while (true) {
                    val state = currentDeviceState(app.settings.value)
                    if (state != s.deviceState) {
                        val ok = s.engine.use { VigilNative.nativeSetDeviceState(it, state.toJson()) } ?: return@collectLatest
                        if (ok) s.deviceState = state else Log.w(TAG, "engine rejected device state ${state.toJson()}")
                    }
                    if (!poll) break
                    delay(FOREGROUND_POLL_MS)
                }
            }
    }

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
            .map { (st, net) -> Triple(VpnRoutes.all(st.excludeLan, net.nat64Prefixes), st.upstream.excludedPackage, buildConfig(st, net)) }
            .distinctUntilChanged()
            .collect { (routes, excludedPackage, config) ->
                if (routes != s.routes || excludedPackage != s.excludedPackage) {
                    // Routes (LAN exclusion, a NAT64 prefix in ULA space) and
                    // excluded apps can only change by re-establishing the interface.
                    commands.trySend(Command.Restart(s.id, "VPN routes or excluded apps changed"))
                    return@collect
                }
                // The engine sizes its runtime once, at start.
                if (config.workerThreads != s.applied.workerThreads) {
                    commands.trySend(Command.Restart(s.id, "engine worker threads changed"))
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

    private suspend fun updateNotification(s: Session) {
        while (true) {
            delay(15_000)
            refreshUpstreamWarning(s, notify = false)
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

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                networkType.value = networkTypeOf(caps)
            }

            override fun onLost(network: Network) {
                networkType.value = DeviceState.NETWORK_NONE
            }
        }
        networkType.value = runCatching { connectivity.activeNetwork?.let { connectivity.getNetworkCapabilities(it) } }
            .getOrNull()?.let(::networkTypeOf) ?: DeviceState.NETWORK_NONE
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

    /** Screen on/off for per-app rules; sticky state from PowerManager, changes by broadcast. */
    private fun registerScreenReceiver() {
        screenOn.value = runCatching { getSystemService(PowerManager::class.java).isInteractive }.getOrDefault(true)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    Intent.ACTION_SCREEN_ON -> screenOn.value = true
                    Intent.ACTION_SCREEN_OFF -> screenOn.value = false
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        // Protected system broadcasts, delivered to non-exported receivers too.
        ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        screenReceiver = receiver
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
        val warning = ServiceState.upstreamWarning.value
        val excluded = current?.excludedPackage
        return NotificationCompat.Builder(this, AlertNotifier.CHANNEL_SERVICE)
            .setSmallIcon(R.drawable.ic_stat_vigil)
            .setContentTitle("vigil is inspecting traffic")
            .setContentText(if (warning != null && excluded != null) ServicePolicy.lockdownShort(excluded, appLabel(excluded)) else text)
            .apply { if (warning != null) setStyle(NotificationCompat.BigTextStyle().bigText("$warning\n\n$text")) }
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
        /** Wi-Fi or mobile data (for per-app rules); VPN-over-VPN never occurs, vigil being excluded. */
        fun networkTypeOf(caps: NetworkCapabilities): String = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> DeviceState.NETWORK_WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> DeviceState.NETWORK_CELLULAR
            else -> DeviceState.NETWORK_OTHER
        }

        private const val TAG = "vigil.vpn"
        private const val NOTIFICATION_ID = 1
        private const val NOTIFICATION_FAILED_ID = 2
        private const val NOTIFICATION_CONFIG_ID = 3
        private const val DRAIN_TIMEOUT_MS = 5_000L
        private const val MAX_DRAIN_BATCHES = 200
        /** How often the foreground app is looked up while a background rule needs it. */
        private const val FOREGROUND_POLL_MS = 1_000L
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
