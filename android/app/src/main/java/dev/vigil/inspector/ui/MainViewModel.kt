package dev.vigil.inspector.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.data.AlertEntity
import dev.vigil.inspector.data.AlertMute
import dev.vigil.inspector.data.AlertMutes
import dev.vigil.inspector.data.AppDomainRule
import dev.vigil.inspector.data.AppRule
import dev.vigil.inspector.data.AppRules
import dev.vigil.inspector.data.AppUsage
import dev.vigil.inspector.data.DestinationUsage
import dev.vigil.inspector.data.DnsEntity
import dev.vigil.inspector.data.ExportSettings
import dev.vigil.inspector.data.FeedEntity
import dev.vigil.inspector.data.FeedKinds
import dev.vigil.inspector.data.FlowEntity
import dev.vigil.inspector.data.NameCount
import dev.vigil.inspector.data.PathFilter
import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.data.TaxiiCollection
import dev.vigil.inspector.data.Totals
import dev.vigil.inspector.engine.StatsEvent
import dev.vigil.inspector.export.ExportStatus
import dev.vigil.inspector.vpn.NetworkInfo
import dev.vigil.inspector.vpn.ServiceState
import dev.vigil.inspector.vpn.VpnStatus
import androidx.work.WorkInfo
import androidx.work.WorkManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

data class Throughput(val downBps: Long = 0, val upBps: Long = 0)

/** A snackbar message, optionally with an action such as Undo. */
class UiMessage(val id: Long, val text: String, val actionLabel: String? = null, val action: (() -> Unit)? = null)

/** Per-app lists of the app detail screen; null until the first query result. */
class AppDetailData(
    val destinations: StateFlow<List<DestinationUsage>?>,
    val flows: StateFlow<List<FlowEntity>?>,
    val dns: StateFlow<List<DnsEntity>?>,
    val alerts: StateFlow<List<AlertEntity>?>,
    internal val scope: CoroutineScope,
)

/** State of the on-demand feed update job. */
enum class FeedWork { IDLE, WAITING, RUNNING }

/** Aggregate queries re-run at most this often under traffic. */
private const val AGGREGATE_THROTTLE_MS = 2_000L
/** List queries (newest 500 rows) re-run at most this often. */
private const val LIST_THROTTLE_MS = 1_000L

@OptIn(ExperimentalCoroutinesApi::class, FlowPreview::class)
class MainViewModel(application: Application) : AndroidViewModel(application) {
    val app = application as VigilApp
    private val db = app.db

    private fun <T> Flow<T>.state(initial: T): StateFlow<T> = stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), initial)

    val status: StateFlow<VpnStatus> = ServiceState.status
    val stats: StateFlow<StatsEvent?> = ServiceState.stats
    val network: StateFlow<NetworkInfo> = ServiceState.network
    val settings: StateFlow<Settings> = app.settings.flow
    val exportStatus: StateFlow<ExportStatus> get() = app.exporter.status

    /** A clock that ticks every minute so "last 24 h" windows keep moving. */
    private val minuteClock = flow {
        while (true) {
            emit(System.currentTimeMillis())
            delay(60_000)
        }
    }

    private fun since(hours: Int): Flow<Long> = flow {
        minuteClock.collect { emit(it - hours * 3_600_000L) }
    }

    // Room re-runs a query on every write to its tables (about twice a second
    // under traffic); throttling keeps the first result immediate.
    private fun <T> Flow<T>.aggregate() = throttleLatest(AGGREGATE_THROTTLE_MS)
    private fun <T> Flow<T>.list() = throttleLatest(LIST_THROTTLE_MS)

    val totals24h: StateFlow<Totals> = since(24).flatMapLatest { db.flows().totals(it).aggregate() }.state(Totals(0, 0, 0, 0))
    val dnsCount24h: StateFlow<Long> = since(24).flatMapLatest { db.dns().countSince(it).aggregate() }.state(0)
    val dnsBlocked24h: StateFlow<Long> = since(24).flatMapLatest { db.dns().blockedSince(it).aggregate() }.state(0)
    val unseenAlerts: StateFlow<Int> = db.alerts().unseenCount().state(0)
    val topApps: StateFlow<List<AppUsage>> = since(24).flatMapLatest { db.flows().appUsage(it).aggregate() }.state(emptyList())

    /**
     * The one time window of the Apps list and the app details: 7 days, or
     * the history retention when that is shorter (older rows are gone).
     */
    val appWindowDays: StateFlow<Int> = settings.map { appWindowDays(it.retentionDays) }.distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, appWindowDays(settings.value.retentionDays))
    private val appWindowStart: Flow<Long> = appWindowDays.flatMapLatest { days -> since(24 * days) }
    val appsWeek: StateFlow<List<AppUsage>> = appWindowStart.flatMapLatest { db.flows().appUsage(it).aggregate() }.state(emptyList())

    val topBlocked: StateFlow<List<NameCount>> = since(24).flatMapLatest { db.dns().topBlocked(it).aggregate() }.state(emptyList())
    val alerts: StateFlow<List<AlertEntity>> = db.alerts().recent().list().state(emptyList())
    val feeds: StateFlow<List<FeedEntity>> = app.feeds.feeds.state(emptyList())
    val loadedFeeds: StateFlow<Map<String, Long>> = ServiceState.loadedFeeds
    /** Set when the engine rejected a settings update (the previous configuration stays active). */
    val configError: StateFlow<String?> = ServiceState.configError
    fun dismissConfigError() {
        ServiceState.configError.value = null
    }

    val throughput: StateFlow<Throughput> = flow {
        var prev: StatsEvent? = null
        ServiceState.stats.collect { s ->
            val p = prev
            prev = s
            if (s == null || p == null || s.ts <= p.ts) {
                emit(Throughput())
            } else {
                val dt = (s.ts - p.ts) / 1000.0
                emit(Throughput(((s.bytesIn - p.bytesIn) / dt).toLong().coerceAtLeast(0), ((s.bytesOut - p.bytesOut) / dt).toLong().coerceAtLeast(0)))
            }
        }
    }.state(Throughput())

    /** Selected Activity tab: 0 connections, 1 DNS. */
    val activityTab = MutableStateFlow(0)
    val flowQuery = MutableStateFlow("")
    val flowBlockedOnly = MutableStateFlow(false)
    /** [PathFilter] value: all connections, only tunnelled/proxied ones, or only direct ones. */
    val flowPath = MutableStateFlow(PathFilter.ALL)
    /** Activity shows only this app's connections and lookups (null: all apps). */
    val activityApp = MutableStateFlow<String?>(null)
    /** Paused: the Activity lists stop following new traffic (filter changes still apply). */
    val activityPaused = MutableStateFlow(false)

    private class ListFilter(val query: String, val blockedOnly: Boolean, val path: String, val app: String?, val paused: Boolean)

    /** Live lists follow the table (throttled); paused ones run the query once per filter change. */
    private fun <T> Flow<T>.liveOrOnce(paused: Boolean): Flow<T> = if (paused) take(1) else list()

    val flows: StateFlow<List<FlowEntity>> =
        combine(flowQuery.debounce(200), flowBlockedOnly, flowPath, activityApp, activityPaused) { q, b, p, a, paused ->
            ListFilter(q.trim(), b, p, a, paused)
        }.flatMapLatest { f ->
            val app = f.app
            val rows = if (app == null) {
                db.flows().recent(f.query, f.blockedOnly, ACTIVITY_LIMIT, f.path)
            } else {
                db.flows().recentForApp(f.query, f.blockedOnly, app, ACTIVITY_LIMIT, f.path)
            }
            rows.liveOrOnce(f.paused)
        }.state(emptyList())

    val dnsQuery = MutableStateFlow("")
    val dnsBlockedOnly = MutableStateFlow(false)
    val dns: StateFlow<List<DnsEntity>> = combine(dnsQuery.debounce(200), dnsBlockedOnly, activityApp, activityPaused) { q, b, a, paused ->
        ListFilter(q.trim(), b, PathFilter.ALL, a, paused)
    }.flatMapLatest { f ->
        val app = f.app
        val rows = if (app == null) db.dns().recent(f.query, f.blockedOnly, ACTIVITY_LIMIT) else db.dns().recentForApp(f.query, f.blockedOnly, app, ACTIVITY_LIMIT)
        rows.liveOrOnce(f.paused)
    }.state(emptyList())

    /** Opens Activity filtered to blocked connections and lookups (the "Blocked" tile). */
    fun showBlockedActivity(preferDns: Boolean) {
        flowQuery.value = ""
        dnsQuery.value = ""
        flowBlockedOnly.value = true
        flowPath.value = PathFilter.ALL
        dnsBlockedOnly.value = true
        activityApp.value = null
        activityPaused.value = false
        activityTab.value = if (preferDns) 1 else 0
    }

    /** Opens the Activity DNS tab searching for [name] (e.g. from "Most blocked domains"). */
    fun showLookups(name: String) {
        dnsQuery.value = name
        dnsBlockedOnly.value = false
        activityApp.value = null
        activityPaused.value = false
        activityTab.value = 1
    }

    /** Clears the Activity filters, e.g. when the tab is opened from the navigation bar. */
    fun clearActivityFilters() {
        flowBlockedOnly.value = false
        dnsBlockedOnly.value = false
        activityApp.value = null
        activityPaused.value = false
    }

    /**
     * Snackbar messages waiting to be shown, oldest first. A message stays
     * here until [messageShown], so one raised while no snackbar host exists
     * (onboarding) or during a rotation is shown later instead of lost.
     */
    private val _messages = MutableStateFlow<List<UiMessage>>(emptyList())
    val messages: StateFlow<List<UiMessage>> = _messages
    private val messageIds = AtomicLong()

    fun showMessage(text: String, actionLabel: String? = null, action: (() -> Unit)? = null) {
        val m = UiMessage(messageIds.incrementAndGet(), text, actionLabel, action)
        _messages.update { (it + m).takeLast(MAX_PENDING_MESSAGES) }
    }

    fun messageShown(id: Long) = _messages.update { list -> list.filterNot { it.id == id } }

    /** App labels resolved off the main thread (PackageManager calls are IPC). */
    private val _labels = MutableStateFlow<Map<String, String>>(emptyMap())
    val labels: StateFlow<Map<String, String>> = _labels
    private val pendingLabels = ConcurrentHashMap.newKeySet<String>()

    fun requestLabels(keys: Collection<String>) {
        val known = _labels.value
        val missing = keys.filter { it !in known && pendingLabels.add(it) }
        if (missing.isEmpty()) return
        viewModelScope.launch(Dispatchers.IO) {
            val resolved = missing.associateWith { app.apps.byKey(it).label }
            _labels.update { it + resolved }
            pendingLabels.removeAll(missing.toSet())
        }
    }

    /** Label for display while the real one is being resolved. */
    fun fallbackLabel(key: String): String = when {
        key == "unknown" -> "Unknown app"
        key.startsWith("uid:") -> "UID " + key.removePrefix("uid:")
        else -> key
    }

    val feedWork: StateFlow<FeedWork> = WorkManager.getInstance(application).getWorkInfosForUniqueWorkFlow(FEEDS_NOW_WORK)
        .map { infos ->
            when {
                infos.any { it.state == WorkInfo.State.RUNNING } -> FeedWork.RUNNING
                infos.any { it.state == WorkInfo.State.ENQUEUED || it.state == WorkInfo.State.BLOCKED } -> FeedWork.WAITING
                else -> FeedWork.IDLE
            }
        }.state(FeedWork.IDLE)

    fun flow(id: Long): Flow<FlowEntity?> = db.flows().byId(id)

    /** Recently opened app details; each entry's queries stop 5 s after its screen is left. */
    private val appDetails = object : LinkedHashMap<String, AppDetailData>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, AppDetailData>): Boolean =
            (size > APP_DETAIL_CACHE).also { if (it) eldest.value.scope.cancel() }
    }

    /**
     * The app detail lists of [pkg], cached per app so that returning to an
     * app shows its data (and keeps the scroll position) at once, then
     * refreshes. Throttled like the other queries.
     */
    fun appDetail(pkg: String): AppDetailData = synchronized(appDetails) {
        appDetails.getOrPut(pkg) {
            val scope = CoroutineScope(viewModelScope.coroutineContext + Job(viewModelScope.coroutineContext[Job]))
            fun <T> Flow<T>.cached(): StateFlow<T?> = stateIn(scope, SharingStarted.WhileSubscribed(5_000), null)
            AppDetailData(
                destinations = appWindowStart.flatMapLatest { db.flows().destinationsFor(pkg, it).aggregate() }.cached(),
                flows = db.flows().byPackage(pkg).list().cached(),
                dns = db.dns().byPackage(pkg).list().cached(),
                alerts = db.alerts().byPackage(pkg).list().cached(),
                scope = scope,
            )
        }
    }

    fun updateSettings(transform: (Settings) -> Settings) = app.settings.update(transform)

    fun setAppBlocked(pkg: String, blocked: Boolean) = updateSettings {
        it.copy(blockedPackages = if (blocked) it.blockedPackages + pkg else it.blockedPackages - pkg)
    }

    /** Blocks all network access of [pkg], with an Undo snackbar. */
    fun blockApp(pkg: String, label: String) {
        val wasBlocked = pkg in settings.value.blockedPackages
        setAppBlocked(pkg, true)
        if (!wasBlocked) showMessage("Blocked all network access of $label", "Undo") { setAppBlocked(pkg, false) }
    }

    fun denyDomain(domain: String) = updateSettings { it.copy(denyDomains = it.denyDomains + domain.lowercase(), allowDomains = it.allowDomains - domain.lowercase()) }
    fun allowDomain(domain: String) = updateSettings { it.copy(allowDomains = it.allowDomains + domain.lowercase(), denyDomains = it.denyDomains - domain.lowercase()) }
    fun removeRule(domain: String) = updateSettings { it.copy(allowDomains = it.allowDomains - domain, denyDomains = it.denyDomains - domain) }

    /** Restores [name]'s membership of the deny and allow lists as it was in [before]. */
    private fun restoreRule(name: String, before: Settings) = updateSettings {
        it.copy(
            denyDomains = if (name in before.denyDomains) it.denyDomains + name else it.denyDomains - name,
            allowDomains = if (name in before.allowDomains) it.allowDomains + name else it.allowDomains - name,
        )
    }

    /** Adds a block rule for [domain] (and its subdomains) and offers Undo. */
    fun blockDomain(domain: String) {
        val name = domain.lowercase()
        val before = settings.value
        denyDomain(name)
        showMessage("Blocked $name (and subdomains)", "Undo") { restoreRule(name, before) }
    }

    /** Adds an allow rule for [domain] (and its subdomains) and offers Undo. */
    fun allowDomainWithUndo(domain: String) {
        val name = domain.lowercase()
        val before = settings.value
        allowDomain(name)
        showMessage("Always allowing $name (and subdomains)", "Undo") { restoreRule(name, before) }
    }

    /** Removes the rule for [domain] and offers Undo. */
    fun removeRuleWithUndo(domain: String) {
        val before = settings.value
        removeRule(domain)
        showMessage("Removed the rule for $domain", "Undo") { restoreRule(domain, before) }
    }

    /** Sets the conditions under which [pkg] is blocked (Wi-Fi, mobile data, background, screen off). */
    fun setAppRule(pkg: String, rule: AppRule) = updateSettings { AppRules.setRule(it, pkg, rule) }

    /** Restores [pkg]'s rule for [domain] as it was in [before]. */
    private fun restoreAppDomainRule(pkg: String, domain: String, before: Settings) = updateSettings { s ->
        val old = before.appDomainRules.firstOrNull { it.app == pkg && it.domain == domain }
        if (old == null) AppRules.removeDomainRule(s, pkg, domain) else AppRules.setDomainRule(s, pkg, domain, old.action)
    }

    /**
     * Allows or blocks [domain] (and its subdomains) for [pkg] only, with Undo.
     * [action] is [AppDomainRule.ALLOW] or [AppDomainRule.BLOCK].
     */
    fun setAppDomainRule(pkg: String, label: String, domain: String, action: String) {
        val name = AppRules.normalize(domain)
        val before = settings.value
        updateSettings { AppRules.setDomainRule(it, pkg, name, action) }
        val verb = if (action == AppDomainRule.BLOCK) "Blocked" else "Allowed"
        showMessage("$verb $name for $label only", "Undo") { restoreAppDomainRule(pkg, name, before) }
    }

    fun removeAppDomainRule(pkg: String, domain: String) {
        val before = settings.value
        updateSettings { AppRules.removeDomainRule(it, pkg, domain) }
        showMessage("Removed the rule for $domain", "Undo") { restoreAppDomainRule(pkg, domain, before) }
    }

    /** The recorded block reason (engine `reason`) of the newest blocked lookup of [qname], or null. */
    suspend fun blockReason(qname: String): String? = db.dns().latestBlocked(qname)?.reason

    /** The database id of the connection an alert names by engine flow id, or null if it is no longer stored. */
    suspend fun flowIdForAlert(engineFlowId: Long, alertTs: Long): Long? = db.flows().byEngineId(engineFlowId, alertTs)?.id

    /** Mutes alerts of [kind] for [pkg] (only those about [target], if given: "mark as expected"), with Undo. */
    fun muteAlerts(kind: String, pkg: String, target: String?, confirmation: String) {
        val before = settings.value.alertMutes
        updateSettings { it.copy(alertMutes = AlertMutes.add(it.alertMutes, AlertMute(kind, pkg, target, System.currentTimeMillis()))) }
        showMessage(confirmation, "Undo") { updateSettings { it.copy(alertMutes = before) } }
    }

    fun unmuteAlerts(kind: String, pkg: String, target: String) =
        updateSettings { it.copy(alertMutes = AlertMutes.remove(it.alertMutes, kind, pkg, target)) }

    fun markAlertsSeen() = viewModelScope.launch { db.alerts().markAllSeen() }
    fun markAlertSeen(id: Long) = viewModelScope.launch { db.alerts().markSeen(id) }
    fun clearHistory() = viewModelScope.launch { app.clearHistory() }

    fun setFeedEnabled(id: String, enabled: Boolean) = viewModelScope.launch { app.feeds.setEnabled(id, enabled) }
    fun refreshFeeds() = app.feeds.scheduleRefreshNow()
    fun addFeed(name: String, url: String, category: String, auth: String?, kind: String = FeedKinds.LIST) =
        viewModelScope.launch { app.feeds.addCustom(name, url, category, auth, kind) }
    fun addTaxii(name: String, collection: TaxiiCollection, category: String, headerName: String?, auth: String?) =
        viewModelScope.launch { app.feeds.addTaxii(name, collection, category, headerName, auth) }
    suspend fun taxiiCollections(url: String, headerName: String?, auth: String?): Result<List<TaxiiCollection>> =
        app.feeds.taxiiCollections(url, headerName, auth)
    fun setBlockJa4Matches(block: Boolean) = updateSettings { it.copy(blockJa4Matches = block) }
    fun deleteFeed(id: String) = viewModelScope.launch { app.feeds.delete(id) }

    fun saveExport(cfg: ExportSettings) = updateSettings { it.copy(export = cfg) }

    suspend fun sendExportTest(cfg: ExportSettings): Result<Unit> = app.exporter.sendTest(cfg)

    companion object {
        /** Row limit of the Activity lists (see FlowDao.recent / DnsDao.recent). */
        const val ACTIVITY_LIMIT = 500
        /** Unique work name used by FeedRepository.scheduleRefreshNow(). */
        const val FEEDS_NOW_WORK = "feeds-now"
        private const val MAX_PENDING_MESSAGES = 8
        private const val APP_DETAIL_CACHE = 6

        /** Days shown on the Apps screens: a week, or less when history is kept for less. */
        fun appWindowDays(retentionDays: Int): Int = retentionDays.coerceIn(1, 7)
    }
}
