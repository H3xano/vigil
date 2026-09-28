package dev.vigil.inspector.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.data.AlertEntity
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

data class Throughput(val downBps: Long = 0, val upBps: Long = 0)

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
    val appsWeek: StateFlow<List<AppUsage>> = since(24 * 7).flatMapLatest { db.flows().appUsage(it).aggregate() }.state(emptyList())
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
    val flows: StateFlow<List<FlowEntity>> = combine(flowQuery.debounce(200), flowBlockedOnly, flowPath) { q, b, p -> Triple(q.trim(), b, p) }
        .flatMapLatest { (q, b, p) -> db.flows().recent(q, b, ACTIVITY_LIMIT, p).list() }.state(emptyList())

    val dnsQuery = MutableStateFlow("")
    val dnsBlockedOnly = MutableStateFlow(false)
    val dns: StateFlow<List<DnsEntity>> = combine(dnsQuery.debounce(200), dnsBlockedOnly) { q, b -> q.trim() to b }
        .flatMapLatest { (q, b) -> db.dns().recent(q, b, ACTIVITY_LIMIT).list() }.state(emptyList())

    /** Opens Activity filtered to blocked connections and lookups (the "Blocked" tile). */
    fun showBlockedActivity(preferDns: Boolean) {
        flowQuery.value = ""
        dnsQuery.value = ""
        flowBlockedOnly.value = true
        flowPath.value = PathFilter.ALL
        dnsBlockedOnly.value = true
        activityTab.value = if (preferDns) 1 else 0
    }

    /** Clears the Activity filters, e.g. when the tab is opened from the navigation bar. */
    fun clearActivityFilters() {
        flowBlockedOnly.value = false
        dnsBlockedOnly.value = false
    }

    /** One-shot messages shown as snackbars. */
    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 8)
    val messages: SharedFlow<String> = _messages
    fun showMessage(text: String) {
        _messages.tryEmit(text)
    }

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
    fun appFlows(pkg: String): Flow<List<FlowEntity>> = db.flows().byPackage(pkg)
    fun appDns(pkg: String): Flow<List<DnsEntity>> = db.dns().byPackage(pkg)
    fun appAlerts(pkg: String): Flow<List<AlertEntity>> = db.alerts().byPackage(pkg)
    fun appDestinations(pkg: String): Flow<List<DestinationUsage>> =
        since(24 * 30).flatMapLatest { db.flows().destinationsFor(pkg, it) }

    fun updateSettings(transform: (Settings) -> Settings) = app.settings.update(transform)

    fun setAppBlocked(pkg: String, blocked: Boolean) = updateSettings {
        it.copy(blockedPackages = if (blocked) it.blockedPackages + pkg else it.blockedPackages - pkg)
    }

    fun denyDomain(domain: String) = updateSettings { it.copy(denyDomains = it.denyDomains + domain.lowercase(), allowDomains = it.allowDomains - domain.lowercase()) }
    fun allowDomain(domain: String) = updateSettings { it.copy(allowDomains = it.allowDomains + domain.lowercase(), denyDomains = it.denyDomains - domain.lowercase()) }
    fun removeRule(domain: String) = updateSettings { it.copy(allowDomains = it.allowDomains - domain, denyDomains = it.denyDomains - domain) }

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
    }
}
