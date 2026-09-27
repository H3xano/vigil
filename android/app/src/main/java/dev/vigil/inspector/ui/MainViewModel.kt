package dev.vigil.inspector.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.data.AlertEntity
import dev.vigil.inspector.data.AppUsage
import dev.vigil.inspector.data.DestinationUsage
import dev.vigil.inspector.data.DnsEntity
import dev.vigil.inspector.data.FeedEntity
import dev.vigil.inspector.data.FlowEntity
import dev.vigil.inspector.data.NameCount
import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.data.Totals
import dev.vigil.inspector.engine.StatsEvent
import dev.vigil.inspector.export.ExportStatus
import dev.vigil.inspector.vpn.NetworkInfo
import dev.vigil.inspector.vpn.ServiceState
import dev.vigil.inspector.vpn.VpnStatus
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class Throughput(val downBps: Long = 0, val upBps: Long = 0)

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

    val totals24h: StateFlow<Totals> = since(24).flatMapLatest { db.flows().totals(it) }.state(Totals(0, 0, 0, 0))
    val dnsCount24h: StateFlow<Long> = since(24).flatMapLatest { db.dns().countSince(it) }.state(0)
    val dnsBlocked24h: StateFlow<Long> = since(24).flatMapLatest { db.dns().blockedSince(it) }.state(0)
    val activeFlows: StateFlow<Int> = db.flows().activeCount().state(0)
    val unseenAlerts: StateFlow<Int> = db.alerts().unseenCount().state(0)
    val topApps: StateFlow<List<AppUsage>> = since(24).flatMapLatest { db.flows().appUsage(it) }.state(emptyList())
    val appsWeek: StateFlow<List<AppUsage>> = since(24 * 7).flatMapLatest { db.flows().appUsage(it) }.state(emptyList())
    val topBlocked: StateFlow<List<NameCount>> = since(24).flatMapLatest { db.dns().topBlocked(it) }.state(emptyList())
    val alerts: StateFlow<List<AlertEntity>> = db.alerts().recent().state(emptyList())
    val feeds: StateFlow<List<FeedEntity>> = app.feeds.feeds.state(emptyList())
    val loadedFeeds: StateFlow<Map<String, Long>> = ServiceState.loadedFeeds

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

    val flowQuery = MutableStateFlow("")
    val flowBlockedOnly = MutableStateFlow(false)
    val flows: StateFlow<List<FlowEntity>> = combine(flowQuery.debounce(200), flowBlockedOnly) { q, b -> q.trim() to b }
        .flatMapLatest { (q, b) -> db.flows().recent(q, b) }.state(emptyList())

    val dnsQuery = MutableStateFlow("")
    val dnsBlockedOnly = MutableStateFlow(false)
    val dns: StateFlow<List<DnsEntity>> = combine(dnsQuery.debounce(200), dnsBlockedOnly) { q, b -> q.trim() to b }
        .flatMapLatest { (q, b) -> db.dns().recent(q, b) }.state(emptyList())

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
    fun clearHistory() = viewModelScope.launch { app.clearHistory() }

    fun setFeedEnabled(id: String, enabled: Boolean) = viewModelScope.launch { app.feeds.setEnabled(id, enabled) }
    fun refreshFeeds() = app.feeds.scheduleRefreshNow()
    fun addFeed(name: String, url: String, category: String, auth: String?) = viewModelScope.launch { app.feeds.addCustom(name, url, category, auth) }
    fun deleteFeed(id: String) = viewModelScope.launch { app.feeds.delete(id) }

    suspend fun sendExportTest(): Result<Unit> = app.exporter.sendTest()

    fun appLabel(key: String): String = app.apps.byKey(key).label
}
