package dev.vigil.inspector.ui

import android.app.Application
import android.net.Uri
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.vigil.inspector.BuildConfig
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.data.FeedEntity
import dev.vigil.inspector.data.FeedKinds
import dev.vigil.inspector.data.HealthCheck
import dev.vigil.inspector.data.HealthReport
import dev.vigil.inspector.data.InstalledApps
import dev.vigil.inspector.vpn.ServiceState
import dev.vigil.inspector.vpn.VpnStatus
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** State of the health check screen. The report lives in memory only and is never stored. */
sealed interface HealthState {
    data object Idle : HealthState
    data object Running : HealthState
    data class Done(val report: HealthReport) : HealthState
    data class Failed(val message: String) : HealthState
}

/** Runs the spyware health check ([HealthCheck]) on the device, offline. */
class HealthCheckViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application as VigilApp

    private val _state = MutableStateFlow<HealthState>(HealthState.Idle)
    val state: StateFlow<HealthState> = _state.asStateFlow()

    /** The feeds of the "Spyware & stalkerware" group. */
    val packs: StateFlow<List<FeedEntity>> = app.feeds.feeds
        .map { list -> list.filter { it.kind in FeedKinds.SPYWARE_KINDS } }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun run() {
        if (_state.value == HealthState.Running) return
        _state.value = HealthState.Running
        viewModelScope.launch {
            _state.value = try {
                HealthState.Done(withContext(Dispatchers.IO) { check() })
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "health check failed", e)
                HealthState.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    private suspend fun check(): HealthReport {
        val db = app.db
        val observed = db.dns().observedNames() + db.flows().observedDomains() + db.flows().observedIps() + db.destinations().observed()
        val since = listOfNotNull(db.dns().oldest(), db.flows().oldest()).minOrNull()
        val labels = HashMap<String, String>()
        return HealthCheck.run(
            HealthCheck.Input(
                now = System.currentTimeMillis(),
                appVersion = BuildConfig.VERSION_NAME,
                packs = app.feeds.spywarePacks(),
                apps = InstalledApps.collect(app),
                observed = observed,
                historySince = since,
                retentionDays = app.settings.value.retentionDays,
                inspectionRunning = ServiceState.status.value is VpnStatus.Running,
                appLabel = { key -> labels.getOrPut(key) { app.apps.byKey(key).label } },
                text = { it.resolve(app) },
            ),
        )
    }

    /** Turns on every spyware feed that is off, and downloads what is missing. */
    fun enableAllPacks() {
        viewModelScope.launch {
            for (f in packs.value.filter { !it.enabled }) app.feeds.setEnabled(f.id, true)
            app.feeds.scheduleRefreshNow(force = false)
        }
    }

    fun updatePacks() = app.feeds.scheduleRefreshNow(force = true)

    /** Writes the JSON report to a document the user picked (Storage Access Framework). */
    fun saveJson(uri: Uri, report: HealthReport, onDone: (Boolean) -> Unit) {
        viewModelScope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching {
                    app.contentResolver.openOutputStream(uri, "wt")?.use { it.write(HealthCheck.toJson(report).toByteArray()) } ?: error("no stream")
                }.onFailure { Log.w(TAG, "saving the report failed: ${it.message}") }.isSuccess
            }
            onDone(ok)
        }
    }

    private companion object {
        const val TAG = "vigil.health"
    }
}
