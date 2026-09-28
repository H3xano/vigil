package dev.vigil.inspector

import android.app.Application
import android.util.Log
import dev.vigil.inspector.data.AppResolver
import dev.vigil.inspector.data.FeedRepository
import dev.vigil.inspector.data.SettingsStore
import dev.vigil.inspector.data.VigilDatabase
import dev.vigil.inspector.export.SiemExporter
import dev.vigil.inspector.processing.AlertNotifier
import dev.vigil.inspector.processing.ExfilDetector
import dev.vigil.inspector.processing.ForegroundTracker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Application-wide singletons (a small hand-rolled service locator). */
class VigilApp : Application() {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val db by lazy { VigilDatabase.create(this) }
    val settings by lazy { SettingsStore(this) }
    val apps by lazy { AppResolver(this) }
    val feeds by lazy { FeedRepository(this, db.feeds()) }
    val foreground by lazy { ForegroundTracker(this) }
    val notifier by lazy { AlertNotifier(this, apps) }
    val exporter by lazy { SiemExporter(this, settings, scope).also { it.start() } }
    /** App-wide, so upload windows and the per-app baseline span engine sessions. */
    val exfil by lazy { ExfilDetector(java.io.File(filesDir, "exfil_baseline.json")) }
    private val pruneLock = Mutex()

    override fun onCreate() {
        super.onCreate()
        notifier.createChannels()
        scope.launch {
            feeds.seedBuiltins()
            feeds.schedulePeriodic()
            pruneOldData()
        }
        // A shorter retention takes effect right away, not at the next daily run.
        scope.launch {
            settings.flow.map { it.retentionDays }.distinctUntilChanged().drop(1).collect { pruneOldData() }
        }
    }

    /**
     * Applies the retention setting to the history tables. Deletes in chunks
     * so a large backlog does not hold one long write transaction (which
     * would stall event persistence). Learned destinations are kept for at
     * least [DESTINATION_MIN_DAYS] so novelty alerts keep their baseline;
     * the same applies to learned (app, network) pairs.
     */
    suspend fun pruneOldData() = pruneLock.withLock {
        val days = settings.value.retentionDays.coerceAtLeast(1)
        val now = System.currentTimeMillis()
        val before = now - days * DAY_MS
        var deleted = 0
        deleted += drain { db.flows().deleteBefore(before, CHUNK) }
        deleted += drain { db.dns().deleteBefore(before, CHUNK) }
        deleted += drain { db.alerts().deleteBefore(before, CHUNK) }
        deleted += db.destinations().deleteBefore(now - maxOf(days, DESTINATION_MIN_DAYS) * DAY_MS)
        deleted += db.appAsns().deleteBefore(now - maxOf(days, DESTINATION_MIN_DAYS) * DAY_MS)
        if (deleted > 0) Log.i(TAG, "pruned $deleted rows older than $days days")
    }

    private suspend fun drain(step: suspend () -> Int): Int {
        var total = 0
        while (true) {
            val n = step()
            total += n
            if (n < CHUNK) return total
        }
    }

    /** Reclaims space freed by pruning; runs at most weekly (from the daily worker). */
    suspend fun vacuumIfDue() = pruneLock.withLock {
        val prefs = getSharedPreferences("vigil_maintenance", MODE_PRIVATE)
        val now = System.currentTimeMillis()
        if (now - prefs.getLong("last_vacuum", 0L) < 7 * DAY_MS) return@withLock
        withContext(Dispatchers.IO) {
            runCatching { db.openHelper.writableDatabase.execSQL("VACUUM") }
                .onSuccess { prefs.edit().putLong("last_vacuum", now).apply() }
                .onFailure { Log.w(TAG, "VACUUM failed", it) }
        }
    }

    suspend fun clearHistory() {
        db.flows().clear()
        db.dns().clear()
        db.alerts().clear()
        db.destinations().clear()
        db.appAsns().clear()
    }

    private companion object {
        const val TAG = "vigil.app"
        const val DAY_MS = 86_400_000L
        const val CHUNK = 5_000
        const val DESTINATION_MIN_DAYS = 90
    }
}
