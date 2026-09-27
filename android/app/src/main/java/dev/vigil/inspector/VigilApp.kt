package dev.vigil.inspector

import android.app.Application
import dev.vigil.inspector.data.AppResolver
import dev.vigil.inspector.data.FeedRepository
import dev.vigil.inspector.data.SettingsStore
import dev.vigil.inspector.data.VigilDatabase
import dev.vigil.inspector.export.SiemExporter
import dev.vigil.inspector.processing.AlertNotifier
import dev.vigil.inspector.processing.ForegroundTracker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

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

    override fun onCreate() {
        super.onCreate()
        notifier.createChannels()
        scope.launch {
            feeds.seedBuiltins()
            feeds.schedulePeriodic()
            pruneOldData()
        }
    }

    /** Applies the retention setting to the history tables. */
    suspend fun pruneOldData() {
        val before = System.currentTimeMillis() - settings.value.retentionDays.coerceAtLeast(1) * 86_400_000L
        db.flows().deleteBefore(before)
        db.dns().deleteBefore(before)
        db.alerts().deleteBefore(before)
    }

    suspend fun clearHistory() {
        db.flows().clear()
        db.dns().clear()
        db.alerts().clear()
        db.destinations().clear()
    }
}
