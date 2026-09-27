package dev.vigil.inspector.processing

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.os.PowerManager
import android.os.Process

/**
 * Tracks the foreground app (needs the "Usage access" special permission)
 * so flows can be tagged as foreground or background traffic.
 */
class ForegroundTracker(private val context: Context) {
    private val usm = context.getSystemService(UsageStatsManager::class.java)
    private val power = context.getSystemService(PowerManager::class.java)
    @Volatile private var current: String? = null
    private var lastQuery = 0L
    private var lastRefresh = 0L

    fun hasPermission(): Boolean {
        val ops = context.getSystemService(AppOpsManager::class.java)
        return ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName) ==
            AppOpsManager.MODE_ALLOWED
    }

    /** Folds new usage events into the current foreground package (throttled). */
    fun refresh() {
        val now = System.currentTimeMillis()
        if (now - lastRefresh < 2_000) return
        lastRefresh = now
        if (!hasPermission()) return
        val from = if (lastQuery == 0L) now - 10 * 60_000 else lastQuery
        val events = runCatching { usm.queryEvents(from, now) }.getOrNull() ?: return
        val e = UsageEvents.Event()
        while (events.hasNextEvent()) {
            events.getNextEvent(e)
            when (e.eventType) {
                UsageEvents.Event.ACTIVITY_RESUMED -> current = e.packageName
                UsageEvents.Event.ACTIVITY_PAUSED -> if (e.packageName == current) current = null
            }
        }
        lastQuery = now
    }

    /** true/false for installed packages when known, null when undeterminable. */
    fun isBackground(appKey: String): Boolean? {
        if (!appKey.contains('.') || appKey.startsWith("uid:") || !hasPermission()) return null
        if (!power.isInteractive) return true
        return appKey != current
    }
}
