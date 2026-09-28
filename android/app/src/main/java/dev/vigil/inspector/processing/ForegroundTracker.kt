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
 *
 * The permission and screen state are binder calls, so they are sampled in
 * [refresh] (at most every 2 s) and cached for the per-flow [isBackground].
 */
class ForegroundTracker(private val context: Context) {
    private val usm = context.getSystemService(UsageStatsManager::class.java)
    private val power = context.getSystemService(PowerManager::class.java)
    @Volatile private var current: String? = null
    @Volatile private var permitted = false
    @Volatile private var interactive = true
    private var lastQuery = 0L
    private var lastRefresh = 0L

    fun hasPermission(): Boolean {
        val ops = context.getSystemService(AppOpsManager::class.java)
        return ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName) ==
            AppOpsManager.MODE_ALLOWED
    }

    /** Folds new usage events into the current foreground package (throttled). */
    @Synchronized
    fun refresh() {
        val now = System.currentTimeMillis()
        if (now - lastRefresh < 2_000) return
        lastRefresh = now
        permitted = hasPermission()
        interactive = power.isInteractive
        if (!permitted) return
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

    /** true/false for installed packages when known, null when undeterminable. Uses state cached by [refresh]. */
    fun isBackground(appKey: String): Boolean? {
        if (!appKey.contains('.') || appKey.startsWith("uid:") || !permitted) return null
        if (!interactive) return true
        return appKey != current
    }
}
