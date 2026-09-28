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
    private val state = ForegroundState()
    @Volatile private var permitted = false
    @Volatile private var interactive = true
    private var lastQuery = 0L
    private var lastRefresh = 0L

    fun hasPermission(): Boolean {
        val ops = context.getSystemService(AppOpsManager::class.java)
        return ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName) ==
            AppOpsManager.MODE_ALLOWED
    }

    /** Folds new usage events into the current foreground package (at most every [minIntervalMs]). */
    @Synchronized
    fun refresh(minIntervalMs: Long = 2_000) {
        val now = System.currentTimeMillis()
        if (now - lastRefresh < minIntervalMs) return
        lastRefresh = now
        permitted = hasPermission()
        interactive = power.isInteractive
        if (!permitted) return
        // The app on screen may have been resumed long ago: look back far on
        // the first query. Until a resume is seen, the foreground app is unknown.
        val from = if (lastQuery == 0L) now - ForegroundState.INITIAL_LOOKBACK_MS else lastQuery
        val events = runCatching { usm.queryEvents(from, now) }.getOrNull() ?: return
        val e = UsageEvents.Event()
        while (events.hasNextEvent()) {
            events.getNextEvent(e)
            when (e.eventType) {
                UsageEvents.Event.ACTIVITY_RESUMED -> state.resumed(e.packageName)
                UsageEvents.Event.ACTIVITY_PAUSED -> state.paused(e.packageName)
            }
        }
        lastQuery = now
    }

    /**
     * true/false for installed packages when known, null when undeterminable
     * (no usage access, or the foreground app is not known yet). Uses state
     * cached by [refresh]. For flow tagging.
     */
    fun isBackground(appKey: String): Boolean? = state.isBackground(appKey, permitted, interactive)

    /**
     * For [ExfilDetector]: like [isBackground], but while usage access is
     * granted and the foreground app is not known yet, uploads are treated as
     * foreground (not counted) instead of unknown, so the app on screen is
     * never reported as uploading in the background. null only without
     * usage access (the detector then counts uploads as "unknown").
     */
    fun isBackgroundForExfil(appKey: String): Boolean? = state.isBackgroundForExfil(appKey, permitted, interactive)

    /**
     * For the per-app background rules: refreshes (at most every
     * [minIntervalMs]) and returns the foreground package, "" when no app is
     * in the foreground, or null when that is unknown (no usage access, or
     * no app resumed since tracking started).
     */
    fun foregroundPackage(minIntervalMs: Long): String? {
        refresh(minIntervalMs)
        return state.foreground(permitted)
    }
}

/**
 * The foreground app as folded from usage events. Pure, so it is testable;
 * [ForegroundTracker] owns one.
 */
class ForegroundState {
    @Volatile private var current: String? = null

    /** False until the first ACTIVITY_RESUMED: before that, "not current" means nothing. */
    @Volatile var known = false
        private set

    fun resumed(pkg: String) {
        current = pkg
        known = true
    }

    fun paused(pkg: String) {
        if (pkg == current) current = null
    }

    /** The foreground package, "" for none, null when unknown (see [ForegroundTracker.foregroundPackage]). */
    fun foreground(permitted: Boolean): String? = if (!permitted || !known) null else current.orEmpty()

    fun isBackground(appKey: String, permitted: Boolean, interactive: Boolean): Boolean? {
        if (!appKey.contains('.') || appKey.startsWith("uid:") || !permitted) return null
        if (!interactive) return true
        if (!known) return null
        return appKey != current
    }

    fun isBackgroundForExfil(appKey: String, permitted: Boolean, interactive: Boolean): Boolean? {
        val bg = isBackground(appKey, permitted, interactive)
        return if (bg == null && permitted && !known && appKey.contains('.') && !appKey.startsWith("uid:")) false else bg
    }

    companion object {
        /** First usage-events query: the app on screen may have been opened hours ago. */
        const val INITIAL_LOOKBACK_MS = 24L * 3600 * 1000
    }
}
