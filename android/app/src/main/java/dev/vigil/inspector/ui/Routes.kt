package dev.vigil.inspector.ui

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.transform

/** Navigation routes that may be requested from outside (intent extra `destination`). */
object Routes {
    val TOP_LEVEL = setOf("dashboard", "activity", "apps", "alerts", "settings", "feeds", "export", "rules", "dns", "upstream")

    /** App keys are package names, "uid:<n>" or "unknown". */
    private val APP_KEY = Regex("^[A-Za-z0-9_.:]{1,255}$")
    private val FLOW_ID = Regex("^[0-9]{1,18}$")

    /**
     * Returns [route] if it names a screen of this app, otherwise null. The
     * main activity is exported, so any app can send an arbitrary string.
     */
    fun sanitize(route: String?): String? {
        if (route == null) return null
        if (route in TOP_LEVEL) return route
        val slash = route.indexOf('/')
        if (slash <= 0) return null
        val arg = route.substring(slash + 1)
        return when (route.substring(0, slash)) {
            "app" -> route.takeIf { APP_KEY.matches(arg) }
            "flow" -> route.takeIf { FLOW_ID.matches(arg) && arg.toLongOrNull() != null }
            else -> null
        }
    }
}

/**
 * Emits the first value at once, then at most one value per [periodMs]
 * (always the latest), so bursts of database invalidations under heavy
 * traffic do not re-run expensive queries many times a second.
 */
fun <T> Flow<T>.throttleLatest(periodMs: Long): Flow<T> = conflate().transform {
    emit(it)
    delay(periodMs)
}
