package dev.vigil.inspector.ui

import androidx.compose.runtime.Composable
import dev.vigil.inspector.R
import java.text.DateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone

fun formatBytes(b: Long): String {
    if (b < 1024) return "$b B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var v = b / 1024.0
    var i = 0
    while (v >= 1024 && i < units.size - 1) {
        v /= 1024
        i++
    }
    return if (v >= 100) String.format(Locale.US, "%.0f %s", v, units[i]) else String.format(Locale.US, "%.1f %s", v, units[i])
}

fun formatCount(n: Long): String = when {
    n >= 1_000_000 -> String.format(Locale.US, "%.1fM", n / 1_000_000.0)
    n >= 10_000 -> String.format(Locale.US, "%.0fk", n / 1000.0)
    n >= 1_000 -> String.format(Locale.US, "%.1fk", n / 1000.0)
    else -> n.toString()
}

/** "now", "30s ago", "5m ago", "2h ago", "3d ago". */
fun relativeTime(ts: Long, now: Long = System.currentTimeMillis()): UiText {
    val d = (now - ts).coerceAtLeast(0) / 1000
    fun ago(id: Int, n: Long) = UiText.plural(id, n.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), n)
    return when {
        d < 5 -> UiText.of(R.string.activity_time_now)
        d < 60 -> ago(R.plurals.activity_time_seconds_ago, d)
        d < 3600 -> ago(R.plurals.activity_time_minutes_ago, d / 60)
        d < 86_400 -> ago(R.plurals.activity_time_hours_ago, d / 3600)
        else -> ago(R.plurals.activity_time_days_ago, d / 86_400)
    }
}

@Composable
fun formatRelative(ts: Long, now: Long = System.currentTimeMillis()): String = relativeTime(ts, now).asString()

fun formatTime(ts: Long): String = DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(ts))

fun formatDateTime(ts: Long): String = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM).format(Date(ts))

/** Whether [a] and [b] (ms) fall on the same calendar day in [zone]. */
fun sameDay(a: Long, b: Long, zone: TimeZone = TimeZone.getDefault()): Boolean {
    val ca = Calendar.getInstance(zone).apply { timeInMillis = a }
    val cb = Calendar.getInstance(zone).apply { timeInMillis = b }
    return ca.get(Calendar.YEAR) == cb.get(Calendar.YEAR) && ca.get(Calendar.DAY_OF_YEAR) == cb.get(Calendar.DAY_OF_YEAR)
}

/** The time of a list row: the time alone today, with a short date on other days (paused or filtered lists reach back). */
fun formatRowTime(ts: Long, now: Long = System.currentTimeMillis()): String =
    if (sameDay(ts, now)) formatTime(ts) else DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM).format(Date(ts))

fun formatDuration(ms: Long): String = when {
    ms < 1000 -> "${ms} ms"
    ms < 60_000 -> String.format(Locale.US, "%.1f s", ms / 1000.0)
    ms < 3_600_000 -> "${ms / 60_000} min ${(ms / 1000) % 60} s"
    else -> "${ms / 3_600_000} h ${(ms / 60_000) % 60} min"
}
