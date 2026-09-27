package dev.vigil.inspector.ui

import java.text.DateFormat
import java.util.Date
import java.util.Locale

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

fun formatRelative(ts: Long, now: Long = System.currentTimeMillis()): String {
    val d = (now - ts).coerceAtLeast(0) / 1000
    return when {
        d < 5 -> "now"
        d < 60 -> "${d}s ago"
        d < 3600 -> "${d / 60}m ago"
        d < 86_400 -> "${d / 3600}h ago"
        else -> "${d / 86_400}d ago"
    }
}

fun formatTime(ts: Long): String = DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(ts))

fun formatDateTime(ts: Long): String = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM).format(Date(ts))

fun formatDuration(ms: Long): String = when {
    ms < 1000 -> "${ms} ms"
    ms < 60_000 -> String.format(Locale.US, "%.1f s", ms / 1000.0)
    ms < 3_600_000 -> "${ms / 60_000} min ${(ms / 1000) % 60} s"
    else -> "${ms / 3_600_000} h ${(ms / 60_000) % 60} min"
}
