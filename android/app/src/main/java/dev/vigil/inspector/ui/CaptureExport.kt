package dev.vigil.inspector.ui

import android.content.Context
import android.net.Uri
import dev.vigil.inspector.engine.PcapExportSummary
import dev.vigil.inspector.engine.PcapFilter
import dev.vigil.inspector.vpn.ActiveEngine
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** A packet export the user asked for: what to export, and from which session. */
data class PcapRequest(
    val filter: PcapFilter,
    /** Suggested file name (`.pcapng`). */
    val fileName: String,
    /**
     * Engine session the packets belong to (a flow's session), or null for
     * "whatever the running session holds". Packets of other sessions are
     * gone: capture lives in the engine's memory.
     */
    val session: Long? = null,
    /**
     * Time (ms) of the item exported when it has no session (an alert):
     * items from before the running session started are gone.
     */
    val itemTs: Long? = null,
    /** Only packets of the last this many ms before the export starts (sets the filter's `since_ms`). */
    val lastMs: Long? = null,
) {
    /** The filter at export time [now]. */
    fun filterAt(now: Long): PcapFilter = if (lastMs == null) filter else filter.copy(sinceMs = now - lastMs)
}

/** Why a [PcapRequest] cannot be served now (shown instead of the file picker), or null. */
object CaptureExport {
    fun unavailable(captureEnabled: Boolean, active: ActiveEngine?, request: PcapRequest): String? = when {
        !captureEnabled ->
            "Packet capture is off. Turn it on in Settings → Packet capture: vigil then keeps the most recent packets in memory, " +
                "and they can be exported from here. Packets from before it was on were not recorded."
        active == null -> "Inspection is not running. Packets are only held in memory while vigil inspects traffic."
        (request.session != null && request.session != active.session) || (request.itemTs != null && request.itemTs < active.session) ->
            "This is from an earlier inspection session. Packets are only held in memory for the running session, so they are gone."
        else -> null
    }

    /**
     * The export for an alert: its connection's packets when the alert names
     * one (`detail.flow_id`), else the app's packets around the alert (5
     * minutes before to 1 minute after). Null when it names neither.
     */
    fun forAlert(ts: Long, kind: String, uid: Int?, target: String, flowId: Long?): PcapRequest? = when {
        flowId != null -> PcapRequest(PcapFilter(flowIds = listOf(flowId)), fileName("alert-$kind-flow-$flowId"), itemTs = ts)
        uid != null -> PcapRequest(
            PcapFilter(uids = listOf(uid), sinceMs = ts - ALERT_BEFORE_MS, untilMs = ts + ALERT_AFTER_MS),
            fileName("alert-$kind-$target"),
            itemTs = ts,
        )
        else -> null
    }

    const val ALERT_BEFORE_MS = 5 * 60_000L
    const val ALERT_AFTER_MS = 60_000L

    /** A file name such as `vigil-flow-17-20260928-101500.pcapng`. */
    fun fileName(what: String, now: Long = System.currentTimeMillis()): String {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date(now))
        val safe = what.lowercase(Locale.US).replace(Regex("[^a-z0-9.-]+"), "-").trim('-').take(60)
        return "vigil-$safe-$stamp.pcapng"
    }

    /** The message after an export. */
    fun resultMessage(s: PcapExportSummary?): String = when {
        s == null -> "Export failed: the capture could not be written."
        s.packets == 0L && s.truncatedByRing ->
            "No packets exported: they were already overwritten in the capture buffer (a larger buffer keeps more)."
        s.packets == 0L -> "No captured packets match (capture may have been turned on after this traffic)."
        s.truncatedByRing ->
            "Exported ${plural(s.packets, "packet")} (${formatBytes(s.bytes)}). Older packets were already overwritten in the capture buffer."
        else -> "Exported ${plural(s.packets, "packet")} (${formatBytes(s.bytes)})."
    }

    /**
     * Blocking: exports into a private temporary file (the engine writes to a
     * path), copies it to [target] (a Storage Access Framework document) and
     * deletes the temporary file. Returns the message to show.
     */
    fun exportTo(context: Context, active: ActiveEngine, request: PcapRequest, target: Uri): String {
        val filter = request.filterAt(System.currentTimeMillis())
        val dir = File(context.cacheDir, "capture").apply { mkdirs() }
        val tmp = File.createTempFile("export-", ".pcapng", dir)
        return try {
            val summary = active.handle.exportPcap(filter, tmp.absolutePath)
                ?: return "Export failed: inspection stopped, or the capture could not be written."
            val out = context.contentResolver.openOutputStream(target, "wt")
                ?: return "Export failed: the chosen file could not be opened."
            out.use { o -> tmp.inputStream().use { it.copyTo(o, 256 * 1024) } }
            resultMessage(summary)
        } catch (e: Exception) {
            "Export failed: ${e.message ?: e.javaClass.simpleName}"
        } finally {
            tmp.delete()
        }
    }
}
