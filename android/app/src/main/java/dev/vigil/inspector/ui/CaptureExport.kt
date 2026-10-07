package dev.vigil.inspector.ui

import android.content.Context
import android.net.Uri
import dev.vigil.inspector.R
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
    /**
     * [pickedSession] is the engine session when the user asked for the
     * file (checked again once the file is chosen): flow ids are per session,
     * so a flow filter must not be applied to a session started meanwhile.
     */
    fun unavailable(captureEnabled: Boolean, active: ActiveEngine?, request: PcapRequest, pickedSession: Long? = null): UiText? = when {
        !captureEnabled -> UiText.of(R.string.capture_unavailable_off)
        active == null -> UiText.of(R.string.capture_unavailable_not_running)
        (request.session != null && request.session != active.session) || (request.itemTs != null && request.itemTs < active.session) ->
            UiText.of(R.string.capture_unavailable_earlier_session)
        pickedSession != null && pickedSession != active.session && request.filter.flowIds.isNotEmpty() ->
            UiText.of(R.string.capture_unavailable_restarted)
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
    fun resultMessage(s: PcapExportSummary?): UiText = when {
        s == null -> UiText.of(R.string.capture_export_failed_write)
        s.packets == 0L && s.truncatedByRing -> UiText.of(R.string.capture_export_none_overwritten)
        s.packets == 0L -> UiText.of(R.string.capture_export_none_match)
        else -> UiText.plural(
            if (s.truncatedByRing) R.plurals.capture_exported_truncated else R.plurals.capture_exported,
            s.packets.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), s.packets, formatBytes(s.bytes),
        )
    }

    /**
     * Blocking: exports into a private temporary file (the engine writes to a
     * path), copies it to [target] (a Storage Access Framework document) and
     * deletes the temporary file. Returns the message to show.
     */
    fun exportTo(context: Context, active: ActiveEngine, request: PcapRequest, target: Uri): UiText {
        val filter = request.filterAt(System.currentTimeMillis())
        val dir = tempDir(context)
        deleteStaleTemp(dir)
        var tmp: File? = null
        var ok = false
        return try {
            dir.mkdirs()
            val file = File.createTempFile("export-", ".pcapng", dir).also { tmp = it }
            val summary = active.handle.exportPcap(filter, file.absolutePath)
                ?: return UiText.of(R.string.capture_export_failed_stopped)
            val out = context.contentResolver.openOutputStream(target, "wt")
                ?: return UiText.of(R.string.capture_export_failed_open)
            out.use { o -> file.inputStream().use { it.copyTo(o, 256 * 1024) } }
            ok = true
            resultMessage(summary)
        } catch (e: Exception) {
            UiText.of(R.string.capture_export_failed, e.message ?: e.javaClass.simpleName)
        } finally {
            tmp?.delete()
            // Do not leave an empty or partial file behind.
            if (!ok) discardDocument(context, target)
        }
    }

    /** Where exports are written before being copied to the chosen document. */
    private fun tempDir(context: Context) = File(context.cacheDir, "capture")

    /** Temporary files older than this are left over from an export that was interrupted (process killed). */
    const val STALE_TEMP_MS = 60 * 60_000L

    /** Deletes leftover temporary export files (older than [STALE_TEMP_MS]); called at app start and before each export. */
    fun deleteStaleTemp(context: Context) = deleteStaleTemp(tempDir(context))

    fun deleteStaleTemp(dir: File, now: Long = System.currentTimeMillis()) {
        dir.listFiles()?.forEach { f -> if (f.isFile && now - f.lastModified() > STALE_TEMP_MS) f.delete() }
    }
}
