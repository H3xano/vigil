package dev.vigil.inspector.ui

import dev.vigil.inspector.R
import dev.vigil.inspector.data.SettingsCodec
import dev.vigil.inspector.engine.EngineHandle
import dev.vigil.inspector.engine.PcapExportSummary
import dev.vigil.inspector.engine.PcapFilter
import dev.vigil.inspector.vpn.ActiveEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class CaptureExportTest {
    private val active = ActiveEngine(session = 1_000_000L, handle = EngineHandle(0L))

    @Test
    fun explainsWhyPacketsAreUnavailable() {
        val flow = PcapRequest(PcapFilter(flowIds = listOf(3)), "f.pcapng", session = 1_000_000L)
        assertEquals(UiText.of(R.string.capture_unavailable_off), CaptureExport.unavailable(false, active, flow))
        assertEquals(UiText.of(R.string.capture_unavailable_not_running), CaptureExport.unavailable(true, null, flow))
        assertNull(CaptureExport.unavailable(true, active, flow))
        val earlier = UiText.of(R.string.capture_unavailable_earlier_session)
        assertEquals(earlier, CaptureExport.unavailable(true, active, flow.copy(session = 5L)))
        // Alerts carry a time instead of a session.
        val alert = CaptureExport.forAlert(999_999L, "beacon", 10123, "c2.example", 17)!!
        assertEquals(earlier, CaptureExport.unavailable(true, active, alert))
        assertNull(CaptureExport.unavailable(true, active, alert.copy(itemTs = 1_000_001L)))
    }

    @Test
    fun alertFilters() {
        val byFlow = CaptureExport.forAlert(2_000_000L, "beacon", 10123, "c2.example", 17)!!
        assertEquals(PcapFilter(flowIds = listOf(17)), byFlow.filter)
        val byApp = CaptureExport.forAlert(2_000_000L, "threat_domain", 10123, "bad.example", null)!!
        assertEquals(listOf(10123), byApp.filter.uids)
        assertEquals(2_000_000L - 300_000L, byApp.filter.sinceMs)
        assertEquals(2_060_000L, byApp.filter.untilMs)
        assertTrue(byApp.fileName, byApp.fileName.startsWith("vigil-alert-threat_domain-bad.example-".replace('_', '-')))
        assertNull(CaptureExport.forAlert(2_000_000L, "threat_domain", null, "bad.example", null))
    }

    @Test
    fun appWindowIsTakenAtExportTime() {
        val r = PcapRequest(PcapFilter(uids = listOf(10123)), "a.pcapng", lastMs = 60_000L)
        assertEquals(PcapFilter(uids = listOf(10123), sinceMs = 40_000L), r.filterAt(100_000L))
        assertEquals(r.filter, r.copy(lastMs = null).filterAt(100_000L))
    }

    @Test
    fun namesAndMessages() {
        val name = CaptureExport.fileName("Flow 17 / Example.COM", now = 0L)
        assertTrue(name, Regex("vigil-flow-17-example\\.com-\\d{8}-\\d{6}\\.pcapng").matches(name))
        assertEquals(
            UiText.plural(R.plurals.capture_exported, 12, 12L, formatBytes(2048)),
            CaptureExport.resultMessage(PcapExportSummary(packets = 12, bytes = 2048)),
        )
        assertEquals(
            UiText.plural(R.plurals.capture_exported_truncated, 1, 1L, formatBytes(60)),
            CaptureExport.resultMessage(PcapExportSummary(packets = 1, bytes = 60, truncatedByRing = true)),
        )
        assertEquals(UiText.of(R.string.capture_export_none_match), CaptureExport.resultMessage(PcapExportSummary()))
        assertEquals(
            UiText.of(R.string.capture_export_none_overwritten),
            CaptureExport.resultMessage(PcapExportSummary(truncatedByRing = true)),
        )
        assertEquals(UiText.of(R.string.capture_export_failed_write), CaptureExport.resultMessage(null))
    }

    @Test
    fun captureSettingsDefaultOffAndSurviveOldDocuments() {
        // Settings stored before packet capture existed decode with capture off.
        val old = SettingsCodec.decode("""{"sinkhole":"nxdomain","deviceId":"x"}""")
        assertFalse(old.unreadable)
        assertFalse(old.settings.capture.enabled)
        assertFalse(old.settings.capture.streamEnabled)
        assertEquals("wifi", old.settings.capture.streamBind)
        val s = old.settings.copy(capture = old.settings.capture.copy(enabled = true, streamAllow = listOf("192.168.1.10")))
        assertEquals(s, SettingsCodec.decode(SettingsCodec.encode(s)).settings)
    }

    @Test
    fun flowExportRefusedWhenInspectionRestartedWhilePicking() {
        val flowAlert = CaptureExport.forAlert(999_999L, "beacon", 10123, "c2.example", 17)!!
        val restarted = ActiveEngine(session = 2_000_000L, handle = EngineHandle(0L))
        // Picked during session 1 000 000; the alert is older than the new session anyway.
        assertEquals(UiText.of(R.string.capture_unavailable_earlier_session), CaptureExport.unavailable(true, restarted, flowAlert, 1_000_000L))
        // Flow ids are per session: a flow filter is refused once the engine changed.
        val flow = PcapRequest(PcapFilter(flowIds = listOf(3)), "f.pcapng", itemTs = 2_500_000L)
        assertEquals(UiText.of(R.string.capture_unavailable_restarted), CaptureExport.unavailable(true, restarted, flow, 1_000_000L))
        assertNull(CaptureExport.unavailable(true, restarted, flow, 2_000_000L))
        // An app window is valid in any session.
        val app = PcapRequest(PcapFilter(uids = listOf(10123)), "a.pcapng", lastMs = 60_000L)
        assertNull(CaptureExport.unavailable(true, restarted, app, 1_000_000L))
        assertEquals(UiText.of(R.string.capture_unavailable_not_running), CaptureExport.unavailable(true, null, app, 1_000_000L))
    }

    @Test
    fun staleTemporaryFilesAreDeleted() {
        val dir = java.nio.file.Files.createTempDirectory("capture").toFile()
        try {
            val now = 10 * CaptureExport.STALE_TEMP_MS
            val old = File(dir, "export-old.pcapng").apply { writeText("x"); setLastModified(now - CaptureExport.STALE_TEMP_MS - 1000) }
            val fresh = File(dir, "export-new.pcapng").apply { writeText("x"); setLastModified(now - 60_000) }
            CaptureExport.deleteStaleTemp(dir, now)
            assertFalse(old.exists())
            assertTrue(fresh.exists())
            // A missing directory is fine.
            CaptureExport.deleteStaleTemp(File(dir, "missing"), now)
        } finally {
            dir.deleteRecursively()
        }
    }
}
