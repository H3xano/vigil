package dev.vigil.inspector.processing

import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.data.AppResolver
import dev.vigil.inspector.engine.AlertEvent
import dev.vigil.inspector.engine.EngineEvent
import dev.vigil.inspector.engine.FlowEndEvent
import dev.vigil.inspector.engine.FlowEvent
import dev.vigil.inspector.engine.FlowUpdateEvent
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class ExfilDetectorTest {
    private val mb = ExfilRules.MB
    private val hour = ExfilRules.HOUR_MS
    /** An hour boundary, so tests control which hour slot data lands in. */
    private val t0 = 1_700_000_000_000L / hour * hour + 10 * 60_000

    private val apps = mapOf(10100 to "com.example.app", 10200 to "com.google.android.apps.photos")
    private val resolve: (Int?) -> AppInfo = { uid ->
        apps[uid]?.let { AppInfo(it, uid, it.substringAfterLast('.'), isSystem = false, isInstalledPackage = true) }
            ?: AppResolver.UNKNOWN
    }

    /** Drives one detector with synthetic flows. */
    private inner class Sim(file: File? = null, val settings: ExfilSettings = ExfilSettings()) {
        val d = ExfilDetector(file)
        var nextId = 1L
        val alerts = ArrayList<AlertEvent>()

        /**
         * One flow of [uid] to [dest], starting at [start], sending [tx] and
         * receiving [rx] bytes evenly over [durationMs] (updates every 2 s).
         */
        fun flow(
            start: Long, durationMs: Long, tx: Long, rx: Long = tx / 100, uid: Int = 10100, dest: String = "drop.example",
            background: Boolean? = true, session: Long = 1,
        ) {
            val id = nextId++
            val bg: (String) -> Boolean? = { background }
            val open = FlowEvent(id = id, ts = start, proto = "tcp", uid = uid, src = "10.111.222.1:40000", dstIp = "192.0.2.7",
                dstPort = 443, domain = dest, verdict = "allow")
            alerts += d.process(session, listOf(open), settings, resolve, bg, start)
            val steps = (durationMs / 2_000).coerceAtLeast(1)
            for (i in 1..steps) {
                val ts = start + i * 2_000
                val ev: EngineEvent = if (i == steps) {
                    FlowEndEvent(id, ts, tx, rx, durationMs)
                } else {
                    FlowUpdateEvent(id, ts, tx * i / steps, rx * i / steps)
                }
                alerts += d.process(session, listOf(ev), settings, resolve, bg, ts)
            }
        }
    }

    @Test
    fun slotRingWindowsAndStaleSlots() {
        val r = SlotRing(60, 60_000)
        r.add(t0, 5)
        r.add(t0 + 30_000, 5)
        r.add(t0 + 4 * 60_000, 7)
        assertEquals(17, r.sum(t0 + 4 * 60_000, 5 * 60_000))
        assertEquals(7, r.sum(t0 + 4 * 60_000, 60_000))
        // An hour later the slots are stale even though they were never overwritten.
        assertEquals(0, r.sum(t0 + 2 * hour, hour))
        // Events older than the slot they would land in are ignored.
        r.add(t0 + 61 * 60_000, 1)
        r.add(t0 + 60_000, 100)
        assertEquals(1 + 7L, r.sum(t0 + 61 * 60_000, hour))
    }

    @Test
    fun p95NeedsHistory() {
        assertNull(ExfilRules.p95(listOf(1, 2)))
        assertEquals(3L, ExfilRules.p95(listOf(1, 2, 3)))
        assertEquals(95L, ExfilRules.p95((1L..100L).toList()))
    }

    @Test
    fun rules() {
        val floor = 50 * mb
        assertFalse("below the floor", ExfilRules.isUnusual(49 * mb, floor, null, 3.0, 49 * mb, 0))
        assertTrue("above the floor, no history", ExfilRules.isUnusual(60 * mb, floor, null, 3.0, 60 * mb, 1 * mb))
        assertFalse("within 3x the baseline", ExfilRules.isUnusual(60 * mb, floor, 30 * mb, 3.0, 60 * mb, 0))
        assertTrue("above 3x the baseline", ExfilRules.isUnusual(100 * mb, floor, 30 * mb, 3.0, 100 * mb, 0))
        assertFalse("a tiny baseline never lowers the floor", ExfilRules.isUnusual(10 * mb, floor, 1, 3.0, 10 * mb, 0))
        assertFalse("two-way traffic (video call)", ExfilRules.isUnusual(60 * mb, floor, null, 3.0, 60 * mb, 55 * mb))
        assertTrue("4:1 is enough", ExfilRules.isUnusual(60 * mb, floor, null, 3.0, 60 * mb, 15 * mb))
    }

    @Test
    fun backgroundBulkUploadAlertsOnce() {
        val s = Sim()
        s.flow(t0, 8 * 60_000, 60 * mb)
        assertEquals(1, s.alerts.size)
        val a = s.alerts[0]
        assertEquals("exfil_volume", a.kind)
        assertEquals("medium", a.severity)
        assertEquals("drop.example", a.target)
        assertEquals(10100, a.uid)
        val d = a.detail as JsonObject
        assertEquals("5 min", d["window"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, d["baseline_bytes_per_hour"])
        assertEquals("yes", d["background"]!!.jsonPrimitive.content)
        assertTrue(d["uploaded_bytes"]!!.jsonPrimitive.long >= 25 * mb)
        assertTrue(a.message, a.message.startsWith("app uploaded ") && "background" in a.message)
        // More upload within the re-alert period: no second alert.
        s.flow(t0 + 10 * 60_000, 10 * 60_000, 100 * mb)
        assertEquals(1, s.alerts.size)
        // After it, the ongoing upload alerts again.
        s.flow(t0 + 7 * hour, 10 * 60_000, 100 * mb)
        assertEquals(2, s.alerts.size)
    }

    @Test
    fun foregroundUploadsNeverAlert() {
        val s = Sim()
        s.flow(t0, 10 * 60_000, 500 * mb, background = false)
        assertTrue(s.alerts.isEmpty())
    }

    @Test
    fun appOnScreenBeforeTrackingStartedIsNotBackground() {
        // Usage access granted, but the app on screen resumed before the
        // tracker's first query: its uploads must not alert (they did, when
        // "not the current app" counted as background).
        val fg = ForegroundState()
        val s = Sim()
        s.flow(t0, 10 * 60_000, 500 * mb, background = fg.isBackgroundForExfil("com.example.app", permitted = true, interactive = true))
        assertTrue(s.alerts.toString(), s.alerts.isEmpty())
        // Once another app is known to be on screen, the same upload alerts.
        fg.resumed("com.example.chat")
        s.flow(t0 + 20 * 60_000, 10 * 60_000, 500 * mb, background = fg.isBackgroundForExfil("com.example.app", true, true))
        assertEquals(1, s.alerts.size)
    }

    @Test
    fun unknownForegroundStateAlertsAtLowSeverity() {
        val s = Sim()
        s.flow(t0, 10 * 60_000, 100 * mb, background = null)
        assertEquals(1, s.alerts.size)
        assertEquals("low", s.alerts[0].severity)
        assertEquals("unknown", (s.alerts[0].detail as JsonObject)["background"]!!.jsonPrimitive.content)
    }

    @Test
    fun absoluteFloorSpreadOverTheHour() {
        val s = Sim()
        // 45 MB over an hour: below the 50 MB/h floor and never 25 MB in 5 minutes.
        s.flow(t0, 55 * 60_000, 45 * mb)
        assertTrue(s.alerts.isEmpty())
        // A lower floor from the settings catches it.
        val low = Sim(settings = ExfilSettings(floorMbPerHour = 20))
        low.flow(t0, 55 * 60_000, 45 * mb)
        assertEquals(1, low.alerts.size)
        assertEquals("1 h", (low.alerts[0].detail as JsonObject)["window"]!!.jsonPrimitive.content)
    }

    @Test
    fun disabledSettingSuppresses() {
        val s = Sim(settings = ExfilSettings(enabled = false))
        s.flow(t0, 8 * 60_000, 200 * mb)
        assertTrue(s.alerts.isEmpty())
    }

    @Test
    fun appBaselineRaisesTheBar() {
        val s = Sim()
        // The app regularly uploads ~40 MB/h in the foreground (its baseline).
        for (h in 1..5) s.flow(t0 - h * hour, 20 * 60_000, 40 * mb, background = false)
        assertEquals(40 * mb, s.d.baseline("com.example.app", t0))
        // 100 MB in the background: above the floor but below 3 x 40 MB.
        s.flow(t0, 30 * 60_000, 100 * mb)
        assertTrue(s.alerts.toString(), s.alerts.isEmpty())
        // 200 MB within the hour is unusual even for this app.
        s.flow(t0 + 31 * 60_000, 20 * 60_000, 200 * mb)
        assertEquals(1, s.alerts.size)
        assertEquals(40 * mb, (s.alerts[0].detail as JsonObject)["baseline_bytes_per_hour"]!!.jsonPrimitive.long)
    }

    @Test
    fun twoWayTrafficAndTrustedUploadersAreIgnored() {
        val s = Sim()
        s.flow(t0, 10 * 60_000, 100 * mb, rx = 90 * mb) // video call
        s.flow(t0, 10 * 60_000, 300 * mb, uid = 10200, dest = "photos.googleapis.com")
        s.flow(t0, 10 * 60_000, 300 * mb, uid = 99999) // unattributed
        assertTrue(s.alerts.toString(), s.alerts.isEmpty())
    }

    @Test
    fun baselinePersistsAcrossInstances() {
        val dir = Files.createTempDirectory("exfil").toFile()
        try {
            val file = File(dir, "baseline.json")
            val s = Sim(file)
            for (h in 1..4) s.flow(t0 - h * hour, 10 * 60_000, 30 * mb, background = false)
            s.d.endSession(1, t0)
            assertTrue(file.exists())
            val again = ExfilDetector(file)
            assertEquals(30 * mb, again.baseline("com.example.app", t0))
            assertNull(ExfilDetector(File(dir, "missing.json")).baseline("com.example.app", t0))
            // A corrupt file is ignored.
            file.writeText("{not json")
            assertNull(ExfilDetector(file).baseline("com.example.app", t0))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun flowIdsAreScopedBySession() {
        val s = Sim()
        val bg: (String) -> Boolean? = { true }
        val open = FlowEvent(id = 1, ts = t0, proto = "tcp", uid = 10100, src = "a", dstIp = "192.0.2.1", dstPort = 443)
        s.d.process(1, listOf(open), s.settings, resolve, bg, t0)
        // Session 2 reuses id 1 without a flow event: an orphan, not session 1's flow.
        assertTrue(s.d.process(2, listOf(FlowUpdateEvent(1, t0 + 1000, 500 * mb, 0)), s.settings, resolve, bg, t0 + 1000).isEmpty())
        assertNull(s.d.baseline("com.example.app", t0 + 2 * hour))
        assertNotNull(s.d.process(1, listOf(FlowEndEvent(1, t0 + 1000, 60 * mb, 0)), s.settings, resolve, bg, t0 + 1000).singleOrNull())
    }
}
