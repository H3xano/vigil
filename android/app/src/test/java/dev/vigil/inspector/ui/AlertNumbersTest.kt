package dev.vigil.inspector.ui

import dev.vigil.inspector.ui.screens.alertNumbers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AlertNumbersTest {
    @Test
    fun beaconDetails() {
        assertEquals(
            "Inside one open connection to c2.example: a burst of about 512 B every 30.0 s ± 1.5 s (8 bursts)",
            alertNumbers(
                "beacon",
                """{"kind":"intra_flow","interval_s":30.0,"jitter":0.05,"samples":8,"burst_bytes":512,"domain":"c2.example","dst":"192.0.2.1:443"}""",
            ),
        )
        assertEquals(
            "A new connection every 60.0 s ± 3.0 s (6 connections)",
            alertNumbers("beacon", """{"kind":"connections","interval_s":60.0,"jitter":0.05,"samples":6,"proto":"tcp"}"""),
        )
        // Alerts stored by older versions (no kind) read as connection beacons.
        assertEquals("A new connection every 120 s ± 0.0 s", alertNumbers("beacon", """{"interval_s":120.0,"jitter":0}"""))
    }

    @Test
    fun exfilDetails() {
        assertEquals(
            "Uploaded 60.0 MB in 5 min; usual busiest hour 4.0 MB (alerts above 3× that); floor 25.0 MB\n" +
                "To drop.example: 58.0 MB sent, 1.0 MB received",
            alertNumbers(
                "exfil_volume",
                """{"window":"5 min","uploaded_bytes":62914560,"baseline_bytes_per_hour":4194304,"floor_bytes":26214400,"factor":3.0,
                   "destination":"drop.example","dest_tx_bytes":60817408,"dest_rx_bytes":1048576}""",
            ),
        )
        assertEquals(
            "Uploaded 60.0 MB in 1 h; no upload history yet; floor 50.0 MB",
            alertNumbers("exfil_volume", """{"window":"1 h","uploaded_bytes":62914560,"baseline_bytes_per_hour":null,"floor_bytes":52428800}"""),
        )
    }

    @Test
    fun otherKindsAndBadDetails() {
        assertNull(alertNumbers("threat_domain", """{"x":1}"""))
        assertNull(alertNumbers("beacon", "not json"))
        assertNull(alertNumbers("exfil_volume", "{}"))
    }
}
