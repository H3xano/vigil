package dev.vigil.inspector.vpn

import dev.vigil.inspector.engine.CaptureStats
import dev.vigil.inspector.engine.CaptureStreamStats
import dev.vigil.inspector.engine.StatsEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ServicePolicyTest {
    @Test
    fun foregroundIsKeptWhileANewerStartIsQueued() {
        // Start#1, then Stop#2 handled with nothing newer: leave the foreground.
        assertTrue(ServicePolicy.mayLeaveForeground(stoppingFor = 2, latestReceived = 2))
        // Quick Stop#2 -> Start#3: Start#3 already arrived, so Stop#2 must not
        // remove the foreground state Start#3 will run the VPN under.
        assertFalse(ServicePolicy.mayLeaveForeground(stoppingFor = 2, latestReceived = 3))
        // Revoke or a failure while handling Start#1 with Start#2 queued.
        assertFalse(ServicePolicy.mayLeaveForeground(stoppingFor = 1, latestReceived = 2))
        // A failure in the newest start: stop.
        assertTrue(ServicePolicy.mayLeaveForeground(stoppingFor = 3, latestReceived = 3))
    }

    @Test
    fun lockdownWarningOnlyWithAnExcludedProxyApp() {
        assertNull(ServicePolicy.lockdownWarning(null, lockdown = true))
        assertNull(ServicePolicy.lockdownWarning("org.torproject.android", lockdown = false))
        val w = ServicePolicy.lockdownWarning("org.torproject.android", lockdown = true, proxyLabel = "Orbot")!!
        assertTrue(w, w.startsWith("Orbot has no network"))
        assertTrue(w, w.contains("Block connections without VPN"))
        val unnamed = ServicePolicy.lockdownWarning("org.torproject.android", lockdown = true, proxyLabel = " ")!!
        assertTrue(unnamed, unnamed.startsWith("org.torproject.android has no network"))
        assertTrue(ServicePolicy.lockdownShort("org.torproject.android", "Orbot").startsWith("Orbot has no network"))
    }

    @Test
    fun connectedStreamClientsAreNamedInTheNotification() {
        assertNull(ServicePolicy.streamingNotice(null))
        assertNull(ServicePolicy.streamingNotice(StatsEvent()))
        val listening = CaptureStats(enabled = true, stream = CaptureStreamStats(listening = "127.0.0.1:57012"))
        assertNull(ServicePolicy.streamingNotice(StatsEvent(capture = listening)))
        val one = StatsEvent(capture = listening.copy(stream = listening.stream!!.copy(clients = 1)))
        assertEquals("Streaming packets to 1 Wireshark client on 127.0.0.1:57012", ServicePolicy.streamingNotice(one))
        val two = StatsEvent(capture = CaptureStats(enabled = true, stream = CaptureStreamStats(clients = 2)))
        assertEquals("Streaming packets to 2 Wireshark clients", ServicePolicy.streamingNotice(two))
    }
}
