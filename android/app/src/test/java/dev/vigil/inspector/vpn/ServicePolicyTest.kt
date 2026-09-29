package dev.vigil.inspector.vpn

import dev.vigil.inspector.R
import dev.vigil.inspector.engine.CaptureStats
import dev.vigil.inspector.engine.CaptureStreamStats
import dev.vigil.inspector.engine.StatsEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import dev.vigil.inspector.ui.UiText
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
        assertEquals(
            UiText.of(R.string.vpn_lockdown_warning, "Orbot"),
            ServicePolicy.lockdownWarning("org.torproject.android", lockdown = true, proxyLabel = "Orbot"),
        )
        assertEquals(
            UiText.of(R.string.vpn_lockdown_warning, "org.torproject.android"),
            ServicePolicy.lockdownWarning("org.torproject.android", lockdown = true, proxyLabel = " "),
        )
        assertEquals(UiText.of(R.string.vpn_lockdown_short, "Orbot"), ServicePolicy.lockdownShort("org.torproject.android", "Orbot"))
    }

    @Test
    fun connectedStreamClientsAreNamedInTheNotification() {
        assertNull(ServicePolicy.streamingNotice(null))
        assertNull(ServicePolicy.streamingNotice(StatsEvent()))
        val listening = CaptureStats(enabled = true, stream = CaptureStreamStats(listening = "127.0.0.1:57012"))
        assertNull(ServicePolicy.streamingNotice(StatsEvent(capture = listening)))
        val one = StatsEvent(capture = listening.copy(stream = listening.stream!!.copy(clients = 1)))
        assertEquals(UiText.plural(R.plurals.vpn_streaming_clients_on, 1, 1L, "127.0.0.1:57012"), ServicePolicy.streamingNotice(one))
        val two = StatsEvent(capture = CaptureStats(enabled = true, stream = CaptureStreamStats(clients = 2)))
        assertEquals(UiText.plural(R.plurals.vpn_streaming_clients, 2, 2L), ServicePolicy.streamingNotice(two))
    }
}
