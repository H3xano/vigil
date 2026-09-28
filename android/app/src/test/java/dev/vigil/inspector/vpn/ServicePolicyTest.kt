package dev.vigil.inspector.vpn

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
}
