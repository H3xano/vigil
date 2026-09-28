package dev.vigil.inspector.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnRoutesTest {
    private fun toLong(a: String) = a.split('.').fold(0L) { acc, p -> (acc shl 8) or p.toLong() }

    private fun covers(routes: List<VpnRoutes.Cidr>, ip: String): Boolean {
        val v = toLong(ip)
        return routes.any { r ->
            val size = 1L shl (32 - r.prefix)
            val start = toLong(r.address)
            v >= start && v < start + size
        }
    }

    @Test
    fun fullTunnelWhenLanIncluded() {
        assertEquals(listOf(VpnRoutes.Cidr("0.0.0.0", 0)), VpnRoutes.ipv4(excludeLan = false))
        assertEquals(listOf(VpnRoutes.Cidr("::", 0)), VpnRoutes.ipv6(excludeLan = false))
    }

    @Test
    fun excludesPrivateRangesButKeepsVirtualResolver() {
        val r = VpnRoutes.ipv4(excludeLan = true)
        for (ip in listOf("1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "192.169.0.1", "223.255.255.255", "11.0.0.1")) {
            assertTrue("$ip must be tunnelled", covers(r, ip))
        }
        for (ip in listOf("10.0.0.5", "192.168.1.10", "172.16.4.4", "172.31.255.255", "169.254.1.1", "127.0.0.1", "224.0.0.251", "100.64.1.1")) {
            assertFalse("$ip must stay direct", covers(r, ip))
        }
        assertTrue("virtual DNS", covers(r, "10.111.222.2"))
    }

    @Test
    fun routesAreValidCidrs() {
        for (c in VpnRoutes.ipv4(excludeLan = true)) {
            val size = 1L shl (32 - c.prefix)
            assertEquals("$c aligned", 0L, toLong(c.address) % size)
        }
    }

    @Test
    fun rangeToCidrsIsMinimal() {
        assertEquals(listOf(VpnRoutes.Cidr("10.0.0.0", 8)), VpnRoutes.rangeToCidrs(toLong("10.0.0.0")..toLong("10.255.255.255")))
        assertEquals(
            listOf(VpnRoutes.Cidr("0.0.0.1", 32), VpnRoutes.Cidr("0.0.0.2", 31)),
            VpnRoutes.rangeToCidrs(1L..3L),
        )
    }
}

class VpnRoutesV6Test {
    private fun big(a: String) = VpnRoutes.v6ToBig(a)

    private fun covers(routes: List<VpnRoutes.Cidr>, ip: String): Boolean {
        val v = big(ip)
        return routes.any { r ->
            val start = big(r.address)
            val size = java.math.BigInteger.ONE.shiftLeft(128 - r.prefix)
            v >= start && v < start + size
        }
    }

    @Test
    fun tunnelsEverythingButLocalRanges() {
        val r = VpnRoutes.ipv6(excludeLan = true)
        for (ip in listOf("64:ff9b::808:808", "64:ff9b:1::1", "2001:4860:4860::8888", "2606:4700::1111", "::ffff:1.2.3.4", "4000::1", "fec0::1")) {
            assertTrue("$ip must be tunnelled", covers(r, ip))
        }
        for (ip in listOf("fe80::1", "febf:ffff::1", "fd00::1", "fc12::5", "ff02::fb", "ff05::1:3")) {
            assertFalse("$ip must stay direct", covers(r, ip))
        }
        assertTrue("virtual DNS", covers(r, "fd76:6967:696c::2"))
    }

    @Test
    fun routesAreAlignedAndFew() {
        val r = VpnRoutes.ipv6(excludeLan = true)
        assertTrue("${r.size} routes", r.size <= 12)
        for (c in r) {
            val size = java.math.BigInteger.ONE.shiftLeft(128 - c.prefix)
            assertEquals("$c aligned", java.math.BigInteger.ZERO, big(c.address).mod(size))
        }
    }

    @Test
    fun extraNat64PrefixInUlaSpaceIsTunnelled() {
        val r = VpnRoutes.ipv6(excludeLan = true, extra = listOf("fd00:64::/96", "64:ff9b::/96", "garbage"))
        assertTrue(covers(r, "fd00:64::102:304"))
        assertFalse(covers(r, "fd00:65::1"))
        assertEquals("global prefix already covered, not duplicated", VpnRoutes.ipv6(true).size + 1, r.size)
        assertEquals(listOf(VpnRoutes.Cidr("::", 0)), VpnRoutes.ipv6(excludeLan = false, extra = listOf("fd00:64::/96")))
    }

    /** The service restarts the session when [VpnRoutes.all] changes (routes are fixed at establish()). */
    @Test
    fun routeSetChangesOnlyWithRouteRelevantNat64Prefixes() {
        val base = VpnRoutes.all(excludeLan = true)
        // A NAT64 prefix in ULA space needs an extra route: a restart.
        assertTrue(VpnRoutes.all(true, listOf("fd00:64::/96")) != base)
        assertTrue(VpnRoutes.all(true, listOf("fd00:64::/96")) != VpnRoutes.all(true, listOf("fd00:65::/96")))
        // Prefixes already tunnelled, or unparseable, change nothing: no restart.
        assertEquals(base, VpnRoutes.all(true, listOf("64:ff9b::/96")))
        assertEquals(base, VpnRoutes.all(true, listOf("2001:db8:64::/96", "bogus")))
        // Without LAN exclusion everything is tunnelled anyway.
        assertEquals(VpnRoutes.all(false), VpnRoutes.all(false, listOf("fd00:64::/96")))
        assertTrue(VpnRoutes.all(false) != base)
        assertEquals(VpnRoutes.ipv4(true) + VpnRoutes.ipv6(true, listOf("fd00:64::/96")), VpnRoutes.all(true, listOf("fd00:64::/96")))
    }
}
