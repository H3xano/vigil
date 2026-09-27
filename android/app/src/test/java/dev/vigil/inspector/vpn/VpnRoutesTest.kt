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
