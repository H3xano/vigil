package dev.vigil.inspector.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpMatchTest {
    private fun key(s: String) = IpAddrs.key(IpAddrs.parse(s)!!)

    @Test
    fun spellingsOfOneAddressAreOneKey() {
        assertEquals(key("2001:db8::1"), key("2001:db8:0::1"))
        assertEquals(key("2001:db8::1"), key("2001:DB8:0:0:0:0:0:1"))
        assertEquals(key("2001:db8::1"), key("2001:0db8::0001"))
        assertEquals(key("192.0.2.1"), key("::ffff:192.0.2.1"))
        assertEquals(key("192.0.2.1"), key("::FFFF:c000:201"))
        assertFalse(key("2001:db8::1") == key("2001:db8::2"))
        assertFalse(key("::1") == key("0.0.0.1"))
        assertNull(IpAddrs.parse("evil.example"))
        assertNull(IpAddrs.parse("fe80::1%wlan0"))
    }

    @Test
    fun formatsIpv6Canonically() {
        fun f(s: String) = IpAddrs.formatV6(dev.vigil.inspector.vpn.IpLiteral.parseV6(s)!!)
        assertEquals("2001:db8::1", f("2001:DB8:0:0:0:0:0:1"))
        assertEquals("::", f("0:0:0:0:0:0:0:0"))
        assertEquals("::1", f("0:0:0:0:0:0:0:1"))
        assertEquals("fe80::", f("fe80:0:0:0:0:0:0:0"))
        // A single zero group is not shortened; the longest run (first on ties) is.
        assertEquals("2001:db8:0:1:1:1:1:1", f("2001:db8::1:1:1:1:1"))
        assertEquals("2001:0:0:1::1", f("2001:0:0:1:0:0:0:1"))
        assertEquals("2001::1:0:0:1", f("2001:0:0:0:1:0:0:1"))
        assertEquals("1::1:0:0:1", f("1:0:0:0:1:0:0:1"))
        assertEquals("1:0:0:1:1::", f("1:0:0:1:1:0:0:0"))
    }

    @Test
    fun rangesContainTheirAddresses() {
        val r6 = IpRange.parse("2001:db8:aa00::/40")!!
        assertTrue(r6.contains(IpAddrs.parse("2001:db8:aaff:ffff::1")!!))
        assertTrue(r6.contains(IpAddrs.parse("2001:DB8:AA00::")!!))
        assertFalse(r6.contains(IpAddrs.parse("2001:db8:ab00::1")!!))
        assertFalse(r6.contains(IpAddrs.parse("198.51.100.1")!!))
        val r4 = IpRange.parse("198.51.100.0/22")!!
        assertTrue(r4.contains(IpAddrs.parse("198.51.103.255")!!))
        assertFalse(r4.contains(IpAddrs.parse("198.51.104.0")!!))
        // IPv4-mapped addresses are their IPv4 address.
        assertTrue(r4.contains(IpAddrs.parse("::ffff:198.51.101.9")!!))
        assertTrue(IpRange.parse("::ffff:198.51.100.0/118")!!.contains(IpAddrs.parse("198.51.103.1")!!))
        // Host bits are ignored; /0 matches its whole family.
        assertTrue(IpRange.parse("2001:db8::1/32")!!.contains(IpAddrs.parse("2001:db8:1::")!!))
        assertTrue(IpRange.parse("::/0")!!.contains(IpAddrs.parse("2001:db8::1")!!))
        assertNull(IpRange.parse("2001:db8::/129"))
        assertNull(IpRange.parse("198.51.100.0/33"))
        assertNull(IpRange.parse("198.51.100.0"))
    }

    @Test
    fun matcherFindsExactAndRangeEntries() {
        val m = IpMatcher<String>()
        assertTrue(m.isEmpty)
        assertTrue(m.add("2001:db8:0::1", "exact"))
        assertTrue(m.add("2001:db8::/32", "range"))
        assertTrue(m.add("203.0.113.0/24", "v4range"))
        assertFalse(m.add("evil.example", "x"))
        assertEquals(listOf("2001:db8:0::1" to "exact", "2001:db8::/32" to "range"), m.match("2001:DB8::1").map { it.text to it.value })
        assertEquals(listOf("range"), m.match("2001:db8:5::7").map { it.value })
        assertEquals(listOf("v4range"), m.match("203.0.113.200").map { it.value })
        assertTrue(m.match("2001:db9::1").isEmpty())
        assertTrue(m.match("bad.example").isEmpty())
    }
}
