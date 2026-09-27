package dev.vigil.inspector.vpn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IpLiteralTest {
    @Test
    fun ipv4IsStrict() {
        for (ok in listOf("0.0.0.0", "1.1.1.1", "255.255.255.255", "192.168.1.10")) assertTrue(ok, IpLiteral.isV4(ok))
        for (bad in listOf("192.168.001.001", "01.1.1.1", "1.1.1", "1.1.1.1.1", "1.1.1.256", "1..1.1", "a.b.c.d", "+1.1.1.1", "", "1.1.1.1 ")) {
            assertFalse(bad, IpLiteral.isV4(bad))
        }
    }

    @Test
    fun ipv6IsStrict() {
        for (ok in listOf("::", "::1", "2001:db8::1", "2606:4700:4700::1111", "fe80::1", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::ffff:1.2.3.4", "64:ff9b::1.2.3.4")) {
            assertTrue(ok, IpLiteral.isV6(ok))
        }
        for (bad in listOf("1:2", "2001:db8", "1:2:3:4:5:6:7:8:9", "1::2::3", ":1", "1:", "12345::", "fe80::1%wlan0", "g::1", "1.2.3.4", "::1.2.3.4:5", "1:2:3:4:5:6:7:8::", "")) {
            assertFalse(bad, IpLiteral.isV6(bad))
        }
    }

    @Test
    fun ipv6Bytes() {
        val b = IpLiteral.parseV6("64:ff9b::1.2.3.4")!!
        assertArrayEquals(byteArrayOf(0, 0x64, 0xff.toByte(), 0x9b.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4), b)
    }
}
