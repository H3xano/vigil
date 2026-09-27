package dev.vigil.inspector.vpn

import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.engine.EngineConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigFactoryTest {
    @Test
    fun resolverNormalisation() {
        assertEquals("1.1.1.1:53", ConfigFactory.normalizeResolver("1.1.1.1"))
        assertEquals("9.9.9.9:5353", ConfigFactory.normalizeResolver(" 9.9.9.9:5353 "))
        assertEquals("[2606:4700::1111]:53", ConfigFactory.normalizeResolver("2606:4700::1111"))
        assertEquals("[2606:4700::1111]:853", ConfigFactory.normalizeResolver("[2606:4700::1111]:853"))
        assertNull(ConfigFactory.normalizeResolver("dns.google"))
        assertNull(ConfigFactory.normalizeResolver("1.2.3.256"))
        assertNull(ConfigFactory.normalizeResolver("1.1.1.1:99999"))
        assertNull(ConfigFactory.normalizeResolver(""))
        // Previously accepted by the lenient validator.
        assertNull(ConfigFactory.normalizeResolver("1:2"))
        assertNull(ConfigFactory.normalizeResolver("2001:db8"))
        assertNull(ConfigFactory.normalizeResolver("192.168.001.001"))
        assertNull(ConfigFactory.normalizeResolver("[::1]53"))
        assertNull(ConfigFactory.normalizeResolver("1.1.1.1:+53"))
        assertNull(ConfigFactory.normalizeResolver("1.1.1.1:0"))
        assertNull(ConfigFactory.normalizeResolver("1.1.1.1:"))
        assertNull(ConfigFactory.normalizeResolver("[fe80::1%wlan0]:53"))
        assertEquals("[::ffff:1.2.3.4]:53", ConfigFactory.normalizeResolver("[::ffff:1.2.3.4]"))
    }

    @Test
    fun linkLocalResolversAreDropped() {
        assertNull(ConfigFactory.formatResolver(java.net.InetAddress.getByName("fe80::1")))
        assertNull(ConfigFactory.formatResolver(java.net.InetAddress.getByName("169.254.1.1")))
        // The JDK does not compress zero groups (Android does), so only check the shape.
        val v6 = ConfigFactory.formatResolver(java.net.InetAddress.getByName("2001:db8::53"))!!
        assertTrue(v6, v6.startsWith("[2001:db8:") && v6.endsWith(":53]:53"))
        assertEquals("192.168.1.1:53", ConfigFactory.formatResolver(java.net.InetAddress.getByName("192.168.1.1")))
    }

    @Test
    fun nat64Prefixes() {
        val cfg = ConfigFactory.build(Settings(), emptyList(), emptyList(), listOf("64:ff9b::/96", "2001:db8:64::/96", "2001:db8::/64", "bogus", "64:ff9b::/96"))
        assertEquals(listOf("64:ff9b::/96", "2001:db8:64::/96"), cfg.nat64Prefixes)
        assertTrue(cfg.toJson().contains("\"nat64_prefixes\":[\"64:ff9b::/96\",\"2001:db8:64::/96\"]"))
        assertTrue(ConfigFactory.build(Settings(), emptyList(), emptyList()).toJson().contains("\"nat64_prefixes\":[]"))
    }

    @Test
    fun networkResolversWithFallback() {
        val s = Settings()
        assertEquals(listOf("192.168.1.1:53"), ConfigFactory.build(s, listOf("192.168.1.1:53"), emptyList()).upstreamDns)
        assertEquals(EngineConfig.FALLBACK_UPSTREAMS, ConfigFactory.build(s, emptyList(), emptyList()).upstreamDns)
        val custom = s.copy(upstreamMode = "custom", customUpstreams = listOf("8.8.8.8", "bogus"))
        assertEquals(listOf("8.8.8.8:53"), ConfigFactory.build(custom, listOf("192.168.1.1:53"), emptyList()).upstreamDns)
    }

    @Test
    fun serialisesRustFieldNames() {
        val cfg = ConfigFactory.build(
            Settings(blockEncryptedDns = true, denyDomains = setOf("b.example", "a.example"), beaconSensitivity = "high"),
            emptyList(), listOf(10123),
        )
        val json = cfg.toJson()
        for (key in listOf("\"virtual_dns\"", "\"upstream_dns\"", "\"block_encrypted_dns\":true", "\"blocked_uids\":[10123]",
            "\"deny_domains\":[\"a.example\",\"b.example\"]", "\"max_jitter\":0.25", "\"stats_interval_ms\"")) {
            assertTrue("$key in $json", json.contains(key))
        }
    }
}
