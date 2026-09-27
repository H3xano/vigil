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
