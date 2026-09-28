package dev.vigil.inspector.vpn

import dev.vigil.inspector.data.EncryptedDnsSettings
import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.data.Socks5Settings
import dev.vigil.inspector.data.UpstreamSettings
import dev.vigil.inspector.data.WireGuardSettings
import dev.vigil.inspector.engine.EngineConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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

    private val wg = WireGuardSettings(
        privateKey = "YAnz4CFg6SqZkWpBHQ3K3G3oN6bT9x5cyTqQyzQ8bVE=",
        addresses = listOf("10.64.0.2/32", "fd00::2/128"),
        dns = listOf("10.64.0.1", "fd00::1"),
        peerPublicKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
        endpoint = "vpn.example.com:51820",
        allowedIps = listOf("0.0.0.0/0", "::/0"),
        persistentKeepalive = 25,
    )

    @Test
    fun directByDefault() {
        val json = ConfigFactory.build(Settings(), emptyList(), emptyList(), networkId = "100").toJson()
        assertTrue(json, json.contains("\"upstream\":{\"mode\":\"direct\",\"fail_closed\":true,\"network_id\":\"100\"}"))
    }

    @Test
    fun wireguardSectionAndTunnelDns() {
        val s = Settings(upstream = UpstreamSettings(mode = "wireguard", wireguard = wg))
        val cfg = ConfigFactory.build(s, listOf("192.168.1.1:53"), emptyList(), networkId = "101")
        // The tunnel's resolvers replace the network's.
        assertEquals(listOf("10.64.0.1:53", "[fd00::1]:53"), cfg.upstreamDns)
        val json = cfg.toJson()
        val expected = "\"upstream\":{\"mode\":\"wireguard\",\"fail_closed\":true,\"wireguard\":{" +
            "\"private_key\":\"${wg.privateKey}\",\"peer_public_key\":\"${wg.peerPublicKey}\",\"endpoint\":\"vpn.example.com:51820\"," +
            "\"addresses\":[\"10.64.0.2/32\",\"fd00::2/128\"],\"allowed_ips\":[\"0.0.0.0/0\",\"::/0\"],\"mtu\":1280," +
            "\"persistent_keepalive\":25},\"network_id\":\"101\"}"
        assertTrue(json, json.contains(expected))
        // Secrets never reach logs.
        val log = cfg.toLogJson()
        assertFalse(log.contains(wg.privateKey))
        assertTrue(log.contains(wg.peerPublicKey))
        // Without tunnel DNS, public resolvers (through the tunnel), not the LAN's.
        val noDns = s.copy(upstream = s.upstream.copy(wireguard = wg.copy(dns = emptyList(), mtu = 1400)))
        val c2 = ConfigFactory.build(noDns, listOf("192.168.1.1:53"), emptyList())
        assertEquals(EngineConfig.FALLBACK_UPSTREAMS, c2.upstreamDns)
        assertEquals(1400, c2.upstream.wireguard!!.mtu)
        // Chosen but never imported: passed on so the engine refuses to start.
        val missing = ConfigFactory.build(Settings(upstream = UpstreamSettings(mode = "wireguard")), emptyList(), emptyList())
        assertEquals("wireguard", missing.upstream.mode)
        assertNull(missing.upstream.wireguard)
    }

    @Test
    fun socks5Section() {
        val socks = Socks5Settings(host = "::1", port = 9050, username = "u", password = "secret", sendDomain = true, udp = "block", proxyApp = "org.torproject.android")
        val s = Settings(upstream = UpstreamSettings(mode = "socks5", failClosed = false, socks5 = socks), upstreamMode = "network")
        val cfg = ConfigFactory.build(s, listOf("192.168.1.1:53"), emptyList())
        assertEquals(EngineConfig.FALLBACK_UPSTREAMS, cfg.upstreamDns)
        val json = cfg.toJson()
        val expected = "\"upstream\":{\"mode\":\"socks5\",\"fail_closed\":false,\"socks5\":{\"server\":\"[::1]:9050\"," +
            "\"username\":\"u\",\"password\":\"secret\",\"send_domain\":true,\"udp\":\"block\"},\"network_id\":\"\"}"
        assertTrue(json, json.contains(expected))
        assertFalse(cfg.toLogJson().contains("secret"))
        // A custom resolver choice is kept (and reached through the proxy).
        val custom = s.copy(upstreamMode = "custom", customUpstreams = listOf("9.9.9.9"))
        assertEquals(listOf("9.9.9.9:53"), ConfigFactory.build(custom, emptyList(), emptyList()).upstreamDns)
        assertEquals("127.0.0.1:9050", ConfigFactory.hostPort(" 127.0.0.1 ", 9050))
        assertEquals("[2001:db8::1]:1080", ConfigFactory.hostPort("[2001:db8::1]", 1080))
    }

    @Test
    fun encryptedDnsWithWireguardAndSocks5() {
        val dot = EncryptedDnsSettings(mode = "dot", provider = "quad9")
        // WireGuard with DNS servers in its conf, plus DoT: both are passed on.
        // The engine sends the virtual resolver's lookups over DoT (through
        // the tunnel); the conf's resolvers stay the plain upstreams.
        val s = Settings(upstream = UpstreamSettings(mode = "wireguard", wireguard = wg), encryptedDns = dot)
        val cfg = ConfigFactory.build(s, listOf("192.168.1.1:53"), emptyList(), networkId = "101")
        assertEquals("dot", cfg.encryptedDns.mode)
        assertEquals("dns.quad9.net", cfg.encryptedDns.servers.single().host)
        assertEquals(listOf("10.64.0.1:53", "[fd00::1]:53"), cfg.upstreamDns)
        assertEquals("wireguard", cfg.upstream.mode)
        val json = cfg.toJson()
        assertTrue(json, json.contains(COMBINED_EDNS))
        assertTrue(json, json.contains("\"upstream\":{\"mode\":\"wireguard\""))
        // Same with SOCKS5: DoT goes through the proxy as TCP; plain upstreams
        // are public resolvers (the LAN resolver is not reachable via the proxy).
        val socks = Settings(
            upstream = UpstreamSettings(mode = "socks5", socks5 = Socks5Settings(host = "127.0.0.1", port = 9050)),
            encryptedDns = dot.copy(fallbackPlain = true),
        )
        val c2 = ConfigFactory.build(socks, listOf("192.168.1.1:53"), emptyList())
        assertEquals(EngineConfig.FALLBACK_UPSTREAMS, c2.upstreamDns)
        assertTrue(c2.encryptedDns.fallbackPlain)
        assertEquals("socks5", c2.upstream.mode)
        // Encrypted DNS off: the plain selection alone decides.
        val off = ConfigFactory.build(s.copy(encryptedDns = EncryptedDnsSettings()), emptyList(), emptyList())
        assertEquals("off", off.encryptedDns.mode)
        assertEquals(listOf("10.64.0.1:53", "[fd00::1]:53"), off.upstreamDns)
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

    private companion object {
        /** Also parsed by the Rust test `upstream_json_contract`. */
        const val COMBINED_EDNS = "\"encrypted_dns\":{\"mode\":\"dot\",\"servers\":[{\"host\":\"dns.quad9.net\"," +
            "\"addrs\":[\"9.9.9.9\",\"149.112.112.112\",\"2620:fe::fe\",\"2620:fe::9\"]}],\"fallback_plain\":false}"
    }
}
