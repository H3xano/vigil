package dev.vigil.inspector.vpn

import dev.vigil.inspector.data.AppDomainRule
import dev.vigil.inspector.data.AppRule
import dev.vigil.inspector.data.EncryptedDnsSettings
import dev.vigil.inspector.data.FeedEntity
import dev.vigil.inspector.data.FeedKinds
import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.data.Socks5Settings
import dev.vigil.inspector.data.UpstreamSettings
import dev.vigil.inspector.data.WireGuardSettings
import dev.vigil.inspector.engine.DeviceState
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

    private fun feed(id: String, category: String, enabled: Boolean = true, lastUpdated: Long? = 1L, kind: String = FeedKinds.LIST) =
        FeedEntity(id = id, name = id, url = "https://feeds.example/$id", category = category, enabled = enabled, builtin = true, lastUpdated = lastUpdated, kind = kind)

    @Test
    fun startConfigPreloadsExactlyTheLoadableFeeds() {
        val all = listOf(
            feed("urlhaus", "malware"),
            feed("ads", "ads", enabled = false),
            feed("never-downloaded", "c2", lastUpdated = null),
            feed("iptoasn", "asn", kind = FeedKinds.ASN),
            feed("ja4-foxio", "ja4", kind = FeedKinds.JA4),
        )
        val onDisk = setOf("urlhaus", "ads", "iptoasn", "ja4-foxio")
        val loadable = ConfigFactory.loadableFeeds(all) { it in onDisk }
        // Enabled and downloaded, the ASN table included: what syncFeeds would load.
        assertEquals(listOf("urlhaus", "iptoasn", "ja4-foxio"), loadable.map { it.id })
        val base = ConfigFactory.build(Settings(), emptyList(), emptyList())
        val start = ConfigFactory.startConfig(base, loadable) { "/data/feeds/$it.txt" }
        assertEquals(base, start.copy(feeds = null, feedsPreloadTimeoutMs = null))
        val json = start.toJson()
        assertTrue(json, json.contains(FEEDS_JSON))
        assertTrue(json, json.contains("\"feeds_preload_timeout_ms\":10000"))
        // Update configs never carry the start-only fields.
        val update = base.toJson()
        assertFalse(update, update.contains("\"feeds\""))
        assertFalse(update, update.contains("feeds_preload_timeout_ms"))
        // No feeds: an empty list (the engine then starts at once).
        assertTrue(ConfigFactory.startConfig(base, emptyList()) { it }.toJson().contains("\"feeds\":[]"))
    }

    @Test
    fun perAppRulesResolvedToUids() {
        val uids = mapOf("com.chat" to 10123, "com.shop" to 10124)
        val s = Settings(
            appRules = mapOf(
                "com.chat" to AppRule(blockWifi = true, blockBackground = true),
                "com.shop" to AppRule(blockCellular = true, blockScreenOff = true),
                "not.installed" to AppRule(blockWifi = true),
            ),
            appDomainRules = listOf(
                AppDomainRule("com.shop", "tracker.example", AppDomainRule.ALLOW),
                AppDomainRule("com.chat", "ads.example.com", AppDomainRule.BLOCK),
            ),
        )
        val cfg = ConfigFactory.build(s, emptyList(), emptyList(), uidOf = { uids[it] })
        val json = cfg.toJson()
        assertTrue(json, json.contains(APP_RULES_JSON))
        // Without resolvable apps: empty lists (and old engines ignore nothing new).
        val none = ConfigFactory.build(s, emptyList(), emptyList()).toJson()
        assertTrue(none, none.contains("\"app_rules\":[],\"app_domain_rules\":[]"))
        // The device state goes into the start config only.
        assertFalse(json, json.contains("device_state"))
        val state = DeviceState(DeviceState.NETWORK_WIFI, screenOn = false, foregroundUids = listOf(10123, 10200))
        assertEquals(DEVICE_STATE_JSON, state.toJson())
        assertEquals(DEVICE_STATE_UNKNOWN_FG_JSON, DeviceState(DeviceState.NETWORK_CELLULAR).toJson())
        val start = ConfigFactory.startConfig(cfg, emptyList(), state) { it }.toJson()
        assertTrue(start, start.contains("\"device_state\":$DEVICE_STATE_JSON"))
    }

    private companion object {
        /** `"{" + APP_RULES_JSON + "}"` is parsed by the Rust test `app_rules_json_contract`. */
        const val APP_RULES_JSON = "\"app_rules\":[{\"uid\":10123,\"block_wifi\":true,\"block_cellular\":false,\"block_background\":true,\"block_screen_off\":false}," +
            "{\"uid\":10124,\"block_wifi\":false,\"block_cellular\":true,\"block_background\":false,\"block_screen_off\":true}]," +
            "\"app_domain_rules\":[{\"uid\":10123,\"domain\":\"ads.example.com\",\"action\":\"block\"}," +
            "{\"uid\":10124,\"domain\":\"tracker.example\",\"action\":\"allow\"}]"

        /** nativeSetDeviceState payloads, also parsed by `app_rules_json_contract`. */
        const val DEVICE_STATE_JSON = "{\"network\":\"wifi\",\"screen_on\":false,\"foreground_uids\":[10123,10200]}"
        const val DEVICE_STATE_UNKNOWN_FG_JSON = "{\"network\":\"cellular\",\"screen_on\":true}"

        /** Start-config feed list (engine `feeds`; see docs/EVENTS.md). */
        /** Also parsed by the Rust test `feeds_json_contract`. */
        const val FEEDS_JSON = "\"feeds\":[{\"id\":\"urlhaus\",\"category\":\"malware\",\"path\":\"/data/feeds/urlhaus.txt\"}," +
            "{\"id\":\"iptoasn\",\"category\":\"asn\",\"path\":\"/data/feeds/iptoasn.txt\"}," +
            "{\"id\":\"ja4-foxio\",\"category\":\"ja4\",\"path\":\"/data/feeds/ja4-foxio.txt\"}]"

        /** Also parsed by the Rust test `upstream_json_contract`. */
        const val COMBINED_EDNS = "\"encrypted_dns\":{\"mode\":\"dot\",\"servers\":[{\"host\":\"dns.quad9.net\"," +
            "\"addrs\":[\"9.9.9.9\",\"149.112.112.112\",\"2620:fe::fe\",\"2620:fe::9\"]}],\"fallback_plain\":false}"
    }

    @Test
    fun workerThreadsFollowMaxThroughput() {
        val net = listOf("192.168.1.1:53")
        assertEquals(1, ConfigFactory.build(Settings(), net, emptyList()).workerThreads)
        assertEquals(2, ConfigFactory.build(Settings(maxThroughput = true), net, emptyList()).workerThreads)
        assertTrue(ConfigFactory.build(Settings(), net, emptyList()).toJson().contains("\"worker_threads\":1"))
    }
}
