package dev.vigil.inspector.data

import dev.vigil.inspector.R
import dev.vigil.inspector.ui.UiText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class WgQuickTest {
    private val key1 = "YAnz4CFg6SqZkWpBHQ3K3G3oN6bT9x5cyTqQyzQ8bVE="
    private val key2 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
    private val psk = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="

    // As handed out by providers (Mullvad/Proton style), with the noise wg-quick allows.
    private val conf = """
        # Provider config
        [Interface]
        PrivateKey = $key1
        Address = 10.64.12.34/32, fc00:bbbb:bbbb:bb01::1:c21/128
        DNS = 10.64.0.1, fc00:bbbb:bbbb:bb01::1, corp.example
        MTU = 1320
        PostUp = iptables -A FORWARD -i %i -j ACCEPT
        ListenPort = 51820

        [Peer]
        PublicKey = $key2
        PresharedKey = $psk
        AllowedIPs = 0.0.0.0/0
        AllowedIPs = ::/0
        Endpoint = 185.65.134.66:51820 # comment after value
        PersistentKeepalive = 25
    """.trimIndent()

    @Test
    fun parsesAProviderConfig() {
        val p = WgQuick.parse(conf, "mullvad-se.conf")
        val s = p.settings
        assertEquals(key1, s.privateKey)
        assertEquals(listOf("10.64.12.34/32", "fc00:bbbb:bbbb:bb01::1:c21/128"), s.addresses)
        assertEquals(listOf("10.64.0.1", "fc00:bbbb:bbbb:bb01::1"), s.dns)
        assertEquals(1320, s.mtu)
        assertEquals(key2, s.peerPublicKey)
        assertEquals(psk, s.presharedKey)
        assertEquals("185.65.134.66:51820", s.endpoint)
        assertEquals(listOf("0.0.0.0/0", "::/0"), s.allowedIps)
        assertEquals(25, s.persistentKeepalive)
        assertEquals("mullvad-se.conf", s.name)
        assertTrue(UiText.of(R.string.upstream_wg_search_domains) in p.warnings)
        assertTrue(UiText.of(R.string.upstream_wg_interface_key_ignored, "PostUp") in p.warnings)
        assertTrue(UiText.of(R.string.upstream_wg_interface_key_ignored, "ListenPort") in p.warnings)
    }

    @Test
    fun minimalConfigWithDefaults() {
        val p = WgQuick.parse(
            """
            [interface]
            privatekey=$key1
            address=10.0.0.2
            [peer]
            publickey=$key2
            endpoint=[2001:db8::1]:51820
            persistentkeepalive = off
            """.trimIndent(),
        )
        val s = p.settings
        assertEquals(listOf("10.0.0.2/32"), s.addresses)
        assertEquals("[2001:db8::1]:51820", s.endpoint)
        assertNull(s.mtu)
        assertNull(s.presharedKey)
        assertEquals(0, s.persistentKeepalive)
        assertTrue(s.allowedIps.isEmpty())
        assertTrue(s.dns.isEmpty())
        assertTrue(p.warnings.isEmpty())
    }

    @Test
    fun warnsWhenAllowedIpsCoverIpv4Only() {
        fun warnings(allowed: String) = WgQuick.parse(
            """
            [Interface]
            PrivateKey = $key1
            Address = 10.0.0.2/32
            [Peer]
            PublicKey = $key2
            Endpoint = vpn.example.com:51820
            AllowedIPs = $allowed
            """.trimIndent(),
        ).warnings.filter { it == UiText.of(R.string.upstream_wg_ipv6_not_tunnelled) }
        assertEquals(1, warnings("0.0.0.0/0").size)
        assertTrue(warnings("0.0.0.0/0, ::/0").isEmpty())
        assertTrue(warnings("0.0.0.0/0, 2000::/3").isEmpty())
        assertTrue(warnings("10.0.0.0/8").isEmpty())
        assertTrue(warnings("::/0").isEmpty())
    }

    @Test
    fun onlyTheFirstPeerAndFirstAddressPerFamily() {
        val p = WgQuick.parse(
            """
            [Interface]
            PrivateKey = $key1
            Address = 10.0.0.2/32, 10.0.0.3/32, fd00::2/128
            [Peer]
            PublicKey = $key2
            Endpoint = vpn.example.com:51820
            [Peer]
            PublicKey = $key1
            Endpoint = other.example.com:51820
            """.trimIndent(),
        )
        assertEquals(listOf("10.0.0.2/32", "fd00::2/128"), p.settings.addresses)
        assertEquals("vpn.example.com:51820", p.settings.endpoint)
        assertEquals(key2, p.settings.peerPublicKey)
        assertTrue(UiText.of(R.string.upstream_wg_only_first_peer) in p.warnings)
        assertTrue(UiText.of(R.string.upstream_wg_first_address_only) in p.warnings)
    }

    @Test
    fun rejectsBrokenConfigs() {
        fun bad(text: String) = assertThrows(WgQuick.ParseException::class.java) { WgQuick.parse(text.trimIndent()) }
        val peer = "[Peer]\nPublicKey = $key2\nEndpoint = 1.2.3.4:51820"
        bad("")
        bad("PrivateKey = $key1")
        bad("[Interface]\nPrivateKey = $key1\nAddress = 10.0.0.2/32")
        bad("[Interface]\nAddress = 10.0.0.2/32\n$peer")
        bad("[Interface]\nPrivateKey = tooshort\nAddress = 10.0.0.2/32\n$peer")
        bad("[Interface]\nPrivateKey = $key1\n$peer")
        bad("[Interface]\nPrivateKey = $key1\nAddress = 10.0.0.300/32\n$peer")
        bad("[Interface]\nPrivateKey = $key1\nAddress = 10.0.0.2/33\n$peer")
        bad("[Interface]\nPrivateKey = $key1\nAddress = 10.0.0.2/32\nMTU = 70000\n$peer")
        bad("[Interface]\nPrivateKey = $key1\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = $key2")
        bad("[Interface]\nPrivateKey = $key1\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = $key2\nEndpoint = 1.2.3.4")
        bad("[Interface]\nPrivateKey = $key1\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = $key2\nEndpoint = 2001:db8::1:51820")
        bad("[Interface]\nPrivateKey = $key1\nAddress = 10.0.0.2/32\n$peer\nAllowedIPs = everything")
        bad("[Interface]\nPrivateKey = $key1\nAddress = 10.0.0.2/32\n$peer\nPresharedKey = nope")
        bad("[Interface]\nPrivateKey = $key1\nnot a key value line\n$peer")
        bad("[Interface]\n" + "#".repeat(70_000))
    }

    @Test
    fun helpers() {
        assertTrue(WgQuick.isKey(key1))
        assertFalse(WgQuick.isKey("AAAA"))
        assertFalse(WgQuick.isKey("not base64 at all!"))
        assertTrue(WgQuick.isEndpoint("[fd00::1]:1"))
        assertTrue(WgQuick.isEndpoint("a-b.example.org:443"))
        assertFalse(WgQuick.isEndpoint("host:0"))
        assertFalse(WgQuick.isEndpoint("bad_host:1"))
        assertFalse(WgQuick.isEndpoint("[fd00::1]1"))
        assertEquals("fd00::/8", WgQuick.normalizeCidr(" fd00::/8 "))
        assertEquals("::1/128", WgQuick.normalizeCidr("::1"))
        assertNull(WgQuick.normalizeCidr("1.2.3.4/x"))
        assertNull(WgQuick.normalizeCidr("1.2.3.4/8/8"))
    }

    @Test
    fun settingsValidation() {
        val wg = WgQuick.parse(conf).settings
        assertNull(UpstreamSettings().validationError())
        assertEquals(UiText.of(R.string.upstream_error_import_first), UpstreamSettings(mode = "wireguard").validationError())
        assertNull(UpstreamSettings(mode = "wireguard", wireguard = wg).validationError())
        val socks = UpstreamSettings(mode = "socks5")
        assertNull(socks.validationError())
        assertNull(socks.copy(socks5 = Socks5Settings(host = "::1", port = 1080)).validationError())
        assertNull(socks.copy(socks5 = Socks5Settings(host = "proxy.example", username = "u", password = "p")).validationError())
        assertTrue(socks.copy(socks5 = Socks5Settings(host = "")).validationError() != null)
        assertTrue(socks.copy(socks5 = Socks5Settings(port = 0)).validationError() != null)
        assertEquals(UiText.of(R.string.upstream_error_bad_host, "bad host"), socks.copy(socks5 = Socks5Settings(host = "bad host")).validationError())
        assertTrue(socks.copy(socks5 = Socks5Settings(password = "p")).validationError() != null)
        assertTrue(socks.copy(socks5 = Socks5Settings(username = "u".repeat(256))).validationError() != null)
        // Only a SOCKS5 proxy app is excluded from the VPN.
        assertEquals("org.torproject.android", socks.copy(socks5 = Socks5Settings(proxyApp = "org.torproject.android")).excludedPackage)
        assertNull(UpstreamSettings(socks5 = Socks5Settings(proxyApp = "org.torproject.android")).excludedPackage)
    }
}
