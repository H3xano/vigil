package dev.vigil.inspector.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SettingsCodecTest {
    private val wg = WireGuardSettings(
        privateKey = "YAnz4CFg6SqZkWpBHQ3K3G3oN6bT9x5cyTqQyzQ8bVE=",
        addresses = listOf("10.64.0.2/32"),
        peerPublicKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
        endpoint = "vpn.example.com:51820",
    )

    @Test
    fun readableDocumentsRoundTrip() {
        assertFalse(SettingsCodec.decode(null).unreadable)
        val s = Settings(excludeLan = false, upstream = UpstreamSettings(mode = "wireguard", wireguard = wg), deviceId = "dev-1")
        val loaded = SettingsCodec.decode(SettingsCodec.encode(s))
        assertEquals(s, loaded.settings)
        assertFalse(loaded.unreadable)
        assertNull(loaded.problem)
    }

    @Test
    fun unreadableDocumentKeepsTheUpstreamWhenItCan() {
        // Another field has a wrong type: the upstream section (with its keys) still decodes.
        val doc = SettingsCodec.encode(Settings(upstream = UpstreamSettings(mode = "wireguard", wireguard = wg), deviceId = "dev-1"))
            .replace("\"retentionDays\":7", "\"retentionDays\":\"seven\"")
        val loaded = SettingsCodec.decode(doc)
        assertTrue(loaded.unreadable)
        assertEquals(wg, loaded.settings.upstream.wireguard)
        assertEquals("wireguard", loaded.settings.upstream.mode)
        assertEquals("dev-1", loaded.settings.deviceId)
        assertNull("upstream recovered: no reason to refuse", loaded.problem)
        // Only the exception type is logged; its message may quote the JSON (with keys).
        assertFalse(loaded.errorType!!.contains(wg.privateKey))
    }

    @Test
    fun unrecoverableTunnelOrProxyFailsClosed() {
        // The WireGuard section itself is broken.
        val broken = SettingsCodec.encode(Settings(upstream = UpstreamSettings(mode = "wireguard", wireguard = wg)))
            .replace("\"privateKey\"", "\"privateKey\":1,\"x\"")
        val a = SettingsCodec.decode(broken)
        assertTrue(a.unreadable)
        assertNotNull(a.problem)
        assertTrue(a.problem!!, a.problem!!.contains("WireGuard"))
        // Shown as WireGuard without a configuration: never silently direct.
        assertEquals("wireguard", a.settings.upstream.mode)
        assertNull(a.settings.upstream.wireguard)

        // Not even JSON any more (truncated write): found by text.
        val truncated = SettingsCodec.encode(Settings(upstream = UpstreamSettings(mode = "socks5", socks5 = Socks5Settings(password = "pw"))))
            .let { it.substring(0, it.indexOf("\"password\"")) }
        val b = SettingsCodec.decode(truncated)
        assertTrue(b.unreadable)
        assertTrue(b.problem!!, b.problem!!.contains("SOCKS5"))
        assertEquals("socks5", b.settings.upstream.mode)
    }

    @Test
    fun unreadableDirectDocumentStartsWithDefaults() {
        val direct = SettingsCodec.encode(Settings(deviceId = "dev-2")).replace("\"excludeLan\":true", "\"excludeLan\":\"maybe\"")
        val loaded = SettingsCodec.decode(direct)
        assertTrue(loaded.unreadable)
        assertNull(loaded.problem)
        assertEquals("direct", loaded.settings.upstream.mode)
        assertEquals("dev-2", loaded.settings.deviceId)
        assertNull(SettingsCodec.decode("{garbage").problem)
    }
}
