package dev.vigil.inspector.data

import dev.vigil.inspector.engine.EncryptedDnsConfig
import dev.vigil.inspector.engine.EngineJson
import dev.vigil.inspector.vpn.ConfigFactory
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptedDnsSettingsTest {
    private fun custom(mode: String, url: String = "", host: String = "", port: Int = 853, addrs: List<String> = emptyList(), fallback: Boolean = false) =
        EncryptedDnsSettings(mode, EncryptedDnsSettings.CUSTOM, url, host, port, addrs, fallback)

    @Test
    fun offByDefaultAndOffConfig() {
        val s = EncryptedDnsSettings()
        assertFalse(s.enabled)
        assertNull(s.problem())
        assertEquals(EncryptedDnsConfig(), s.toEngine())
        assertEquals("Off", s.summary())
    }

    @Test
    fun presetsProduceEngineServers() {
        for (p in DnsProviders.ALL) {
            for (mode in listOf("dot", "doh")) {
                val s = EncryptedDnsSettings(mode = mode, provider = p.id)
                assertNull("${p.id}/$mode", s.problem())
                val c = s.toEngine()
                assertEquals(mode, c.mode)
                val server = c.servers.single()
                assertTrue(server.addrs.isNotEmpty())
                assertTrue(server.addrs.first().contains('.'))
                if (mode == "doh") {
                    assertEquals(p.dohUrl, server.url)
                    assertNotNull(EncryptedDnsSettings.parseDohUrl(p.dohUrl))
                    assertNull(server.host)
                } else {
                    assertEquals(p.dotHost, server.host)
                    assertTrue(EncryptedDnsSettings.isServerName(p.dotHost))
                    assertNull(server.url)
                }
            }
        }
        assertEquals("DNS over HTTPS · Quad9", EncryptedDnsSettings(mode = "doh").summary())
        assertEquals("Choose a provider.", EncryptedDnsSettings(mode = "dot", provider = "nope").problem())
    }

    @Test
    fun customServersValidated() {
        assertNull(custom("doh", url = "https://dns.example/dns-query", addrs = listOf("192.0.2.1", "2001:db8::1")).problem())
        assertNull(custom("dot", host = "dns.example", addrs = listOf("192.0.2.1")).problem())
        // An IP literal needs no separate addresses.
        assertNull(custom("dot", host = "192.0.2.1").problem())
        assertNull(custom("doh", url = "https://[2001:db8::1]/dns-query").problem())
        // A name without addresses needs a cleartext lookup, so the fallback.
        assertNotNull(custom("doh", url = "https://dns.example/dns-query").problem())
        assertNull(custom("doh", url = "https://dns.example/dns-query", fallback = true).problem())
        assertNotNull(custom("doh", url = "http://dns.example/dns-query", addrs = listOf("192.0.2.1")).problem())
        assertNotNull(custom("doh", url = "", addrs = listOf("192.0.2.1")).problem())
        assertNotNull(custom("dot", host = "localhost", addrs = listOf("192.0.2.1")).problem())
        assertNotNull(custom("dot", host = "dns.example", port = 0, addrs = listOf("192.0.2.1")).problem())
        assertNotNull(custom("dot", host = "dns.example", addrs = listOf("dns.example")).problem())
        assertNotNull(custom("dot", host = "dns.example", addrs = List(9) { "192.0.2.$it" }).problem())
        // Invalid settings never reach the engine as encrypted.
        assertEquals("off", custom("dot", host = "bad host").toEngine().mode)
        val c = custom("dot", host = "Dns.Example.", port = 8853, addrs = listOf("192.0.2.1")).toEngine()
        assertEquals("Dns.Example", c.servers.single().host)
        assertEquals(8853, c.servers.single().port)
    }

    @Test
    fun dohUrlParsing() {
        fun p(s: String) = EncryptedDnsSettings.parseDohUrl(s)
        assertEquals(EncryptedDnsSettings.Companion.DohUrl("dns.example", 443, "/dns-query"), p("https://DNS.example/dns-query"))
        assertEquals(EncryptedDnsSettings.Companion.DohUrl("dns.example", 8443, "/dns-query"), p("https://dns.example:8443"))
        assertEquals(EncryptedDnsSettings.Companion.DohUrl("2001:db8::1", 443, "/?dns"), p("https://[2001:db8::1]?dns"))
        for (bad in listOf(
            "dns.example/dns-query", "https://", "https://dns example/", "https://user@dns.example/",
            "https://dns.example:0/", "https://dns.example:65536/", "https://dns.example/#f", "https://[::1/",
            "https://[::1]x/", "https://-dns.example/", "https://dns/", "https://dns.exämple/",
        )) {
            assertNull(bad, p(bad))
        }
        assertEquals(listOf("9.9.9.9", "2620:fe::fe", "1.1.1.1"), EncryptedDnsSettings.splitAddrs(" 9.9.9.9, 2620:fe::fe\n1.1.1.1 ,"))
    }

    @Test
    fun engineJsonCarriesEncryptedDns() {
        val s = Settings(encryptedDns = EncryptedDnsSettings(mode = "dot", provider = "quad9", fallbackPlain = true))
        val json = EngineJson.json.parseToJsonElement(ConfigFactory.build(s, listOf("192.168.1.1:53"), emptyList()).toJson()).jsonObject
        val e = json["encrypted_dns"]!!.jsonObject
        assertEquals("dot", e["mode"]!!.jsonPrimitive.content)
        assertEquals("true", e["fallback_plain"]!!.jsonPrimitive.content)
        val server = e["servers"]!!.jsonArray.single().jsonObject
        assertEquals("dns.quad9.net", server["host"]!!.jsonPrimitive.content)
        assertFalse("nulls are omitted", server.containsKey("url") || server.containsKey("port"))
        assertEquals("9.9.9.9", server["addrs"]!!.jsonArray.first().jsonPrimitive.content)
        // Off: an empty server list and mode "off".
        val off = EngineJson.json.parseToJsonElement(ConfigFactory.build(Settings(), emptyList(), emptyList()).toJson()).jsonObject
        assertEquals("off", off["encrypted_dns"]!!.jsonObject["mode"]!!.jsonPrimitive.content)
        // Settings written before this field existed still load.
        val old = EngineJson.json.decodeFromString(Settings.serializer(), """{"sinkhole":"nxdomain"}""")
        assertEquals(EncryptedDnsSettings(), old.encryptedDns)
    }
}
