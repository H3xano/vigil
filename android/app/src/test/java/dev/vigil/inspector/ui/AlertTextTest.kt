package dev.vigil.inspector.ui

import dev.vigil.inspector.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Alert titles and sentences come from resources; in English they must read
 * exactly like the message the engine or the detector stored (the stored
 * messages below are in the formats of core/vigil-core/src/engine and
 * processing/), and fall back to that message when they cannot be rebuilt.
 */
class AlertTextTest {
    private fun msg(kind: String, target: String, stored: String, detail: String, app: String = "Chrome") =
        AlertText.message(kind, target, app, stored, detail)

    /** The rebuilt sentence reads, in English, exactly like the stored one. */
    private fun assertSameInEnglish(t: UiText, stored: String) {
        assertTrue("fell back to the stored message: $t", t !is UiText.Raw)
        assertEquals(stored, EnglishStrings.resolve(t))
    }

    @Test
    fun titles() {
        assertEquals(UiText.of(R.string.alert_title_threat_domain), AlertText.title("threat_domain"))
        assertEquals(UiText.of(R.string.alert_title_beacon), AlertText.title("beacon"))
        assertEquals(UiText.of(R.string.alert_title_new_asn), AlertText.title("new_asn"))
        assertEquals("threat IP blocked", EnglishStrings.resolve(AlertText.title("threat_ip")))
        assertEquals("encrypted DNS in use", EnglishStrings.resolve(AlertText.title("encrypted_dns")))
        // Unknown kinds show the kind itself.
        assertNull(AlertText.titleRes("something_new"))
        assertEquals(UiText.Raw("something new"), AlertText.title("something_new"))
        for (k in listOf("threat_domain", "threat_ip", "threat_ja4", "beacon", "exfil_volume", "encrypted_dns", "hardcoded_dns", "new_destination", "new_asn")) {
            assertNotNull(k, AlertText.titleRes(k))
        }
    }

    @Test
    fun threatDomain() {
        val lookup = "Lookup of x1.evil.example sinkholed: listed by feed:urlhaus (evil.example)"
        val t = msg("threat_domain", "x1.evil.example", lookup, """{"category":"malware","qtype":"A"}""")
        assertEquals(UiText.of(R.string.alert_msg_threat_domain_lookup, "x1.evil.example", "feed:urlhaus (evil.example)"), t)
        assertSameInEnglish(t, lookup)

        val conn = "Connection to evil.example blocked: listed by feed:urlhaus (evil.example)"
        val c = msg("threat_domain", "evil.example", conn, """{"dst":"192.0.2.1:443","category":"malware"}""")
        assertEquals(UiText.of(R.string.alert_msg_threat_connection, "evil.example", "feed:urlhaus (evil.example)"), c)
        assertSameInEnglish(c, conn)
    }

    @Test
    fun threatIp() {
        val conn = "Connection to 192.0.2.7 blocked: listed by feed:ipsum (192.0.2.0/24)"
        val c = msg("threat_ip", "192.0.2.7", conn, """{"dst":"192.0.2.7:443","category":"c2"}""")
        assertEquals(UiText.of(R.string.alert_msg_threat_connection, "192.0.2.7", "feed:ipsum (192.0.2.0/24)"), c)
        assertSameInEnglish(c, conn)

        val dns = "DNS query to 192.0.2.53:53 refused: listed by feed:c2 (192.0.2.53)"
        val d = msg("threat_ip", "192.0.2.53", dns, """{"dst":"192.0.2.53:53","qname":"x.example","category":"c2"}""")
        assertEquals(UiText.of(R.string.alert_msg_threat_ip_dns, "192.0.2.53:53", "feed:c2 (192.0.2.53)"), d)
        assertSameInEnglish(d, dns)
    }

    @Test
    fun spywareSuffix() {
        val stored = "Lookup of spy.example sinkholed: listed by feed:mvt (spy.example). Spyware indicator: Pegasus (NSO Group Pegasus)"
        val t = msg(
            "threat_domain", "spy.example", stored,
            """{"category":"malware","qtype":"A","spyware":{"label":"Pegasus","pack":"NSO Group Pegasus","feed":"mvt-x"}}""",
        )
        assertEquals(
            UiText.of(
                R.string.alert_msg_with_spyware,
                UiText.of(R.string.alert_msg_threat_domain_lookup, "spy.example", "feed:mvt (spy.example)"),
                "Pegasus", "NSO Group Pegasus",
            ),
            t,
        )
        assertSameInEnglish(t, stored)
    }

    @Test
    fun threatJa4() {
        val labelled = "TLS fingerprint of Sliver (JA4 t13d190900_9dc949149365_97f8aa674fd9, feed ja4db) in a connection to c2.example; blocked"
        val t = msg(
            "threat_ja4", "t13d190900_9dc949149365_97f8aa674fd9", labelled,
            """{"ja4":"t13d190900_9dc949149365_97f8aa674fd9","rule":"x","label":"Sliver","feed":"ja4db","dst":"192.0.2.1:443",
               "domain":"c2.example","proto":"tls","blocked":true}""",
        )
        assertEquals(
            UiText.of(R.string.alert_msg_threat_ja4_blocked, "Sliver", "t13d190900_9dc949149365_97f8aa674fd9", "ja4db", "c2.example"),
            t,
        )
        assertSameInEnglish(t, labelled)

        val unlabelled = "TLS fingerprint of a listed client (JA4 t13d1, feed custom) in a connection to 192.0.2.1:443"
        val u = msg(
            "threat_ja4", "t13d1", unlabelled,
            """{"ja4":"t13d1","rule":"x","label":null,"feed":"custom","dst":"192.0.2.1:443","domain":null,"proto":"quic","blocked":false}""",
        )
        assertEquals(UiText.of(R.string.alert_msg_threat_ja4_unlabeled, "t13d1", "custom", "192.0.2.1:443"), u)
        assertSameInEnglish(u, unlabelled)
    }

    @Test
    fun beacon() {
        val stored = "Periodic connections to c2.example every 60s (jitter 5%)"
        val t = msg("beacon", "c2.example", stored, """{"kind":"connections","interval_s":60.2,"jitter":0.05,"samples":6,"proto":"tcp"}""")
        assertEquals(UiText.of(R.string.alert_msg_beacon_connections, "c2.example", 60.2, 0.05 * 100), t)
        assertSameInEnglish(t, stored)
        // Older alerts have no detail.kind.
        assertSameInEnglish(msg("beacon", "c2.example", stored, """{"interval_s":60.0,"jitter":0.05}"""), stored)

        val intra = "Small bursts of data (about 512 bytes) every 30s (jitter 5%) inside one open connection to c2.example"
        val i = msg(
            "beacon", "c2.example", intra,
            """{"kind":"intra_flow","interval_s":30.0,"jitter":0.05,"samples":8,"burst_bytes":512,"flow_id":3,"dst":"192.0.2.1:443","domain":"c2.example"}""",
        )
        assertEquals(UiText.plural(R.plurals.alert_msg_beacon_intra_flow, 512, 512L, 30.0, 0.05 * 100, "c2.example"), i)
        assertSameInEnglish(i, intra)
    }

    @Test
    fun dnsKinds() {
        val enc = "App uses encrypted DNS (dns.google); its lookups are invisible to vigil"
        val e = msg("encrypted_dns", "dns.google", enc, """{"dst":"8.8.8.8:853"}""")
        assertEquals(UiText.of(R.string.alert_msg_encrypted_dns, "dns.google"), e)
        assertSameInEnglish(e, enc)

        val hard = "App bypasses the system resolver and queries [2001:db8::53]:53 directly"
        val h = msg("hardcoded_dns", "2001:db8::53", hard, """{"qname":"x.example","suppressed":2}""")
        assertEquals(UiText.of(R.string.alert_msg_hardcoded_dns, "[2001:db8::53]:53"), h)
        assertSameInEnglish(h, hard)
    }

    @Test
    fun appSideKinds() {
        val dest = "Chrome contacted a destination it has never used before: new.example"
        val d = msg("new_destination", "new.example", dest, """{"destination":"new.example"}""")
        assertEquals(UiText.of(R.string.alert_msg_new_destination, "Chrome", "new.example"), d)
        assertSameInEnglish(d, dest)

        val named = "Chrome contacted a network it has never used before: AS13335 (Cloudflare, Inc.), reached as one.example"
        val n = msg(
            "new_asn", "AS13335", named,
            """{"asn":13335,"as_name":"CLOUDFLARENET-AS Cloudflare, Inc.","as_country":"US","destination":"one.example","dst_ip":"192.0.2.1","known_networks":2}""",
        )
        assertEquals(UiText.of(R.string.alert_msg_new_asn_named, "Chrome", "AS13335", "Cloudflare, Inc.", "one.example"), n)
        assertSameInEnglish(n, named)
        val plain = "Chrome contacted a network it has never used before: AS64500, reached as 192.0.2.9"
        assertSameInEnglish(msg("new_asn", "AS64500", plain, """{"asn":64500,"destination":"192.0.2.9","dst_ip":"192.0.2.9","known_networks":9}"""), plain)
    }

    @Test
    fun exfil() {
        fun detail(windowS: Int, background: String, base: String) =
            """{"window":"x","window_s":$windowS,"uploaded_bytes":62914560,"baseline_bytes_per_hour":$base,"floor_bytes":52428800,"factor":3.0,
               "destination":"drop.example","dest_tx_bytes":60817408,"dest_rx_bytes":1048576,"background":"$background","package":"com.x"}"""
        val hour = "Chrome uploaded 60.0 MB in the last hour while in the background, mostly to drop.example (58.0 MB sent, 1.0 MB received). " +
            "Its usual busiest hour is 4.0 MB."
        val t = msg("exfil_volume", "drop.example", hour, detail(3600, "yes", "4194304"))
        assertEquals(
            UiText.of(
                R.string.alert_msg_exfil_with_baseline,
                UiText.of(R.string.alert_msg_exfil_hour_background, "Chrome", "60.0 MB", "drop.example", "58.0 MB", "1.0 MB"),
                "4.0 MB",
            ),
            t,
        )
        assertSameInEnglish(t, hour)
        val short = "Chrome uploaded 60.0 MB in the last 5 minutes (vigil cannot tell whether it was on screen: usage access is not granted), " +
            "mostly to drop.example (58.0 MB sent, 1.0 MB received). There is no upload history for it yet."
        assertSameInEnglish(msg("exfil_volume", "drop.example", short, detail(300, "unknown", "null")), short)
        // A window this version does not know: the stored text.
        assertEquals(UiText.Raw("stored"), msg("exfil_volume", "drop.example", "stored", detail(600, "yes", "null")))
    }

    @Test
    fun fallsBackToTheStoredMessage() {
        fun raw(s: String) = UiText.Raw(s)
        assertEquals(raw("Something new happened"), msg("future_kind", "x", "Something new happened", """{"a":1}"""))
        assertEquals(raw("Lookup of x sinkholed"), msg("threat_domain", "x", "Lookup of x sinkholed", "not json"))
        // The feed entry cannot be found in the message.
        assertEquals(raw("Lookup of x blocked"), msg("threat_domain", "x", "Lookup of x blocked", """{"qtype":"A"}"""))
        // Details that lack what the sentence needs (older versions).
        assertEquals(raw("beacon"), msg("beacon", "x", "beacon", """{"kind":"connections"}"""))
        assertEquals(raw("burst"), msg("beacon", "x", "burst", """{"kind":"intra_flow","interval_s":30.0,"jitter":0.1}"""))
        assertEquals(raw("ja4"), msg("threat_ja4", "t13", "ja4", """{"ja4":"t13"}"""))
        val noServer = "DNS query to 192.0.2.1:53 refused: listed by feed:x (192.0.2.1)"
        assertEquals(raw(noServer), msg("threat_ip", "192.0.2.1", noServer, """{"qname":"a"}"""))
        assertEquals(raw("App queries a server"), msg("hardcoded_dns", "192.0.2.1", "App queries a server", """{"qname":"x"}"""))
        assertEquals(raw("asn"), msg("new_asn", "AS1", "asn", """{"asn":1}"""))
        assertEquals(raw("up"), msg("exfil_volume", "d", "up", """{"uploaded_bytes":1}"""))
    }
}
