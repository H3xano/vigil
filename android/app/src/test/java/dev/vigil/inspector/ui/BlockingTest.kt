package dev.vigil.inspector.ui

import dev.vigil.inspector.data.AlertEntity
import dev.vigil.inspector.data.AlertMute
import dev.vigil.inspector.data.AlertMutes
import dev.vigil.inspector.data.ExportSettings
import dev.vigil.inspector.data.FeedEntity
import dev.vigil.inspector.ui.screens.filterAlerts
import dev.vigil.inspector.ui.screens.validationError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BlockingTest {
    @Test
    fun registrableDomains() {
        assertEquals("example.com", DomainNames.registrable("api.cdn.example.com"))
        assertEquals("example.com", DomainNames.registrable("example.com"))
        assertEquals("example.co.uk", DomainNames.registrable("shop.example.co.uk"))
        assertEquals("example.com.au", DomainNames.registrable("a.b.example.com.au"))
        // Names starting with a digit are domains too.
        assertEquals("163.com", DomainNames.registrable("mail.163.com"))
        assertEquals("1password.com", DomainNames.registrable("my.1password.com"))
        // Shared hosting: each subdomain is a separate site.
        assertEquals("someone.github.io", DomainNames.registrable("docs.someone.github.io"))
        // Infrastructure: never wider than the host.
        assertEquals("d111111abcdef8.cloudfront.net", DomainNames.registrable("d111111abcdef8.cloudfront.net"))
        assertEquals("bucket.s3.amazonaws.com", DomainNames.registrable("bucket.s3.amazonaws.com"))
        assertNull(DomainNames.registrable("cloudfront.net"))
        assertNull(DomainNames.registrable("co.uk"))
        assertNull(DomainNames.registrable("localhost"))
        assertNull(DomainNames.registrable("192.0.2.1"))
        assertNull(DomainNames.registrable("2001:db8::1"))
        assertEquals("example.com", DomainNames.registrable("WWW.Example.COM."))
    }

    @Test
    fun blockChoicesOfferHostAndSite() {
        assertEquals(listOf("tracker.ads.example.net", "example.net"), DomainNames.blockChoices("tracker.ads.example.net"))
        assertEquals(listOf("example.net"), DomainNames.blockChoices("example.net"))
        assertEquals(listOf("163.com"), DomainNames.blockChoices("163.com"))
        assertEquals(emptyList<String>(), DomainNames.blockChoices("203.0.113.9"))
        assertEquals(emptyList<String>(), DomainNames.blockChoices("t13d1516h2_8daaf6152771_d8a2da3f94cd"))
    }

    @Test
    fun domainAndAddressRecognition() {
        assertTrue(DomainNames.isDomainName("163.com"))
        assertTrue(DomainNames.isDomainName("1password.com"))
        assertFalse(DomainNames.isDomainName("1.2.3.4"))
        assertFalse(DomainNames.isDomainName("AS13335"))
        assertFalse(DomainNames.isDomainName("123.456"))
        assertTrue(DomainNames.isIpLiteral("2001:db8::1"))
        assertTrue(DomainNames.isIpLiteral("10.0.0.1"))
        assertFalse(DomainNames.isIpLiteral("example.com"))
    }

    @Test
    fun matchingRulesCoverSubdomains() {
        val rules = setOf("example.com", "ads.example.com")
        assertEquals("ads.example.com", DomainNames.matchingRule("x.ads.example.com", rules))
        assertEquals("example.com", DomainNames.matchingRule("example.com", rules))
        assertNull(DomainNames.matchingRule("notexample.com", rules))
    }

    @Test
    fun blockReasonsInPlainWords() {
        val feeds = listOf(FeedEntity("urlhaus", "URLhaus", "https://x", "malware", enabled = true, builtin = true))
        assertEquals("Listed by the feed “URLhaus” (malware) as bad.example.", BlockReasons.explain("feed:urlhaus (bad.example)", feeds))
        assertEquals("Listed by the feed “other” as x.example.", BlockReasons.explain("feed:other (x.example)", feeds))
        assertEquals("Your block rule for example.com (Settings → Custom rules).", BlockReasons.explain("custom (example.com)", feeds))
        assertTrue(BlockReasons.explain("app", feeds, "Chrome").contains("Chrome"))
        assertTrue(BlockReasons.explain("feed:urlhaus (tracker.example via CNAME t.tracker.example)", feeds).contains("alias (CNAME) of t.tracker.example"))
        assertTrue(BlockReasons.explain(null, feeds).startsWith("Blocked"))
    }

    @Test
    fun perAppReasons() {
        val feeds = emptyList<FeedEntity>()
        assertEquals(
            "Network access of Chrome is blocked while it is in the background (Apps → Chrome → Network access).",
            BlockReasons.explain("app rule: background", feeds, "Chrome"),
        )
        assertTrue(BlockReasons.explain("app rule: wifi", feeds, "Chrome").contains("on Wi-Fi"))
        assertTrue(BlockReasons.explain("app rule: cellular", feeds).contains("mobile data"))
        assertTrue(BlockReasons.explain("app rule: screen off", feeds).contains("screen is off"))
        assertEquals(
            "Your rule for Chrome blocks ads.example.com (for this app only).",
            BlockReasons.explain("app domain rule (ads.example.com)", feeds, "Chrome"),
        )
        for (r in listOf("app", "app rule: wifi", "app domain rule (x.example)")) assertTrue(r, BlockReasons.isPerApp(r))
        for (r in listOf(null, "custom (x.example)", "feed:urlhaus (x.example)", "encrypted_dns")) assertFalse("$r", BlockReasons.isPerApp(r))
    }

    private fun alert(id: Long, kind: String, pkg: String, target: String, severity: String = "medium") =
        AlertEntity(id = id, ts = id, kind = kind, severity = severity, uid = null, pkg = pkg, target = target, message = "m", detail = "{}")

    @Test
    fun alertMutes() {
        val a = alert(1, "beacon", "com.a", "x.example")
        val b = alert(2, "beacon", "com.a", "y.example")
        val c = alert(3, "beacon", "com.b", "x.example")
        val expected = AlertMutes.add(emptyList(), AlertMute("beacon", "com.a", "x.example"))
        assertTrue(AlertMutes.isMuted(expected, a))
        assertFalse(AlertMutes.isMuted(expected, b))
        assertFalse(AlertMutes.isMuted(expected, c))

        // Muting the kind for the app replaces the narrower mute and covers every target.
        val kind = AlertMutes.add(expected, AlertMute("beacon", "com.a"))
        assertEquals(1, kind.size)
        assertTrue(AlertMutes.isMuted(kind, b))
        // Adding a narrower mute under it changes nothing.
        assertEquals(kind, AlertMutes.add(kind, AlertMute("beacon", "com.a", "z.example")))
        assertEquals(emptyList<AlertMute>(), AlertMutes.remove(kind, "beacon", "com.a", "x.example"))
    }

    @Test
    fun alertFilters() {
        val alerts = listOf(
            alert(1, "beacon", "com.a", "x.example", "medium"),
            alert(2, "threat_domain", "com.a", "bad.example", "high"),
            alert(3, "beacon", "com.b", "y.example", "medium"),
        )
        val mutes = listOf(AlertMute("beacon", "com.a"))
        assertEquals(listOf(2L, 3L), filterAlerts(alerts, mutes, null, null, showMuted = false).map { it.id })
        assertEquals(listOf(1L), filterAlerts(alerts, mutes, null, null, showMuted = true).map { it.id })
        assertEquals(listOf(2L), filterAlerts(alerts, mutes, "high", null, showMuted = false).map { it.id })
        assertEquals(listOf(3L), filterAlerts(alerts, mutes, null, "beacon", showMuted = false).map { it.id })
    }

    @Test
    fun appWindowFollowsShortRetention() {
        assertEquals(7, MainViewModel.appWindowDays(90))
        assertEquals(7, MainViewModel.appWindowDays(7))
        assertEquals(1, MainViewModel.appWindowDays(1))
    }

    @Test
    fun exportStreamingNeedsAValidDestination() {
        assertNotNull(validationError(ExportSettings()))
        assertNull(validationError(ExportSettings(host = "siem.example", port = 6514)))
        assertNotNull(validationError(ExportSettings(mode = "http", url = "")))
        assertNull(validationError(ExportSettings(mode = "http", url = "https://siem.example/in")))
        assertNotNull(validationError(ExportSettings(mode = "http", httpFormat = "elastic_bulk", url = "https://es:9200/_bulk")))
        assertNull(validationError(ExportSettings(mode = "http", httpFormat = "elastic_bulk", url = "https://es:9200/vigil/_bulk")))
    }
}
