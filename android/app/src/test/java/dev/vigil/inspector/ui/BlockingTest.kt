package dev.vigil.inspector.ui

import dev.vigil.inspector.R
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
        // The engine matches ASCII names only: Unicode is converted by ruleDomain first.
        assertFalse(DomainNames.isDomainName("bücher.de"))
        assertNull(DomainNames.registrable("bücher.de"))
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
        assertEquals(
            UiText.of(R.string.block_reason_feed_category_rule, UiText.Raw("URLhaus"), "malware", "bad.example"),
            BlockReasons.explainText("feed:urlhaus (bad.example)", feeds),
        )
        assertEquals(UiText.of(R.string.block_reason_feed_rule, UiText.Raw("other"), "x.example"), BlockReasons.explainText("feed:other (x.example)", feeds))
        assertEquals(UiText.of(R.string.block_reason_feed, UiText.Raw("other")), BlockReasons.explainText("feed:other", feeds))
        assertEquals(UiText.of(R.string.block_reason_custom, "example.com"), BlockReasons.explainText("custom (example.com)", feeds))
        assertEquals(UiText.of(R.string.block_reason_app_all, "Chrome"), BlockReasons.explainText("app", feeds, "Chrome"))
        assertEquals(
            UiText.of(
                R.string.block_reason_with_cname,
                UiText.of(R.string.block_reason_feed_category_rule, UiText.Raw("URLhaus"), "malware", "tracker.example"),
                "t.tracker.example",
            ),
            BlockReasons.explainText("feed:urlhaus (tracker.example via CNAME t.tracker.example)", feeds),
        )
        assertEquals(
            UiText.of(R.string.block_reason_ja4_rule, "foxio", "Sliver"),
            BlockReasons.explainText("ja4:foxio (Sliver)", feeds),
        )
        assertEquals(UiText.of(R.string.block_reason_none), BlockReasons.explainText(null, feeds))
        assertEquals(UiText.of(R.string.block_reason_encrypted_dns), BlockReasons.explainText("encrypted_dns", feeds))
        assertEquals(
            UiText.of(R.string.block_reason_nonstandard_dns, "DNS opcode 2"),
            BlockReasons.explainText("not a standard query (DNS opcode 2)", feeds),
        )
        assertEquals(UiText.Raw("future_code"), BlockReasons.explainText("future_code", feeds))
    }

    @Test
    fun perAppReasons() {
        val feeds = emptyList<FeedEntity>()
        val thisApp = UiText.of(R.string.block_reason_this_app)
        assertEquals(UiText.of(R.string.block_reason_app_background, "Chrome"), BlockReasons.explainText("app rule: background", feeds, "Chrome"))
        assertEquals(UiText.of(R.string.block_reason_app_wifi, "Chrome"), BlockReasons.explainText("app rule: wifi", feeds, "Chrome"))
        assertEquals(UiText.of(R.string.block_reason_app_cellular, thisApp), BlockReasons.explainText("app rule: cellular", feeds))
        assertEquals(UiText.of(R.string.block_reason_app_screen_off, thisApp), BlockReasons.explainText("app rule: screen off", feeds))
        assertEquals(UiText.of(R.string.block_reason_app_other, thisApp, "new"), BlockReasons.explainText("app rule: new", feeds))
        assertEquals(
            UiText.of(R.string.block_reason_app_domain, "Chrome", "ads.example.com"),
            BlockReasons.explainText("app domain rule (ads.example.com)", feeds, "Chrome"),
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

    @Test
    fun ruleDomainsAreConvertedToAscii() {
        assertEquals("xn--bcher-kva.de", DomainNames.ruleDomain("bücher.de"))
        assertEquals("xn--bcher-kva.de", DomainNames.ruleDomain("  *.Bücher.DE. "))
        assertEquals("example.com", DomainNames.ruleDomain("*.Example.com"))
        assertEquals("ads_tracker.example.com", DomainNames.ruleDomain("ads_tracker.example.com"))
        assertEquals("xn--fiqs8s.example", DomainNames.ruleDomain("中国.example"))
        assertNull(DomainNames.ruleDomain(""))
        assertNull(DomainNames.ruleDomain("localhost"))
        assertNull(DomainNames.ruleDomain("1.2.3.4"))
        assertNull(DomainNames.ruleDomain("a b.example"))
        assertNull(DomainNames.ruleDomain("a..example"))
        // A label too long for DNS (IDN refuses it) or a name IDN cannot convert.
        assertNull(DomainNames.ruleDomain("${"a".repeat(64)}.example"))
        assertNull(DomainNames.ruleDomain("${"ü".repeat(60)}.example"))
    }
}
