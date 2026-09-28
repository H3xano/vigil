package dev.vigil.inspector.data

import dev.vigil.inspector.vpn.ConfigFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException
import java.io.StringReader

/**
 * The fixtures in src/test/resources/trackers are a trimmed excerpt of
 * AdGuard companiesdb (CC BY-SA 4.0), see their `_attribution` key.
 */
class TrackerDatabaseTest {
    private fun resource(name: String) = javaClass.getResource("/trackers/$name")!!.readText()

    private fun tmp() = File.createTempFile("trackers", ".tsv").apply { deleteOnExit() }

    private fun fixtureIndex(): Pair<TrackerDatabase.Stats, TrackerIndex> {
        val out = tmp()
        val stats = TrackerDatabase.convert(resource("trackers.json"), resource("companies.json"), out)
        return stats to TrackerDatabase.load(out)
    }

    @Test
    fun convertsTheRealFormat() {
        val (stats, index) = fixtureIndex()
        assertEquals(TrackerDatabase.Stats(domains = 10, rejected = 0, trackers = 9, companies = 3), stats)
        assertEquals(10, index.domainCount)
        assertEquals(9, index.trackerCount)
        assertEquals(3, index.companyCount)

        val dc = index.match("doubleclick.net")!!.tracker
        assertEquals("google_marketing", dc.id)
        assertEquals("Google Marketing", dc.name)
        assertEquals("advertising", dc.category)
        assertEquals("Google", dc.companyName)
        assertEquals("http://www.google.com", dc.companyWebsite)
        assertTrue(dc.isTracking)
        assertEquals("Google · Advertising", TrackerDatabase.label(dc))

        val firebase = index.match("app-measurement.com")!!.tracker
        assertEquals("mobile_analytics", firebase.category)
        assertEquals("Google · Mobile analytics", TrackerDatabase.label(firebase))

        val apis = index.match("www.googleapis.com")!!.tracker
        assertEquals("cdn", apis.category)
        assertFalse(apis.isTracking)
    }

    @Test
    fun missingCompanyFallsBackToTheTrackerName() {
        val (_, index) = fixtureIndex()
        val t = index.match("static.aaxads.com")!!.tracker
        assertNull(t.companyName)
        assertNull(t.companyWebsite)
        assertEquals("Acceptable Ads Exchange", t.company)
        assertEquals("Acceptable Ads Exchange · Advertising", TrackerDatabase.label(t))
    }

    @Test
    fun longestSuffixOnLabelBoundaries() {
        val (_, index) = fixtureIndex()
        // Subdomains match their listed parent.
        assertEquals(TrackerMatch("doubleclick.net", index.match("doubleclick.net")!!.tracker), index.match("a.b.doubleclick.net"))
        assertEquals("doubleclick.net", index.match("Securepubads.G.DoubleClick.NET.")!!.domain)
        // The longest listed suffix wins: graph.facebook.com is the Audience Network, facebook.com Facebook.
        assertEquals("facebook_audience", index.match("graph.facebook.com")!!.tracker.id)
        assertEquals("facebook_audience", index.match("x.graph.facebook.com")!!.tracker.id)
        assertEquals("facebook", index.match("www.facebook.com")!!.tracker.id)
        // firebaselogging-pa.googleapis.com is Firebase, other googleapis.com hosts Google APIs.
        assertEquals("firebase", index.match("firebaselogging-pa.googleapis.com")!!.tracker.id)
        assertEquals("googleapis.com", index.match("fcm.googleapis.com")!!.tracker.id)
        // No partial-label matches, no TLD-only matches, no IP literals.
        assertNull(index.match("notdoubleclick.net"))
        assertNull(index.match("doubleclick.net.example.org"))
        assertNull(index.match("net"))
        assertNull(index.match("com"))
        assertNull(index.match("142.250.1.1"))
        assertNull(index.match("2a00:1450::1"))
        assertNull(index.match(""))
        assertNull(index.match(null))
    }

    @Test
    fun rejectsNonCompaniesdbFiles() {
        val out = tmp()
        for ((trackers, companies) in listOf(
            "<html>captive portal</html>" to resource("companies.json"),
            "[]" to resource("companies.json"),
            """{"trackers":{}, "categories":{}}""" to resource("companies.json"),
            resource("trackers.json") to """{"not":"companies"}""",
        )) {
            try {
                TrackerDatabase.convert(trackers, companies, out)
                throw AssertionError("accepted $trackers / $companies")
            } catch (e: IOException) {
                assertNotNull(e.message)
            }
        }
    }

    @Test
    fun dropsUnusableDomainsAndUnknownTrackers() {
        val trackers = """
            {"categories": {"4": "advertising"},
             "trackers": {"ads": {"name": "Ads\tInc", "categoryId": 4, "companyId": "nope"}, "odd": {"name": "Odd", "categoryId": 99}},
             "trackerDomains": {"ads.example": "ads", "bad domain": "ads", "x.example": "missing", "odd.example": "odd", "EXAMPLE.org.": "ads"}}
        """.trimIndent()
        val out = tmp()
        val stats = TrackerDatabase.convert(trackers, """{"companies": {}}""", out)
        assertEquals(TrackerDatabase.Stats(domains = 3, rejected = 2, trackers = 2, companies = 0), stats)
        val index = TrackerDatabase.load(out)
        val ads = index.match("sub.ads.example")!!.tracker
        assertEquals("Ads Inc", ads.name) // tabs cannot break the file
        assertNull(ads.companyName) // unknown company id
        assertEquals("unknown", index.match("odd.example")!!.tracker.category) // unknown category id
        assertNotNull(index.match("example.org"))
    }

    @Test
    fun loadSkipsMalformedLines() {
        val index = TrackerDatabase.load(
            StringReader(
                "# header\n\nc\tg\tGoogle\thttps://google.com\nt\tga\tGoogle Analytics\tsite_analytics\tg\n" +
                    "t\tshort\nd\tgoogle-analytics.com\tga\nd\torphan.example\tnobody\nx\tunknown\nd\n",
            ),
        )
        assertEquals(1, index.domainCount)
        assertEquals("Google · Analytics", TrackerDatabase.label(index.match("ssl.google-analytics.com")!!.tracker))
    }

    @Test
    fun validation() {
        assertNull(TrackerDatabase.validate(TrackerDatabase.Stats(5000, 10, 3000, 2000), null))
        assertNotNull(TrackerDatabase.validate(TrackerDatabase.Stats(0, 0, 0, 0), null))
        assertNotNull(TrackerDatabase.validate(TrackerDatabase.Stats(10, 0, 9, 3), null)) // truncated
        assertNotNull(TrackerDatabase.validate(TrackerDatabase.Stats(5000, 1000, 3000, 2000), null)) // too many rejected
        assertNotNull(TrackerDatabase.validate(TrackerDatabase.Stats(2000, 0, 1000, 800), 5000)) // shrank by more than half
        assertNull(TrackerDatabase.validate(TrackerDatabase.Stats(4000, 0, 3000, 2000), 5000))
    }

    @Test
    fun categoryLabels() {
        assertEquals("Mobile analytics", TrackerDatabase.categoryLabel("mobile_analytics"))
        assertEquals("CDN", TrackerDatabase.categoryLabel("cdn"))
        assertEquals("New thing", TrackerDatabase.categoryLabel("new_thing"))
        assertTrue(TrackerDatabase.isTrackingCategory("telemetry"))
        assertFalse(TrackerDatabase.isTrackingCategory("hosting"))
    }

    @Test
    fun catalogueEntryAndSchedule() {
        val feed = FeedCatalog.builtin.single { it.kind == FeedKinds.TRACKERS }
        assertEquals(TrackerDatabase.FEED_ID, feed.id)
        assertTrue(feed.enabled)
        assertTrue(feed.description.contains("CC BY-SA 4.0"))
        assertTrue(TrackerDatabase.CATEGORY in FeedCatalog.categories)
        assertEquals(
            "https://raw.githubusercontent.com/AdguardTeam/companiesdb/main/dist/companies.json",
            TrackerDatabase.companiesUrl(feed.url),
        )
        // Weekly like the ASN table, at most daily when forced.
        assertEquals(TrackerDatabase.MAX_AGE_MS, FeedRepository.maxAgeFor(feed, FeedRepository.MAX_AGE_MS, force = false))
        assertTrue(FeedRepository.maxAgeFor(feed, FeedRepository.MAX_AGE_MS, force = true) > 0)
        // Read by the app only: never handed to the engine.
        val list = FeedCatalog.builtin.first { it.id == "urlhaus" }
        assertEquals(listOf(list), ConfigFactory.loadableFeeds(listOf(feed, list)) { true })
    }
}
