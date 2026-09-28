package dev.vigil.inspector.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TrackerSummariesTest {
    private val google = "Google"
    private val index = TrackerIndex(
        mapOf(
            "doubleclick.net" to Tracker("google_marketing", "Google Marketing", "advertising", google, "http://www.google.com"),
            "app-measurement.com" to Tracker("firebase", "Firebase", "mobile_analytics", google, "http://www.google.com"),
            "googleapis.com" to Tracker("googleapis.com", "Google APIs", "cdn", google, "http://www.google.com"),
            "fbcdn.net" to Tracker("facebook_cdn", "Facebook CDN", "cdn", "Meta", null),
            "aaxads.com" to Tracker("aaxads.com", "Acceptable Ads Exchange", "advertising", null, null),
        ),
    )

    @Test
    fun groupsByCompanyWithCountsAndBlocking() {
        val hits = listOf(
            DomainHits("app", "ad.doubleclick.net", flows = 0, lookups = 4, blocked = 4),
            DomainHits("app", "AD.doubleclick.net", flows = 1, lookups = 0, blocked = 0), // same name, other case
            DomainHits("app", "app-measurement.com", flows = 3, lookups = 2, blocked = 0),
            DomainHits("app", "fcm.googleapis.com", flows = 10, lookups = 10, blocked = 0),
            DomainHits("app", "static.fbcdn.net", flows = 50, lookups = 5, blocked = 0),
            DomainHits("app", "x.aaxads.com", flows = 0, lookups = 1, blocked = 1),
            DomainHits("app", "example.org", flows = 99, lookups = 99, blocked = 0), // no label
        )
        val companies = TrackerSummaries.byCompany(index, hits)
        // Tracking companies first (even with fewer hits than Meta's CDN), then by hits.
        assertEquals(listOf("Google", "Acceptable Ads Exchange", "Meta"), companies.map { it.company })

        val g = companies[0]
        assertTrue(g.tracking)
        assertEquals(listOf("advertising", "mobile_analytics", "cdn"), g.categories)
        // Tracking domains first (ties by name), then the CDN.
        assertEquals(listOf("ad.doubleclick.net", "app-measurement.com", "fcm.googleapis.com"), g.domains.map { it.domain })
        assertEquals(14L, g.flows)
        assertEquals(16L, g.lookups)
        assertEquals(4L, g.blocked)
        assertFalse(g.allBlocked)
        assertEquals(5L, g.domains.single { it.domain == "ad.doubleclick.net" }.total)
        assertEquals("http://www.google.com", g.website)

        val aax = companies[1]
        assertTrue(aax.allBlocked) // missing company: grouped under the tracker's name
        assertFalse(companies[2].tracking)
    }

    @Test
    fun countsTrackingTrackersPerApp() {
        val pairs = listOf(
            AppDomain("a", "ad.doubleclick.net"),
            AppDomain("a", "stats.g.doubleclick.net"), // same tracker
            AppDomain("a", "app-measurement.com"),
            AppDomain("a", "fcm.googleapis.com"), // CDN: labelled, not counted
            AppDomain("b", "static.fbcdn.net"),
            AppDomain("c", "x.aaxads.com"),
            AppDomain("c", "notdoubleclick.net"),
        )
        assertEquals(mapOf("a" to 2, "c" to 1), TrackerSummaries.trackerCountsByApp(index, pairs))
    }

    @Test
    fun topCompaniesByApps() {
        val pairs = listOf(
            AppDomain("a", "ad.doubleclick.net"),
            AppDomain("a", "app-measurement.com"),
            AppDomain("b", "app-measurement.com"),
            AppDomain("c", "x.aaxads.com"),
            AppDomain("d", "static.fbcdn.net"),
        )
        val top = TrackerSummaries.topCompanies(index, pairs)
        assertEquals(listOf(CompanyApps("Google", listOf("advertising", "mobile_analytics"), 2), CompanyApps("Acceptable Ads Exchange", listOf("advertising"), 1)), top)
        assertEquals(1, TrackerSummaries.topCompanies(index, pairs, limit = 1).size)
    }
}
