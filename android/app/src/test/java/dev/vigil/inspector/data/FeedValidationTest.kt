package dev.vigil.inspector.data

import dev.vigil.inspector.engine.FeedSummary
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class FeedValidationTest {
    @Test
    fun acceptsNormalFeeds() {
        assertNull(FeedValidation.check(FeedSummary(domains = 1000, rejectedLines = 3), null))
        assertNull(FeedValidation.check(FeedSummary(ipRanges = 50), previousEntries = 60))
        // Exactly half unreadable is still accepted.
        assertNull(FeedValidation.check(FeedSummary(domains = 10, rejectedLines = 10), null))
        // Shrinking to 10 % is the limit.
        assertNull(FeedValidation.check(FeedSummary(domains = 100), previousEntries = 1000))
    }

    @Test
    fun rejectsEmptyFeeds() {
        assertNotNull(FeedValidation.check(FeedSummary(), null))
        assertNotNull(FeedValidation.check(FeedSummary(rejectedLines = 40), null))
    }

    @Test
    fun rejectsMostlyUnreadableContent() {
        // A captive-portal HTML page that happens to contain a few host-like tokens.
        assertNotNull(FeedValidation.check(FeedSummary(domains = 3, rejectedLines = 120), null))
    }

    @Test
    fun rejectsSuddenCollapse() {
        assertNotNull(FeedValidation.check(FeedSummary(domains = 99), previousEntries = 1000))
        assertNotNull(FeedValidation.check(FeedSummary(domains = 5, ipRanges = 4), previousEntries = 850_000))
        // No previous copy: nothing to compare against.
        assertNull(FeedValidation.check(FeedSummary(domains = 5), previousEntries = null))
        assertNull(FeedValidation.check(FeedSummary(domains = 5), previousEntries = 0))
    }
}
