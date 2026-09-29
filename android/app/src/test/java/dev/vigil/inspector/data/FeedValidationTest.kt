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
    fun ja4FeedsCountFingerprintsOnly() {
        assertNull(FeedValidation.check(FeedSummary(ja4 = 7, rejectedLines = 1), null, FeedKinds.JA4))
        // Mixed lists count JA4 lines as entries too.
        assertNull(FeedValidation.check(FeedSummary(ja4 = 7), null, FeedKinds.LIST))
        assertNotNull(FeedValidation.check(FeedSummary(domains = 500), null, FeedKinds.JA4))
        assertNotNull(FeedValidation.check(FeedSummary(ja4 = 2, domains = 30), null, FeedKinds.JA4))
        assertNotNull(FeedValidation.check(FeedSummary(ja4 = 2), previousEntries = 100, kind = FeedKinds.JA4))
    }

    @Test
    fun taxiiResyncMustNotCollapse() {
        assertNull(FeedValidation.checkTaxiiResync(0, null))
        assertNull(FeedValidation.checkTaxiiResync(0, 100))
        assertNull(FeedValidation.checkTaxiiResync(500, 5000))
        assertNotNull(FeedValidation.checkTaxiiResync(10, 5000))
    }

    @Test
    fun rejectsSuddenCollapse() {
        assertNotNull(FeedValidation.check(FeedSummary(domains = 99), previousEntries = 1000))
        assertNotNull(FeedValidation.check(FeedSummary(domains = 5, ipRanges = 4), previousEntries = 850_000))
        // No previous copy: nothing to compare against.
        assertNull(FeedValidation.check(FeedSummary(domains = 5), previousEntries = null))
        assertNull(FeedValidation.check(FeedSummary(domains = 5), previousEntries = 0))
    }

    @Test
    fun spywarePacksRefuseToLoseHalfTheirIndicators() {
        assertNull(FeedValidation.checkSpywarePack(1000, null))
        assertNull(FeedValidation.checkSpywarePack(500, 1000))
        assertNull(FeedValidation.checkSpywarePack(1200, 1000))
        // A pack stripped of one stalkerware family's indicators (a MITM'd download) is refused.
        assertNotNull(FeedValidation.checkSpywarePack(499, 1000))
        assertNotNull(FeedValidation.checkSpywarePack(0, null))
    }
}
