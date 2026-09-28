package dev.vigil.inspector.data

import org.junit.Assert.assertEquals
import org.junit.Test

class FeedOrderTest {
    @Test
    fun threatListsDownloadBeforeLabellingData() {
        val ordered = FeedCatalog.builtin.sortedBy(FeedRepository::downloadPriority).map { it.id }
        val first = FeedCatalog.builtin.filter { FeedRepository.downloadPriority(it) == 0 }.map { it.id }
        assertEquals(listOf(FeedCatalog.MVT_INDEX_ID), first)
        assertEquals("iptoasn", ordered.last())
        assertEquals(true, ordered.indexOf("urlhaus") < ordered.indexOf("echap-stalkerware-network"))
        assertEquals(true, ordered.indexOf("echap-stalkerware-network") < ordered.indexOf(TrackerDatabase.FEED_ID))
    }
}
