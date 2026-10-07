package dev.vigil.inspector.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HistoryCapTest {
    private val mb = 1024L * 1024

    @Test
    fun usedBytesExcludeFreePages() {
        assertEquals(90L * 4096, HistoryCap.usedBytes(pageCount = 100, freePages = 10, pageSize = 4096))
        assertEquals(0L, HistoryCap.usedBytes(pageCount = 5, freePages = 9, pageSize = 4096))
    }

    @Test
    fun startsAboveTheCapAndStopsBelowTheTarget() {
        assertTrue(HistoryCap.TARGET_BYTES < HistoryCap.MAX_BYTES)
        // Under the cap: nothing to do, even above the target.
        assertNull(HistoryCap.next(HistoryCap.MAX_BYTES, trimming = false, oldestFlow = 1, oldestDns = 2))
        assertNull(HistoryCap.next(HistoryCap.TARGET_BYTES + mb, trimming = false, oldestFlow = 1, oldestDns = 2))
        // Over the cap: trims.
        assertEquals(HistoryCap.Table.FLOWS, HistoryCap.next(HistoryCap.MAX_BYTES + 1, trimming = false, oldestFlow = 1, oldestDns = 2))
        // Once trimming, goes on down to the target.
        assertEquals(HistoryCap.Table.FLOWS, HistoryCap.next(HistoryCap.TARGET_BYTES + mb, trimming = true, oldestFlow = 1, oldestDns = 2))
        assertNull(HistoryCap.next(HistoryCap.TARGET_BYTES, trimming = true, oldestFlow = 1, oldestDns = 2))
    }

    @Test
    fun trimsTheTableWithTheOlderRowsFirst() {
        val over = HistoryCap.MAX_BYTES + 1
        assertEquals(HistoryCap.Table.DNS, HistoryCap.next(over, trimming = false, oldestFlow = 500, oldestDns = 100))
        assertEquals(HistoryCap.Table.FLOWS, HistoryCap.next(over, trimming = false, oldestFlow = 100, oldestDns = 500))
        assertEquals(HistoryCap.Table.FLOWS, HistoryCap.next(over, trimming = false, oldestFlow = 100, oldestDns = 100))
        // An empty table is skipped; both empty (the rest is alerts and learned destinations): stop.
        assertEquals(HistoryCap.Table.DNS, HistoryCap.next(over, trimming = false, oldestFlow = null, oldestDns = 100))
        assertEquals(HistoryCap.Table.FLOWS, HistoryCap.next(over, trimming = false, oldestFlow = 100, oldestDns = null))
        assertNull(HistoryCap.next(over, trimming = false, oldestFlow = null, oldestDns = null))
    }

    @Test
    fun customLimits() {
        assertEquals(HistoryCap.Table.DNS, HistoryCap.next(11, trimming = false, oldestFlow = null, oldestDns = 1, max = 10, target = 5))
        assertEquals(HistoryCap.Table.DNS, HistoryCap.next(6, trimming = true, oldestFlow = null, oldestDns = 1, max = 10, target = 5))
        assertNull(HistoryCap.next(6, trimming = false, oldestFlow = null, oldestDns = 1, max = 10, target = 5))
    }

    @Test
    fun historyScanWindowsCoverTheIdsInBoundedSteps() {
        assertEquals(emptyList<LongRange>(), HistoryScan.windows(IdRange(null, null), 10).toList())
        assertEquals(listOf(5L..5L), HistoryScan.windows(IdRange(5, 5), 10).toList())
        assertEquals(listOf(1L..10L, 11L..20L, 21L..25L), HistoryScan.windows(IdRange(1, 25), 10).toList())
        assertEquals(listOf(1L..10L, 11L..20L), HistoryScan.windows(IdRange(1, 20), 10).toList())
        // Near Long.MAX_VALUE without overflow.
        val top = Long.MAX_VALUE
        assertEquals(listOf(top - 4..top), HistoryScan.windows(IdRange(top - 4, top), 10).toList())
        val big = HistoryScan.windows(IdRange(1, 3_000_000)).toList()
        assertEquals(300, big.size)
        assertTrue(big.all { it.last - it.first + 1 <= HistoryScan.WINDOW })
    }
}
