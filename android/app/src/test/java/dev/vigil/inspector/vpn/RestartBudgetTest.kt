package dev.vigil.inspector.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RestartBudgetTest {
    @Test
    fun givesUpAfterThreeRestartsInFiveMinutes() {
        val b = RestartBudget()
        assertEquals(1_000L, b.onFailure(0))
        assertEquals(2_000L, b.onFailure(10_000))
        assertEquals(4_000L, b.onFailure(20_000))
        assertNull(b.onFailure(30_000))
    }

    @Test
    fun oldFailuresExpire() {
        val b = RestartBudget()
        b.onFailure(0)
        b.onFailure(1_000)
        b.onFailure(2_000)
        // Five minutes after the first ones, the window is empty again.
        assertEquals(1_000L, b.onFailure(2_000 + 5 * 60_000 + 1))
    }

    @Test
    fun resetRestoresTheBudget() {
        val b = RestartBudget()
        repeat(4) { b.onFailure(it * 1_000L) }
        b.reset()
        assertEquals(1_000L, b.onFailure(5_000))
    }
}
