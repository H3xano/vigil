package dev.vigil.inspector.ui

import dev.vigil.inspector.data.AlertMute
import dev.vigil.inspector.data.AlertMutes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MuteChangeTest {
    private val target1 = AlertMute("new_destination", "com.a", "x.example", since = 1)
    private val target2 = AlertMute("new_destination", "com.a", "y.example", since = 2)
    private val other = AlertMute("beacon", "com.b", null, since = 3)

    @Test
    fun noChangeWhenAlreadyCovered() {
        val kind = AlertMute("new_destination", "com.a", null, since = 1)
        assertNull(MuteChange.of(listOf(kind), AlertMute("new_destination", "com.a", "x.example", since = 9)))
        assertNull(MuteChange.of(listOf(target1), target1.copy(since = 9)))
    }

    @Test
    fun undoRemovesOnlyTheAddedMute() {
        val mute = AlertMute("beacon", "com.c", "c2.example", since = 10)
        val change = MuteChange.of(listOf(other), mute)!!
        assertEquals(emptyList<AlertMute>(), change.replaced)
        // Another mute was added after this one: Undo keeps it.
        val later = AlertMute("threat_domain", "com.d", null, since = 11)
        val current = AlertMutes.add(AlertMutes.add(listOf(other), mute), later)
        assertEquals(listOf(other, later), change.undo(current))
    }

    @Test
    fun undoRestoresTheNarrowerMutesItReplaced() {
        val before = listOf(target1, other, target2)
        val kind = AlertMute("new_destination", "com.a", null, since = 10)
        val change = MuteChange.of(before, kind)!!
        assertEquals(listOf(target1, target2), change.replaced)
        val after = AlertMutes.add(before, kind)
        assertEquals(listOf(other, kind), after)
        val later = AlertMute("threat_ip", "com.e", null, since = 11)
        assertEquals(listOf(other, later, target1, target2), change.undo(after + later))
    }

    @Test
    fun undoDoesNotRestoreWhatIsCoveredAgain() {
        val kind = AlertMute("new_destination", "com.a", null, since = 10)
        val change = MuteChange.of(listOf(target1), kind)!!
        // The mute was removed meanwhile and the same kind muted again (a different entry).
        val again = kind.copy(since = 20)
        assertEquals(listOf(again), change.undo(listOf(again)))
    }
}
