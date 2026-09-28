package dev.vigil.inspector.processing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ForegroundStateTest {
    @Test
    fun unknownUntilAResumeIsSeen() {
        val s = ForegroundState()
        // The app on screen resumed before the first query window: nothing is
        // known, so nothing may be called background (for flow tagging).
        assertNull(s.isBackground("com.example.chat", permitted = true, interactive = true))
        // Exfil counts it as foreground (not uploaded "in the background").
        assertEquals(false, s.isBackgroundForExfil("com.example.chat", permitted = true, interactive = true))
        // Screen off: everything is background, known or not.
        assertEquals(true, s.isBackground("com.example.chat", permitted = true, interactive = false))
        assertEquals(true, s.isBackgroundForExfil("com.example.chat", permitted = true, interactive = false))

        s.resumed("com.example.chat")
        assertEquals(false, s.isBackground("com.example.chat", true, true))
        assertEquals(true, s.isBackground("com.example.sync", true, true))
        assertEquals(true, s.isBackgroundForExfil("com.example.sync", true, true))
        s.paused("com.example.other") // someone else's pause changes nothing
        assertEquals(false, s.isBackground("com.example.chat", true, true))
        s.paused("com.example.chat")
        assertEquals(true, s.isBackground("com.example.chat", true, true))
    }

    @Test
    fun withoutUsageAccessStaysUnknown() {
        val s = ForegroundState()
        s.resumed("com.example.chat")
        assertNull(s.isBackground("com.example.chat", permitted = false, interactive = true))
        // ExfilDetector then counts uploads as "unknown" (its documented no-usage-access mode).
        assertNull(s.isBackgroundForExfil("com.example.chat", permitted = false, interactive = true))
        // Shared-UID and unresolved keys are never classified.
        assertNull(s.isBackground("uid:10123", true, true))
        assertNull(s.isBackgroundForExfil("uid:10123", true, true))
        assertNull(ForegroundState().isBackgroundForExfil("uid:10123", true, true))
    }
}
