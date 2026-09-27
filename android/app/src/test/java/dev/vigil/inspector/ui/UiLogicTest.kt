package dev.vigil.inspector.ui

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UiLogicTest {
    @Test
    fun routeWhitelist() {
        for (r in listOf("dashboard", "activity", "apps", "alerts", "settings", "feeds", "export", "rules")) assertEquals(r, Routes.sanitize(r))
        assertEquals("app/com.android.shell", Routes.sanitize("app/com.android.shell"))
        assertEquals("app/uid:1000", Routes.sanitize("app/uid:1000"))
        assertEquals("app/unknown", Routes.sanitize("app/unknown"))
        assertEquals("flow/123", Routes.sanitize("flow/123"))
        assertNull(Routes.sanitize(null))
        assertNull(Routes.sanitize(""))
        assertNull(Routes.sanitize("nope"))
        assertNull(Routes.sanitize("flow/abc"))
        assertNull(Routes.sanitize("flow/99999999999999999999"))
        assertNull(Routes.sanitize("flow/"))
        assertNull(Routes.sanitize("app/"))
        assertNull(Routes.sanitize("app/a/b"))
        assertNull(Routes.sanitize("app/{pkg}"))
        assertNull(Routes.sanitize("/dashboard"))
        assertNull(Routes.sanitize("android-app://evil"))
    }

    @Test
    fun formatting() {
        assertEquals("512 B", formatBytes(512))
        assertEquals("1.0 KB", formatBytes(1024))
        assertEquals("1.5 MB", formatBytes(1024L * 1024 * 3 / 2))
        assertEquals("100 GB", formatBytes(100L * 1024 * 1024 * 1024))
        assertEquals("999", formatCount(999))
        assertEquals("1.2k", formatCount(1_234))
        assertEquals("12k", formatCount(12_345))
        assertEquals("1.2M", formatCount(1_234_567))
        assertEquals("now", formatRelative(10_000, now = 12_000))
        assertEquals("now", formatRelative(20_000, now = 12_000))
        assertEquals("30s ago", formatRelative(0, now = 30_000))
        assertEquals("5m ago", formatRelative(0, now = 300_000))
        assertEquals("2h ago", formatRelative(0, now = 7_200_000))
        assertEquals("3d ago", formatRelative(0, now = 3 * 86_400_000L))
        assertEquals("250 ms", formatDuration(250))
        assertEquals("1.5 s", formatDuration(1_500))
        assertEquals("2 min 5 s", formatDuration(125_000))
        assertEquals("1 h 1 min", formatDuration(3_660_000))
        assertEquals("1 connection", plural(1, "connection"))
        assertEquals("0 connections", plural(0, "connection"))
        assertEquals("2 entries", plural(2, "entry", "entries"))
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun throttleLatestEmitsFirstAtOnceThenTheLatest() = runTest {
        val source = flow {
            repeat(10) {
                emit(it)
                delay(100)
            }
        }
        val out = source.throttleLatest(330).toList()
        assertEquals(0, out.first())
        assertEquals("the final value is never lost", 9, out.last())
        assertEquals(listOf(0, 3, 6, 9), out)
        assertEquals(1320L, currentTime)
    }
}
