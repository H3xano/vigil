package dev.vigil.inspector.ui

import dev.vigil.inspector.R
import dev.vigil.inspector.engine.StatsEvent
import dev.vigil.inspector.ui.screens.encryptedDnsStatus
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
        for (r in listOf("dashboard", "activity", "apps", "alerts", "settings", "feeds", "export", "rules", "dns")) assertEquals(r, Routes.sanitize(r))
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
        assertEquals(UiText.of(R.string.activity_time_now), relativeTime(10_000, now = 12_000))
        assertEquals(UiText.of(R.string.activity_time_now), relativeTime(20_000, now = 12_000))
        assertEquals(UiText.plural(R.plurals.activity_time_seconds_ago, 30, 30L), relativeTime(0, now = 30_000))
        assertEquals(UiText.plural(R.plurals.activity_time_minutes_ago, 5, 5L), relativeTime(0, now = 300_000))
        assertEquals(UiText.plural(R.plurals.activity_time_hours_ago, 2, 2L), relativeTime(0, now = 7_200_000))
        assertEquals(UiText.plural(R.plurals.activity_time_days_ago, 3, 3L), relativeTime(0, now = 3 * 86_400_000L))
        assertEquals("now", EnglishStrings.resolve(relativeTime(10_000, now = 12_000)))
        assertEquals("30s ago", EnglishStrings.resolve(relativeTime(0, now = 30_000)))
        assertEquals("5m ago", EnglishStrings.resolve(relativeTime(0, now = 300_000)))
        assertEquals("2h ago", EnglishStrings.resolve(relativeTime(0, now = 7_200_000)))
        assertEquals("3d ago", EnglishStrings.resolve(relativeTime(0, now = 3 * 86_400_000L)))
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

    @Test
    fun encryptedDnsStatusLine() {
        val on = dev.vigil.inspector.data.EncryptedDnsSettings(mode = "doh")
        val now = 100_000L
        assertNull(encryptedDnsStatus(dev.vigil.inspector.data.EncryptedDnsSettings(), true, null, now))
        assertEquals(false, encryptedDnsStatus(on, false, null, now)!!.second)
        assertEquals(UiText.of(R.string.dns_status_inactive), encryptedDnsStatus(on, false, null, now)!!.first)
        assertEquals(UiText.of(R.string.dns_status_waiting), encryptedDnsStatus(on, true, StatsEvent(), now)!!.first)
        val ok = encryptedDnsStatus(on, true, StatsEvent(encryptedDnsOk = 5, encryptedDnsLastOkTs = now - 10_000), now)!!
        assertEquals(
            UiText.of(
                R.string.dns_status_working,
                UiText.plural(R.plurals.activity_time_seconds_ago, 10, 10L),
                UiText.of(
                    R.string.dns_status_counts,
                    UiText.plural(R.plurals.dns_status_answered, 5, 5L),
                    UiText.plural(R.plurals.dns_status_failed, 0, 0L),
                ),
            ),
            ok.first,
        )
        // The emulator tests look for "Working" on this screen.
        assertEquals("Working: last encrypted answer 10s ago · 5 answered encrypted, 0 failed", EnglishStrings.resolve(ok.first))
        assertEquals(false, ok.second)
        val bad = encryptedDnsStatus(
            on, true,
            StatsEvent(encryptedDnsOk = 5, encryptedDnsFailed = 2, encryptedDnsFallback = 2, encryptedDnsLastOkTs = now - 60_000,
                encryptedDnsLastErrorTs = now - 2_000, encryptedDnsLastError = "dns.quad9.net (9.9.9.9:443): timed out"),
            now,
        )!!
        assertEquals(true, bad.second)
        assertEquals(
            UiText.of(
                R.string.dns_status_failing,
                UiText.of(R.string.activity_time_now),
                UiText.Raw("dns.quad9.net (9.9.9.9:443): timed out"),
                UiText.of(
                    R.string.dns_status_counts_fallback,
                    UiText.plural(R.plurals.dns_status_answered, 5, 5L),
                    UiText.plural(R.plurals.dns_status_failed, 2, 2L),
                    UiText.plural(R.plurals.dns_status_fallback, 2, 2L),
                ),
            ),
            bad.first,
        )
        assertEquals(
            "Failing (last error now): dns.quad9.net (9.9.9.9:443): timed out · 5 answered encrypted, 2 failed (2 answered over plain DNS)",
            EnglishStrings.resolve(bad.first),
        )
        val noMessage = encryptedDnsStatus(on, true, StatsEvent(encryptedDnsFailed = 1, encryptedDnsLastErrorTs = now), now)!!
        assertEquals("Failing (last error now): unknown error · 0 answered encrypted, 1 failed", EnglishStrings.resolve(noMessage.first))
    }
}
