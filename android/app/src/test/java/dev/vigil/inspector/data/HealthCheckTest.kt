package dev.vigil.inspector.data

import dev.vigil.inspector.R
import dev.vigil.inspector.ui.UiText
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HealthCheckTest {
    private val now = 1_800_000_000_000L
    private val day = 86_400_000L

    private val stalker = SpywarePack(
        feedId = "echap-stalkerware-apps", name = "Stalkerware apps (Echap)", source = "https://raw.githubusercontent.com/x",
        reference = FeedCatalog.ECHAP_REPO, license = FeedCatalog.ECHAP_LICENSE, downloadedAt = now - day,
        groups = listOf(
            SpywareGroup(
                "TheTruthSpy", apps = listOf("com.thetruth"), certs = listOf("SHA1:31A6ECECD97CF39BC4126B8745CD94A7C30BF81C"),
                domains = listOf("copy9.com"), ips = listOf("69.64.74.239"),
            ),
        ),
    )
    private val watch = SpywarePack(
        feedId = "echap-watchware", name = "Monitoring apps (Echap watchware)", source = "s", license = FeedCatalog.ECHAP_LICENSE,
        downloadedAt = now - day,
        groups = listOf(SpywareGroup("FamiSafe", SpywareSeverity.WARNING, apps = listOf("com.wondershare.famisafe"), domains = listOf("famisafe.com"))),
    )
    private val pegasus = SpywarePack(
        feedId = "mvt-2021-07-18-nso-pegasus", name = "NSO Group Pegasus", source = "s", reference = "https://www.amnesty.org/x",
        license = "CC BY 2.0 (Amnesty International)", downloadedAt = now - 20 * day,
        groups = listOf(
            SpywareGroup("Pegasus", domains = listOf("bad.example"), ips = listOf("198.51.100.0/24")),
            SpywareGroup("Predator", certs = listOf("SHA256:" + "AB".repeat(32))),
        ),
    )

    private fun feed(p: SpywarePack, enabled: Boolean = true, kind: String = FeedKinds.SPYWARE_APPS) =
        FeedEntity(id = p.feedId, name = p.name, url = p.source, category = "malware", enabled = enabled, builtin = true, kind = kind, lastUpdated = p.downloadedAt)

    private fun input(
        packs: List<Pair<FeedEntity, SpywarePack?>> = listOf(feed(stalker) to stalker, feed(watch) to watch, feed(pegasus, kind = FeedKinds.SPYWARE) to pegasus),
        apps: List<InstalledApp> = emptyList(),
        observed: List<ObservedName> = emptyList(),
        running: Boolean = true,
    ) = HealthCheck.Input(
        now = now, appVersion = "0.5.0", packs = packs, apps = apps, observed = observed,
        historySince = observed.minOfOrNull { it.firstSeen }, retentionDays = 7, inspectionRunning = running,
        appLabel = { if (it == "com.android.chrome") "Chrome" else it },
        text = ::text,
    )

    /** Stands in for the resources (no Robolectric): each text renders as its resource id and arguments. */
    private fun text(t: UiText): String = t.toString()

    private fun app(pkg: String, vararg certs: String) = InstalledApp(pkg, pkg.substringAfterLast('.'), certs.toList(), firstInstall = now - 3 * day)

    @Test
    fun cleanDevice() {
        val r = HealthCheck.run(input(apps = listOf(app("org.mozilla.firefox", "SHA1:" + "0".repeat(40))), observed = listOf(obs("example.org"))))
        assertEquals(HealthCheck.VERDICT_NONE, r.verdict)
        assertTrue(r.findings.isEmpty())
        assertEquals(1, r.appsChecked)
        assertEquals(1, r.destinationsChecked)
        assertEquals(
            UiText.of(R.string.health_summary_none, UiText.plural(R.plurals.health_summary_apps, 1, 1), UiText.plural(R.plurals.health_summary_destinations, 1, 1)),
            HealthCheck.verdictSummary(r),
        )
        // The 20-day-old pack is reported as out of date.
        assertTrue(r.packs.single { it.feedId == pegasus.feedId }.stale)
        assertTrue(text(UiText.of(R.string.health_note_stale, "NSO Group Pegasus")) in r.notes)
    }

    @Test
    fun appPackageAndCertificateMatches() {
        // The certificate as a device reports it (upper-case, no colons) matches the normalised pack value.
        val cert = AppCerts.normalize("31:a6:ec:ec:d9:7c:f3:9b:c4:12:6b:87:45:cd:94:a7:c3:0b:f8:1c")!!
        val r = HealthCheck.run(
            input(
                apps = listOf(
                    app("com.systemservice.renamed", cert), // renamed package, known certificate
                    app("com.thetruth"),
                    app("com.example.other", "SHA256:" + "AB".repeat(32)),
                ),
            ),
        )
        assertEquals(HealthCheck.VERDICT_FOUND, r.verdict)
        val kinds = r.findings.map { Triple(it.kind, it.pkg, it.label) }
        assertTrue(Triple(HealthCheck.KIND_APP_CERTIFICATE, "com.systemservice.renamed", "TheTruthSpy") in kinds)
        assertTrue(Triple(HealthCheck.KIND_APP_PACKAGE, "com.thetruth", "TheTruthSpy") in kinds)
        assertTrue(Triple(HealthCheck.KIND_APP_CERTIFICATE, "com.example.other", "Predator") in kinds)
        val f = r.findings.first { it.pkg == "com.thetruth" }
        assertEquals(FeedCatalog.ECHAP_REPO, f.reference)
        assertEquals(now - 3 * day, f.firstSeen)
    }

    @Test
    fun watchwareIsOnlyAWarning() {
        val r = HealthCheck.run(input(apps = listOf(app("com.wondershare.famisafe"))))
        assertEquals(HealthCheck.VERDICT_WARNINGS, r.verdict)
        assertEquals(UiText.plural(R.plurals.health_summary_monitoring, 1, 1), HealthCheck.verdictSummary(r))
        assertEquals(SpywareSeverity.WARNING, r.findings.single().severity)
        assertEquals("FamiSafe", r.findings.single().label)
    }

    private fun obs(name: String, pkg: String = "com.android.chrome", first: Long = now - 2 * day, last: Long = now - day, count: Long = 1, blocked: Long = 0) =
        ObservedName(name, pkg, first, last, count, blocked)

    @Test
    fun networkHistoryMatchesSubdomainsAddressesAndRanges() {
        val r = HealthCheck.run(
            input(
                observed = listOf(
                    // The same name from DNS, connections and learned destinations: one finding, merged.
                    obs("media.copy9.com", first = now - 5 * day, last = now - 4 * day, count = 3, blocked = 3),
                    obs("MEDIA.COPY9.COM.", first = now - 6 * day, last = now - 2 * day, count = 2, blocked = 0),
                    obs("69.64.74.239", pkg = "com.systemservice"),
                    obs("198.51.100.77", pkg = "com.systemservice"),
                    obs("notcopy9.com"),
                    obs("famisafe.com", pkg = "com.wondershare.famisafe"),
                ),
            ),
        )
        assertEquals(HealthCheck.VERDICT_FOUND, r.verdict)
        val copy9 = r.findings.single { it.indicator == "copy9.com" }
        assertEquals("media.copy9.com", copy9.observed)
        assertEquals("Chrome", copy9.appLabel)
        assertEquals(now - 6 * day, copy9.firstSeen)
        assertEquals(now - 2 * day, copy9.lastSeen)
        assertEquals(5L, copy9.count)
        assertEquals(3L, copy9.blocked)
        assertTrue(r.findings.any { it.indicator == "69.64.74.239" && it.observed == null })
        assertTrue(r.findings.any { it.indicator == "198.51.100.0/24" && it.observed == "198.51.100.77" && it.label == "Pegasus" })
        assertTrue(r.findings.none { it.observed == "notcopy9.com" })
        // Indicators first, warnings last.
        assertEquals(SpywareSeverity.WARNING, r.findings.last().severity)
        assertEquals(5, r.destinationsChecked)
    }

    @Test
    fun disabledOrMissingPacksAreNotUsed() {
        val off = HealthCheck.run(
            input(packs = listOf(feed(stalker, enabled = false) to stalker, feed(watch) to null), apps = listOf(app("com.thetruth")), running = false),
        )
        assertEquals(HealthCheck.VERDICT_NOT_CHECKED, off.verdict)
        assertTrue(off.findings.isEmpty())
        assertEquals(text(UiText.of(R.string.health_note_nothing_loaded)), off.notes.first())
        assertTrue(text(UiText.of(R.string.health_note_inspection_off)) in off.notes)
        assertTrue(text(UiText.of(R.string.health_note_no_history)) in off.notes)
        assertEquals(UiText.of(R.string.health_summary_not_checked), HealthCheck.verdictSummary(off))
    }

    @Test
    fun exportsTextAndJson() {
        val r = HealthCheck.run(input(apps = listOf(app("com.thetruth")), observed = listOf(obs("bad.example"))))
        // Two indicators (the app and the Pegasus domain), no warnings.
        assertEquals(UiText.plural(R.plurals.health_summary_found, 2, 2), HealthCheck.verdictSummary(r))
        val out = HealthCheck.toText(r, ::text)
        val lines = out.lines()
        fun has(t: UiText) = assertTrue("${text(t)} in\n$out", text(t) in out)
        has(UiText.of(R.string.health_report_result, text(UiText.of(R.string.health_verdict_found))))
        has(UiText.of(R.string.health_report_generated, "2027-01-15 08:00 UTC", "0.5.0"))
        assertTrue(out, "  " + text(UiText.of(R.string.health_finding_app, "thetruth", "com.thetruth")) in lines)
        assertTrue(out, "  " + text(UiText.of(R.string.health_report_reference, "https://www.amnesty.org/x")) in lines)
        // Pack versions (update times), counts and licences.
        val pack = listOf(
            text(UiText.of(R.string.health_report_pack_updated_stale, "2026-12-26 08:00 UTC")),
            listOf(R.plurals.health_report_count_domains, R.plurals.health_report_count_ips, R.plurals.health_report_count_certs)
                .joinToString(", ") { text(UiText.plural(it, 1, 1L)) },
            text(UiText.of(R.string.health_report_license, "CC BY 2.0 (Amnesty International)")),
        ).joinToString("; ")
        assertTrue(out, "- " + text(UiText.of(R.string.health_report_pack, "NSO Group Pegasus", pack)) in lines)
        // The guidance, with the helplines' addresses.
        assertEquals(HealthCheck.GUIDANCE.map(::text), r.guidance)
        has(UiText.of(R.string.health_guidance_help, HealthCheck.ACCESS_NOW, HealthCheck.STOP_STALKERWARE))
        has(UiText.of(R.string.health_guidance_safety))
        val json = Json.parseToJsonElement(HealthCheck.toJson(r)).jsonObject
        assertEquals(HealthCheck.VERDICT_FOUND, json["verdict"]!!.jsonPrimitive.content)
        assertEquals(now.toString(), json["generatedAt"]!!.jsonPrimitive.content)
        assertTrue(json["packs"].toString().contains("\"downloadedAt\""))
        assertTrue(json["guidance"].toString().contains("stopstalkerware.org"))
        assertTrue(json["notes"].toString().contains("NSO Group Pegasus"))
    }

    @Test
    fun suffixes() {
        assertEquals(listOf("a.b.example.com", "b.example.com", "example.com"), HealthCheck.suffixes("a.b.example.com"))
        assertEquals(emptyList<String>(), HealthCheck.suffixes("localhost"))
    }

    @Test
    fun ipv6IndicatorsMatchByValueAndRange() {
        val pack = SpywarePack(
            feedId = "v6", name = "v6 pack", source = "s", license = "CC0", downloadedAt = now - day,
            groups = listOf(
                SpywareGroup("Exact6", ips = listOf("2001:db8:0::1")),
                SpywareGroup("Range6", ips = listOf("2001:DB8:aa00::/40")),
                SpywareGroup("Mapped", ips = listOf("::ffff:192.0.2.7")),
            ),
        )
        val r = HealthCheck.run(
            input(
                packs = listOf(feed(pack, kind = FeedKinds.SPYWARE) to pack),
                observed = listOf(obs("2001:DB8::1"), obs("2001:db8:aabb::5"), obs("2001:db8:ab00::5"), obs("192.0.2.7")),
            ),
        )
        assertEquals(HealthCheck.VERDICT_FOUND, r.verdict)
        // A different spelling of the listed address matches; the listed text is the indicator.
        assertTrue(r.findings.any { it.label == "Exact6" && it.indicator == "2001:db8:0::1" && it.observed == "2001:db8::1" })
        // An IPv6 range matches the addresses inside it, not the ones outside.
        assertTrue(r.findings.any { it.label == "Range6" && it.indicator == "2001:DB8:aa00::/40" && it.observed == "2001:db8:aabb::5" })
        assertEquals(1, r.findings.count { it.label == "Range6" })
        assertTrue(r.findings.any { it.label == "Mapped" && it.observed == "192.0.2.7" })
    }

    @Test
    fun streamedHistoryWithCallerCount() {
        // The caller streams the history and counts distinct names itself (in SQL).
        val base = input()
        val stream = sequenceOf(obs("media.copy9.com"), obs("media.copy9.com", count = 4, blocked = 1)).asIterable()
        val r = HealthCheck.run(
            HealthCheck.Input(
                now = base.now, appVersion = base.appVersion, packs = base.packs, apps = base.apps, observed = stream, destinationsChecked = 1234,
                historySince = null, retentionDays = 7, inspectionRunning = true, text = ::text,
            ),
        )
        assertEquals(1234, r.destinationsChecked)
        val f = r.findings.single { it.label == "TheTruthSpy" }
        assertEquals(5L, f.count)
        assertEquals(1L, f.blocked)
    }
}
