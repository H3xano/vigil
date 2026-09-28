package dev.vigil.inspector.data

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
    )

    private fun app(pkg: String, vararg certs: String) = InstalledApp(pkg, pkg.substringAfterLast('.'), certs.toList(), firstInstall = now - 3 * day)

    @Test
    fun cleanDevice() {
        val r = HealthCheck.run(input(apps = listOf(app("org.mozilla.firefox", "SHA1:" + "0".repeat(40))), observed = listOf(obs("example.org"))))
        assertEquals(HealthCheck.VERDICT_NONE, r.verdict)
        assertTrue(r.findings.isEmpty())
        assertEquals(1, r.appsChecked)
        assertEquals(1, r.destinationsChecked)
        assertTrue(HealthCheck.verdictSummary(r).startsWith("None of the 1 installed apps"))
        // The 20-day-old pack is reported as out of date.
        assertTrue(r.packs.single { it.feedId == pegasus.feedId }.stale)
        assertTrue(r.notes.any { it.startsWith("Out of date") && "NSO Group Pegasus" in it })
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
        assertTrue(off.notes.first().startsWith("No spyware packs are downloaded"))
        assertTrue(off.notes.any { it.startsWith("Inspection is off") })
        assertTrue(off.notes.any { it.startsWith("There is no recorded network history") })
    }

    @Test
    fun exportsTextAndJson() {
        val r = HealthCheck.run(input(apps = listOf(app("com.thetruth")), observed = listOf(obs("bad.example"))))
        val text = HealthCheck.toText(r)
        assertTrue(text, text.contains("Result: Indicators found"))
        assertTrue(text.contains("Generated: 2027-01-15 08:00 UTC (vigil 0.5.0)"))
        assertTrue(text.contains("App: thetruth (com.thetruth)"))
        assertTrue(text.contains("Reference: https://www.amnesty.org/x"))
        // Pack versions (update times) and licences.
        assertTrue(text.contains("- NSO Group Pegasus: updated 2026-12-26 08:00 UTC (out of date); 1 domains, 1 IPs, 1 certificates; licence CC BY 2.0"))
        assertTrue(text.contains(HealthCheck.ACCESS_NOW) && text.contains(HealthCheck.STOP_STALKERWARE))
        assertTrue(text.contains("Do not uninstall anything right away"))
        val json = Json.parseToJsonElement(HealthCheck.toJson(r)).jsonObject
        assertEquals(HealthCheck.VERDICT_FOUND, json["verdict"]!!.jsonPrimitive.content)
        assertEquals(now.toString(), json["generatedAt"]!!.jsonPrimitive.content)
        assertTrue(json["packs"].toString().contains("\"downloadedAt\""))
        assertTrue(json["guidance"].toString().contains("stopstalkerware.org"))
    }

    @Test
    fun suffixes() {
        assertEquals(listOf("a.b.example.com", "b.example.com", "example.com"), HealthCheck.suffixes("a.b.example.com"))
        assertEquals(emptyList<String>(), HealthCheck.suffixes("localhost"))
    }
}
