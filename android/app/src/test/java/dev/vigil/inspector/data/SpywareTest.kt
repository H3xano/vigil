package dev.vigil.inspector.data

import dev.vigil.inspector.engine.AlertEvent
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException
import java.io.StringReader

/** Spyware pack conversion, the MVT index and alert labels; fixtures in test/resources/spyware (see NOTICE). */
class SpywareTest {
    private fun fixture(name: String) = javaClass.getResource("/spyware/$name")!!.readText()

    @Test
    fun echapIocYaml() {
        val groups = SpywareConverters.echapYaml(fixture("ioc-excerpt.yaml"), SpywareSeverity.INDICATOR).associateBy { it.label }
        assertEquals(setOf("TheTruthSpy", "jjspy", "NemoSpy", "KidsShield", "Trackplus", "MobiStealth", "Ahmyth"), groups.keys)
        val tts = groups.getValue("TheTruthSpy")
        assertEquals(SpywareSeverity.INDICATOR, tts.severity)
        assertTrue("com.thetruth" in tts.apps)
        assertTrue("SHA1:31A6ECECD97CF39BC4126B8745CD94A7C30BF81C" in tts.certs)
        assertTrue("copy9.com" in tts.domains) // websites
        assertTrue("app.fonetracker.com" in tts.domains) // distribution
        assertTrue("69.64.74.239" in tts.ips) // c2.ips
        // "c2: ip:" instead of "ips:".
        assertEquals(listOf("72.167.46.196", "5.79.71.114"), groups.getValue("MobiStealth").ips)
        assertEquals(listOf("85.10.199.40"), groups.getValue("Ahmyth").ips)
        // A list indented deeper than its key.
        assertTrue("setup.nemospy.com" in groups.getValue("NemoSpy").domains)
        // An inline comment after a value.
        assertTrue("edlnc255s2q.s3.amazonaws.com" in groups.getValue("Trackplus").domains)
        // Every certificate normalised.
        assertTrue(groups.values.flatMap { it.certs }.all { it.matches(Regex("SHA(1|256):[0-9A-F]+")) })
    }

    @Test
    fun watchwareIsAWarning() {
        val groups = SpywareConverters.echapYaml(fixture("watchware-excerpt.yaml"), SpywareSeverity.WARNING)
        assertEquals(listOf("WiseMo", "FamiSafe"), groups.map { it.label })
        assertTrue(groups.all { it.severity == SpywareSeverity.WARNING })
        assertTrue("com.wondershare.famisafe" in groups[1].apps)
        // A shared-platform apex is never an indicator; its subdomains are.
        assertTrue("famisafe-b6807.firebaseio.com" in groups[1].domains)
        val pack = SpywarePack(feedId = "w", name = "W", source = "s", license = "l", groups = groups)
        assertTrue(pack.engineLines().isEmpty()) // warnings never reach the engine
        // An entry typed "watchware" is a warning whatever the file.
        val mixed = SpywareConverters.echapYaml("- name: X\n  type: watchware\n  packages:\n  - com.x.y\n", SpywareSeverity.INDICATOR)
        assertEquals(SpywareSeverity.WARNING, mixed.single().severity)
    }

    @Test
    fun echapNetworkCsv() {
        val groups = SpywareConverters.echapNetworkCsv(fixture("network-excerpt.csv"), "Stalkerware")
        val g = groups.single()
        assertEquals("TheTruthSpy", g.label)
        assertEquals(5, g.domains.size)
        assertEquals(listOf("69.64.74.239", "69.64.81.166", "69.64.81.49"), g.ips)
        val pack = SpywarePack(feedId = "n", name = "N", source = "s", license = "l", groups = groups)
        assertEquals(8, pack.engineLines().size)
        try {
            SpywareConverters.echapNetworkCsv("<html>login</html>\n", "x")
            fail("expected an error")
        } catch (e: IOException) {
            // expected
        }
    }

    @Test
    fun stixPacksAreLabelledFromRelationships() {
        val novi = SpywareConverters.stix(StringReader(fixture("novispy-excerpt.stix2")), "NoviSpy pack").single()
        assertEquals("NoviSpy", novi.label)
        assertEquals(listOf("176.223.111.131", "195.178.51.251"), novi.ips)
        assertTrue(novi.domains.isEmpty())
        assertEquals(listOf("com.gu.activity", "com.serv.services"), novi.apps)

        val echap = SpywareConverters.stix(StringReader(fixture("echap-excerpt.stix2")), "Stalkerware").associateBy { it.label }
        val tts = echap.getValue("TheTruthSpy")
        assertEquals(listOf("1ca43.appspot.com", "copy9.com"), tts.domains)
        assertEquals(listOf("com.apspy.app"), tts.apps)
        assertEquals(listOf("SHA1:31A6ECECD97CF39BC4126B8745CD94A7C30BF81C"), tts.certs)
        assertEquals(listOf("a-qa3.thd.cc"), echap.getValue("mSpy").domains)
        // The GitHub URL indicator must not turn github.com into an indicator.
        assertTrue(echap.values.none { g -> g.domains.any { it.endsWith("github.com") } })
    }

    @Test
    fun revokedAndExpiredStixIndicatorsAreDropped() {
        val doc = """{"type":"bundle","id":"b","objects":[
            {"type":"indicator","id":"indicator--1","pattern":"[domain-name:value='live.example']","pattern_type":"stix"},
            {"type":"indicator","id":"indicator--2","pattern":"[domain-name:value='old.example']","pattern_type":"stix","valid_until":"2020-01-01T00:00:00Z"},
            {"type":"indicator","id":"indicator--3","pattern":"[domain-name:value='gone.example']","pattern_type":"stix","revoked":true},
            {"type":"indicator","id":"indicator--4","pattern":"[domain-name:value='github.com']","pattern_type":"stix"}
        ]}"""
        val g = SpywareConverters.stix(StringReader(doc), "Fallback").single()
        assertEquals("Fallback", g.label)
        assertEquals(listOf("live.example"), g.domains)
    }

    @Test
    fun mvtIndexExpandsIntoPacks() {
        val packs = MvtIndex.parse(fixture("indicators-excerpt.yaml"))
        assertEquals(4, packs.size)
        val pegasus = packs[0]
        assertEquals("mvt-2021-07-18-nso-pegasus", pegasus.id)
        assertEquals("NSO Group Pegasus", pegasus.name)
        assertEquals("https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2", pegasus.url)
        assertEquals("CC BY 2.0 (Amnesty International)", pegasus.license)
        assertEquals(listOf("Amnesty International"), pegasus.sources)
        assertTrue(pegasus.references.single().startsWith("https://www.amnesty.org/"))
        assertEquals("MIT (MVT project)", packs[1].license)
        val echap = packs.single { it.owner == "AssoEchap" }
        assertEquals("CC BY 4.0 (Echap)", echap.license)
        // Feeds: spyware kind, malware category; Echap's STIX copy is off (the Echap feeds cover it).
        val feeds = packs.map(MvtIndex::feedFor)
        assertTrue(feeds.all { it.kind == FeedKinds.SPYWARE && it.category == "malware" && it.builtin })
        assertEquals(listOf(true, true, true, false), feeds.map { it.enabled })
        assertTrue(feeds[0].description.contains("CC BY 2.0"))
    }

    @Test
    fun mvtIndexUrlAllowlist() {
        assertEquals(
            "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/a/b.stix2",
            MvtIndex.rawUrl("mvt-project", "mvt-indicators", "main", "a/b.stix2"),
        )
        assertNull(MvtIndex.rawUrl("evil-org", "mvt-indicators", "main", "a.stix2"))
        assertNull(MvtIndex.rawUrl("mvt-project", "mvt-indicators", "main", "../../evil/x.stix2"))
        assertNull(MvtIndex.rawUrl("mvt-project", "mvt-indicators", "main", "a/../b.stix2"))
        assertNull(MvtIndex.rawUrl("mvt-project", "mvt-indicators", "main", "a.stix2?x=1"))
        assertNull(MvtIndex.rawUrl("mvt-project", "..", "main", "a.stix2"))
        assertNull(MvtIndex.rawUrl("mvt-project", "repo", "main/../x", "a.stix2"))
        assertNull(MvtIndex.rawUrl("mvt-project", "repo", "main", "a b.stix2"))
        assertNull(MvtIndex.rawUrl("MVT-project", "repo", "main", "a.stix2")) // exact owner
        val doc = """
            indicators:
              - type: github
                name: Evil
                github: {}
              - type: github
                name: Elsewhere Indicators of Compromise
                github:
                  owner: someone-else
                  repo: x
                  branch: main
                  path: x.stix2
              - type: download
                name: Other type
              - type: github
                name: Kept
                github:
                  owner: mvt-project
                  repo: mvt-indicators
                  branch: main
                  path: kept/kept.stix2
              - type: github
                name: Same path
                github:
                  owner: AmnestyTech
                  repo: investigations
                  branch: master
                  path: kept/kept.stix2
        """.trimIndent()
        val packs = MvtIndex.parse(doc)
        assertEquals(listOf("mvt-kept-kept", "mvt-kept-kept-2"), packs.map { it.id })
        try {
            MvtIndex.parse("<html>rate limited</html>")
            fail("expected an error")
        } catch (e: IOException) {
            // expected
        }
    }

    @Test
    fun catalogueSpywareGroup() {
        val spy = FeedCatalog.builtin.filter { it.kind in FeedKinds.SPYWARE_KINDS }
        assertEquals(
            listOf("echap-stalkerware-network", "echap-stalkerware-apps", "echap-watchware", FeedCatalog.MVT_INDEX_ID),
            spy.map { it.id },
        )
        // Every URL is a raw GitHub URL of an accepted publisher, fetched from the original source.
        for (f in spy) {
            val owner = f.url.removePrefix("https://raw.githubusercontent.com/").substringBefore('/')
            assertTrue(f.url, f.url.startsWith("https://raw.githubusercontent.com/") && owner in MvtIndex.OWNER_LICENSES)
            assertTrue(f.id, f.id in FeedCatalog.spywareSources)
            assertEquals("malware", f.category)
        }
        // Only the network pack is loaded by the engine; ids stay unique across the catalogue.
        assertEquals(listOf("echap-stalkerware-network"), spy.filter { FeedKinds.loadsIntoEngine(it.kind) }.map { it.id })
        assertEquals(FeedCatalog.builtin.size, FeedCatalog.builtin.map { it.id }.toSet().size)
    }

    @Test
    fun packRoundTripAndAlertLabels() {
        val dir = createTempDirectory()
        try {
            val file = File(dir, "echap-stalkerware-network.spy.json")
            val pack = SpywarePack(
                feedId = "echap-stalkerware-network", name = "Stalkerware network indicators (Echap)", source = "https://x",
                reference = FeedCatalog.ECHAP_REPO, license = FeedCatalog.ECHAP_LICENSE, downloadedAt = 42,
                groups = listOf(
                    SpywareGroup("TheTruthSpy", domains = listOf("copy9.com"), ips = listOf("69.64.74.239")),
                    SpywareGroup("WiseMo", SpywareSeverity.WARNING, domains = listOf("wisemo.com")),
                ),
            )
            SpywareStore.write(pack, file)
            assertEquals(pack, SpywareStore.read(file))
            // Listed in a non-canonical spelling (as an older pack file may hold it).
            SpywareStore.write(
                pack.copy(
                    feedId = "v6", name = "v6",
                    groups = listOf(SpywareGroup("Pegasus6", ips = listOf("2001:DB8:0:0::1")), SpywareGroup("Range6", ips = listOf("2001:db8:ff00::/40"))),
                ),
                File(dir, "v6.spy.json"),
            )
            assertNull(SpywareStore.read(File(dir, "missing.spy.json")))

            val labels = SpywareLabels { dir.listFiles()!!.toList() }
            val alert = AlertEvent(
                ts = 1, kind = "threat_domain", severity = "high", uid = 10123, target = "media.copy9.com",
                message = "Lookup of media.copy9.com sinkholed: listed by feed:echap-stalkerware-network (copy9.com)",
                detail = Json.parseToJsonElement("""{"category":"malware","qtype":"A"}"""),
            )
            val e = labels.enrich(alert)
            assertTrue(e.message, e.message.endsWith("Spyware indicator: TheTruthSpy (Stalkerware network indicators (Echap))"))
            val d = e.detail as JsonObject
            assertEquals("A", d["qtype"]!!.jsonPrimitive.content)
            assertEquals("TheTruthSpy", d["spyware"]!!.jsonObject["label"]!!.jsonPrimitive.content)
            assertEquals("echap-stalkerware-network", d["spyware"]!!.jsonObject["feed"]!!.jsonPrimitive.content)
            // IP alerts: the rule is the address.
            val ip = labels.enrich(alert.copy(kind = "threat_ip", target = "69.64.74.239", message = "Connection to 69.64.74.239 blocked: listed by feed:x (69.64.74.239)"))
            assertTrue(ip.message.contains("TheTruthSpy"))
            // IPv6 entries match by value (any spelling) and ranges by containment.
            val v6 = labels.enrich(alert.copy(kind = "threat_ip", target = "2001:db8::1", message = "Connection to 2001:db8::1 blocked: listed by feed:x (2001:db8::1)"))
            assertTrue(v6.message, v6.message.contains("Pegasus6"))
            val v6Range = labels.enrich(alert.copy(kind = "threat_ip", target = "2001:db8:ffff::9", message = "Connection to 2001:db8:ffff::9 blocked"))
            assertTrue(v6Range.message, v6Range.message.contains("Range6"))
            // Warnings, other kinds and unknown entries are left alone.
            val warn = alert.copy(message = "Lookup of wisemo.com sinkholed: listed by feed:urlhaus (wisemo.com)", target = "wisemo.com")
            assertSame(warn, labels.enrich(warn))
            val other = alert.copy(kind = "beacon")
            assertSame(other, labels.enrich(other))
            val unknown = alert.copy(message = "Lookup of a.example sinkholed: listed by feed:urlhaus (a.example)", target = "a.example")
            assertSame(unknown, labels.enrich(unknown))
            // A replaced pack file is re-read.
            SpywareStore.write(pack.copy(groups = listOf(SpywareGroup("Renamed", domains = listOf("copy9.com")))), file)
            file.setLastModified(file.lastModified() + 5_000)
            assertTrue(labels.enrich(alert).message.contains("Renamed"))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun ruleOfAlertMessages() {
        assertEquals("bad.example", SpywareLabels.ruleOf("Lookup of x.bad.example sinkholed: listed by feed:urlhaus (bad.example)"))
        assertEquals("203.0.113.9", SpywareLabels.ruleOf("Connection to 203.0.113.9 blocked: listed by feed:feodo (203.0.113.9)"))
        assertNull(SpywareLabels.ruleOf("something else"))
        assertFalse(SpywareLabels.ruleOf("listed by feed:x (a.example)").isNullOrEmpty())
    }

    private fun createTempDirectory(): File = kotlin.io.path.createTempDirectory("spy").toFile()
}
