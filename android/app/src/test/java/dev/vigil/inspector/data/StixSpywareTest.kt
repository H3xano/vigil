package dev.vigil.inspector.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.io.StringReader

/** STIX features used by spyware packs (MVT, Amnesty, Echap); fixtures in test/resources/spyware (see NOTICE). */
class StixSpywareTest {
    private fun fixture(name: String) = javaClass.getResource("/spyware/$name")!!.readText()

    @Test
    fun ipAddressesInDomainPatternsBecomeIps() {
        // Amnesty's NoviSpy bundle lists its C2 addresses as domain-name values.
        val v = StixPattern.extract("[domain-name:value='176.223.111.131']")
        assertEquals(listOf("176.223.111.131"), v.ips)
        assertTrue(v.domains.isEmpty())
        assertEquals(listOf("2001:db8::1"), StixPattern.extract("[domain-name:value = '2001:db8::1']").ips)
        // Domain-name SCOs too.
        val sco = Stix.item(Json.parseToJsonElement("""{"type":"domain-name","id":"domain-name--1","value":"198.51.100.4"}""").jsonObject)!!
        assertEquals(listOf("198.51.100.4"), sco.values.ips)
    }

    @Test
    fun appPackagesAndCertificates() {
        assertEquals(listOf("com.gu.activity"), StixPattern.extract("[app:id='com.gu.activity']").apps)
        assertEquals(
            listOf("SHA256:3AC97735164824657B683E805133B1274B2DEDABF9FDD6AA9ACA31089D501E64"),
            StixPattern.extract("[app:cert.sha256='3ac97735164824657b683e805133b1274b2dedabf9fdd6aa9aca31089d501e64']").certs,
        )
        assertEquals(
            listOf("SHA1:31A6ECECD97CF39BC4126B8745CD94A7C30BF81C"),
            StixPattern.extract("[app:cert.sha1 = '31:a6:ec:ec:d9:7c:f3:9b:c4:12:6b:87:45:cd:94:a7:c3:0b:f8:1c']").certs,
        )
        // Wrong length for the algorithm, or not hex: ignored.
        assertTrue(StixPattern.extract("[app:cert.sha1='3ac97735164824657b683e805133b1274b2dedabf9fdd6aa9aca31089d501e64']").isEmpty)
        assertTrue(StixPattern.extract("[app:cert.md5='d41d8cd98f00b204e9800998ecf8427e']").isEmpty)
        assertTrue(StixPattern.extract("[app:id='not a package']").isEmpty)
        // Other MVT observables are not used.
        assertTrue(StixPattern.extract("[android-property:name='persist.sys.x']").isEmpty)
        assertTrue(StixPattern.extract("[process:name='bh']").isEmpty)
    }

    @Test
    fun urlHostsCanBeIgnored() {
        val p = "[url:value='https://evil.example/karma9874/AndroRAT']"
        assertEquals(listOf("evil.example"), StixPattern.extract(p).domains)
        assertTrue(StixPattern.extract(p, urlHosts = false).isEmpty)
    }

    @Test
    fun urlHostsOfSharedPlatformsAreDropped() {
        // A TAXII URL indicator on a shared platform must not block the whole platform.
        for (url in listOf(
            "https://github.com/x/y/a.apk", "https://raw.githubusercontent.com/x/y/main/a.apk", "https://drive.google.com/file/d/1",
            "https://cdn.discordapp.com/attachments/1/2/a.apk", "https://www.dropbox.com/s/x/a.apk", "https://1drv.ms/u/s!x",
            "https://mega.nz/file/x", "https://pastebin.com/raw/x", "https://t.me/x", "https://bit.ly/x", "https://herokuapp.com/",
        )) {
            assertTrue(url, StixPattern.extract("[url:value = '$url']").isEmpty)
            val o = Json.parseToJsonElement(
                """{"type":"indicator","id":"indicator--1","pattern":"[url:value = '$url']","pattern_type":"stix"}""",
            ).jsonObject
            assertNull(url, Stix.item(o))
        }
        // A customer's subdomain of a hosting platform, and IP hosts, stay indicators.
        assertEquals(listOf("evil-c2.herokuapp.com"), StixPattern.extract("[url:value = 'https://evil-c2.herokuapp.com/x']").domains)
        assertEquals(listOf("203.0.113.9"), StixPattern.extract("[url:value = 'http://203.0.113.9/a.apk']").ips)
        // Explicit domain indicators are left to the source.
        assertEquals(listOf("github.com"), StixPattern.extract("[domain-name:value = 'github.com']").domains)
    }

    @Test
    fun certificateNormalisation() {
        val sha1 = "SHA1:31A6ECECD97CF39BC4126B8745CD94A7C30BF81C"
        assertEquals(sha1, AppCerts.normalize("31a6ecec d97cf39bc4126b8745cd94a7c30bf81c"))
        assertEquals(sha1, AppCerts.normalize("31:A6:EC:EC:D9:7C:F3:9B:C4:12:6B:87:45:CD:94:A7:C3:0B:F8:1C", "SHA-1"))
        assertNull(AppCerts.normalize(sha1.substringAfter(':'), "sha256"))
        assertNull(AppCerts.normalize("xyz"))
        assertEquals("SHA1:00FF", AppCerts.of("SHA1", byteArrayOf(0, -1)))
        // Idempotent.
        assertEquals(sha1, AppCerts.normalize(sha1))
        assertNull(AppCerts.normalize("SHA256:" + sha1.substringAfter(':')))
    }

    @Test
    fun relationshipsNameTheIndicators() {
        val rel = StixRelationshipLabels()
        val items = ArrayList<StixItem>()
        // The fixture puts relationships first and the malware object last.
        val r = StixStream.forEachObject(StringReader(fixture("novispy-excerpt.stix2"))) { o ->
            rel.accept(o)
            Stix.item(o)?.let(items::add)
        }
        assertEquals(13, r.objects)
        assertEquals(0, r.skipped)
        assertEquals(5, items.size) // 6 indicators, the file hash is not usable
        assertTrue(items.all { rel.labelFor(it.id) == "NoviSpy" })
        assertTrue(items.all { it.label == null }) // no name or labels of their own
        val all = items.fold(IndicatorValues()) { a, i -> a + i.values }
        assertEquals(listOf("176.223.111.131", "195.178.51.251"), all.ips)
        assertEquals(listOf("com.gu.activity", "com.serv.services"), all.apps)
        assertEquals(1, all.certs.size)
        assertNull(rel.labelFor("indicator--unknown"))
    }

    @Test
    fun streamSkipsOversizedObjectsAndRejectsNonBundles() {
        val big = "x".repeat(500)
        val doc = """{"type":"bundle","id":"b","note":"objects: [ {not} ]","objects":[
            {"type":"malware","id":"malware--1","name":"A"},
            {"type":"indicator","id":"indicator--1","description":"$big","pattern":"[domain-name:value='a.example']"},
            {"type":"indicator","id":"indicator--2","pattern":"[domain-name:value='b.example']","nested":{"k":["}"]}}
        ],"trailer":{"objects":[{"type":"x"}]}}"""
        val seen = ArrayList<JsonObject>()
        val r = StixStream.forEachObject(StringReader(doc), maxObjectChars = 200) { seen += it }
        assertEquals(2, r.objects)
        assertEquals(1, r.skipped)
        assertEquals(listOf("malware--1", "indicator--2"), seen.map { it["id"].toString().trim('"') })
        try {
            StixStream.forEachObject(StringReader("<html>captive portal</html>")) {}
            fail("expected an error")
        } catch (e: IOException) {
            // expected
        }
    }

    @Test
    fun taxiiStateKeepsAppValues() {
        val s = TaxiiState(fullSyncAt = 5)
        s.apply(StixItem("indicator--1", 1, false, null, IndicatorValues(apps = listOf("com.example.spy"), certs = listOf("SHA1:" + "A".repeat(40))), "X"))
        val f = java.io.File.createTempFile("state", ".taxii")
        try {
            s.write(f)
            val back = TaxiiState.read(f)!!
            assertEquals(listOf("com.example.spy"), back.entries.getValue("indicator--1").values.apps)
            assertEquals(listOf("SHA1:" + "A".repeat(40)), back.entries.getValue("indicator--1").values.certs)
            // App values never become feed lines.
            assertEquals(0, back.feedLines(10).total)
        } finally {
            f.delete()
        }
    }
}
