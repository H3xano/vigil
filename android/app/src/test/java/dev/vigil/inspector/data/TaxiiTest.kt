package dev.vigil.inspector.data

import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException

class TaxiiTest {
    private val taxii = "application/taxii+json;version=2.1"

    /** Serves canned responses by URL and records the requests. */
    private class FakeServer(private val routes: Map<String, TaxiiResponse>) : TaxiiTransport {
        val requests = ArrayList<String>()
        override fun get(url: String): TaxiiResponse {
            requests += url
            return routes[url] ?: TaxiiResponse(404, "text/html", emptyMap(), "<h1>not found</h1>")
        }
    }

    private fun ok(body: String, headers: Map<String, String> = emptyMap()) = TaxiiResponse(200, taxii, headers, body)

    private fun indicator(id: String, domain: String, modified: String = "2024-01-01T00:00:00.000Z", extra: String = "") =
        """{"type":"indicator","spec_version":"2.1","id":"$id","created":"2024-01-01T00:00:00.000Z","modified":"$modified",
            "pattern":"[domain-name:value = '$domain']","pattern_type":"stix","valid_from":"2024-01-01T00:00:00Z"$extra}"""

    @Test
    fun listsCollectionsFromDiscoveryOrApiRoot() {
        val server = FakeServer(
            mapOf(
                "https://ti.example/taxii2/" to ok("""{"title":"TI","api_roots":["https://ti.example/api1/","/api2/"]}"""),
                "https://ti.example/api1/collections/" to ok(
                    """{"collections":[{"id":"91a7b528-80eb-42ed-a74d-c6fbd5a26116","title":"High-confidence","can_read":true,"can_write":false},
                        {"id":"52892447-4d7e-4f70-b94d-d7f22742ff63","title":"Write-only drop box","can_read":false,"can_write":true}]}""",
                ),
                "https://ti.example/api2" to ok("""{"title":"API 2","versions":["application/taxii+json;version=2.1"],"max_content_length":10485760}"""),
                "https://ti.example/api2/collections/" to ok("""{"collections":[{"id":"c3","title":"MISP events","can_read":true}]}"""),
            ),
        )
        val client = TaxiiClient(server)
        val all = client.collections("https://ti.example/taxii2/")
        assertEquals(listOf("High-confidence", "Write-only drop box", "MISP events"), all.map { it.title })
        assertEquals("https://ti.example/api2/", all.last().apiRoot)
        assertEquals(listOf(true, false, true), all.map { it.canRead })
        // An API root URL (without the trailing slash) works directly.
        val direct = client.collections("https://ti.example/api2")
        assertEquals(listOf("c3"), direct.map { it.id })
    }

    @Test
    fun credentialedDiscoveryRefusesForeignApiRoots() {
        val server = FakeServer(
            mapOf(
                "https://ti.example/taxii2/" to ok(
                    """{"api_roots":["https://attacker.example/api/","http://ti.example/plain/","/api2/"]}""",
                ),
                "https://attacker.example/api/collections/" to ok("""{"collections":[{"id":"x","title":"Foreign"}]}"""),
                "http://ti.example/plain/collections/" to ok("""{"collections":[{"id":"p","title":"Plain"}]}"""),
                "https://ti.example/api2/collections/" to ok("""{"collections":[{"id":"c3","title":"Own"}]}"""),
            ),
        )
        // With credentials: only the root on the entered host over HTTPS is asked.
        val own = TaxiiClient(server, credentialOrigin = "https://ti.example/taxii2/").collections("https://ti.example/taxii2/")
        assertEquals(listOf("Own"), own.map { it.title })
        assertTrue(server.requests.none { it.startsWith("https://attacker.example") || it.startsWith("http://") })
        // Only foreign roots: the refusal is the error.
        val onlyForeign = FakeServer(mapOf("https://ti.example/taxii2/" to ok("""{"api_roots":["https://attacker.example/api/"]}""")))
        val e = runCatching { TaxiiClient(onlyForeign, "https://ti.example/taxii2/").collections("https://ti.example/taxii2/") }.exceptionOrNull()
        assertTrue("$e", e is IOException && e.message!!.contains("does not send the credentials"))
        // Without credentials every root is fine.
        assertEquals(3, TaxiiClient(server).collections("https://ti.example/taxii2/").size)
    }

    @Test
    fun rejectsNonTaxiiAnswers() {
        val client = TaxiiClient(
            FakeServer(
                mapOf(
                    "https://portal.example/" to TaxiiResponse(200, "text/html; charset=utf-8", emptyMap(), "<html>login</html>"),
                    "https://auth.example/" to TaxiiResponse(401, "application/taxii+json;version=2.1", emptyMap(), ""),
                ),
            ),
        )
        val html = runCatching { client.collections("https://portal.example/") }.exceptionOrNull()
        assertTrue(html is IOException && "content type" in html.message!!)
        val auth = runCatching { client.collections("https://auth.example/") }.exceptionOrNull()
        assertTrue(auth is IOException && "401" in auth.message!!)
    }

    @Test
    fun pollsWithNextAndAddedAfter() {
        val base = "https://ti.example/api1/collections/coll%201/objects/?limit=${TaxiiClient.PAGE_LIMIT}&added_after=2024-01-01T00%3A00%3A00.000Z"
        val server = FakeServer(
            mapOf(
                base to ok(
                    """{"more":true,"next":"p2","objects":[${indicator("indicator--1", "a.example")}]}""",
                    mapOf("x-taxii-date-added-first" to "2024-02-01T00:00:00.000Z", "x-taxii-date-added-last" to "2024-02-01T00:00:00.000Z"),
                ),
                "$base&next=p2" to ok(
                    """{"more":false,"objects":[${indicator("indicator--2", "b.example")}]}""",
                    mapOf("x-taxii-date-added-last" to "2024-03-01T00:00:00.000Z"),
                ),
            ),
        )
        val seen = ArrayList<JsonObject>()
        val r = TaxiiClient(server).poll("https://ti.example/api1", "coll 1", "2024-01-01T00:00:00.000Z") { seen += it }
        assertEquals(2, r.pages)
        assertEquals(2, r.objects)
        assertEquals(2, seen.size)
        assertEquals("2024-03-01T00:00:00.000Z", r.nextAddedAfter)
        assertEquals(2, server.requests.size)
    }

    @Test
    fun pagesByAddedAfterWhenTheServerHasNoNext() {
        val base = "https://ti.example/api/collections/c/objects/?limit=${TaxiiClient.PAGE_LIMIT}"
        val server = FakeServer(
            mapOf(
                base to ok("""{"more":true,"objects":[${indicator("indicator--1", "a.example")}]}""", mapOf("x-taxii-date-added-last" to "T1")),
                "$base&added_after=T1" to ok("""{"more":false,"objects":[]}""", mapOf("x-taxii-date-added-last" to "T2")),
            ),
        )
        val r = TaxiiClient(server).poll("https://ti.example/api/", "c", null) {}
        assertEquals(2, r.pages)
        assertEquals("T2", r.nextAddedAfter)
        // An empty collection (empty body) is not an error; the previous state is kept.
        val empty = FakeServer(mapOf(base to TaxiiResponse(200, taxii, emptyMap(), "")))
        assertEquals(TaxiiPollResult(1, 0, null), TaxiiClient(empty).poll("https://ti.example/api/", "c", null) {})
    }

    @Test
    fun stopsOnPaginationLoops() {
        val base = "https://ti.example/api/collections/c/objects/?limit=${TaxiiClient.PAGE_LIMIT}"
        val loop = FakeServer(mapOf(base to ok("""{"more":true,"objects":[]}""")))
        assertTrue(runCatching { TaxiiClient(loop).poll("https://ti.example/api/", "c", null) {} }.isFailure)
        val repeat = FakeServer(
            mapOf(
                base to ok("""{"more":true,"next":"x","objects":[]}"""),
                "$base&next=x" to ok("""{"more":true,"next":"x","objects":[]}"""),
            ),
        )
        assertTrue(runCatching { TaxiiClient(repeat).poll("https://ti.example/api/", "c", null) {} }.isFailure)
    }

    private fun item(id: String, version: Long, domain: String? = null, revoked: Boolean = false, validUntil: Long? = null, ja4: String? = null, label: String? = null) =
        StixItem(id, version, revoked, validUntil, IndicatorValues(listOfNotNull(domain), emptyList(), listOfNotNull(ja4)), label)

    @Test
    fun stateAppliesVersionsRevocationsAndExpiry() {
        val s = TaxiiState(fullSyncAt = 5)
        s.apply(item("i1", 10, "a.example"))
        s.apply(item("i2", 10, "b.example", validUntil = 1_000))
        s.apply(item("i3", 10, ja4 = "t13d190900_9dc949149365_97f8aa674fd9", label = "Sliver"))
        s.apply(item("i1", 5, "stale.example")) // older version: ignored
        assertEquals(listOf("a.example", "b.example"), s.feedLines(now = 999).domains)
        assertEquals(listOf("a.example"), s.feedLines(now = 1_000).domains) // i2 expired
        s.apply(item("i1", 20, "a2.example")) // newer version replaces
        assertEquals(listOf("a2.example"), s.feedLines(now = 1_000).domains)
        s.apply(item("i1", 30, revoked = true))
        assertTrue(s.feedLines(now = 1_000).domains.isEmpty())
        assertEquals(listOf("t13d190900_9dc949149365_97f8aa674fd9  Sliver"), s.feedLines(now = 0).ja4)

        val f = File.createTempFile("state", ".taxii")
        try {
            s.write(f)
            val back = TaxiiState.read(f)!!
            assertEquals(5L, back.fullSyncAt)
            assertEquals(s.entries, back.entries)
            f.writeText("not a state file\n")
            assertNull(TaxiiState.read(f))
        } finally {
            f.delete()
        }
        assertNull(TaxiiState.read(File("/nonexistent/state")))
    }

    @Test
    fun endToEndPollIntoState() {
        val base = "https://ti.example/api/collections/c/objects/?limit=${TaxiiClient.PAGE_LIMIT}"
        val server = FakeServer(
            mapOf(
                base to ok(
                    """{"more":false,"objects":[${indicator("indicator--1", "a.example")},
                        ${indicator("indicator--2", "b.example", modified = "2024-02-01T00:00:00.000Z", extra = ""","revoked":true""")},
                        ${indicator("indicator--3", "c.example")}]}""",
                ),
            ),
        )
        val state = TaxiiState()
        state.apply(item("indicator--2", 0, "b.example"))
        TaxiiClient(server).poll("https://ti.example/api/", "c", null) { page -> page.mapNotNull { Stix.item(it) }.forEach(state::apply) }
        assertEquals(listOf("a.example", "c.example"), state.feedLines(0).domains)
    }
}
