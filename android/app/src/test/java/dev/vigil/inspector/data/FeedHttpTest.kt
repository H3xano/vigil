package dev.vigil.inspector.data

import com.sun.net.httpserver.HttpServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.InetSocketAddress
import java.net.URL
import java.util.concurrent.ConcurrentHashMap

class FeedHttpTest {
    private val servers = ArrayList<HttpServer>()

    /** Header value of `X-Api-Key` seen per request path (`-` when absent). */
    private val seen = ConcurrentHashMap<String, String>()

    private fun server(routes: Map<String, (HttpServer) -> Pair<Int, Map<String, String>>>): HttpServer {
        val s = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        for ((path, handler) in routes) {
            s.createContext(path) { ex ->
                seen[path] = ex.requestHeaders.getFirst("X-Api-Key") ?: "-"
                val (code, headers) = handler(s)
                headers.forEach { (k, v) -> ex.responseHeaders.add(k, v) }
                val body = "ok $path".toByteArray()
                ex.sendResponseHeaders(code, if (code in 300..399) -1 else body.size.toLong())
                if (code !in 300..399) ex.responseBody.use { it.write(body) } else ex.close()
            }
        }
        s.start()
        servers += s
        return s
    }

    @After
    fun stop() = servers.forEach { it.stop(0) }

    private fun get(url: String, credential: FeedCredential?): Pair<Int, String> {
        val conn = FeedHttp.get(url, credential, { it.connectTimeout = 5_000; it.readTimeout = 5_000 })
        try {
            return conn.responseCode to conn.inputStream.use { it.readBytes().decodeToString() }
        } finally {
            conn.disconnect()
        }
    }

    @Test
    fun credentialStaysOnTheEnteredHost() {
        // "localhost" and "127.0.0.1" are different hosts to the credential check.
        val other = server(mapOf("/file" to { _ -> 200 to emptyMap() }))
        val otherUrl = "http://localhost:${other.address.port}/file"
        val origin = server(
            mapOf(
                "/feed" to { _ -> 302 to mapOf("Location" to "/moved") },
                "/moved" to { _ -> 200 to emptyMap() },
                "/away" to { _ -> 307 to mapOf("Location" to otherUrl) },
                "/loop" to { _ -> 302 to mapOf("Location" to "/loop") },
            ),
        )
        val base = "http://127.0.0.1:${origin.address.port}"
        val cred = FeedCredential("X-Api-Key", "s3cret", "$base/feed")

        // Same-host redirect: followed, credential kept.
        assertEquals(200 to "ok /moved", get("$base/feed", cred))
        assertEquals("s3cret", seen["/feed"])
        assertEquals("s3cret", seen["/moved"])

        // Cross-host redirect: followed without the credential.
        assertEquals(200 to "ok /file", get("$base/away", cred))
        assertEquals("s3cret", seen["/away"])
        assertEquals("-", seen["/file"])

        val loop = runCatching { get("$base/loop", cred) }.exceptionOrNull()
        assertTrue("$loop", loop is IOException && loop.message!!.contains("redirects"))
    }

    @Test
    fun credentialRules() {
        val https = URL("https://ti.example/taxii2/")
        assertTrue(FeedHttp.mayCarryCredential(https, URL("https://ti.example/api1/")))
        assertTrue(FeedHttp.mayCarryCredential(https, URL("https://TI.example:8443/api1/")))
        assertFalse(FeedHttp.mayCarryCredential(https, URL("https://evil.example/api1/")))
        assertFalse(FeedHttp.mayCarryCredential(https, URL("http://ti.example/api1/")))
        assertFalse(FeedHttp.mayCarryCredential(https, URL("https://ti.example.evil.example/")))
        // The user chose plain HTTP for this host (e.g. a LAN server): allowed there only.
        val http = URL("http://10.0.0.5:5000/taxii2/")
        assertTrue(FeedHttp.mayCarryCredential(http, URL("http://10.0.0.5:5000/api/")))
        assertTrue(FeedHttp.mayCarryCredential(http, URL("https://10.0.0.5/api/")))
        assertFalse(FeedHttp.mayCarryCredential(http, URL("http://10.0.0.6:5000/api/")))
    }

    @Test
    fun redirectTargets() {
        val from = URL("https://feeds.example/a/list.txt")
        assertEquals("https://feeds.example/b.txt", FeedHttp.redirectTarget(from, "/b.txt").toString())
        assertEquals("https://cdn.example/x", FeedHttp.redirectTarget(from, "https://cdn.example/x").toString())
        for (bad in listOf(null, "", "http://feeds.example/a/list.txt", "ftp://feeds.example/x", "file:///etc/passwd")) {
            val e = runCatching { FeedHttp.redirectTarget(from, bad) }.exceptionOrNull()
            assertTrue("$bad: $e", e is IOException)
        }
        // Upgrading to HTTPS is fine.
        assertEquals("https", FeedHttp.redirectTarget(URL("http://feeds.example/"), "https://feeds.example/").protocol)
    }

    @Test
    fun readCappedStopsAtTheLimit() {
        assertEquals(10, FeedHttp.readCapped(ByteArray(10).inputStream(), 10, "page").size)
        val e = runCatching { FeedHttp.readCapped(ByteArray(200_000).inputStream(), 100_000, "TAXII response") }.exceptionOrNull()
        assertTrue("$e", e is IOException && e.message!!.startsWith("TAXII response larger"))
        // Logging a credential never prints its value.
        assertFalse(FeedCredential("Authorization", "Bearer s3cret", "https://a.example/").toString().contains("s3cret"))
    }
}
