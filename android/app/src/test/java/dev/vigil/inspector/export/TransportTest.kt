package dev.vigil.inspector.export

import com.sun.net.httpserver.HttpServer
import dev.vigil.inspector.R
import dev.vigil.inspector.data.ExportSettings
import dev.vigil.inspector.ui.UiText
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class TransportTest {
    private val record = JsonObject(mapOf("message" to JsonPrimitive("x")))

    private fun withServer(handler: (method: String, path: String) -> Pair<Int, Map<String, String>>, block: (base: String, seen: List<String>) -> Unit) {
        val server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
        val seen = Collections.synchronizedList(ArrayList<String>())
        server.createContext("/") { ex ->
            ex.requestBody.readBytes()
            seen += "${ex.requestMethod} ${ex.requestURI.path}"
            val (code, headers) = handler(ex.requestMethod, ex.requestURI.path)
            headers.forEach { (k, v) -> ex.responseHeaders.add(k, v) }
            val body = if (code == 200) "ok".toByteArray() else ByteArray(0)
            ex.sendResponseHeaders(code, if (body.isEmpty()) -1 else body.size.toLong())
            if (body.isNotEmpty()) ex.responseBody.use { it.write(body) } else ex.close()
        }
        server.start()
        try {
            block("http://127.0.0.1:${server.address.port}", seen)
        } finally {
            server.stop(0)
        }
    }

    private fun http(url: String, format: String = "ndjson") = ExportSettings(enabled = true, mode = "http", url = url, httpFormat = format)

    @Test
    fun redirectIsAConfigProblemNotADelivery() {
        // An SSO proxy or a trailing-slash redirect: the redirected request would be a GET answered with 200.
        withServer({ _, path -> if (path == "/ingest") 302 to mapOf("Location" to "/ingest/") else 200 to emptyMap() }) { base, seen ->
            val cfg = http("$base/ingest")
            try {
                HttpSender.send(cfg, listOf(record), listOf(record)) { null }
                fail("a redirect must not count as delivered")
            } catch (e: ExportConfigException) {
                assertEquals(UiText.of(R.string.export_error_redirected, "/ingest/", 302), e.problem)
                assertEquals(FailureKind.CONFIG, ExportRetry.classify(e, cfg))
                assertEquals(e.problem, ExportRetry.configProblem(e, cfg))
            }
            assertEquals("not followed", listOf("POST /ingest"), seen.toList())
            // The URL it pointed to works.
            assertEquals(1, HttpSender.send(http("$base/ingest/"), listOf(record), listOf(record)) { null }.delivered)
        }
    }

    @Test
    fun redirectKeepsRecordsQueuedInThePipeline() = runTest {
        withServer({ _, _ -> 301 to mapOf("Location" to "https://elsewhere.example/ingest") }) { base, seen ->
            val pipeline = ExportPipeline(MutableStateFlow(http("$base/ingest")), MutableStateFlow(true), { c, b -> HttpSender.send(c, b, b) { null } })
            repeat(3) { pipeline.offer(record) }
            backgroundScope.launch { pipeline.run() }
            // The transport blocks the test thread, so this runs the first attempt to completion.
            runCurrent()
            val s = pipeline.status.value
            assertEquals(UiText.of(R.string.export_error_redirected, "https://elsewhere.example/ingest", 301), s.configProblem)
            assertEquals(0L, s.sent)
            assertEquals(0L, s.rejected)
            assertEquals(3, s.queued)
            assertEquals(1, seen.size)
        }
    }

    @Test
    fun unreadableElasticResponseIsRetried() {
        // The test server answers "ok", which is not a _bulk response.
        withServer({ _, _ -> 200 to emptyMap() }) { base, _ ->
            val out = HttpSender.send(http("$base/vigil/_bulk", "elastic_bulk"), listOf(record), listOf(record)) { null }
            assertEquals(0, out.delivered)
            assertEquals(listOf(record), out.retry)
            assertEquals(UiText.of(R.string.export_error_elastic_unreadable), out.detail)
        }
    }

    @Test
    fun elasticBulkUrlMustNameTheIndex() {
        assertNull(HttpSender.elasticBulkUrlProblem("https://es:9200/vigil/_bulk"))
        assertNull(HttpSender.elasticBulkUrlProblem("https://proxy/es/vigil-events/_bulk/"))
        assertNotNull(HttpSender.elasticBulkUrlProblem("https://es:9200/_bulk"))
        assertNotNull(HttpSender.elasticBulkUrlProblem("https://es:9200/"))
        assertNotNull(HttpSender.elasticBulkUrlProblem("https://es:9200/vigil"))
        assertNotNull(HttpSender.elasticBulkUrlProblem("https://es:9200/_data_stream/_bulk"))
        assertNull(HttpSender.urlProblem(http("https://es:9200/_bulk", "ndjson")))
        val bare = http("https://es:9200/_bulk", "elastic_bulk")
        assertEquals(UiText.of(R.string.export_error_bulk_index), HttpSender.urlProblem(bare))
        // Refused before any request, as a configuration problem.
        try {
            HttpSender.send(bare, listOf(record), listOf(record)) { null }
            fail()
        } catch (e: ExportConfigException) {
            assertEquals(FailureKind.CONFIG, ExportRetry.classify(e, bare))
        }
    }

    // --- Syslog over TCP ---

    /** Accepts connections and hands out the octet-counted messages with the connection number. */
    private class SyslogServer : AutoCloseable {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val messages = LinkedBlockingQueue<Pair<Int, String>>()
        val conns = Collections.synchronizedList(ArrayList<Socket>())

        /** Close each connection after this many messages (0: never). */
        @Volatile var closeAfter = 0

        init {
            thread(isDaemon = true) {
                var n = 0
                while (!server.isClosed) {
                    val s = runCatching { server.accept() }.getOrNull() ?: break
                    val id = ++n
                    conns += s
                    thread(isDaemon = true) {
                        runCatching {
                            val input = DataInputStream(s.getInputStream().buffered())
                            var count = 0
                            while (true) {
                                val len = StringBuilder()
                                while (true) {
                                    val c = input.read()
                                    if (c < 0) return@runCatching
                                    if (c == ' '.code) break
                                    len.append(c.toChar())
                                }
                                val buf = ByteArray(len.toString().toInt())
                                input.readFully(buf)
                                messages += id to String(buf, Charsets.UTF_8)
                                if (closeAfter > 0 && ++count >= closeAfter) {
                                    s.close()
                                    return@runCatching
                                }
                            }
                        }
                    }
                }
            }
        }

        val port get() = server.localPort

        fun take(): Pair<Int, String> = messages.poll(5, TimeUnit.SECONDS) ?: error("no message")

        override fun close() {
            server.close()
            conns.forEach { runCatching { it.close() } }
        }
    }

    @Test
    fun streamSinkReconnectsAfterTheCollectorClosedTheConnection() {
        SyslogServer().use { srv ->
            srv.closeAfter = 1
            val sink = StreamSink({ Socket("127.0.0.1", srv.port) })
            sink.write(listOf("first"))
            assertEquals(1 to "first", srv.take())
            // Let the FIN arrive.
            Thread.sleep(200)
            sink.write(listOf("second"))
            assertEquals("not written into a closed connection", 2 to "second", srv.take())
            assertEquals(2, sink.connects)
            sink.close()
        }
    }

    @Test
    fun streamSinkKeepsALiveConnectionAndReopensAnIdleOne() {
        SyslogServer().use { srv ->
            var now = 0L
            val sink = StreamSink({ Socket("127.0.0.1", srv.port) }, nanoTime = { now })
            sink.write(listOf("a"))
            now += 10_000_000_000L
            sink.write(listOf("b"))
            assertEquals(1 to "a", srv.take())
            assertEquals(1 to "b", srv.take())
            assertEquals(1, sink.connects)
            // Idle longer than 30 s: a NAT or the collector may have dropped it silently.
            now += StreamSink.IDLE_REOPEN_NS + 1
            sink.write(listOf("c"))
            assertEquals(2 to "c", srv.take())
            assertEquals(2, sink.connects)
            sink.close()
        }
    }

    @Test
    fun peerCheckRestoresTheReadTimeout() {
        SyslogServer().use { srv ->
            Socket("127.0.0.1", srv.port).use { s ->
                s.soTimeout = 15_000
                assertTrue(StreamSink.peerStillOpen(s))
                assertEquals(15_000, s.soTimeout)
            }
        }
    }
}
