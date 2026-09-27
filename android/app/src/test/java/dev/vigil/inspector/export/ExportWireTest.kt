package dev.vigil.inspector.export

import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.engine.DnsEvent
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class ExportWireTest {
    private val app = AppInfo("com.example.app", 10123, "Example", isSystem = false, isInstalledPackage = true)

    @Test
    fun recordIdsAreDeterministicAndDistinct() {
        val a = ExportRecords.dns(DnsEvent(ts = 1, qname = "a.example", qtype = "A", rcode = "NOERROR", verdict = "allow", server = "virtual", transport = "udp"), app)
        val b = ExportRecords.dns(DnsEvent(ts = 2, qname = "a.example", qtype = "A", rcode = "NOERROR", verdict = "allow", server = "virtual", transport = "udp"), app)
        val id = ExportRecords.recordId("device-1", a)
        assertEquals(32, id.length)
        assertEquals(id, ExportRecords.recordId("device-1", a))
        assertNotEquals(id, ExportRecords.recordId("device-2", a))
        assertNotEquals(id, ExportRecords.recordId("device-1", b))

        val withId = ExportRecords.withEventId(a, id)
        assertEquals(id, ExportRecords.eventId(withId))
        // Other event fields survive.
        assertEquals("vigil.dns", withId["event"]!!.jsonObject["dataset"]!!.jsonPrimitive.content)
    }

    @Test
    fun elasticBulkUsesIdsInCreateActions() {
        val r = ExportRecords.withEventId(JsonObject(mapOf("message" to JsonPrimitive("x"))), "abc")
        val lines = WireFormats.httpBody(listOf(r), "elastic_bulk").trimEnd().lines()
        assertEquals("{\"create\":{\"_id\":\"abc\"}}", lines[0])
        assertEquals(r.toString(), lines[1])
        val hec = Json.parseToJsonElement(WireFormats.httpBody(listOf(r), "splunk_hec")).jsonObject
        assertEquals("abc", hec["event"]!!.jsonObject["event"]!!.jsonObject["id"]!!.jsonPrimitive.content)
    }

    @Test
    fun elasticBulkResponseItems() {
        val ok = ElasticBulk.parse("""{"took":3,"errors":false,"items":[{"create":{"status":201}}]}""", 1)!!
        assertEquals(1, ok.delivered)
        assertTrue(ok.retry.isEmpty())

        val body = """{"took":3,"errors":true,"items":[
            {"create":{"_id":"a","status":201}},
            {"create":{"_id":"b","status":409,"error":{"type":"version_conflict_engine_exception","reason":"exists"}}},
            {"create":{"_id":"c","status":429,"error":{"type":"es_rejected_execution_exception","reason":"queue full"}}},
            {"create":{"_id":"d","status":400,"error":{"type":"mapper_parsing_exception","reason":"bad field"}}},
            {"create":{"_id":"e","status":503}}
        ]}"""
        val r = ElasticBulk.parse(body, 5)!!
        assertEquals("201 and 409 are delivered", 2, r.delivered)
        assertEquals(listOf(2, 4), r.retry)
        assertEquals(1, r.rejected)
        assertEquals("document status 429: es_rejected_execution_exception: queue full", r.firstError)

        assertNull("garbage", ElasticBulk.parse("<html>", 1))
        assertNull("item count mismatch", ElasticBulk.parse("""{"errors":true,"items":[]}""", 2))
    }

    @Test
    fun syslogTimestampHasAtMostSixFractionDigits() {
        val ts = WireFormats.syslogTimestamp(Instant.ofEpochSecond(1_767_225_600, 123_456_789))
        assertEquals("2026-01-01T00:00:00.123456Z", ts)
        assertEquals("2026-01-01T00:00:00Z", WireFormats.syslogTimestamp(Instant.ofEpochSecond(1_767_225_600)))
    }

    @Test
    fun udpMessagesAreShrunkToValidJson() {
        val small = JsonObject(mapOf("vigil" to JsonObject(mapOf("type" to JsonPrimitive("alert"))), "message" to JsonPrimitive("hi")))
        assertEquals(WireFormats.syslog(small, "h", "t"), WireFormats.syslogFitted(small, "h", "t", 8192))

        val big = JsonObject(
            mapOf(
                "vigil" to JsonObject(mapOf("type" to JsonPrimitive("alert"), "detail" to JsonPrimitive("x".repeat(50_000)))),
                "message" to JsonPrimitive("é".repeat(10_000)),
            ),
        )
        val msg = WireFormats.syslogFitted(big, "h", "t", WireFormats.UDP_MAX_BYTES)!!
        assertTrue(msg.toByteArray(Charsets.UTF_8).size <= WireFormats.UDP_MAX_BYTES)
        val json = Json.parseToJsonElement(msg.substring(msg.indexOf('{'))).jsonObject
        assertTrue(json["vigil"]!!.jsonObject["truncated"]!!.jsonPrimitive.boolean)
        assertEquals("alert", json["vigil"]!!.jsonObject["type"]!!.jsonPrimitive.content)

        val hopeless = JsonObject((0 until 2_000).associate { "k$it" to JsonPrimitive(it) })
        assertNull(WireFormats.syslogFitted(hopeless, "h", "t", 1024))
    }
}
