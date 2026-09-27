package dev.vigil.inspector.export

import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.engine.AlertEvent
import dev.vigil.inspector.engine.FlowEndEvent
import dev.vigil.inspector.engine.FlowEvent
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WireFormatsTest {
    private val app = AppInfo("com.example.app", 10123, "Example", isSystem = false, isInstalledPackage = true)
    private val flow = FlowEvent(
        id = 7, ts = 1_700_000_000_000, proto = "tcp", uid = 10123, src = "10.111.222.1:40000", dstIp = "93.184.216.34",
        dstPort = 443, domain = "example.com", domainSource = "sni", appProto = "tls", alpn = "h2", tlsVersion = "TLS1.3",
        ja4 = "t13d", verdict = "allow",
    )
    private val end = FlowEndEvent(id = 7, ts = 1_700_000_001_000, tx = 100, rx = 5000, durationMs = 1000)

    @Test
    fun flowRecordUsesEcsFields() {
        val r = ExportRecords.flow(flow, end, app)
        assertEquals("2023-11-14T22:13:20Z", r["@timestamp"]!!.jsonPrimitive.content)
        assertEquals("example.com", r["destination"]!!.jsonObject["domain"]!!.jsonPrimitive.content)
        assertEquals(5100L, r["network"]!!.jsonObject["bytes"]!!.jsonPrimitive.long)
        assertEquals("t13d", r["tls"]!!.jsonObject["client"]!!.jsonObject["ja4"]!!.jsonPrimitive.content)
        assertEquals("com.example.app", r["app"]!!.jsonObject["package"]!!.jsonPrimitive.content)
        assertEquals(40000L, r["source"]!!.jsonObject["port"]!!.jsonPrimitive.long)
        assertEquals(1_000_000_000L, r["event"]!!.jsonObject["duration"]!!.jsonPrimitive.long)
    }

    @Test
    fun syslogRfc5424() {
        val alert = ExportRecords.alert(AlertEvent(ts = 0, kind = "threat_domain", severity = "high", target = "bad.example", message = "m"), app)
        val msg = WireFormats.syslog(alert, "Pixel 8", "2026-01-01T00:00:00Z")
        // local0 (16) * 8 + error (3) = 131; hostname must not contain spaces.
        assertTrue(msg, msg.startsWith("<131>1 2026-01-01T00:00:00Z Pixel8 vigil - alert - {"))
        val framed = String(WireFormats.octetCounted("héllo"), Charsets.UTF_8)
        assertEquals("6 héllo", framed)
    }

    @Test
    fun httpBodies() {
        val records = listOf(JsonObject(mapOf("@timestamp" to JsonPrimitive("2026-01-01T00:00:01Z"))), JsonObject(emptyMap()))

        val nd = WireFormats.httpBody(records, "ndjson")
        assertEquals(listOf(records[0].toString(), "{}"), nd.trimEnd().lines())
        assertTrue(nd.endsWith("\n"))

        val bulk = WireFormats.httpBody(records, "elastic_bulk").trimEnd().lines()
        assertEquals(listOf("{\"create\":{}}", records[0].toString(), "{\"create\":{}}", "{}"), bulk)

        val hec = WireFormats.httpBody(records, "splunk_hec").lines().map { Json.parseToJsonElement(it).jsonObject }
        assertEquals(2, hec.size)
        assertEquals(1767225601.0, hec[0]["time"]!!.jsonPrimitive.content.toDouble(), 0.001)
        assertTrue("record without timestamp has no time", hec[1]["time"] == null)
        assertTrue(hec.all { it["sourcetype"]!!.jsonPrimitive.content == "vigil:json" })
        assertEquals(records[0], hec[0]["event"])
    }
}
