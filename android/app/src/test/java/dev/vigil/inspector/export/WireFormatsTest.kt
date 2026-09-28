package dev.vigil.inspector.export

import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.engine.AlertEvent
import dev.vigil.inspector.engine.FlowEndEvent
import dev.vigil.inspector.engine.FlowEvent
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.int
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

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

    private fun JsonObject.path(vararg keys: String): kotlinx.serialization.json.JsonElement? {
        var cur: kotlinx.serialization.json.JsonElement? = this
        for (k in keys) cur = (cur as? JsonObject)?.get(k)
        return cur
    }

    private fun JsonObject.str(vararg keys: String) = (path(*keys) as? JsonPrimitive)?.content

    private fun JsonObject.list(vararg keys: String) = (path(*keys) as JsonArray).map { it.jsonPrimitive.content }

    @Test
    fun tlsVersionIsEcsNumberAndProtocol() {
        val r = ExportRecords.flow(flow, end, app)
        assertEquals("1.3", r.str("tls", "version"))
        assertEquals("tls", r.str("tls", "version_protocol"))
        assertEquals("3", ExportRecords.tlsVersionNumber("SSL3"))
        assertEquals("ssl", ExportRecords.tlsVersionProtocol("SSL3"))
        assertNull(ExportRecords.tlsVersionNumber("unknown"))
        assertNull(ExportRecords.tlsVersionProtocol(null))
    }

    @Test
    fun threatAlertIsDeniedIntrusionDetectionWithDestination() {
        val r = ExportRecords.alert(
            AlertEvent(ts = 0, kind = "threat_domain", severity = "high", target = "1password-login.example", message = "m",
                detail = Json.parseToJsonElement("""{"category":"phishing","qtype":"A"}""")),
            app,
        )
        assertEquals("alert", r.str("event", "kind"))
        assertEquals(listOf("intrusion_detection", "network"), r.list("event", "category"))
        assertEquals(listOf("denied"), r.list("event", "type"))
        assertEquals("threat_domain", r.str("rule", "name"))
        assertEquals("1password-login.example", r.str("destination", "domain"))
        assertNull(r.path("destination", "ip"))
    }

    @Test
    fun alertDestinationsFromTargetAndDetail() {
        fun dest(kind: String, target: String, detail: String? = null) =
            ExportRecords.alertDestination(AlertEvent(ts = 0, kind = kind, severity = "medium", target = target, message = "m", detail = detail?.let { Json.parseToJsonElement(it) }))

        assertEquals(ExportRecords.AlertTarget(null, "203.0.113.7", null), dest("threat_ip", "203.0.113.7"))
        assertEquals(ExportRecords.AlertTarget("163.com", null, null), dest("beacon", "163.com", """{"kind":"connections"}"""))
        assertEquals(
            ExportRecords.AlertTarget("c2.example", "198.51.100.4", 443),
            dest("beacon", "c2.example", """{"kind":"intra_flow","flow_id":3,"dst":"198.51.100.4:443","domain":"c2.example"}"""),
        )
        assertEquals(ExportRecords.AlertTarget(null, "2001:db8::1", 853), dest("threat_ja4", "t13d190900_9dc949149365_97f8aa674fd9", """{"dst":"[2001:db8::1]:853","domain":null}"""))
        assertEquals(ExportRecords.AlertTarget("cdn.example", "192.0.2.9", null), dest("new_asn", "AS64500", """{"destination":"cdn.example","dst_ip":"192.0.2.9"}"""))
        assertNull("a JA4 or AS number is not a destination", dest("new_asn", "AS64500"))
    }

    @Test
    fun beaconAlertIsInfoNotIndicator() {
        val r = ExportRecords.alert(AlertEvent(ts = 0, kind = "beacon", severity = "medium", target = "x.example", message = "m"), app)
        assertEquals(listOf("info"), r.list("event", "type"))
        val ja4Blocked = ExportRecords.alert(
            AlertEvent(ts = 0, kind = "threat_ja4", severity = "high", target = "t13d", message = "m", detail = Json.parseToJsonElement("""{"blocked":true}""")),
            app,
        )
        assertEquals(listOf("denied"), ja4Blocked.list("event", "type"))
    }

    @Test
    fun deviceMetadataUsesAndroidRelease() {
        val r = ExportRecords.withDevice(ExportRecords.alert(AlertEvent(ts = 0, kind = "beacon", severity = "low", target = "x", message = "m"), app),
            "id-1", "Google Pixel 8", "16", 36, "0.5.0")
        assertEquals("16", r.str("host", "os", "version"))
        assertEquals("android", r.str("host", "os", "type"))
        assertEquals(36, r.path("vigil", "android", "api_level")!!.jsonPrimitive.int)
        assertEquals("alert", r.str("vigil", "type"))
    }

    @Test
    fun syslogHeaderUsesTheRecordTime() {
        val r = JsonObject(mapOf("@timestamp" to JsonPrimitive("2026-09-27T18:06:02.114Z")))
        val now = Instant.parse("2026-09-28T00:00:00Z")
        assertEquals("2026-09-27T18:06:02.114Z", WireFormats.recordSyslogTimestamp(r, now))
        assertEquals("2026-09-28T00:00:00Z", WireFormats.recordSyslogTimestamp(JsonObject(emptyMap()), now))
        assertEquals("2026-09-28T00:00:00Z", WireFormats.recordSyslogTimestamp(JsonObject(mapOf("@timestamp" to JsonPrimitive("garbage"))), now))
    }
}
