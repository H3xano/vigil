package dev.vigil.inspector.processing

import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.engine.AsnInfo
import dev.vigil.inspector.engine.DnsEvent
import dev.vigil.inspector.engine.EngineJson
import dev.vigil.inspector.engine.FlowEndEvent
import dev.vigil.inspector.engine.FlowEvent
import dev.vigil.inspector.export.ExportRecords
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** `via`, DNS `upstream` and `asn` from the engine's JSON to Room rows and SIEM records. */
class EnrichmentMappingTest {
    // Wire format as emitted by vigil-cli (see scripts/e2e/check_events.py).
    private val batch = EngineJson.parseBatch(
        """[
          {"type":"flow","id":7,"ts":10,"proto":"udp","uid":10123,"src":"10.111.222.1:5000","dst_ip":"1.1.1.1","dst_port":443,
           "domain":"www.cloudflare.com","domain_source":"quic","app_proto":"quic","tags":[],"verdict":"allow","via":"wireguard",
           "asn":{"number":13335,"name":"CLOUDFLARENET","country":"US"}},
          {"type":"flow","id":8,"ts":11,"proto":"tcp","src":"s","dst_ip":"10.0.0.1","dst_port":80,"tags":[],"via":null,"asn":null},
          {"type":"flow","id":9,"ts":12,"proto":"tcp","src":"s","dst_ip":"192.0.2.1","dst_port":80,"tags":[],"via":"direct",
           "asn":{"number":64496,"name":"","country":null}},
          {"type":"dns","ts":13,"qname":"example.com","qtype":"A","rcode":"NOERROR","answers":["93.184.215.14"],"verdict":"allow",
           "latency_ms":20,"server":"virtual","transport":"udp","upstream":"doh"},
          {"type":"dns","ts":14,"qname":"ads.example","qtype":"A","rcode":"NOERROR","answers":[],"verdict":"block",
           "latency_ms":0,"server":"virtual","transport":"udp","upstream":null}
        ]""",
    )
    private val flows = batch.filterIsInstance<FlowEvent>()
    private val dns = batch.filterIsInstance<DnsEvent>()

    @Test
    fun parsesViaAsnAndUpstream() {
        assertEquals(3, flows.size)
        assertEquals("wireguard", flows[0].via)
        assertEquals(AsnInfo(13335, "CLOUDFLARENET", "US"), flows[0].asn)
        assertNull(flows[1].via)
        assertNull(flows[1].asn)
        assertEquals("doh", dns[0].upstream)
        assertNull(dns[1].upstream)
    }

    @Test
    fun mapsToRows() {
        val f = EntityMapping.flow(flows[0], session = 5, pkg = "com.android.chrome", background = false)
        assertEquals("wireguard", f.via)
        assertEquals(13335L, f.asn)
        assertEquals("CLOUDFLARENET", f.asnName)
        assertEquals("US", f.asnCountry)
        assertEquals(5L, f.session)
        val none = EntityMapping.flow(flows[1], 5, "unknown", null)
        assertNull(none.via)
        assertNull(none.asn)
        assertNull(none.asnName)
        val noName = EntityMapping.flow(flows[2], 5, "x", null)
        assertEquals("direct", noName.via)
        assertEquals(64496L, noName.asn)
        assertNull("empty names are stored as null", noName.asnName)
        assertEquals("doh", EntityMapping.dns(dns[0], "x").upstream)
        assertNull(EntityMapping.dns(dns[1], "x").upstream)
    }

    @Test
    fun siemRecordsCarryViaAndEcsAs() {
        val app = AppInfo("com.android.chrome", 10123, "Chrome", isSystem = true, isInstalledPackage = true)
        val end = FlowEndEvent(id = 7, ts = 20, tx = 1, rx = 2, durationMs = 10)
        val r = ExportRecords.flow(flows[0], end, app)
        val dest = r.getValue("destination").jsonObject
        val asObj = dest.getValue("as").jsonObject
        assertEquals("13335", asObj.getValue("number").jsonPrimitive.content)
        assertEquals("CLOUDFLARENET", asObj.getValue("organization").jsonObject.getValue("name").jsonPrimitive.content)
        val vigil = r.getValue("vigil").jsonObject
        assertEquals("wireguard", vigil.getValue("via").jsonPrimitive.content)
        assertEquals("US", vigil.getValue("asn_country").jsonPrimitive.content)
        val bare = ExportRecords.flow(flows[1], end, app)
        assertNull((bare.getValue("destination") as JsonObject)["as"])
        assertNull((bare.getValue("vigil") as JsonObject)["via"])
        val noName = ExportRecords.flow(flows[2], end, app).getValue("destination").jsonObject.getValue("as").jsonObject
        assertNull(noName["organization"])
        assertEquals("doh", ExportRecords.dns(dns[0], app).getValue("vigil").jsonObject.getValue("upstream").jsonPrimitive.content)
    }
}
