package dev.vigil.inspector.export

import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.data.Tracker
import dev.vigil.inspector.data.TrackerIndex
import dev.vigil.inspector.engine.AlertEvent
import dev.vigil.inspector.engine.DnsEvent
import dev.vigil.inspector.engine.FlowEndEvent
import dev.vigil.inspector.engine.FlowEvent
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class ExportTrackerTest {
    private val app = AppInfo("com.example.app", 10123, "Example", isSystem = false, isInstalledPackage = true)
    private val index = TrackerIndex(
        mapOf(
            "doubleclick.net" to Tracker("google_marketing", "Google Marketing", "advertising", "Google", "http://www.google.com"),
            "aaxads.com" to Tracker("aaxads.com", "Acceptable Ads Exchange", "advertising", null, null),
        ),
    )

    private fun flow(domain: String?) = ExportRecords.flow(
        FlowEvent(id = 1, ts = 1_000, proto = "tcp", src = "10.111.222.1:40000", dstIp = "142.250.1.1", dstPort = 443, domain = domain, verdict = "allow"),
        FlowEndEvent(id = 1, ts = 2_000, tx = 10, rx = 20),
        app,
    )

    private fun dns(qname: String) = ExportRecords.dns(
        DnsEvent(ts = 1, qname = qname, qtype = "A", rcode = "NOERROR", verdict = "block", server = "virtual", transport = "udp"),
        app,
    )

    private fun tracker(r: JsonObject): JsonObject? = r["vigil"]!!.jsonObject["tracker"]?.jsonObject

    private fun JsonObject.str(k: String) = this[k]?.jsonPrimitive?.content

    @Test
    fun flowAndDnsRecordsGetTrackerFields() {
        val f = tracker(ExportRecords.withTracker(flow("securepubads.g.doubleclick.net"), index::match))!!
        assertEquals("google_marketing", f.str("id"))
        assertEquals("Google Marketing", f.str("name"))
        assertEquals("Google", f.str("company"))
        assertEquals("advertising", f.str("category"))
        assertEquals("doubleclick.net", f.str("domain"))

        val d = ExportRecords.withTracker(dns("x.aaxads.com"), index::match)
        val t = tracker(d)!!
        assertEquals("Acceptable Ads Exchange", t.str("name"))
        assertNull(t["company"]) // unknown company: omitted
        // Other vigil fields are kept.
        assertEquals("dns", d["vigil"]!!.jsonObject.str("type"))
        assertEquals("virtual", d["vigil"]!!.jsonObject.str("server"))
    }

    @Test
    fun unlabelledAndOtherRecordsAreUnchanged() {
        val plain = flow("en.wikipedia.org")
        assertSame(plain, ExportRecords.withTracker(plain, index::match))
        val noName = flow(null)
        assertSame(noName, ExportRecords.withTracker(noName, index::match))
        val lookalike = dns("notdoubleclick.net")
        assertSame(lookalike, ExportRecords.withTracker(lookalike, index::match))
        // Alerts are not labelled, even when they name a tracker domain.
        val alert = ExportRecords.alert(
            AlertEvent(ts = 1, kind = "new_destination", severity = "info", uid = 1, target = "doubleclick.net", message = "m"),
            app,
        )
        assertSame(alert, ExportRecords.withTracker(alert, index::match))
    }

    @Test
    fun recordDomain() {
        assertEquals("a.doubleclick.net", ExportRecords.recordDomain(flow("a.doubleclick.net")))
        assertEquals("q.example", ExportRecords.recordDomain(dns("q.example")))
        assertNull(ExportRecords.recordDomain(flow(null)))
    }
}
