package dev.vigil.inspector.processing

import dev.vigil.inspector.data.AlertEntity
import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.engine.AlertEvent
import dev.vigil.inspector.export.ExportRecords
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AppAlertsTest {
    private val app = AppInfo("com.example.app", 10123, "Example", isSystem = false, isInstalledPackage = true)

    private fun JsonObject.o(k: String) = this[k]!!.jsonObject
    private fun JsonObject.s(k: String) = this[k]!!.jsonPrimitive.content

    @Test
    fun newAsnAlertExportsLikeAnEngineAlert() {
        val detail = """{"asn":64500,"as_name":"Example Net","as_country":"NL","destination":"cdn.example.net","dst_ip":"192.0.2.7","known_networks":2}"""
        val stored = AlertEntity(
            ts = 1_700_000_000_000, kind = "new_asn", severity = "medium", uid = 10123, pkg = app.key, target = "AS64500",
            message = "Example contacted a network it has never used before: AS64500 Example Net", detail = detail,
        )
        val event = AppAlerts.toEvent(stored)
        val r = ExportRecords.alert(event, app)
        // The same record as for an engine alert with these fields.
        assertEquals(
            ExportRecords.alert(
                AlertEvent(ts = stored.ts, kind = "new_asn", severity = "medium", uid = 10123, target = "AS64500", message = stored.message,
                    detail = kotlinx.serialization.json.Json.parseToJsonElement(detail)),
                app,
            ),
            r,
        )
        assertEquals("alert", r.o("event").s("kind"))
        assertEquals("vigil.alert", r.o("event").s("dataset"))
        assertEquals("new_asn", r.o("event").s("action"))
        assertEquals(listOf("intrusion_detection", "network"), r.o("event")["category"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("new_asn", r.o("rule").s("name"))
        assertEquals("192.0.2.7", r.o("destination").s("ip"))
        assertEquals("cdn.example.net", r.o("destination").s("domain"))
        assertEquals(64500, r.o("vigil").o("detail")["asn"]!!.jsonPrimitive.content.toInt())
        assertEquals("com.example.app", r.o("app").s("package"))
    }

    @Test
    fun newDestinationAlertCarriesTheDomain() {
        val stored = AlertEntity(
            ts = 1, kind = "new_destination", severity = "info", uid = 10123, pkg = app.key, target = "tracker.example",
            message = "m", detail = JsonObject(mapOf("destination" to JsonPrimitive("tracker.example"))).toString(),
        )
        val r = ExportRecords.alert(AppAlerts.toEvent(stored), app)
        assertEquals("tracker.example", r.o("destination").s("domain"))
        assertEquals("info", r.o("vigil").s("severity"))
    }

    @Test
    fun unreadableDetailIsDropped() {
        val stored = AlertEntity(ts = 1, kind = "new_asn", severity = "low", uid = null, pkg = "x", target = "AS1", message = "m", detail = "{")
        assertNull(AppAlerts.toEvent(stored).detail)
    }
}
