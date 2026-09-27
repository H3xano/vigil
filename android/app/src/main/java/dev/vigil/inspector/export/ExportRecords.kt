package dev.vigil.inspector.export

import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.engine.AlertEvent
import dev.vigil.inspector.engine.DnsEvent
import dev.vigil.inspector.engine.FlowEndEvent
import dev.vigil.inspector.engine.FlowEvent
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant

/**
 * Builds the records sent to a SIEM. Field names loosely follow the Elastic
 * Common Schema (`@timestamp`, `event.*`, `source.*`, `destination.*`,
 * `network.*`, `tls.*`, `dns.*`) so they map cleanly into Elastic, Splunk
 * CIM or Sentinel without custom parsing. See docs/EVENTS.md.
 */
object ExportRecords {
    private fun p(v: Any?): JsonElement = when (v) {
        null -> JsonNull
        is String -> JsonPrimitive(v)
        is Number -> JsonPrimitive(v)
        is Boolean -> JsonPrimitive(v)
        is JsonElement -> v
        is List<*> -> JsonArray(v.map { p(it) })
        else -> JsonPrimitive(v.toString())
    }

    private fun obj(vararg pairs: Pair<String, Any?>) = JsonObject(pairs.filter { it.second != null }.associate { it.first to p(it.second) })

    private fun iso(ms: Long) = Instant.ofEpochMilli(ms).toString()

    private fun app(a: AppInfo) = obj("package" to a.key, "name" to a.label, "uid" to a.uid, "system" to a.isSystem)

    private fun hostPort(s: String): Pair<String, Int?> {
        val i = s.lastIndexOf(':')
        if (i <= 0) return s to null
        return s.substring(0, i).trim('[', ']') to s.substring(i + 1).toIntOrNull()
    }

    fun flow(f: FlowEvent, end: FlowEndEvent, a: AppInfo): JsonObject {
        val (srcIp, srcPort) = hostPort(f.src)
        return obj(
            "@timestamp" to iso(f.ts),
            "event" to obj(
                "kind" to "event", "category" to listOf("network"), "type" to listOf(if (f.verdict == "block") "denied" else "connection"),
                "action" to f.verdict, "reason" to f.reason, "duration" to end.durationMs * 1_000_000, "end" to iso(end.ts),
                "dataset" to "vigil.flow",
            ),
            "vigil" to obj("type" to "flow", "flow_id" to f.id, "domain_source" to f.domainSource, "tags" to f.tags, "error" to end.error),
            "app" to app(a),
            "network" to obj("transport" to f.proto, "protocol" to f.appProto, "bytes" to end.tx + end.rx),
            "source" to obj("ip" to srcIp, "port" to srcPort, "bytes" to end.tx),
            "destination" to obj("ip" to f.dstIp, "port" to f.dstPort, "domain" to f.domain, "bytes" to end.rx),
            "tls" to if (f.tlsVersion != null || f.ja4 != null) {
                obj("version" to f.tlsVersion, "next_protocol" to f.alpn, "client" to obj("ja4" to f.ja4, "server_name" to f.domain.takeIf { f.domainSource == "sni" || f.domainSource == "quic" }), "ech" to f.ech)
            } else null,
            "http" to f.httpMethod?.let { obj("request" to obj("method" to it)) },
        )
    }

    fun dns(d: DnsEvent, a: AppInfo) = obj(
        "@timestamp" to iso(d.ts),
        "event" to obj(
            "kind" to "event", "category" to listOf("network"), "type" to listOf("protocol"), "action" to d.verdict,
            "reason" to d.reason, "dataset" to "vigil.dns", "duration" to d.latencyMs * 1_000_000,
        ),
        "vigil" to obj("type" to "dns", "server" to d.server),
        "app" to app(a),
        "network" to obj("transport" to d.transport, "protocol" to "dns"),
        "dns" to obj(
            "question" to obj("name" to d.qname, "type" to d.qtype),
            "response_code" to d.rcode,
            "answers" to d.answers.map { obj("data" to it) },
        ),
    )

    fun alert(e: AlertEvent, a: AppInfo) = obj(
        "@timestamp" to iso(e.ts),
        "event" to obj(
            "kind" to "alert", "category" to listOf(if (e.kind.startsWith("threat")) "intrusion_detection" else "network"),
            "type" to listOf("indicator"), "action" to e.kind, "severity" to severityNumber(e.severity), "dataset" to "vigil.alert",
        ),
        "message" to e.message,
        "vigil" to obj("type" to "alert", "kind" to e.kind, "severity" to e.severity, "target" to e.target, "detail" to e.detail),
        "app" to app(a),
    )

    /** ECS event.severity (0-100) from vigil's severity names. */
    fun severityNumber(s: String) = when (s) {
        "high" -> 73
        "medium" -> 47
        "low" -> 21
        else -> 0
    }

    /** Adds device metadata; done at send time so records stay small in memory. */
    fun withDevice(record: JsonObject, deviceId: String, model: String, sdk: Int, appVersion: String): JsonObject =
        JsonObject(
            record + mapOf(
                "host" to obj("id" to deviceId, "type" to "mobile", "os" to obj("family" to "android", "version" to sdk.toString()), "hostname" to model),
                "observer" to obj("vendor" to "vigil", "product" to "vigil", "version" to appVersion),
            ),
        )
}

/** RFC 5424 syslog framing and HTTP body formats. */
object WireFormats {
    /** Facility local0. */
    private const val FACILITY = 16

    fun syslogSeverity(record: JsonObject): Int {
        val vigil = record["vigil"] as? JsonObject
        return when ((vigil?.get("severity") as? JsonPrimitive)?.content) {
            "high" -> 3
            "medium" -> 4
            "low" -> 5
            "info" -> 6
            else -> 6
        }
    }

    fun syslog(record: JsonObject, hostname: String, timestamp: String): String {
        val vigil = record["vigil"] as? JsonObject
        val msgId = (vigil?.get("type") as? JsonPrimitive)?.content ?: "event"
        val pri = FACILITY * 8 + syslogSeverity(record)
        val host = hostname.filter { it in '!'..'~' }.take(255).ifEmpty { "-" }
        return "<$pri>1 $timestamp $host vigil - $msgId - $record"
    }

    /** RFC 6587 octet counting, required for multi-line safety over TCP/TLS. */
    fun octetCounted(msg: String): ByteArray {
        val body = msg.toByteArray(Charsets.UTF_8)
        return "${body.size} ".toByteArray(Charsets.US_ASCII) + body
    }

    fun httpBody(records: List<JsonObject>, format: String): String = when (format) {
        "splunk_hec" -> records.joinToString("\n") { r ->
            val ts = (r["@timestamp"] as? JsonPrimitive)?.content?.let { runCatching { Instant.parse(it).toEpochMilli() / 1000.0 }.getOrNull() }
            JsonObject(
                listOfNotNull(
                    ts?.let { "time" to JsonPrimitive(it) },
                    "sourcetype" to JsonPrimitive("vigil:json"),
                    "source" to JsonPrimitive("vigil"),
                    "event" to r,
                ).toMap(),
            ).toString()
        }
        "elastic_bulk" -> records.joinToString("") { "{\"create\":{}}\n$it\n" }
        else -> records.joinToString("\n", postfix = "\n")
    }

    fun contentType(format: String) = when (format) {
        "splunk_hec" -> "application/json"
        else -> "application/x-ndjson"
    }
}
