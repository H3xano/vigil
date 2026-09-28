package dev.vigil.inspector.engine

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/** Events emitted by the engine (see core/vigil-core/src/event.rs). */
@Serializable
sealed interface EngineEvent

@Serializable
@SerialName("flow")
data class FlowEvent(
    val id: Long,
    val ts: Long,
    val proto: String,
    val uid: Int? = null,
    val src: String,
    @SerialName("dst_ip") val dstIp: String,
    @SerialName("dst_port") val dstPort: Int,
    val domain: String? = null,
    @SerialName("domain_source") val domainSource: String? = null,
    @SerialName("app_proto") val appProto: String? = null,
    val alpn: String? = null,
    @SerialName("tls_version") val tlsVersion: String? = null,
    val ja4: String? = null,
    val ech: Boolean = false,
    @SerialName("http_method") val httpMethod: String? = null,
    val verdict: String? = null,
    val reason: String? = null,
    val tags: List<String> = emptyList(),
    /** Upstream path: "direct", "wireguard" or "socks5" (null if never connected). */
    val via: String? = null,
) : EngineEvent

@Serializable
@SerialName("flow_end")
data class FlowEndEvent(
    val id: Long,
    val ts: Long,
    val tx: Long = 0,
    val rx: Long = 0,
    @SerialName("duration_ms") val durationMs: Long = 0,
    val error: String? = null,
) : EngineEvent

@Serializable
@SerialName("flow_update")
data class FlowUpdateEvent(val id: Long, val ts: Long, val tx: Long, val rx: Long) : EngineEvent

@Serializable
@SerialName("dns")
data class DnsEvent(
    val ts: Long,
    val uid: Int? = null,
    val qname: String,
    val qtype: String,
    val rcode: String,
    val answers: List<String> = emptyList(),
    val verdict: String,
    val reason: String? = null,
    @SerialName("latency_ms") val latencyMs: Long = 0,
    val server: String,
    val transport: String,
) : EngineEvent

@Serializable
@SerialName("alert")
data class AlertEvent(
    val ts: Long,
    val kind: String,
    val severity: String,
    val uid: Int? = null,
    val target: String,
    val message: String,
    val detail: JsonElement? = null,
) : EngineEvent

@Serializable
@SerialName("stats")
data class StatsEvent(
    val ts: Long = 0,
    @SerialName("packets_in") val packetsIn: Long = 0,
    @SerialName("packets_out") val packetsOut: Long = 0,
    @SerialName("bytes_in") val bytesIn: Long = 0,
    @SerialName("bytes_out") val bytesOut: Long = 0,
    @SerialName("tcp_active") val tcpActive: Long = 0,
    @SerialName("udp_active") val udpActive: Long = 0,
    @SerialName("flows_total") val flowsTotal: Long = 0,
    @SerialName("dns_queries") val dnsQueries: Long = 0,
    val blocked: Long = 0,
    @SerialName("dropped_packets") val droppedPackets: Long = 0,
    @SerialName("dropped_events") val droppedEvents: Long = 0,
    @SerialName("dns_cache_size") val dnsCacheSize: Long = 0,
    val upstream: UpstreamStatus? = null,
) : EngineEvent

/** State of the upstream path (WireGuard tunnel or SOCKS5 proxy). */
@Serializable
data class UpstreamStatus(
    val mode: String = "direct",
    /** "up", "connecting", "idle" or "down". */
    val state: String = "up",
    @SerialName("fail_closed") val failClosed: Boolean = true,
    val endpoint: String? = null,
    @SerialName("handshake_age_s") val handshakeAgeS: Long? = null,
    @SerialName("tx_bytes") val txBytes: Long? = null,
    @SerialName("rx_bytes") val rxBytes: Long? = null,
    @SerialName("last_error") val lastError: String? = null,
    /** SOCKS5 only: "unknown", "supported", "unsupported" or "blocked". */
    val udp: String? = null,
)

@Serializable
@SerialName("engine")
data class EngineStateEvent(val ts: Long, val state: String, val message: String = "") : EngineEvent

@Serializable
data class FeedSummary(
    val id: String = "",
    val domains: Int = 0,
    @SerialName("ip_ranges") val ipRanges: Int = 0,
    @SerialName("rejected_lines") val rejectedLines: Int = 0,
    @SerialName("memory_bytes") val memoryBytes: Long = 0,
)

object EngineJson {
    val json = Json {
        classDiscriminator = "type"
        ignoreUnknownKeys = true
        explicitNulls = false
        encodeDefaults = true
    }

    private val listSerializer = ListSerializer(EngineEvent.serializer())

    /** Parses one batch; unknown event types are skipped rather than fatal. */
    fun parseBatch(text: String): List<EngineEvent> = try {
        json.decodeFromString(listSerializer, text)
    } catch (e: Exception) {
        parseLeniently(text)
    }

    private fun parseLeniently(text: String): List<EngineEvent> {
        val elements = try {
            json.parseToJsonElement(text) as? kotlinx.serialization.json.JsonArray ?: return emptyList()
        } catch (e: Exception) {
            return emptyList()
        }
        return elements.mapNotNull { runCatching { json.decodeFromJsonElement(EngineEvent.serializer(), it) }.getOrNull() }
    }
}
