package dev.vigil.inspector.engine

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Mirror of the Rust `Config` (core/vigil-core/src/config.rs). */
@Serializable
data class EngineConfig(
    @SerialName("virtual_dns") val virtualDns: List<String> = listOf(VIRTUAL_DNS_V4, VIRTUAL_DNS_V6),
    @SerialName("upstream_dns") val upstreamDns: List<String>,
    val sinkhole: String = "null_ip",
    @SerialName("sinkhole_ttl") val sinkholeTtl: Int = 60,
    @SerialName("block_encrypted_dns") val blockEncryptedDns: Boolean = false,
    /** Reset connections whose JA4 is on a feed (otherwise the match only alerts). */
    @SerialName("block_ja4_matches") val blockJa4Matches: Boolean = false,
    @SerialName("blocked_uids") val blockedUids: List<Int> = emptyList(),
    @SerialName("allow_domains") val allowDomains: List<String> = emptyList(),
    @SerialName("deny_domains") val denyDomains: List<String> = emptyList(),
    val beacon: BeaconConfig = BeaconConfig(),
    /** NAT64 prefixes (IPv6 /96) of the underlying network; the engine always implies 64:ff9b::/96. */
    @SerialName("nat64_prefixes") val nat64Prefixes: List<String> = emptyList(),
    val mtu: Int = MTU,
    @SerialName("tcp_connect_timeout_ms") val tcpConnectTimeoutMs: Long = 15_000,
    @SerialName("udp_idle_timeout_s") val udpIdleTimeoutS: Long = 60,
    @SerialName("stats_interval_ms") val statsIntervalMs: Long = 2_000,
    @SerialName("worker_threads") val workerThreads: Int = 2,
) {
    fun toJson(): String = EngineJson.json.encodeToString(serializer(), this)

    companion object {
        const val TUN_V4 = "10.111.222.1"
        const val VIRTUAL_DNS_V4 = "10.111.222.2"
        const val TUN_V6 = "fd76:6967:696c::1"
        const val VIRTUAL_DNS_V6 = "fd76:6967:696c::2"
        const val MTU = 1500
        val FALLBACK_UPSTREAMS = listOf("1.1.1.1:53", "9.9.9.9:53")
    }
}

@Serializable
data class BeaconConfig(
    val enabled: Boolean = true,
    @SerialName("min_events") val minEvents: Int = 6,
    @SerialName("max_jitter") val maxJitter: Double = 0.15,
    @SerialName("min_interval_s") val minIntervalS: Double = 10.0,
    @SerialName("max_interval_s") val maxIntervalS: Double = 3600.0,
)
