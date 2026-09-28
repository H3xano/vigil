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
    val upstream: UpstreamConfig = UpstreamConfig(),
) {
    fun toJson(): String = EngineJson.json.encodeToString(serializer(), this)

    /** JSON for logs: keys and passwords replaced. */
    fun toLogJson(): String = copy(upstream = upstream.redacted()).toJson()

    companion object {
        const val TUN_V4 = "10.111.222.1"
        const val VIRTUAL_DNS_V4 = "10.111.222.2"
        const val TUN_V6 = "fd76:6967:696c::1"
        const val VIRTUAL_DNS_V6 = "fd76:6967:696c::2"
        const val MTU = 1500
        val FALLBACK_UPSTREAMS = listOf("1.1.1.1:53", "9.9.9.9:53")
    }
}

/** Mirror of the Rust `UpstreamConfig` (core/vigil-core/src/config/upstream.rs). */
@Serializable
data class UpstreamConfig(
    /** "direct", "wireguard" or "socks5". */
    val mode: String = "direct",
    @SerialName("fail_closed") val failClosed: Boolean = true,
    val wireguard: WireGuardConfig? = null,
    val socks5: Socks5Config? = null,
    /** Identifies the underlying network; a change makes WireGuard roam. */
    @SerialName("network_id") val networkId: String = "",
) {
    fun redacted() = copy(
        wireguard = wireguard?.copy(privateKey = REDACTED, presharedKey = wireguard.presharedKey?.let { REDACTED }),
        socks5 = socks5?.copy(password = if (socks5.password.isEmpty()) "" else REDACTED),
    )

    private companion object {
        const val REDACTED = "<redacted>"
    }
}

@Serializable
data class WireGuardConfig(
    @SerialName("private_key") val privateKey: String,
    @SerialName("peer_public_key") val peerPublicKey: String,
    @SerialName("preshared_key") val presharedKey: String? = null,
    val endpoint: String,
    val addresses: List<String>,
    @SerialName("allowed_ips") val allowedIps: List<String> = emptyList(),
    val mtu: Int = 1280,
    @SerialName("persistent_keepalive") val persistentKeepalive: Int = 0,
)

@Serializable
data class Socks5Config(
    val server: String,
    val username: String = "",
    val password: String = "",
    @SerialName("send_domain") val sendDomain: Boolean = false,
    /** "auto" or "block". */
    val udp: String = "auto",
)

@Serializable
data class BeaconConfig(
    val enabled: Boolean = true,
    @SerialName("min_events") val minEvents: Int = 6,
    @SerialName("max_jitter") val maxJitter: Double = 0.15,
    @SerialName("min_interval_s") val minIntervalS: Double = 10.0,
    @SerialName("max_interval_s") val maxIntervalS: Double = 3600.0,
)
