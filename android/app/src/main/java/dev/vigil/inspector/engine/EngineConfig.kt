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
    /** Conditional blocking per app UID (Wi-Fi, mobile data, background, screen off). */
    @SerialName("app_rules") val appRules: List<AppRuleConfig> = emptyList(),
    /** Allow or block a domain (and its subdomains) for one app UID only. */
    @SerialName("app_domain_rules") val appDomainRules: List<AppDomainRuleConfig> = emptyList(),
    val beacon: BeaconConfig = BeaconConfig(),
    /** NAT64 prefixes (IPv6 /96) of the underlying network; the engine always implies 64:ff9b::/96. */
    @SerialName("nat64_prefixes") val nat64Prefixes: List<String> = emptyList(),
    val mtu: Int = MTU,
    @SerialName("tcp_connect_timeout_ms") val tcpConnectTimeoutMs: Long = 15_000,
    @SerialName("udp_idle_timeout_s") val udpIdleTimeoutS: Long = 60,
    @SerialName("stats_interval_ms") val statsIntervalMs: Long = 2_000,
    @SerialName("worker_threads") val workerThreads: Int = 2,
    /** Upstream DNS over TLS/HTTPS for the virtual resolver's lookups. */
    @SerialName("encrypted_dns") val encryptedDns: EncryptedDnsConfig = EncryptedDnsConfig(),
    val upstream: UpstreamConfig = UpstreamConfig(),
    /**
     * Start config only: feed files the engine loads before it processes the
     * first TUN packet (null: omitted from the JSON, as in every
     * `nativeUpdateConfig` call; later feed changes use `nativeLoadFeedFile`).
     */
    val feeds: List<FeedFileConfig>? = null,
    /** Start config only: how long the engine waits for [feeds] before processing packets. */
    @SerialName("feeds_preload_timeout_ms") val feedsPreloadTimeoutMs: Long? = null,
    /**
     * Start config only: the device state the app conditions start with.
     * Afterwards it is pushed with `nativeSetDeviceState` (null: omitted).
     */
    @SerialName("device_state") val deviceState: DeviceState? = null,
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

        /** The engine's default too; sent explicitly with a feed list. */
        const val FEEDS_PRELOAD_TIMEOUT_MS = 10_000L
    }
}

/**
 * One feed file of the start config: loaded exactly as
 * `nativeLoadFeedFile(handle, id, category, path)` would load it.
 */
@Serializable
data class FeedFileConfig(
    val id: String,
    val category: String,
    val path: String,
)

/** Mirror of the Rust `AppRule` (core/vigil-core/src/config/app_rules.rs). */
@Serializable
data class AppRuleConfig(
    val uid: Int,
    @SerialName("block_wifi") val blockWifi: Boolean = false,
    @SerialName("block_cellular") val blockCellular: Boolean = false,
    @SerialName("block_background") val blockBackground: Boolean = false,
    @SerialName("block_screen_off") val blockScreenOff: Boolean = false,
)

/** Mirror of the Rust `AppDomainRule`: [action] is "allow" or "block". */
@Serializable
data class AppDomainRuleConfig(
    val uid: Int,
    val domain: String,
    val action: String,
)

/**
 * Mirror of the Rust `DeviceState`, sent with `nativeSetDeviceState`.
 * [network]: "wifi", "cellular", "other" or "none". [foregroundUids]: null
 * when unknown (no usage access), so background rules cannot apply.
 */
@Serializable
data class DeviceState(
    val network: String = NETWORK_OTHER,
    @SerialName("screen_on") val screenOn: Boolean = true,
    @SerialName("foreground_uids") val foregroundUids: List<Int>? = null,
) {
    fun toJson(): String = EngineJson.json.encodeToString(serializer(), this)

    companion object {
        const val NETWORK_WIFI = "wifi"
        const val NETWORK_CELLULAR = "cellular"
        const val NETWORK_OTHER = "other"
        const val NETWORK_NONE = "none"
    }
}

/** Mirror of the Rust `EncryptedDnsConfig` (see docs/EVENTS.md). */
@Serializable
data class EncryptedDnsConfig(
    /** "off", "dot" or "doh". */
    val mode: String = "off",
    val servers: List<EncryptedDnsServer> = emptyList(),
    @SerialName("fallback_plain") val fallbackPlain: Boolean = false,
)

/** DoH: [url]. DoT: [host] and [port]. [addrs] are the bootstrap addresses. */
@Serializable
data class EncryptedDnsServer(
    val url: String? = null,
    val host: String? = null,
    val addrs: List<String> = emptyList(),
    val port: Int? = null,
)

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

/**
 * Mirror of the Rust `BeaconConfig`. The in-flow detector's `flow_*` fields
 * and `ignore_domains` are deliberately not mirrored: omitted, they keep the
 * engine's defaults (see docs/EVENTS.md, "`beacon`").
 */
@Serializable
data class BeaconConfig(
    val enabled: Boolean = true,
    @SerialName("min_events") val minEvents: Int = 6,
    @SerialName("max_jitter") val maxJitter: Double = 0.15,
    @SerialName("min_interval_s") val minIntervalS: Double = 10.0,
    @SerialName("max_interval_s") val maxIntervalS: Double = 3600.0,
)
