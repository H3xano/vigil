package dev.vigil.inspector.data

import kotlinx.serialization.Serializable

/**
 * How vigil's own relay connections leave the device: directly, through a
 * WireGuard peer or through a SOCKS5 proxy. Inspection is the same in
 * every mode. Stored inside [Settings] (so it shares its backup exclusion).
 */
@Serializable
data class UpstreamSettings(
    /** "direct", "wireguard" or "socks5". */
    val mode: String = "direct",
    /** When the tunnel or proxy is down, fail connections instead of going direct. */
    val failClosed: Boolean = true,
    val wireguard: WireGuardSettings? = null,
    val socks5: Socks5Settings = Socks5Settings(),
) {
    /**
     * App excluded from the VPN because it is the proxy itself (e.g. Orbot):
     * its own connections must not loop back through vigil.
     */
    val excludedPackage: String?
        get() = socks5.proxyApp?.takeIf { mode == MODE_SOCKS5 && it.isNotBlank() }

    /** Why these settings cannot be saved, or null (mirrors the engine's validation). */
    fun validationError(): String? = when (mode) {
        MODE_DIRECT -> null
        MODE_WIREGUARD -> if (wireguard == null) "Import a WireGuard configuration first." else null
        MODE_SOCKS5 -> {
            val s = socks5
            val host = s.host.trim().removePrefix("[").removeSuffix("]")
            val bracketed = if (host.contains(':')) "[$host]" else host
            when {
                host.isEmpty() -> "Enter the proxy host."
                s.port !in 1..65535 -> "The port must be between 1 and 65535."
                !WgQuick.isEndpoint("$bracketed:${s.port}") -> "\"${s.host}\" is not a host name or IP address."
                s.username.toByteArray().size > 255 || s.password.toByteArray().size > 255 -> "Username and password are limited to 255 bytes."
                s.username.isEmpty() && s.password.isNotEmpty() -> "A password needs a username."
                else -> null
            }
        }
        else -> "Unknown mode $mode."
    }

    companion object {
        const val MODE_DIRECT = "direct"
        const val MODE_WIREGUARD = "wireguard"
        const val MODE_SOCKS5 = "socks5"
    }
}

/** The parts of a wg-quick configuration that vigil uses (one peer). */
@Serializable
data class WireGuardSettings(
    val privateKey: String,
    /** Tunnel addresses in CIDR form: at most one IPv4 and one IPv6. */
    val addresses: List<String>,
    /** Resolvers inside the tunnel ([Interface] DNS), IP addresses only. */
    val dns: List<String> = emptyList(),
    val mtu: Int? = null,
    val peerPublicKey: String,
    val presharedKey: String? = null,
    /** `host:port` or `[v6]:port`. */
    val endpoint: String,
    val allowedIps: List<String> = emptyList(),
    val persistentKeepalive: Int = 0,
    /** Name of the imported file or "pasted", for display. */
    val name: String = "",
)

@Serializable
data class Socks5Settings(
    val host: String = "127.0.0.1",
    val port: Int = 9050,
    val username: String = "",
    val password: String = "",
    /** Connect by the sniffed TLS SNI / HTTP Host name (the proxy resolves it). */
    val sendDomain: Boolean = false,
    /** "auto" (UDP ASSOCIATE when the proxy supports it) or "block". */
    val udp: String = "auto",
    /** Package of a proxy app on this device (e.g. Orbot), excluded from the VPN. */
    val proxyApp: String? = null,
)
