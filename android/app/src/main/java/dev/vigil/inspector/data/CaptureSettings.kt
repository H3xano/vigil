package dev.vigil.inspector.data

import dev.vigil.inspector.vpn.IpLiteral
import kotlinx.serialization.Serializable

/**
 * Packet capture (Settings → Packet capture). Packets are kept in the
 * engine's memory only; nothing is written to disk except on export.
 */
@Serializable
data class CaptureSettings(
    val enabled: Boolean = false,
    /** Ring size in MiB (one of [BUFFER_CHOICES_MB]). */
    val bufferMb: Int = 16,
    /** PCAP-over-IP server for Wireshark. */
    val streamEnabled: Boolean = false,
    val streamPort: Int = DEFAULT_STREAM_PORT,
    /** Where the server listens: [BIND_WIFI] (default), [BIND_ALL] or [BIND_LOOPBACK]. */
    val streamBind: String = BIND_WIFI,
    /**
     * Client addresses or CIDR ranges allowed to connect. Required when the
     * stream listens on the network ([BIND_WIFI], [BIND_ALL]): with an empty
     * list the stream does not listen at all ([streamRefused]).
     */
    val streamAllow: List<String> = emptyList(),
) {
    /** The allowlist as the engine gets it: valid entries only, trimmed, de-duplicated, at most [MAX_ALLOW]. */
    fun allowList(): List<String> = streamAllow.map { it.trim() }.filter { isValidAllowEntry(it) }.distinct().take(MAX_ALLOW)

    /**
     * True when the stream may not listen with these settings. A listener
     * on the network ([BIND_WIFI], [BIND_ALL]) needs a non-empty allowlist:
     * otherwise anyone on the network would receive the packets (the UI
     * explains this with `capture_needs_allowlist`).
     */
    fun streamRefused(): Boolean = streamEnabled && needsAllowList(streamBind) && allowList().isEmpty()

    companion object {
        const val MAX_ALLOW = 32

        /** True for the bind choices that listen on the network rather than on loopback. */
        fun needsAllowList(bind: String) = bind != BIND_LOOPBACK

        const val DEFAULT_STREAM_PORT = 57012
        const val BIND_WIFI = "wifi"
        const val BIND_ALL = "all"
        const val BIND_LOOPBACK = "loopback"
        val BUFFER_CHOICES_MB = listOf(4, 16, 64, 128)

        /** An allowlist entry: an IP address or `address/prefix` (as the engine parses them). */
        fun isValidAllowEntry(raw: String): Boolean {
            val parts = raw.trim().split('/')
            if (parts.size > 2) return false
            val addr = parts[0]
            val v4 = IpLiteral.isV4(addr)
            if (!v4 && !IpLiteral.isV6(addr)) return false
            if (parts.size == 1) return true
            val p = parts[1]
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return false
            return p.toInt() <= if (v4) 32 else 128
        }

        fun isValidPort(port: Int) = port in 1024..65535
    }
}
