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
    /** Client addresses or CIDR ranges allowed to connect; empty = anyone who can reach the port. */
    val streamAllow: List<String> = emptyList(),
) {
    companion object {
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
