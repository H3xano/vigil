package dev.vigil.inspector.vpn

/**
 * Strict numeric IP address parsing in pure Kotlin (no DNS, no android.*),
 * so it behaves the same on the device and in JVM unit tests. It mirrors
 * `InetAddresses.isNumericAddress` minus its leniencies: IPv4 needs exactly
 * four decimal parts without leading zeros, IPv6 needs eight groups (or `::`)
 * and scope ids (`%wlan0`) are rejected.
 */
object IpLiteral {
    /** 4 bytes, or null if [s] is not a dotted-quad IPv4 literal. */
    fun parseV4(s: String): ByteArray? {
        val parts = s.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
            if (p.length > 1 && p[0] == '0') return null
            val v = p.toInt()
            if (v > 255) return null
            out[i] = v.toByte()
        }
        return out
    }

    /** 16 bytes, or null if [s] is not an IPv6 literal (embedded IPv4 tail allowed). */
    fun parseV6(s: String): ByteArray? {
        if (s.isEmpty() || s.length > 45 || '%' in s) return null
        val halves = s.split("::")
        if (halves.size > 2) return null
        val head = groups(halves[0]) ?: return null
        val tail = if (halves.size == 2) groups(halves[1]) ?: return null else emptyList()
        val all = head + tail
        // An IPv4 tail may only be the very last element.
        for ((i, g) in all.withIndex()) if (g.size == 4 && i != all.lastIndex) return null
        val words = all.sumOf { it.size } / 2
        if (halves.size == 1 && words != 8) return null
        if (halves.size == 2 && words > 7) return null
        val out = ByteArray(16)
        var pos = 0
        for (g in head) for (b in g) out[pos++] = b
        pos = 16 - tail.sumOf { it.size }
        for (g in tail) for (b in g) out[pos++] = b
        return out
    }

    fun isV4(s: String) = parseV4(s) != null
    fun isV6(s: String) = parseV6(s) != null

    /** Each element is 2 bytes (hex group) or 4 bytes (IPv4 tail). */
    private fun groups(part: String): List<ByteArray>? {
        if (part.isEmpty()) return emptyList()
        val items = part.split(':')
        return items.mapIndexed { i, g ->
            if (i == items.lastIndex && '.' in g) return@mapIndexed parseV4(g) ?: return null
            if (g.isEmpty() || g.length > 4 || !g.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
            val v = g.toInt(16)
            byteArrayOf((v shr 8).toByte(), v.toByte())
        }
    }
}
