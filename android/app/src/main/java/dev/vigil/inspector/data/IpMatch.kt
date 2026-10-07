package dev.vigil.inspector.data

import dev.vigil.inspector.vpn.IpLiteral

/**
 * IP addresses compared by value, not by text: `2001:db8:0::1`,
 * `2001:DB8::1` and `2001:db8::0:1` are one address. IPv4-mapped IPv6
 * addresses (`::ffff:192.0.2.1`) are the IPv4 address.
 */
object IpAddrs {
    /** 4 or 16 bytes, or null if [s] is not an IP literal. */
    fun parse(s: String): ByteArray? {
        val t = s.trim()
        IpLiteral.parseV4(t)?.let { return it }
        val v6 = IpLiteral.parseV6(t) ?: return null
        return if (isV4Mapped(v6)) v6.copyOfRange(12, 16) else v6
    }

    private fun isV4Mapped(b: ByteArray): Boolean {
        for (i in 0 until 10) if (b[i] != 0.toByte()) return false
        return b[10] == 0xFF.toByte() && b[11] == 0xFF.toByte()
    }

    /** A map key for [bytes] (hex; the length tells the family apart). */
    fun key(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for ((i, b) in bytes.withIndex()) {
            val v = b.toInt() and 0xFF
            out[2 * i] = HEX[v shr 4]
            out[2 * i + 1] = HEX[v and 15]
        }
        return String(out)
    }

    /** RFC 5952 text of a 16-byte IPv6 address: lower case, the longest run of two or more zero groups as `::`. */
    fun formatV6(b: ByteArray): String {
        require(b.size == 16)
        val g = IntArray(8) { ((b[2 * it].toInt() and 0xFF) shl 8) or (b[2 * it + 1].toInt() and 0xFF) }
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (g[i] != 0) { i++; continue }
            var j = i
            while (j < 8 && g[j] == 0) j++
            if (j - i > bestLen) { bestStart = i; bestLen = j - i }
            i = j
        }
        if (bestLen < 2) return g.joinToString(":") { it.toString(16) }
        val head = (0 until bestStart).joinToString(":") { g[it].toString(16) }
        val tail = (bestStart + bestLen until 8).joinToString(":") { g[it].toString(16) }
        return "$head::$tail"
    }

    private val HEX = "0123456789abcdef".toCharArray()
}

/** An IPv4 or IPv6 CIDR range. */
class IpRange private constructor(private val base: ByteArray, val bits: Int) {
    fun contains(address: ByteArray): Boolean {
        if (address.size != base.size) return false
        val full = bits / 8
        for (i in 0 until full) if (address[i] != base[i]) return false
        val rest = bits % 8
        if (rest == 0) return true
        val mask = (0xFF shl (8 - rest)) and 0xFF
        return (address[full].toInt() and mask) == (base[full].toInt() and mask)
    }

    companion object {
        /** `address/prefix` (IPv4 or IPv6), or null. Host bits are ignored, as a router would. */
        fun parse(s: String): IpRange? {
            val t = s.trim()
            val slash = t.indexOf('/')
            if (slash < 0) return null
            val text = t.substring(0, slash)
            val raw = IpLiteral.parseV4(text) ?: IpLiteral.parseV6(text) ?: return null
            var bits = t.substring(slash + 1).toIntOrNull() ?: return null
            if (bits !in 0..raw.size * 8) return null
            var bytes = raw
            // ::ffff:a.b.c.d/(96+n) is the IPv4 range a.b.c.d/n.
            if (raw.size == 16 && bits >= 96 && IpAddrs.parse(text)?.size == 4) {
                bytes = raw.copyOfRange(12, 16)
                bits -= 96
            }
            return IpRange(bytes, bits)
        }
    }
}

/**
 * Indicators listed as IP addresses or CIDR ranges, each with a value.
 * Addresses are keyed by their bytes, so any textual form of a listed
 * address matches, and ranges match every address they contain.
 */
class IpMatcher<T> {
    /** A listed indicator ([text] as listed) and its value. */
    data class Hit<T>(val text: String, val value: T)

    private val exact = HashMap<String, MutableList<Hit<T>>>()
    private val ranges = ArrayList<Pair<IpRange, Hit<T>>>()

    val isEmpty: Boolean get() = exact.isEmpty() && ranges.isEmpty()

    /** Adds [indicator] (address or range); false if it is neither. */
    fun add(indicator: String, value: T): Boolean {
        val text = indicator.trim()
        if ('/' in text) {
            val r = IpRange.parse(text) ?: return false
            ranges += r to Hit(text, value)
        } else {
            val b = IpAddrs.parse(text) ?: return false
            exact.getOrPut(IpAddrs.key(b)) { ArrayList(1) } += Hit(text, value)
        }
        return true
    }

    /** Indicators matching [address]: exact entries first, then ranges in the order added. Empty if it is no address. */
    fun match(address: String): List<Hit<T>> {
        val b = IpAddrs.parse(address) ?: return emptyList()
        val out = ArrayList<Hit<T>>(exact[IpAddrs.key(b)].orEmpty())
        for ((r, h) in ranges) if (r.contains(b)) out += h
        return out
    }
}
