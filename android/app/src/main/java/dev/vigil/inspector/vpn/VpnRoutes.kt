package dev.vigil.inspector.vpn

/**
 * Computes the routes installed into the VPN. With `excludeLan`, private and
 * link-local ranges are left out so local devices (casting, printers, NAS)
 * keep working without being relayed, while the virtual resolver's subnet is
 * always routed into the tunnel.
 */
object VpnRoutes {
    data class Cidr(val address: String, val prefix: Int) {
        override fun toString() = "$address/$prefix"
    }

    private val PRIVATE_V4 = listOf(
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.168.0.0/16", "224.0.0.0/3",
    )
    const val VIRTUAL_V4 = "10.111.222.0/24"
    const val VIRTUAL_V6 = "fd76:6967:696c::/64"

    fun ipv4(excludeLan: Boolean): List<Cidr> {
        if (!excludeLan) return listOf(Cidr("0.0.0.0", 0))
        val excluded = PRIVATE_V4.map(::v4Range)
        return subtract(0L..0xFFFF_FFFFL, excluded).flatMap(::rangeToCidrs) + parseCidr(VIRTUAL_V4)
    }

    fun ipv6(excludeLan: Boolean): List<Cidr> =
        if (!excludeLan) listOf(Cidr("::", 0)) else listOf(Cidr("2000::", 3), parseCidr(VIRTUAL_V6))

    private fun parseCidr(s: String): Cidr {
        val (a, p) = s.split('/')
        return Cidr(a, p.toInt())
    }

    private fun v4ToLong(a: String): Long = a.split('.').fold(0L) { acc, part -> (acc shl 8) or part.toLong() }

    private fun longToV4(v: Long) = "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"

    private fun v4Range(cidr: String): LongRange {
        val (a, p) = cidr.split('/')
        val prefix = p.toInt()
        val size = 1L shl (32 - prefix)
        val start = v4ToLong(a) and (size - 1).inv() and 0xFFFF_FFFFL
        return start until start + size
    }

    /** [whole] minus the union of [holes], as sorted disjoint ranges. */
    internal fun subtract(whole: LongRange, holes: List<LongRange>): List<LongRange> {
        val out = mutableListOf<LongRange>()
        var cursor = whole.first
        for (h in holes.sortedBy { it.first }) {
            if (h.last < cursor) continue
            if (h.first > cursor) out += cursor until h.first
            cursor = maxOf(cursor, h.last + 1)
            if (cursor > whole.last) break
        }
        if (cursor <= whole.last) out += cursor..whole.last
        return out
    }

    /** Minimal CIDR cover of an IPv4 range. */
    internal fun rangeToCidrs(r: LongRange): List<Cidr> {
        val out = mutableListOf<Cidr>()
        var start = r.first
        while (start <= r.last) {
            var size = if (start == 0L) 1L shl 32 else java.lang.Long.lowestOneBit(start)
            while (start + size - 1 > r.last) size = size shr 1
            out += Cidr(longToV4(start), 32 - java.lang.Long.numberOfTrailingZeros(size))
            start += size
        }
        return out
    }
}
