package dev.vigil.inspector.vpn

import java.math.BigInteger

/**
 * Computes the routes installed into the VPN. With `excludeLan`, private and
 * link-local ranges are left out so local devices (casting, printers, NAS)
 * keep working without being relayed, while the virtual resolver's subnet is
 * always routed into the tunnel.
 *
 * The exclusions are computed as complements (instead of
 * `VpnService.Builder.excludeRoute`, API 33+) so one code path serves every
 * supported API level and stays unit-testable.
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

    /** ULA, link-local and multicast. Everything else (incl. NAT64 64:ff9b::/96, 64:ff9b:1::/48) is tunnelled. */
    private val PRIVATE_V6 = listOf("fc00::/7", "fe80::/10", "ff00::/8")

    /**
     * IPv6 routes. [extra] adds prefixes that must be tunnelled even when they
     * fall into an excluded range (e.g. a NAT64 prefix taken from ULA space).
     */
    fun ipv6(excludeLan: Boolean, extra: List<String> = emptyList()): List<Cidr> {
        if (!excludeLan) return listOf(Cidr("::", 0))
        val excluded = PRIVATE_V6.map(::v6Range)
        val base = subtract6(V6_ALL, excluded).flatMap(::rangeToCidrs6) + parseCidr(VIRTUAL_V6)
        val extras = extra.mapNotNull { c -> runCatching { v6Range(c) }.getOrNull()?.let { c } }
            .filter { c -> val r = v6Range(c); excluded.any { r.first >= it.first && r.second <= it.second } }
            .map(::parseCidr)
        return (base + extras).distinct()
    }

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

    private val V6_MAX: BigInteger = BigInteger.ONE.shiftLeft(128) - BigInteger.ONE
    private val V6_ALL = BigInteger.ZERO to V6_MAX

    internal fun v6ToBig(a: String): BigInteger {
        val bytes = requireNotNull(IpLiteral.parseV6(a)) { "not IPv6: $a" }
        return BigInteger(1, bytes)
    }

    internal fun bigToV6(v: BigInteger): String =
        (0 until 8).joinToString(":") { i -> v.shiftRight(16 * (7 - i)).and(BigInteger.valueOf(0xFFFF)).toString(16) }

    /** Inclusive range of an IPv6 CIDR. */
    private fun v6Range(cidr: String): Pair<BigInteger, BigInteger> {
        val (a, p) = cidr.split('/')
        val prefix = p.toInt()
        require(prefix in 0..128)
        val hostMask = BigInteger.ONE.shiftLeft(128 - prefix) - BigInteger.ONE
        val start = v6ToBig(a).andNot(hostMask)
        return start to start + hostMask
    }

    private fun subtract6(whole: Pair<BigInteger, BigInteger>, holes: List<Pair<BigInteger, BigInteger>>): List<Pair<BigInteger, BigInteger>> {
        val out = mutableListOf<Pair<BigInteger, BigInteger>>()
        var cursor = whole.first
        for (h in holes.sortedBy { it.first }) {
            if (h.second < cursor) continue
            if (h.first > cursor) out += cursor to h.first - BigInteger.ONE
            cursor = cursor.max(h.second + BigInteger.ONE)
            if (cursor > whole.second) break
        }
        if (cursor <= whole.second) out += cursor to whole.second
        return out
    }

    /** Minimal CIDR cover of an inclusive IPv6 range. */
    private fun rangeToCidrs6(r: Pair<BigInteger, BigInteger>): List<Cidr> {
        val out = mutableListOf<Cidr>()
        var start = r.first
        while (start <= r.second) {
            var bits = if (start.signum() == 0) 128 else start.lowestSetBit
            while (start + BigInteger.ONE.shiftLeft(bits) - BigInteger.ONE > r.second) bits--
            out += Cidr(bigToV6(start), 128 - bits)
            start += BigInteger.ONE.shiftLeft(bits)
        }
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
