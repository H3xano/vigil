package dev.vigil.inspector.data

import dev.vigil.inspector.R
import dev.vigil.inspector.ui.UiText
import dev.vigil.inspector.vpn.IpLiteral
import java.io.BufferedInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.zip.GZIPInputStream

/**
 * The offline IP → ASN database (engine category `asn`): download
 * conversion, validation and display helpers.
 *
 * The built-in source is iptoasn.com's `ip2asn-combined.tsv.gz`
 * (Public Domain, PDDL 1.0): one TSV row per range,
 * `range_start range_end AS_number country_code AS_description`, IPv4 and
 * IPv6 in one file. The download is gunzipped here and the engine streams
 * the TSV from disk (see core/vigil-core/src/asn.rs).
 */
object AsnDatabase {
    /** [FeedEntity.format] of an iptoasn.com TSV, gzip-compressed or plain. */
    const val FORMAT_IPTOASN = "iptoasn_tsv"

    /** Engine feed category. */
    const val CATEGORY = "asn"

    /** A real table has hundreds of thousands of rows; fewer than this means a truncated or wrong file. */
    const val MIN_ROUTED_ROWS = 1_000

    /** Reject when more than this share of the rows is unreadable. */
    const val MAX_REJECTED_RATIO = 0.01

    /** Refresh interval (the daily feed job skips the table until it is this old). */
    const val MAX_AGE_MS = 7L * 24 * 3600 * 1000 - 4L * 3600 * 1000

    /** Upper bound of the decompressed file (the full table is ≈ 46 MB). */
    const val MAX_TSV_BYTES = 256L * 1024 * 1024

    /** Longest accepted row (real rows are under 200 bytes; AS descriptions are short). */
    const val MAX_LINE_BYTES = 4096

    data class Stats(
        /** Rows mapping a range to an AS (AS number > 0). */
        val routed: Int,
        /** Valid rows with AS 0 ("Not routed"). */
        val unrouted: Int,
        val rejected: Int,
        val asCount: Int,
    )

    /**
     * Checks one TSV row. Returns the AS number (0 for unrouted space), or
     * null if the row is malformed. Comments and blank lines are not rows.
     */
    fun parseRow(line: String): Long? {
        val f = line.split('\t')
        if (f.size < 3) return null
        val start = f[0].trim()
        val end = f[1].trim()
        val asn = f[2].trim().removePrefix("AS").removePrefix("as").toLongOrNull() ?: return null
        if (asn < 0 || asn > 0xFFFF_FFFFL) return null
        val s = IpLiteral.parseV4(start) ?: IpLiteral.parseV6(start) ?: return null
        val e = IpLiteral.parseV4(end) ?: IpLiteral.parseV6(end) ?: return null
        if (s.size != e.size || compareUnsigned(s, e) > 0) return null
        return asn
    }

    private fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val c = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (c != 0) return c
        }
        return 0
    }

    private fun isComment(line: String) = line.isBlank() || line.trimStart().startsWith('#')

    /**
     * Copies [input] (gzip or plain TSV, detected from the magic bytes) to
     * [output] as plain TSV while validating every row, and returns the
     * counts. Throws [IOException] for a corrupt or truncated gzip stream or
     * an oversized file.
     */
    fun convert(input: File, output: File): Stats = input.inputStream().use { raw -> convert(raw, output) }

    fun convert(raw: InputStream, output: File): Stats {
        val buffered = BufferedInputStream(raw, 64 * 1024)
        buffered.mark(2)
        val magic = ByteArray(2)
        val n = buffered.read(magic)
        buffered.reset()
        val gzip = n == 2 && magic[0] == 0x1f.toByte() && magic[1] == 0x8b.toByte()
        val source = if (gzip) GZIPInputStream(buffered, 64 * 1024) else buffered
        var routed = 0
        var unrouted = 0
        var rejected = 0
        val asns = HashSet<Long>()
        // Sizes are counted on the decompressed bytes as they are read, and
        // lines are capped, so a gzip bomb fails before it fills the heap.
        BoundedLineReader(source, MAX_LINE_BYTES, MAX_TSV_BYTES, "ASN table").use { reader ->
            output.bufferedWriter(Charsets.UTF_8).use { w ->
                while (true) {
                    val line = reader.readLine() ?: break
                    if (isComment(line)) continue
                    val asn = parseRow(line)
                    when {
                        asn == null -> rejected++
                        asn == 0L -> unrouted++
                        else -> {
                            routed++
                            asns += asn
                        }
                    }
                    w.write(line)
                    w.write("\n")
                }
            }
        }
        return Stats(routed, unrouted, rejected, asns.size)
    }

    /**
     * Returns null if the converted table is acceptable, otherwise the
     * reason. [previousRouted] is the routed-range count of the copy in use.
     */
    fun validate(stats: Stats, previousRouted: Int?): String? {
        val rows = stats.routed + stats.unrouted + stats.rejected
        if (rows == 0) return "the ASN table is empty"
        if (stats.rejected > rows * MAX_REJECTED_RATIO) return "${stats.rejected} of $rows rows unreadable; not an IP-to-ASN table?"
        if (stats.routed < MIN_ROUTED_ROWS) return "only ${stats.routed} routed ranges; truncated download?"
        if (previousRouted != null && previousRouted > 0 && stats.routed < previousRouted / 2) {
            return "only ${stats.routed} routed ranges (previously $previousRouted); keeping the previous copy"
        }
        return null
    }

    /**
     * A readable organisation name from an AS description. iptoasn.com uses
     * the registry handle, often followed by the organisation:
     * `GTELECOM-AS-AP Gtelecom Pty Ltd` → `Gtelecom Pty Ltd`; a bare handle
     * (`CLOUDFLARENET`, `AMAZON-02`) is kept.
     */
    fun displayName(description: String?): String? {
        val d = description?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val space = d.indexOf(' ')
        if (space <= 0) return d
        val handle = d.substring(0, space)
        val rest = d.substring(space + 1).trim()
        val looksLikeHandle = '-' in handle && handle.all { it.isUpperCase() || it.isDigit() || it == '-' || it == '_' }
        // Only strip a registry handle (with a dash) when a mixed-case name follows.
        return if (looksLikeHandle && rest.any { it.isLowerCase() }) rest else d
    }

    /**
     * Networks of a destination in the app's host list: [asns] is the
     * comma-separated list of distinct AS numbers ([DestinationUsage.asns]),
     * [name] the AS name when there is exactly one.
     */
    fun networksLabel(asns: String?, name: String?): String? {
        val numbers = asns?.split(',')?.mapNotNull { it.trim().toLongOrNull() }?.filter { it > 0 }?.distinct().orEmpty()
        return when {
            numbers.isEmpty() -> null
            numbers.size == 1 -> label(numbers[0], name)
            numbers.size <= 3 -> numbers.joinToString(", ") { "AS$it" }
            else -> numbers.take(3).joinToString(", ") { "AS$it" } + " +${numbers.size - 3}"
        }
    }

    /** "AS13335 CLOUDFLARENET"; null without an AS number. */
    fun label(number: Long?, name: String?): String? {
        if (number == null || number <= 0) return null
        return listOfNotNull("AS$number", displayName(name)).joinToString(" ")
    }
}

/** Labels for the upstream path (`via`) of a flow and the DNS upstream transport. */
object PathLabels {
    fun via(via: String?): UiText? = when (via) {
        "wireguard" -> UiText.of(R.string.activity_via_wireguard)
        "socks5" -> UiText.of(R.string.activity_via_socks5)
        "direct" -> UiText.of(R.string.activity_via_direct)
        null -> null
        else -> UiText.of(R.string.activity_via_other, via)
    }

    /** True when the flow's connection went through a tunnel or proxy. */
    fun isTunnelled(via: String?) = via != null && via != "direct"

    fun dnsUpstream(upstream: String?): String? = when (upstream) {
        "doh" -> "DoH"
        "dot" -> "DoT"
        "tcp" -> "TCP"
        "udp" -> "UDP"
        null -> null
        else -> upstream.uppercase()
    }
}
