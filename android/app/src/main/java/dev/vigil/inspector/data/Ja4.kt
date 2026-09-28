package dev.vigil.inspector.data

import dev.vigil.inspector.vpn.IpLiteral
import java.io.File

/**
 * JA4 fingerprint validation, mirroring `intel::parse_ja4` in the engine
 * (core/vigil-core/src/intel.rs), and feed-line formatting.
 */
object Ja4 {
    private val VERSIONS = setOf("13", "12", "11", "10", "s3", "s2", "d1", "d2", "d3", "00")
    const val MAX_LABEL = 80

    /**
     * The normalised fingerprint (`a_b_c`, or `a_b_*` for a wildcard `c`
     * section) or null if [raw] is not a JA4 fingerprint. Case is normalised
     * except for the two ALPN characters.
     */
    fun normalize(raw: String): String? {
        val s = raw.trim()
        if (s.any { it.code >= 128 }) return null
        val wildcard = s.length == 25 && s.endsWith("_*")
        if (!(s.length == 36 || wildcard) || s[10] != '_' || s[23] != '_') return null
        val a = s.substring(0, 8).lowercase() + s.substring(8, 10)
        val b = s.substring(11, 23).lowercase()
        val c = if (wildcard) "*" else s.substring(24).lowercase()
        val ok = a[0] in "tqd" && a.substring(1, 3) in VERSIONS && a[3] in "di" &&
            a.substring(4, 8).all { it in '0'..'9' } && a.substring(8, 10).all { it.isLetterOrDigit() } &&
            b.isHex() && (wildcard || c.isHex())
        return if (ok) "${a}_${b}_$c" else null
    }

    fun isValid(raw: String) = normalize(raw) != null

    private fun String.isHex() = all { it in '0'..'9' || it in 'a'..'f' }

    /** One feed line: the fingerprint, two spaces and a single-line label. */
    fun line(ja4: String, label: String?): String {
        val l = label?.let(::cleanLabel)
        return if (l.isNullOrEmpty()) ja4 else "$ja4  $l"
    }

    /** Labels are single-line and at most [MAX_LABEL] characters. */
    fun cleanLabel(label: String): String =
        label.map { if (it.isISOControl()) ' ' else it }.joinToString("").replace(Regex("\\s+"), " ").trim().take(MAX_LABEL).trim()
}

/** Validation of plain indicators written into feed files. */
object Indicators {
    private val DOMAIN = Regex("^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\\.)+[a-z0-9-]{2,63}$")

    /** Lower-cased domain name (trailing dot and `*.` removed) or null. */
    fun domain(raw: String): String? {
        val d = raw.trim().lowercase().removePrefix("*.").removeSuffix(".")
        return d.takeIf { DOMAIN.matches(it) && !IpLiteral.isV4(it) }
    }

    /** IPv4/IPv6 address or CIDR range in canonical input form, or null. */
    fun ipOrCidr(raw: String): String? {
        val s = raw.trim()
        val slash = s.indexOf('/')
        val addr = if (slash < 0) s else s.substring(0, slash)
        val prefix = if (slash < 0) null else s.substring(slash + 1).toIntOrNull() ?: return null
        return when {
            IpLiteral.isV4(addr) -> s.takeIf { prefix == null || prefix in 0..32 }
            IpLiteral.isV6(addr) -> s.lowercase().takeIf { prefix == null || prefix in 0..128 }
            else -> null
        }
    }

    private val PACKAGE = Regex("^[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+$")

    /**
     * An Android package name (as listed by indicator sources; case kept,
     * hyphens tolerated because some sources list them), or null.
     */
    fun packageName(raw: String): String? = raw.trim().takeIf { it.length <= 255 && PACKAGE.matches(it) }

    /** Host of a URL (`scheme://host[:port]/…`): a domain or IP address, or null. */
    fun urlHost(url: String): String? {
        val m = Regex("^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/?#@]*@)?(\\[[0-9a-fA-F:.]+]|[^/?#:]+)").find(url.trim()) ?: return null
        val host = m.groupValues[1].removePrefix("[").removeSuffix("]")
        return ipOrCidr(host)?.takeIf { '/' !in it } ?: domain(host)
    }
}

/**
 * Converters for published JA4 lists that are not in vigil's line format.
 * They run at download time (see [FeedRepository]) and write the line
 * format: one fingerprint per line with an optional label.
 */
object Ja4Converters {
    const val FORMAT_TEXT = "text"

    /** FoxIO `ja4plus-mapping.csv` (github.com/FoxIO-LLC/ja4), malware and C2 tooling rows only. */
    const val FORMAT_FOXIO_MAPPING = "foxio_mapping_csv"

    /**
     * Application names treated as malicious in the FoxIO mapping. The file
     * mixes browsers, libraries and devices with malware; only these rows
     * become entries. Matched as whole words, case-insensitively.
     */
    private val MALICIOUS = Regex(
        "\\b(sliver|cobalt ?strike|icedid|qakbot|qbot|pikabot|darkgate|lumma|havoc|metasploit|meterpreter|brute ?ratel|" +
            "mythic|asyncrat|remcos|njrat|emotet|trickbot|bumblebee|c2)\\b",
        RegexOption.IGNORE_CASE,
    )

    fun needsConversion(format: String) = format != FORMAT_TEXT

    /** Converts [input] (format [format]) into a line-format file [output]. */
    fun convert(format: String, input: File, output: File) {
        val lines = when (format) {
            FORMAT_FOXIO_MAPPING -> foxioMapping(input.readText())
            else -> throw java.io.IOException("unknown feed format $format")
        }
        output.bufferedWriter().use { w ->
            w.write("# converted by vigil from format $format\n")
            for (l in lines) w.write(l + "\n")
        }
    }

    /**
     * Rows of the FoxIO mapping whose Application names malware or C2
     * tooling and that carry a valid `ja4`; the label is the application
     * (plus the notes, if any).
     */
    fun foxioMapping(csv: String): List<String> {
        val rows = Csv.parse(csv)
        val header = rows.firstOrNull()?.map { it.trim().lowercase() } ?: return emptyList()
        val app = header.indexOf("application")
        val ja4 = header.indexOf("ja4")
        val notes = header.indexOf("notes")
        if (app < 0 || ja4 < 0) throw java.io.IOException("not a JA4+ mapping file (no Application/ja4 columns)")
        val out = LinkedHashMap<String, String>()
        for (r in rows.drop(1)) {
            val name = r.getOrNull(app)?.trim().orEmpty()
            val fp = r.getOrNull(ja4)?.let(Ja4::normalize) ?: continue
            if (!MALICIOUS.containsMatchIn(name)) continue
            val note = r.getOrNull(notes)?.trim().orEmpty()
            out.putIfAbsent(fp, if (note.isEmpty()) name else "$name ($note)")
        }
        return out.map { (fp, label) -> Ja4.line(fp, label) }
    }
}

/** Minimal RFC 4180 CSV reader (quoted fields, doubled quotes, CRLF). */
object Csv {
    fun parse(text: String): List<List<String>> {
        val rows = ArrayList<List<String>>()
        var row = ArrayList<String>()
        val field = StringBuilder()
        var quoted = false
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (quoted) {
                if (c == '"') {
                    if (i + 1 < text.length && text[i + 1] == '"') {
                        field.append('"')
                        i++
                    } else {
                        quoted = false
                    }
                } else {
                    field.append(c)
                }
            } else {
                when (c) {
                    '"' -> quoted = true
                    ',' -> { row.add(field.toString()); field.clear() }
                    '\r' -> {}
                    '\n' -> { row.add(field.toString()); field.clear(); rows.add(row); row = ArrayList() }
                    else -> field.append(c)
                }
            }
            i++
        }
        if (field.isNotEmpty() || row.isNotEmpty()) {
            row.add(field.toString())
            rows.add(row)
        }
        return rows
    }
}
