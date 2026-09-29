package dev.vigil.inspector.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import java.io.BufferedReader
import java.io.IOException
import java.io.Reader
import java.time.Instant
import java.time.OffsetDateTime

/**
 * Domains, IP addresses/ranges and JA4 fingerprints taken from STIX content,
 * plus Android app indicators ([apps]: package names; [certs]: signing
 * certificate digests as `SHA1:<HEX>` / `SHA256:<HEX>`, see [AppCerts]).
 * Only the network values go into feed files; the app values are for the
 * health check.
 */
data class IndicatorValues(
    val domains: List<String> = emptyList(),
    val ips: List<String> = emptyList(),
    val ja4: List<String> = emptyList(),
    val apps: List<String> = emptyList(),
    val certs: List<String> = emptyList(),
) {
    val isEmpty: Boolean get() = domains.isEmpty() && ips.isEmpty() && ja4.isEmpty() && apps.isEmpty() && certs.isEmpty()
    val size: Int get() = domains.size + ips.size + ja4.size + apps.size + certs.size

    operator fun plus(o: IndicatorValues) = IndicatorValues(
        (domains + o.domains).distinct(), (ips + o.ips).distinct(), (ja4 + o.ja4).distinct(),
        (apps + o.apps).distinct(), (certs + o.certs).distinct(),
    )

    /** Each list cut to [max] values. */
    fun capped(max: Int) = IndicatorValues(domains.take(max), ips.take(max), ja4.take(max), apps.take(max), certs.take(max))
}

/** Android signing-certificate digests in one normal form: `SHA1:<UPPER HEX>` or `SHA256:<UPPER HEX>`. */
object AppCerts {
    const val SHA1 = "SHA1"
    const val SHA256 = "SHA256"

    /**
     * [raw] (hex, any case, with or without `:` or space separators) as
     * `ALGO:HEX`. The algorithm is taken from [algorithm] if given (`sha1`,
     * `SHA-256`, …), otherwise from the length (40 or 64 hex digits). Null
     * if it is not a digest of that algorithm.
     */
    fun normalize(raw: String, algorithm: String? = null): String? {
        val t = raw.trim()
        // Already normalised ("SHA1:ABC…"): keep its algorithm.
        val prefix = t.substringBefore(':', "").uppercase()
        if (algorithm == null && (prefix == SHA1 || prefix == SHA256)) return normalize(t.substringAfter(':'), prefix)
        val hex = t.replace(":", "").replace(" ", "").uppercase()
        if (hex.isEmpty() || !hex.all { it in '0'..'9' || it in 'A'..'F' }) return null
        val algo = when (algorithm?.lowercase()?.replace("-", "")?.replace("_", "")) {
            null -> when (hex.length) {
                40 -> SHA1
                64 -> SHA256
                else -> return null
            }
            "sha1" -> SHA1
            "sha256" -> SHA256
            else -> return null
        }
        val expected = if (algo == SHA1) 40 else 64
        return if (hex.length == expected) "$algo:$hex" else null
    }

    /** `ALGO:HEX` of the digest bytes. */
    fun of(algorithm: String, digest: ByteArray): String = "$algorithm:" + digest.joinToString("") { "%02X".format(it) }
}

/**
 * What one STIX object contributes to a feed. [id] and [version] (the
 * `modified` time in ms; 0 for objects without one, such as SCOs) identify
 * it across polls, so a newer version (e.g. a revocation) replaces an older one.
 */
data class StixItem(
    val id: String,
    val version: Long,
    val revoked: Boolean,
    /** `valid_until` in ms, or null if open-ended. */
    val validUntil: Long?,
    val values: IndicatorValues,
    val label: String?,
)

/**
 * Pragmatic STIX 2.1 pattern reader. It does not evaluate patterns; it
 * collects the constants of simple equality comparisons that name a
 * destination vigil can match:
 *
 * - `[domain-name:value = 'evil.example']` → domain (an IP address there → IP)
 * - `[ipv4-addr:value = '198.51.100.7']`, `'198.51.100.0/24'`, `[ipv6-addr:value = '…']` → IP / range
 * - `[url:value = 'https://evil.example/x']` → the URL's host (domain or IP), unless `urlHosts` is off
 *   (spyware packs list repositories such as `https://github.com/…/AndroRAT`) or the host is a shared
 *   platform ([SharedPlatforms]: `https://raw.githubusercontent.com/x/y/a.apk` must not block GitHub)
 * - `[app:id = 'com.example']` → app package; `[app:cert.sha1 = '…']`, `[app:cert.sha256 = '…']` → certificate
 * - `[network-traffic:dst_ref.value = '…']` → IP or domain
 * - `[domain-name:resolves_to_refs[*].value = '…']` → IP (MISP `domain|ip`)
 * - any compared constant that is a JA4 fingerprint, whatever the path
 *   (`[x-ja4:value = …]`, `[network-traffic:extensions.'x-ja4'.fingerprint = …]`…) → JA4
 *
 * `IN ('a', 'b')` lists are read like several `=` comparisons. Patterns with
 * `NOT` or `!=` are skipped entirely (they describe exclusions), as are
 * comparisons with other operators (`MATCHES`, `LIKE`, `<`…).
 */
object StixPattern {
    private const val STR = """'(?:[^'\\]|\\.)*'"""
    private val COMPARISON = Regex(
        """([a-z0-9][a-z0-9-]*):([A-Za-z0-9_.\-'\[\]*]+?)\s*(!=|<=|>=|=|<|>|\bNOT\s+IN\b|\bIN\b|\bMATCHES\b|\bLIKE\b|\bISSUBSET\b|\bISSUPERSET\b)\s*(\(\s*$STR(?:\s*,\s*$STR)*\s*\)|$STR)""",
    )
    private val STRING = Regex(STR)

    fun extract(pattern: String, urlHosts: Boolean = true): IndicatorValues {
        // Exclusions: a value after NOT/!= is not an indicator of compromise.
        if (Regex("""!=|\bNOT\b""").containsMatchIn(pattern.replace(Regex(STR), "''"))) return IndicatorValues()
        val domains = LinkedHashSet<String>()
        val ips = LinkedHashSet<String>()
        val ja4 = LinkedHashSet<String>()
        val apps = LinkedHashSet<String>()
        val certs = LinkedHashSet<String>()
        for (m in COMPARISON.findAll(pattern)) {
            val (type, path, op, rhs) = m.destructured
            if (op != "=" && op != "IN") continue
            for (sm in STRING.findAll(rhs)) {
                val value = unescape(sm.value.substring(1, sm.value.length - 1))
                val fp = Ja4.normalize(value)
                if (fp != null) {
                    ja4 += fp
                    continue
                }
                when {
                    // Some publishers put addresses in domain-name patterns (e.g. Amnesty's NoviSpy bundle).
                    type == "domain-name" && path == "value" ->
                        Indicators.domain(value)?.let { domains += it } ?: Indicators.ipOrCidr(value)?.let { ips += it }
                    // MISP domain|ip: [domain-name:value = 'x' AND domain-name:resolves_to_refs[*].value = 'ip']
                    type == "domain-name" && path.startsWith("resolves_to_refs") -> Indicators.ipOrCidr(value)?.let { ips += it }
                    (type == "ipv4-addr" || type == "ipv6-addr") && path == "value" -> Indicators.ipOrCidr(value)?.let { ips += it }
                    type == "url" && path == "value" && urlHosts ->
                        Indicators.urlHost(value)?.let {
                            if (Indicators.ipOrCidr(it) != null) ips += it else if (!SharedPlatforms.isShared(it)) domains += it
                        }
                    type == "network-traffic" && path.endsWith("_ref.value") ->
                        Indicators.ipOrCidr(value)?.let { ips += it } ?: Indicators.domain(value)?.let { domains += it }
                    // MVT's Android extensions: package name and signing certificate of an app.
                    type == "app" && path == "id" -> Indicators.packageName(value)?.let { apps += it }
                    type == "app" && path.startsWith("cert.") -> AppCerts.normalize(value, path.removePrefix("cert."))?.let { certs += it }
                }
            }
        }
        return IndicatorValues(domains.toList(), ips.toList(), ja4.toList(), apps.toList(), certs.toList())
    }

    private fun unescape(s: String) = s.replace("\\'", "'").replace("\\\\", "\\")
}

/** Reads STIX 2.1 objects from bundles and TAXII envelopes. */
object Stix {
    /** Maximum values taken from one object (a pattern can list thousands). */
    const val MAX_VALUES_PER_OBJECT = 1000

    /** The `objects` of a STIX bundle or a TAXII 2.1 envelope. */
    fun objects(doc: JsonObject): List<JsonObject> =
        (doc["objects"] as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }

    /**
     * The contribution of [o], or null if it cannot contribute (unsupported
     * type, non-STIX pattern language without JA4 properties, nothing
     * extractable). A revoked indicator is returned (with empty values) so
     * it can replace an earlier version.
     */
    fun item(o: JsonObject, urlHosts: Boolean = true): StixItem? {
        val type = o.str("type") ?: return null
        val id = o.str("id") ?: return null
        val version = (o.str("modified") ?: o.str("created"))?.let(::parseTime) ?: 0L
        val validUntil = o.str("valid_until")?.let(::parseTime)
        val revoked = o["revoked"]?.let { (it as? JsonPrimitive)?.booleanOrNull } == true
        var values = customJa4(o)
        when (type) {
            "indicator" -> {
                val lang = o.str("pattern_type") ?: "stix"
                if (lang.equals("stix", ignoreCase = true)) o.str("pattern")?.let { values += StixPattern.extract(it, urlHosts) }
            }
            "domain-name" -> o.str("value")?.let { v ->
                Indicators.domain(v)?.let { values += IndicatorValues(domains = listOf(it)) }
                    ?: Indicators.ipOrCidr(v)?.let { values += IndicatorValues(ips = listOf(it)) }
            }
            "ipv4-addr", "ipv6-addr" -> o.str("value")?.let(Indicators::ipOrCidr)?.let { values += IndicatorValues(ips = listOf(it)) }
            else -> if ("ja4" in type) o.str("value")?.let(Ja4::normalize)?.let { values += IndicatorValues(ja4 = listOf(it)) }
        }
        if (revoked) return StixItem(id, version, true, validUntil, IndicatorValues(), null)
        if (values.isEmpty) return null
        values = values.capped(MAX_VALUES_PER_OBJECT)
        return StixItem(id, version, false, validUntil, values, label(o, values))
    }

    /** JA4 fingerprints in custom properties such as `x_ja4` or `x_opencti_ja4` (strings or string lists). */
    private fun customJa4(o: JsonObject): IndicatorValues {
        val found = o.entries.filter { (k, _) -> "ja4" in k.lowercase() }.flatMap { (_, v) -> strings(v) }.mapNotNull(Ja4::normalize)
        return IndicatorValues(ja4 = found.distinct())
    }

    private fun strings(e: JsonElement): List<String> = when (e) {
        is JsonPrimitive -> if (e.isString) listOf(e.content) else emptyList()
        is JsonArray -> e.flatMap(::strings)
        else -> emptyList()
    }

    /** The indicator's name (unless it only repeats the value), otherwise its labels. */
    private fun label(o: JsonObject, v: IndicatorValues): String? {
        val all = v.domains + v.ips + v.ja4 + v.apps
        val name = o.str("name")?.trim()?.takeIf { n -> n.isNotEmpty() && all.none { n.equals(it, ignoreCase = true) } }
        val labels = (o["labels"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }?.joinToString(", ")
        return (name ?: labels?.takeIf { it.isNotBlank() })?.let(Ja4::cleanLabel)
    }

    private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

    /** RFC 3339 timestamp (`2024-05-01T12:00:00.000Z`, offsets allowed) in ms, or null. */
    fun parseTime(s: String): Long? =
        runCatching { Instant.parse(s).toEpochMilli() }.getOrNull()
            ?: runCatching { OffsetDateTime.parse(s).toInstant().toEpochMilli() }.getOrNull()
}

/**
 * Names from STIX relationships. MVT and Echap bundles give their indicators
 * no name or labels: the spyware's name is on a `malware` object that an
 * `indicates` relationship (source: indicator, target: malware) links to.
 * Objects may come in any order; ask [labelFor] after all were [accept]ed.
 */
class StixRelationshipLabels {
    private val names = HashMap<String, String>()
    private val indicates = HashMap<String, String>()

    fun accept(o: JsonObject) {
        val type = o.str("type") ?: return
        val id = o.str("id") ?: return
        when (type) {
            "malware", "tool", "intrusion-set", "threat-actor", "campaign" ->
                if (names.size < MAX_ENTRIES) o.str("name")?.let(Ja4::cleanLabel)?.takeIf { it.isNotEmpty() }?.let { names[id] = it }
            "relationship" -> {
                if (o.str("relationship_type") != "indicates") return
                val src = o.str("source_ref")?.takeIf { it.startsWith("indicator--") } ?: return
                val target = o.str("target_ref") ?: return
                if (indicates.size < MAX_ENTRIES) indicates.putIfAbsent(src, target)
            }
        }
    }

    /** The name of what indicator [indicatorId] indicates, or null. */
    fun labelFor(indicatorId: String): String? = indicates[indicatorId]?.let(names::get)

    private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

    private companion object {
        const val MAX_ENTRIES = 500_000
    }
}

/**
 * Streams the `objects` of a STIX bundle (or TAXII envelope) without
 * building the whole document: only one object's text is held at a time, so
 * a multi-megabyte bundle (Echap's is 4.6 MB) costs little memory.
 */
object StixStream {
    /** Objects longer than this (in characters) are skipped. */
    const val MAX_OBJECT_CHARS = 1_000_000

    class Result(val objects: Int, val skipped: Int)

    /**
     * Calls [onObject] for each JSON object in the top-level `objects` array
     * of the document read from [reader]. Objects that are too long or not
     * valid JSON are skipped and counted. Throws [IOException] if the
     * document has no `objects` array.
     */
    fun forEachObject(reader: Reader, maxObjectChars: Int = MAX_OBJECT_CHARS, onObject: (JsonObject) -> Unit): Result {
        val r = reader as? BufferedReader ?: BufferedReader(reader, 64 * 1024)
        var depth = 0
        var inString = false
        var escaped = false
        // The last string closed at depth 1; a ':' after it makes it the current key.
        val lastString = StringBuilder()
        var key: String? = null
        var sawObjects = false
        var inObjects = false
        var capture: StringBuilder? = null
        var tooLong = false
        var count = 0
        var skipped = 0
        while (true) {
            val code = r.read()
            if (code < 0) break
            val c = code.toChar()
            capture?.let { if (it.length >= maxObjectChars) tooLong = true else it.append(c) }
            if (inString) {
                when {
                    escaped -> escaped = false
                    c == '\\' -> escaped = true
                    c == '"' -> inString = false
                    depth == 1 && lastString.length < 64 -> lastString.append(c)
                }
                continue
            }
            when (c) {
                '"' -> {
                    inString = true
                    if (depth == 1) lastString.setLength(0)
                }
                ':' -> if (depth == 1) key = lastString.toString()
                ',' -> if (depth == 1) key = null
                '{', '[' -> {
                    if (depth == 1 && c == '[' && key == "objects") {
                        inObjects = true
                        sawObjects = true
                    } else if (depth == 2 && inObjects && c == '{') {
                        capture = StringBuilder().append('{')
                        tooLong = false
                    }
                    depth++
                }
                '}', ']' -> {
                    depth--
                    val text = capture
                    if (depth == 2 && c == '}' && text != null) {
                        capture = null
                        val o = if (tooLong) null else runCatching { Json.parseToJsonElement(text.toString()) as? JsonObject }.getOrNull()
                        if (o != null) {
                            count++
                            onObject(o)
                        } else {
                            skipped++
                        }
                    } else if (depth == 1 && c == ']' && inObjects) {
                        inObjects = false
                    }
                }
            }
        }
        if (!sawObjects) throw IOException("not a STIX bundle (no objects array)")
        return Result(count, skipped)
    }
}
