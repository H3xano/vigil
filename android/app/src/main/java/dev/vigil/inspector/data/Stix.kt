package dev.vigil.inspector.data

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import java.time.Instant
import java.time.OffsetDateTime

/** Domains, IP addresses/ranges and JA4 fingerprints taken from STIX content. */
data class IndicatorValues(
    val domains: List<String> = emptyList(),
    val ips: List<String> = emptyList(),
    val ja4: List<String> = emptyList(),
) {
    val isEmpty: Boolean get() = domains.isEmpty() && ips.isEmpty() && ja4.isEmpty()
    val size: Int get() = domains.size + ips.size + ja4.size

    operator fun plus(o: IndicatorValues) =
        IndicatorValues((domains + o.domains).distinct(), (ips + o.ips).distinct(), (ja4 + o.ja4).distinct())
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
 * - `[domain-name:value = 'evil.example']` → domain
 * - `[ipv4-addr:value = '198.51.100.7']`, `'198.51.100.0/24'`, `[ipv6-addr:value = '…']` → IP / range
 * - `[url:value = 'https://evil.example/x']` → the URL's host (domain or IP)
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

    fun extract(pattern: String): IndicatorValues {
        // Exclusions: a value after NOT/!= is not an indicator of compromise.
        if (Regex("""!=|\bNOT\b""").containsMatchIn(pattern.replace(Regex(STR), "''"))) return IndicatorValues()
        val domains = LinkedHashSet<String>()
        val ips = LinkedHashSet<String>()
        val ja4 = LinkedHashSet<String>()
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
                    type == "domain-name" && path == "value" -> Indicators.domain(value)?.let { domains += it }
                    // MISP domain|ip: [domain-name:value = 'x' AND domain-name:resolves_to_refs[*].value = 'ip']
                    type == "domain-name" && path.startsWith("resolves_to_refs") -> Indicators.ipOrCidr(value)?.let { ips += it }
                    (type == "ipv4-addr" || type == "ipv6-addr") && path == "value" -> Indicators.ipOrCidr(value)?.let { ips += it }
                    type == "url" && path == "value" -> Indicators.urlHost(value)?.let { if (Indicators.ipOrCidr(it) != null) ips += it else domains += it }
                    type == "network-traffic" && path.endsWith("_ref.value") ->
                        Indicators.ipOrCidr(value)?.let { ips += it } ?: Indicators.domain(value)?.let { domains += it }
                }
            }
        }
        return IndicatorValues(domains.toList(), ips.toList(), ja4.toList())
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
    fun item(o: JsonObject): StixItem? {
        val type = o.str("type") ?: return null
        val id = o.str("id") ?: return null
        val version = (o.str("modified") ?: o.str("created"))?.let(::parseTime) ?: 0L
        val validUntil = o.str("valid_until")?.let(::parseTime)
        val revoked = o["revoked"]?.let { (it as? JsonPrimitive)?.booleanOrNull } == true
        var values = customJa4(o)
        when (type) {
            "indicator" -> {
                val lang = o.str("pattern_type") ?: "stix"
                if (lang.equals("stix", ignoreCase = true)) o.str("pattern")?.let { values += StixPattern.extract(it) }
            }
            "domain-name" -> o.str("value")?.let(Indicators::domain)?.let { values += IndicatorValues(domains = listOf(it)) }
            "ipv4-addr", "ipv6-addr" -> o.str("value")?.let(Indicators::ipOrCidr)?.let { values += IndicatorValues(ips = listOf(it)) }
            else -> if ("ja4" in type) o.str("value")?.let(Ja4::normalize)?.let { values += IndicatorValues(ja4 = listOf(it)) }
        }
        if (revoked) return StixItem(id, version, true, validUntil, IndicatorValues(), null)
        if (values.isEmpty) return null
        values = IndicatorValues(
            values.domains.take(MAX_VALUES_PER_OBJECT),
            values.ips.take(MAX_VALUES_PER_OBJECT),
            values.ja4.take(MAX_VALUES_PER_OBJECT),
        )
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
        val all = v.domains + v.ips + v.ja4
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
