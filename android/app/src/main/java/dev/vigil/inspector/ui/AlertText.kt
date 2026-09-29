package dev.vigil.inspector.ui

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalConfiguration
import dev.vigil.inspector.R
import dev.vigil.inspector.data.AlertEntity
import dev.vigil.inspector.data.AsnDatabase
import dev.vigil.inspector.engine.EngineJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

/**
 * The title and sentence shown for an alert, in the app's language.
 *
 * Alerts are stored (and exported) with an English `message` written by the
 * engine or the app's detectors. For display, [message] rebuilds that
 * sentence from the kind, target, app label and `detail` (docs/EVENTS.md)
 * with string resources; in English the result equals the stored message.
 * Unknown kinds, and details that lack what the sentence needs (alerts from
 * older versions), fall back to the stored message as it is.
 */
object AlertText {
    /** The alert kinds with a translated title; others show the kind itself. */
    @StringRes
    fun titleRes(kind: String): Int? = when (kind) {
        "threat_domain" -> R.string.alert_title_threat_domain
        "threat_ip" -> R.string.alert_title_threat_ip
        "threat_ja4" -> R.string.alert_title_threat_ja4
        "beacon" -> R.string.alert_title_beacon
        "exfil_volume" -> R.string.alert_title_exfil_volume
        "encrypted_dns" -> R.string.alert_title_encrypted_dns
        "hardcoded_dns" -> R.string.alert_title_hardcoded_dns
        "new_destination" -> R.string.alert_title_new_destination
        "new_asn" -> R.string.alert_title_new_asn
        else -> null
    }

    /** Lower-case title ("periodic beaconing"), for use inside other text. */
    fun title(kind: String): UiText = titleRes(kind)?.let { UiText.of(it) } ?: UiText.Raw(kind.replace('_', ' '))

    fun message(a: AlertEntity, appLabel: String): UiText = message(a.kind, a.target, appLabel, a.message, a.detail)

    fun message(kind: String, target: String, appLabel: String, stored: String, detail: String): UiText {
        val d = parse(detail) ?: return UiText.Raw(stored)
        val spyware = d["spyware"] as? JsonObject
        val spyLabel = spyware?.str("label")
        val spyPack = spyware?.str("pack")
        val base = if (spyLabel != null && spyPack != null) stored.substringBefore(SPYWARE_SUFFIX) else stored
        val text = sentence(kind, target, appLabel, base, d) ?: return UiText.Raw(stored)
        return if (spyLabel != null && spyPack != null) UiText.of(R.string.alert_msg_with_spyware, text, spyLabel, spyPack) else text
    }

    private fun sentence(kind: String, target: String, appLabel: String, stored: String, d: JsonObject): UiText? = when (kind) {
        "threat_domain", "threat_ip" -> {
            // The matched feed entry is only in the message ("… listed by feed:<id> (<entry>)").
            val listedBy = LISTED_BY.find(stored)?.groupValues?.get(1)
            when {
                listedBy == null -> null
                kind == "threat_domain" && "qtype" in d -> UiText.of(R.string.alert_msg_threat_domain_lookup, target, listedBy)
                kind == "threat_ip" && "qname" in d -> d.str("dst")?.let { UiText.of(R.string.alert_msg_threat_ip_dns, it, listedBy) }
                else -> UiText.of(R.string.alert_msg_threat_connection, target, listedBy)
            }
        }
        "threat_ja4" -> {
            val ja4 = d.str("ja4")
            val feed = d.str("feed")
            val dest = d.str("domain") ?: d.str("dst")
            val label = d.str("label")
            val blocked = (d["blocked"] as? JsonPrimitive)?.booleanOrNull ?: false
            when {
                ja4 == null || feed == null || dest == null -> null
                label != null -> UiText.of(
                    if (blocked) R.string.alert_msg_threat_ja4_blocked else R.string.alert_msg_threat_ja4, label, ja4, feed, dest,
                )
                else -> UiText.of(
                    if (blocked) R.string.alert_msg_threat_ja4_unlabeled_blocked else R.string.alert_msg_threat_ja4_unlabeled, ja4, feed, dest,
                )
            }
        }
        "beacon" -> {
            val interval = d.num("interval_s")
            val jitter = d.num("jitter")
            when {
                interval == null || jitter == null -> null
                d.str("kind") == "intra_flow" -> d.long("burst_bytes")?.let { burst ->
                    UiText.plural(R.plurals.alert_msg_beacon_intra_flow, quantity(burst), burst, interval, jitter * 100, target)
                }
                else -> UiText.of(R.string.alert_msg_beacon_connections, target, interval, jitter * 100)
            }
        }
        "encrypted_dns" -> UiText.of(R.string.alert_msg_encrypted_dns, target)
        // The server with its port is only in the message; the target is the address alone.
        "hardcoded_dns" -> HARDCODED_SERVER.find(stored)?.groupValues?.get(1)?.let { UiText.of(R.string.alert_msg_hardcoded_dns, it) }
        "new_destination" -> UiText.of(R.string.alert_msg_new_destination, appLabel, d.str("destination") ?: target)
        "new_asn" -> d.str("destination")?.let { where ->
            val name = AsnDatabase.displayName(d.str("as_name"))
            if (name != null) {
                UiText.of(R.string.alert_msg_new_asn_named, appLabel, target, name, where)
            } else {
                UiText.of(R.string.alert_msg_new_asn, appLabel, target, where)
            }
        }
        "exfil_volume" -> exfil(appLabel, d)
        else -> null
    }

    private fun exfil(appLabel: String, d: JsonObject): UiText? {
        val uploaded = d.long("uploaded_bytes") ?: return null
        val dest = d.str("destination") ?: return null
        val tx = d.long("dest_tx_bytes") ?: return null
        val rx = d.long("dest_rx_bytes") ?: return null
        val hour = when (d.long("window_s") ?: return null) {
            3600L -> true
            300L -> false
            else -> return null
        }
        val id = when (d.str("background")) {
            "yes" -> if (hour) R.string.alert_msg_exfil_hour_background else R.string.alert_msg_exfil_5min_background
            "unknown" -> if (hour) R.string.alert_msg_exfil_hour_unknown else R.string.alert_msg_exfil_5min_unknown
            else -> return null
        }
        val main = UiText.of(id, appLabel, formatBytes(uploaded), dest, formatBytes(tx), formatBytes(rx))
        val base = d.long("baseline_bytes_per_hour")
        return if (base != null) {
            UiText.of(R.string.alert_msg_exfil_with_baseline, main, formatBytes(base))
        } else {
            UiText.of(R.string.alert_msg_exfil_no_baseline, main)
        }
    }

    private fun quantity(n: Long): Int = n.coerceIn(0, Int.MAX_VALUE.toLong()).toInt()

    private const val SPYWARE_SUFFIX = ". Spyware indicator: "
    private val LISTED_BY = Regex(""": listed by (.+)$""")
    private val HARDCODED_SERVER = Regex("""queries (\S+) directly$""")
}

/** The alert's title with a capital first letter, for lists and filters. */
@Composable
fun alertTitle(kind: String): String {
    val locale = LocalConfiguration.current.locales[0]
    return AlertText.title(kind).asString().replaceFirstChar { it.titlecase(locale) }
}

private fun parse(detail: String): JsonObject? =
    runCatching { EngineJson.json.parseToJsonElement(detail) as? JsonObject }.getOrNull()

private fun JsonObject.prim(key: String): JsonPrimitive? = this[key] as? JsonPrimitive
private fun JsonObject.str(key: String): String? = prim(key)?.takeIf { it.isString }?.content
private fun JsonObject.num(key: String): Double? = prim(key)?.doubleOrNull
private fun JsonObject.long(key: String): Long? = prim(key)?.longOrNull
