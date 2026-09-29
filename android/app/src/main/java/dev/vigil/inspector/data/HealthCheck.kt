package dev.vigil.inspector.data

import androidx.annotation.StringRes
import dev.vigil.inspector.R
import dev.vigil.inspector.ui.UiText
import dev.vigil.inspector.vpn.IpLiteral
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/** An installed app as the health check sees it. */
@Serializable
data class InstalledApp(
    val pkg: String,
    val label: String,
    /** Signing certificates, `SHA1:<HEX>` and `SHA256:<HEX>` of each (see [AppCerts]). */
    val certs: List<String> = emptyList(),
    val system: Boolean = false,
    /** Package that installed it (e.g. `com.android.vending`), if known. */
    val installer: String? = null,
    val firstInstall: Long? = null,
)

/** One match of the health check. */
@Serializable
data class HealthFinding(
    /** [SpywareSeverity]: `indicator` (known spyware) or `warning` (monitoring app). */
    val severity: String,
    /** [HealthCheck.KIND_APP_PACKAGE], [HealthCheck.KIND_APP_CERTIFICATE] or [HealthCheck.KIND_NETWORK]. */
    val kind: String,
    /** The spyware family or app the indicator belongs to. */
    val label: String,
    val packId: String,
    val packName: String,
    val reference: String? = null,
    val license: String? = null,
    /** The app concerned: the installed app, or the app that made the connection or lookup. */
    val pkg: String? = null,
    val appLabel: String? = null,
    /** The listed indicator: package, `ALGO:HEX` certificate, domain or IP address. */
    val indicator: String,
    /** The name or address vigil recorded, when it differs from [indicator] (a subdomain). */
    val observed: String? = null,
    val firstSeen: Long? = null,
    val lastSeen: Long? = null,
    /** Connections and lookups recorded. */
    val count: Long? = null,
    /** How many of them vigil blocked. */
    val blocked: Long? = null,
)

/** State of one indicator source at the time of the check. */
@Serializable
data class HealthPackStatus(
    val feedId: String,
    val name: String,
    val enabled: Boolean,
    val downloadedAt: Long? = null,
    val lastError: String? = null,
    val license: String? = null,
    val reference: String? = null,
    val source: String? = null,
    val domains: Int = 0,
    val ips: Int = 0,
    val apps: Int = 0,
    val certs: Int = 0,
    val stale: Boolean = false,
)

@Serializable
data class HealthReport(
    val generatedAt: Long,
    val appVersion: String,
    /** [HealthCheck.VERDICT_NONE], [HealthCheck.VERDICT_WARNINGS], [HealthCheck.VERDICT_FOUND] or [HealthCheck.VERDICT_NOT_CHECKED]. */
    val verdict: String,
    val findings: List<HealthFinding>,
    val packs: List<HealthPackStatus>,
    val appsChecked: Int,
    val destinationsChecked: Int,
    /** Oldest record of the network history that was checked (null: none). */
    val historySince: Long? = null,
    val retentionDays: Int,
    val inspectionRunning: Boolean,
    /** Limitations of this check (stale packs, inspection off, short history), in the app's language. */
    val notes: List<String> = emptyList(),
    /** [HealthCheck.GUIDANCE] in the app's language. */
    val guidance: List<String> = emptyList(),
)

/**
 * The spyware health check: compares installed apps (package names and
 * signing certificates) and the recorded network history (DNS lookups,
 * connections and learned destinations, blocked ones included) with the
 * downloaded spyware packs. Pure and offline; the caller gathers the inputs.
 */
object HealthCheck {
    const val KIND_APP_PACKAGE = "app_package"
    const val KIND_APP_CERTIFICATE = "app_certificate"
    const val KIND_NETWORK = "network"

    const val VERDICT_NONE = "no_known_indicators"
    const val VERDICT_WARNINGS = "warnings"
    const val VERDICT_FOUND = "indicators_found"
    const val VERDICT_NOT_CHECKED = "not_checked"

    /** A pack not updated for this long is reported as out of date. */
    const val STALE_MS = 8L * 24 * 3600 * 1000

    const val ACCESS_NOW = "https://www.accessnow.org/help/"
    const val STOP_STALKERWARE = "https://stopstalkerware.org/"

    val GUIDANCE: List<UiText> = listOf(
        UiText.of(R.string.health_guidance_safety),
        UiText.of(R.string.health_guidance_help, ACCESS_NOW, STOP_STALKERWARE),
        UiText.of(R.string.health_guidance_keep),
        UiText.of(R.string.health_guidance_warnings),
        UiText.of(R.string.health_guidance_limits),
    )

    class Input(
        val now: Long,
        val appVersion: String,
        /** Spyware feeds with their downloaded pack (null if off or not downloaded). */
        val packs: List<Pair<FeedEntity, SpywarePack?>>,
        val apps: List<InstalledApp>,
        /** Names and addresses from the history (any mix of DNS, connections and learned destinations). */
        val observed: List<ObservedName>,
        val historySince: Long?,
        val retentionDays: Int,
        val inspectionRunning: Boolean,
        /** App labels for packages of the network history (default: the package). */
        val appLabel: (String) -> String = { it },
        /** Resolves the report's notes and guidance in the app's language (the report is exported as is). */
        val text: (UiText) -> String,
    )

    private class Ref(val group: SpywareGroup, val pack: SpywarePack)

    fun run(input: Input): HealthReport {
        val loaded = input.packs.mapNotNull { (f, p) -> p?.takeIf { f.enabled } }
        val byApp = HashMap<String, MutableList<Ref>>()
        val byCert = HashMap<String, MutableList<Ref>>()
        val byDomain = HashMap<String, MutableList<Ref>>()
        val byIp = HashMap<String, MutableList<Ref>>()
        val cidrs = ArrayList<Pair<Cidr4, Ref>>()
        for (p in loaded) for (g in p.groups) {
            val ref = Ref(g, p)
            g.apps.forEach { byApp.getOrPut(it.lowercase()) { ArrayList() } += ref }
            g.certs.forEach { byCert.getOrPut(it) { ArrayList() } += ref }
            g.domains.forEach { byDomain.getOrPut(it) { ArrayList() } += ref }
            for (ip in g.ips) {
                val c = if ('/' in ip) Cidr4.parse(ip) else null
                if (c != null) cidrs += c to ref else byIp.getOrPut(ip.lowercase()) { ArrayList() } += ref
            }
        }

        val findings = LinkedHashMap<String, HealthFinding>()
        fun add(key: String, f: HealthFinding) {
            val old = findings[key]
            findings[key] = if (old == null) {
                f
            } else {
                old.copy(
                    firstSeen = minOfNullable(old.firstSeen, f.firstSeen), lastSeen = maxOfNullable(old.lastSeen, f.lastSeen),
                    count = sumNullable(old.count, f.count), blocked = sumNullable(old.blocked, f.blocked),
                    observed = old.observed ?: f.observed,
                )
            }
        }

        for (app in input.apps) {
            for (r in byApp[app.pkg.lowercase()].orEmpty()) {
                add(
                    "a|${app.pkg}|${r.group.label}|${r.group.severity}",
                    finding(r, KIND_APP_PACKAGE, app.pkg).copy(pkg = app.pkg, appLabel = app.label, firstSeen = app.firstInstall),
                )
            }
            for (cert in app.certs) for (r in byCert[cert].orEmpty()) {
                add(
                    "c|${app.pkg}|$cert|${r.group.label}|${r.group.severity}",
                    finding(r, KIND_APP_CERTIFICATE, cert).copy(pkg = app.pkg, appLabel = app.label, firstSeen = app.firstInstall),
                )
            }
        }

        val names = HashSet<String>()
        for (o in input.observed) {
            val name = o.name.trim().lowercase().removeSuffix(".")
            if (name.isEmpty()) continue
            names += name
            val hits: List<Pair<String, Ref>> = if (IpLiteral.isV4(name) || IpLiteral.isV6(name)) {
                byIp[name].orEmpty().map { name to it } +
                    (Cidr4.address(name)?.let { a -> cidrs.filter { it.first.contains(a) }.map { it.first.text to it.second } } ?: emptyList())
            } else {
                suffixes(name).flatMap { s -> byDomain[s].orEmpty().map { s to it } }
            }
            for ((indicator, r) in hits) {
                add(
                    "n|${o.pkg}|$indicator|${r.group.label}|${r.group.severity}",
                    finding(r, KIND_NETWORK, indicator).copy(
                        pkg = o.pkg, appLabel = input.appLabel(o.pkg), observed = name.takeIf { it != indicator },
                        firstSeen = o.firstSeen, lastSeen = o.lastSeen, count = o.count, blocked = o.blocked,
                    ),
                )
            }
        }

        val packs = input.packs.map { (f, p) ->
            HealthPackStatus(
                feedId = f.id, name = f.name, enabled = f.enabled, downloadedAt = p?.downloadedAt ?: f.lastUpdated, lastError = f.lastError,
                license = p?.license, reference = p?.reference, source = f.url,
                domains = p?.domainCount ?: 0, ips = p?.ipCount ?: 0, apps = p?.appCount ?: 0, certs = p?.certCount ?: 0,
                stale = f.enabled && p != null && input.now - p.downloadedAt > STALE_MS,
            )
        }
        val sorted = findings.values.sortedWith(
            compareBy<HealthFinding> { if (it.severity == SpywareSeverity.INDICATOR) 0 else 1 }
                .thenBy { it.kind != KIND_APP_PACKAGE && it.kind != KIND_APP_CERTIFICATE }
                .thenBy { it.label.lowercase() }
                .thenByDescending { it.lastSeen ?: 0 },
        )
        val verdict = when {
            sorted.any { it.severity == SpywareSeverity.INDICATOR } -> VERDICT_FOUND
            sorted.isNotEmpty() -> VERDICT_WARNINGS
            loaded.isEmpty() -> VERDICT_NOT_CHECKED
            else -> VERDICT_NONE
        }
        return HealthReport(
            generatedAt = input.now, appVersion = input.appVersion, verdict = verdict, findings = sorted, packs = packs,
            appsChecked = input.apps.size, destinationsChecked = names.size, historySince = input.historySince,
            retentionDays = input.retentionDays, inspectionRunning = input.inspectionRunning,
            notes = notes(input, packs, loaded.isEmpty()).map(input.text),
            guidance = GUIDANCE.map(input.text),
        )
    }

    /** Limitations of a check. */
    fun notes(input: Input, packs: List<HealthPackStatus>, nothingLoaded: Boolean): List<UiText> {
        val out = ArrayList<UiText>()
        if (nothingLoaded) out += UiText.of(R.string.health_note_nothing_loaded)
        val stale = packs.filter { it.stale }
        if (stale.isNotEmpty()) out += UiText.of(R.string.health_note_stale, stale.joinToString(", ") { it.name })
        val failing = packs.filter { it.enabled && it.lastError != null }
        if (failing.isNotEmpty()) out += UiText.of(R.string.health_note_failed, failing.joinToString(", ") { it.name })
        val missing = packs.filter { it.enabled && it.downloadedAt == null }
        if (missing.isNotEmpty() && !nothingLoaded) out += UiText.of(R.string.health_note_missing, missing.joinToString(", ") { it.name })
        if (!input.inspectionRunning) out += UiText.of(R.string.health_note_inspection_off)
        out += if (input.historySince == null) {
            UiText.of(R.string.health_note_no_history)
        } else {
            UiText.plural(R.plurals.health_note_history, input.retentionDays, formatTime(input.historySince), input.retentionDays)
        }
        return out
    }

    private fun finding(r: Ref, kind: String, indicator: String) = HealthFinding(
        severity = r.group.severity, kind = kind, label = r.group.label, packId = r.pack.feedId, packName = r.pack.name,
        reference = r.pack.reference, license = r.pack.license, indicator = indicator,
    )

    /** [name] and its parent domains, down to two labels ("a.b.example.com" → …, "example.com"). */
    fun suffixes(name: String): List<String> {
        val out = ArrayList<String>()
        var s = name
        while (s.count { it == '.' } >= 1) {
            out += s
            s = s.substringAfter('.')
        }
        return out
    }

    private fun minOfNullable(a: Long?, b: Long?) = if (a == null) b else if (b == null) a else minOf(a, b)
    private fun maxOfNullable(a: Long?, b: Long?) = if (a == null) b else if (b == null) a else maxOf(a, b)
    private fun sumNullable(a: Long?, b: Long?) = if (a == null) b else if (b == null) a else a + b

    /** An IPv4 range for matching the rare CIDR indicators. */
    class Cidr4(val text: String, private val base: Long, private val mask: Long) {
        fun contains(address: Long) = (address and mask) == base

        companion object {
            fun address(s: String): Long? {
                if (!IpLiteral.isV4(s)) return null
                return s.split('.').fold(0L) { acc, p -> (acc shl 8) or (p.toLongOrNull() ?: return null) }
            }

            fun parse(s: String): Cidr4? {
                val a = address(s.substringBefore('/')) ?: return null
                val bits = s.substringAfter('/').toIntOrNull()?.takeIf { it in 0..32 } ?: return null
                val mask = if (bits == 0) 0L else (0xFFFFFFFFL shl (32 - bits)) and 0xFFFFFFFFL
                return Cidr4(s, a and mask, mask)
            }
        }
    }

    // --- Report export -----------------------------------------------------------------------------

    private val json = Json { prettyPrint = true; encodeDefaults = true }

    fun toJson(report: HealthReport): String = json.encodeToString(HealthReport.serializer(), report)

    @StringRes
    fun verdictTitle(verdict: String): Int = when (verdict) {
        VERDICT_FOUND -> R.string.health_verdict_found
        VERDICT_WARNINGS -> R.string.health_verdict_warnings
        VERDICT_NOT_CHECKED -> R.string.health_verdict_not_checked
        else -> R.string.health_verdict_none
    }

    fun verdictSummary(r: HealthReport): UiText {
        val indicators = r.findings.count { it.severity == SpywareSeverity.INDICATOR }
        val warnings = r.findings.size - indicators
        return when (r.verdict) {
            VERDICT_FOUND -> if (warnings > 0) {
                UiText.plural(R.plurals.health_summary_found_warnings, indicators, indicators, UiText.plural(R.plurals.health_summary_warnings, warnings, warnings))
            } else {
                UiText.plural(R.plurals.health_summary_found, indicators, indicators)
            }
            VERDICT_WARNINGS -> UiText.plural(R.plurals.health_summary_monitoring, warnings, warnings)
            VERDICT_NOT_CHECKED -> UiText.of(R.string.health_summary_not_checked)
            else -> UiText.of(
                R.string.health_summary_none,
                UiText.plural(R.plurals.health_summary_apps, r.appsChecked, r.appsChecked),
                UiText.plural(R.plurals.health_summary_destinations, r.destinationsChecked, r.destinationsChecked),
            )
        }
    }

    @StringRes
    fun kindTitle(kind: String): Int = when (kind) {
        KIND_APP_PACKAGE -> R.string.health_kind_app_package
        KIND_APP_CERTIFICATE -> R.string.health_kind_app_certificate
        else -> R.string.health_kind_network
    }

    /** A plain-text report for sharing, in the language of [text]. */
    fun toText(r: HealthReport, text: (UiText) -> String): String = buildString {
        fun t(@StringRes id: Int, vararg args: Any) = text(UiText.of(id, *args))
        fun count(id: Int, n: Long) = text(UiText.plural(id, n.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), n))
        appendLine(t(R.string.health_report_title))
        appendLine(t(R.string.health_report_generated, formatTime(r.generatedAt), r.appVersion))
        appendLine()
        appendLine(t(R.string.health_report_result, text(UiText.of(verdictTitle(r.verdict)))))
        appendLine(text(verdictSummary(r)))
        appendLine()
        if (r.findings.isNotEmpty()) {
            appendLine(t(R.string.health_heading_findings))
            for (f in r.findings) {
                val severity = t(if (f.severity == SpywareSeverity.INDICATOR) R.string.health_report_severity_indicator else R.string.health_report_severity_warning)
                appendLine("- " + t(R.string.health_report_finding, severity, f.label, t(kindTitle(f.kind))))
                f.pkg?.let { appendLine("  " + t(R.string.health_finding_app, f.appLabel ?: it, it)) }
                appendLine(
                    "  " + if (f.observed != null) t(R.string.health_finding_indicator_seen_as, f.indicator, f.observed)
                    else t(R.string.health_finding_indicator, f.indicator),
                )
                if (f.kind == KIND_NETWORK) {
                    val seen = listOfNotNull(
                        count(R.plurals.health_report_seen, f.count ?: 0),
                        f.blocked?.takeIf { it > 0 }?.let { count(R.plurals.health_report_blocked, it) },
                        f.firstSeen?.let { t(R.string.health_finding_first, formatTime(it)) },
                        f.lastSeen?.let { t(R.string.health_finding_last, formatTime(it)) },
                    )
                    appendLine("  " + seen.joinToString(", "))
                } else {
                    f.firstSeen?.let { appendLine("  " + t(R.string.health_report_installed, formatTime(it))) }
                }
                appendLine(
                    "  " + if (f.license != null) t(R.string.health_report_source_license, f.packName, f.license)
                    else t(R.string.health_report_source, f.packName),
                )
                f.reference?.let { appendLine("  " + t(R.string.health_report_reference, it)) }
            }
            appendLine()
        }
        appendLine(t(R.string.health_heading_checked))
        appendLine("- " + text(UiText.plural(R.plurals.health_checked_apps, r.appsChecked, r.appsChecked)))
        appendLine("- " + text(UiText.plural(R.plurals.health_checked_destinations, r.destinationsChecked, r.destinationsChecked)))
        for (n in r.notes) appendLine("- $n")
        appendLine()
        appendLine(t(R.string.health_report_packs))
        for (p in r.packs) {
            val state = when {
                !p.enabled -> t(R.string.health_report_pack_off)
                p.downloadedAt == null -> t(R.string.health_report_pack_not_downloaded)
                else -> t(if (p.stale) R.string.health_report_pack_updated_stale else R.string.health_report_pack_updated, formatTime(p.downloadedAt))
            }
            val counts = listOf(
                p.domains to R.plurals.health_report_count_domains, p.ips to R.plurals.health_report_count_ips,
                p.apps to R.plurals.health_report_count_apps, p.certs to R.plurals.health_report_count_certs,
            ).filter { it.first > 0 }.joinToString(", ") { count(it.second, it.first.toLong()) }
            val details = listOfNotNull(state, counts.ifEmpty { null }, p.license?.let { t(R.string.health_report_license, it) })
            appendLine("- " + t(R.string.health_report_pack, p.name, details.joinToString("; ")))
        }
        appendLine()
        appendLine(t(R.string.health_report_guidance))
        for (g in r.guidance) appendLine("- $g")
    }

    /** UTC, so a report reads the same wherever it is opened. */
    fun formatTime(ms: Long): String = SimpleDateFormat("yyyy-MM-dd HH:mm 'UTC'", Locale.US)
        .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(ms))
}
