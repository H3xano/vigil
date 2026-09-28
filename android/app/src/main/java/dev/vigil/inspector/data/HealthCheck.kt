package dev.vigil.inspector.data

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
    /** Limitations of this check (stale packs, inspection off, short history). */
    val notes: List<String> = emptyList(),
    val guidance: List<String> = HealthCheck.GUIDANCE,
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

    val GUIDANCE = listOf(
        "If you think someone may be monitoring you, think about your safety before acting. Removing an app, resetting " +
            "the phone or confronting someone can alert the person who installed it. Do not uninstall anything right away.",
        "Get help from people who do this every day. Access Now's Digital Security Helpline ($ACCESS_NOW) supports " +
            "journalists, activists and other people at risk, free of charge. The Coalition Against Stalkerware " +
            "($STOP_STALKERWARE) lists support services for people facing stalking or domestic abuse.",
        "Keep this report (Export) and share it only with someone you trust; it records what was found and when.",
        "A warning about a monitoring app is not necessarily a problem: if you installed it yourself or know why it is " +
            "there (for example a parental-control app you manage), it is expected.",
        "No known indicators is not proof that the device is safe. The packs only cover spyware that researchers have " +
            "documented, and vigil only checks the network activity it recorded while inspecting.",
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
            notes = notes(input, packs, loaded.isEmpty()),
        )
    }

    private fun notes(input: Input, packs: List<HealthPackStatus>, nothingLoaded: Boolean): List<String> {
        val out = ArrayList<String>()
        if (nothingLoaded) {
            out += "No spyware packs are downloaded yet, so nothing could be compared. Turn them on under Threat intelligence " +
                "(Spyware & stalkerware) and update the feeds, then run the check again."
        }
        val stale = packs.filter { it.stale }
        if (stale.isNotEmpty()) out += "Out of date (not updated for over a week): ${stale.joinToString(", ") { it.name }}."
        val failing = packs.filter { it.enabled && it.lastError != null }
        if (failing.isNotEmpty()) out += "Last update failed: ${failing.joinToString(", ") { it.name }}."
        val missing = packs.filter { it.enabled && it.downloadedAt == null }
        if (missing.isNotEmpty() && !nothingLoaded) out += "Not downloaded yet: ${missing.joinToString(", ") { it.name }}."
        if (!input.inspectionRunning) {
            out += "Inspection is off, so vigil is not recording network activity right now; only the recorded history was checked."
        }
        out += if (input.historySince == null) {
            "There is no recorded network history, so only the installed apps were checked."
        } else {
            "Network history checked from ${formatTime(input.historySince)} (history is kept ${input.retentionDays} days; " +
                "learned destinations up to 90 days)."
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

    fun verdictTitle(verdict: String) = when (verdict) {
        VERDICT_FOUND -> "Indicators found"
        VERDICT_WARNINGS -> "Warnings"
        VERDICT_NOT_CHECKED -> "Not checked"
        else -> "No known indicators"
    }

    fun verdictSummary(r: HealthReport): String {
        val indicators = r.findings.count { it.severity == SpywareSeverity.INDICATOR }
        val warnings = r.findings.size - indicators
        return when (r.verdict) {
            VERDICT_FOUND -> "$indicators ${plural(indicators, "match", "matches")} with known spyware or stalkerware indicators" +
                (if (warnings > 0) ", and $warnings ${plural(warnings, "warning", "warnings")}" else "") + ". Read the guidance below before acting."
            VERDICT_WARNINGS -> "No known spyware found, but $warnings ${plural(warnings, "sign", "signs")} of monitoring apps that deserve a look."
            VERDICT_NOT_CHECKED -> "No spyware packs are downloaded, so nothing could be compared."
            else -> "None of the ${r.appsChecked} installed apps and ${r.destinationsChecked} recorded destinations match the downloaded packs."
        }
    }

    private fun plural(n: Int, one: String, many: String) = if (n == 1) one else many

    fun kindTitle(kind: String) = when (kind) {
        KIND_APP_PACKAGE -> "Installed app"
        KIND_APP_CERTIFICATE -> "App signing certificate"
        else -> "Network activity"
    }

    /** A plain-text report for sharing. */
    fun toText(r: HealthReport): String = buildString {
        appendLine("vigil health check report")
        appendLine("Generated: ${formatTime(r.generatedAt)} (vigil ${r.appVersion})")
        appendLine()
        appendLine("Result: ${verdictTitle(r.verdict)}")
        appendLine(verdictSummary(r))
        appendLine()
        if (r.findings.isNotEmpty()) {
            appendLine("Findings")
            for (f in r.findings) {
                appendLine("- [${if (f.severity == SpywareSeverity.INDICATOR) "indicator" else "warning"}] ${f.label}: ${kindTitle(f.kind)}")
                f.pkg?.let { appendLine("  App: ${f.appLabel ?: it} ($it)") }
                appendLine("  Indicator: ${f.indicator}" + (f.observed?.let { " (seen as $it)" } ?: ""))
                if (f.kind == KIND_NETWORK) {
                    appendLine(
                        "  Seen: ${f.count ?: 0} times" + (f.blocked?.takeIf { it > 0 }?.let { ", $it blocked" } ?: "") +
                            (f.firstSeen?.let { ", first ${formatTime(it)}" } ?: "") + (f.lastSeen?.let { ", last ${formatTime(it)}" } ?: ""),
                    )
                } else {
                    f.firstSeen?.let { appendLine("  Installed: ${formatTime(it)}") }
                }
                appendLine("  Source: ${f.packName}" + (f.license?.let { " ($it)" } ?: ""))
                f.reference?.let { appendLine("  Reference: $it") }
            }
            appendLine()
        }
        appendLine("What was checked")
        appendLine("- ${r.appsChecked} installed apps (package names and signing certificates)")
        appendLine("- ${r.destinationsChecked} domains and addresses from the network history")
        for (n in r.notes) appendLine("- $n")
        appendLine()
        appendLine("Indicator packs")
        for (p in r.packs) {
            val state = when {
                !p.enabled -> "off"
                p.downloadedAt == null -> "not downloaded"
                else -> "updated ${formatTime(p.downloadedAt)}" + if (p.stale) " (out of date)" else ""
            }
            val counts = listOf(p.domains to "domains", p.ips to "IPs", p.apps to "apps", p.certs to "certificates")
                .filter { it.first > 0 }.joinToString(", ") { "${it.first} ${it.second}" }
            appendLine("- ${p.name}: $state" + (if (counts.isNotEmpty()) "; $counts" else "") + (p.license?.let { "; licence $it" } ?: ""))
        }
        appendLine()
        appendLine("Guidance")
        for (g in r.guidance) appendLine("- $g")
    }

    /** UTC, so a report reads the same wherever it is opened. */
    fun formatTime(ms: Long): String = SimpleDateFormat("yyyy-MM-dd HH:mm 'UTC'", Locale.US)
        .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(ms))
}
