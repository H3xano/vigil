package dev.vigil.inspector.data

import dev.vigil.inspector.engine.AlertEvent
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.io.IOException
import java.io.Reader

/** Severity of a spyware indicator: a known threat, or a legitimate monitoring app worth a look. */
object SpywareSeverity {
    const val INDICATOR = "indicator"
    const val WARNING = "warning"
}

/** The indicators of one spyware family or app ([label]) in a pack. */
@Serializable
data class SpywareGroup(
    val label: String,
    val severity: String = SpywareSeverity.INDICATOR,
    val domains: List<String> = emptyList(),
    val ips: List<String> = emptyList(),
    /** Android package names. */
    val apps: List<String> = emptyList(),
    /** Signing certificates, `SHA1:<HEX>` / `SHA256:<HEX>` (see [AppCerts]). */
    val certs: List<String> = emptyList(),
)

/**
 * A downloaded spyware indicator pack, stored next to the feed file
 * (`<feed id>.spy.json`). The feed file holds the network indicators the
 * engine loads; this file keeps what the engine cannot carry: the family
 * label of each indicator, app packages and certificates, the licence and
 * the reference, for alert labels and the health check.
 */
@Serializable
data class SpywarePack(
    val format: Int = 1,
    val feedId: String,
    val name: String,
    /** The URL the pack was downloaded from. */
    val source: String,
    val reference: String? = null,
    val license: String,
    val downloadedAt: Long = 0,
    val groups: List<SpywareGroup> = emptyList(),
) {
    val domainCount: Int get() = groups.sumOf { it.domains.size }
    val ipCount: Int get() = groups.sumOf { it.ips.size }
    val appCount: Int get() = groups.sumOf { it.apps.size }
    val certCount: Int get() = groups.sumOf { it.certs.size }
    val total: Int get() = domainCount + ipCount + appCount + certCount

    /**
     * Lines of the engine feed file: the domains and IP addresses of
     * [SpywareSeverity.INDICATOR] groups (monitoring-app warnings never
     * raise live alerts or block).
     */
    fun engineLines(): List<String> {
        val threats = groups.filter { it.severity == SpywareSeverity.INDICATOR }
        return (threats.flatMap { it.domains } + threats.flatMap { it.ips }).distinct()
    }
}

/**
 * Converters from the published formats to [SpywareGroup]s. They run at
 * download time (see [FeedRepository]).
 */
object SpywareConverters {
    const val FORMAT_STIX2 = "stix2"
    const val FORMAT_ECHAP_NETWORK_CSV = "echap_network_csv"
    const val FORMAT_ECHAP_IOC_YAML = "echap_ioc_yaml"
    const val FORMAT_ECHAP_WATCHWARE_YAML = "echap_watchware_yaml"
    const val FORMAT_MVT_INDEX = "mvt_index_yaml"

    /** At most this many indicators per pack (the largest source has about 10 k). */
    const val MAX_INDICATORS = 200_000

    /** Converts [input]; an input too large for memory fails with an [IOException] instead of killing the process. */
    fun convert(format: String, input: File, defaultLabel: String): List<SpywareGroup> = try {
        when (format) {
            FORMAT_STIX2 -> input.bufferedReader().use { stix(it, defaultLabel) }
            FORMAT_ECHAP_NETWORK_CSV -> echapNetworkCsv(input.readText(), defaultLabel)
            FORMAT_ECHAP_IOC_YAML -> echapYaml(input.readText(), SpywareSeverity.INDICATOR)
            FORMAT_ECHAP_WATCHWARE_YAML -> echapYaml(input.readText(), SpywareSeverity.WARNING)
            else -> throw IOException("unknown spyware pack format $format")
        }
    } catch (e: OutOfMemoryError) {
        throw IOException("spyware pack too large to process on this device", e)
    } catch (e: StackOverflowError) {
        throw IOException("spyware pack nested too deeply to process", e)
    }

    /**
     * A STIX 2.1 bundle, streamed. Each indicator is labelled with the name
     * of the `malware` object it `indicates`, else its own name or labels,
     * else [defaultLabel]. URL indicators are ignored: spyware bundles list
     * download pages on code-hosting sites, whose host must not be flagged.
     * Revoked and expired indicators are left out.
     */
    fun stix(reader: Reader, defaultLabel: String, now: Long = System.currentTimeMillis()): List<SpywareGroup> {
        val rel = StixRelationshipLabels()
        val items = ArrayList<StixItem>()
        var count = 0
        StixStream.forEachObject(reader) { o ->
            rel.accept(o)
            if ((o["type"] as? JsonPrimitive)?.content != "indicator") return@forEachObject
            val item = Stix.item(o, urlHosts = false) ?: return@forEachObject
            if (item.revoked || (item.validUntil != null && item.validUntil <= now)) return@forEachObject
            if (count >= MAX_INDICATORS) return@forEachObject
            count += item.values.size
            items += item
        }
        val groups = Groups()
        for (item in items) {
            val label = rel.labelFor(item.id) ?: item.label ?: defaultLabel
            val v = item.values
            groups.add(label, SpywareSeverity.INDICATOR, v.domains, v.ips, v.apps, v.certs)
        }
        return groups.build()
    }

    /** Echap `generated/network.csv`: `type,indicator,app` rows (domain / ipv4 / ipv6). */
    fun echapNetworkCsv(text: String, defaultLabel: String): List<SpywareGroup> {
        val rows = Csv.parse(text)
        val header = rows.firstOrNull()?.map { it.trim().lowercase() } ?: return emptyList()
        val type = header.indexOf("type")
        val value = header.indexOf("indicator")
        val app = header.indexOf("app")
        if (type < 0 || value < 0) throw IOException("not an indicator CSV (no type/indicator columns)")
        val groups = Groups()
        for (r in rows.drop(1)) {
            val v = r.getOrNull(value)?.trim().orEmpty()
            val label = r.getOrNull(app)?.trim()?.takeIf { it.isNotEmpty() } ?: defaultLabel
            when (r.getOrNull(type)?.trim()?.lowercase()) {
                "domain", "domain-name", "hostname" -> groups.add(label, SpywareSeverity.INDICATOR, domains = listOf(v))
                "ipv4", "ipv6", "ip", "ip-dst" -> groups.add(label, SpywareSeverity.INDICATOR, ips = listOf(v))
            }
        }
        return groups.build()
    }

    /**
     * Echap `ioc.yaml` / `watchware.yaml`: a list of apps with `name`,
     * `type`, `packages`, `certificates` (SHA-1), `websites`,
     * `distribution` and `c2` (`domains`, and `ips` or, in two entries,
     * `ip`). Entries of type `watchware` are warnings; others take
     * [severity].
     */
    fun echapYaml(text: String, severity: String): List<SpywareGroup> {
        val root = MiniYaml.parse(text) as? List<*> ?: throw IOException("not an indicator list")
        val groups = Groups()
        for (e in root) {
            val m = MiniYaml.map(e) ?: continue
            val name = MiniYaml.strings(m["name"]).firstOrNull()?.trim()?.takeIf { it.isNotEmpty() } ?: continue
            val sev = if (MiniYaml.strings(m["type"]).firstOrNull()?.trim() == "watchware") SpywareSeverity.WARNING else severity
            val c2 = MiniYaml.map(m["c2"])
            groups.add(
                name, sev,
                domains = MiniYaml.strings(m["websites"]) + MiniYaml.strings(m["distribution"]) + MiniYaml.strings(c2?.get("domains")),
                ips = MiniYaml.strings(c2?.get("ips")) + MiniYaml.strings(c2?.get("ip")),
                apps = MiniYaml.strings(m["packages"]),
                certs = MiniYaml.strings(m["certificates"]),
            )
        }
        return groups.build()
    }

    /** Collects validated, de-duplicated values per (label, severity), capped at [MAX_INDICATORS]. */
    private class Groups {
        private class G(val label: String, val severity: String) {
            val domains = LinkedHashSet<String>()
            val ips = LinkedHashSet<String>()
            val apps = LinkedHashSet<String>()
            val certs = LinkedHashSet<String>()
        }

        private val groups = LinkedHashMap<String, G>()
        private var total = 0

        fun add(
            label: String,
            severity: String,
            domains: List<String> = emptyList(),
            ips: List<String> = emptyList(),
            apps: List<String> = emptyList(),
            certs: List<String> = emptyList(),
        ) {
            val clean = Ja4.cleanLabel(label).ifEmpty { "unnamed" }
            val g = groups.getOrPut("$severity|$clean") { G(clean, severity) }
            fun put(set: MutableSet<String>, v: String?) {
                if (v != null && total < MAX_INDICATORS && set.add(v)) total++
            }
            for (d in domains) {
                // Some sources put addresses in domain fields.
                val dom = Indicators.domain(d)
                if (dom != null) {
                    // A shared platform (github.com, drive.google.com…) is never an indicator.
                    if (!SharedPlatforms.isShared(dom)) put(g.domains, dom)
                } else {
                    put(g.ips, Indicators.ipOrCidr(d))
                }
            }
            for (i in ips) put(g.ips, Indicators.ipOrCidr(i))
            for (a in apps) put(g.apps, Indicators.packageName(a))
            for (c in certs) put(g.certs, AppCerts.normalize(c))
        }

        fun build(): List<SpywareGroup> = groups.values
            .filter { it.domains.isNotEmpty() || it.ips.isNotEmpty() || it.apps.isNotEmpty() || it.certs.isNotEmpty() }
            .map { SpywareGroup(it.label, it.severity, it.domains.toList(), it.ips.toList(), it.apps.toList(), it.certs.toList()) }
    }
}

/** One pack listed by MVT's `indicators.yaml`. */
@Serializable
data class MvtPack(
    /** Feed id, `mvt-<slug of the path>`. */
    val id: String,
    /** Display name ("NSO Group Pegasus", without "Indicators of Compromise"). */
    val name: String,
    val url: String,
    val owner: String,
    val sources: List<String> = emptyList(),
    val references: List<String> = emptyList(),
    val license: String,
)

/**
 * MVT's index of indicator packs (github.com/mvt-project/mvt-indicators,
 * `indicators.yaml`). Only packs hosted in the repositories of the MVT
 * project, Amnesty International's Security Lab and Echap are accepted;
 * each becomes a feed of its own.
 */
object MvtIndex {
    const val URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
    const val MAX_PACKS = 64
    const val ID_PREFIX = "mvt-"

    /** Accepted GitHub owners and the licence of their indicator repositories. */
    val OWNER_LICENSES = mapOf(
        "mvt-project" to "MIT (MVT project)",
        "AmnestyTech" to "CC BY 2.0 (Amnesty International)",
        "AssoEchap" to "CC BY 4.0 (Echap)",
    )

    private val NAME_PART = Regex("^[A-Za-z0-9._-]{1,100}$")

    /**
     * The raw.githubusercontent.com URL of a pack, or null unless [owner] is
     * accepted and every part is a plain path segment (no `..`, no query).
     */
    fun rawUrl(owner: String, repo: String, branch: String, path: String): String? {
        if (owner !in OWNER_LICENSES) return null
        if (!NAME_PART.matches(repo) || !NAME_PART.matches(branch) || repo.startsWith(".") || branch.startsWith(".")) return null
        val segments = path.split('/')
        if (segments.isEmpty() || segments.size > 8 || segments.any { !NAME_PART.matches(it) || it == "." || it == ".." }) return null
        return "https://raw.githubusercontent.com/$owner/$repo/$branch/$path"
    }

    /** Parses the index; entries that are not accepted GitHub packs are skipped. */
    fun parse(text: String): List<MvtPack> {
        val root = MiniYaml.map(MiniYaml.parse(text)) ?: throw IOException("not an MVT indicators index")
        val list = root["indicators"] as? List<*> ?: throw IOException("not an MVT indicators index (no indicators list)")
        val out = ArrayList<MvtPack>()
        val ids = HashSet<String>()
        for (e in list) {
            if (out.size >= MAX_PACKS) break
            val m = MiniYaml.map(e) ?: continue
            val type = MiniYaml.strings(m["type"]).firstOrNull() ?: "github"
            if (type != "github") continue
            val gh = MiniYaml.map(m["github"]) ?: continue
            fun s(k: String) = MiniYaml.strings(gh[k]).firstOrNull()?.trim().orEmpty()
            val owner = s("owner")
            val path = s("path")
            val url = rawUrl(owner, s("repo"), s("branch"), path) ?: continue
            val rawName = MiniYaml.strings(m["name"]).firstOrNull()?.trim().orEmpty()
            val name = Ja4.cleanLabel(rawName.replace(Regex("\\s+Indicators of Compromise\\s*$", RegexOption.IGNORE_CASE), ""))
                .ifEmpty { path.substringAfterLast('/') }
            var id = ID_PREFIX + slug(path.substringBeforeLast('.'))
            if (!ids.add(id)) {
                var n = 2
                while (!ids.add("$id-$n")) n++
                id = "$id-$n"
            }
            out += MvtPack(
                id = id, name = name, url = url, owner = owner,
                sources = MiniYaml.strings(m["sources"]).map(Ja4::cleanLabel).filter { it.isNotEmpty() }.take(10),
                references = MiniYaml.strings(m["references"]).map { it.trim() }.filter { it.startsWith("https://") && it.length < 500 }.take(10),
                license = OWNER_LICENSES.getValue(owner),
            )
        }
        return out
    }

    fun slug(s: String): String = s.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-').take(60).trim('-').ifEmpty { "pack" }

    /**
     * The feed of [pack]. On by default except Echap's STIX bundle, which
     * repeats the dedicated Echap feeds as a 4.6 MB download.
     */
    fun feedFor(pack: MvtPack): FeedEntity = FeedEntity(
        id = pack.id, name = pack.name, url = pack.url, category = "malware",
        enabled = pack.owner != "AssoEchap", builtin = true, kind = FeedKinds.SPYWARE, format = SpywareConverters.FORMAT_STIX2,
        description = description(pack),
    )

    fun description(pack: MvtPack): String {
        val by = if (pack.sources.isEmpty()) "" else "Research by ${pack.sources.joinToString(", ")}. "
        return "${by}Listed by MVT; licence: ${pack.license}."
    }

    private val json = Json { ignoreUnknownKeys = true }

    fun write(packs: List<MvtPack>, file: File) = file.writeText(json.encodeToString(ListSerializer(MvtPack.serializer()), packs))

    fun read(file: File): List<MvtPack>? =
        runCatching { json.decodeFromString(ListSerializer(MvtPack.serializer()), file.readText()) }.getOrNull()
}

/** Reads and writes pack files. */
object SpywareStore {
    private val json = Json { ignoreUnknownKeys = true }

    fun write(pack: SpywarePack, file: File) = file.writeText(json.encodeToString(SpywarePack.serializer(), pack))

    fun read(file: File): SpywarePack? =
        if (!file.exists()) null else runCatching { json.decodeFromString(SpywarePack.serializer(), file.readText()) }.getOrNull()
}

/**
 * Names the spyware behind threat alerts. The engine's alerts carry the
 * feed and the listed entry (`listed by feed:<id> (<entry>)`) but no label
 * for domain and IP feeds; this looks the entry up in the downloaded packs
 * ([files], re-read when they change) and adds the family and pack.
 */
class SpywareLabels(private val files: () -> List<File>) {
    data class Hit(val label: String, val pack: String, val feedId: String)

    private var key: List<Pair<String, Long>> = emptyList()
    private var index: Map<String, Hit> = emptyMap()
    private var ips: IpMatcher<Hit> = IpMatcher()

    @Synchronized
    fun lookup(value: String): Hit? {
        val current = files().filter { it.exists() }.sortedBy { it.name }
        val k = current.map { it.path to it.lastModified() }
        if (k != key) {
            val m = HashMap<String, Hit>()
            val ipm = IpMatcher<Hit>()
            for (f in current) {
                val p = SpywareStore.read(f) ?: continue
                for (g in p.groups) {
                    if (g.severity != SpywareSeverity.INDICATOR) continue
                    val hit = Hit(g.label, p.name, p.feedId)
                    for (v in g.domains) m.putIfAbsent(v, hit)
                    for (v in g.ips) {
                        ipm.add(v, hit)
                        m.putIfAbsent(v.lowercase(), hit)
                    }
                }
            }
            index = m
            ips = ipm
            key = k
        }
        // Addresses by value (the engine names the address it matched, in its own spelling), ranges included.
        return ips.match(value).firstOrNull()?.value ?: index[value.lowercase()]
    }

    /** [e] with the spyware named in its message and `detail.spyware`, or [e] itself. */
    fun enrich(e: AlertEvent): AlertEvent {
        if (e.kind != "threat_domain" && e.kind != "threat_ip") return e
        val rule = ruleOf(e.message) ?: e.target
        val hit = lookup(rule) ?: return e
        val detail = buildJsonObject {
            (e.detail as? JsonObject)?.forEach { (k, v) -> put(k, v) }
            put("spyware", buildJsonObject {
                put("label", hit.label)
                put("pack", hit.pack)
                put("feed", hit.feedId)
            })
        }
        return e.copy(message = "${e.message}. Spyware indicator: ${hit.label} (${hit.pack})", detail = detail)
    }

    companion object {
        private val RULE = Regex("""listed by feed:\S+ \(([^()\s]+)\)""")

        /** The listed entry named by an engine threat alert message, or null. */
        fun ruleOf(message: String): String? = RULE.find(message)?.groupValues?.get(1)
    }
}
