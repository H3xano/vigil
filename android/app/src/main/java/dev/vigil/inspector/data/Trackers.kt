package dev.vigil.inspector.data

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import java.io.File
import java.io.IOException
import java.io.Reader
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A tracker from the tracker database, with its category and company
 * resolved. Labels only: vigil never blocks because of this data.
 */
data class Tracker(
    val id: String,
    val name: String,
    /** Category key as in AdGuard companiesdb, e.g. `advertising`, `mobile_analytics`, `cdn`. */
    val category: String,
    /** Null when the database names no company for this tracker. */
    val companyName: String?,
    val companyWebsite: String?,
) {
    /** What to group by: the company, or the tracker itself when no company is known. */
    val company: String get() = companyName ?: name

    /** Advertising, analytics, telemetry or social tracking (not a CDN, host or other service). */
    val isTracking: Boolean get() = TrackerDatabase.isTrackingCategory(category)
}

/** A host matched to a tracker: [domain] is the listed domain (the host itself or a parent). */
data class TrackerMatch(val domain: String, val tracker: Tracker)

/**
 * In-memory tracker labels: listed domain → [Tracker]. Immutable, so it is
 * safe to share between threads. Matching is by longest suffix on label
 * boundaries: for `a.b.doubleclick.net` it tries `a.b.doubleclick.net`,
 * `b.doubleclick.net` and `doubleclick.net`, never a bare TLD, and
 * `notdoubleclick.net` does not match `doubleclick.net`.
 */
class TrackerIndex(private val byDomain: Map<String, Tracker>) {
    val domainCount: Int get() = byDomain.size
    val trackerCount: Int by lazy { byDomain.values.distinctBy { it.id }.size }
    val companyCount: Int by lazy { byDomain.values.mapNotNull { it.companyName }.distinct().size }

    fun match(host: String?): TrackerMatch? {
        var name = normalize(host) ?: return null
        while (true) {
            byDomain[name]?.let { return TrackerMatch(name, it) }
            val dot = name.indexOf('.')
            if (dot < 0) return null
            val parent = name.substring(dot + 1)
            // A single label is a TLD: nothing is listed at that level.
            if (parent.indexOf('.') < 0) return null
            name = parent
        }
    }

    companion object {
        /** Lower-case name without a trailing dot; null for IP literals and empty names. */
        fun normalize(host: String?): String? {
            val h = host?.trim()?.trimEnd('.')?.lowercase() ?: return null
            if (h.isEmpty() || ':' in h || '/' in h || ' ' in h) return null
            if (h.all { it.isDigit() || it == '.' }) return null
            return h
        }
    }
}

/**
 * The tracker database: AdGuard companiesdb (CC BY-SA 4.0), downloaded by
 * the device from AdguardTeam/companiesdb on GitHub. It started from
 * WhoTracks.me data and is maintained by AdGuard independently.
 *
 * Two JSON files are downloaded, `trackers.json` (the feed URL) and
 * `companies.json` (next to it), and converted into one compact TSV:
 *
 * ```
 * # comment
 * c	<company id>	<name>	<website>
 * t	<tracker id>	<name>	<category key>	<company id or empty>
 * d	<domain>	<tracker id>
 * ```
 */
object TrackerDatabase {
    /** Feed category (never loaded by the engine; see ConfigFactory.loadableFeeds). */
    const val CATEGORY = "trackers"

    /** [FeedEntity.format] of AdGuard companiesdb's `trackers.json` (+ `companies.json`). */
    const val FORMAT_ADGUARD = "adguard_companiesdb"

    const val FEED_ID = "adguard-companiesdb"
    const val TRACKERS_URL = "https://raw.githubusercontent.com/AdguardTeam/companiesdb/main/dist/trackers.json"
    const val SOURCE_URL = "https://github.com/AdguardTeam/companiesdb"
    const val LICENSE_URL = "https://creativecommons.org/licenses/by-sa/4.0/"
    const val ATTRIBUTION = "AdGuard companiesdb — CC BY-SA 4.0"

    /** The companies file sits next to the trackers file. */
    fun companiesUrl(trackersUrl: String): String = trackersUrl.substringBeforeLast('/') + "/companies.json"

    /** Refreshed weekly, like the ASN table (the daily job skips it until it is this old). */
    const val MAX_AGE_MS = 7L * 24 * 3600 * 1000 - 4L * 3600 * 1000

    /** Each JSON file is under 1 MB today. */
    const val MAX_JSON_BYTES = 16L * 1024 * 1024

    /** The real database lists about 5,000 domains; fewer than this means a wrong or truncated file. */
    const val MIN_DOMAINS = 1_000

    /** Reject when more than this share of the domains is unusable. */
    const val MAX_REJECTED_RATIO = 0.05

    private val TRACKING = setOf("advertising", "pornvertising", "site_analytics", "mobile_analytics", "telemetry", "social_media")

    fun isTrackingCategory(category: String) = category in TRACKING

    /** A readable category name. */
    fun categoryLabel(category: String): String = when (category) {
        "advertising" -> "Advertising"
        "pornvertising" -> "Adult advertising"
        "site_analytics" -> "Analytics"
        "mobile_analytics" -> "Mobile analytics"
        "telemetry" -> "Telemetry"
        "social_media" -> "Social media"
        "customer_interaction" -> "Customer interaction"
        "audio_video_player" -> "Audio/video player"
        "cdn" -> "CDN"
        "hosting" -> "Hosting"
        "essential" -> "Essential"
        "consent" -> "Consent management"
        "email" -> "Email"
        "comments" -> "Comments"
        "extensions" -> "Extensions"
        "misc" -> "Miscellaneous"
        "unknown" -> "Unknown"
        else -> category.replace('_', ' ').replaceFirstChar { it.uppercase() }
    }

    /** "Google · Advertising". */
    fun label(t: Tracker): String = "${t.company} · ${categoryLabel(t.category)}"

    data class Stats(val domains: Int, val rejected: Int, val trackers: Int, val companies: Int)

    private val DOMAIN = Regex("""^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,62})?(\.[a-z0-9_]([a-z0-9_-]{0,62})?)+$""")

    fun isDomain(s: String) = DOMAIN.matches(s)

    private val json = Json { ignoreUnknownKeys = true }

    private fun JsonElement?.str(): String? = (this as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() }

    /** Tabs and line breaks would break the TSV; names never need them. */
    private fun clean(s: String?): String = s.orEmpty().replace(Regex("[\\t\\r\\n]+"), " ").trim()

    private fun obj(root: JsonObject, key: String, what: String): JsonObject =
        root[key] as? JsonObject ?: throw IOException("not an AdGuard companiesdb $what (no \"$key\" object)")

    private fun parse(text: String, what: String): JsonObject = try {
        json.parseToJsonElement(text) as? JsonObject ?: throw IOException("$what is not a JSON object")
    } catch (e: IllegalArgumentException) {
        // kotlinx.serialization's parse errors are IllegalArgumentExceptions.
        throw IOException("$what is not valid JSON", e)
    }

    /**
     * Converts the two downloads into the compact TSV [out] and returns the
     * counts. Throws [IOException] for files that are not companiesdb JSON.
     * Domains that are not valid names or name an unknown tracker are
     * dropped (and counted); a tracker whose company is missing keeps no company.
     */
    fun convert(trackersJson: String, companiesJson: String, out: File): Stats {
        val trackersRoot = parse(trackersJson, "trackers.json")
        val companiesRoot = parse(companiesJson, "companies.json")
        val categories = obj(trackersRoot, "categories", "trackers.json")
        val trackers = obj(trackersRoot, "trackers", "trackers.json")
        val domains = obj(trackersRoot, "trackerDomains", "trackers.json")
        val companies = obj(companiesRoot, "companies", "companies.json")

        val usedTrackers = LinkedHashSet<String>()
        val rows = ArrayList<Pair<String, String>>(domains.size)
        var rejected = 0
        for ((rawDomain, idElement) in domains) {
            val domain = rawDomain.trim().trimEnd('.').lowercase()
            val id = idElement.str()
            if (id == null || !isDomain(domain) || trackers[id] !is JsonObject) {
                rejected++
                continue
            }
            rows += domain to id
            usedTrackers += id
        }
        val usedCompanies = LinkedHashSet<String>()
        val trackerLines = ArrayList<String>(usedTrackers.size)
        for (id in usedTrackers) {
            val t = trackers[id] as JsonObject
            val categoryId = (t["categoryId"] as? JsonPrimitive)?.intOrNull
            val category = categoryId?.let { categories[it.toString()].str() } ?: "unknown"
            val companyId = t["companyId"].str()?.takeIf { companies[it] is JsonObject }
            if (companyId != null) usedCompanies += companyId
            trackerLines += "t\t${clean(id)}\t${clean(t["name"].str() ?: id)}\t${clean(category)}\t${clean(companyId)}"
        }
        out.bufferedWriter(Charsets.UTF_8).use { w ->
            w.write("# vigil tracker labels v1. Data: AdGuard companiesdb ($SOURCE_URL), CC BY-SA 4.0\n")
            for (id in usedCompanies) {
                val c = companies[id] as JsonObject
                w.write("c\t${clean(id)}\t${clean(c["name"].str() ?: id)}\t${clean(c["websiteUrl"].str())}\n")
            }
            for (l in trackerLines) w.write(l + "\n")
            for ((domain, id) in rows) w.write("d\t$domain\t${clean(id)}\n")
        }
        return Stats(rows.size, rejected, usedTrackers.size, usedCompanies.size)
    }

    /** Null if the converted database is acceptable, otherwise the reason. */
    fun validate(stats: Stats, previousDomains: Int?): String? {
        val total = stats.domains + stats.rejected
        if (total == 0) return "the tracker database is empty"
        if (stats.rejected > total * MAX_REJECTED_RATIO) return "${stats.rejected} of $total tracker domains unusable; not a companiesdb file?"
        if (stats.domains < MIN_DOMAINS) return "only ${stats.domains} tracker domains; truncated download?"
        if (previousDomains != null && previousDomains > 0 && stats.domains < previousDomains / 2) {
            return "only ${stats.domains} tracker domains (previously $previousDomains); keeping the previous copy"
        }
        return null
    }

    /**
     * Reads the converted TSV. Strings repeated across rows (categories,
     * company names and websites) are shared; unknown or malformed lines
     * are skipped.
     */
    fun load(reader: Reader): TrackerIndex {
        val intern = HashMap<String, String>()
        fun i(s: String) = intern.getOrPut(s) { s }
        val companies = HashMap<String, Pair<String, String?>>()
        val trackers = HashMap<String, Tracker>()
        val domains = HashMap<String, Tracker>(8192)
        reader.buffered().useLines { lines ->
            for (line in lines) {
                if (line.isEmpty() || line[0] == '#') continue
                val f = line.split('\t')
                when (f[0]) {
                    "c" -> if (f.size >= 3) companies[f[1]] = i(f[2]) to f.getOrNull(3)?.takeIf { it.isNotEmpty() }?.let(::i)
                    "t" -> if (f.size >= 4) {
                        val company = f.getOrNull(4)?.takeIf { it.isNotEmpty() }?.let { companies[it] }
                        trackers[f[1]] = Tracker(f[1], f[2], i(f[3]), company?.first, company?.second)
                    }
                    "d" -> if (f.size >= 3) trackers[f[2]]?.let { domains[f[1]] = it }
                }
            }
        }
        return TrackerIndex(domains)
    }

    fun load(file: File): TrackerIndex = file.reader(Charsets.UTF_8).use(::load)
}

/**
 * The app-wide tracker labels: loads the converted database lazily (on the
 * first lookup or subscription) and again after each refresh, and drops it
 * when the source is turned off. Lookups before the load finishes return null.
 */
class TrackerLabels(
    private val scope: CoroutineScope,
    private val feeds: Flow<List<FeedEntity>>,
    private val fileFor: (String) -> File,
) {
    private val started = AtomicBoolean(false)
    private val current = MutableStateFlow<TrackerIndex?>(null)

    /** The loaded index; null while loading, when disabled or not downloaded yet. */
    val index: StateFlow<TrackerIndex?>
        get() {
            start()
            return current
        }

    fun match(host: String?): TrackerMatch? = index.value?.match(host)

    private fun start() {
        if (!started.compareAndSet(false, true)) return
        scope.launch(Dispatchers.IO) {
            feeds.map { list -> list.firstOrNull { it.kind == FeedKinds.TRACKERS && it.enabled && it.lastUpdated != null } }
                .map { f -> f?.let { it.id to it.lastUpdated } }
                .distinctUntilChanged()
                .collect { version ->
                    current.value = version?.let { (id, _) ->
                        val file = fileFor(id)
                        try {
                            if (file.exists()) TrackerDatabase.load(file).also { Log.i(TAG, "tracker labels: ${it.domainCount} domains") } else null
                        } catch (e: IOException) {
                            Log.w(TAG, "tracker labels unreadable: ${e.message}")
                            null
                        }
                    }
                }
        }
    }

    private companion object {
        const val TAG = "vigil.trackers"
    }
}
