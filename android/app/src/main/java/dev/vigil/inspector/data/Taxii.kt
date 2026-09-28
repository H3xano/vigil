package dev.vigil.inspector.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import java.io.File
import java.io.IOException
import java.net.URLEncoder

/** One HTTP response as seen by the TAXII client. Header names are lower-case. */
class TaxiiResponse(val code: Int, val contentType: String?, val headers: Map<String, String>, val body: String)

/** Performs a GET with the TAXII Accept header and the source's credentials. */
fun interface TaxiiTransport {
    @Throws(IOException::class)
    fun get(url: String): TaxiiResponse
}

/** A collection offered by a TAXII 2.1 API root. */
data class TaxiiCollection(val apiRoot: String, val id: String, val title: String, val description: String?, val canRead: Boolean)

/** Outcome of one poll: how many pages and objects were read, and the `added_after` to use next time. */
data class TaxiiPollResult(val pages: Int, val objects: Int, val nextAddedAfter: String?)

/**
 * TAXII 2.1 client (OASIS TAXII 2.1, sections 4 and 5): discovery, API root
 * collections and paginated object retrieval. The HTTP layer is injected, so
 * the logic is testable on the JVM.
 */
class TaxiiClient(private val http: TaxiiTransport) {
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Collections reachable from [url], which may be a discovery endpoint
     * (`…/taxii2/`, listing API roots) or an API root. At most
     * [MAX_API_ROOTS] roots are asked.
     */
    fun collections(url: String): List<TaxiiCollection> {
        val doc = getJson(url)
        val roots = (doc["api_roots"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content }
        if (roots == null) return collectionsOf(url)
        if (roots.isEmpty()) throw IOException("the discovery endpoint lists no API roots")
        val out = ArrayList<TaxiiCollection>()
        var lastError: IOException? = null
        for (root in roots.take(MAX_API_ROOTS)) {
            try {
                out += collectionsOf(resolve(url, root))
            } catch (e: IOException) {
                lastError = e
            }
        }
        if (out.isEmpty() && lastError != null) throw lastError
        return out
    }

    private fun collectionsOf(apiRoot: String): List<TaxiiCollection> {
        val root = withSlash(apiRoot)
        val doc = getJson(root + "collections/")
        return (doc["collections"] as? JsonArray).orEmpty().mapNotNull { e ->
            val o = e as? JsonObject ?: return@mapNotNull null
            val id = o.str("id") ?: return@mapNotNull null
            TaxiiCollection(
                apiRoot = root, id = id, title = o.str("title") ?: id, description = o.str("description"),
                canRead = (o["can_read"] as? JsonPrimitive)?.booleanOrNull ?: true,
            )
        }
    }

    /**
     * Reads every object added to the collection after [addedAfter] (all of
     * them when null), page by page, handing each page's objects to
     * [onPage]. Follows `next` (TAXII 2.1), or advances `added_after` from
     * the `X-TAXII-Date-Added-Last` header when a server sets `more` without
     * `next`. Throws on any HTTP or format error; the caller then keeps its
     * previous state.
     */
    fun poll(apiRoot: String, collectionId: String, addedAfter: String?, onPage: (List<JsonObject>) -> Unit): TaxiiPollResult {
        val base = withSlash(apiRoot) + "collections/" + enc(collectionId) + "/objects/?limit=$PAGE_LIMIT"
        var after = addedAfter
        var next: String? = null
        var lastAdded: String? = addedAfter
        var pages = 0
        var objects = 0
        var emptyPages = 0
        while (true) {
            if (pages >= MAX_PAGES) throw IOException("more than $MAX_PAGES pages; collection too large")
            val url = base + (after?.let { "&added_after=" + enc(it) } ?: "") + (next?.let { "&next=" + enc(it) } ?: "")
            val resp = request(url)
            pages++
            // 204-like empty answers (no objects yet) are valid.
            val doc = if (resp.body.isBlank()) JsonObject(emptyMap()) else parse(resp.body)
            val page = Stix.objects(doc)
            objects += page.size
            if (objects > MAX_OBJECTS) throw IOException("more than $MAX_OBJECTS objects; collection too large")
            onPage(page)
            val headerLast = resp.headers["x-taxii-date-added-last"]
            if (headerLast != null) lastAdded = headerLast
            val more = (doc["more"] as? JsonPrimitive)?.booleanOrNull == true
            if (!more) break
            val n = doc.str("next")
            if (n != null) {
                // Servers may reuse one token for a whole paging session (medallion does), so
                // only a run of empty pages counts as a loop.
                emptyPages = if (page.isEmpty()) emptyPages + 1 else 0
                if (emptyPages > MAX_EMPTY_PAGES) throw IOException("server keeps reporting more objects but sends none")
                next = n
            } else {
                // Pagination by added_after (servers without `next`).
                if (headerLast == null || headerLast == after) throw IOException("server reports more objects but no way to page")
                after = headerLast
            }
        }
        return TaxiiPollResult(pages, objects, lastAdded)
    }

    private fun getJson(url: String): JsonObject = parse(request(url).body)

    private fun request(url: String): TaxiiResponse {
        val r = http.get(url)
        when (r.code) {
            in 200..299 -> {}
            401, 403 -> throw IOException("HTTP ${r.code}: check the credentials and the collection's read permission")
            404 -> throw IOException("HTTP 404: no TAXII endpoint at $url")
            406, 415 -> throw IOException("HTTP ${r.code}: the server does not speak TAXII 2.1")
            else -> throw IOException("HTTP ${r.code}")
        }
        val ct = r.contentType?.lowercase().orEmpty()
        if (r.body.isNotBlank() && !(ct.startsWith("application/taxii+json") || ct.startsWith("application/json") || ct.startsWith("application/stix+json"))) {
            throw IOException("unexpected content type ${ct.ifEmpty { "(none)" }}; not a TAXII 2.1 server (login page?)")
        }
        return r
    }

    private fun parse(body: String): JsonObject =
        runCatching { json.parseToJsonElement(body) as? JsonObject }.getOrNull() ?: throw IOException("response is not a JSON object")

    private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

    companion object {
        const val MEDIA_TYPE = "application/taxii+json;version=2.1"
        const val PAGE_LIMIT = 1000
        const val MAX_PAGES = 2000
        const val MAX_OBJECTS = 2_000_000
        const val MAX_API_ROOTS = 8
        private const val MAX_EMPTY_PAGES = 3

        fun withSlash(url: String) = if (url.endsWith("/")) url else "$url/"

        /** Percent-encoding valid in paths and query values (URLEncoder alone turns spaces into `+`). */
        private fun enc(s: String) = URLEncoder.encode(s, "UTF-8").replace("+", "%20")

        /** Resolves an API root listed by a discovery document (absolute URL or path) against [base]. */
        fun resolve(base: String, root: String): String = java.net.URI(base).resolve(root).toString()
    }
}

/**
 * The indicators of one TAXII source, kept across incremental polls: STIX
 * object id → latest version. Newer versions replace older ones; revoked
 * objects are dropped; expired ones (`valid_until` passed) are left out of
 * the feed file. Bounded to [MAX_ENTRIES] objects (further new objects are
 * ignored and counted).
 */
class TaxiiState(var fullSyncAt: Long = 0) {
    data class Entry(val version: Long, val validUntil: Long?, val label: String?, val values: IndicatorValues)

    val entries = LinkedHashMap<String, Entry>()
    var dropped = 0
        private set

    fun apply(item: StixItem) {
        val old = entries[item.id]
        if (old != null && item.version < old.version) return
        if (item.revoked) {
            entries.remove(item.id)
            return
        }
        if (old == null && entries.size >= MAX_ENTRIES) {
            dropped++
            return
        }
        entries[item.id] = Entry(item.version, item.validUntil, item.label, item.values)
    }

    /** Distinct feed lines of the entries still valid at [now]: domains, then IPs, then JA4 (first label wins). */
    fun feedLines(now: Long): FeedLines {
        val domains = LinkedHashSet<String>()
        val ips = LinkedHashSet<String>()
        val ja4 = LinkedHashMap<String, String?>()
        for (e in entries.values) {
            if (e.validUntil != null && e.validUntil <= now) continue
            domains += e.values.domains
            ips += e.values.ips
            for (fp in e.values.ja4) if (ja4[fp] == null) ja4[fp] = e.label
        }
        return FeedLines(domains.toList(), ips.toList(), ja4.map { (fp, l) -> Ja4.line(fp, l) })
    }

    class FeedLines(val domains: List<String>, val ips: List<String>, val ja4: List<String>) {
        val total: Int get() = domains.size + ips.size + ja4.size
    }

    fun write(file: File) {
        file.bufferedWriter().use { w ->
            w.write("$HEADER\t$fullSyncAt\n")
            for ((id, e) in entries) {
                val values = e.values.domains.map { "d:$it" } + e.values.ips.map { "i:$it" } + e.values.ja4.map { "j:$it" }
                w.write("${id.replace('\t', ' ')}\t${e.version}\t${e.validUntil ?: -1}\t${e.label.orEmpty()}\t${values.joinToString(" ")}\n")
            }
        }
    }

    companion object {
        const val MAX_ENTRIES = 250_000
        private const val HEADER = "#vigil-taxii-state-v1"

        /** Reads a state file; null if missing or not a state file (the caller then does a full sync). */
        fun read(file: File): TaxiiState? {
            if (!file.exists()) return null
            file.bufferedReader().use { r ->
                val head = r.readLine()?.split('\t') ?: return null
                if (head.firstOrNull() != HEADER) return null
                val s = TaxiiState(head.getOrNull(1)?.toLongOrNull() ?: 0)
                r.forEachLine { line ->
                    val f = line.split('\t')
                    if (f.size < 5) return@forEachLine
                    val d = ArrayList<String>()
                    val i = ArrayList<String>()
                    val j = ArrayList<String>()
                    for (v in f[4].split(' ')) when {
                        v.startsWith("d:") -> d += v.substring(2)
                        v.startsWith("i:") -> i += v.substring(2)
                        v.startsWith("j:") -> j += v.substring(2)
                    }
                    s.entries[f[0]] = Entry(f[1].toLongOrNull() ?: 0, f[2].toLongOrNull()?.takeIf { it >= 0 }, f[3].ifEmpty { null }, IndicatorValues(d, i, j))
                }
                return s
            }
        }
    }
}
