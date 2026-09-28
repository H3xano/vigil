package dev.vigil.inspector.processing

import dev.vigil.inspector.data.AlertEntity
import dev.vigil.inspector.data.AppAsnDao
import dev.vigil.inspector.data.AppAsnEntity
import dev.vigil.inspector.data.AppResolver
import dev.vigil.inspector.data.AsnDatabase
import dev.vigil.inspector.data.FlowEntity
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * "New network for this app": records which autonomous systems (ASNs) each
 * app connects to and, when enabled, raises a `new_asn` alert the first
 * time an app contacts one it has never used, once the app is past its
 * learning period. The learning period starts when vigil first records a
 * network for the app (so it also restarts when the ASN database is first
 * installed, or after "clear history").
 *
 * Alerts are rate limited per app and in total ([MAX_PER_APP_PER_HOUR],
 * [MAX_PER_HOUR]); networks seen while over the limit are learned silently.
 * Runs inside the batch transaction of [EventProcessor].
 */
class NewAsnDetector(
    private val dao: AppAsnDao,
    /** Display name of an app key. */
    private val appLabel: (String) -> String,
) {
    /** (pkg|asn) keys known to be stored in `app_asns`. */
    private val known = object : LinkedHashMap<String, Boolean>(1024, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?) = size > 20_000
    }

    /** Alert times (ms) per app, and overall, for the rate limits. */
    private val perApp = HashMap<String, ArrayDeque<Long>>()
    private val overall = ArrayDeque<Long>()

    /** Networks learned while the rate limit was exhausted (for logs and tests). */
    var suppressed = 0
        private set

    private class Seen(val first: FlowEntity, var count: Long = 0, var minTs: Long = Long.MAX_VALUE, var maxTs: Long = Long.MIN_VALUE)

    suspend fun process(flows: List<FlowEntity>, enabled: Boolean, learningMs: Long): List<AlertEntity> {
        val seen = LinkedHashMap<String, Seen>()
        for (f in flows) {
            val asn = f.asn ?: continue
            if (asn <= 0 || f.pkg == AppResolver.UNKNOWN.key) continue
            val s = seen.getOrPut("${f.pkg}|$asn") { Seen(f) }
            s.count++
            s.minTs = minOf(s.minTs, f.ts)
            s.maxTs = maxOf(s.maxTs, f.ts)
        }
        if (seen.isEmpty()) return emptyList()
        val out = ArrayList<AlertEntity>()
        val inserts = ArrayList<AppAsnEntity>()
        for ((key, s) in seen) {
            val pkg = s.first.pkg
            val asn = s.first.asn ?: continue
            // A cached key can be stale after pruning or "clear history": touch() then changes no row.
            if (known[key] == true && dao.touch(pkg, asn, s.maxTs, s.count) > 0) continue
            if (dao.get(pkg, asn) != null) {
                dao.touch(pkg, asn, s.maxTs, s.count)
                known[key] = true
                continue
            }
            if (enabled) {
                // Networks inserted earlier in this batch are not in the table yet; they count as learned now.
                val appFirstSeen = dao.firstSeenApp(pkg) ?: inserts.filter { it.pkg == pkg }.minOfOrNull { it.firstSeen }
                if (appFirstSeen != null && s.first.ts - appFirstSeen >= learningMs) {
                    if (allow(pkg, s.first.ts)) {
                        val knownCount = dao.countFor(pkg) + inserts.count { it.pkg == pkg }
                        out += alert(s.first, asn, knownCount)
                    } else {
                        suppressed++
                    }
                }
            }
            inserts += AppAsnEntity(pkg = pkg, asn = asn, firstSeen = s.minTs, lastSeen = s.maxTs, flows = s.count)
            known[key] = true
        }
        if (inserts.isNotEmpty()) dao.insertIfAbsent(inserts)
        return out
    }

    private fun alert(f: FlowEntity, asn: Long, knownCount: Int): AlertEntity {
        val network = AsnDatabase.label(asn, null)!!
        val name = AsnDatabase.displayName(f.asnName)
        val where = f.domain ?: f.dstIp
        val detail = JsonObject(
            listOfNotNull(
                "asn" to JsonPrimitive(asn),
                f.asnName?.let { "as_name" to JsonPrimitive(it) },
                f.asnCountry?.let { "as_country" to JsonPrimitive(it) },
                "destination" to JsonPrimitive(where),
                "dst_ip" to JsonPrimitive(f.dstIp),
                "known_networks" to JsonPrimitive(knownCount),
            ).toMap(),
        )
        return AlertEntity(
            ts = f.ts, kind = KIND, severity = if (knownCount <= FEW_NETWORKS) "medium" else "low", uid = f.uid, pkg = f.pkg,
            target = network,
            message = "${appLabel(f.pkg)} contacted a network it has never used before: $network" +
                (name?.let { " ($it)" } ?: "") + ", reached as $where",
            detail = detail.toString(),
        )
    }

    private fun allow(pkg: String, now: Long): Boolean {
        val times = perApp.getOrPut(pkg) { ArrayDeque() }
        for (q in listOf(times, overall)) while (q.isNotEmpty() && now - q.first() >= HOUR_MS) q.removeFirst()
        if (times.size >= MAX_PER_APP_PER_HOUR || overall.size >= MAX_PER_HOUR) return false
        times.addLast(now)
        overall.addLast(now)
        if (perApp.size > 1_000) perApp.entries.removeAll { it.value.isEmpty() }
        return true
    }

    companion object {
        const val KIND = "new_asn"
        const val DAY_MS = 86_400_000L
        const val HOUR_MS = 3_600_000L
        const val MAX_PER_APP_PER_HOUR = 5
        const val MAX_PER_HOUR = 30

        /** Apps that used at most this many networks so far get a medium-severity alert (they are predictable). */
        const val FEW_NETWORKS = 3

        fun learningMs(days: Int) = days.coerceIn(0, 90) * DAY_MS
    }
}
