package dev.vigil.inspector.data

import androidx.room.Dao
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/** Connections and lookups of one app to one name in a time window. */
data class DomainHits(
    val pkg: String,
    val name: String,
    val flows: Long,
    val lookups: Long,
    /** Blocked connections plus sinkholed lookups. */
    val blocked: Long,
)

/** An (app, name) pair seen in a time window. */
data class AppDomain(val pkg: String, val name: String)

/**
 * Read-only queries behind the tracker summaries. Tracker labels are applied
 * when displaying (no column stores them), so these return plain names.
 */
@Dao
interface TrackerUsageDao {
    /** Per name contacted by [pkg] since [since]: connections (with a name) and DNS lookups. */
    @Query(
        """SELECT pkg, name, SUM(flows) AS flows, SUM(lookups) AS lookups, SUM(blocked) AS blocked FROM (
             SELECT pkg, domain AS name, COUNT(*) AS flows, 0 AS lookups, SUM(verdict = 'block') AS blocked
               FROM flows WHERE pkg = :pkg AND ts >= :since AND domain IS NOT NULL GROUP BY pkg, domain
             UNION ALL
             SELECT pkg, qname AS name, 0 AS flows, COUNT(*) AS lookups, SUM(verdict = 'block') AS blocked
               FROM dns_queries WHERE pkg = :pkg AND ts >= :since GROUP BY pkg, qname
           ) GROUP BY pkg, name""",
    )
    fun domainsFor(pkg: String, since: Long): Flow<List<DomainHits>>

    /**
     * Every (app, name) pair since [since]: named connections from the small
     * learned-destinations table, plus DNS lookups (sinkholed trackers never connect).
     */
    @Query(
        """SELECT pkg, destination AS name FROM destinations WHERE lastSeen >= :since
           UNION
           SELECT pkg, qname AS name FROM dns_queries WHERE ts >= :since""",
    )
    fun appDomains(since: Long): Flow<List<AppDomain>>
}

/** One tracker domain an app contacted. */
data class TrackerDomainHits(val domain: String, val tracker: Tracker, val flows: Long, val lookups: Long, val blocked: Long) {
    val total: Long get() = flows + lookups
}

/** The tracker domains of one company that an app contacted. */
data class CompanyHits(
    val company: String,
    val website: String?,
    /** Category keys, tracking ones first. */
    val categories: List<String>,
    val tracking: Boolean,
    /** Tracking domains first, then by connections + lookups. */
    val domains: List<TrackerDomainHits>,
) {
    val flows: Long get() = domains.sumOf { it.flows }
    val lookups: Long get() = domains.sumOf { it.lookups }
    val blocked: Long get() = domains.sumOf { it.blocked }
    val total: Long get() = flows + lookups

    /** Everything to this company was blocked or sinkholed. */
    val allBlocked: Boolean get() = total > 0 && blocked >= total
}

/** A company across apps (the Overview card). */
data class CompanyApps(val company: String, val categories: List<String>, val apps: Int)

/** Pure aggregation of labelled names; unit-tested. */
object TrackerSummaries {
    /**
     * Groups [hits] by tracker company: tracking companies first, then by
     * connections + lookups. Names without a label are left out.
     */
    fun byCompany(index: TrackerIndex, hits: List<DomainHits>): List<CompanyHits> {
        val perDomain = LinkedHashMap<String, TrackerDomainHits>()
        for (h in hits) {
            val m = index.match(h.name) ?: continue
            val key = TrackerIndex.normalize(h.name) ?: continue
            val prev = perDomain[key]
            perDomain[key] = if (prev == null) {
                TrackerDomainHits(key, m.tracker, h.flows, h.lookups, h.blocked)
            } else {
                prev.copy(flows = prev.flows + h.flows, lookups = prev.lookups + h.lookups, blocked = prev.blocked + h.blocked)
            }
        }
        return perDomain.values.groupBy { it.tracker.company }.map { (company, domains) ->
            CompanyHits(
                company = company,
                website = domains.firstNotNullOfOrNull { it.tracker.companyWebsite },
                categories = sortedCategories(domains.map { it.tracker.category }),
                tracking = domains.any { it.tracker.isTracking },
                domains = domains.sortedWith(
                    compareByDescending<TrackerDomainHits> { it.tracker.isTracking }.thenByDescending { it.total }.thenBy { it.domain },
                ),
            )
        }.sortedWith(compareByDescending<CompanyHits> { it.tracking }.thenByDescending { it.total }.thenBy { it.company.lowercase() })
    }

    /** Distinct tracking trackers (advertising, analytics, telemetry, social) contacted per app. */
    fun trackerCountsByApp(index: TrackerIndex, pairs: List<AppDomain>): Map<String, Int> {
        val perApp = HashMap<String, HashSet<String>>()
        for (p in pairs) {
            val t = index.match(p.name)?.tracker ?: continue
            if (!t.isTracking) continue
            perApp.getOrPut(p.pkg) { HashSet() } += t.id
        }
        return perApp.mapValues { it.value.size }
    }

    /** Tracking companies ranked by the number of apps that contacted them. */
    fun topCompanies(index: TrackerIndex, pairs: List<AppDomain>, limit: Int = 5): List<CompanyApps> {
        val apps = HashMap<String, HashSet<String>>()
        val categories = HashMap<String, HashSet<String>>()
        for (p in pairs) {
            val t = index.match(p.name)?.tracker ?: continue
            if (!t.isTracking) continue
            apps.getOrPut(t.company) { HashSet() } += p.pkg
            categories.getOrPut(t.company) { HashSet() } += t.category
        }
        return apps.map { (company, pkgs) -> CompanyApps(company, sortedCategories(categories[company].orEmpty()), pkgs.size) }
            .sortedWith(compareByDescending<CompanyApps> { it.apps }.thenBy { it.company.lowercase() })
            .take(limit)
    }

    private fun sortedCategories(keys: Collection<String>): List<String> =
        keys.distinct().sortedWith(compareByDescending<String> { TrackerDatabase.isTrackingCategory(it) }.thenBy { it })
}
