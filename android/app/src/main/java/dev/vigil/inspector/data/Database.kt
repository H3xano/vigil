package dev.vigil.inspector.data

import android.content.Context
import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Upsert
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.flow.Flow

@Entity(
    tableName = "flows",
    // No index on domain: searches use leading-wildcard LIKE, which cannot use one.
    indices = [Index(value = ["session", "engineId"], unique = true), Index("ts"), Index(value = ["pkg", "ts"]), Index("endTs")],
)
data class FlowEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    /** Engine session (start time); engine flow ids restart every session. */
    val session: Long,
    val engineId: Long,
    val ts: Long,
    val endTs: Long? = null,
    val proto: String,
    val uid: Int?,
    val pkg: String,
    val src: String,
    val dstIp: String,
    val dstPort: Int,
    val domain: String?,
    val domainSource: String?,
    val appProto: String?,
    val alpn: String?,
    val tlsVersion: String?,
    val ja4: String?,
    val ech: Boolean,
    val httpMethod: String?,
    val verdict: String,
    val reason: String?,
    /** Comma-separated tags. */
    val tags: String,
    val tx: Long = 0,
    val rx: Long = 0,
    val durationMs: Long? = null,
    val error: String? = null,
    /** null = unknown (usage access not granted). */
    val background: Boolean? = null,
    /** Feed that lists [ja4] (engine `ja4_match.feed`); null if not listed. */
    val ja4Feed: String? = null,
    /** That feed's label for the fingerprint, e.g. a malware family. */
    val ja4Label: String? = null,
    /** Upstream path of the connection (engine `via`): "direct", "wireguard", "socks5"; null if none was made. */
    val via: String? = null,
    /** Autonomous system of [dstIp] (engine `asn`); null when unknown or no ASN table is loaded. */
    val asn: Long? = null,
    val asnName: String? = null,
    /** Country code of the AS registration (not a geolocation of the address). */
    val asnCountry: String? = null,
) {
    val destination: String get() = domain ?: dstIp
    val isBlocked: Boolean get() = verdict == "block"
    val isActive: Boolean get() = endTs == null
    val tagList: List<String> get() = if (tags.isEmpty()) emptyList() else tags.split(',')
}

@Entity(tableName = "dns_queries", indices = [Index("ts"), Index(value = ["pkg", "ts"])])
data class DnsEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val ts: Long,
    val uid: Int?,
    val pkg: String,
    val qname: String,
    val qtype: String,
    val rcode: String,
    val answers: String,
    val verdict: String,
    val reason: String?,
    val latencyMs: Long,
    val server: String,
    val transport: String,
    /** How vigil reached the resolver (engine `upstream`): "udp", "tcp", "dot", "doh"; null if none was asked. */
    val upstream: String? = null,
) {
    val isBlocked: Boolean get() = verdict == "block"
}

@Entity(tableName = "alerts", indices = [Index("ts"), Index("pkg")])
data class AlertEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val ts: Long,
    val kind: String,
    val severity: String,
    val uid: Int?,
    val pkg: String,
    val target: String,
    val message: String,
    val detail: String,
    val seen: Boolean = false,
)

/**
 * (app, destination) pairs observed, for novelty alerts. Kept longer than the
 * history tables (see VigilApp.pruneOldData) so learning survives retention.
 */
@Entity(tableName = "destinations", primaryKeys = ["pkg", "destination"])
data class DestinationEntity(
    val pkg: String,
    val destination: String,
    val firstSeen: Long,
    val lastSeen: Long,
    val flows: Long,
)

/**
 * (app, autonomous system) pairs observed, for "new network" alerts. Pruned
 * like [DestinationEntity], so learning survives the history retention.
 */
@Entity(tableName = "app_asns", primaryKeys = ["pkg", "asn"])
data class AppAsnEntity(
    val pkg: String,
    val asn: Long,
    val firstSeen: Long,
    val lastSeen: Long,
    val flows: Long,
)

@Entity(tableName = "feeds")
data class FeedEntity(
    @PrimaryKey val id: String,
    val name: String,
    val url: String,
    val category: String,
    val enabled: Boolean,
    val builtin: Boolean,
    val description: String = "",
    /** Sent as the Authorization header (e.g. MISP API key). */
    val authHeader: String? = null,
    val lastUpdated: Long? = null,
    val domains: Int = 0,
    val ipRanges: Int = 0,
    val lastError: String? = null,
    /** [FeedKinds]: what the source is and what the file may contain. */
    @ColumnInfo(defaultValue = FeedKinds.LIST) val kind: String = FeedKinds.LIST,
    /** Download format converted to the line format (see [Ja4Converters]); "text" needs none. */
    @ColumnInfo(defaultValue = Ja4Converters.FORMAT_TEXT) val format: String = Ja4Converters.FORMAT_TEXT,
    /** JA4 fingerprints in the downloaded copy. */
    @ColumnInfo(defaultValue = "0") val ja4: Int = 0,
    /** Header carrying [authHeader]; null means `Authorization`. */
    val authHeaderName: String? = null,
    /** TAXII: collection id ([url] is the API root). */
    val taxiiCollection: String? = null,
    /** TAXII: `added_after` for the next incremental poll (server timestamp). */
    val taxiiAddedAfter: String? = null,
) {
    val isTaxii: Boolean get() = kind == FeedKinds.TAXII
    val entries: Int get() = domains + ipRanges + ja4
}

/** Values of [FeedEntity.kind]. */
object FeedKinds {
    /** A downloaded list of domains and/or IP ranges (JA4 lines are matched too). */
    const val LIST = "list"

    /** A downloaded list of JA4 fingerprints (engine category `ja4`). */
    const val JA4 = "ja4"

    /** A TAXII 2.1 collection polled incrementally; may hold domains, IPs and JA4. */
    const val TAXII = "taxii"

    /** An IP-to-ASN table (engine category `asn`): enriches connections, never blocks. */
    const val ASN = "asn"
}

data class AppUsage(
    val pkg: String,
    val uid: Int?,
    val flows: Long,
    val blocked: Long,
    val tx: Long,
    val rx: Long,
    val destinations: Long,
    val lastSeen: Long,
)

data class DestinationUsage(
    val destination: String,
    val flows: Long,
    val bytes: Long,
    val blocked: Long,
    val firstSeen: Long,
    val lastSeen: Long,
    /** Distinct AS numbers of the destination's addresses, comma-separated (null if none known). */
    val asns: String? = null,
    /** The AS name when all connections went to one AS. */
    val asnName: String? = null,
)

data class NameCount(val name: String, val hits: Long)

data class Totals(
    val flows: Long,
    val blocked: Long,
    val tx: Long,
    val rx: Long,
)

@Dao
interface FlowDao {
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(flows: List<FlowEntity>)

    @Query("UPDATE flows SET endTs = :endTs, tx = :tx, rx = :rx, durationMs = :durationMs, error = :error WHERE session = :session AND engineId = :engineId")
    suspend fun finish(session: Long, engineId: Long, endTs: Long, tx: Long, rx: Long, durationMs: Long, error: String?)

    @Query("UPDATE flows SET tx = :tx, rx = :rx WHERE session = :session AND engineId = :engineId")
    suspend fun progress(session: Long, engineId: Long, tx: Long, rx: Long)

    /** Flows left open by a previous session that ended abruptly. */
    @Query("UPDATE flows SET endTs = ts, error = 'session ended' WHERE endTs IS NULL AND session != :current")
    suspend fun closeStale(current: Long)

    @Query(
        """SELECT * FROM flows WHERE (:query = '' OR domain LIKE '%' || $LIKE_ARG || '%' ESCAPE '\' OR dstIp LIKE $LIKE_ARG || '%' ESCAPE '\'
             OR pkg LIKE '%' || $LIKE_ARG || '%' ESCAPE '\' OR asnName LIKE '%' || $LIKE_ARG || '%' ESCAPE '\' OR 'AS' || asn = upper(:query))
           AND (:blockedOnly = 0 OR verdict = 'block')
           AND (:path = '' OR (:path = 'direct' AND via = 'direct') OR (:path = 'tunnel' AND via IS NOT NULL AND via != 'direct'))
           ORDER BY ts DESC LIMIT :limit""",
    )
    fun recent(query: String, blockedOnly: Boolean, limit: Int = 500, path: String = PathFilter.ALL): Flow<List<FlowEntity>>

    @Query("SELECT * FROM flows WHERE id = :id")
    fun byId(id: Long): Flow<FlowEntity?>

    @Query("SELECT * FROM flows WHERE pkg = :pkg ORDER BY ts DESC LIMIT :limit")
    fun byPackage(pkg: String, limit: Int = 200): Flow<List<FlowEntity>>

    @Query(
        """SELECT pkg, MAX(uid) AS uid, COUNT(*) AS flows, SUM(verdict = 'block') AS blocked, SUM(tx) AS tx, SUM(rx) AS rx,
           COUNT(DISTINCT COALESCE(domain, dstIp)) AS destinations, MAX(ts) AS lastSeen
           FROM flows WHERE ts >= :since GROUP BY pkg ORDER BY (SUM(tx) + SUM(rx)) DESC, flows DESC""",
    )
    fun appUsage(since: Long): Flow<List<AppUsage>>

    @Query(
        """SELECT COALESCE(domain, dstIp) AS destination, COUNT(*) AS flows, SUM(tx + rx) AS bytes, SUM(verdict = 'block') AS blocked,
           MIN(ts) AS firstSeen, MAX(ts) AS lastSeen, GROUP_CONCAT(DISTINCT asn) AS asns,
           CASE WHEN COUNT(DISTINCT asn) = 1 THEN MAX(asnName) END AS asnName FROM flows WHERE pkg = :pkg AND ts >= :since
           GROUP BY destination ORDER BY lastSeen DESC""",
    )
    fun destinationsFor(pkg: String, since: Long): Flow<List<DestinationUsage>>

    @Query("SELECT COUNT(*) AS flows, COALESCE(SUM(verdict = 'block'), 0) AS blocked, COALESCE(SUM(tx), 0) AS tx, COALESCE(SUM(rx), 0) AS rx FROM flows WHERE ts >= :since")
    fun totals(since: Long): Flow<Totals>

    @Query("SELECT COUNT(*) FROM flows WHERE endTs IS NULL")
    fun activeCount(): Flow<Int>

    /** Closes rows of [session] still open (their `flow_end` was lost or never came). */
    @Query("UPDATE flows SET endTs = MAX(ts, :now), durationMs = MAX(0, :now - ts), error = COALESCE(error, 'session ended') WHERE session = :session AND endTs IS NULL")
    suspend fun closeSession(session: Long, now: Long)

    /** Deletes at most [limit] rows older than [before]; call until it returns less than [limit]. */
    @Query("DELETE FROM flows WHERE id IN (SELECT id FROM flows WHERE ts < :before LIMIT :limit)")
    suspend fun deleteBefore(before: Long, limit: Int): Int

    @Query("DELETE FROM flows")
    suspend fun clear()
}

@Dao
interface DnsDao {
    @Insert
    suspend fun insert(rows: List<DnsEntity>)

    @Query(
        """SELECT * FROM dns_queries WHERE (:query = '' OR qname LIKE '%' || $LIKE_ARG || '%' ESCAPE '\' OR pkg LIKE '%' || $LIKE_ARG || '%' ESCAPE '\')
           AND (:blockedOnly = 0 OR verdict = 'block') ORDER BY ts DESC LIMIT :limit""",
    )
    fun recent(query: String, blockedOnly: Boolean, limit: Int = 500): Flow<List<DnsEntity>>

    @Query("SELECT * FROM dns_queries WHERE pkg = :pkg ORDER BY ts DESC LIMIT :limit")
    fun byPackage(pkg: String, limit: Int = 200): Flow<List<DnsEntity>>

    @Query("SELECT qname AS name, COUNT(*) AS hits FROM dns_queries WHERE verdict = 'block' AND ts >= :since GROUP BY qname ORDER BY hits DESC LIMIT :limit")
    fun topBlocked(since: Long, limit: Int = 8): Flow<List<NameCount>>

    @Query("SELECT COUNT(*) FROM dns_queries WHERE ts >= :since")
    fun countSince(since: Long): Flow<Long>

    @Query("SELECT COUNT(*) FROM dns_queries WHERE ts >= :since AND verdict = 'block'")
    fun blockedSince(since: Long): Flow<Long>

    @Query("DELETE FROM dns_queries WHERE id IN (SELECT id FROM dns_queries WHERE ts < :before LIMIT :limit)")
    suspend fun deleteBefore(before: Long, limit: Int): Int

    @Query("DELETE FROM dns_queries")
    suspend fun clear()
}

@Dao
interface AlertDao {
    @Insert
    suspend fun insert(rows: List<AlertEntity>)

    @Query("SELECT * FROM alerts ORDER BY ts DESC LIMIT :limit")
    fun recent(limit: Int = 500): Flow<List<AlertEntity>>

    @Query("SELECT * FROM alerts WHERE pkg = :pkg ORDER BY ts DESC LIMIT 100")
    fun byPackage(pkg: String): Flow<List<AlertEntity>>

    @Query("SELECT COUNT(*) FROM alerts WHERE seen = 0")
    fun unseenCount(): Flow<Int>

    @Query("UPDATE alerts SET seen = 1 WHERE seen = 0")
    suspend fun markAllSeen()

    @Query("UPDATE alerts SET seen = 1 WHERE id = :id AND seen = 0")
    suspend fun markSeen(id: Long)

    @Query("DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE ts < :before LIMIT :limit)")
    suspend fun deleteBefore(before: Long, limit: Int): Int

    @Query("DELETE FROM alerts")
    suspend fun clear()
}

@Dao
interface DestinationDao {
    @Query("SELECT * FROM destinations WHERE pkg = :pkg AND destination = :destination")
    suspend fun get(pkg: String, destination: String): DestinationEntity?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIfAbsent(rows: List<DestinationEntity>)

    /** Counts [flows] more connections; returns 0 if the pair is not (or no longer) stored. */
    @Query("UPDATE destinations SET flows = flows + :flows, lastSeen = MAX(lastSeen, :lastSeen) WHERE pkg = :pkg AND destination = :destination")
    suspend fun touch(pkg: String, destination: String, lastSeen: Long, flows: Long): Int

    @Query("DELETE FROM destinations WHERE lastSeen < :before")
    suspend fun deleteBefore(before: Long): Int

    @Query("SELECT MIN(firstSeen) FROM destinations WHERE pkg = :pkg")
    suspend fun firstSeenApp(pkg: String): Long?

    @Query("DELETE FROM destinations")
    suspend fun clear()
}

@Dao
interface AppAsnDao {
    @Query("SELECT * FROM app_asns WHERE pkg = :pkg AND asn = :asn")
    suspend fun get(pkg: String, asn: Long): AppAsnEntity?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIfAbsent(rows: List<AppAsnEntity>)

    /** Counts [flows] more connections; returns 0 if the pair is not (or no longer) stored. */
    @Query("UPDATE app_asns SET flows = flows + :flows, lastSeen = MAX(lastSeen, :lastSeen) WHERE pkg = :pkg AND asn = :asn")
    suspend fun touch(pkg: String, asn: Long, lastSeen: Long, flows: Long): Int

    /** When vigil first recorded a network for [pkg]: the start of its learning period. */
    @Query("SELECT MIN(firstSeen) FROM app_asns WHERE pkg = :pkg")
    suspend fun firstSeenApp(pkg: String): Long?

    @Query("SELECT COUNT(*) FROM app_asns WHERE pkg = :pkg")
    suspend fun countFor(pkg: String): Int

    @Query("DELETE FROM app_asns WHERE lastSeen < :before")
    suspend fun deleteBefore(before: Long): Int

    @Query("DELETE FROM app_asns")
    suspend fun clear()
}

@Dao
interface FeedDao {
    @Query("SELECT * FROM feeds ORDER BY builtin DESC, category, name")
    fun all(): Flow<List<FeedEntity>>

    @Query("SELECT * FROM feeds")
    suspend fun list(): List<FeedEntity>

    @Query("SELECT * FROM feeds WHERE id = :id")
    suspend fun get(id: String): FeedEntity?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIfAbsent(rows: List<FeedEntity>)

    @Upsert
    suspend fun upsert(row: FeedEntity)

    @Query("UPDATE feeds SET enabled = :enabled WHERE id = :id")
    suspend fun setEnabled(id: String, enabled: Boolean)

    /** Targeted updates: unlike an upsert they cannot resurrect a feed deleted meanwhile. Return the rows changed. */
    @Query("UPDATE feeds SET lastUpdated = :ts, domains = :domains, ipRanges = :ipRanges, ja4 = :ja4, lastError = NULL WHERE id = :id")
    suspend fun markUpdated(id: String, ts: Long, domains: Int, ipRanges: Int, ja4: Int): Int

    @Query("UPDATE feeds SET taxiiAddedAfter = :addedAfter WHERE id = :id")
    suspend fun setTaxiiAddedAfter(id: String, addedAfter: String?): Int

    @Query("UPDATE feeds SET lastError = :error WHERE id = :id")
    suspend fun markError(id: String, error: String): Int

    /** The downloaded copy was deleted (feed disabled). */
    @Query("UPDATE feeds SET lastUpdated = NULL, domains = 0, ipRanges = 0, ja4 = 0, taxiiAddedAfter = NULL, lastError = NULL WHERE id = :id")
    suspend fun clearDownload(id: String)

    @Query("DELETE FROM feeds WHERE id = :id AND builtin = 0")
    suspend fun deleteCustom(id: String)
}

@Database(
    entities = [FlowEntity::class, DnsEntity::class, AlertEntity::class, DestinationEntity::class, FeedEntity::class, AppAsnEntity::class],
    version = 4,
    exportSchema = true,
)
abstract class VigilDatabase : RoomDatabase() {
    abstract fun flows(): FlowDao
    abstract fun dns(): DnsDao
    abstract fun alerts(): AlertDao
    abstract fun destinations(): DestinationDao
    abstract fun feeds(): FeedDao
    abstract fun appAsns(): AppAsnDao

    companion object {
        fun create(context: Context): VigilDatabase =
            Room.databaseBuilder(context, VigilDatabase::class.java, "vigil.db")
                .setJournalMode(JournalMode.WRITE_AHEAD_LOGGING)
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
                .build()

        /**
         * Index changes only. Written by hand because Room's AutoMigration
         * would copy both tables to drop an index.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                for (sql in MIGRATION_1_2_SQL) db.execSQL(sql)
            }
        }

        /** JA4 match columns on flows; feed kind, format, JA4 count and TAXII state on feeds. */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                for (sql in MIGRATION_2_3_SQL) db.execSQL(sql)
            }
        }

        /** Path and ASN columns on flows, the DNS upstream transport, and the app_asns table. */
        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                for (sql in MIGRATION_3_4_SQL) db.execSQL(sql)
            }
        }

        val MIGRATION_3_4_SQL = listOf(
            "ALTER TABLE `flows` ADD COLUMN `via` TEXT",
            "ALTER TABLE `flows` ADD COLUMN `asn` INTEGER",
            "ALTER TABLE `flows` ADD COLUMN `asnName` TEXT",
            "ALTER TABLE `flows` ADD COLUMN `asnCountry` TEXT",
            "ALTER TABLE `dns_queries` ADD COLUMN `upstream` TEXT",
            "CREATE TABLE IF NOT EXISTS `app_asns` (`pkg` TEXT NOT NULL, `asn` INTEGER NOT NULL, `firstSeen` INTEGER NOT NULL, " +
                "`lastSeen` INTEGER NOT NULL, `flows` INTEGER NOT NULL, PRIMARY KEY(`pkg`, `asn`))",
        )

        val MIGRATION_2_3_SQL = listOf(
            "ALTER TABLE `flows` ADD COLUMN `ja4Feed` TEXT",
            "ALTER TABLE `flows` ADD COLUMN `ja4Label` TEXT",
            "ALTER TABLE `feeds` ADD COLUMN `kind` TEXT NOT NULL DEFAULT 'list'",
            "ALTER TABLE `feeds` ADD COLUMN `format` TEXT NOT NULL DEFAULT 'text'",
            "ALTER TABLE `feeds` ADD COLUMN `ja4` INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE `feeds` ADD COLUMN `authHeaderName` TEXT",
            "ALTER TABLE `feeds` ADD COLUMN `taxiiCollection` TEXT",
            "ALTER TABLE `feeds` ADD COLUMN `taxiiAddedAfter` TEXT",
        )

        val MIGRATION_1_2_SQL = listOf(
            "DROP INDEX IF EXISTS `index_flows_domain`",
            "DROP INDEX IF EXISTS `index_flows_pkg`",
            "CREATE INDEX IF NOT EXISTS `index_flows_pkg_ts` ON `flows` (`pkg`, `ts`)",
            "CREATE INDEX IF NOT EXISTS `index_flows_endTs` ON `flows` (`endTs`)",
            "DROP INDEX IF EXISTS `index_dns_queries_qname`",
            "DROP INDEX IF EXISTS `index_dns_queries_pkg`",
            "CREATE INDEX IF NOT EXISTS `index_dns_queries_pkg_ts` ON `dns_queries` (`pkg`, `ts`)",
        )
    }
}

/**
 * SQL for the `:query` search term with LIKE wildcards escaped (used with
 * `ESCAPE '\'`), so typing `%` or `_` searches for those characters literally.
 */
private const val LIKE_ARG = """replace(replace(replace(:query, '\', '\\'), '%', '\%'), '_', '\_')"""

/** Values of the Activity "path" filter ([FlowDao.recent]). */
object PathFilter {
    const val ALL = ""
    const val DIRECT = "direct"

    /** Through the WireGuard tunnel or the SOCKS5 proxy. */
    const val TUNNEL = "tunnel"
}

/** Column helper so string constants stay in one place. */
object Verdicts {
    const val ALLOW = "allow"
    const val BLOCK = "block"
}
