package dev.vigil.inspector.data

import android.content.Context
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
import kotlinx.coroutines.flow.Flow

@Entity(
    tableName = "flows",
    indices = [Index(value = ["session", "engineId"], unique = true), Index("ts"), Index("pkg"), Index("domain")],
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
) {
    val destination: String get() = domain ?: dstIp
    val isBlocked: Boolean get() = verdict == "block"
    val isActive: Boolean get() = endTs == null
    val tagList: List<String> get() = if (tags.isEmpty()) emptyList() else tags.split(',')
}

@Entity(tableName = "dns_queries", indices = [Index("ts"), Index("pkg"), Index("qname")])
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

/** Every (app, destination) pair ever observed; survives retention pruning. */
@Entity(tableName = "destinations", primaryKeys = ["pkg", "destination"])
data class DestinationEntity(
    val pkg: String,
    val destination: String,
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
)

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
        """SELECT * FROM flows WHERE (:query = '' OR domain LIKE '%' || :query || '%' OR dstIp LIKE :query || '%' OR pkg LIKE '%' || :query || '%')
           AND (:blockedOnly = 0 OR verdict = 'block') ORDER BY ts DESC LIMIT :limit""",
    )
    fun recent(query: String, blockedOnly: Boolean, limit: Int = 500): Flow<List<FlowEntity>>

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
           MIN(ts) AS firstSeen, MAX(ts) AS lastSeen FROM flows WHERE pkg = :pkg AND ts >= :since
           GROUP BY destination ORDER BY lastSeen DESC""",
    )
    fun destinationsFor(pkg: String, since: Long): Flow<List<DestinationUsage>>

    @Query("SELECT COUNT(*) AS flows, COALESCE(SUM(verdict = 'block'), 0) AS blocked, COALESCE(SUM(tx), 0) AS tx, COALESCE(SUM(rx), 0) AS rx FROM flows WHERE ts >= :since")
    fun totals(since: Long): Flow<Totals>

    @Query("SELECT COUNT(*) FROM flows WHERE endTs IS NULL")
    fun activeCount(): Flow<Int>

    @Query("DELETE FROM flows WHERE ts < :before")
    suspend fun deleteBefore(before: Long): Int

    @Query("DELETE FROM flows")
    suspend fun clear()
}

@Dao
interface DnsDao {
    @Insert
    suspend fun insert(rows: List<DnsEntity>)

    @Query(
        """SELECT * FROM dns_queries WHERE (:query = '' OR qname LIKE '%' || :query || '%' OR pkg LIKE '%' || :query || '%')
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

    @Query("DELETE FROM dns_queries WHERE ts < :before")
    suspend fun deleteBefore(before: Long): Int

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

    @Query("DELETE FROM alerts WHERE ts < :before")
    suspend fun deleteBefore(before: Long): Int

    @Query("DELETE FROM alerts")
    suspend fun clear()
}

@Dao
interface DestinationDao {
    @Query("SELECT * FROM destinations WHERE pkg = :pkg AND destination = :destination")
    suspend fun get(pkg: String, destination: String): DestinationEntity?

    @Upsert
    suspend fun upsert(rows: List<DestinationEntity>)

    @Query("SELECT MIN(firstSeen) FROM destinations WHERE pkg = :pkg")
    suspend fun firstSeenApp(pkg: String): Long?

    @Query("DELETE FROM destinations")
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

    @Query("DELETE FROM feeds WHERE id = :id AND builtin = 0")
    suspend fun deleteCustom(id: String)
}

@Database(
    entities = [FlowEntity::class, DnsEntity::class, AlertEntity::class, DestinationEntity::class, FeedEntity::class],
    version = 1,
    exportSchema = true,
)
abstract class VigilDatabase : RoomDatabase() {
    abstract fun flows(): FlowDao
    abstract fun dns(): DnsDao
    abstract fun alerts(): AlertDao
    abstract fun destinations(): DestinationDao
    abstract fun feeds(): FeedDao

    companion object {
        fun create(context: Context): VigilDatabase =
            Room.databaseBuilder(context, VigilDatabase::class.java, "vigil.db")
                .setJournalMode(JournalMode.WRITE_AHEAD_LOGGING)
                .build()
    }
}

/** Column helper so string constants stay in one place. */
object Verdicts {
    const val ALLOW = "allow"
    const val BLOCK = "block"
}
