package dev.vigil.inspector.data

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.engine.EngineJson
import dev.vigil.inspector.engine.FeedSummary
import dev.vigil.inspector.engine.VigilNative
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

class FeedRepository(private val context: Context, private val dao: FeedDao) {
    private val dir = File(context.filesDir, "feeds").apply { mkdirs() }

    val feeds: Flow<List<FeedEntity>> = dao.all()

    fun fileFor(id: String) = File(dir, "$id.txt")

    suspend fun seedBuiltins() = dao.insertIfAbsent(FeedCatalog.builtin)

    suspend fun setEnabled(id: String, enabled: Boolean) {
        dao.setEnabled(id, enabled)
        if (enabled && !fileFor(id).exists()) scheduleRefreshNow()
    }

    suspend fun addCustom(name: String, url: String, category: String, authHeader: String?): String {
        val id = "custom-" + name.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-').ifEmpty { "feed" } +
            "-" + (System.currentTimeMillis() % 100_000)
        dao.upsert(
            FeedEntity(
                id = id, name = name, url = url, category = category, enabled = true, builtin = false,
                description = "Custom feed", authHeader = authHeader?.takeIf { it.isNotBlank() },
            ),
        )
        scheduleRefreshNow()
        return id
    }

    suspend fun delete(id: String) {
        dao.deleteCustom(id)
        fileFor(id).delete()
    }

    /** Downloads one feed; the previous copy is kept if anything fails. */
    suspend fun refresh(feed: FeedEntity): Result<FeedSummary> = withContext(Dispatchers.IO) {
        val tmp = File(dir, "${feed.id}.tmp")
        val result = runCatching {
            download(feed, tmp)
            val summary = VigilNative.nativeInspectFeedFile(tmp.absolutePath)
                ?.let { EngineJson.json.decodeFromString(FeedSummary.serializer(), it) }
                ?: throw IOException("unreadable feed")
            if (summary.domains == 0 && summary.ipRanges == 0) throw IOException("feed contained no usable entries")
            if (!tmp.renameTo(fileFor(feed.id))) throw IOException("could not store feed")
            summary
        }
        tmp.delete()
        val current = dao.get(feed.id) ?: feed
        result.onSuccess { s ->
            dao.upsert(current.copy(lastUpdated = System.currentTimeMillis(), domains = s.domains, ipRanges = s.ipRanges, lastError = null))
        }.onFailure { e ->
            Log.w(TAG, "feed ${feed.id}: ${e.message}")
            dao.upsert(current.copy(lastError = e.message ?: e.javaClass.simpleName))
        }
        result
    }

    /** Refreshes enabled feeds older than [maxAgeMs]. */
    suspend fun refreshStale(maxAgeMs: Long): Int {
        val now = System.currentTimeMillis()
        var failures = 0
        for (f in dao.list().filter { it.enabled }) {
            val fresh = f.lastUpdated != null && now - f.lastUpdated < maxAgeMs && fileFor(f.id).exists()
            if (!fresh && refresh(f).isFailure) failures++
        }
        return failures
    }

    private fun download(feed: FeedEntity, dest: File) {
        val conn = URL(feed.url).openConnection() as HttpURLConnection
        conn.connectTimeout = 20_000
        conn.readTimeout = 60_000
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("User-Agent", "vigil/${dev.vigil.inspector.BuildConfig.VERSION_NAME} (+feed updater)")
        feed.authHeader?.let { conn.setRequestProperty("Authorization", it) }
        try {
            if (conn.responseCode !in 200..299) throw IOException("HTTP ${conn.responseCode}")
            conn.inputStream.use { input ->
                dest.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_FEED_BYTES) throw IOException("feed larger than ${MAX_FEED_BYTES / 1_000_000} MB")
                        out.write(buf, 0, n)
                    }
                }
            }
        } finally {
            conn.disconnect()
        }
    }

    fun scheduleRefreshNow() {
        WorkManager.getInstance(context).enqueueUniqueWork(
            "feeds-now",
            ExistingWorkPolicy.REPLACE,
            OneTimeWorkRequestBuilder<FeedUpdateWorker>().setConstraints(networkConstraint).build(),
        )
    }

    fun schedulePeriodic() {
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            "feeds-daily",
            ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<FeedUpdateWorker>(24, TimeUnit.HOURS).setConstraints(networkConstraint).build(),
        )
    }

    companion object {
        private const val TAG = "vigil.feeds"
        private const val MAX_FEED_BYTES = 150L * 1024 * 1024
        const val MAX_AGE_MS = 20L * 3600 * 1000
        private val networkConstraint = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
    }
}

class FeedUpdateWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext as VigilApp
        val failures = app.feeds.refreshStale(FeedRepository.MAX_AGE_MS)
        app.pruneOldData()
        return if (failures > 0 && runAttemptCount < 3) Result.retry() else Result.success()
    }
}
