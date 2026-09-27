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
import androidx.work.workDataOf
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.engine.EngineJson
import dev.vigil.inspector.engine.FeedSummary
import dev.vigil.inspector.engine.VigilNative
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit
import kotlin.coroutines.coroutineContext

class FeedRepository(private val context: Context, private val dao: FeedDao) {
    private val dir = File(context.filesDir, "feeds").apply { mkdirs() }

    val feeds: Flow<List<FeedEntity>> = dao.all()

    fun fileFor(id: String) = File(dir, "$id.txt")

    suspend fun seedBuiltins() = dao.insertIfAbsent(FeedCatalog.builtin)

    /**
     * Disabling deletes the downloaded copy (the service unloads the feed from
     * the engine because it is no longer enabled); enabling downloads it.
     */
    suspend fun setEnabled(id: String, enabled: Boolean) {
        dao.setEnabled(id, enabled)
        if (enabled) {
            if (!fileFor(id).exists()) scheduleRefreshNow(force = false)
        } else {
            fileFor(id).delete()
            dao.clearDownload(id)
        }
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
        scheduleRefreshNow(force = false)
        return id
    }

    suspend fun delete(id: String) {
        dao.deleteCustom(id)
        fileFor(id).delete()
    }

    /** Downloads one feed; the previous copy is kept if anything fails. */
    suspend fun refresh(feed: FeedEntity): Result<FeedSummary> = refreshLock.withLock { refreshLocked(feed) }

    private suspend fun refreshLocked(feed: FeedEntity): Result<FeedSummary> = withContext(Dispatchers.IO) {
        // Unique name: a crashed or cancelled run can never collide with this one.
        val tmp = File.createTempFile("${feed.id}-", ".tmp", dir)
        val target = fileFor(feed.id)
        val result = try {
            download(feed, tmp)
            val summary = VigilNative.nativeInspectFeedFile(tmp.absolutePath)
                ?.let { EngineJson.json.decodeFromString(FeedSummary.serializer(), it) }
                ?: throw IOException("unreadable feed")
            val previous = if (feed.lastUpdated != null && target.exists()) feed.domains + feed.ipRanges else null
            FeedValidation.check(summary, previous)?.let { throw IOException(it) }
            if (!tmp.renameTo(target)) throw IOException("could not store feed")
            Result.success(summary)
        } catch (e: CancellationException) {
            throw e
        } catch (e: IOException) {
            Result.failure(e)
        } catch (e: RuntimeException) {
            Result.failure(e)
        } finally {
            tmp.delete()
        }
        ensureActive() // a cancelled download fails with a socket error; don't record that as the feed's error
        result.onSuccess { s ->
            // Targeted update: a feed deleted or disabled during the download must not come back.
            val current = dao.get(feed.id)
            if (current == null || !current.enabled) {
                target.delete()
                if (current != null) dao.clearDownload(feed.id)
                return@withContext Result.failure(IOException("feed was removed or disabled during the download"))
            }
            dao.markUpdated(feed.id, System.currentTimeMillis(), s.domains, s.ipRanges)
        }.onFailure { e ->
            Log.w(TAG, "feed ${feed.id}: ${e.message}")
            dao.markError(feed.id, e.message ?: e.javaClass.simpleName)
        }
        result
    }

    /**
     * Refreshes enabled feeds older than [maxAgeMs], or all enabled feeds when
     * [force] is set. Runs are serialised process-wide, so the daily job and a
     * "refresh now" can never download the same feed concurrently.
     */
    suspend fun refreshStale(maxAgeMs: Long, force: Boolean = false): Int = refreshLock.withLock {
        // Leftovers of a run killed mid-download (safe: we hold the lock).
        dir.listFiles { f -> f.name.endsWith(".tmp") }?.forEach { it.delete() }
        val now = System.currentTimeMillis()
        var failures = 0
        for (f in dao.list().filter { it.enabled }) {
            coroutineContext.ensureActive()
            val fresh = !force && f.lastUpdated != null && now - f.lastUpdated < maxAgeMs && fileFor(f.id).exists()
            if (!fresh && refreshLocked(f).isFailure) failures++
        }
        failures
    }

    /** Blocking download that still honours cancellation (WorkManager stop, REPLACE). */
    private suspend fun download(feed: FeedEntity, dest: File) = coroutineScope {
        val conn = URL(feed.url).openConnection() as HttpURLConnection
        conn.connectTimeout = 20_000
        conn.readTimeout = 60_000
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("User-Agent", "vigil/${dev.vigil.inspector.BuildConfig.VERSION_NAME} (+feed updater)")
        feed.authHeader?.let { conn.setRequestProperty("Authorization", it) }
        // Disconnecting from another thread unblocks a read stuck in the socket.
        val watchdog = launch(Dispatchers.IO) {
            try {
                awaitCancellation()
            } finally {
                conn.disconnect()
            }
        }
        try {
            if (conn.responseCode !in 200..299) throw IOException("HTTP ${conn.responseCode}")
            conn.inputStream.use { input ->
                dest.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        ensureActive()
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_FEED_BYTES) throw IOException("feed larger than ${MAX_FEED_BYTES / 1_000_000} MB")
                        out.write(buf, 0, n)
                    }
                }
            }
        } finally {
            watchdog.cancel()
        }
        ensureActive()
    }

    /**
     * Downloads feeds now. With [force] (the user's explicit "Refresh"),
     * every enabled feed is downloaded again; otherwise only missing or stale
     * ones. Requests queue behind a running one instead of cancelling it.
     */
    fun scheduleRefreshNow(force: Boolean = true) {
        WorkManager.getInstance(context).enqueueUniqueWork(
            "feeds-now",
            ExistingWorkPolicy.APPEND_OR_REPLACE,
            OneTimeWorkRequestBuilder<FeedUpdateWorker>()
                .setConstraints(networkConstraint)
                .setInputData(workDataOf(FeedUpdateWorker.KEY_FORCE to force))
                .build(),
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

        /** Process-wide: serialises every feed download and the files it replaces. */
        private val refreshLock = Mutex()
    }
}

class FeedUpdateWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext as VigilApp
        // A retry after partial failure only fetches what is still stale.
        val force = inputData.getBoolean(KEY_FORCE, false) && runAttemptCount == 0
        val failures = app.feeds.refreshStale(FeedRepository.MAX_AGE_MS, force)
        app.pruneOldData()
        app.vacuumIfDue()
        return if (failures > 0 && runAttemptCount < 3) Result.retry() else Result.success()
    }

    companion object {
        const val KEY_FORCE = "force"
    }
}
