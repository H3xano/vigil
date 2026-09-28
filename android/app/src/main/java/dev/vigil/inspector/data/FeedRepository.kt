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
import kotlinx.coroutines.CoroutineScope
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
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.TimeUnit
import kotlin.coroutines.coroutineContext

class FeedRepository(private val context: Context, private val dao: FeedDao) {
    private val dir = File(context.filesDir, "feeds").apply { mkdirs() }

    val feeds: Flow<List<FeedEntity>> = dao.all()

    fun fileFor(id: String) = File(dir, "$id.txt")

    /** Indicator state of a TAXII source, kept between incremental polls. */
    private fun stateFor(id: String) = File(dir, "$id.taxii")

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
            stateFor(id).delete()
            dao.clearDownload(id)
        }
    }

    private fun newId(prefix: String, name: String) =
        prefix + name.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-').ifEmpty { "feed" } +
            "-" + (System.currentTimeMillis() % 100_000)

    /**
     * Adds a custom downloaded list. [kind] is [FeedKinds.LIST] (domains/IPs,
     * in [category]) or [FeedKinds.JA4] (category `ja4`).
     */
    suspend fun addCustom(name: String, url: String, category: String, authHeader: String?, kind: String = FeedKinds.LIST): String {
        val id = newId("custom-", name)
        val ja4 = kind == FeedKinds.JA4
        dao.upsert(
            FeedEntity(
                id = id, name = name, url = url, category = if (ja4) "ja4" else category, enabled = true, builtin = false,
                description = if (ja4) "Custom JA4 feed" else "Custom feed", authHeader = authHeader?.takeIf { it.isNotBlank() },
                kind = if (ja4) FeedKinds.JA4 else FeedKinds.LIST,
            ),
        )
        scheduleRefreshNow(force = false)
        return id
    }

    /**
     * Adds a TAXII 2.1 collection. Its domains, IPs and JA4 fingerprints go
     * into one feed file loaded with [category] (a threat category), so
     * domain/IP hits raise threat alerts and JA4 hits `threat_ja4` alerts.
     */
    suspend fun addTaxii(name: String, collection: TaxiiCollection, category: String, authHeaderName: String?, authValue: String?): String {
        val id = newId("taxii-", name)
        val auth = authValue?.takeIf { it.isNotBlank() }
        dao.upsert(
            FeedEntity(
                id = id, name = name, url = collection.apiRoot, category = category, enabled = true, builtin = false,
                description = "TAXII 2.1 collection “${collection.title}”", authHeader = auth,
                authHeaderName = authHeaderName?.trim()?.takeIf { auth != null && it.isNotEmpty() && !it.equals("Authorization", ignoreCase = true) },
                kind = FeedKinds.TAXII, taxiiCollection = collection.id,
            ),
        )
        scheduleRefreshNow(force = false)
        return id
    }

    /** Lists the collections of a TAXII 2.1 discovery URL or API root. */
    suspend fun taxiiCollections(url: String, authHeaderName: String?, authValue: String?): Result<List<TaxiiCollection>> =
        withContext(Dispatchers.IO) {
            try {
                val probe = FeedEntity(
                    id = "probe", name = "probe", url = url, category = "c2", enabled = false, builtin = false,
                    authHeader = authValue?.takeIf { it.isNotBlank() }, authHeaderName = authHeaderName?.takeIf { it.isNotBlank() },
                )
                // With credentials, API roots on other hosts (or plain HTTP) are refused:
                // the collection's URL is stored and polled with the credentials later.
                val origin = probe.authHeader?.let { url }
                Result.success(TaxiiClient(taxiiTransport(probe), credentialOrigin = origin).collections(url))
            } catch (e: CancellationException) {
                throw e
            } catch (e: IOException) {
                Result.failure(e)
            } catch (e: RuntimeException) {
                Result.failure(e)
            }
        }

    suspend fun delete(id: String) {
        dao.deleteCustom(id)
        fileFor(id).delete()
        stateFor(id).delete()
    }

    /** Downloads one feed; the previous copy is kept if anything fails. */
    suspend fun refresh(feed: FeedEntity): Result<FeedSummary> = refreshLock.withLock { refreshLocked(feed) }

    private suspend fun refreshLocked(feed: FeedEntity): Result<FeedSummary> = withContext(Dispatchers.IO) {
        // Unique names: a crashed or cancelled run can never collide with this one.
        val tmp = File.createTempFile("${feed.id}-", ".tmp", dir)
        val converted = File.createTempFile("${feed.id}-conv-", ".tmp", dir)
        val stateTmp = File.createTempFile("${feed.id}-state-", ".tmp", dir)
        val target = fileFor(feed.id)
        var nextAddedAfter: String? = null
        val result = try {
            val summary = if (feed.isTaxii) {
                val (s, after) = pollTaxii(feed, tmp, stateTmp)
                nextAddedAfter = after
                s
            } else if (feed.kind == FeedKinds.ASN) {
                // Gunzipped and checked row by row here; the engine streams the TSV (category `asn`).
                download(feed, tmp)
                val stats = AsnDatabase.convert(tmp, converted)
                ensureActive()
                val previous = if (feed.lastUpdated != null && target.exists()) feed.ipRanges else null
                AsnDatabase.validate(stats, previous)?.let { throw IOException(it) }
                if (!converted.renameTo(target)) throw IOException("could not store feed")
                Log.i(TAG, "asn ${feed.id}: ${stats.routed} routed ranges, ${stats.asCount} networks, ${stats.rejected} rejected rows")
                FeedSummary(id = feed.id, ipRanges = stats.routed)
            } else {
                download(feed, tmp)
                val file = if (Ja4Converters.needsConversion(feed.format)) {
                    Ja4Converters.convert(feed.format, tmp, converted)
                    converted
                } else {
                    tmp
                }
                val summary = VigilNative.nativeInspectFeedFile(file.absolutePath)
                    ?.let { EngineJson.json.decodeFromString(FeedSummary.serializer(), it) }
                    ?: throw IOException("unreadable feed")
                val previous = if (feed.lastUpdated != null && target.exists()) feed.entries else null
                FeedValidation.check(summary, previous, feed.kind)?.let { throw IOException(it) }
                if (!file.renameTo(target)) throw IOException("could not store feed")
                // The engine loads a JA4 feed with category `ja4`, which ignores other lines.
                if (feed.kind == FeedKinds.JA4) summary.copy(domains = 0, ipRanges = 0) else summary
            }
            Result.success(summary)
        } catch (e: CancellationException) {
            throw e
        } catch (e: IOException) {
            Result.failure(e)
        } catch (e: RuntimeException) {
            Result.failure(e)
        } finally {
            tmp.delete()
            converted.delete()
            stateTmp.delete()
        }
        ensureActive() // a cancelled download fails with a socket error; don't record that as the feed's error
        result.onSuccess { s ->
            // Targeted update: a feed deleted or disabled during the download must not come back.
            val current = dao.get(feed.id)
            if (current == null || !current.enabled) {
                target.delete()
                stateFor(feed.id).delete()
                if (current != null) dao.clearDownload(feed.id)
                return@withContext Result.failure(IOException("feed was removed or disabled during the download"))
            }
            dao.markUpdated(feed.id, System.currentTimeMillis(), s.domains, s.ipRanges, s.ja4)
            if (feed.isTaxii) {
                dao.setTaxiiAddedAfter(feed.id, nextAddedAfter)
                if (s.domains + s.ipRanges + s.ja4 == 0) {
                    dao.markError(feed.id, "no supported indicators yet (domain, IP, URL and JA4 indicators are used)")
                }
            }
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
            val fresh = f.lastUpdated != null && now - f.lastUpdated < maxAgeFor(f, maxAgeMs, force) && fileFor(f.id).exists()
            if (!fresh && refreshLocked(f).isFailure) failures++
        }
        failures
    }

    /**
     * Polls a TAXII collection into [out] (the feed file) and [stateOut]
     * (the indicator state), then moves both into place. Incremental from
     * the stored `added_after`; a full sync when there is no state yet or
     * the last full sync is older than [TAXII_FULL_SYNC_MS] (this catches
     * objects deleted from the collection). Any failure leaves the previous
     * files and state untouched. Returns the summary and the next `added_after`.
     */
    private suspend fun pollTaxii(feed: FeedEntity, out: File, stateOut: File): Pair<FeedSummary, String?> = coroutineScope {
        val collection = feed.taxiiCollection ?: throw IOException("no TAXII collection selected")
        val now = System.currentTimeMillis()
        val previous = TaxiiState.read(stateFor(feed.id))?.takeIf { fileFor(feed.id).exists() }
        val incremental = previous != null && feed.taxiiAddedAfter != null && now - previous.fullSyncAt <= TAXII_FULL_SYNC_MS
        val state = if (incremental) previous else TaxiiState(fullSyncAt = now)
        // Cancellation disconnects the current request (see taxiiTransport) and is checked between pages.
        val poll = TaxiiClient(taxiiTransport(feed)).poll(feed.url, collection, if (incremental) feed.taxiiAddedAfter else null) { page ->
            ensureActive()
            for (o in page) Stix.item(o)?.let(state::apply)
        }
        val lines = state.feedLines(now)
        val before = previous?.feedLines(now)?.total
        FeedValidation.checkTaxiiResync(lines.total, before.takeIf { !incremental })?.let { throw IOException(it) }
        out.bufferedWriter().use { w ->
            w.write("# TAXII 2.1 collection $collection\n")
            for (l in lines.domains) w.write(l + "\n")
            for (l in lines.ips) w.write(l + "\n")
            for (l in lines.ja4) w.write(l + "\n")
        }
        state.write(stateOut)
        ensureActive()
        if (!stateOut.renameTo(stateFor(feed.id)) || !out.renameTo(fileFor(feed.id))) throw IOException("could not store feed")
        Log.i(
            TAG,
            "taxii ${feed.id}: ${if (incremental) "incremental" else "full"} poll, ${poll.pages} pages, ${poll.objects} objects, " +
                "${state.entries.size} indicators" + if (state.dropped > 0) ", ${state.dropped} over the limit" else "",
        )
        FeedSummary(id = feed.id, domains = lines.domains.size, ipRanges = lines.ips.size, ja4 = lines.ja4.size) to
            (poll.nextAddedAfter ?: feed.taxiiAddedAfter.takeIf { incremental })
    }

    /**
     * HTTP for the TAXII client: Accept header, credentials (only for the
     * host the user entered, see [FeedHttp]), size cap, disconnect on cancellation.
     */
    private fun CoroutineScope.taxiiTransport(feed: FeedEntity): TaxiiTransport = TaxiiTransport { url ->
        val current = AtomicReference<HttpURLConnection?>()
        val watchdog = launch(Dispatchers.IO) {
            try {
                awaitCancellation()
            } finally {
                current.get()?.disconnect()
            }
        }
        var conn: HttpURLConnection? = null
        try {
            conn = FeedHttp.get(url, credentialOf(feed), { c ->
                c.connectTimeout = 20_000
                c.readTimeout = 60_000
                c.setRequestProperty("Accept", TaxiiClient.MEDIA_TYPE)
                c.setRequestProperty("User-Agent", "vigil/${dev.vigil.inspector.BuildConfig.VERSION_NAME} (+TAXII poller)")
            }) { c -> current.set(c); ensureActive() }
            val code = conn.responseCode
            // Bytes, then one String, then the JSON tree: the cap bounds all three.
            val body = if (code in 200..299) {
                conn.inputStream.use { String(FeedHttp.readCapped(it, MAX_TAXII_PAGE_BYTES, "TAXII response"), Charsets.UTF_8) }
            } else {
                ""
            }
            val headers = conn.headerFields.orEmpty().mapNotNull { (k, v) -> k?.lowercase()?.let { it to v.lastOrNull().orEmpty() } }.toMap()
            TaxiiResponse(code, conn.contentType, headers, body)
        } finally {
            watchdog.cancel()
            conn?.disconnect()
        }
    }

    /** The feed's credential, bound to the host of its URL (the one the user entered). */
    private fun credentialOf(feed: FeedEntity): FeedCredential? =
        feed.authHeader?.let { FeedCredential(feed.authHeaderName ?: "Authorization", it, feed.url) }

    /** Blocking download that still honours cancellation (WorkManager stop, REPLACE). */
    private suspend fun download(feed: FeedEntity, dest: File) = coroutineScope {
        // Disconnecting from another thread unblocks a read stuck in the socket.
        val current = AtomicReference<HttpURLConnection?>()
        val watchdog = launch(Dispatchers.IO) {
            try {
                awaitCancellation()
            } finally {
                current.get()?.disconnect()
            }
        }
        try {
            val conn = FeedHttp.get(feed.url, credentialOf(feed), { c ->
                c.connectTimeout = 20_000
                c.readTimeout = 60_000
                c.setRequestProperty("User-Agent", "vigil/${dev.vigil.inspector.BuildConfig.VERSION_NAME} (+feed updater)")
            }) { c -> current.set(c); ensureActive() }
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
        /**
         * How old a downloaded copy may be before a refresh fetches it again.
         * The ASN table changes slowly and is large: weekly, and at most daily
         * even for a forced refresh. Other feeds: [maxAgeMs], 0 when forced.
         */
        fun maxAgeFor(feed: FeedEntity, maxAgeMs: Long, force: Boolean): Long = when {
            feed.kind == FeedKinds.ASN -> if (force) ASN_FORCED_MIN_AGE_MS else maxOf(maxAgeMs, AsnDatabase.MAX_AGE_MS)
            force -> 0L
            else -> maxAgeMs
        }

        private const val ASN_FORCED_MIN_AGE_MS = 20L * 3600 * 1000
        private const val TAG = "vigil.feeds"
        private const val MAX_FEED_BYTES = 150L * 1024 * 1024
        const val MAX_AGE_MS = 20L * 3600 * 1000
        /** One page of up to [TaxiiClient.PAGE_LIMIT] objects is a few MB at most. */
        private const val MAX_TAXII_PAGE_BYTES = 8L * 1024 * 1024
        private const val TAXII_FULL_SYNC_MS = 7L * 24 * 3600 * 1000
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
        app.vacuumIfDue(allowWhileInspecting = false)
        return if (failures > 0 && runAttemptCount < 3) Result.retry() else Result.success()
    }

    companion object {
        const val KEY_FORCE = "force"
    }
}
