package dev.vigil.inspector.export

import dev.vigil.inspector.data.ExportSettings
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger

data class ExportStatus(
    val sent: Long = 0,
    /** Records lost before delivery: queue overflow, or discarded because export was turned off. */
    val dropped: Long = 0,
    /** Records the collector refused (malformed or rejected documents); retrying would not help. */
    val rejected: Long = 0,
    val lastError: String? = null,
    val lastSuccess: Long? = null,
    /** True while the exporter holds records it could not deliver yet. */
    val retrying: Boolean = false,
    /** Records waiting to be sent, including the batch being delivered. */
    val queued: Int = 0,
    /**
     * Set while the collector refuses records because of its own
     * configuration (e.g. a Splunk HEC token not allowed to write to the
     * index). The records stay queued and are retried once a minute, or at
     * once when the settings change. Cleared by the next successful delivery.
     */
    val configProblem: String? = null,
)

/** The collector answered with a non-2xx HTTP status. [body] is the response body, if any. */
class HttpStatusException(val code: Int, val body: String? = null) :
    IOException("HTTP $code" + (body?.takeIf { it.isNotBlank() }?.let { ": ${it.take(200)}" } ?: ""))

/** Result of one delivery attempt that reached the collector. */
data class SendOutcome(
    val delivered: Int,
    val rejected: Int = 0,
    /** Records to send again (throttled or failed server-side). */
    val retry: List<JsonObject> = emptyList(),
    val detail: String? = null,
)

/** How a failed delivery attempt is handled. */
enum class FailureKind {
    /** Network trouble, timeouts, 408/429/5xx: retry with growing backoff. */
    TRANSIENT,
    /** Credentials or endpoint wrong (401/403/404...): retry slowly until the settings change. */
    PERMANENT,
    /**
     * The collector refused this payload (400/413/422): retrying the same
     * bytes cannot succeed. The batch is split in halves until the offending
     * records are isolated (a 413 on a batch usually only means it was too
     * large); a single refused record is counted as rejected.
     */
    BAD_BATCH,
    /**
     * The collector's own configuration refuses every record (Splunk HEC
     * codes 7, 10, 11): keep the records queued and retry slowly until the
     * settings change or the collector is fixed.
     */
    CONFIG,
}

object ExportRetry {
    const val MIN_BACKOFF_MS = 1_000L
    const val MAX_BACKOFF_MS = 60_000L

    /** Splunk HEC status codes that mean the token or collector is misconfigured, not the data. */
    private val HEC_CONFIG_CODES = mapOf(
        7 to "incorrect index. The token may not write to the index; check the HEC token's allowed indexes.",
        10 to "data channel is missing. Indexer acknowledgement is enabled for this HEC token; turn it off for vigil's token.",
        11 to "invalid data channel. Indexer acknowledgement is enabled for this HEC token; turn it off for vigil's token.",
    )

    /** The `code` of a Splunk HEC error body such as `{"text":"Incorrect index","code":7}`. */
    fun splunkHecCode(body: String?): Int? {
        if (body.isNullOrBlank()) return null
        val obj = runCatching { Json.parseToJsonElement(body) as? JsonObject }.getOrNull() ?: return null
        return (obj["code"] as? JsonPrimitive)?.intOrNull
    }

    /** A user-facing explanation if [e] is a collector configuration error, else null. */
    fun configProblem(e: Throwable, cfg: ExportSettings): String? {
        val http = e as? HttpStatusException ?: return null
        if (cfg.mode != "http" || cfg.httpFormat != "splunk_hec") return null
        val code = splunkHecCode(http.body) ?: return null
        return HEC_CONFIG_CODES[code]?.let { "Splunk HEC refuses events (code $code): $it" }
    }

    fun classify(e: Throwable, cfg: ExportSettings? = null): FailureKind {
        val code = (e as? HttpStatusException)?.code ?: return FailureKind.TRANSIENT
        if (cfg != null && configProblem(e, cfg) != null) return FailureKind.CONFIG
        return when {
            code == 408 || code == 429 || code >= 500 -> FailureKind.TRANSIENT
            code == 400 || code == 413 || code == 422 -> FailureKind.BAD_BATCH
            code in 400..499 -> FailureKind.PERMANENT
            else -> FailureKind.TRANSIENT
        }
    }

    fun nextBackoff(current: Long): Long = (current * 2).coerceIn(MIN_BACKOFF_MS, MAX_BACKOFF_MS)
}

/**
 * The export queue and delivery loop, independent of Android so it can be
 * tested on the JVM. Records wait in a bounded queue (the oldest are dropped
 * and counted when it overflows). The head batch is retried until it is
 * delivered, the collector rejects its records, or export is turned off:
 * while offline it waits for the network instead of burning attempts, and a
 * settings change retries at once. A batch the collector refuses as a whole
 * is split until the refused records are isolated.
 */
class ExportPipeline(
    private val config: StateFlow<ExportSettings>,
    private val online: StateFlow<Boolean>,
    private val transport: suspend (ExportSettings, List<JsonObject>) -> SendOutcome,
    /** Called after a failed attempt so a broken connection is not reused. */
    private val onFailure: () -> Unit = {},
    private val clock: () -> Long = System::currentTimeMillis,
    capacity: Int = 10_000,
    private val batchSize: Int = 200,
) {
    private val _status = MutableStateFlow(ExportStatus())
    val status: StateFlow<ExportStatus> = _status.asStateFlow()

    /** Records in [queue] (a channel does not expose its size). */
    private val inQueue = AtomicInteger(0)

    /** Records taken from the queue and not yet delivered, rejected or discarded. */
    @Volatile private var inFlight = 0

    private val queue = Channel<JsonObject>(capacity, BufferOverflow.DROP_OLDEST) {
        inQueue.decrementAndGet()
        _status.update { s -> s.copy(dropped = s.dropped + 1) }
    }

    private fun publishQueued() = _status.update { it.copy(queued = inQueue.get().coerceAtLeast(0) + inFlight) }

    fun offer(record: JsonObject) {
        inQueue.incrementAndGet()
        if (queue.trySend(record).isFailure) inQueue.decrementAndGet()
        publishQueued()
    }

    fun reportError(message: String?) = _status.update { it.copy(lastError = message) }

    /** Runs until the calling coroutine is cancelled. */
    suspend fun run() {
        var backoff = ExportRetry.MIN_BACKOFF_MS
        while (currentCoroutineContext().isActive) {
            // The head batch, possibly split into parts after the collector
            // refused it as a whole; the first part is sent next.
            val parts = ArrayDeque<List<JsonObject>>()
            parts.addLast(nextBatch())
            var lastCfg: ExportSettings? = null
            while (parts.isNotEmpty()) {
                val batch = parts.first()
                val cfg = config.value
                if (!cfg.enabled) {
                    // Turned off: what is queued will never be sent. Count it.
                    discard(parts.sumOf { it.size } + drain())
                    parts.clear()
                    break
                }
                if (cfg != lastCfg) {
                    lastCfg = cfg
                    backoff = ExportRetry.MIN_BACKOFF_MS
                }
                if (!online.value) {
                    _status.update { it.copy(retrying = true, lastError = it.lastError ?: "waiting for a network connection") }
                    combine(online, config) { o, c -> o || c != cfg }.first { it }
                    continue
                }
                val result = runCatching { transport(cfg, batch) }
                var wait = false
                result.onSuccess { out ->
                    parts.removeFirst()
                    if (out.retry.isNotEmpty()) parts.addFirst(out.retry)
                    settle(parts)
                    _status.update { s ->
                        s.copy(
                            sent = s.sent + out.delivered,
                            rejected = s.rejected + out.rejected,
                            lastSuccess = if (out.delivered > 0) clock() else s.lastSuccess,
                            lastError = out.detail,
                            retrying = out.retry.isNotEmpty(),
                            configProblem = if (out.delivered > 0) null else s.configProblem,
                        )
                    }
                    if (out.retry.isEmpty()) backoff = ExportRetry.MIN_BACKOFF_MS else wait = true
                }
                val error = result.exceptionOrNull()
                if (error != null) {
                    if (error is kotlinx.coroutines.CancellationException) throw error
                    onFailure()
                    val msg = error.message ?: error.javaClass.simpleName
                    when (ExportRetry.classify(error, cfg)) {
                        FailureKind.BAD_BATCH -> if (batch.size > 1) {
                            // Try the halves at once: only the refused records are lost.
                            parts.removeFirst()
                            parts.addFirst(batch.subList(batch.size / 2, batch.size))
                            parts.addFirst(batch.subList(0, batch.size / 2))
                            _status.update { it.copy(lastError = "$msg (retrying in smaller batches)", retrying = true) }
                        } else {
                            parts.removeFirst()
                            settle(parts)
                            _status.update { s ->
                                s.copy(rejected = s.rejected + 1, lastError = "$msg (record rejected)", retrying = parts.isNotEmpty())
                            }
                        }
                        FailureKind.CONFIG -> {
                            backoff = ExportRetry.MAX_BACKOFF_MS
                            wait = true
                            val problem = ExportRetry.configProblem(error, cfg)
                            _status.update { it.copy(lastError = msg, configProblem = problem, retrying = true) }
                        }
                        FailureKind.PERMANENT -> {
                            backoff = ExportRetry.MAX_BACKOFF_MS
                            wait = true
                            _status.update { it.copy(lastError = "$msg (check the endpoint and credentials)", retrying = true) }
                        }
                        FailureKind.TRANSIENT -> {
                            wait = true
                            _status.update { it.copy(lastError = msg, retrying = true) }
                        }
                    }
                }
                if (wait && parts.isNotEmpty()) {
                    waitOrConfigChange(cfg, backoff)
                    backoff = ExportRetry.nextBackoff(backoff)
                }
            }
        }
    }

    /** Updates the queue depth after the records still held changed. */
    private fun settle(parts: ArrayDeque<List<JsonObject>>) {
        inFlight = parts.sumOf { it.size }
        publishQueued()
    }

    private suspend fun nextBatch(): List<JsonObject> {
        val first = queue.receive()
        val batch = ArrayList<JsonObject>(batchSize)
        batch += first
        while (batch.size < batchSize) batch += queue.tryReceive().getOrNull() ?: break
        inQueue.addAndGet(-batch.size)
        inFlight = batch.size
        publishQueued()
        return batch
    }

    private fun drain(): Int {
        var n = 0
        while (queue.tryReceive().isSuccess) n++
        inQueue.addAndGet(-n)
        return n
    }

    private fun discard(n: Int) {
        inFlight = 0
        _status.update { s -> s.copy(dropped = s.dropped + n, retrying = false, configProblem = null) }
        publishQueued()
    }

    /** Sleeps for [ms], returning early when the export settings change. */
    private suspend fun waitOrConfigChange(cfg: ExportSettings, ms: Long) {
        withTimeoutOrNull(ms) { config.first { it != cfg } }
    }
}
