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
import kotlinx.serialization.json.JsonObject
import java.io.IOException

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
)

/** The collector answered with a non-2xx HTTP status. */
class HttpStatusException(val code: Int, detail: String? = null) :
    IOException("HTTP $code" + (detail?.takeIf { it.isNotBlank() }?.let { ": ${it.take(200)}" } ?: ""))

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
    /** The collector refused this payload (400/413/422): retrying the same bytes cannot succeed. */
    BAD_BATCH,
}

object ExportRetry {
    const val MIN_BACKOFF_MS = 1_000L
    const val MAX_BACKOFF_MS = 60_000L

    fun classify(e: Throwable): FailureKind {
        val code = (e as? HttpStatusException)?.code ?: return FailureKind.TRANSIENT
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
 * delivered, the collector rejects it, or export is turned off: while offline
 * it waits for the network instead of burning attempts, and a settings change
 * retries at once.
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

    private val queue = Channel<JsonObject>(capacity, BufferOverflow.DROP_OLDEST) {
        _status.update { s -> s.copy(dropped = s.dropped + 1) }
    }

    fun offer(record: JsonObject) {
        queue.trySend(record)
    }

    fun reportError(message: String?) = _status.update { it.copy(lastError = message) }

    /** Runs until the calling coroutine is cancelled. */
    suspend fun run() {
        var backoff = ExportRetry.MIN_BACKOFF_MS
        while (currentCoroutineContext().isActive) {
            var batch: List<JsonObject> = nextBatch()
            var lastCfg: ExportSettings? = null
            while (batch.isNotEmpty()) {
                val cfg = config.value
                if (!cfg.enabled) {
                    // Turned off: what is queued will never be sent. Count it.
                    discard(batch.size + drain())
                    batch = emptyList()
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
                result.onSuccess { out ->
                    _status.update { s ->
                        s.copy(
                            sent = s.sent + out.delivered,
                            rejected = s.rejected + out.rejected,
                            lastSuccess = if (out.delivered > 0) clock() else s.lastSuccess,
                            lastError = out.detail,
                            retrying = out.retry.isNotEmpty(),
                        )
                    }
                    batch = out.retry
                    if (batch.isEmpty()) backoff = ExportRetry.MIN_BACKOFF_MS
                }
                val error = result.exceptionOrNull()
                if (error != null) {
                    if (error is kotlinx.coroutines.CancellationException) throw error
                    onFailure()
                    val msg = error.message ?: error.javaClass.simpleName
                    when (ExportRetry.classify(error)) {
                        FailureKind.BAD_BATCH -> {
                            _status.update { s -> s.copy(rejected = s.rejected + batch.size, lastError = "$msg (batch rejected)", retrying = false) }
                            batch = emptyList()
                        }
                        FailureKind.PERMANENT -> {
                            backoff = ExportRetry.MAX_BACKOFF_MS
                            _status.update { it.copy(lastError = "$msg (check the endpoint and credentials)", retrying = true) }
                        }
                        FailureKind.TRANSIENT -> _status.update { it.copy(lastError = msg, retrying = true) }
                    }
                }
                if (batch.isNotEmpty()) {
                    waitOrConfigChange(cfg, backoff)
                    backoff = ExportRetry.nextBackoff(backoff)
                }
            }
        }
    }

    private suspend fun nextBatch(): List<JsonObject> {
        val first = queue.receive()
        val batch = ArrayList<JsonObject>(batchSize)
        batch += first
        while (batch.size < batchSize) batch += queue.tryReceive().getOrNull() ?: break
        return batch
    }

    private fun drain(): Int {
        var n = 0
        while (queue.tryReceive().isSuccess) n++
        return n
    }

    private fun discard(n: Int) = _status.update { s -> s.copy(dropped = s.dropped + n, retrying = false) }

    /** Sleeps for [ms], returning early when the export settings change. */
    private suspend fun waitOrConfigChange(cfg: ExportSettings, ms: Long) {
        withTimeoutOrNull(ms) { config.first { it != cfg } }
    }
}
