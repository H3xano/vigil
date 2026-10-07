package dev.vigil.inspector.export

import dev.vigil.inspector.R
import dev.vigil.inspector.data.ExportSettings
import dev.vigil.inspector.ui.UiText
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class ExportPipelineTest {
    private val enabled = ExportSettings(enabled = true, host = "collector", transport = "tcp", port = 514)

    private fun rec(n: Int) = JsonObject(mapOf("n" to JsonPrimitive(n)))

    private class Harness(
        val config: MutableStateFlow<ExportSettings>,
        val online: MutableStateFlow<Boolean>,
        val pipeline: ExportPipeline,
        val attempts: MutableList<List<JsonObject>>,
    )

    private fun TestScope.harness(
        cfg: ExportSettings = enabled,
        capacity: Int = 10_000,
        transport: suspend (Int, List<JsonObject>) -> SendOutcome,
    ): Harness {
        val config = MutableStateFlow(cfg)
        val online = MutableStateFlow(true)
        val attempts = mutableListOf<List<JsonObject>>()
        val pipeline = ExportPipeline(config, online, { _, batch ->
            attempts += batch
            transport(attempts.size, batch)
        }, clock = { 42L }, capacity = capacity)
        return Harness(config, online, pipeline, attempts)
    }

    @Test
    fun keepsRetryingPastALongOutage() = runTest {
        val h = harness { attempt, batch -> if (attempt <= 12) throw IOException("connection refused") else SendOutcome(batch.size) }
        repeat(3) { h.pipeline.offer(rec(it)) }
        backgroundScope.launch { h.pipeline.run() }
        advanceTimeBy(15 * 60_000L)
        runCurrent()
        assertEquals(13, h.attempts.size)
        assertEquals(3L, h.pipeline.status.value.sent)
        assertEquals(0L, h.pipeline.status.value.dropped)
        assertEquals(null, h.pipeline.status.value.lastError)
        assertEquals(42L, h.pipeline.status.value.lastSuccess)
    }

    @Test
    fun backoffIsCappedAtOneMinute() = runTest {
        val h = harness { _, _ -> throw IOException("down") }
        h.pipeline.offer(rec(1))
        backgroundScope.launch { h.pipeline.run() }
        advanceTimeBy(10 * 60_000L)
        runCurrent()
        // 1+2+4+8+16+32 s, then one attempt a minute.
        assertTrue("attempts=${h.attempts.size}", h.attempts.size in 14..16)
        assertTrue(h.pipeline.status.value.retrying)
    }

    @Test
    fun disablingCountsDiscardedRecords() = runTest {
        val h = harness { _, _ -> throw IOException("down") }
        repeat(250) { h.pipeline.offer(rec(it)) }
        backgroundScope.launch { h.pipeline.run() }
        runCurrent()
        h.config.value = enabled.copy(enabled = false)
        runCurrent()
        assertEquals(250L, h.pipeline.status.value.dropped)
        assertEquals(0L, h.pipeline.status.value.sent)
    }

    @Test
    fun waitsForNetworkWithoutAttempting() = runTest {
        val h = harness { _, batch -> SendOutcome(batch.size) }
        h.online.value = false
        h.pipeline.offer(rec(1))
        backgroundScope.launch { h.pipeline.run() }
        advanceTimeBy(30 * 60_000L)
        runCurrent()
        assertEquals(0, h.attempts.size)
        h.online.value = true
        runCurrent()
        assertEquals(1, h.attempts.size)
        assertEquals(1L, h.pipeline.status.value.sent)
    }

    @Test
    fun badRequestSplitsTheBatchAndRejectsOnlyTheBadRecord() = runTest {
        val bad = rec(5)
        val h = harness { _, batch -> if (bad in batch) throw HttpStatusException(400, "mapper_parsing_exception") else SendOutcome(batch.size) }
        repeat(8) { h.pipeline.offer(rec(it)) }
        backgroundScope.launch { h.pipeline.run() }
        runCurrent()
        // Attempts after a refusal are paced (1 s), not sent in a burst.
        assertEquals(1, h.attempts.size)
        advanceTimeBy(10_000)
        runCurrent()
        assertEquals(7L, h.pipeline.status.value.sent)
        assertEquals(1L, h.pipeline.status.value.rejected)
        assertEquals(0, h.pipeline.status.value.queued)
        assertEquals(null, h.pipeline.status.value.configProblem)
        // [0-7] -> [0-3] ok, [4-7] -> [4,5] -> [4] ok, [5] rejected; then [6,7].
        assertEquals(listOf(8, 4, 4, 2, 1, 1, 2), h.attempts.map { it.size })
        assertEquals(listOf(bad), h.attempts[5])
        h.pipeline.offer(rec(9))
        runCurrent()
        assertEquals(8L, h.pipeline.status.value.sent)
    }

    @Test
    fun payloadTooLargeSplitsUntilBatchesFit() = runTest {
        val h = harness { _, batch -> if (batch.size > 50) throw HttpStatusException(413) else SendOutcome(batch.size) }
        repeat(200) { h.pipeline.offer(rec(it)) }
        backgroundScope.launch { h.pipeline.run() }
        advanceTimeBy(10_000)
        runCurrent()
        assertEquals(200L, h.pipeline.status.value.sent)
        assertEquals(0L, h.pipeline.status.value.rejected)
        // Order is kept.
        assertEquals((0 until 200).map(::rec), h.attempts.filter { it.size <= 50 }.flatten())
    }

    @Test
    fun collectorRefusingEverythingKeepsRecordsQueued() = runTest {
        // E.g. an Elastic _bulk URL without an index behind a proxy that hides the error body.
        val h = harness { _, _ -> throw HttpStatusException(400, "bad request") }
        repeat(200) { h.pipeline.offer(rec(it)) }
        backgroundScope.launch { h.pipeline.run() }
        advanceTimeBy(40_000)
        runCurrent()
        val first = h.attempts.size
        assertTrue("detected in a few attempts, not ~399: $first", first in 10..25)
        var s = h.pipeline.status.value
        assertEquals(UiText.of(R.string.export_error_refused_everything, 400), s.configProblem)
        assertEquals(0L, s.rejected)
        assertEquals(200, s.queued)
        // Then about one detection round a minute, paced.
        advanceTimeBy(10 * 60_000L)
        runCurrent()
        s = h.pipeline.status.value
        assertTrue("attempts=${h.attempts.size}", h.attempts.size <= first * 11)
        assertEquals(0L, s.rejected)
        assertEquals(0L, s.dropped)
        assertEquals(200, s.queued)
        assertTrue(s.retrying)
        // Every attempt was at least a second after the previous one: 10 min 40 s allows at most 640.
        assertTrue(h.attempts.size <= 640)
    }

    @Test
    fun refusedFirstRecordIsStillIsolatedAndRejected() = runTest {
        val bad = rec(0)
        val h = harness { _, batch -> if (bad in batch) throw HttpStatusException(400, "mapper_parsing_exception") else SendOutcome(batch.size) }
        repeat(8) { h.pipeline.offer(rec(it)) }
        backgroundScope.launch { h.pipeline.run() }
        advanceTimeBy(10_000)
        runCurrent()
        val s = h.pipeline.status.value
        assertEquals(7L, s.sent)
        assertEquals(1L, s.rejected)
        assertEquals(0, s.queued)
        assertEquals(null, s.configProblem)
        // [0-7] -> [0-3] -> [0,1] -> [0] held, then the rest [1-7] at once.
        assertEquals(listOf(8, 4, 2, 1, 7), h.attempts.map { it.size })
    }

    @Test
    fun loneRefusedRecordIsRejectedOnceOthersGetThrough() = runTest {
        val bad = rec(0)
        val h = harness { _, batch -> if (bad in batch) throw HttpStatusException(400) else SendOutcome(batch.size) }
        h.pipeline.offer(bad)
        backgroundScope.launch { h.pipeline.run() }
        runCurrent()
        // Alone, it cannot be told from a collector refusing everything: kept.
        assertEquals(0L, h.pipeline.status.value.rejected)
        assertEquals(1, h.pipeline.status.value.queued)
        repeat(3) { h.pipeline.offer(rec(it + 1)) }
        advanceTimeBy(70_000)
        runCurrent()
        val s = h.pipeline.status.value
        assertEquals(3L, s.sent)
        assertEquals(1L, s.rejected)
        assertEquals(0, s.queued)
        assertEquals(null, s.configProblem)
    }

    @Test
    fun heldRecordIsNotRejectedWhileTheCollectorOnlyThrottles() = runTest {
        val bad = rec(0)
        var throttle = true
        val h = harness { _, batch ->
            when {
                bad in batch -> throw HttpStatusException(400)
                // Every item answered 429: a successful request, but nothing was taken.
                throttle -> SendOutcome(delivered = 0, retry = batch, detail = UiText.Raw("throttled"))
                else -> SendOutcome(batch.size)
            }
        }
        h.pipeline.offer(bad)
        backgroundScope.launch { h.pipeline.run() }
        runCurrent()
        repeat(3) { h.pipeline.offer(rec(it + 1)) }
        advanceTimeBy(70_000)
        runCurrent()
        // The others were throttled, not accepted: the lone refused record is not known to be bad yet.
        assertEquals(0L, h.pipeline.status.value.rejected)
        assertEquals(0L, h.pipeline.status.value.sent)
        assertEquals(4, h.pipeline.status.value.queued)
        throttle = false
        advanceTimeBy(130_000)
        runCurrent()
        val s = h.pipeline.status.value
        assertEquals(3L, s.sent)
        assertEquals(1L, s.rejected)
        assertEquals(0, s.queued)
    }

    @Test
    fun elasticRequestValidationErrorIsAConfigProblem() = runTest {
        val es = enabled.copy(mode = "http", url = "https://es:9200/vigil/_bulk", httpFormat = "elastic_bulk")
        val body = """{"error":{"root_cause":[{"type":"action_request_validation_exception","reason":"Validation Failed: 1: index is missing;"}],""" +
            """"type":"action_request_validation_exception","reason":"Validation Failed: 1: index is missing;"},"status":400}"""
        val e = HttpStatusException(400, body)
        assertEquals(FailureKind.CONFIG, ExportRetry.classify(e, es))
        assertEquals(
            UiText.of(R.string.export_error_elastic_validation, "Validation Failed: 1: index is missing;"),
            ExportRetry.configProblem(e, es),
        )
        val h = harness(cfg = es) { _, _ -> throw e }
        repeat(50) { h.pipeline.offer(rec(it)) }
        backgroundScope.launch { h.pipeline.run() }
        advanceTimeBy(30_000)
        runCurrent()
        assertEquals("not split", 1, h.attempts.size)
        assertEquals(50, h.pipeline.status.value.queued)
        assertEquals(0L, h.pipeline.status.value.rejected)
    }

    @Test
    fun alertsHaveTheirOwnQueueAndGoFirst() = runTest {
        val config = MutableStateFlow(enabled)
        val attempts = mutableListOf<List<JsonObject>>()
        val pipeline = ExportPipeline(config, MutableStateFlow(true), { _, batch ->
            attempts += batch
            SendOutcome(batch.size)
        }, capacity = 5, batchSize = 4, alertCapacity = 3)
        val alert = { n: Int -> JsonObject(mapOf("alert" to JsonPrimitive(n))) }
        // The alert queue drops its own oldest when it overflows.
        repeat(4) { pipeline.offer(alert(it), alert = true) }
        assertEquals(1L, pipeline.status.value.dropped)
        // An outage's worth of flows: they overflow their own queue only.
        repeat(20) { pipeline.offer(rec(it)) }
        assertEquals(16L, pipeline.status.value.dropped)
        assertEquals(8, pipeline.status.value.queued)
        backgroundScope.launch { pipeline.run() }
        runCurrent()
        assertEquals(listOf(alert(1), alert(2), alert(3), rec(15)), attempts[0])
        assertEquals(listOf(rec(16), rec(17), rec(18), rec(19)), attempts[1])
        assertEquals(8L, pipeline.status.value.sent)
        assertEquals(0, pipeline.status.value.queued)
    }

    @Test
    fun singleRecordTooLargeIsRejected() = runTest {
        val h = harness { _, _ -> throw HttpStatusException(413) }
        h.pipeline.offer(rec(1))
        backgroundScope.launch { h.pipeline.run() }
        runCurrent()
        assertEquals(1, h.attempts.size)
        assertEquals(1L, h.pipeline.status.value.rejected)
        assertEquals(UiText.of(R.string.export_error_record_rejected, UiText.Raw("HTTP 413")), h.pipeline.status.value.lastError)
    }

    @Test
    fun splunkIndexErrorKeepsRecordsQueued() = runTest {
        val hec = enabled.copy(mode = "http", url = "https://splunk:8088/services/collector", httpFormat = "splunk_hec")
        val h = harness(cfg = hec) { attempt, batch ->
            if (attempt <= 2) throw HttpStatusException(400, """{"text":"Incorrect index","code":7,"invalid-event-number":0}""") else SendOutcome(batch.size)
        }
        repeat(3) { h.pipeline.offer(rec(it)) }
        backgroundScope.launch { h.pipeline.run() }
        runCurrent()
        val s = h.pipeline.status.value
        assertEquals("not split, not rejected", 1, h.attempts.size)
        assertEquals(0L, s.rejected)
        assertEquals(3, s.queued)
        assertEquals(UiText.of(R.string.export_error_hec_code7), s.configProblem)
        advanceTimeBy(59_000)
        runCurrent()
        assertEquals("retried slowly", 1, h.attempts.size)
        advanceTimeBy(2_000)
        runCurrent()
        assertEquals(2, h.attempts.size)
        // Fixing the settings retries at once and clears the problem.
        h.config.value = hec.copy(url = "https://splunk:8088/services/collector/event")
        runCurrent()
        assertEquals(3L, h.pipeline.status.value.sent)
        assertEquals(null, h.pipeline.status.value.configProblem)
        assertEquals(0, h.pipeline.status.value.queued)
    }

    @Test
    fun splunkDataErrorsStillSplit() = runTest {
        val hec = enabled.copy(mode = "http", url = "https://splunk", httpFormat = "splunk_hec")
        val body = """{"text":"Invalid data format","code":6,"invalid-event-number":1}"""
        assertEquals(FailureKind.BAD_BATCH, ExportRetry.classify(HttpStatusException(400, body), hec))
        assertEquals(FailureKind.CONFIG, ExportRetry.classify(HttpStatusException(400, """{"text":"Data channel is missing","code":10}"""), hec))
        // Only for Splunk HEC: another collector's body with a "code" is not interpreted.
        assertEquals(FailureKind.BAD_BATCH, ExportRetry.classify(HttpStatusException(400, """{"code":7}"""), enabled))
        assertEquals(null, ExportRetry.splunkHecCode("<html>"))
    }

    @Test
    fun queueDepthCountsWaitingAndInFlightRecords() = runTest {
        val h = harness { _, _ -> throw IOException("down") }
        repeat(5) { h.pipeline.offer(rec(it)) }
        assertEquals(5, h.pipeline.status.value.queued)
        backgroundScope.launch { h.pipeline.run() }
        runCurrent()
        h.pipeline.offer(rec(5))
        assertEquals(6, h.pipeline.status.value.queued)
        h.config.value = enabled.copy(enabled = false)
        runCurrent()
        assertEquals(0, h.pipeline.status.value.queued)
        assertEquals(6L, h.pipeline.status.value.dropped)
    }

    @Test
    fun authErrorsBackOffToMaxAndRetryOnSettingsChange() = runTest {
        val h = harness { attempt, batch -> if (attempt <= 2) throw HttpStatusException(401) else SendOutcome(batch.size) }
        h.pipeline.offer(rec(1))
        backgroundScope.launch { h.pipeline.run() }
        runCurrent()
        assertEquals(1, h.attempts.size)
        advanceTimeBy(59_000)
        runCurrent()
        assertEquals("no hot loop on 401", 1, h.attempts.size)
        advanceTimeBy(2_000)
        runCurrent()
        assertEquals(2, h.attempts.size)
        assertEquals(UiText.of(R.string.export_error_check_credentials, UiText.Raw("HTTP 401")), h.pipeline.status.value.lastError)
        // Fixing the credentials retries immediately.
        h.config.value = enabled.copy(authHeader = "Bearer fixed")
        runCurrent()
        assertEquals(3, h.attempts.size)
        assertEquals(1L, h.pipeline.status.value.sent)
    }

    @Test
    fun retriesOnlyTheItemsTheCollectorAskedFor() = runTest {
        val h = harness { attempt, batch ->
            if (attempt == 1) SendOutcome(delivered = 1, rejected = 1, retry = listOf(batch[2]), detail = UiText.Raw("throttled")) else SendOutcome(batch.size)
        }
        repeat(3) { h.pipeline.offer(rec(it)) }
        backgroundScope.launch { h.pipeline.run() }
        advanceTimeBy(5_000)
        runCurrent()
        assertEquals(listOf(rec(2)), h.attempts[1])
        assertEquals(2L, h.pipeline.status.value.sent)
        assertEquals(1L, h.pipeline.status.value.rejected)
    }

    @Test
    fun overflowDropsOldestAndCountsThem() = runTest {
        val h = harness(capacity = 3) { _, batch -> SendOutcome(batch.size) }
        repeat(5) { h.pipeline.offer(rec(it)) }
        assertEquals(2L, h.pipeline.status.value.dropped)
        backgroundScope.launch { h.pipeline.run() }
        runCurrent()
        assertEquals(listOf(rec(2), rec(3), rec(4)), h.attempts.single())
    }

    @Test
    fun classifiesHttpStatuses() {
        assertEquals(FailureKind.TRANSIENT, ExportRetry.classify(IOException("timeout")))
        assertEquals(FailureKind.TRANSIENT, ExportRetry.classify(HttpStatusException(503)))
        assertEquals(FailureKind.TRANSIENT, ExportRetry.classify(HttpStatusException(429)))
        assertEquals(FailureKind.TRANSIENT, ExportRetry.classify(HttpStatusException(408)))
        assertEquals(FailureKind.BAD_BATCH, ExportRetry.classify(HttpStatusException(400)))
        assertEquals(FailureKind.BAD_BATCH, ExportRetry.classify(HttpStatusException(413)))
        assertEquals(FailureKind.PERMANENT, ExportRetry.classify(HttpStatusException(401)))
        assertEquals(FailureKind.PERMANENT, ExportRetry.classify(HttpStatusException(403)))
        assertEquals(60_000L, ExportRetry.nextBackoff(40_000))
    }
}
