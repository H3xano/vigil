package dev.vigil.inspector.export

import dev.vigil.inspector.data.ExportSettings
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
    fun badRequestDropsTheBatchAsRejected() = runTest {
        val h = harness { attempt, batch -> if (attempt == 1) throw HttpStatusException(400) else SendOutcome(batch.size) }
        repeat(2) { h.pipeline.offer(rec(it)) }
        backgroundScope.launch { h.pipeline.run() }
        runCurrent()
        assertEquals(1, h.attempts.size)
        assertEquals(2L, h.pipeline.status.value.rejected)
        h.pipeline.offer(rec(3))
        runCurrent()
        assertEquals(1L, h.pipeline.status.value.sent)
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
        assertTrue(h.pipeline.status.value.lastError!!.startsWith("HTTP 401"))
        // Fixing the credentials retries immediately.
        h.config.value = enabled.copy(authHeader = "Bearer fixed")
        runCurrent()
        assertEquals(3, h.attempts.size)
        assertEquals(1L, h.pipeline.status.value.sent)
    }

    @Test
    fun retriesOnlyTheItemsTheCollectorAskedFor() = runTest {
        val h = harness { attempt, batch ->
            if (attempt == 1) SendOutcome(delivered = 1, rejected = 1, retry = listOf(batch[2]), detail = "throttled") else SendOutcome(batch.size)
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
        assertEquals(FailureKind.PERMANENT, ExportRetry.classify(HttpStatusException(401)))
        assertEquals(FailureKind.PERMANENT, ExportRetry.classify(HttpStatusException(403)))
        assertEquals(60_000L, ExportRetry.nextBackoff(40_000))
    }
}
