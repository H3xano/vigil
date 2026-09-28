package dev.vigil.inspector.processing

import dev.vigil.inspector.data.AppAsnDao
import dev.vigil.inspector.data.AppAsnEntity
import dev.vigil.inspector.data.FlowEntity
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** In-memory [AppAsnDao] with the same semantics as the Room queries. */
private class FakeAppAsnDao : AppAsnDao {
    val rows = LinkedHashMap<Pair<String, Long>, AppAsnEntity>()
    override suspend fun get(pkg: String, asn: Long) = rows[pkg to asn]
    override suspend fun insertIfAbsent(rows: List<AppAsnEntity>) {
        for (r in rows) this.rows.putIfAbsent(r.pkg to r.asn, r)
    }
    override suspend fun touch(pkg: String, asn: Long, lastSeen: Long, flows: Long): Int {
        val r = rows[pkg to asn] ?: return 0
        rows[pkg to asn] = r.copy(flows = r.flows + flows, lastSeen = maxOf(r.lastSeen, lastSeen))
        return 1
    }
    override suspend fun firstSeenApp(pkg: String) = rows.values.filter { it.pkg == pkg }.minOfOrNull { it.firstSeen }
    override suspend fun countFor(pkg: String) = rows.values.count { it.pkg == pkg }
    override suspend fun deleteBefore(before: Long): Int {
        val old = rows.filterValues { it.lastSeen < before }.keys
        old.forEach(rows::remove)
        return old.size
    }
    override suspend fun clear() = rows.clear()
}

class NewAsnDetectorTest {
    private val day = NewAsnDetector.DAY_MS
    private val learning = NewAsnDetector.learningMs(7)
    private val t0 = 1_700_000_000_000L

    private fun flow(pkg: String, asn: Long?, ts: Long, name: String? = "NET-$asn", domain: String? = "host$asn.example") = FlowEntity(
        session = 1, engineId = ts, ts = ts, proto = "tcp", uid = 10_100, pkg = pkg, src = "10.111.222.1:40000", dstIp = "192.0.2.1",
        dstPort = 443, domain = domain, domainSource = "sni", appProto = "tls", alpn = null, tlsVersion = null, ja4 = null, ech = false,
        httpMethod = null, verdict = "allow", reason = null, tags = "", asn = asn, asnName = name, asnCountry = "US",
    )

    private val labels = mapOf("com.android.chrome" to "Chrome", "com.example.bank" to "Bank")
    private fun detector(dao: AppAsnDao) = NewAsnDetector(dao) { labels[it] ?: it }

    @Test
    fun learningPeriodThenAlert() = runBlocking {
        val dao = FakeAppAsnDao()
        val d = detector(dao)
        // First sight of the app starts learning; new networks during learning are recorded silently.
        assertTrue(d.process(listOf(flow("com.android.chrome", 13335, t0)), true, learning).isEmpty())
        assertTrue(d.process(listOf(flow("com.android.chrome", 15169, t0 + 6 * day)), true, learning).isEmpty())
        assertEquals(2, dao.countFor("com.android.chrome"))
        // Known networks never alert, and their counters grow.
        assertTrue(d.process(listOf(flow("com.android.chrome", 13335, t0 + 8 * day)), true, learning).isEmpty())
        assertEquals(2L, dao.rows.getValue("com.android.chrome" to 13335L).flows)
        // A new network after the learning period alerts once.
        val alerts = d.process(listOf(flow("com.android.chrome", 16509, t0 + 8 * day, name = "AMAZON-02", domain = "cdn.example")), true, learning)
        assertEquals(1, alerts.size)
        val a = alerts.single()
        assertEquals(NewAsnDetector.KIND, a.kind)
        assertEquals("AS16509", a.target)
        assertEquals("medium", a.severity) // Chrome used only 2 networks so far
        assertEquals("Chrome contacted a network it has never used before: AS16509 (AMAZON-02), reached as cdn.example", a.message)
        val detail = Json.parseToJsonElement(a.detail).jsonObject
        assertEquals("16509", detail.getValue("asn").jsonPrimitive.content)
        assertEquals("AMAZON-02", detail.getValue("as_name").jsonPrimitive.content)
        assertEquals("2", detail.getValue("known_networks").jsonPrimitive.content)
        assertTrue(d.process(listOf(flow("com.android.chrome", 16509, t0 + 9 * day)), true, learning).isEmpty())
    }

    @Test
    fun disabledOnlyLearnsAndUnknownAppsAndAsnsAreSkipped() = runBlocking {
        val dao = FakeAppAsnDao()
        val d = detector(dao)
        d.process(listOf(flow("com.example.bank", 1, t0)), false, learning)
        assertTrue(d.process(listOf(flow("com.example.bank", 2, t0 + 30 * day)), false, learning).isEmpty())
        assertEquals(2, dao.countFor("com.example.bank"))
        assertTrue(d.process(listOf(flow("unknown", 3, t0), flow("com.example.bank", null, t0), flow("com.example.bank", 0, t0)), true, learning).isEmpty())
        assertEquals(2, dao.rows.size)
    }

    @Test
    fun severityDropsForAppsWithManyNetworksAndRateLimitApplies() = runBlocking {
        val dao = FakeAppAsnDao()
        val d = detector(dao)
        // One batch with many networks while learning: none alerts.
        d.process((1L..10L).map { flow("com.android.chrome", it, t0) }, true, learning)
        val now = t0 + 10 * day
        val alerts = d.process((100L..110L).map { flow("com.android.chrome", it, now + it) }, true, learning)
        assertEquals(NewAsnDetector.MAX_PER_APP_PER_HOUR, alerts.size)
        assertTrue(alerts.all { it.severity == "low" })
        assertEquals(11 - NewAsnDetector.MAX_PER_APP_PER_HOUR, d.suppressed)
        // Suppressed networks were learned: they never alert later.
        assertEquals(21, dao.countFor("com.android.chrome"))
        assertTrue(d.process(listOf(flow("com.android.chrome", 110, now + 2 * NewAsnDetector.HOUR_MS)), true, learning).isEmpty())
        // The limit window slides.
        assertEquals(1, d.process(listOf(flow("com.android.chrome", 200, now + 2 * NewAsnDetector.HOUR_MS)), true, learning).size)
    }

    @Test
    fun cacheSurvivesPruning() = runBlocking {
        val dao = FakeAppAsnDao()
        val d = detector(dao)
        d.process(listOf(flow("com.example.bank", 1, t0)), true, learning)
        dao.clear() // "clear history" or retention: learning restarts
        assertTrue(d.process(listOf(flow("com.example.bank", 1, t0 + 30 * day)), true, learning).isEmpty())
        assertEquals(1, dao.countFor("com.example.bank"))
        assertEquals(0, NewAsnDetector.learningMs(0).toInt())
        assertEquals(90 * day, NewAsnDetector.learningMs(365))
    }
}
