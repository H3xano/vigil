package dev.vigil.inspector.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EngineJsonTest {
    // Captured from vigil-cli (scripts/e2e) — the exact wire format of the Rust engine.
    private val batch = """[
      {"type":"engine","ts":1,"state":"started","message":""},
      {"type":"flow","id":1,"ts":2,"proto":"tcp","uid":10123,"src":"10.111.222.1:40000","dst_ip":"93.184.216.34","dst_port":443,
       "domain":"example.com","domain_source":"sni","app_proto":"tls","alpn":"h2","tls_version":"TLS1.3",
       "ja4":"t13d3112h2_e8f1e7e78f70_b26ce05bbdd6","ech":false,"http_method":null,"verdict":"allow","reason":null,"tags":[]},
      {"type":"flow_update","id":1,"ts":3,"tx":100,"rx":2000},
      {"type":"flow_end","id":1,"ts":4,"tx":797,"rx":5322,"duration_ms":514,"error":null},
      {"type":"dns","ts":5,"uid":null,"qname":"ads.example","qtype":"A","rcode":"NOERROR","answers":[],"verdict":"block",
       "reason":"feed:test (ads.example)","latency_ms":0,"server":"virtual","transport":"udp"},
      {"type":"alert","ts":6,"kind":"beacon","severity":"medium","uid":10123,"target":"c2.example","message":"m",
       "detail":{"interval_s":60.0,"jitter":0.01,"samples":6}},
      {"type":"stats","ts":7,"packets_in":1,"packets_out":2,"bytes_in":3,"bytes_out":4,"tcp_active":0,"udp_active":1,
       "flows_total":9,"dns_queries":15,"blocked":6,"dropped_packets":3,"dropped_events":0,"dns_cache_size":10},
      {"type":"some_future_event","ts":8}
    ]"""

    @Test
    fun parsesJa4MatchAndFeedSummary() {
        val flow = EngineJson.parseBatch(
            """[{"type":"flow","id":2,"ts":2,"proto":"udp","uid":10200,"src":"10.111.222.1:5000","dst_ip":"192.0.2.9","dst_port":443,
               "domain":"c2.example","domain_source":"quic","app_proto":"quic","alpn":"h3","tls_version":"TLS1.3",
               "ja4":"q13d0205h3_62ed6f6ca7ad_e0b9a5db47b5","ja4_match":{"feed":"ja4-foxio","rule":"q13d0205h3_62ed6f6ca7ad_*","label":"Sliver"},
               "ech":false,"http_method":null,"verdict":"block","reason":"ja4:ja4-foxio (q13d0205h3_62ed6f6ca7ad_*)","tags":[]},
              {"type":"flow","id":3,"ts":2,"proto":"tcp","src":"s","dst_ip":"d","dst_port":1,"ja4_match":null,"tags":[]}]""",
        )
        val m = (flow[0] as FlowEvent).ja4Match!!
        assertEquals(Ja4Match("ja4-foxio", "q13d0205h3_62ed6f6ca7ad_*", "Sliver"), m)
        assertEquals(null, (flow[1] as FlowEvent).ja4Match)
        val s = EngineJson.json.decodeFromString(FeedSummary.serializer(), """{"id":"x","domains":0,"ip_ranges":0,"ja4":7,"rejected_lines":1,"memory_bytes":400}""")
        assertEquals(7, s.ja4)
        val cfg = EngineConfig(upstreamDns = listOf("1.1.1.1:53"), blockJa4Matches = true).toJson()
        assertTrue(cfg.contains("\"block_ja4_matches\":true"))
    }

    @Test
    fun parsesEveryEventTypeAndSkipsUnknown() {
        val events = EngineJson.parseBatch(batch)
        assertEquals(7, events.size)
        val flow = events[1] as FlowEvent
        assertEquals("example.com", flow.domain)
        assertEquals(10123, flow.uid)
        assertEquals(443, flow.dstPort)
        assertEquals(5322L, (events[3] as FlowEndEvent).rx)
        assertEquals("block", (events[4] as DnsEvent).verdict)
        val alert = events[5] as AlertEvent
        assertTrue(alert.detail.toString().contains("interval_s"))
        assertEquals(15L, (events[6] as StatsEvent).dnsQueries)
    }

    @Test
    fun garbageYieldsEmptyBatch() {
        assertTrue(EngineJson.parseBatch("not json").isEmpty())
        assertTrue(EngineJson.parseBatch("{}").isEmpty())
    }
}
