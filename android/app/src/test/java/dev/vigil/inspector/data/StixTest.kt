package dev.vigil.inspector.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class StixTest {
    private val ja4 = "t13d190900_9dc949149365_97f8aa674fd9"

    private fun values(p: String) = StixPattern.extract(p)

    @Test
    fun extractsSimpleComparisons() {
        assertEquals(listOf("evil.example"), values("[domain-name:value = 'Evil.Example']").domains)
        assertEquals(listOf("198.51.100.7"), values("[ipv4-addr:value = '198.51.100.7']").ips)
        assertEquals(listOf("198.51.100.0/24"), values("[ipv4-addr:value='198.51.100.0/24']").ips)
        assertEquals(listOf("2001:db8::1"), values("[ipv6-addr:value = '2001:db8::1']").ips)
        assertEquals(listOf("cdn.evil.example"), values("[url:value = 'https://cdn.evil.example/payload.bin?x=1']").domains)
        assertEquals(listOf("203.0.113.9"), values("[url:value = 'http://203.0.113.9:8080/gate.php']").ips)
        // Observation expressions combined with OR / FOLLOWEDBY, and IN lists.
        val v = values(
            "([domain-name:value = 'a.example'] OR [domain-name:value IN ('b.example', 'c.example')]) " +
                "FOLLOWEDBY [ipv4-addr:value = '192.0.2.1'] WITHIN 300 SECONDS",
        )
        assertEquals(listOf("a.example", "b.example", "c.example"), v.domains)
        assertEquals(listOf("192.0.2.1"), v.ips)
    }

    @Test
    fun extractsJa4WhateverThePath() {
        assertEquals(listOf(ja4), values("[x-ja4:value = '$ja4']").ja4)
        assertEquals(listOf(ja4), values("[network-traffic:extensions.'x-ja4-ext'.ja4 = '$ja4']").ja4)
        assertEquals(listOf(ja4), values("[x-misp-attribute:value = '$ja4' AND x-misp-attribute:type = 'ja4-fingerprint']").ja4)
        // A JA4 compared under domain-name is still a JA4, not a domain.
        assertTrue(values("[domain-name:value = '$ja4']").domains.isEmpty())
    }

    @Test
    fun skipsExclusionsAndOtherOperators() {
        assertTrue(values("[domain-name:value != 'good.example']").isEmpty)
        assertTrue(values("[ipv4-addr:value NOT IN ('192.0.2.1')]").isEmpty)
        assertTrue(values("[domain-name:value MATCHES '^evil']").isEmpty)
        assertTrue(values("[domain-name:value LIKE 'evil%']").isEmpty)
        assertTrue(values("[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']").isEmpty)
        assertTrue(values("[email-addr:value = 'phish@evil.example']").isEmpty)
        assertTrue(values("[ipv4-addr:value = 'not-an-ip']").isEmpty)
        // A NOT inside a string constant is not an operator.
        assertEquals(listOf("not.evil.example"), values("[domain-name:value = 'not.evil.example']").domains)
        // Escaped quotes do not end the constant.
        assertTrue(values("[url:value = 'http://x.example/it\\'s']").domains == listOf("x.example"))
    }

    private fun parse(s: String): JsonObject = Json.parseToJsonElement(s).jsonObject

    /** Shaped like MISP's STIX 2.1 export (misp-stix): labels, kill chain, network-traffic for ip-dst|port. */
    private val mispBundle = """
    {"type": "bundle", "id": "bundle--0c8fe7a0-4a7c-4b1d-9c3a-2f1e0f0b1a11", "objects": [
      {"type": "identity", "spec_version": "2.1", "id": "identity--55f6ea5e-2c60-40e5-964f-47a8950d210f", "name": "CIRCL",
       "identity_class": "organization", "created": "2024-05-01T10:00:00.000Z", "modified": "2024-05-01T10:00:00.000Z"},
      {"type": "report", "spec_version": "2.1", "id": "report--9b1c5a2e-0d51-4c16-8a0b-1f5b6f1d2c3e", "name": "Sliver C2 campaign",
       "published": "2024-05-01T10:00:00Z", "object_refs": ["indicator--a1"], "created": "2024-05-01T10:00:00.000Z", "modified": "2024-05-01T10:00:00.000Z"},
      {"type": "indicator", "spec_version": "2.1", "id": "indicator--a1", "created": "2024-05-01T10:00:00.000Z",
       "modified": "2024-05-01T10:00:00.000Z", "pattern": "[domain-name:value = 'update.evil.example']", "pattern_type": "stix",
       "pattern_version": "2.1", "valid_from": "2024-05-01T10:00:00Z",
       "kill_chain_phases": [{"kill_chain_name": "misp-category", "phase_name": "Network activity"}],
       "labels": ["misp:type=\"domain\"", "misp:category=\"Network activity\"", "misp:to_ids=\"True\""]},
      {"type": "indicator", "spec_version": "2.1", "id": "indicator--a2", "created": "2024-05-01T10:00:00.000Z",
       "modified": "2024-05-01T10:00:00.000Z",
       "pattern": "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '198.51.100.23' AND network-traffic:dst_port = '8888']",
       "pattern_type": "stix", "valid_from": "2024-05-01T10:00:00Z", "labels": ["misp:type=\"ip-dst|port\""]},
      {"type": "indicator", "spec_version": "2.1", "id": "indicator--a3", "created": "2024-05-01T10:00:00.000Z",
       "modified": "2024-05-01T10:00:00.000Z",
       "pattern": "[domain-name:value = 'c2.evil.example' AND domain-name:resolves_to_refs[*].value = '203.0.113.50']",
       "pattern_type": "stix", "valid_from": "2024-05-01T10:00:00Z", "labels": ["misp:type=\"domain|ip\""]},
      {"type": "indicator", "spec_version": "2.1", "id": "indicator--a4", "name": "Sliver implant",
       "created": "2024-05-01T10:00:00.000Z", "modified": "2024-05-01T10:00:00.000Z",
       "pattern": "[x-misp-attribute:type = 'ja4-fingerprint' AND x-misp-attribute:value = '$ja4']",
       "pattern_type": "stix", "valid_from": "2024-05-01T10:00:00Z"},
      {"type": "indicator", "spec_version": "2.1", "id": "indicator--a5", "created": "2024-05-01T10:00:00.000Z",
       "modified": "2024-05-01T10:00:00.000Z", "pattern": "alert tcp any any -> any 443 (msg:\"x\";)", "pattern_type": "snort",
       "valid_from": "2024-05-01T10:00:00Z"},
      {"type": "indicator", "spec_version": "2.1", "id": "indicator--a6", "created": "2024-05-01T10:00:00.000Z",
       "modified": "2024-05-01T10:00:00.000Z", "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
       "pattern_type": "stix", "valid_from": "2024-05-01T10:00:00Z"}
    ]}
    """.trimIndent()

    @Test
    fun readsMispStyleBundles() {
        val items = Stix.objects(parse(mispBundle)).mapNotNull { Stix.item(it) }
        assertEquals(listOf("indicator--a1", "indicator--a2", "indicator--a3", "indicator--a4"), items.map { it.id })
        val all = items.fold(IndicatorValues()) { acc, i -> acc + i.values }
        assertEquals(listOf("update.evil.example", "c2.evil.example"), all.domains)
        assertEquals(listOf("198.51.100.23", "203.0.113.50"), all.ips)
        assertEquals(listOf(ja4), all.ja4)
        assertEquals("Sliver implant", items.last().label)
        // Without a name the MISP labels describe the entry.
        assertTrue(items.first().label!!.startsWith("misp:type=\"domain\""))
        assertEquals(Stix.parseTime("2024-05-01T10:00:00.000Z"), items.first().version)
    }

    /** Shaped like OpenCTI's TAXII feed: name = value, x_opencti_* properties, valid_until, SCOs alongside. */
    private val openctiEnvelope = """
    {"more": false, "objects": [
      {"id": "indicator--b1", "spec_version": "2.1", "type": "indicator", "created": "2024-06-01T08:00:00.000Z",
       "modified": "2024-06-02T08:00:00.000Z", "name": "phish.evil.example", "description": "Phishing kit host",
       "pattern": "[domain-name:value = 'phish.evil.example']", "pattern_type": "stix", "valid_from": "2024-06-01T08:00:00.000Z",
       "valid_until": "2099-01-01T00:00:00.000Z", "x_opencti_score": 80, "x_opencti_detection": true,
       "x_opencti_main_observable_type": "Domain-Name", "labels": ["phishing"]},
      {"id": "indicator--b2", "spec_version": "2.1", "type": "indicator", "created": "2024-06-01T08:00:00.000Z",
       "modified": "2024-06-01T08:00:00.000Z", "name": "Old C2", "pattern": "[ipv4-addr:value = '192.0.2.200']",
       "pattern_type": "stix", "valid_from": "2023-01-01T00:00:00Z", "valid_until": "2023-06-01T00:00:00+00:00"},
      {"id": "indicator--b3", "spec_version": "2.1", "type": "indicator", "created": "2024-06-01T08:00:00.000Z",
       "modified": "2024-06-03T08:00:00.000Z", "name": "Revoked", "revoked": true,
       "pattern": "[domain-name:value = 'revoked.example']", "pattern_type": "stix", "valid_from": "2024-06-01T08:00:00Z"},
      {"id": "indicator--b4", "spec_version": "2.1", "type": "indicator", "created": "2024-06-01T08:00:00.000Z",
       "modified": "2024-06-01T08:00:00.000Z", "name": "Cobalt Strike beacon TLS", "pattern_type": "stix",
       "pattern": "[network-traffic:dst_port = 443]", "x_ja4": ["t12i210700_76e208dd3e22_16bbda4055b2", "garbage"]},
      {"id": "domain-name--c1", "spec_version": "2.1", "type": "domain-name", "value": "observable.evil.example",
       "x_opencti_score": 50},
      {"id": "ipv4-addr--c2", "spec_version": "2.1", "type": "ipv4-addr", "value": "198.51.100.99"},
      {"id": "ipv6-addr--c3", "spec_version": "2.1", "type": "ipv6-addr", "value": "2001:db8::bad"},
      {"id": "malware--m1", "spec_version": "2.1", "type": "malware", "name": "Sliver", "is_family": true}
    ]}
    """.trimIndent()

    @Test
    fun readsOpenctiStyleEnvelopes() {
        val items = Stix.objects(parse(openctiEnvelope)).mapNotNull { Stix.item(it) }.associateBy { it.id }
        assertEquals(setOf("indicator--b1", "indicator--b2", "indicator--b3", "indicator--b4", "domain-name--c1", "ipv4-addr--c2", "ipv6-addr--c3"), items.keys)
        val phish = items.getValue("indicator--b1")
        assertEquals(listOf("phish.evil.example"), phish.values.domains)
        assertEquals("phishing", phish.label) // the name only repeats the value
        assertNotNull(phish.validUntil)
        assertEquals(Stix.parseTime("2023-06-01T00:00:00Z"), items.getValue("indicator--b2").validUntil)
        assertTrue(items.getValue("indicator--b3").revoked)
        assertTrue(items.getValue("indicator--b3").values.isEmpty)
        val cs = items.getValue("indicator--b4")
        assertEquals(listOf("t12i210700_76e208dd3e22_16bbda4055b2"), cs.values.ja4)
        assertEquals("Cobalt Strike beacon TLS", cs.label)
        assertEquals(listOf("observable.evil.example"), items.getValue("domain-name--c1").values.domains)
        assertEquals(0L, items.getValue("ipv4-addr--c2").version)
        assertNull(Stix.item(parse("""{"type": "indicator", "pattern": "[domain-name:value = 'x.example']"}""")))
    }

    @Test
    fun parsesTimestamps() {
        assertEquals(0L, Stix.parseTime("1970-01-01T00:00:00Z"))
        assertEquals(1_000L, Stix.parseTime("1970-01-01T00:00:01.000Z"))
        assertEquals(3_600_000L, Stix.parseTime("1970-01-01T02:00:00+01:00"))
        assertNull(Stix.parseTime("yesterday"))
    }
}
