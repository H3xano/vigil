package dev.vigil.inspector.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import java.net.URI
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Every host a built-in feed, spyware pack, ASN table or tracker file is
 * downloaded from must trust system CAs only (a user-installed CA could
 * otherwise serve a doctored spyware pack).
 */
class NetworkSecurityConfigTest {
    private class DomainConfig(val domains: List<Pair<String, Boolean>>, val anchors: List<String>, val cleartext: Boolean)

    private fun configs(): List<DomainConfig> {
        // Unit tests run in the module directory.
        val file = listOf(File("src/main/res/xml/network_security_config.xml"), File("app/src/main/res/xml/network_security_config.xml"))
            .first { it.exists() }
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
        val list = doc.documentElement.getElementsByTagName("domain-config")
        return (0 until list.length).map { i ->
            val dc = list.item(i) as Element
            val domains = dc.getElementsByTagName("domain")
            val certs = dc.getElementsByTagName("certificates")
            DomainConfig(
                (0 until domains.length).map { j ->
                    val d = domains.item(j) as Element
                    d.textContent.trim().lowercase() to (d.getAttribute("includeSubdomains") == "true")
                },
                (0 until certs.length).map { j -> (certs.item(j) as Element).getAttribute("src") },
                dc.getAttribute("cleartextTrafficPermitted") != "false",
            )
        }
    }

    private fun builtinUrls(): List<String> {
        val packs = MvtIndex.OWNER_LICENSES.keys.map { owner -> MvtIndex.rawUrl(owner, "repo", "main", "pack.stix2")!! }
        return FeedCatalog.builtin.map { it.url } + MvtIndex.URL + TrackerDatabase.TRACKERS_URL +
            TrackerDatabase.companiesUrl(TrackerDatabase.TRACKERS_URL) + packs
    }

    /** The most specific domain-config for [host], as Android picks it. */
    private fun configFor(host: String, all: List<DomainConfig>): DomainConfig? =
        all.flatMap { c -> c.domains.map { it to c } }
            .filter { (d, _) -> host == d.first || (d.second && host.endsWith("." + d.first)) }
            .maxByOrNull { (d, _) -> d.first.length }?.second

    @Test
    fun everyBuiltinHostTrustsSystemCasOnly() {
        val all = configs()
        assertTrue(all.isNotEmpty())
        val urls = builtinUrls()
        assertTrue(urls.size > 20)
        for (url in urls) {
            assertTrue(url, url.startsWith("https://"))
            val host = URI(url).host.lowercase()
            val c = configFor(host, all)
            assertNotNull("no domain-config for $host ($url)", c)
            assertEquals(host, listOf("system"), c!!.anchors)
            assertFalse(host, c.cleartext)
        }
    }

    @Test
    fun customHostsKeepTheBaseConfig() {
        // Custom feeds and SIEM collectors (private CAs) are not caught by the system-only config.
        val all = configs()
        for (host in listOf("siem.corp.example", "evil.github.io", "bucket.s3.amazonaws.com", "misp.example.org")) {
            assertEquals(host, null, configFor(host, all))
        }
    }
}
