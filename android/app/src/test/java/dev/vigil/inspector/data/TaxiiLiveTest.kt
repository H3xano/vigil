package dev.vigil.inspector.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

/**
 * Optional check against a real TAXII 2.1 server, e.g. OASIS medallion with
 * the data from its README. Skipped unless `VIGIL_TAXII_URL` (discovery URL)
 * is set; `VIGIL_TAXII_USER` / `VIGIL_TAXII_PASSWORD` give Basic credentials.
 * It lists the collections, polls the first readable one completely and then
 * incrementally, and checks that the second poll returns nothing new.
 */
class TaxiiLiveTest {
    private val url: String? = System.getenv("VIGIL_TAXII_URL")

    private fun transport(): TaxiiTransport {
        val user = System.getenv("VIGIL_TAXII_USER")
        val auth = user?.let { "Basic " + Base64.getEncoder().encodeToString("$it:${System.getenv("VIGIL_TAXII_PASSWORD").orEmpty()}".toByteArray()) }
        return TaxiiTransport { u ->
            val c = URL(u).openConnection() as HttpURLConnection
            c.setRequestProperty("Accept", TaxiiClient.MEDIA_TYPE)
            auth?.let { c.setRequestProperty("Authorization", it) }
            val code = c.responseCode
            val body = if (code in 200..299) c.inputStream.use { it.readBytes().decodeToString() } else ""
            val headers = c.headerFields.mapNotNull { (k, v) -> k?.lowercase()?.let { it to v.last() } }.toMap()
            TaxiiResponse(code, c.contentType, headers, body).also { c.disconnect() }
        }
    }

    @Test
    fun pollsARealServer() {
        assumeTrue("set VIGIL_TAXII_URL to run", url != null)
        val client = TaxiiClient(transport())
        val collection = client.collections(url!!).first { it.canRead }
        val state = TaxiiState()
        val full = client.poll(collection.apiRoot, collection.id, null) { page -> page.mapNotNull { Stix.item(it) }.forEach(state::apply) }
        println("TAXII live: ${collection.title}: $full, ${state.entries.size} indicators")
        assertTrue(full.objects > 0)
        val lines = state.feedLines(System.currentTimeMillis())
        println("TAXII live: ${lines.domains.size} domains, ${lines.ips.size} IPs, ${lines.ja4.size} JA4: ${lines.ja4}")
        val again = client.poll(collection.apiRoot, collection.id, full.nextAddedAfter) {}
        assertEquals(0, again.objects)
    }
}
