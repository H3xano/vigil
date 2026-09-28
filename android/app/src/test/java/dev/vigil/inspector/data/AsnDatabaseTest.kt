package dev.vigil.inspector.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.util.zip.GZIPOutputStream

class AsnDatabaseTest {
    private val sample = """
        1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET
        1.0.1.0	1.0.3.255	0	None	Not routed
        1.0.4.0	1.0.7.255	38803	AU	GTELECOM-AS-AP Gtelecom Pty Ltd
        # comment

        2606:4700::	2606:4700:ffff:ffff:ffff:ffff:ffff:ffff	13335	US	CLOUDFLARENET
        2a00:1450::	2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff	15169	US	GOOGLE
    """.trimIndent() + "\n"

    private fun gzip(text: String): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(text.toByteArray()) }
        return out.toByteArray()
    }

    private fun tmp() = File.createTempFile("asn", ".tsv").apply { deleteOnExit() }

    @Test
    fun rowsAreValidated() {
        assertEquals(13335L, AsnDatabase.parseRow("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET"))
        assertEquals(0L, AsnDatabase.parseRow("1.0.1.0\t1.0.3.255\t0\tNone\tNot routed"))
        assertEquals(64500L, AsnDatabase.parseRow("2001:db8::\t2001:db8::ffff\tAS64500"))
        assertEquals(4_200_000_000L, AsnDatabase.parseRow("10.0.0.0\t10.0.0.1\t4200000000\tZZ\tprivate use"))
        for (bad in listOf(
            "1.0.0.0\t1.0.0.255",
            "1.0.0.0 1.0.0.255 13335 US CLOUDFLARENET", // not tab-separated
            "1.0.0.300\t1.0.0.255\t1\tUS\tx",
            "1.0.0.9\t1.0.0.1\t1\tUS\tbackwards",
            "1.0.0.0\t2001:db8::\t1\tUS\tmixed",
            "1.0.0.0\t1.0.0.255\tx\tUS\tno number",
            "1.0.0.0\t1.0.0.255\t4294967296\tUS\ttoo large",
            "<html><body>captive portal</body></html>",
        )) assertNull(bad, AsnDatabase.parseRow(bad))
    }

    @Test
    fun gzipAndPlainInputsConvertToTheSameTsv() {
        val fromGz = tmp()
        val gz = tmp().apply { writeBytes(gzip(sample)) }
        val s1 = AsnDatabase.convert(gz, fromGz)
        val fromPlain = tmp()
        val s2 = AsnDatabase.convert(tmp().apply { writeText(sample) }, fromPlain)
        assertEquals(s1, s2)
        assertEquals(AsnDatabase.Stats(routed = 4, unrouted = 1, rejected = 0, asCount = 3), s1)
        assertEquals(fromGz.readText(), fromPlain.readText())
        assertEquals(5, fromGz.readLines().size) // comments and blank lines dropped
    }

    @Test(expected = IOException::class)
    fun truncatedGzipFails() {
        val bytes = gzip(sample.repeat(200))
        AsnDatabase.convert(tmp().apply { writeBytes(bytes.copyOf(bytes.size / 2)) }, tmp())
    }

    /** A gzip bomb without newlines must fail on the line cap, not build a huge String. */
    @Test
    fun gzipBombWithoutNewlinesFailsEarly() {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { gz ->
            val zeros = ByteArray(1 shl 20) { 'A'.code.toByte() }
            repeat(64) { gz.write(zeros) } // 64 MB decompressed, one "line"
        }
        val e = runCatching { AsnDatabase.convert(tmp().apply { writeBytes(out.toByteArray()) }, tmp()) }.exceptionOrNull()
        assertTrue("$e", e is IOException && e.message!!.contains("line longer"))
    }

    @Test
    fun boundedLineReaderLimits() {
        fun reader(text: String, maxLine: Int = 8, maxTotal: Long = 100) =
            BoundedLineReader(text.byteInputStream(), maxLine, maxTotal, "test file")
        val r = reader("a\r\nbb\n\nccc")
        assertEquals(listOf("a", "bb", "", "ccc", null), List(5) { r.readLine() })
        assertEquals(10L, r.totalBytes)
        assertNull(reader("").readLine())
        // UTF-8 is decoded per line, not per read.
        assertEquals("Zürich", reader("Zürich\n", maxLine = 16).readLine())
        val long = runCatching { reader("123456789\n").readLine() }.exceptionOrNull()
        assertTrue("$long", long is IOException && long.message!!.contains("longer than 8 bytes"))
        val big = runCatching { reader("a\n".repeat(60), maxTotal = 100).let { rr -> while (rr.readLine() != null) Unit } }.exceptionOrNull()
        assertTrue("$big", big is IOException && big.message!!.contains("test file larger"))
    }

    @Test
    fun validation() {
        fun stats(routed: Int, rejected: Int = 0) = AsnDatabase.Stats(routed, unrouted = 10, rejected = rejected, asCount = routed / 5)
        assertNull(AsnDatabase.validate(stats(500_000, rejected = 3), previousRouted = 480_000))
        assertNull(AsnDatabase.validate(stats(500_000), previousRouted = null))
        assertNotNull("empty", AsnDatabase.validate(AsnDatabase.Stats(0, 0, 0, 0), null))
        assertNotNull("too few rows", AsnDatabase.validate(stats(999), null))
        assertNotNull("too many rejected", AsnDatabase.validate(stats(10_000, rejected = 500), null))
        assertTrue(AsnDatabase.validate(stats(200_000), previousRouted = 500_000)!!.contains("keeping the previous copy"))
        // A captive-portal page is all rejected rows.
        val html = tmp()
        val s = AsnDatabase.convert(tmp().apply { writeText("<html>\n<body>Login</body>\n</html>\n") }, html)
        assertEquals(3, s.rejected)
        assertNotNull(AsnDatabase.validate(s, null))
    }

    @Test
    fun labels() {
        assertEquals("AS13335 CLOUDFLARENET", AsnDatabase.label(13335, "CLOUDFLARENET"))
        assertEquals("AS38803 Gtelecom Pty Ltd", AsnDatabase.label(38803, "GTELECOM-AS-AP Gtelecom Pty Ltd"))
        assertEquals("AS28573 CLARO S.A.", AsnDatabase.label(28573, "CLARO S.A."))
        assertEquals("AS64500", AsnDatabase.label(64500, ""))
        assertNull(AsnDatabase.label(null, "x"))
        assertNull(AsnDatabase.label(0, "Not routed"))
        assertEquals("AS15169 GOOGLE", AsnDatabase.networksLabel("15169", "GOOGLE"))
        assertEquals("AS1, AS2", AsnDatabase.networksLabel("1,2", null))
        assertEquals("AS1, AS2, AS3 +2", AsnDatabase.networksLabel("1,2,3,4,5", null))
        assertNull(AsnDatabase.networksLabel(null, null))
    }

    @Test
    fun pathLabels() {
        assertEquals("via WireGuard", PathLabels.via("wireguard"))
        assertEquals("via SOCKS5", PathLabels.via("socks5"))
        assertEquals("direct", PathLabels.via("direct"))
        assertNull(PathLabels.via(null))
        assertTrue(PathLabels.isTunnelled("wireguard") && PathLabels.isTunnelled("socks5"))
        assertTrue(!PathLabels.isTunnelled("direct") && !PathLabels.isTunnelled(null))
        assertEquals("DoH", PathLabels.dnsUpstream("doh"))
        assertEquals("DoT", PathLabels.dnsUpstream("dot"))
        assertNull(PathLabels.dnsUpstream(null))
    }

    @Test
    fun catalogueEntryAndRefreshAge() {
        val asn = FeedCatalog.builtin.single { it.kind == FeedKinds.ASN }
        assertEquals("asn", asn.category)
        assertTrue("metadata only, on by default", asn.enabled)
        assertTrue(asn.url.startsWith("https://iptoasn.com/"))
        assertTrue("attribution shown", asn.description.contains("iptoasn.com"))
        val day = 24L * 3600 * 1000
        assertTrue(FeedRepository.maxAgeFor(asn, 20 * 3600 * 1000L, force = false) > 6 * day)
        assertTrue(FeedRepository.maxAgeFor(asn, 20 * 3600 * 1000L, force = true) in (day / 2)..day)
        val list = FeedCatalog.builtin.first { it.kind == FeedKinds.LIST }
        assertEquals(0L, FeedRepository.maxAgeFor(list, 20 * 3600 * 1000L, force = true))
        assertEquals(20 * 3600 * 1000L, FeedRepository.maxAgeFor(list, 20 * 3600 * 1000L, force = false))
    }
}
