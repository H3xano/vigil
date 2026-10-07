package dev.vigil.inspector.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class Ja4Test {
    private val sliver = "t13d190900_9dc949149365_97f8aa674fd9"

    @Test
    fun validatesTheGrammarLikeTheEngine() {
        for (ok in listOf(
            sliver,
            "q13d0312h3_55b375c5d22e_06cda9e17597",
            "t12i210700_76e208dd3e22_16bbda4055b2",
            "d13d1516h2_8daaf6152771_02713d6af862",
            "ts3i0203c9_aaaaaaaaaaaa_bbbbbbbbbbbb",
        )) assertEquals(ok, Ja4.normalize(ok))
        assertEquals("t13d1516H2_8daaf6152771_02713d6af862", Ja4.normalize(" T13D1516H2_8DAAF6152771_02713D6AF862 "))
        assertEquals("t13d1516h2_8daaf6152771_*", Ja4.normalize("t13d1516h2_8daaf6152771_*"))
        for (bad in listOf(
            "", "t13d190900_9dc949149365", "t13d190900_9dc949149365_97f8aa674fd", "x13d190900_9dc949149365_97f8aa674fd9",
            "t14d190900_9dc949149365_97f8aa674fd9", "t13x190900_9dc949149365_97f8aa674fd9", "t13d1a0900_9dc949149365_97f8aa674fd9",
            "t13d1909-0_9dc949149365_97f8aa674fd9", "t13d190900_9dc94914936g_97f8aa674fd9", "t13d190900-9dc949149365-97f8aa674fd9",
            "t13d190900_9dc949149365_97f8aa674fdé", "*_9dc949149365_97f8aa674fd9", "t13d190900_002f,0035_0005,000a_0403",
        )) assertNull(bad, Ja4.normalize(bad))
    }

    @Test
    fun formatsFeedLines() {
        assertEquals(sliver, Ja4.line(sliver, null))
        assertEquals(sliver, Ja4.line(sliver, "  "))
        assertEquals("$sliver  Sliver C2 agent", Ja4.line(sliver, "Sliver\n\tC2   agent"))
        assertEquals(Ja4.MAX_LABEL, Ja4.cleanLabel("x".repeat(500)).length)
    }

    @Test
    fun validatesPlainIndicators() {
        assertEquals("evil.example", Indicators.domain("*.EVIL.example."))
        assertNull(Indicators.domain("localhost"))
        assertNull(Indicators.domain("1.2.3.4"))
        assertNull(Indicators.domain("evil example.com"))
        assertEquals("198.51.100.0/24", Indicators.ipOrCidr("198.51.100.0/24"))
        assertEquals("2001:db8::/32", Indicators.ipOrCidr("2001:DB8::/32"))
        // IPv6 is written canonically (RFC 5952), whatever the source's spelling.
        assertEquals("2001:db8::1", Indicators.ipOrCidr("2001:DB8:0:0::1"))
        assertEquals("2001:db8::/48", Indicators.ipOrCidr(" 2001:0db8:0000::/48 "))
        assertNull(Indicators.ipOrCidr("2001:db8::/129"))
        assertNull(Indicators.ipOrCidr("198.51.100.0/33"))
        assertNull(Indicators.ipOrCidr("evil.example"))
        assertEquals("evil.example", Indicators.urlHost("https://user:pw@Evil.Example:8443/a?b#c"))
        assertEquals("203.0.113.9", Indicators.urlHost("http://203.0.113.9/gate.php"))
        assertEquals("2001:db8::7", Indicators.urlHost("http://[2001:db8::7]:80/x"))
        assertNull(Indicators.urlHost("not a url"))
    }

    @Test
    fun parsesCsvWithQuotes() {
        val rows = Csv.parse("a,b,c\r\n\"x, y\",\"say \"\"hi\"\"\",\n\"multi\nline\",2,3")
        assertEquals(listOf("a", "b", "c"), rows[0])
        assertEquals(listOf("x, y", "say \"hi\"", ""), rows[1])
        assertEquals(listOf("multi\nline", "2", "3"), rows[2])
    }

    /** Rows taken from FoxIO-LLC/ja4 ja4plus-mapping.csv (September 2026). */
    private val foxio = """
        Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes
        ,Python,,,t13i181000_85036bcba153_d41ae481755e,,,,,,
        Chromium Browser,,,,t13d1516h2_8daaf6152771_02713d6af862,,,,,,
        ,GoLang,,,t13d190900_9dc949149365_97f8aa674fd9,,,,,,
        Sliver Agent,GoLang,,,t13d190900_9dc949149365_97f8aa674fd9,,,,,,
        Sliver Agent,GoLang,,,t13i190800_9dc949149365_97f8aa674fd9,,,,,,
        Sliver/Havoc C2 Server,,,,,t130200_1301_a56c5b993250,,,,,
        IcedID ,,,,t13d201100_2b729b4bf6f3_9e7b989ebec8,,,,,,
        SoftEther VPN Client,,,,t13d880900_fcb5b95cb75a_b0d3b4ac2a14,,,,,,
        Cobalt Strike v4.9.1 beacon,,,Windows 10,t12i190700_d83cc789557e_16bbda4055b2,,,,,,Cobalt Strike v4.9.1 over wininet
        Pikabot C2,,,,,,,,,,NOT Aegir
    """.trimIndent()

    @Test
    fun convertsTheFoxioMappingToMalwareRowsOnly() {
        val lines = Ja4Converters.foxioMapping(foxio)
        assertEquals(
            listOf(
                "t13d190900_9dc949149365_97f8aa674fd9  Sliver Agent",
                "t13i190800_9dc949149365_97f8aa674fd9  Sliver Agent",
                "t13d201100_2b729b4bf6f3_9e7b989ebec8  IcedID",
                "t12i190700_d83cc789557e_16bbda4055b2  Cobalt Strike v4.9.1 beacon (Cobalt Strike v4.9.1 over wininet)",
            ),
            lines,
        )
        val dir = kotlin.io.path.createTempDirectory().toFile()
        try {
            val input = File(dir, "in.csv").apply { writeText(foxio) }
            val out = File(dir, "out.txt")
            Ja4Converters.convert(Ja4Converters.FORMAT_FOXIO_MAPPING, input, out)
            val written = out.readLines()
            assertTrue(written.first().startsWith("#"))
            assertEquals(lines, written.drop(1))
            assertTrue(runCatching { Ja4Converters.foxioMapping("<html>captive portal</html>") }.isFailure)
        } finally {
            dir.deleteRecursively()
        }
    }
}
