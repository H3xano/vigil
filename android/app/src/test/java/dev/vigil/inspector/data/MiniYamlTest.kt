package dev.vigil.inspector.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

class MiniYamlTest {
    @Test
    fun mappingsSequencesAndScalars() {
        val doc = """
            # comment
            ---
            name: Test app   # trailing comment
            quoted: 'it''s'
            dq: "a \"b\" c#d"
            url: https://example.com/a#frag
            empty:
            tilde: ~
            flow: [a, 'b, c', "d"]
            none: []
            obj: {}
            list:
              - one
              - two
            indentless:
            - x
            - y
            nested:
              deeper:
                - k: v
                  k2: v2
                - plain
                -
                  lone: dash
        """.trimIndent()
        val m = MiniYaml.map(MiniYaml.parse(doc))!!
        assertEquals("Test app", m["name"])
        assertEquals("it's", m["quoted"])
        assertEquals("a \"b\" c#d", m["dq"])
        assertEquals("https://example.com/a#frag", m["url"])
        assertNull(m["empty"])
        assertEquals(true, m.containsKey("empty"))
        assertNull(m["tilde"])
        assertEquals(listOf("a", "b, c", "d"), m["flow"])
        assertEquals(emptyList<Any>(), m["none"])
        assertEquals(emptyMap<String, Any>(), m["obj"])
        assertEquals(listOf("one", "two"), m["list"])
        assertEquals(listOf("x", "y"), m["indentless"])
        val deeper = MiniYaml.map(m["nested"])!!["deeper"] as List<*>
        assertEquals(mapOf("k" to "v", "k2" to "v2"), deeper[0])
        assertEquals("plain", deeper[1])
        assertEquals(mapOf("lone" to "dash"), deeper[2])
    }

    @Test
    fun echapQuirks() {
        // "name : x" (space before the colon), lists deeper than their key, regex values with colons.
        val doc = """
            - name : jjspy
              packages:
                  - com.jj.spy
              certificate_cname_re:
              - ^Kids\WSafety\W[0-9]{2}:[0-9]{2}$
            - name: Other
              c2:
                ip:
                - 85.10.199.40
        """.trimIndent()
        val list = MiniYaml.parse(doc) as List<*>
        val a = MiniYaml.map(list[0])!!
        assertEquals("jjspy", a["name"])
        assertEquals(listOf("com.jj.spy"), a["packages"])
        assertEquals(listOf("^Kids\\WSafety\\W[0-9]{2}:[0-9]{2}$"), a["certificate_cname_re"])
        assertEquals(listOf("85.10.199.40"), MiniYaml.map(MiniYaml.map(list[1])!!["c2"])!!["ip"])
    }

    @Test
    fun blockScalarsAndHelpers() {
        val m = MiniYaml.map(MiniYaml.parse("a: |\n  line 1\n  line 2\nb: >\n  folded\n  text\n"))!!
        assertEquals("line 1\nline 2", m["a"])
        assertEquals("folded text", m["b"])
        assertEquals(listOf("a", "b", "c"), MiniYaml.strings(listOf("a", listOf("b", null), "c", mapOf("x" to "y"))))
        assertEquals(emptyList<String>(), MiniYaml.strings(null))
        assertNull(MiniYaml.parse("# only a comment\n"))
    }

    @Test
    fun rejectsBrokenStructure() {
        for (bad in listOf("a: 'unterminated", "a: {b: c}", "a: 1\n   b: 2\n c: 3", "a: [x, [y]]")) {
            try {
                MiniYaml.parse(bad)
                fail("accepted: $bad")
            } catch (e: IOException) {
                // expected
            }
        }
    }

    @Test
    fun deepNestingIsRefused() {
        val deep = (0 until 40).joinToString("\n") { "  ".repeat(it) + "k$it:" }
        try {
            MiniYaml.parse(deep)
            fail("accepted deep nesting")
        } catch (e: IOException) {
            // expected
        }
    }
}
