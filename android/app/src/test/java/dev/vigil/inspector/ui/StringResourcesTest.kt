package dev.vigil.inspector.ui

import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Keeps the app translatable: no English passed straight to the UI from
 * Kotlin, and translations that keep the English placeholders. See
 * docs/TRANSLATING.md.
 */
class StringResourcesTest {
    private val main = listOf(File("src/main"), File("app/src/main")).first { it.isDirectory }
    private val sources = main.resolve("java/dev/vigil/inspector")

    /** A string literal given to a UI call or a UI named argument. */
    private val uiLiteral = Regex(
        """(?:\b(?:Text|SectionTitle|SettingRow|Field|showMessage|setContentTitle|setContentText|setTicker|setName|addAction|""" +
            """Toast\.makeText|newPlainText|createChooser)\(\s*(?:[^,()"]*,\s*)?|""" +
            """\b(?:label|title|placeholder|contentDescription|supportingText|onClickLabel|text|summary|description)\s*=\s*""" +
            """(?:\{\s*Text\()?)"((?:[^"\\]|\\.)*)"""",
    )

    /** A lower-case or capitalised word of three letters or more, i.e. prose rather than a name like "WireGuard" or "DNS". */
    private val word = Regex("""(?<![A-Za-z])[A-Za-z][a-z]{2,}(?![A-Za-z])""")

    /** Literals that are not prose: examples, config syntax, commands and names. */
    private val allowed = setOf(
        "example.com",
        "dns.example",
        "https://dns.example/dns-query",
        "AdGuard companiesdb",
        "Bearer … / Splunk … / ApiKey …",
        """[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\nPublicKey = …\nEndpoint = …""",
        """wireshark -k -i TCP@${'$'}host:${'$'}{c.streamPort}\nnc ${'$'}host ${'$'}{c.streamPort} | wireshark -k -i -""",
    )

    @Test
    fun noHardCodedEnglishInTheUi() {
        val found = mutableListOf<String>()
        for (dir in listOf("ui", "vpn", "processing")) {
            sources.resolve(dir).walk().filter { it.extension == "kt" }.forEach { file ->
                file.readLines().forEachIndexed { i, line ->
                    val code = line.trim()
                    if (code.startsWith("//") || code.startsWith("*") || "Log." in code) return@forEachIndexed
                    for (m in uiLiteral.findAll(line)) {
                        val literal = m.groupValues[1]
                        if (literal in allowed) continue
                        val prose = literal.replace(Regex("""\$\{[^}]*}|\$[A-Za-z_]+"""), "")
                        if (word.containsMatchIn(prose)) found += "${file.relativeTo(sources)}:${i + 1}: \"$literal\""
                    }
                }
            }
        }
        assertTrue(
            "English text in Kotlin; move it to res/values/strings_<area>.xml (docs/TRANSLATING.md):\n" + found.joinToString("\n"),
            found.isEmpty(),
        )
    }

    @Test
    fun translationsKeepThePlaceholders() {
        val english = placeholders(main.resolve("res/values"))
        val problems = mutableListOf<String>()
        main.resolve("res").listFiles { f -> f.isDirectory && f.name.startsWith("values-") }.orEmpty().forEach { dir ->
            for ((name, args) in placeholders(dir)) {
                val source = english[name]
                when {
                    source == null -> problems += "${dir.name}: $name is not in the English strings"
                    args != source -> problems += "${dir.name}: $name uses $args, English uses $source"
                }
            }
        }
        assertTrue(problems.joinToString("\n"), problems.isEmpty())
    }

    @Test
    fun placeholdersArePositional() {
        val loose = mutableListOf<String>()
        forEachString(main.resolve("res/values")) { name, text ->
            val all = Regex("""%(?!%)(\d+\$)?[-#+ 0,(]*\d*(\.\d+)?[a-zA-Z]""").findAll(text).toList()
            if (all.size > 1 && all.any { it.groupValues[1].isEmpty() }) loose += name
        }
        assertTrue("Use %1\$s, %2\$d… when a string has several placeholders: $loose", loose.isEmpty())
    }

    /** Placeholder set per string (plural items merged), for the strings*.xml files of [dir]. */
    private fun placeholders(dir: File): Map<String, Set<String>> {
        val out = HashMap<String, MutableSet<String>>()
        forEachString(dir) { name, text ->
            val set = out.getOrPut(name) { mutableSetOf() }
            Regex("""%(\d+\$)?[-#+ 0,(]*\d*(\.\d+)?[a-zA-Z]""").findAll(text.replace("%%", "")).forEach { set += it.value }
        }
        return out
    }

    private fun forEachString(dir: File, f: (name: String, text: String) -> Unit) {
        val files = dir.listFiles { x -> x.name.startsWith("strings") && x.extension == "xml" }.orEmpty()
        for (file in files) {
            val root = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file).documentElement
            val nodes = root.childNodes
            for (i in 0 until nodes.length) {
                val e = nodes.item(i) as? Element ?: continue
                val name = e.getAttribute("name")
                when (e.tagName) {
                    "string" -> f(name, e.textContent)
                    "plurals" -> {
                        val items = e.getElementsByTagName("item")
                        for (j in 0 until items.length) f(name, items.item(j).textContent)
                    }
                }
            }
        }
    }
}
