package dev.vigil.inspector.ui

import dev.vigil.inspector.R
import org.w3c.dom.Element
import java.io.File
import java.util.Locale
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Resolves a [UiText] against the default (English) resource files, without
 * Android, so tests can check that a translated sentence still reads exactly
 * as before in English. Only handles what the app's strings use: positional
 * arguments and the escapes \', \" and \n.
 */
object EnglishStrings {
    private val strings = HashMap<String, String>()
    private val plurals = HashMap<String, Map<String, String>>()

    init {
        val dir = listOf(File("src/main/res/values"), File("app/src/main/res/values")).first { it.isDirectory }
        val files = dir.listFiles { f -> f.name.startsWith("strings") && f.name.endsWith(".xml") }.orEmpty()
        for (file in files) {
            val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
            val root = doc.documentElement
            val nodes = root.childNodes
            for (i in 0 until nodes.length) {
                val e = nodes.item(i) as? Element ?: continue
                val name = e.getAttribute("name")
                when (e.tagName) {
                    "string" -> strings[name] = unescape(e.textContent)
                    "plurals" -> {
                        val items = e.getElementsByTagName("item")
                        plurals[name] = (0 until items.length).associate {
                            val item = items.item(it) as Element
                            item.getAttribute("quantity") to unescape(item.textContent)
                        }
                    }
                }
            }
        }
    }

    private fun unescape(s: String) = s.replace("\\'", "'").replace("\\\"", "\"").replace("\\n", "\n")

    private fun name(holder: Class<*>, id: Int): String =
        holder.fields.first { it.type == Int::class.javaPrimitiveType && it.getInt(null) == id }.name

    fun resolve(t: UiText): String = when (t) {
        is UiText.Raw -> t.text
        is UiText.Res -> format(strings.getValue(name(R.string::class.java, t.id)), t.args)
        is UiText.Plural -> {
            val forms = plurals.getValue(name(R.plurals::class.java, t.id))
            format((if (t.count == 1) forms["one"] else null) ?: forms.getValue("other"), t.args)
        }
    }

    private fun format(template: String, args: List<Any>): String =
        String.format(Locale.US, template, *args.map { if (it is UiText) resolve(it) else it }.toTypedArray())
}
