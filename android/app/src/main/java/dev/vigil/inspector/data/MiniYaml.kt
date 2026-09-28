package dev.vigil.inspector.data

import java.io.IOException

/**
 * A small reader for the block-style YAML of indicator sources (MVT's
 * `indicators.yaml`, Echap's `ioc.yaml` and `watchware.yaml`), so vigil
 * needs no YAML library. It reads:
 *
 * - block mappings (`key: value`, `key:` followed by an indented block; a
 *   space before the colon is tolerated, as in Echap's `- name : jjspy`),
 * - block sequences (`- item`, a lone `-` followed by an indented block,
 *   `- key: value` starting a mapping, and sequences at the same indentation
 *   as their key),
 * - plain, 'single-quoted' and "double-quoted" scalars, `#` comments,
 *   simple flow sequences (`[a, b]`), `{}`, and `|` / `>` block scalars.
 *
 * Anchors, aliases, tags and multi-document streams are not interpreted
 * (an alias stays a plain string). Values are [String], [List], [Map]
 * (insertion-ordered) or null. Malformed structure throws [IOException].
 */
object MiniYaml {
    /** Nesting deeper than this is rejected (no real source comes close). */
    const val MAX_DEPTH = 32

    private class Line(val number: Int, var indent: Int, var text: String)

    fun parse(text: String): Any? {
        val lines = ArrayList<Line>()
        text.removePrefix("\uFEFF").lineSequence().forEachIndexed { i, raw -> lines.addLine(i, raw.trimEnd('\r')) }
        if (lines.isEmpty()) return null
        val p = Parser(lines)
        val value = p.node(lines[0].indent, 0)
        if (p.pos < lines.size) throw IOException("YAML line ${lines[p.pos].number}: unexpected indentation")
        return value
    }

    private fun ArrayList<Line>.addLine(index: Int, raw: String) {
        val indent = raw.length - raw.trimStart(' ').length
        val content = stripComment(raw.substring(indent)).trimEnd()
        if (content.isEmpty() || content == "---" || content == "...") return
        if (content.startsWith("%")) return // directive
        add(Line(index + 1, indent, content))
    }

    /** Removes a `#` comment (at the start or after whitespace, outside quotes). */
    private fun stripComment(s: String): String {
        var quote: Char? = null
        var escaped = false
        for (i in s.indices) {
            val c = s[i]
            when {
                escaped -> escaped = false
                quote == '"' && c == '\\' -> escaped = true
                quote != null -> if (c == quote) quote = null
                (c == '\'' || c == '"') && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '-' || s[i - 1] == ':' || s[i - 1] == '[' || s[i - 1] == ',') -> quote = c
                c == '#' && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t') -> return s.substring(0, i)
            }
        }
        return s
    }

    private class Parser(val lines: List<Line>) {
        var pos = 0

        fun node(indent: Int, depth: Int): Any? {
            if (depth > MAX_DEPTH) throw IOException("YAML nested too deeply")
            if (pos >= lines.size) return null
            val line = lines[pos]
            if (line.indent < indent) return null
            return when {
                isDash(line.text) -> sequence(line.indent, depth)
                keyOf(line.text) != null -> mapping(line.indent, depth)
                else -> {
                    pos++
                    scalar(line.text, line)
                }
            }
        }

        fun sequence(indent: Int, depth: Int): List<Any?> {
            val out = ArrayList<Any?>()
            while (pos < lines.size) {
                val line = lines[pos]
                if (line.indent != indent || !isDash(line.text)) break
                val rest = line.text.substring(1).trimStart()
                if (rest.isEmpty()) {
                    pos++
                    out += if (pos < lines.size && lines[pos].indent > indent) node(lines[pos].indent, depth + 1) else null
                } else if (isDash(rest) || keyOf(rest) != null) {
                    // "- key: value" or "- - x": the rest is a nested node starting at its own column.
                    line.indent = indent + (line.text.length - rest.length)
                    line.text = rest
                    out += node(line.indent, depth + 1)
                } else {
                    pos++
                    out += scalar(rest, line)
                }
            }
            return out
        }

        fun mapping(indent: Int, depth: Int): Map<String, Any?> {
            val out = LinkedHashMap<String, Any?>()
            while (pos < lines.size) {
                val line = lines[pos]
                if (line.indent != indent || isDash(line.text)) break
                val (key, rest) = keyOf(line.text) ?: throw IOException("YAML line ${line.number}: expected a key")
                pos++
                out[key] = if (rest.isNotEmpty()) {
                    scalar(rest, line)
                } else if (pos < lines.size && lines[pos].indent > indent) {
                    node(lines[pos].indent, depth + 1)
                } else if (pos < lines.size && lines[pos].indent == indent && isDash(lines[pos].text)) {
                    // A sequence at the key's own indentation belongs to the key.
                    sequence(indent, depth + 1)
                } else {
                    null
                }
            }
            return out
        }

        /** A scalar, flow sequence or block scalar whose text starts on [line]. */
        fun scalar(s: String, line: Line): Any? {
            if (s == "|" || s == ">" || s.matches(Regex("[|>][-+]?[0-9]?"))) return blockScalar(line.indent, fold = s.startsWith(">"))
            if (s.startsWith("[") && s.endsWith("]")) return flowSequence(s.substring(1, s.length - 1), line)
            if (s == "{}") return emptyMap<String, Any?>()
            if (s.startsWith("{")) throw IOException("YAML line ${line.number}: flow mappings are not supported")
            return unquote(s, line)
        }

        private fun blockScalar(parentIndent: Int, fold: Boolean): String {
            val parts = ArrayList<String>()
            while (pos < lines.size && lines[pos].indent > parentIndent) {
                parts += lines[pos].text
                pos++
            }
            return parts.joinToString(if (fold) " " else "\n")
        }

        private fun flowSequence(inner: String, line: Line): List<Any?> {
            if (inner.isBlank()) return emptyList()
            val items = ArrayList<String>()
            val cur = StringBuilder()
            var quote: Char? = null
            for (c in inner) {
                when {
                    quote != null -> { cur.append(c); if (c == quote) quote = null }
                    c == '\'' || c == '"' -> { cur.append(c); quote = c }
                    c == ',' -> { items += cur.toString(); cur.clear() }
                    c == '[' || c == '{' -> throw IOException("YAML line ${line.number}: nested flow collections are not supported")
                    else -> cur.append(c)
                }
            }
            items += cur.toString()
            return items.map { it.trim() }.filter { it.isNotEmpty() }.map { unquote(it, line) }
        }
    }

    private fun isDash(s: String) = s == "-" || s.startsWith("- ")

    /**
     * `key: rest` (or `key : rest`) → (key, rest), or null if [s] is not a
     * mapping entry. The colon must be followed by a space or end the line,
     * so URLs and times are not keys.
     */
    private fun keyOf(s: String): Pair<String, String>? {
        if (s.startsWith("'") || s.startsWith("\"")) {
            val q = s[0]
            val end = s.indexOf(q, 1)
            if (end < 0) return null
            val after = s.substring(end + 1).trimStart()
            if (!after.startsWith(":") || (after.length > 1 && after[1] != ' ')) return null
            return s.substring(1, end) to after.substring(1).trim()
        }
        if (s.startsWith("[") || s.startsWith("{") || s.startsWith("|") || s.startsWith(">")) return null
        var i = s.indexOf(':')
        while (i >= 0) {
            if (i + 1 == s.length || s[i + 1] == ' ') {
                val key = s.substring(0, i).trim()
                if (key.isEmpty()) return null
                return key to s.substring(i + 1).trim()
            }
            i = s.indexOf(':', i + 1)
        }
        return null
    }

    private fun unquote(s: String, line: Line): String? {
        if (s.length >= 2 && s.startsWith("'") && s.endsWith("'")) return s.substring(1, s.length - 1).replace("''", "'")
        if (s.length >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
            val b = StringBuilder()
            var i = 1
            while (i < s.length - 1) {
                val c = s[i]
                if (c == '\\' && i + 1 < s.length - 1) {
                    i++
                    b.append(
                        when (s[i]) {
                            'n' -> '\n'
                            't' -> '\t'
                            '"' -> '"'
                            '\\' -> '\\'
                            '/' -> '/'
                            else -> s[i]
                        },
                    )
                } else {
                    b.append(c)
                }
                i++
            }
            return b.toString()
        }
        if (s.startsWith("'") || s.startsWith("\"")) throw IOException("YAML line ${line.number}: unterminated quoted string")
        return if (s == "~" || s == "null") null else s
    }

    /** [value] as strings: a string, the strings of a list (nested lists flattened), otherwise empty. */
    fun strings(value: Any?): List<String> = when (value) {
        is String -> listOf(value)
        is List<*> -> value.flatMap(::strings)
        else -> emptyList()
    }

    @Suppress("UNCHECKED_CAST")
    fun map(value: Any?): Map<String, Any?>? = value as? Map<String, Any?>
}
