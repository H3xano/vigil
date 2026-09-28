package dev.vigil.inspector.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Checks the hand-written 1 → 2 migration against the exported Room schemas
 * (instrumented migration tests are not available in JVM unit tests).
 */
class MigrationTest {
    private fun schema(v: Int): JsonObject =
        Json.parseToJsonElement(File("schemas/dev.vigil.inspector.data.VigilDatabase/$v.json").readText()).jsonObject["database"]!!.jsonObject

    /** index name → CREATE INDEX statement */
    private fun indices(v: Int): Map<String, String> = schema(v)["entities"]!!.jsonArray.flatMap { e ->
        val table = e.jsonObject["tableName"]!!.jsonPrimitive.content
        e.jsonObject["indices"]?.jsonArray.orEmpty().map { i ->
            i.jsonObject["name"]!!.jsonPrimitive.content to
                i.jsonObject["createSql"]!!.jsonPrimitive.content.replace("\${TABLE_NAME}", table)
        }
    }.toMap()

    private fun tables(v: Int): Map<String, String> = schema(v)["entities"]!!.jsonArray.associate { e ->
        e.jsonObject["tableName"]!!.jsonPrimitive.content to e.jsonObject["createSql"]!!.jsonPrimitive.content
    }

    @Test
    fun migration1to2ProducesSchema2Indices() {
        assertEquals("only indices may change in 1 → 2", tables(1), tables(2))
        val result = indices(1).toMutableMap()
        for (sql in VigilDatabase.MIGRATION_1_2_SQL) {
            val name = Regex("`(index_[a-zA-Z_]+)`").find(sql)!!.groupValues[1]
            when {
                sql.startsWith("DROP INDEX") -> assertTrue("$name exists in v1", result.remove(name) != null)
                else -> result[name] = sql
            }
        }
        assertEquals(indices(2), result)
    }

    /** column name → (affinity, notNull, defaultValue) */
    private fun fields(v: Int, table: String): Map<String, Triple<String, Boolean, String?>> =
        schema(v)["entities"]!!.jsonArray.map { it.jsonObject }.single { it["tableName"]!!.jsonPrimitive.content == table }["fields"]!!
            .jsonArray.associate { f ->
                val o = f.jsonObject
                o["columnName"]!!.jsonPrimitive.content to Triple(
                    o["affinity"]!!.jsonPrimitive.content,
                    o["notNull"]!!.jsonPrimitive.content.toBoolean(),
                    o["defaultValue"]?.jsonPrimitive?.content,
                )
            }

    @Test
    fun migration2to3AddsExactlyTheSchema3Columns() {
        assertEquals("indices are unchanged in 2 → 3", indices(2), indices(3))
        val t2 = tables(2)
        val t3 = tables(3)
        assertEquals(t2.keys, t3.keys)
        val result = t2.keys.associateWith { fields(2, it).toMutableMap() }
        val created = t2.toMutableMap()
        val add = Regex("^ALTER TABLE `(\\w+)` ADD COLUMN `(\\w+)` (INTEGER|TEXT)( NOT NULL)?(?: DEFAULT (.+))?$")
        for (sql in VigilDatabase.MIGRATION_2_3_SQL) {
            val m = add.matchEntire(sql) ?: error("unexpected statement $sql")
            val (table, column, type, notNull, default) = m.destructured
            result.getValue(table)[column] = Triple(type, notNull.isNotEmpty(), default.ifEmpty { null })
            // SQLite appends the column definition to the table's CREATE statement.
            val def = sql.substringAfter("ADD COLUMN ")
            val sqlText = created.getValue(table)
            created[table] = if (", PRIMARY KEY" in sqlText) sqlText.replace(", PRIMARY KEY", ", $def, PRIMARY KEY") else sqlText.dropLast(1) + ", $def)"
        }
        for (table in t3.keys) assertEquals(table, fields(3, table), result.getValue(table).toMap())
        assertEquals(t3, created)
    }
}
