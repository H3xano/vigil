package dev.vigil.inspector.export

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull

/** Interprets Elasticsearch `_bulk` responses item by item. */
object ElasticBulk {
    data class Result(
        val delivered: Int,
        /** Positions (in the request) of documents to send again. */
        val retry: List<Int>,
        val rejected: Int,
        /** First error reason reported, for the status line. */
        val firstError: String?,
    )

    /**
     * Per item: 2xx is delivered, 409 (a document with this `_id` already
     * exists, i.e. an earlier attempt got through) counts as delivered, 429
     * and 5xx are retried, and any other status is a rejected document.
     * Returns null if the body cannot be interpreted, in which case the
     * caller retries the whole batch; ids make that safe.
     */
    fun parse(body: String, batchSize: Int): Result? {
        val root = runCatching { Json.parseToJsonElement(body) as? JsonObject }.getOrNull() ?: return null
        val errors = (root["errors"] as? JsonPrimitive)?.booleanOrNull ?: return null
        if (!errors) return Result(batchSize, emptyList(), 0, null)
        val items = root["items"] as? JsonArray ?: return null
        if (items.size != batchSize) return null
        var delivered = 0
        var rejected = 0
        val retry = ArrayList<Int>()
        var firstError: String? = null
        items.forEachIndexed { i, item ->
            val op = (item as? JsonObject)?.values?.firstOrNull() as? JsonObject
            val status = (op?.get("status") as? JsonPrimitive)?.intOrNull ?: 0
            when {
                status in 200..299 || status == 409 -> delivered++
                status == 429 || status >= 500 || status == 0 -> retry += i
                else -> rejected++
            }
            if (status !in 200..299 && status != 409 && firstError == null) {
                val err = op?.get("error")
                firstError = when (err) {
                    is JsonObject -> listOfNotNull((err["type"] as? JsonPrimitive)?.content, (err["reason"] as? JsonPrimitive)?.content).joinToString(": ")
                    is JsonPrimitive -> err.content
                    else -> null
                }?.let { "document status $status: $it" } ?: "document status $status"
            }
        }
        return Result(delivered, retry, rejected, firstError)
    }
}
