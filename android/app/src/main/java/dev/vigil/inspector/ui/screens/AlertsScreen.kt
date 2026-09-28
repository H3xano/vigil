package dev.vigil.inspector.ui.screens

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.processing.AlertNotifier
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.AppIcon
import dev.vigil.inspector.ui.components.EmptyState
import dev.vigil.inspector.ui.components.SeverityDot
import dev.vigil.inspector.ui.components.Tag
import dev.vigil.inspector.engine.EngineJson
import dev.vigil.inspector.ui.formatBytes
import dev.vigil.inspector.ui.formatDateTime
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import java.util.Locale

@Composable
fun AlertsScreen(vm: MainViewModel, nav: NavController) {
    val alerts by vm.alerts.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    Column(Modifier.fillMaxSize()) {
        VigilTopBar("Alerts") {
            TextButton(onClick = { vm.markAlertsSeen() }) { Text("Mark all read") }
        }
        if (alerts.isEmpty()) {
            EmptyState(
                "No alerts",
                "vigil raises alerts for threat-feed hits, periodic beaconing, unusual background uploads, apps bypassing the system resolver and encrypted DNS use.",
            )
            return@Column
        }
        val appLabel = rememberAppLabels(vm, alerts.map { it.pkg }.distinct())
        LazyColumn {
            items(alerts, key = { it.id }) { a ->
                var expanded by rememberSaveable(a.id) { mutableStateOf(false) }
                val label = appLabel(a.pkg)
                Column(
                    Modifier.fillMaxWidth()
                        .clickable(onClickLabel = if (expanded) "Collapse" else "Show details") {
                            expanded = !expanded
                            // Opening an alert counts as reading it.
                            if (expanded && !a.seen) vm.markAlertSeen(a.id)
                        }
                        .animateContentSize()
                        .padding(16.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SeverityDot(a.severity)
                        Spacer(Modifier.width(8.dp))
                        Text(
                            AlertNotifier.titleFor(a.kind).replaceFirstChar { it.uppercase() },
                            Modifier.weight(1f).semantics { if (!a.seen) stateDescription = "Unread" },
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = if (a.seen) FontWeight.Normal else FontWeight.Bold,
                        )
                        Tag(a.severity.uppercase(), VigilColors.severity(a.severity), filled = true)
                    }
                    Row(Modifier.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        AppIcon(a.pkg, label, 24.dp)
                        Spacer(Modifier.width(8.dp))
                        Text("$label · ${formatRelative(a.ts)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Text(a.message, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 6.dp))
                    if (expanded) {
                        Text(formatDateTime(a.ts), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
                        alertNumbers(a.kind, a.detail)?.let {
                            Text(it, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 6.dp))
                        }
                        alertHelp(a.kind, a.detail)?.let { (term, text) ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("What does this mean?", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                HelpIcon(term, text)
                            }
                        }
                        Text(a.detail, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
                        Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            val target = a.target
                            if (target.contains('.') && !target.first().isDigit() && target !in settings.denyDomains) {
                                OutlinedButton(onClick = { vm.denyDomain(target) }) { Text("Block $target") }
                            }
                            if (a.pkg != "unknown") OutlinedButton(onClick = { nav.navigate("app/${a.pkg}") }) { Text("Open app") }
                        }
                    }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        }
    }
}

private fun alertHelp(kind: String, detail: String): Pair<String, String>? = when (kind) {
    "beacon" -> if (detailObject(detail)?.str("kind") == "intra_flow") {
        "Beaconing inside a connection" to Glossary.BEACONING_IN_CONNECTION
    } else {
        "Beaconing" to Glossary.BEACONING
    }
    "exfil_volume" -> "Exfiltration" to Glossary.EXFILTRATION
    "threat_domain", "threat_ip" -> "Threat feed hit" to
        "The destination is listed in an enabled threat-intelligence feed (malware, phishing or C2). ${Glossary.C2}"
    "threat_ja4" -> "JA4 match" to Glossary.JA4_MATCH
    "new_asn" -> "New network for this app" to Glossary.NEW_ASN
    "encrypted_dns" -> "Encrypted DNS" to
        "The app resolves names over DNS-over-HTTPS/TLS/QUIC, so vigil cannot see which names it looks up. " +
        "Connections are still named from TLS/QUIC SNI. ${Glossary.SNI}"
    "hardcoded_dns" -> "Bypassing system DNS" to
        "The app sent DNS queries straight to its own resolver instead of the one Android configured."
    else -> null
}

private fun detailObject(detail: String): JsonObject? =
    runCatching { EngineJson.json.parseToJsonElement(detail) as? JsonObject }.getOrNull()

private fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
private fun JsonObject.num(key: String): Double? = (this[key] as? JsonPrimitive)?.doubleOrNull
private fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.longOrNull

private fun seconds(s: Double): String = if (s >= 100) String.format(Locale.US, "%.0f s", s) else String.format(Locale.US, "%.1f s", s)

/**
 * The numbers behind a beacon or upload-volume alert in plain words, or
 * null for other kinds and unreadable details (older alerts, other versions).
 */
internal fun alertNumbers(kind: String, detail: String): String? {
    val d = detailObject(detail) ?: return null
    return when (kind) {
        "beacon" -> {
            val interval = d.num("interval_s") ?: return null
            val jitter = d.num("jitter") ?: 0.0
            val samples = d.long("samples")
            val every = "every ${seconds(interval)} ± ${seconds(interval * jitter)}"
            if (d.str("kind") == "intra_flow") {
                val burst = d.long("burst_bytes")?.let { "a burst of about ${formatBytes(it)} " }.orEmpty()
                val to = d.str("domain") ?: d.str("dst")
                "Inside one open connection${to?.let { " to $it" }.orEmpty()}: $burst$every" +
                    (samples?.let { " ($it bursts)" }.orEmpty())
            } else {
                "A new connection $every" + (samples?.let { " ($it connections)" }.orEmpty())
            }
        }
        "exfil_volume" -> {
            val up = d.long("uploaded_bytes") ?: return null
            val window = d.str("window") ?: "the window"
            val base = d.long("baseline_bytes_per_hour")
            val factor = d.num("factor") ?: 3.0
            val baseText = if (base != null) {
                "usual busiest hour ${formatBytes(base)} (alerts above ${String.format(Locale.US, "%.0f", factor)}× that)"
            } else {
                "no upload history yet"
            }
            val dest = d.str("destination")
            val destText = if (dest != null) {
                "\nTo $dest: ${formatBytes(d.long("dest_tx_bytes") ?: 0)} sent, ${formatBytes(d.long("dest_rx_bytes") ?: 0)} received"
            } else {
                ""
            }
            "Uploaded ${formatBytes(up)} in $window; $baseText; floor ${formatBytes(d.long("floor_bytes") ?: 0)}$destText"
        }
        else -> null
    }
}
