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
import dev.vigil.inspector.ui.formatDateTime
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors

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
                "vigil raises alerts for threat-feed hits, periodic beaconing, apps bypassing the system resolver and encrypted DNS use.",
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
                        alertHelp(a.kind)?.let { (term, text) ->
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

private fun alertHelp(kind: String): Pair<String, String>? = when (kind) {
    "beacon" -> "Beaconing" to Glossary.BEACONING
    "threat_domain", "threat_ip" -> "Threat feed hit" to
        "The destination is listed in an enabled threat-intelligence feed (malware, phishing or C2). ${Glossary.C2}"
    "encrypted_dns" -> "Encrypted DNS" to
        "The app resolves names over DNS-over-HTTPS/TLS/QUIC, so vigil cannot see which names it looks up. " +
        "Connections are still named from TLS/QUIC SNI. ${Glossary.SNI}"
    "hardcoded_dns" -> "Bypassing system DNS" to
        "The app sent DNS queries straight to its own resolver instead of the one Android configured."
    else -> null
}
