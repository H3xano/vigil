package dev.vigil.inspector.ui.screens

import android.content.ActivityNotFoundException
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import dev.vigil.inspector.data.FeedEntity
import dev.vigil.inspector.data.FeedKinds
import dev.vigil.inspector.data.HealthCheck
import dev.vigil.inspector.data.HealthFinding
import dev.vigil.inspector.data.HealthReport
import dev.vigil.inspector.data.SpywareSeverity
import dev.vigil.inspector.ui.FeedWork
import dev.vigil.inspector.ui.HealthCheckViewModel
import dev.vigil.inspector.ui.HealthState
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.components.Tag
import dev.vigil.inspector.ui.formatDateTime
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors
import dev.vigil.inspector.vpn.VpnStatus

/**
 * The spyware health check: compares installed apps and the recorded
 * network history with the downloaded spyware packs, on the device. Calm
 * wording on purpose: the people using it may be under stress.
 */
@Composable
fun HealthCheckScreen(vm: MainViewModel, nav: NavController) {
    val hc: HealthCheckViewModel = viewModel()
    val state by hc.state.collectAsStateWithLifecycle()
    val packs by hc.packs.collectAsStateWithLifecycle()
    val status by vm.status.collectAsStateWithLifecycle()
    val work by vm.feedWork.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val report = (state as? HealthState.Done)?.report
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri != null && report != null) {
            hc.saveJson(uri, report) { ok -> vm.showMessage(if (ok) "Report saved" else "Could not save the report") }
        }
    }

    Column(Modifier.fillMaxSize()) {
        VigilTopBar("Health check", nav)
        LazyColumn {
            item {
                Text(
                    "Checks the apps installed on this phone and the network activity vigil recorded against published " +
                        "indicators of spyware and stalkerware (Amnesty International, Citizen Lab, Echap and others). " +
                        "Everything runs on this phone, offline; nothing is uploaded and the report is not stored.",
                    Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            item { Heading("Before you start") }
            item { Readiness(packs, status is VpnStatus.Running, work, onEnableAll = hc::enableAllPacks, onUpdate = {
                hc.updatePacks()
                vm.showMessage("Updating spyware packs…")
            }) }
            item {
                Column(Modifier.fillMaxWidth().padding(16.dp)) {
                    Button(onClick = hc::run, enabled = state != HealthState.Running, modifier = Modifier.fillMaxWidth()) {
                        Text(if (report == null) "Run health check" else "Run again")
                    }
                    if (state == HealthState.Running) {
                        LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                        Text("Checking apps and history…", Modifier.padding(top = 4.dp), style = MaterialTheme.typography.bodySmall)
                    }
                    (state as? HealthState.Failed)?.let {
                        Text("The check could not finish: ${it.message}", Modifier.padding(top = 8.dp), color = VigilColors.Block)
                    }
                }
            }
            if (report != null) {
                item { Verdict(report) }
                if (report.findings.isNotEmpty()) {
                    item { Heading("Findings") }
                    items(report.findings) { f -> FindingCard(f) }
                }
                item { Heading("What to do next") }
                items(report.guidance) { g -> Guidance(g) }
                item { HelpLinks() }
                item { Heading("What was checked") }
                item {
                    Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Bullet("${report.appsChecked} installed apps (package names and signing certificates)")
                        Bullet("${report.destinationsChecked} domains and addresses from the network history")
                        report.notes.forEach { Bullet(it) }
                        Bullet("Checked ${formatDateTime(report.generatedAt)}")
                    }
                }
                item { Heading("Export") }
                item {
                    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            "The report names apps and sites from this phone. Share it only with someone you trust, such as a helpline.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        OutlinedButton(onClick = {
                            val send = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_SUBJECT, "vigil health check report")
                                putExtra(Intent.EXTRA_TEXT, HealthCheck.toText(report))
                            }
                            try {
                                context.startActivity(Intent.createChooser(send, "Share report"))
                            } catch (e: ActivityNotFoundException) {
                                vm.showMessage("No app can share text")
                            }
                        }, Modifier.fillMaxWidth()) { Text("Share as text") }
                        OutlinedButton(onClick = {
                            try {
                                save.launch("vigil-health-check-${HealthCheck.formatTime(report.generatedAt).take(10)}.json")
                            } catch (e: ActivityNotFoundException) {
                                vm.showMessage("No file picker available")
                            }
                        }, Modifier.fillMaxWidth()) { Text("Save as JSON file") }
                    }
                }
            }
            item { Spacer(Modifier.height(32.dp)) }
        }
    }
}

@Composable
private fun Heading(text: String) = SectionTitle(text, Modifier.semantics { heading() })

@Composable
private fun Bullet(text: String) {
    Text("• $text", style = MaterialTheme.typography.bodyMedium)
}

@Composable
private fun Readiness(packs: List<FeedEntity>, running: Boolean, work: FeedWork, onEnableAll: () -> Unit, onUpdate: () -> Unit) {
    val usable = packs.filter { it.kind != FeedKinds.SPYWARE_INDEX }
    val on = usable.filter { it.enabled }
    val downloaded = on.filter { it.lastUpdated != null }
    val oldest = downloaded.mapNotNull { it.lastUpdated }.minOrNull()
    Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(
            when {
                usable.isEmpty() -> "The spyware pack list has not been downloaded yet."
                on.isEmpty() -> "All ${usable.size} spyware packs are off."
                else -> "${downloaded.size} of ${on.size} enabled spyware packs downloaded" +
                    (oldest?.let { ", oldest updated ${formatRelative(it)}" } ?: "") + "."
            },
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            if (running) {
                "Inspection is on: new connections to known spyware servers raise an alert and are blocked."
            } else {
                "Inspection is off. The check still covers installed apps and the history recorded so far."
            },
            style = MaterialTheme.typography.bodyMedium,
        )
        if (work != FeedWork.IDLE) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(if (work == FeedWork.RUNNING) "Downloading packs…" else "Waiting for a network connection…", style = MaterialTheme.typography.bodySmall)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (usable.isEmpty() || on.size < usable.size) {
                OutlinedButton(onClick = onEnableAll, enabled = work == FeedWork.IDLE) { Text("Turn on all packs") }
            }
            OutlinedButton(onClick = onUpdate, enabled = work != FeedWork.RUNNING) { Text("Update packs") }
        }
    }
}

@Composable
private fun Verdict(r: HealthReport) {
    // Calm colours: amber for findings, neutral otherwise; never a full-screen red alarm.
    val accent: Color = when (r.verdict) {
        HealthCheck.VERDICT_FOUND -> VigilColors.Medium
        HealthCheck.VERDICT_WARNINGS -> VigilColors.Low
        HealthCheck.VERDICT_NOT_CHECKED -> MaterialTheme.colorScheme.onSurfaceVariant
        else -> VigilColors.Allow
    }
    val title = HealthCheck.verdictTitle(r.verdict)
    val summary = HealthCheck.verdictSummary(r)
    Card(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).semantics(mergeDescendants = true) {
            contentDescription = "Result: $title. $summary"
        },
        colors = CardDefaults.cardColors(containerColor = accent.copy(alpha = 0.12f)),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, color = accent)
            Text(summary, Modifier.padding(top = 6.dp), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun FindingCard(f: HealthFinding) {
    val uri = LocalUriHandler.current
    val indicator = f.severity == SpywareSeverity.INDICATOR
    Card(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Row(Modifier.semantics(mergeDescendants = true) {}, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(f.label, Modifier.weight(1f), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Tag(if (indicator) "INDICATOR" else "WARNING", if (indicator) VigilColors.Medium else VigilColors.Low, filled = true)
            }
            Text(HealthCheck.kindTitle(f.kind), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            f.pkg?.let { Text("App: ${f.appLabel ?: it} ($it)", style = MaterialTheme.typography.bodyMedium) }
            Text(
                "Indicator: ${f.indicator}" + (f.observed?.let { " (seen as $it)" } ?: ""),
                style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace,
            )
            if (f.kind == HealthCheck.KIND_NETWORK) {
                Text(
                    "Seen ${f.count ?: 0}×" + (f.blocked?.takeIf { it > 0 }?.let { ", $it blocked" } ?: "") +
                        (f.firstSeen?.let { " · first ${formatDateTime(it)}" } ?: "") +
                        (f.lastSeen?.let { " · last ${formatDateTime(it)}" } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                f.firstSeen?.let { Text("Installed ${formatDateTime(it)}", style = MaterialTheme.typography.bodySmall) }
            }
            Text(
                "Source: ${f.packName}" + (f.license?.let { " · $it" } ?: ""),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            f.reference?.let { ref -> Link("Read the research", ref) { runCatching { uri.openUri(ref) } } }
        }
    }
}

@Composable
private fun Guidance(text: String) {
    Text(text, Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodyMedium)
}

@Composable
private fun HelpLinks() {
    val uri = LocalUriHandler.current
    Column(Modifier.padding(horizontal = 16.dp, vertical = 4.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Link("Access Now Digital Security Helpline", HealthCheck.ACCESS_NOW) { runCatching { uri.openUri(HealthCheck.ACCESS_NOW) } }
        Link("Coalition Against Stalkerware", HealthCheck.STOP_STALKERWARE) { runCatching { uri.openUri(HealthCheck.STOP_STALKERWARE) } }
    }
}

@Composable
private fun Link(text: String, url: String, onClick: () -> Unit) {
    Text(
        text,
        Modifier.clickable(role = Role.Button, onClickLabel = "Open $url", onClick = onClick).padding(vertical = 6.dp),
        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary, textDecoration = TextDecoration.Underline,
    )
}
