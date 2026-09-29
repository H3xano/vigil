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
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
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
import dev.vigil.inspector.R
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
import dev.vigil.inspector.ui.UiText
import dev.vigil.inspector.ui.asString
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
    val resources = LocalResources.current
    val report = (state as? HealthState.Done)?.report
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri != null && report != null) {
            hc.saveJson(uri, report) { ok -> vm.showMessage(UiText.of(if (ok) R.string.health_saved else R.string.health_save_failed)) }
        }
    }

    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.health_title), nav)
        LazyColumn {
            item {
                Text(
                    stringResource(R.string.health_intro),
                    Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            item { Heading(stringResource(R.string.health_heading_before)) }
            item { Readiness(packs, status is VpnStatus.Running, work, onEnableAll = hc::enableAllPacks, onUpdate = {
                hc.updatePacks()
                vm.showMessage(UiText.of(R.string.health_packs_updating))
            }) }
            item {
                Column(Modifier.fillMaxWidth().padding(16.dp)) {
                    Button(onClick = hc::run, enabled = state != HealthState.Running, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(if (report == null) R.string.health_run else R.string.health_run_again))
                    }
                    if (state == HealthState.Running) {
                        LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                        Text(stringResource(R.string.health_running), Modifier.padding(top = 4.dp), style = MaterialTheme.typography.bodySmall)
                    }
                    (state as? HealthState.Failed)?.let {
                        Text(stringResource(R.string.health_failed, it.message), Modifier.padding(top = 8.dp), color = VigilColors.Block)
                    }
                }
            }
            if (report != null) {
                item { Verdict(report) }
                if (report.findings.isNotEmpty()) {
                    item { Heading(stringResource(R.string.health_heading_findings)) }
                    items(report.findings) { f -> FindingCard(f) }
                }
                item { Heading(stringResource(R.string.health_heading_next)) }
                items(report.guidance) { g -> Guidance(g) }
                item { HelpLinks() }
                item { Heading(stringResource(R.string.health_heading_checked)) }
                item {
                    Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Bullet(pluralStringResource(R.plurals.health_checked_apps, report.appsChecked, report.appsChecked))
                        Bullet(pluralStringResource(R.plurals.health_checked_destinations, report.destinationsChecked, report.destinationsChecked))
                        report.notes.forEach { Bullet(it) }
                        Bullet(stringResource(R.string.health_checked_at, formatDateTime(report.generatedAt)))
                    }
                }
                item { Heading(stringResource(R.string.health_heading_export)) }
                item {
                    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            stringResource(R.string.health_export_warning),
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        OutlinedButton(onClick = {
                            val send = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_SUBJECT, resources.getString(R.string.health_report_title))
                                putExtra(Intent.EXTRA_TEXT, HealthCheck.toText(report) { it.resolve(context) })
                            }
                            try {
                                context.startActivity(Intent.createChooser(send, resources.getString(R.string.health_share_report)))
                            } catch (e: ActivityNotFoundException) {
                                vm.showMessage(UiText.of(R.string.health_share_none))
                            }
                        }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.health_share_text)) }
                        OutlinedButton(onClick = {
                            try {
                                save.launch("vigil-health-check-${HealthCheck.formatTime(report.generatedAt).take(10)}.json")
                            } catch (e: ActivityNotFoundException) {
                                vm.showMessage(UiText.of(R.string.health_save_no_picker))
                            }
                        }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.health_save_json)) }
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
                usable.isEmpty() -> stringResource(R.string.health_packs_none)
                on.isEmpty() -> pluralStringResource(R.plurals.health_packs_all_off, usable.size, usable.size)
                oldest != null -> pluralStringResource(R.plurals.health_packs_downloaded_oldest, on.size, downloaded.size, on.size, formatRelative(oldest))
                else -> pluralStringResource(R.plurals.health_packs_downloaded, on.size, downloaded.size, on.size)
            },
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            stringResource(if (running) R.string.health_inspection_on else R.string.health_inspection_off),
            style = MaterialTheme.typography.bodyMedium,
        )
        if (work != FeedWork.IDLE) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(stringResource(if (work == FeedWork.RUNNING) R.string.health_packs_downloading else R.string.health_packs_waiting), style = MaterialTheme.typography.bodySmall)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (usable.isEmpty() || on.size < usable.size) {
                OutlinedButton(onClick = onEnableAll, enabled = work == FeedWork.IDLE) { Text(stringResource(R.string.health_packs_enable_all)) }
            }
            OutlinedButton(onClick = onUpdate, enabled = work != FeedWork.RUNNING) { Text(stringResource(R.string.health_packs_update)) }
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
    val title = stringResource(HealthCheck.verdictTitle(r.verdict))
    val summary = HealthCheck.verdictSummary(r).asString()
    val description = stringResource(R.string.health_verdict_description, title, summary)
    Card(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).semantics(mergeDescendants = true) {
            contentDescription = description
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
                Tag(stringResource(if (indicator) R.string.health_tag_indicator else R.string.health_tag_warning), if (indicator) VigilColors.Medium else VigilColors.Low, filled = true)
            }
            Text(stringResource(HealthCheck.kindTitle(f.kind)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            f.pkg?.let { Text(stringResource(R.string.health_finding_app, f.appLabel ?: it, it), style = MaterialTheme.typography.bodyMedium) }
            Text(
                f.observed?.let { stringResource(R.string.health_finding_indicator_seen_as, f.indicator, it) }
                    ?: stringResource(R.string.health_finding_indicator, f.indicator),
                style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace,
            )
            if (f.kind == HealthCheck.KIND_NETWORK) {
                val count = f.count ?: 0
                val quantity = count.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                val blocked = f.blocked?.takeIf { it > 0 }
                Text(
                    listOfNotNull(
                        if (blocked != null) pluralStringResource(R.plurals.health_finding_seen_blocked, quantity, count, blocked)
                        else pluralStringResource(R.plurals.health_finding_seen, quantity, count),
                        f.firstSeen?.let { stringResource(R.string.health_finding_first, formatDateTime(it)) },
                        f.lastSeen?.let { stringResource(R.string.health_finding_last, formatDateTime(it)) },
                    ).joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                f.firstSeen?.let { Text(stringResource(R.string.health_finding_installed, formatDateTime(it)), style = MaterialTheme.typography.bodySmall) }
            }
            Text(
                f.license?.let { stringResource(R.string.health_finding_source_license, f.packName, it) }
                    ?: stringResource(R.string.health_finding_source, f.packName),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            f.reference?.let { ref -> Link(stringResource(R.string.health_finding_research), ref) { runCatching { uri.openUri(ref) } } }
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
        Link(stringResource(R.string.health_link_access_now), HealthCheck.ACCESS_NOW) { runCatching { uri.openUri(HealthCheck.ACCESS_NOW) } }
        Link(stringResource(R.string.health_link_stop_stalkerware), HealthCheck.STOP_STALKERWARE) { runCatching { uri.openUri(HealthCheck.STOP_STALKERWARE) } }
    }
}

@Composable
private fun Link(text: String, url: String, onClick: () -> Unit) {
    Text(
        text,
        Modifier.clickable(role = Role.Button, onClickLabel = stringResource(R.string.health_link_open, url), onClick = onClick).padding(vertical = 6.dp),
        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary, textDecoration = TextDecoration.Underline,
    )
}
