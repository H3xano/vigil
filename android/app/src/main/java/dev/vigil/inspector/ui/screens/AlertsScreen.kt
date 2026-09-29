package dev.vigil.inspector.ui.screens

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics

import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.AlertEntity
import dev.vigil.inspector.data.AlertMute
import dev.vigil.inspector.data.AlertMutes
import dev.vigil.inspector.data.Settings
import dev.vigil.inspector.export.ExportRecords
import dev.vigil.inspector.R
import dev.vigil.inspector.ui.AlertText
import dev.vigil.inspector.ui.UiText
import dev.vigil.inspector.ui.alertTitle
import dev.vigil.inspector.ui.asString
import dev.vigil.inspector.ui.CaptureExport
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
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import java.util.Locale

private val SEVERITIES = listOf(
    "high" to R.string.alert_severity_high,
    "medium" to R.string.alert_severity_medium,
    "low" to R.string.alert_severity_low,
    "info" to R.string.alert_severity_info,
)

/** The severity as a short upper-case tag ("HIGH"). */
@Composable
private fun severityTag(severity: String): String {
    val locale = LocalConfiguration.current.locales[0]
    val id = SEVERITIES.firstOrNull { it.first == severity }?.second ?: return severity.uppercase(locale)
    return stringResource(id).uppercase(locale)
}

/**
 * The alerts shown for the chosen filters: muted ones only when [showMuted]
 * (then only them), otherwise the unmuted ones; [severity] and [kind] null
 * mean any.
 */
internal fun filterAlerts(
    alerts: List<AlertEntity>,
    mutes: List<AlertMute>,
    severity: String?,
    kind: String?,
    showMuted: Boolean,
): List<AlertEntity> = alerts.filter { a ->
    AlertMutes.isMuted(mutes, a) == showMuted &&
        (severity == null || a.severity == severity) &&
        (kind == null || a.kind == kind)
}

@Composable
fun AlertsScreen(vm: MainViewModel, nav: NavController) {
    val alerts by vm.alerts.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    var severity by rememberSaveable { mutableStateOf<String?>(null) }
    var kind by rememberSaveable { mutableStateOf<String?>(null) }
    var showMuted by rememberSaveable { mutableStateOf(false) }
    val mutes = settings.alertMutes
    val shown = remember(alerts, mutes, severity, kind, showMuted) { filterAlerts(alerts, mutes, severity, kind, showMuted) }
    val mutedCount = remember(alerts, mutes) { alerts.count { AlertMutes.isMuted(mutes, it) } }
    val kinds = remember(alerts) { alerts.map { it.kind }.distinct().sorted() }
    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.alert_screen_title)) {
            TextButton(onClick = { vm.markAlertsSeen() }) { Text(stringResource(R.string.alert_mark_all_read)) }
        }
        if (alerts.isEmpty()) {
            EmptyState(stringResource(R.string.alert_empty_title), stringResource(R.string.alert_empty_body))
            return@Column
        }
        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            for ((value, text) in SEVERITIES) {
                FilterChip(selected = severity == value, onClick = { severity = if (severity == value) null else value }, label = { Text(stringResource(text)) })
            }
            KindFilterChip(kinds, kind) { kind = it }
            if (mutedCount > 0 || showMuted) {
                FilterChip(
                    selected = showMuted, onClick = { showMuted = !showMuted },
                    label = { Text(stringResource(R.string.alert_filter_muted, mutedCount)) },
                )
            }
        }
        if (shown.isEmpty()) {
            if (showMuted) {
                EmptyState(stringResource(R.string.alert_empty_muted_title), stringResource(R.string.alert_empty_muted_body))
            } else {
                EmptyState(
                    stringResource(R.string.alert_empty_filtered_title),
                    listOfNotNull(
                        stringResource(R.string.alert_empty_filtered_body),
                        if (mutedCount > 0) pluralStringResource(R.plurals.alert_empty_filtered_hidden, mutedCount, mutedCount) else null,
                    ).joinToString(" "),
                )
            }
            return@Column
        }
        val appLabel = rememberAppLabels(vm, shown.map { it.pkg }.distinct())
        LazyColumn {
            items(shown, key = { it.id }) { a ->
                AlertItem(a, appLabel(a.pkg), settings, muted = showMuted, vm, nav)
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        }
    }
}

@Composable
private fun KindFilterChip(kinds: List<String>, selected: String?, onSelect: (String?) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        FilterChip(
            selected = selected != null,
            onClick = { if (selected != null) onSelect(null) else open = true },
            label = { Text(if (selected != null) alertTitle(selected) else stringResource(R.string.alert_filter_kind)) },
        )
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            kinds.forEach { k ->
                DropdownMenuItem(text = { Text(alertTitle(k)) }, onClick = {
                    onSelect(k)
                    open = false
                })
            }
        }
    }
}

@Composable
private fun AlertItem(a: AlertEntity, label: String, settings: Settings, muted: Boolean, vm: MainViewModel, nav: NavController) {
    var expanded by rememberSaveable(a.id) { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    Column(
        Modifier.fillMaxWidth()
            .clickable(onClickLabel = stringResource(if (expanded) R.string.alert_action_collapse else R.string.alert_action_show_details)) {
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
            val unread = stringResource(R.string.alert_state_unread)
            Text(
                alertTitle(a.kind),
                Modifier.weight(1f).semantics { if (!a.seen) stateDescription = unread },
                style = MaterialTheme.typography.titleSmall,
                fontWeight = if (a.seen) FontWeight.Normal else FontWeight.Bold,
            )
            if (muted) Tag(stringResource(R.string.alert_tag_muted))
            Spacer(Modifier.width(4.dp))
            Tag(severityTag(a.severity), VigilColors.severity(a.severity), filled = true)
        }
        Row(Modifier.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            AppIcon(a.pkg, label, 24.dp)
            Spacer(Modifier.width(8.dp))
            Text("$label · ${formatRelative(a.ts)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(AlertText.message(a, label).asString(), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 6.dp))
        if (!expanded) return@Column
        Text(formatDateTime(a.ts), style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
        alertNumbers(a.kind, a.detail)?.let {
            Text(it.asString(), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 6.dp))
        }
        alertHelp(a.kind, a.detail)?.let { (term, text) ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.alert_what_does_this_mean), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                HelpIcon(term.asString(), text.asString())
            }
        }
        Text(a.detail, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))

        val detail = detailObject(a.detail)
        val dest = ExportRecords.alertDestination(a.kind, a.target, detail)
        val flowId = detail?.long("flow_id")
        Column(Modifier.padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            val domain = dest?.domain
            when {
                domain != null -> BlockDomainButtons(domain, settings, vm, pkg = a.pkg, appLabel = label)
                dest?.ip != null -> {
                    val alreadyBlocked = a.kind == "threat_ip"
                    Text(
                        stringResource(if (alreadyBlocked) R.string.alert_ip_on_threat_feed else R.string.alert_ip_cannot_block, dest.ip),
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (!alreadyBlocked && a.pkg != "unknown" && a.pkg !in settings.blockedPackages) {
                        OutlinedButton(onClick = { vm.blockApp(a.pkg, label) }, Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.apps_block_network, label))
                        }
                    }
                }
            }
            if (flowId != null) {
                OutlinedButton(onClick = {
                    scope.launch {
                        val id = vm.flowIdForAlert(flowId, a.ts)
                        if (id != null) nav.navigate("flow/$id") else vm.showMessage(UiText.of(R.string.alert_connection_gone))
                    }
                }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.alert_view_connection)) }
            }
            if (a.pkg != "unknown") OutlinedButton(onClick = { nav.openApp(a.pkg) }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.alert_open_app)) }
            CaptureExport.forAlert(a.ts, a.kind, a.uid, a.target, flowId)?.let {
                ExportPacketsButton(vm, nav, stringResource(R.string.flow_export_packets), it)
            }
            if (muted) {
                TextButton(onClick = { vm.unmuteAlerts(a.kind, a.pkg, a.target) }) { Text(stringResource(R.string.alert_unmute)) }
            } else {
                val title = AlertText.title(a.kind)
                val expected = UiText.of(R.string.alert_marked_expected, title, a.target, label)
                val mutedKind = UiText.of(R.string.alert_muted_kind, title, label)
                TextButton(onClick = { vm.muteAlerts(a.kind, a.pkg, a.target, expected) }) { Text(stringResource(R.string.alert_mark_expected)) }
                TextButton(onClick = { vm.muteAlerts(a.kind, a.pkg, null, mutedKind) }) { Text(stringResource(R.string.alert_mute_kind)) }
                Text(
                    stringResource(R.string.alert_mute_note),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** The term and explanation behind "What does this mean?", or null for kinds without one. */
private fun alertHelp(kind: String, detail: String): Pair<UiText, UiText>? = when (kind) {
    "beacon" -> if (detailObject(detail)?.str("kind") == "intra_flow") {
        UiText.of(R.string.alert_help_beacon_in_connection) to Glossary.BEACONING_IN_CONNECTION
    } else {
        UiText.of(R.string.alert_help_beacon) to Glossary.BEACONING
    }
    "exfil_volume" -> UiText.of(R.string.alert_help_exfil) to Glossary.EXFILTRATION
    "threat_domain", "threat_ip" -> UiText.of(R.string.alert_help_threat) to UiText.of(R.string.alert_help_threat_text, Glossary.C2)
    "threat_ja4" -> UiText.of(R.string.flow_ja4_match) to Glossary.JA4_MATCH
    "new_asn" -> UiText.of(R.string.alert_help_new_asn) to Glossary.NEW_ASN
    "encrypted_dns" -> UiText.of(R.string.dns_title) to UiText.of(R.string.alert_help_encrypted_dns_text, Glossary.SNI)
    "hardcoded_dns" -> UiText.of(R.string.alert_help_hardcoded_dns) to UiText.of(R.string.alert_help_hardcoded_dns_text)
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
internal fun alertNumbers(kind: String, detail: String): UiText? {
    val d = detailObject(detail) ?: return null
    return when (kind) {
        "beacon" -> {
            val interval = d.num("interval_s") ?: return null
            val jitter = d.num("jitter") ?: 0.0
            val samples = d.long("samples")
            val burst = if (d.str("kind") == "intra_flow") d.long("burst_bytes") else null
            val rhythm = if (burst != null) {
                UiText.of(R.string.alert_numbers_rhythm_burst, formatBytes(burst), seconds(interval), seconds(interval * jitter))
            } else {
                UiText.of(R.string.alert_numbers_rhythm, seconds(interval), seconds(interval * jitter))
            }
            if (d.str("kind") == "intra_flow") {
                val to = d.str("domain") ?: d.str("dst")
                when {
                    to != null && samples != null -> UiText.plural(R.plurals.alert_numbers_intra_to_samples, quantity(samples), to, rhythm, samples)
                    to != null -> UiText.of(R.string.alert_numbers_intra_to, to, rhythm)
                    samples != null -> UiText.plural(R.plurals.alert_numbers_intra_samples, quantity(samples), rhythm, samples)
                    else -> UiText.of(R.string.alert_numbers_intra, rhythm)
                }
            } else if (samples != null) {
                UiText.plural(R.plurals.alert_numbers_connections_samples, quantity(samples), rhythm, samples)
            } else {
                UiText.of(R.string.alert_numbers_connections, rhythm)
            }
        }
        "exfil_volume" -> {
            val up = d.long("uploaded_bytes") ?: return null
            val window: Any = d.str("window") ?: UiText.of(R.string.alert_numbers_exfil_window_unknown)
            val base = d.long("baseline_bytes_per_hour")
            val factor = d.num("factor") ?: 3.0
            val baseText = if (base != null) {
                UiText.of(R.string.alert_numbers_exfil_baseline, formatBytes(base), factor)
            } else {
                UiText.of(R.string.alert_numbers_exfil_no_baseline)
            }
            val main = UiText.of(R.string.alert_numbers_exfil, formatBytes(up), window, baseText, formatBytes(d.long("floor_bytes") ?: 0))
            val dest = d.str("destination") ?: return main
            UiText.of(
                R.string.alert_numbers_exfil_destination, main, dest,
                formatBytes(d.long("dest_tx_bytes") ?: 0), formatBytes(d.long("dest_rx_bytes") ?: 0),
            )
        }
        else -> null
    }
}
