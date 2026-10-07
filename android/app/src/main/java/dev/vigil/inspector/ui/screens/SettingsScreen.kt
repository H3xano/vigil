package dev.vigil.inspector.ui.screens

import android.content.Intent
import android.provider.Settings as AndroidSettings
import androidx.compose.foundation.clickable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.BuildConfig
import dev.vigil.inspector.R
import dev.vigil.inspector.data.UpstreamSettings
import dev.vigil.inspector.engine.VigilNative
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.asString
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.vpn.ConfigFactory
import dev.vigil.inspector.ui.startActivitySafely

@Composable
fun SettingRow(
    title: String,
    summary: String? = null,
    checked: Boolean? = null,
    onClick: (() -> Unit)? = null,
    onChecked: ((Boolean) -> Unit)? = null,
    enabled: Boolean = true,
) {
    // A switch row is one focus target: the whole row toggles, and the
    // Switch itself is decorative (onCheckedChange = null).
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = summary?.let { { Text(it) } },
        trailingContent = checked?.let { c -> { Switch(checked = c, onCheckedChange = null, enabled = enabled) } },
        modifier = Modifier.fillMaxWidth().let { m ->
            when {
                checked != null && onChecked != null -> m.toggleable(value = checked, enabled = enabled, role = Role.Switch, onValueChange = onChecked)
                onClick != null -> m.clickable(onClick = onClick)
                else -> m
            }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun <T> Segmented(options: List<Pair<T, String>>, selected: T, onSelect: (T) -> Unit, modifier: Modifier = Modifier) {
    SingleChoiceSegmentedButtonRow(modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
        options.forEachIndexed { i, (value, label) ->
            SegmentedButton(
                selected = value == selected,
                onClick = { onSelect(value) },
                shape = SegmentedButtonDefaults.itemShape(i, options.size),
            ) { Text(label, maxLines = 1) }
        }
    }
}

@Composable
fun SettingsScreen(vm: MainViewModel, nav: NavController) {
    val s by vm.settings.collectAsStateWithLifecycle()
    val feeds by vm.feeds.collectAsStateWithLifecycle()
    val configError by vm.configError.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var confirmClear by rememberSaveable { mutableStateOf(false) }
    var editUpstreams by rememberSaveable { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.settings_title))
        Column(Modifier.verticalScroll(rememberScrollState())) {
            configError?.let { ConfigErrorCard(it) { vm.dismissConfigError() } }
            SectionTitle(stringResource(R.string.settings_section_blocking))
            Row(Modifier.padding(start = 16.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.settings_sinkhole_label), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                HelpIcon(stringResource(R.string.settings_sinkhole_help_title), Glossary.SINKHOLE)
            }
            // DNS answer syntax: not translated.
            Segmented(listOf("null_ip" to "0.0.0.0 / ::", "nxdomain" to "NXDOMAIN"), s.sinkhole, { v -> vm.updateSettings { it.copy(sinkhole = v) } })
            Text(
                stringResource(if (s.sinkhole == "nxdomain") R.string.settings_sinkhole_nxdomain_summary else R.string.settings_sinkhole_null_ip_summary),
                Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SettingRow(
                stringResource(R.string.settings_block_encrypted_dns_title),
                stringResource(R.string.settings_block_encrypted_dns_summary),
                s.blockEncryptedDns, onChecked = { v -> vm.updateSettings { it.copy(blockEncryptedDns = v) } },
            )
            val enabledFeeds = feeds.filter { it.enabled }
            val feedDomains = enabledFeeds.sumOf { it.domains }
            val feedRanges = enabledFeeds.sumOf { it.ipRanges }
            SettingRow(
                stringResource(R.string.settings_feeds_title),
                stringResource(
                    R.string.settings_feeds_summary,
                    pluralStringResource(R.plurals.settings_feeds_enabled, enabledFeeds.size, enabledFeeds.size),
                    pluralStringResource(R.plurals.settings_feeds_domains, feedDomains, feedDomains),
                    pluralStringResource(R.plurals.settings_feeds_ip_ranges, feedRanges, feedRanges),
                ),
                onClick = { nav.navigate("feeds") },
            )
            SettingRow(
                stringResource(R.string.settings_health_title),
                stringResource(R.string.settings_health_summary),
                onClick = { nav.navigate("health") },
            )
            SettingRow(
                stringResource(R.string.settings_rules_title),
                stringResource(
                    R.string.settings_rules_summary,
                    pluralStringResource(R.plurals.settings_rules_blocked, s.denyDomains.size, s.denyDomains.size),
                    pluralStringResource(R.plurals.settings_rules_allowed, s.allowDomains.size, s.allowDomains.size),
                ),
                onClick = { nav.navigate("rules") },
            )

            SectionTitle(stringResource(R.string.settings_section_network))
            val route = when (s.upstream.mode) {
                UpstreamSettings.MODE_WIREGUARD -> s.upstream.wireguard?.endpoint?.let { stringResource(R.string.settings_route_wireguard_to, it) } ?: "WireGuard"
                UpstreamSettings.MODE_SOCKS5 -> stringResource(R.string.settings_route_socks5, ConfigFactory.hostPort(s.upstream.socks5.host, s.upstream.socks5.port))
                else -> stringResource(R.string.settings_route_direct)
            }
            SettingRow(
                stringResource(R.string.upstream_title),
                if (s.upstream.mode != UpstreamSettings.MODE_DIRECT && !s.upstream.failClosed) stringResource(R.string.settings_route_falls_back, route) else route,
                onClick = { nav.navigate("upstream") },
            )
            SettingRow(
                stringResource(R.string.settings_exclude_lan_title),
                stringResource(R.string.settings_exclude_lan_summary),
                s.excludeLan, onChecked = { v -> vm.updateSettings { it.copy(excludeLan = v) } },
            )
            SettingRow(
                stringResource(R.string.settings_max_throughput_title),
                stringResource(R.string.settings_max_throughput_summary),
                s.maxThroughput, onChecked = { v -> vm.updateSettings { it.copy(maxThroughput = v) } },
            )
            Text(stringResource(R.string.settings_upstream_dns_label), Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodyMedium)
            Segmented(
                listOf("network" to stringResource(R.string.settings_upstream_dns_network), "custom" to stringResource(R.string.settings_upstream_dns_custom)),
                s.upstreamMode, { v -> vm.updateSettings { it.copy(upstreamMode = v) } },
            )
            if (s.upstreamMode == "custom") {
                SettingRow(stringResource(R.string.settings_custom_resolvers_title), s.customUpstreams.joinToString(", "), onClick = { editUpstreams = true })
            }
            SettingRow(
                stringResource(R.string.settings_encrypted_dns_title),
                if (s.encryptedDns.enabled) {
                    val summary = s.encryptedDns.summary().asString()
                    if (s.encryptedDns.fallbackPlain) stringResource(R.string.settings_encrypted_dns_falls_back, summary) else summary
                } else {
                    stringResource(R.string.settings_encrypted_dns_off)
                },
                onClick = { nav.navigate("dns") },
            )

            SectionTitle(stringResource(R.string.settings_section_detection))
            SettingRow(
                stringResource(R.string.settings_beacon_title),
                stringResource(R.string.settings_beacon_summary),
                s.beaconEnabled, onChecked = { v -> vm.updateSettings { it.copy(beaconEnabled = v) } },
            )
            if (s.beaconEnabled) {
                Segmented(
                    listOf(
                        "low" to stringResource(R.string.settings_beacon_strict),
                        "normal" to stringResource(R.string.settings_beacon_balanced),
                        "high" to stringResource(R.string.settings_beacon_sensitive),
                    ),
                    s.beaconSensitivity,
                    { v -> vm.updateSettings { it.copy(beaconSensitivity = v) } })
            }
            SettingRow(
                stringResource(R.string.settings_exfil_title),
                stringResource(R.string.settings_exfil_summary, s.exfil.floorMbPerHour),
                s.exfil.enabled, onChecked = { v -> vm.updateSettings { it.copy(exfil = it.exfil.copy(enabled = v)) } },
            )
            if (s.exfil.enabled) {
                // Units, as in formatBytes: not translated.
                Segmented(listOf(20 to "20 MB/h", 50 to "50 MB/h", 100 to "100 MB/h", 250 to "250 MB/h"), s.exfil.floorMbPerHour,
                    { v -> vm.updateSettings { it.copy(exfil = it.exfil.copy(floorMbPerHour = v)) } })
            }
            SettingRow(
                stringResource(R.string.settings_novelty_title),
                stringResource(R.string.settings_novelty_summary),
                s.noveltyAlerts, onChecked = { v -> vm.updateSettings { it.copy(noveltyAlerts = v) } },
            )
            SettingRow(
                stringResource(R.string.settings_new_asn_title),
                pluralStringResource(R.plurals.settings_new_asn_summary, s.asnLearningDays, s.asnLearningDays),
                s.newAsnAlerts, onChecked = { v -> vm.updateSettings { it.copy(newAsnAlerts = v) } },
            )
            if (s.newAsnAlerts) {
                Text(stringResource(R.string.settings_learning_period), Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodyMedium)
                Segmented(listOf(1, 7, 14, 30).map { it to pluralStringResource(R.plurals.settings_days, it, it) }, s.asnLearningDays,
                    { v -> vm.updateSettings { it.copy(asnLearningDays = v) } })
            }
            SettingRow(stringResource(R.string.settings_notify_title), stringResource(R.string.settings_notify_summary), s.notifyAlerts,
                onChecked = { v -> vm.updateSettings { it.copy(notifyAlerts = v) } })

            SectionTitle(stringResource(R.string.capture_title))
            SettingRow(
                stringResource(R.string.capture_title),
                when {
                    !s.capture.enabled -> stringResource(R.string.settings_capture_off)
                    s.capture.streamRefused() -> stringResource(R.string.settings_capture_not_streaming, s.capture.bufferMb)
                    s.capture.streamEnabled -> stringResource(R.string.settings_capture_streaming, s.capture.bufferMb, s.capture.streamPort.toString())
                    else -> stringResource(R.string.settings_capture_recording, s.capture.bufferMb)
                },
                onClick = { nav.navigate("capture") },
            )

            SectionTitle(stringResource(R.string.settings_section_enterprise))
            SettingRow(
                stringResource(R.string.export_title),
                if (s.export.enabled) {
                    val level = when (s.export.level) {
                        "alerts" -> stringResource(R.string.settings_siem_level_alerts)
                        "alerts_dns" -> stringResource(R.string.settings_siem_level_alerts_dns)
                        "all" -> stringResource(R.string.settings_siem_level_all)
                        else -> s.export.level.replace("_", " + ")
                    }
                    // Protocol names: not translated.
                    stringResource(R.string.settings_siem_streaming, level, if (s.export.mode == "http") "HTTP" else "syslog/${s.export.transport}")
                } else {
                    stringResource(R.string.common_off)
                },
                onClick = { nav.navigate("export") },
            )

            SectionTitle(stringResource(R.string.settings_section_permissions))
            SettingRow(
                stringResource(R.string.settings_usage_access_title),
                stringResource(if (usageAccessGranted(vm)) R.string.settings_usage_access_granted else R.string.settings_usage_access_not_granted),
                onClick = { context.startActivitySafely(Intent(AndroidSettings.ACTION_USAGE_ACCESS_SETTINGS)) })
            SettingRow(stringResource(R.string.settings_always_on_title), stringResource(R.string.settings_always_on_summary),
                onClick = { context.startActivitySafely(Intent(AndroidSettings.ACTION_VPN_SETTINGS)) })
            SettingRow(stringResource(R.string.settings_notifications_title), stringResource(R.string.settings_notifications_summary), onClick = {
                context.startActivitySafely(Intent(AndroidSettings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(AndroidSettings.EXTRA_APP_PACKAGE, context.packageName))
            })

            SectionTitle(stringResource(R.string.settings_section_data))
            Text(stringResource(R.string.settings_keep_history), Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodyMedium)
            Segmented(listOf(1, 7, 30, 90).map { it to pluralStringResource(R.plurals.settings_days, it, it) }, s.retentionDays,
                { v -> vm.updateSettings { it.copy(retentionDays = v) } })
            SettingRow(stringResource(R.string.settings_clear_history_title), stringResource(R.string.settings_clear_history_summary), onClick = { confirmClear = true })

            SectionTitle(stringResource(R.string.settings_section_about))
            // Product name and version: not translated.
            SettingRow(
                "vigil ${BuildConfig.VERSION_NAME}",
                stringResource(R.string.settings_engine_version, runCatching { VigilNative.nativeVersion() }.getOrDefault("?")),
            )
            SettingRow(stringResource(R.string.settings_source_code), "github.com/H3xano/vigil", onClick = {
                context.startActivitySafely(Intent(Intent.ACTION_VIEW, "https://github.com/H3xano/vigil".toUri()))
            })
            Row(Modifier.padding(24.dp)) {}
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text(stringResource(R.string.settings_clear_history_confirm_title)) },
            text = { Text(stringResource(R.string.settings_clear_history_confirm_text)) },
            confirmButton = { TextButton(onClick = { vm.clearHistory(); confirmClear = false }) { Text(stringResource(R.string.settings_clear_history_confirm)) } },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
    if (editUpstreams) {
        var text by rememberSaveable { mutableStateOf(s.customUpstreams.joinToString(", ")) }
        val parsed = text.split(',', ' ', '\n').filter { it.isNotBlank() }
        val invalid = parsed.filter { ConfigFactory.normalizeResolver(it) == null }
        AlertDialog(
            onDismissRequest = { editUpstreams = false },
            title = { Text(stringResource(R.string.settings_custom_resolvers_title)) },
            text = {
                Column {
                    Text(stringResource(R.string.settings_custom_resolvers_hint), style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(text, { text = it }, Modifier.fillMaxWidth().padding(top = 8.dp), isError = invalid.isNotEmpty(),
                        supportingText = { if (invalid.isNotEmpty()) Text(stringResource(R.string.settings_custom_resolvers_invalid, invalid.joinToString())) })
                }
            },
            confirmButton = {
                TextButton(enabled = invalid.isEmpty() && parsed.isNotEmpty(), onClick = {
                    vm.updateSettings { it.copy(customUpstreams = parsed) }
                    editUpstreams = false
                }) { Text(stringResource(R.string.common_save)) }
            },
            dismissButton = { TextButton(onClick = { editUpstreams = false }) { Text(stringResource(R.string.common_cancel)) } },
        )
    }
}
