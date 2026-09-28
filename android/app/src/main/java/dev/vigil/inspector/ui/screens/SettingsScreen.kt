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
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.BuildConfig
import dev.vigil.inspector.data.UpstreamSettings
import dev.vigil.inspector.engine.VigilNative
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.vpn.ConfigFactory

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
        VigilTopBar("Settings")
        Column(Modifier.verticalScroll(rememberScrollState())) {
            configError?.let { ConfigErrorCard(it) { vm.dismissConfigError() } }
            SectionTitle("Blocking")
            Row(Modifier.padding(start = 16.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("Answer for blocked domains", Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                HelpIcon("Blocked-domain answer", Glossary.SINKHOLE)
            }
            Segmented(listOf("null_ip" to "0.0.0.0 / ::", "nxdomain" to "NXDOMAIN"), s.sinkhole, { v -> vm.updateSettings { it.copy(sinkhole = v) } })
            Text(
                if (s.sinkhole == "nxdomain") "Blocked names are reported as nonexistent." else "Blocked names resolve to an address that goes nowhere (recommended).",
                Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SettingRow(
                "Block encrypted DNS",
                "Refuse DNS-over-TLS/QUIC and known DNS-over-HTTPS servers so apps fall back to DNS that vigil can inspect. " +
                    "Breaks DNS if Private DNS is in strict mode.",
                s.blockEncryptedDns, onChecked = { v -> vm.updateSettings { it.copy(blockEncryptedDns = v) } },
            )
            val enabledFeeds = feeds.filter { it.enabled }
            SettingRow(
                "Threat intelligence feeds",
                "${enabledFeeds.size} enabled · ${enabledFeeds.sumOf { it.domains }} domains, ${enabledFeeds.sumOf { it.ipRanges }} IP ranges · " +
                    "downloaded daily from their publishers",
                onClick = { nav.navigate("feeds") },
            )
            SettingRow(
                "Spyware health check",
                "Check installed apps and recorded activity against known spyware and stalkerware indicators, on this phone",
                onClick = { nav.navigate("health") },
            )
            SettingRow("Custom rules", "${s.denyDomains.size} blocked · ${s.allowDomains.size} allowed domains", onClick = { nav.navigate("rules") })

            SectionTitle("Network")
            SettingRow(
                "Route through VPN / proxy",
                when (s.upstream.mode) {
                    UpstreamSettings.MODE_WIREGUARD -> "WireGuard" + (s.upstream.wireguard?.endpoint?.let { " to $it" } ?: "")
                    UpstreamSettings.MODE_SOCKS5 -> "SOCKS5 proxy ${ConfigFactory.hostPort(s.upstream.socks5.host, s.upstream.socks5.port)}"
                    else -> "Direct. Use your WireGuard server or a SOCKS5 proxy (e.g. Tor) while vigil runs."
                } + if (s.upstream.mode != UpstreamSettings.MODE_DIRECT && !s.upstream.failClosed) " · falls back to direct" else "",
                onClick = { nav.navigate("upstream") },
            )
            SettingRow(
                "Keep local network traffic direct",
                "Private and link-local destinations (printers, casting, NAS) bypass the inspector. Changing this restarts inspection.",
                s.excludeLan, onChecked = { v -> vm.updateSettings { it.copy(excludeLan = v) } },
            )
            SettingRow(
                "Maximum throughput",
                "Uses a second engine thread for the fastest connections (roughly above 500 Mbit/s). Uses more battery; off is best for everyday use. Changing this restarts inspection.",
                s.maxThroughput, onChecked = { v -> vm.updateSettings { it.copy(maxThroughput = v) } },
            )
            Text("Upstream DNS resolver", Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodyMedium)
            Segmented(listOf("network" to "Network's resolver", "custom" to "Custom"), s.upstreamMode, { v -> vm.updateSettings { it.copy(upstreamMode = v) } })
            if (s.upstreamMode == "custom") {
                SettingRow("Custom resolvers", s.customUpstreams.joinToString(", "), onClick = { editUpstreams = true })
            }
            SettingRow(
                "Encrypted DNS",
                if (s.encryptedDns.enabled) {
                    s.encryptedDns.summary() + if (s.encryptedDns.fallbackPlain) " · falls back to plain DNS" else ""
                } else {
                    "Off: lookups go to the resolver above unencrypted. Use DNS over TLS or HTTPS instead."
                },
                onClick = { nav.navigate("dns") },
            )

            SectionTitle("Detection")
            SettingRow(
                "Beaconing detection",
                "Alert when an app contacts the same destination at a near-constant interval, or sends small bursts through one open connection at a near-constant interval: malware checking in with its command-and-control (C2) server, but also telemetry heartbeats. Push services are skipped.",
                s.beaconEnabled, onChecked = { v -> vm.updateSettings { it.copy(beaconEnabled = v) } },
            )
            if (s.beaconEnabled) {
                Segmented(listOf("low" to "Strict", "normal" to "Balanced", "high" to "Sensitive"), s.beaconSensitivity,
                    { v -> vm.updateSettings { it.copy(beaconSensitivity = v) } })
            }
            SettingRow(
                "Unusual upload alerts",
                "Alert when an app uploads far more than usual while in the background (possible data theft): at least " +
                    "${s.exfil.floorMbPerHour} MB in an hour and several times its own busiest hour of the past week.",
                s.exfil.enabled, onChecked = { v -> vm.updateSettings { it.copy(exfil = it.exfil.copy(enabled = v)) } },
            )
            if (s.exfil.enabled) {
                Segmented(listOf(20 to "20 MB/h", 50 to "50 MB/h", 100 to "100 MB/h", 250 to "250 MB/h"), s.exfil.floorMbPerHour,
                    { v -> vm.updateSettings { it.copy(exfil = it.exfil.copy(floorMbPerHour = v)) } })
            }
            SettingRow(
                "New destination alerts",
                "After a one-day learning period, alert when an app contacts a domain it has never used before.",
                s.noveltyAlerts, onChecked = { v -> vm.updateSettings { it.copy(noveltyAlerts = v) } },
            )
            SettingRow(
                "New network alerts",
                "Alert when an app contacts a network (autonomous system, e.g. AS13335 Cloudflare) it has never used before, " +
                    "after a ${s.asnLearningDays}-day learning period per app. Needs the IP-to-ASN database (Threat intelligence feeds).",
                s.newAsnAlerts, onChecked = { v -> vm.updateSettings { it.copy(newAsnAlerts = v) } },
            )
            if (s.newAsnAlerts) {
                Text("Learning period", Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodyMedium)
                Segmented(listOf(1 to "1 day", 7 to "7 days", 14 to "14 days", 30 to "30 days"), s.asnLearningDays,
                    { v -> vm.updateSettings { it.copy(asnLearningDays = v) } })
            }
            SettingRow("Notify on alerts", "Post a notification for medium and high severity alerts.", s.notifyAlerts,
                onChecked = { v -> vm.updateSettings { it.copy(notifyAlerts = v) } })

            SectionTitle("Packet capture")
            SettingRow(
                "Packet capture",
                when {
                    !s.capture.enabled -> "Off. Keep recent packets in memory to export them as PCAPng for Wireshark, or stream them live."
                    s.capture.streamEnabled -> "Recording (${s.capture.bufferMb} MB) · streaming on port ${s.capture.streamPort}"
                    else -> "Recording the most recent ${s.capture.bufferMb} MB of packets in memory"
                },
                onClick = { nav.navigate("capture") },
            )

            SectionTitle("Enterprise")
            SettingRow(
                "SIEM export",
                if (s.export.enabled) "Streaming ${s.export.level.replace("_", " + ")} via ${if (s.export.mode == "http") "HTTP" else "syslog/${s.export.transport}"}" else "Off",
                onClick = { nav.navigate("export") },
            )

            SectionTitle("Permissions")
            SettingRow("Usage access", if (usageAccessGranted(vm)) "Granted: flows are tagged foreground/background" else "Not granted",
                onClick = { context.startActivity(Intent(AndroidSettings.ACTION_USAGE_ACCESS_SETTINGS)) })
            SettingRow("Always-on VPN", "Start vigil at boot and keep it running: VPN settings → vigil → Always-on",
                onClick = { context.startActivity(Intent(AndroidSettings.ACTION_VPN_SETTINGS)) })
            SettingRow("Notifications", "Manage alert and status notifications", onClick = {
                context.startActivity(Intent(AndroidSettings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(AndroidSettings.EXTRA_APP_PACKAGE, context.packageName))
            })

            SectionTitle("Data")
            Text("Keep history for", Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodyMedium)
            Segmented(listOf(1 to "1 day", 7 to "7 days", 30 to "30 days", 90 to "90 days"), s.retentionDays, { v -> vm.updateSettings { it.copy(retentionDays = v) } })
            SettingRow("Clear history", "Delete all recorded connections, lookups and alerts", onClick = { confirmClear = true })

            SectionTitle("About")
            SettingRow("vigil ${BuildConfig.VERSION_NAME}", "Engine ${runCatching { VigilNative.nativeVersion() }.getOrDefault("?")} · Apache-2.0")
            SettingRow("Source code & documentation", "github.com/H3xano/vigil", onClick = {
                context.startActivity(Intent(Intent.ACTION_VIEW, "https://github.com/H3xano/vigil".toUri()))
            })
            Row(Modifier.padding(24.dp)) {}
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("Clear history?") },
            text = { Text("All recorded connections, DNS lookups, alerts, learned destinations and learned networks will be deleted.") },
            confirmButton = { TextButton(onClick = { vm.clearHistory(); confirmClear = false }) { Text("Clear") } },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("Cancel") } },
        )
    }
    if (editUpstreams) {
        var text by rememberSaveable { mutableStateOf(s.customUpstreams.joinToString(", ")) }
        val parsed = text.split(',', ' ', '\n').filter { it.isNotBlank() }
        val invalid = parsed.filter { ConfigFactory.normalizeResolver(it) == null }
        AlertDialog(
            onDismissRequest = { editUpstreams = false },
            title = { Text("Custom resolvers") },
            text = {
                Column {
                    Text("Plain DNS resolvers, e.g. 1.1.1.1, 9.9.9.9:53, [2606:4700::1111]:53", style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(text, { text = it }, Modifier.fillMaxWidth().padding(top = 8.dp), isError = invalid.isNotEmpty(),
                        supportingText = { if (invalid.isNotEmpty()) Text("Invalid: ${invalid.joinToString()}") })
                }
            },
            confirmButton = {
                TextButton(enabled = invalid.isEmpty() && parsed.isNotEmpty(), onClick = {
                    vm.updateSettings { it.copy(customUpstreams = parsed) }
                    editUpstreams = false
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { editUpstreams = false }) { Text("Cancel") } },
        )
    }
}
