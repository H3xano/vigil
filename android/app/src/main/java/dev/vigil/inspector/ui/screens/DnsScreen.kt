package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.DnsProviders
import dev.vigil.inspector.data.EncryptedDnsSettings
import dev.vigil.inspector.engine.StatsEvent
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.rememberRetained
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors
import dev.vigil.inspector.vpn.VpnStatus

/** One line on how encrypted DNS is doing, and whether it is a problem; null when it is off. */
internal fun encryptedDnsStatus(s: EncryptedDnsSettings, running: Boolean, stats: StatsEvent?, now: Long): Pair<String, Boolean>? {
    if (!s.enabled) return null
    if (!running) return "Takes effect while inspection is running." to false
    if (stats == null || (stats.encryptedDnsOk == 0L && stats.encryptedDnsFailed == 0L)) return "Waiting for the first lookup…" to false
    val counts = "${stats.encryptedDnsOk} answered encrypted, ${stats.encryptedDnsFailed} failed" +
        if (stats.encryptedDnsFallback > 0) " (${stats.encryptedDnsFallback} answered over plain DNS)" else ""
    return if (stats.encryptedDnsLastErrorTs > stats.encryptedDnsLastOkTs) {
        "Failing (last error ${formatRelative(stats.encryptedDnsLastErrorTs, now)}): ${stats.encryptedDnsLastError ?: "unknown error"} · $counts" to true
    } else {
        "Working: last encrypted answer ${formatRelative(stats.encryptedDnsLastOkTs, now)} · $counts" to false
    }
}

@Composable
fun DnsScreen(vm: MainViewModel, nav: NavController) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val stats by vm.stats.collectAsStateWithLifecycle()
    val status by vm.status.collectAsStateWithLifecycle()
    val saved = settings.encryptedDns

    // Edited locally and applied with Save, so half-typed custom servers
    // never reach the engine. Kept across rotation.
    var draft by rememberRetained("dns.draft") { saved }
    var addrsText by rememberRetained("dns.addrs") { saved.customAddrs.joinToString(", ") }
    var portText by rememberRetained("dns.port") { saved.customPort.toString() }
    val candidate = draft.copy(
        customAddrs = EncryptedDnsSettings.splitAddrs(addrsText),
        customPort = portText.toIntOrNull() ?: 0,
    )
    val problem = candidate.problem()
    val dirty = candidate != saved

    Column(Modifier.fillMaxSize()) {
        VigilTopBar("Encrypted DNS", nav)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Text(
                "vigil answers every app's lookups itself and forwards them to a resolver. Encrypting that hop keeps the network " +
                    "(Wi-Fi operator, carrier) from reading or altering your lookups, as Android's Private DNS does. " +
                    "Blocking, alerts and the DNS log work the same.",
                Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                style = MaterialTheme.typography.bodyMedium,
            )
            encryptedDnsStatus(saved, status is VpnStatus.Running, stats, System.currentTimeMillis())?.let { (line, bad) ->
                Text(
                    line,
                    Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (bad) MaterialTheme.colorScheme.error else VigilColors.Allow,
                )
            }

            SectionTitle("Protocol")
            Segmented(
                listOf("off" to "Off", "dot" to "DoT", "doh" to "DoH"),
                draft.mode, { v -> draft = draft.copy(mode = v) },
            )
            Text(
                when (draft.mode) {
                    "dot" -> "DNS over TLS (RFC 7858), port 853. Easy for a network to recognise (and block) by its port."
                    "doh" -> "DNS over HTTPS (RFC 8484), port 443. Looks like ordinary HTTPS; HTTP/2 when the server offers it."
                    else -> "Lookups leave in cleartext to the resolvers chosen under Settings → Upstream DNS resolver."
                },
                Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (draft.enabled) {
                SectionTitle("Provider")
                for (p in DnsProviders.ALL) {
                    ProviderRow(
                        p.name,
                        "${p.description} ${if (draft.mode == "doh") p.dohUrl else p.dotHost}",
                        draft.provider == p.id,
                    ) { draft = draft.copy(provider = p.id) }
                }
                ProviderRow("Custom", "Your own server", draft.provider == EncryptedDnsSettings.CUSTOM) {
                    draft = draft.copy(provider = EncryptedDnsSettings.CUSTOM)
                }
                if (draft.provider == EncryptedDnsSettings.CUSTOM) {
                    Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (draft.mode == "doh") {
                            OutlinedTextField(
                                draft.customUrl, { v -> draft = draft.copy(customUrl = v.trim()) }, Modifier.fillMaxWidth(),
                                label = { Text("URL") }, placeholder = { Text("https://dns.example/dns-query") }, singleLine = true,
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                            )
                        } else {
                            OutlinedTextField(
                                draft.customHost, { v -> draft = draft.copy(customHost = v.trim()) }, Modifier.fillMaxWidth(),
                                label = { Text("Server name") }, placeholder = { Text("dns.example") }, singleLine = true,
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                            )
                            OutlinedTextField(
                                portText, { v -> portText = v.filter(Char::isDigit).take(5) }, Modifier.fillMaxWidth(),
                                label = { Text("Port") }, singleLine = true,
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            )
                        }
                        OutlinedTextField(
                            addrsText, { v -> addrsText = v }, Modifier.fillMaxWidth(),
                            label = { Text("IP addresses") }, placeholder = { Text("192.0.2.53, 2001:db8::53") },
                            supportingText = {
                                Text("Where to connect. The certificate is still checked against the name. " +
                                    "Without addresses the name is looked up over plain DNS, which needs the fallback below.")
                            },
                        )
                    }
                }

                SectionTitle("When the encrypted server fails")
                SettingRow(
                    "Fall back to plain DNS",
                    if (draft.fallbackPlain) {
                        "On: if the server cannot be reached (a network that blocks it, a captive portal), lookups are sent " +
                            "unencrypted to the plain resolvers instead of failing. Convenient, but the network can then read them."
                    } else {
                        "Off: lookups fail rather than leave unencrypted. Captive portal sign-in pages may not load until you " +
                            "turn encrypted DNS off."
                    },
                    draft.fallbackPlain, onChecked = { v -> draft = draft.copy(fallbackPlain = v) },
                )
            }

            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (problem != null) {
                    Text(problem, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = dirty && problem == null, onClick = {
                        vm.updateSettings { it.copy(encryptedDns = candidate) }
                        draft = candidate
                    }) { Text("Save") }
                    OutlinedButton(enabled = dirty, onClick = {
                        draft = saved
                        addrsText = saved.customAddrs.joinToString(", ")
                        portText = saved.customPort.toString()
                    }) { Text("Discard") }
                }
            }
        }
    }
}

@Composable
private fun ProviderRow(title: String, summary: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().selectable(selected = selected, role = Role.RadioButton, onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Column(Modifier.padding(start = 8.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Text(summary, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
