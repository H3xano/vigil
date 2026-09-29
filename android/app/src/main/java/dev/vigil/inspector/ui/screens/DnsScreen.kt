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
import androidx.compose.ui.res.stringResource
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
import dev.vigil.inspector.R
import dev.vigil.inspector.ui.UiText
import dev.vigil.inspector.ui.asString
import dev.vigil.inspector.ui.relativeTime
import dev.vigil.inspector.ui.theme.VigilColors
import dev.vigil.inspector.vpn.VpnStatus

/** One line on how encrypted DNS is doing, and whether it is a problem; null when it is off. */
internal fun encryptedDnsStatus(s: EncryptedDnsSettings, running: Boolean, stats: StatsEvent?, now: Long): Pair<UiText, Boolean>? {
    if (!s.enabled) return null
    if (!running) return UiText.of(R.string.dns_status_inactive) to false
    if (stats == null || (stats.encryptedDnsOk == 0L && stats.encryptedDnsFailed == 0L)) return UiText.of(R.string.dns_status_waiting) to false
    fun count(id: Int, n: Long) = UiText.plural(id, quantity(n), n)
    val answered = count(R.plurals.dns_status_answered, stats.encryptedDnsOk)
    val failed = count(R.plurals.dns_status_failed, stats.encryptedDnsFailed)
    val counts = if (stats.encryptedDnsFallback > 0) {
        UiText.of(R.string.dns_status_counts_fallback, answered, failed, count(R.plurals.dns_status_fallback, stats.encryptedDnsFallback))
    } else {
        UiText.of(R.string.dns_status_counts, answered, failed)
    }
    return if (stats.encryptedDnsLastErrorTs > stats.encryptedDnsLastOkTs) {
        val error = stats.encryptedDnsLastError?.let { UiText.Raw(it) } ?: UiText.of(R.string.dns_status_unknown_error)
        UiText.of(R.string.dns_status_failing, relativeTime(stats.encryptedDnsLastErrorTs, now), error, counts) to true
    } else {
        UiText.of(R.string.dns_status_working, relativeTime(stats.encryptedDnsLastOkTs, now), counts) to false
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
    val problem = candidate.problemText()?.asString()
    val dirty = candidate != saved

    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.dns_title), nav)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Text(
                stringResource(R.string.dns_intro),
                Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                style = MaterialTheme.typography.bodyMedium,
            )
            encryptedDnsStatus(saved, status is VpnStatus.Running, stats, System.currentTimeMillis())?.let { (line, bad) ->
                Text(
                    line.asString(),
                    Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (bad) MaterialTheme.colorScheme.error else VigilColors.Allow,
                )
            }

            SectionTitle(stringResource(R.string.dns_protocol))
            Segmented(
                listOf("off" to stringResource(R.string.common_off), "dot" to "DoT", "doh" to "DoH"),
                draft.mode, { v -> draft = draft.copy(mode = v) },
            )
            Text(
                stringResource(
                    when (draft.mode) {
                        "dot" -> R.string.dns_dot_description
                        "doh" -> R.string.dns_doh_description
                        else -> R.string.dns_off_description
                    },
                ),
                Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (draft.enabled) {
                SectionTitle(stringResource(R.string.dns_provider))
                for (p in DnsProviders.ALL) {
                    ProviderRow(
                        p.name,
                        stringResource(R.string.dns_provider_summary, stringResource(p.description), if (draft.mode == "doh") p.dohUrl else p.dotHost),
                        draft.provider == p.id,
                    ) { draft = draft.copy(provider = p.id) }
                }
                ProviderRow(stringResource(R.string.dns_custom), stringResource(R.string.dns_custom_summary), draft.provider == EncryptedDnsSettings.CUSTOM) {
                    draft = draft.copy(provider = EncryptedDnsSettings.CUSTOM)
                }
                if (draft.provider == EncryptedDnsSettings.CUSTOM) {
                    Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (draft.mode == "doh") {
                            OutlinedTextField(
                                draft.customUrl, { v -> draft = draft.copy(customUrl = v.trim()) }, Modifier.fillMaxWidth(),
                                label = { Text(stringResource(R.string.dns_url)) }, placeholder = { Text("https://dns.example/dns-query") }, singleLine = true,
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                            )
                        } else {
                            OutlinedTextField(
                                draft.customHost, { v -> draft = draft.copy(customHost = v.trim()) }, Modifier.fillMaxWidth(),
                                label = { Text(stringResource(R.string.dns_server_name)) }, placeholder = { Text("dns.example") }, singleLine = true,
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                            )
                            OutlinedTextField(
                                portText, { v -> portText = v.filter(Char::isDigit).take(5) }, Modifier.fillMaxWidth(),
                                label = { Text(stringResource(R.string.dns_port)) }, singleLine = true,
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            )
                        }
                        OutlinedTextField(
                            addrsText, { v -> addrsText = v }, Modifier.fillMaxWidth(),
                            label = { Text(stringResource(R.string.dns_ip_addresses)) }, placeholder = { Text("192.0.2.53, 2001:db8::53") },
                            supportingText = { Text(stringResource(R.string.dns_ip_addresses_help)) },
                        )
                    }
                }

                SectionTitle(stringResource(R.string.dns_when_fails))
                SettingRow(
                    stringResource(R.string.dns_fallback),
                    stringResource(if (draft.fallbackPlain) R.string.dns_fallback_on else R.string.dns_fallback_off),
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
                    }) { Text(stringResource(R.string.common_save)) }
                    OutlinedButton(enabled = dirty, onClick = {
                        draft = saved
                        addrsText = saved.customAddrs.joinToString(", ")
                        portText = saved.customPort.toString()
                    }) { Text(stringResource(R.string.common_discard)) }
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
