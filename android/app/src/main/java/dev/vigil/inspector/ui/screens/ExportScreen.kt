package dev.vigil.inspector.ui.screens

import android.app.Activity
import android.security.KeyChain
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.ExportSettings
import dev.vigil.inspector.export.HttpSender
import dev.vigil.inspector.export.WireFormats
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.rememberRetained
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors
import kotlinx.coroutines.launch

/** Default syslog port of a transport. */
private fun defaultPort(transport: String) = if (transport == "tls") 6514 else 514

/** Connection settings are problems-free enough to save. */
internal fun validationError(d: ExportSettings, portText: String = d.port.toString()): String? = when {
    d.mode == "syslog" && d.host.isBlank() -> "Enter the collector's host name or address."
    d.mode == "syslog" && portText.toIntOrNull()?.takeIf { it in 1..65535 } == null -> "The port must be between 1 and 65535."
    else -> HttpSender.urlProblem(d)
}

@Composable
fun ExportScreen(vm: MainViewModel, nav: NavController) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val status by vm.exportStatus.collectAsStateWithLifecycle()
    val saved = settings.export
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    // Connection fields are edited locally and applied with Save, so the
    // exporter does not reconnect to every half-typed host name. The draft
    // survives rotation but is never written to the saved-instance Bundle
    // (it may hold an Authorization token).
    var testResult by rememberRetained("export.test") { null as String? }
    var draft by rememberRetained("export.draft") { saved }
    var portText by rememberRetained("export.port") { saved.port.toString() }
    // Streaming needs a saved destination that passes validation.
    val savedValid = validationError(saved) == null
    val candidate = draft.copy(enabled = saved.enabled, level = saved.level, port = portText.toIntOrNull() ?: draft.port)
    val dirty = candidate != saved
    val error = validationError(candidate, portText)
    fun edit(t: (ExportSettings) -> ExportSettings) {
        draft = t(draft)
        testResult = null
    }
    fun updateSaved(t: (ExportSettings) -> ExportSettings) = vm.updateSettings { it.copy(export = t(it.export)) }

    Column(Modifier.fillMaxSize()) {
        VigilTopBar("SIEM export", nav)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            SettingRow(
                "Stream events",
                if (savedValid || saved.enabled) {
                    "Send structured events (ECS-style JSON) to your collector. No traffic data leaves the device while this is off."
                } else {
                    "Set up and save a destination below first."
                },
                saved.enabled, onChecked = { v -> updateSaved { it.copy(enabled = v) } },
                // Turning off is always possible.
                enabled = savedValid || saved.enabled,
            )
            Row(Modifier.padding(start = 16.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("Fields follow the Elastic Common Schema (ECS).", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                HelpIcon("ECS", Glossary.ECS)
            }
            SectionTitle("What to send")
            Segmented(listOf("alerts" to "Alerts", "alerts_dns" to "+ DNS", "all" to "Everything"), saved.level, { v -> updateSaved { it.copy(level = v) } })

            SectionTitle("Destination")
            Segmented(listOf("syslog" to "Syslog", "http" to "HTTP"), draft.mode, { v -> edit { it.copy(mode = v) } })
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (draft.mode == "syslog") {
                    OutlinedTextField(draft.host, { v -> edit { it.copy(host = v.trim()) } }, Modifier.fillMaxWidth(), label = { Text("Host") }, singleLine = true)
                    OutlinedTextField(
                        portText, { v -> portText = v.filter(Char::isDigit).take(5); testResult = null },
                        Modifier.fillMaxWidth(), label = { Text("Port") }, singleLine = true,
                        isError = portText.toIntOrNull()?.takeIf { it in 1..65535 } == null,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    )
                    Text(
                        "RFC 5424 messages; TCP and TLS use octet-counting framing (RFC 6587). UDP and TCP are unencrypted. " +
                            "Over UDP each message is capped at ${WireFormats.UDP_MAX_BYTES / 1024} KB: long values in larger records are shortened.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    OutlinedTextField(draft.url, { v -> edit { it.copy(url = v.trim()) } }, Modifier.fillMaxWidth(), label = { Text("Endpoint URL") }, singleLine = true)
                    SecretField(draft.authHeader, { v -> edit { it.copy(authHeader = v) } }, "Authorization header", Modifier.fillMaxWidth(),
                        placeholder = "Bearer … / Splunk … / ApiKey …")
                    CleartextWarning(draft.url, hasSecret = draft.authHeader.isNotBlank(), isFeed = false)
                }
            }
            if (draft.mode == "syslog") {
                Segmented(listOf("udp" to "UDP", "tcp" to "TCP", "tls" to "TLS"), draft.transport, { v ->
                    // Only replace the port if it is still the previous transport's default.
                    if (portText.toIntOrNull() == defaultPort(draft.transport)) portText = defaultPort(v).toString()
                    edit { it.copy(transport = v) }
                })
            } else {
                Segmented(listOf("ndjson" to "NDJSON", "splunk_hec" to "Splunk HEC", "elastic_bulk" to "Elastic _bulk"), draft.httpFormat, { v -> edit { it.copy(httpFormat = v) } })
            }
            if (draft.mode == "http" || draft.transport == "tls") {
                SectionTitle("Mutual TLS")
                SettingRow(
                    "Client certificate",
                    draft.clientCertAlias ?: "None: tap to choose a certificate installed on this device",
                    onClick = {
                        val activity = context as? Activity ?: return@SettingRow
                        KeyChain.choosePrivateKeyAlias(activity, { alias -> if (alias != null) activity.runOnUiThread { draft = draft.copy(clientCertAlias = alias) } }, null, null, null, null)
                    },
                )
                if (draft.clientCertAlias != null) {
                    OutlinedButton(onClick = { edit { it.copy(clientCertAlias = null) } }, Modifier.padding(horizontal = 16.dp)) { Text("Remove client certificate") }
                }
            }

            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (error != null) Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                else if (dirty) Text("Unsaved changes", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = dirty && error == null, onClick = { vm.saveExport(candidate.copy(enabled = saved.enabled, level = saved.level)) }) { Text("Save") }
                    OutlinedButton(enabled = dirty, onClick = {
                        draft = saved
                        portText = saved.port.toString()
                        testResult = null
                    }) { Text("Discard") }
                }
            }

            SectionTitle("Status")
            Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    "Sent ${status.sent} · queued ${status.queued} · dropped ${status.dropped}" +
                        (if (status.rejected > 0) " · rejected ${status.rejected}" else "") +
                        (status.lastSuccess?.let { " · last success ${formatRelative(it)}" } ?: ""),
                )
                status.configProblem?.let {
                    Text(
                        "Configuration problem: $it Events stay queued and are retried once a minute.",
                        color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium,
                    )
                }
                if (status.retrying) Text("Undelivered events are queued and retried.", style = MaterialTheme.typography.bodySmall)
                status.lastError?.let { Text("Last error: $it", color = VigilColors.Block) }
                Button(enabled = error == null, onClick = {
                    testResult = "Sending…"
                    scope.launch {
                        val r = vm.sendExportTest(candidate)
                        val udp = candidate.mode == "syslog" && candidate.transport == "udp"
                        testResult = r.fold(
                            { if (udp) "Test event sent (UDP cannot confirm delivery)" else "Test event delivered" },
                            { "Failed: ${it.message ?: it.javaClass.simpleName}" },
                        )
                    }
                }, modifier = Modifier.padding(top = 8.dp)) { Text(if (dirty) "Send test event (unsaved settings)" else "Send test event") }
                testResult?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            }
            Column(Modifier.padding(24.dp)) {}
        }
    }
}
