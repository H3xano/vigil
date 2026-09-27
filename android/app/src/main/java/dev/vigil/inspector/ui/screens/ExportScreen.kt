package dev.vigil.inspector.ui.screens

import android.app.Activity
import android.security.KeyChain
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.ExportSettings
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors
import kotlinx.coroutines.launch

@Composable
fun ExportScreen(vm: MainViewModel, nav: NavController) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val status by vm.exportStatus.collectAsStateWithLifecycle()
    val e = settings.export
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var testResult by remember { mutableStateOf<String?>(null) }
    fun update(t: (ExportSettings) -> ExportSettings) = vm.updateSettings { it.copy(export = t(it.export)) }

    Column(Modifier.fillMaxSize()) {
        VigilTopBar("SIEM export", nav)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            SettingRow(
                "Stream events",
                "Send structured events (ECS-style JSON) to your collector. Nothing leaves the device while this is off.",
                e.enabled, onChecked = { v -> update { it.copy(enabled = v) } },
            )
            SectionTitle("What to send")
            Segmented(listOf("alerts" to "Alerts", "alerts_dns" to "+ DNS", "all" to "Everything"), e.level, { v -> update { it.copy(level = v) } })

            SectionTitle("Destination")
            Segmented(listOf("syslog" to "Syslog", "http" to "HTTP"), e.mode, { v -> update { it.copy(mode = v) } })
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (e.mode == "syslog") {
                    OutlinedTextField(e.host, { v -> update { it.copy(host = v.trim()) } }, Modifier.fillMaxWidth(), label = { Text("Host") }, singleLine = true)
                    OutlinedTextField(
                        e.port.toString(), { v -> v.toIntOrNull()?.let { p -> update { it.copy(port = p.coerceIn(1, 65535)) } } },
                        Modifier.fillMaxWidth(), label = { Text("Port") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    )
                    Text("RFC 5424 messages; TCP and TLS use octet-counting framing (RFC 6587).", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    OutlinedTextField(e.url, { v -> update { it.copy(url = v.trim()) } }, Modifier.fillMaxWidth(), label = { Text("Endpoint URL") }, singleLine = true)
                    OutlinedTextField(e.authHeader, { v -> update { it.copy(authHeader = v) } }, Modifier.fillMaxWidth(),
                        label = { Text("Authorization header") }, placeholder = { Text("Bearer … / Splunk … / ApiKey …") }, singleLine = true)
                }
            }
            if (e.mode == "syslog") {
                Segmented(listOf("udp" to "UDP", "tcp" to "TCP", "tls" to "TLS"), e.transport, { v -> update { it.copy(transport = v, port = if (v == "tls") 6514 else 514) } })
            } else {
                Segmented(listOf("ndjson" to "NDJSON", "splunk_hec" to "Splunk HEC", "elastic_bulk" to "Elastic _bulk"), e.httpFormat, { v -> update { it.copy(httpFormat = v) } })
            }
            if (e.mode == "http" || e.transport == "tls") {
                SectionTitle("Mutual TLS")
                SettingRow(
                    "Client certificate",
                    e.clientCertAlias ?: "None: tap to choose a certificate installed on this device",
                    onClick = {
                        val activity = context as? Activity ?: return@SettingRow
                        KeyChain.choosePrivateKeyAlias(activity, { alias -> update { it.copy(clientCertAlias = alias) } }, null, null, null, null)
                    },
                )
                if (e.clientCertAlias != null) {
                    OutlinedButton(onClick = { update { it.copy(clientCertAlias = null) } }, Modifier.padding(horizontal = 16.dp)) { Text("Remove client certificate") }
                }
            }

            SectionTitle("Status")
            Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Sent ${status.sent} · dropped ${status.dropped}" + (status.lastSuccess?.let { " · last success ${formatRelative(it)}" } ?: ""))
                status.lastError?.let { Text("Last error: $it", color = VigilColors.Block) }
                Button(onClick = {
                    testResult = "Sending…"
                    scope.launch {
                        val r = vm.sendExportTest()
                        testResult = r.fold({ "Test event delivered" }, { "Failed: ${it.message ?: it.javaClass.simpleName}" })
                    }
                }, Modifier.padding(top = 8.dp)) { Text("Send test event") }
                testResult?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            }
            Column(Modifier.padding(24.dp)) {}
        }
    }
}
