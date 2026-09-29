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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.R
import dev.vigil.inspector.data.ExportSettings
import dev.vigil.inspector.export.ExportConfigException
import dev.vigil.inspector.export.ExportTestRefused
import dev.vigil.inspector.export.HttpSender
import dev.vigil.inspector.export.WireFormats
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.UiText
import dev.vigil.inspector.ui.asString
import dev.vigil.inspector.ui.rememberRetained
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors
import kotlinx.coroutines.launch

/** Default syslog port of a transport. */
private fun defaultPort(transport: String) = if (transport == "tls") 6514 else 514

/** Connection settings are problems-free enough to save. */
internal fun validationError(d: ExportSettings, portText: String = d.port.toString()): UiText? = when {
    d.mode == "syslog" && d.host.isBlank() -> UiText.of(R.string.export_error_host)
    d.mode == "syslog" && portText.toIntOrNull()?.takeIf { it in 1..65535 } == null -> UiText.of(R.string.settings_port_range)
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
    var testResult by rememberRetained("export.test") { null as UiText? }
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
        VigilTopBar(stringResource(R.string.export_title), nav)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            SettingRow(
                stringResource(R.string.export_stream_title),
                stringResource(if (savedValid || saved.enabled) R.string.export_stream_summary else R.string.export_stream_needs_destination),
                saved.enabled, onChecked = { v -> updateSaved { it.copy(enabled = v) } },
                // Turning off is always possible.
                enabled = savedValid || saved.enabled,
            )
            Row(Modifier.padding(start = 16.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.export_ecs_note), Modifier.weight(1f), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                HelpIcon("ECS", Glossary.ECS)
            }
            SectionTitle(stringResource(R.string.export_section_what))
            Segmented(
                listOf(
                    "alerts" to stringResource(R.string.export_level_alerts),
                    "alerts_dns" to stringResource(R.string.export_level_dns),
                    "all" to stringResource(R.string.export_level_all),
                ),
                saved.level, { v -> updateSaved { it.copy(level = v) } })

            SectionTitle(stringResource(R.string.export_section_destination))
            // Protocol names: not translated.
            Segmented(listOf("syslog" to "Syslog", "http" to "HTTP"), draft.mode, { v -> edit { it.copy(mode = v) } })
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (draft.mode == "syslog") {
                    OutlinedTextField(draft.host, { v -> edit { it.copy(host = v.trim()) } }, Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.settings_field_host)) }, singleLine = true)
                    OutlinedTextField(
                        portText, { v -> portText = v.filter(Char::isDigit).take(5); testResult = null },
                        Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.settings_field_port)) }, singleLine = true,
                        isError = portText.toIntOrNull()?.takeIf { it in 1..65535 } == null,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    )
                    Text(
                        stringResource(R.string.export_syslog_note, WireFormats.UDP_MAX_BYTES / 1024),
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    OutlinedTextField(draft.url, { v -> edit { it.copy(url = v.trim()) } }, Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.export_endpoint_url)) }, singleLine = true)
                    SecretField(draft.authHeader, { v -> edit { it.copy(authHeader = v) } }, stringResource(R.string.export_auth_header), Modifier.fillMaxWidth(),
                        // HTTP header syntax: not translated.
                        placeholder = "Bearer … / Splunk … / ApiKey …")
                    CleartextWarning(draft.url, hasSecret = draft.authHeader.isNotBlank(), isFeed = false)
                }
            }
            // Protocol and product names: not translated.
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
                SectionTitle(stringResource(R.string.export_section_mtls))
                SettingRow(
                    stringResource(R.string.export_client_cert),
                    draft.clientCertAlias ?: stringResource(R.string.export_client_cert_none),
                    onClick = {
                        val activity = context as? Activity ?: return@SettingRow
                        KeyChain.choosePrivateKeyAlias(activity, { alias -> if (alias != null) activity.runOnUiThread { draft = draft.copy(clientCertAlias = alias) } }, null, null, null, null)
                    },
                )
                if (draft.clientCertAlias != null) {
                    OutlinedButton(onClick = { edit { it.copy(clientCertAlias = null) } }, Modifier.padding(horizontal = 16.dp)) { Text(stringResource(R.string.export_remove_client_cert)) }
                }
            }

            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (error != null) Text(error.asString(), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                else if (dirty) Text(stringResource(R.string.export_unsaved), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = dirty && error == null, onClick = { vm.saveExport(candidate.copy(enabled = saved.enabled, level = saved.level)) }) { Text(stringResource(R.string.common_save)) }
                    OutlinedButton(enabled = dirty, onClick = {
                        draft = saved
                        portText = saved.port.toString()
                        testResult = null
                    }) { Text(stringResource(R.string.common_discard)) }
                }
            }

            SectionTitle(stringResource(R.string.export_section_status))
            Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    listOfNotNull(
                        stringResource(R.string.export_status_counts, status.sent, status.queued, status.dropped),
                        if (status.rejected > 0) stringResource(R.string.export_status_rejected, status.rejected) else null,
                        status.lastSuccess?.let { stringResource(R.string.export_status_last_success, formatRelative(it)) },
                    ).joinToString(" · "),
                )
                status.configProblem?.let {
                    Text(
                        stringResource(R.string.export_config_problem, it.asString()),
                        color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium,
                    )
                }
                if (status.retrying) Text(stringResource(R.string.export_retrying), style = MaterialTheme.typography.bodySmall)
                status.lastError?.let { Text(stringResource(R.string.settings_last_error, it.asString()), color = VigilColors.Block) }
                Button(enabled = error == null, onClick = {
                    testResult = UiText.of(R.string.export_test_sending)
                    scope.launch {
                        val r = vm.sendExportTest(candidate)
                        val udp = candidate.mode == "syslog" && candidate.transport == "udp"
                        testResult = r.fold(
                            { UiText.of(if (udp) R.string.export_test_sent_udp else R.string.export_test_delivered) },
                            {
                                // The collector's own error text is shown as it is.
                                val why = (it as? ExportConfigException)?.problem ?: (it as? ExportTestRefused)?.problem
                                    ?: UiText.Raw(it.message ?: it.javaClass.simpleName)
                                UiText.of(R.string.export_test_failed, why)
                            },
                        )
                    }
                }, modifier = Modifier.padding(top = 8.dp)) { Text(stringResource(if (dirty) R.string.export_send_test_unsaved else R.string.export_send_test)) }
                testResult?.let { Text(it.asString(), style = MaterialTheme.typography.bodyMedium) }
            }
            Column(Modifier.padding(24.dp)) {}
        }
    }
}
