package dev.vigil.inspector.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.navigation.NavController
import dev.vigil.inspector.R
import dev.vigil.inspector.data.CaptureSettings
import dev.vigil.inspector.engine.PcapFilter
import dev.vigil.inspector.ui.CaptureExport
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.PcapRequest
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.formatBytes
import dev.vigil.inspector.ui.theme.VigilColors
import dev.vigil.inspector.vpn.ServiceState
import dev.vigil.inspector.vpn.VpnStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Settings → Packet capture: the capture ring, export, and PCAP-over-IP for Wireshark. */
@Composable
fun CaptureSettingsScreen(vm: MainViewModel, nav: NavController) {
    val s by vm.settings.collectAsStateWithLifecycle()
    val stats by vm.stats.collectAsStateWithLifecycle()
    val status by vm.status.collectAsStateWithLifecycle()
    val network by ServiceState.network.collectAsStateWithLifecycle()
    val c = s.capture
    fun update(t: (CaptureSettings) -> CaptureSettings) = vm.updateSettings { it.copy(capture = t(it.capture)) }
    val running = status is VpnStatus.Running
    val cap = stats?.capture?.takeIf { running }
    val needsAllowlist = stringResource(R.string.capture_needs_allowlist)

    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.capture_title), nav)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            SettingRow(
                stringResource(R.string.capture_record_title),
                stringResource(R.string.capture_record_summary),
                c.enabled, onChecked = { v -> update { it.copy(enabled = v) } },
            )
            Text(stringResource(R.string.capture_privacy_note), Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            SectionTitle(stringResource(R.string.capture_section_buffer))
            // Units, as in formatBytes: not translated.
            Segmented(CaptureSettings.BUFFER_CHOICES_MB.map { it to "$it MB" }, c.bufferMb, { v -> update { it.copy(bufferMb = v) } })
            Text(
                stringResource(R.string.capture_buffer_note),
                Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (c.enabled) {
                Text(
                    when {
                        cap == null || !cap.enabled ->
                            stringResource(if (running) R.string.capture_starting else R.string.capture_starts_when_running)
                        else -> listOfNotNull(
                            pluralStringResource(
                                R.plurals.capture_holding, count(cap.bufferedPackets),
                                cap.bufferedPackets, formatBytes(cap.bufferedBytes), formatBytes(cap.bufferBytes),
                            ),
                            if (cap.dropped > 0) pluralStringResource(R.plurals.capture_overwritten, count(cap.dropped), cap.dropped) else null,
                        ).joinToString(" · ")
                    },
                    Modifier.padding(horizontal = 16.dp, vertical = 8.dp), style = MaterialTheme.typography.bodyMedium,
                )
                Column(Modifier.padding(horizontal = 16.dp)) {
                    ExportPacketsButton(
                        vm, nav, stringResource(R.string.capture_export_all),
                        PcapRequest(PcapFilter(), CaptureExport.fileName("capture")),
                    )
                }
            }

            SectionTitle(stringResource(R.string.capture_section_stream))
            SettingRow(
                stringResource(R.string.capture_stream_title),
                stringResource(if (c.enabled) R.string.capture_stream_summary else R.string.capture_stream_needs_record),
                c.streamEnabled,
                onChecked = { v ->
                    // Never on the network without an allowlist: anyone there would get the packets.
                    val refusal = c.copy(streamEnabled = v).streamRefusal()
                    if (v && refusal != null) vm.showMessage(needsAllowlist) else update { it.copy(streamEnabled = v) }
                },
                enabled = c.enabled || c.streamEnabled,
            )
            Text(stringResource(R.string.capture_stream_warning), Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = VigilColors.Medium)
            // Shown before streaming is on, so the address or "This device" can be set first.
            if (c.enabled || c.streamEnabled) {
                Text(stringResource(R.string.capture_listen_on), Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodyMedium)
                Segmented(
                    listOf(
                        CaptureSettings.BIND_WIFI to stringResource(R.string.capture_bind_wifi),
                        CaptureSettings.BIND_ALL to stringResource(R.string.capture_bind_all),
                        CaptureSettings.BIND_LOOPBACK to stringResource(R.string.capture_bind_loopback),
                    ),
                    c.streamBind,
                    { v ->
                        val refusal = c.copy(streamBind = v).streamRefusal()
                        if (refusal != null) vm.showMessage(needsAllowlist) else update { it.copy(streamBind = v) }
                    },
                )
                StreamFields(c) { t -> update(t) }
            }
            if (c.streamEnabled) {
                val host = when (c.streamBind) {
                    CaptureSettings.BIND_LOOPBACK -> "127.0.0.1"
                    else -> network.wifiAddress
                }
                val st = cap?.stream
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        when {
                            c.streamRefusal() != null -> stringResource(R.string.capture_not_listening_no_allowlist)
                            !running || !c.enabled -> stringResource(R.string.capture_not_listening_not_running)
                            st?.listening != null -> listOfNotNull(
                                stringResource(R.string.capture_listening, st.listening, st.clients),
                                if (st.dropped > 0) pluralStringResource(R.plurals.capture_stream_dropped, count(st.dropped), st.dropped) else null,
                                if (st.rejected > 0) pluralStringResource(R.plurals.capture_stream_refused, count(st.rejected), st.rejected) else null,
                            ).joinToString(" · ")
                            c.streamBind == CaptureSettings.BIND_WIFI && network.wifiAddress == null -> stringResource(R.string.capture_not_listening_no_wifi)
                            st?.error != null -> stringResource(R.string.capture_not_listening_error, st.error)
                            else -> stringResource(R.string.capture_starting)
                        },
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    if (host != null) {
                        Text(stringResource(R.string.capture_wireshark_hint),
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        // Wireshark interface names and shell commands: not translated.
                        Text("TCP@$host:${c.streamPort}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
                        Text(stringResource(R.string.capture_from_shell), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text("wireshark -k -i TCP@$host:${c.streamPort}\nnc $host ${c.streamPort} | wireshark -k -i -",
                            fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        if (c.streamBind == CaptureSettings.BIND_LOOPBACK) {
                            Text(stringResource(R.string.capture_loopback_hint, c.streamPort.toString()),
                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun StreamFields(c: CaptureSettings, update: ((CaptureSettings) -> CaptureSettings) -> Unit) {
    var portText by rememberSaveable { mutableStateOf(c.streamPort.toString()) }
    var allowText by rememberSaveable { mutableStateOf(c.streamAllow.joinToString(", ")) }
    val port = portText.toIntOrNull()?.takeIf { CaptureSettings.isValidPort(it) }
    val allow = allowText.split(',', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }
    val badAllow = allow.filterNot { CaptureSettings.isValidAllowEntry(it) }
    val network = CaptureSettings.needsAllowList(c.streamBind)
    Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            portText,
            { v ->
                portText = v.filter(Char::isDigit).take(5)
                portText.toIntOrNull()?.takeIf { CaptureSettings.isValidPort(it) }?.let { p -> update { it.copy(streamPort = p) } }
            },
            Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.settings_field_port)) }, singleLine = true, isError = port == null,
            supportingText = { if (port == null) Text(stringResource(R.string.capture_port_range)) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        )
        OutlinedTextField(
            allowText,
            { v ->
                allowText = v
                val entries = v.split(',', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }
                // Not saved when invalid, nor when it would leave network streaming without an allowlist.
                val refused = c.copy(streamAllow = entries).streamRefusal() != null
                if (entries.all { CaptureSettings.isValidAllowEntry(it) } && entries.size <= CaptureSettings.MAX_ALLOW && !refused) {
                    update { it.copy(streamAllow = entries.distinct()) }
                }
            },
            Modifier.fillMaxWidth(),
            label = { Text(stringResource(if (network) R.string.capture_allowed_clients_required else R.string.capture_allowed_clients)) },
            // Example addresses: not translated.
            placeholder = { Text("192.168.1.10, 192.168.1.0/24") },
            isError = badAllow.isNotEmpty() || (network && allow.isEmpty()),
            supportingText = {
                Text(
                    when {
                        badAllow.isNotEmpty() -> stringResource(R.string.capture_allow_invalid, badAllow.joinToString())
                        allow.size > CaptureSettings.MAX_ALLOW ->
                            pluralStringResource(R.plurals.capture_allow_too_many, CaptureSettings.MAX_ALLOW, CaptureSettings.MAX_ALLOW)
                        network && allow.isEmpty() -> stringResource(R.string.capture_allow_required)
                        network -> stringResource(R.string.capture_allow_network)
                        else -> stringResource(R.string.capture_allow_loopback)
                    },
                )
            },
        )
    }
}

/**
 * A button exporting captured packets: explains how to enable capture (or
 * why the packets are gone), otherwise asks for a file (Storage Access
 * Framework) and exports on a background thread.
 */
@Composable
fun ExportPacketsButton(vm: MainViewModel, nav: NavController, label: String, request: PcapRequest, modifier: Modifier = Modifier) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val active by ServiceState.engine.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var explain by rememberSaveable { mutableStateOf<String?>(null) }
    // application/octet-stream: document providers append the extension of
    // a known MIME type (".pcap") to a ".pcapng" name.
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val engine = ServiceState.engine.value
        if (uri == null || engine == null) return@rememberLauncherForActivityResult
        val app = context.applicationContext
        vm.viewModelScope.launch {
            val msg = withContext(Dispatchers.IO) { CaptureExport.exportTo(app, engine, request, uri) }
            vm.showMessage(msg)
        }
    }
    OutlinedButton(onClick = {
        val why = CaptureExport.unavailable(settings.capture.enabled, active, request)
        if (why != null) explain = why.resolve(context) else picker.launch(request.fileName)
    }, modifier.fillMaxWidth()) { Text(label) }
    explain?.let { text ->
        AlertDialog(
            onDismissRequest = { explain = null },
            title = { Text(stringResource(R.string.capture_unavailable_title)) },
            text = { Text(text) },
            confirmButton = {
                if (!settings.capture.enabled) {
                    TextButton(onClick = { explain = null; nav.navigate("capture") }) { Text(stringResource(R.string.capture_settings_button)) }
                } else {
                    TextButton(onClick = { explain = null }) { Text(stringResource(R.string.capture_ok)) }
                }
            },
            dismissButton = if (!settings.capture.enabled) {
                { TextButton(onClick = { explain = null }) { Text(stringResource(R.string.action_cancel)) } }
            } else {
                null
            },
        )
    }
}

/** App detail: export an app's packets, choosing the time window first. */
@Composable
fun ExportAppPacketsButton(vm: MainViewModel, nav: NavController, uid: Int?, label: String) {
    if (uid == null) return
    var choose by rememberSaveable { mutableStateOf(false) }
    var window by rememberSaveable { mutableStateOf<Long?>(15 * 60_000L) }
    if (!choose) {
        OutlinedButton(onClick = { choose = true }, Modifier.fillMaxWidth()) { Text(stringResource(R.string.capture_app_export)) }
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(R.string.capture_app_window, label), style = MaterialTheme.typography.bodyMedium)
        Segmented(
            listOf<Pair<Long?, String>>(
                5 * 60_000L to stringResource(R.string.settings_duration_minutes, 5),
                15 * 60_000L to stringResource(R.string.settings_duration_minutes, 15),
                60 * 60_000L to stringResource(R.string.settings_duration_hours, 1),
                null to stringResource(R.string.capture_window_all),
            ),
            window, { window = it },
        )
        ExportPacketsButton(
            vm, nav, stringResource(R.string.capture_export),
            PcapRequest(PcapFilter(uids = listOf(uid)), CaptureExport.fileName("app-$label"), lastMs = window),
        )
        TextButton(onClick = { choose = false }) { Text(stringResource(R.string.action_cancel)) }
    }
}

/** A count for choosing a plural form. */
private fun count(n: Long): Int = n.coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
