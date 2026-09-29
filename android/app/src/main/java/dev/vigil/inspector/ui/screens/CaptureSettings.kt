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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.navigation.NavController
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

private const val PRIVACY_NOTE =
    "Captured packets hold everything that is not encrypted: plain HTTP requests and responses (pages, form data, cookies), " +
        "DNS lookups and answers, and the handshakes of encrypted connections. HTTPS and QUIC contents stay encrypted. " +
        "Packets are kept in memory only and are discarded when capture is turned off or inspection stops; " +
        "nothing is written to storage unless you export."

private const val STREAM_WARNING =
    "The captured packets are sent unencrypted. “This device” accepts only connections through adb forward " +
        "(from a computer, via the adb shell); other apps on the phone cannot connect. Wi-Fi and All networks " +
        "require the address of your computer below: only the allowed addresses can connect, and anyone on the " +
        "network able to use such an address could receive the packets. Use them on a trusted network and turn " +
        "streaming off when done."

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

    Column(Modifier.fillMaxSize()) {
        VigilTopBar("Packet capture", nav)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            SettingRow(
                "Record packets",
                "Keep the most recent packets of every app in memory, to export them as a PCAPng file for Wireshark " +
                    "(from a connection, an alert or an app) or stream them live.",
                c.enabled, onChecked = { v -> update { it.copy(enabled = v) } },
            )
            Text(PRIVACY_NOTE, Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            SectionTitle("Buffer")
            Segmented(CaptureSettings.BUFFER_CHOICES_MB.map { it to "$it MB" }, c.bufferMb, { v -> update { it.copy(bufferMb = v) } })
            Text(
                "Memory for packets while inspecting; when it is full the oldest packets are overwritten. " +
                    "16 MB holds a few minutes of browsing; downloads and video fill it in seconds.",
                Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (c.enabled) {
                Text(
                    when {
                        cap == null || !cap.enabled -> if (running) "Starting…" else "Recording starts when inspection runs."
                        else -> "Holding ${cap.bufferedPackets} packets (${formatBytes(cap.bufferedBytes)} of ${formatBytes(cap.bufferBytes)})" +
                            if (cap.dropped > 0) " · ${cap.dropped} older ones overwritten" else ""
                    },
                    Modifier.padding(horizontal = 16.dp, vertical = 8.dp), style = MaterialTheme.typography.bodyMedium,
                )
                Column(Modifier.padding(horizontal = 16.dp)) {
                    ExportPacketsButton(
                        vm, nav, "Export all captured packets (PCAPng)",
                        PcapRequest(PcapFilter(), CaptureExport.fileName("capture")),
                    )
                }
            }

            SectionTitle("Stream to Wireshark (PCAP-over-IP)")
            SettingRow(
                "Stream live packets",
                if (c.enabled) "Serve the packets as they are captured to up to two clients on the network." else "Turn on “Record packets” first.",
                c.streamEnabled,
                onChecked = { v ->
                    // Never on the network without an allowlist: anyone there would get the packets.
                    val refusal = c.copy(streamEnabled = v).streamRefusal()
                    if (v && refusal != null) vm.showMessage(refusal) else update { it.copy(streamEnabled = v) }
                },
                enabled = c.enabled || c.streamEnabled,
            )
            Text(STREAM_WARNING, Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = VigilColors.Medium)
            // Shown before streaming is on, so the address or "This device" can be set first.
            if (c.enabled || c.streamEnabled) {
                Text("Listen on", Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodyMedium)
                Segmented(
                    listOf(CaptureSettings.BIND_WIFI to "Wi-Fi", CaptureSettings.BIND_ALL to "All networks", CaptureSettings.BIND_LOOPBACK to "This device"),
                    c.streamBind,
                    { v ->
                        val refusal = c.copy(streamBind = v).streamRefusal()
                        if (refusal != null) vm.showMessage(refusal) else update { it.copy(streamBind = v) }
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
                            c.streamRefusal() != null -> "Not listening: add the address of your computer below (required for Wi-Fi and All networks)."
                            !running || !c.enabled -> "Not listening: inspection is not running."
                            st?.listening != null -> "Listening on ${st.listening} · ${st.clients} of 2 clients connected" +
                                (if (st.dropped > 0) " · ${st.dropped} packets dropped for slow clients" else "") +
                                if (st.rejected > 0) " · ${st.rejected} connections refused" else ""
                            c.streamBind == CaptureSettings.BIND_WIFI && network.wifiAddress == null -> "Not listening: not connected to Wi-Fi."
                            st?.error != null -> "Not listening: ${st.error}"
                            else -> "Starting…"
                        },
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    if (host != null) {
                        Text("In Wireshark, open the capture interface (or add it as a pipe under Capture → Options → Manage Interfaces):",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text("TCP@$host:${c.streamPort}", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
                        Text("From a shell:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text("wireshark -k -i TCP@$host:${c.streamPort}\nnc $host ${c.streamPort} | wireshark -k -i -",
                            fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        if (c.streamBind == CaptureSettings.BIND_LOOPBACK) {
                            Text("This device: only adb forward can connect. On the computer run adb forward tcp:${c.streamPort} tcp:${c.streamPort}, " +
                                "then use 127.0.0.1 there. Other apps on the phone are refused.",
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
            Modifier.fillMaxWidth(), label = { Text("Port") }, singleLine = true, isError = port == null,
            supportingText = { if (port == null) Text("1024 to 65535") },
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
            label = { Text(if (network) "Allowed clients (required)" else "Allowed clients") },
            placeholder = { Text("192.168.1.10, 192.168.1.0/24") },
            isError = badAllow.isNotEmpty() || (network && allow.isEmpty()),
            supportingText = {
                Text(
                    when {
                        badAllow.isNotEmpty() -> "Not an address or range: ${badAllow.joinToString()}"
                        allow.size > CaptureSettings.MAX_ALLOW -> "At most ${CaptureSettings.MAX_ALLOW} entries"
                        network && allow.isEmpty() -> "Required for Wi-Fi and All networks: the address of your computer."
                        network -> "Only these addresses can connect."
                        else -> "Not needed for This device (adb forward only)."
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
        if (why != null) explain = why else picker.launch(request.fileName)
    }, modifier.fillMaxWidth()) { Text(label) }
    explain?.let { text ->
        AlertDialog(
            onDismissRequest = { explain = null },
            title = { Text("Packets not available") },
            text = { Text(text) },
            confirmButton = {
                if (!settings.capture.enabled) {
                    TextButton(onClick = { explain = null; nav.navigate("capture") }) { Text("Packet capture settings") }
                } else {
                    TextButton(onClick = { explain = null }) { Text("OK") }
                }
            },
            dismissButton = if (!settings.capture.enabled) {
                { TextButton(onClick = { explain = null }) { Text("Cancel") } }
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
        OutlinedButton(onClick = { choose = true }, Modifier.fillMaxWidth()) { Text("Export app capture (PCAPng)") }
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("Packets of $label from the last", style = MaterialTheme.typography.bodyMedium)
        Segmented(listOf<Pair<Long?, String>>(5 * 60_000L to "5 min", 15 * 60_000L to "15 min", 60 * 60_000L to "1 h", null to "All held"), window, { window = it })
        ExportPacketsButton(
            vm, nav, "Export",
            PcapRequest(PcapFilter(uids = listOf(uid)), CaptureExport.fileName("app-$label"), lastMs = window),
        )
        TextButton(onClick = { choose = false }) { Text("Cancel") }
    }
}
