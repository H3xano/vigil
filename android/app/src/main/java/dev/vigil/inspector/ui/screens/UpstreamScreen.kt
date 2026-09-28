package dev.vigil.inspector.ui.screens

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.Socks5Settings
import dev.vigil.inspector.data.UpstreamSettings
import dev.vigil.inspector.data.WgQuick
import dev.vigil.inspector.engine.UpstreamStatus
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.rememberRetained
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.formatBytes
import dev.vigil.inspector.ui.theme.VigilColors
import dev.vigil.inspector.vpn.VpnStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** "Route through VPN / proxy": direct, WireGuard or SOCKS5 egress. */
@Composable
fun UpstreamScreen(vm: MainViewModel, nav: NavController) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val stats by vm.stats.collectAsStateWithLifecycle()
    val status by vm.status.collectAsStateWithLifecycle()
    val saved = settings.upstream
    val context = LocalContext.current

    // Edited locally and applied with Save, so half-typed proxy settings
    // never reach the engine. The draft (with the WireGuard private key or
    // proxy password) survives rotation in memory, never in the saved state.
    var draft by rememberRetained("upstream.draft") { saved }
    var portText by rememberRetained("upstream.port") { saved.socks5.port.toString() }
    var warnings by rememberRetained("upstream.warnings") { emptyList<String>() }
    var importError by rememberRetained("upstream.importError") { null as String? }
    var pasting by rememberSaveable { mutableStateOf(false) }
    var pickingApp by rememberSaveable { mutableStateOf(false) }
    val candidate = draft.copy(socks5 = draft.socks5.copy(port = portText.toIntOrNull() ?: -1))
    val error = candidate.validationError()
    val dirty = candidate != saved

    fun import(text: String, name: String) {
        try {
            val parsed = WgQuick.parse(text, name)
            draft = draft.copy(wireguard = parsed.settings, mode = UpstreamSettings.MODE_WIREGUARD)
            warnings = parsed.warnings
            importError = null
        } catch (e: WgQuick.ParseException) {
            importError = e.message
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            val (text, name) = readSmallText(context, uri) ?: run {
                importError = "Could not read the file (or it is larger than 64 KB)."
                return@rememberLauncherForActivityResult
            }
            import(text, name)
        }
    }

    Column(Modifier.fillMaxSize()) {
        VigilTopBar("Route through VPN / proxy", nav)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Text(
                "Android runs one VPN at a time. Instead of your VPN app, vigil can send the traffic it inspects through your " +
                    "WireGuard server or a SOCKS5 proxy (e.g. Tor via Orbot). Inspection is unchanged; only the way out differs.",
                Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium,
            )
            Segmented(
                listOf(UpstreamSettings.MODE_DIRECT to "Direct", UpstreamSettings.MODE_WIREGUARD to "WireGuard", UpstreamSettings.MODE_SOCKS5 to "SOCKS5"),
                draft.mode, { v -> draft = draft.copy(mode = v) },
            )
            if (saved.mode != UpstreamSettings.MODE_DIRECT && status is VpnStatus.Running) {
                stats?.upstream?.takeIf { it.mode == saved.mode }?.let { UpstreamStatusCard(it) }
            }

            when (draft.mode) {
                UpstreamSettings.MODE_WIREGUARD -> {
                    SectionTitle("WireGuard")
                    val wg = draft.wireguard
                    if (wg == null) {
                        Text("Import the wg-quick configuration (.conf) from your VPN provider or your own server.",
                            Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall)
                    } else {
                        Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            if (wg.name.isNotEmpty()) Text(wg.name, style = MaterialTheme.typography.titleSmall)
                            Detail("Endpoint", wg.endpoint)
                            Detail("Addresses", wg.addresses.joinToString(", "))
                            Detail("DNS", wg.dns.joinToString(", ").ifEmpty { "none (public resolvers through the tunnel)" })
                            Detail("Peer key", wg.peerPublicKey)
                            Detail("Private key", "•".repeat(12) + " (stored on this device only)")
                            if (wg.presharedKey != null) Detail("Pre-shared key", "•".repeat(12))
                            Detail("Routed", wg.allowedIps.joinToString(", ").ifEmpty { "everything" })
                            Detail("MTU", (wg.mtu ?: dev.vigil.inspector.vpn.ConfigFactory.DEFAULT_WG_MTU).toString())
                            Detail("Keepalive", if (wg.persistentKeepalive > 0) "${wg.persistentKeepalive} s" else "off")
                        }
                    }
                    warnings.forEach { Text("• $it", Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall) }
                    importError?.let { Text(it, Modifier.padding(horizontal = 16.dp), color = MaterialTheme.colorScheme.error) }
                    Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { picker.launch(arrayOf("*/*")) }) { Text("Import file") }
                        OutlinedButton(onClick = { pasting = true }) { Text("Paste text") }
                        if (wg != null) TextButton(onClick = { draft = draft.copy(wireguard = null); warnings = emptyList() }) { Text("Remove") }
                    }
                    Text(
                        "Destinations outside the peer's AllowedIPs go direct, as with wg-quick. IPv6 needs an IPv6 Address in the configuration; " +
                            "without one, apps fall back to IPv4.",
                        Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                UpstreamSettings.MODE_SOCKS5 -> {
                    SectionTitle("SOCKS5 proxy")
                    val s = draft.socks5
                    fun edit(t: (Socks5Settings) -> Socks5Settings) { draft = draft.copy(socks5 = t(draft.socks5)) }
                    Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(s.host, { v -> edit { it.copy(host = v.trim()) } }, Modifier.fillMaxWidth(), label = { Text("Host") }, singleLine = true)
                        OutlinedTextField(
                            portText, { v -> portText = v.filter(Char::isDigit).take(5) }, Modifier.fillMaxWidth(),
                            label = { Text("Port") }, singleLine = true, isError = portText.toIntOrNull()?.takeIf { it in 1..65535 } == null,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        )
                        OutlinedTextField(s.username, { v -> edit { it.copy(username = v) } }, Modifier.fillMaxWidth(), label = { Text("Username (optional)") }, singleLine = true)
                        SecretField(s.password, { v -> edit { it.copy(password = v) } }, "Password (optional)", Modifier.fillMaxWidth())
                    }
                    SettingRow(
                        "Pass domain names",
                        "Connect by the name the app asked for (from TLS or HTTP) and let the proxy resolve it. Recommended for Tor. " +
                            "The connection to the proxy then starts when the app sends its first bytes.",
                        s.sendDomain, onChecked = { v -> edit { it.copy(sendDomain = v) } },
                    )
                    Text("UDP (QUIC, games, calls)", Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodyMedium)
                    Segmented(listOf("auto" to "Relay if supported", "block" to "Block"), s.udp, { v -> edit { it.copy(udp = v) } })
                    Text(
                        "DNS always goes to the proxy over TCP. When UDP cannot be relayed (Tor cannot), it is blocked and apps fall back to TCP.",
                        Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    SettingRow(
                        "Proxy app",
                        (s.proxyApp ?: "None") + ": an app on this phone that provides the proxy (e.g. Orbot) must be excluded from vigil's VPN, " +
                            "or its own traffic would loop back into it. Changing this restarts inspection.",
                        onClick = { pickingApp = true },
                    )
                    Text(
                        "Orbot: host 127.0.0.1, port 9050, proxy app Orbot, pass domain names on.",
                        Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                else -> Text(
                    "Traffic leaves through the phone's own network, as without vigil.",
                    Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall,
                )
            }

            if (draft.mode != UpstreamSettings.MODE_DIRECT) {
                SectionTitle("When the tunnel or proxy is down")
                SettingRow(
                    "Block traffic (fail closed)",
                    if (draft.failClosed) {
                        "Connections fail and lookups get no answer until the tunnel or proxy works again. Nothing goes out directly."
                    } else {
                        "Connections fall back to the phone's own network while the tunnel or proxy is unreachable: your real IP address is exposed."
                    },
                    draft.failClosed, onChecked = { v -> draft = draft.copy(failClosed = v) },
                )
            }

            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (error != null) Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                else if (dirty) Text("Unsaved changes. Saving applies them to new connections at once.", style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = dirty && error == null, onClick = { vm.updateSettings { it.copy(upstream = candidate) } }) { Text("Save") }
                    OutlinedButton(enabled = dirty, onClick = {
                        draft = saved
                        portText = saved.socks5.port.toString()
                        warnings = emptyList()
                        importError = null
                    }) { Text("Discard") }
                }
            }
            Column(Modifier.padding(24.dp)) {}
        }
    }

    if (pasting) {
        // The pasted configuration contains the private key: retained in memory only.
        var text by rememberRetained("upstream.paste") { "" }
        val closePaste = {
            pasting = false
            text = ""
        }
        AlertDialog(
            onDismissRequest = closePaste,
            title = { Text("WireGuard configuration") },
            text = {
                OutlinedTextField(
                    text, { text = it }, Modifier.fillMaxWidth().heightIn(min = 160.dp),
                    placeholder = { Text("[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\nPublicKey = …\nEndpoint = …") },
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    // Holds a private key: keep it out of keyboard suggestions and learning.
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii, autoCorrectEnabled = false, capitalization = KeyboardCapitalization.None),
                )
            },
            confirmButton = { TextButton(enabled = text.isNotBlank(), onClick = { import(text, "pasted"); closePaste() }) { Text("Import") } },
            dismissButton = { TextButton(onClick = closePaste) { Text("Cancel") } },
        )
    }
    if (pickingApp) {
        ProxyAppPicker(
            onPick = { pkg -> draft = draft.copy(socks5 = draft.socks5.copy(proxyApp = pkg)); pickingApp = false },
            onDismiss = { pickingApp = false },
        )
    }
}

@Composable
private fun Detail(label: String, value: String) {
    Row {
        Text("$label: ", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun UpstreamStatusCard(s: UpstreamStatus) {
    Card(Modifier.fillMaxWidth().padding(16.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            val (label, color) = when (s.state) {
                "up" -> "Connected" to VigilColors.Allow
                "connecting" -> "Connecting…" to VigilColors.Medium
                "idle" -> "Idle (connects on first use)" to MaterialTheme.colorScheme.onSurfaceVariant
                else -> "Down" to VigilColors.Block
            }
            Text(label, color = color, style = MaterialTheme.typography.titleMedium)
            s.endpoint?.let { Text("Endpoint $it", style = MaterialTheme.typography.bodySmall) }
            s.handshakeAgeS?.let { Text("Last handshake ${formatAge(it)} ago", style = MaterialTheme.typography.bodySmall) }
            if (s.txBytes != null && s.rxBytes != null) {
                Text("Sent ${formatBytes(s.txBytes)} · received ${formatBytes(s.rxBytes)}", style = MaterialTheme.typography.bodySmall)
            }
            s.udp?.let { Text("UDP: $it", style = MaterialTheme.typography.bodySmall) }
            s.lastError?.let { Text("Last error: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        }
    }
}

internal fun formatAge(seconds: Long): String = when {
    seconds < 60 -> "$seconds s"
    seconds < 3600 -> "${seconds / 60} min"
    else -> "${seconds / 3600} h"
}

/** Launchable apps, to pick the one that provides the proxy. */
@Composable
private fun ProxyAppPicker(onPick: (String?) -> Unit, onDismiss: () -> Unit) {
    val context = LocalContext.current
    var apps by remember { mutableStateOf<List<Pair<String, String>>?>(null) }
    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            pm.queryIntentActivities(launcher, 0)
                .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
                .filter { it.first != context.packageName }
                .distinctBy { it.first }
                .sortedBy { it.second.lowercase() }
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Proxy app") },
        text = {
            val list = apps
            if (list == null) {
                Text("Loading…")
            } else {
                LazyColumn(Modifier.heightIn(max = 400.dp)) {
                    item { ListItem(headlineContent = { Text("None") }, modifier = Modifier.clickable { onPick(null) }) }
                    items(list, key = { it.first }) { (pkg, label) ->
                        ListItem(
                            headlineContent = { Text(label) },
                            supportingContent = { Text(pkg) },
                            modifier = Modifier.clickable { onPick(pkg) },
                        )
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Reads a small text document chosen through the system picker. */
private fun readSmallText(context: Context, uri: Uri): Pair<String, String>? = runCatching {
    val name = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) c.getString(0) else null
    } ?: "imported.conf"
    val limit = 64 * 1024
    val out = java.io.ByteArrayOutputStream()
    context.contentResolver.openInputStream(uri)?.use { input ->
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > limit) return null
        }
    } ?: return null
    out.toString(Charsets.UTF_8.name()) to name
}.getOrNull()
