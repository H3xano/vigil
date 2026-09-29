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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.R
import dev.vigil.inspector.data.Socks5Settings
import dev.vigil.inspector.vpn.ServiceState
import dev.vigil.inspector.data.UpstreamSettings
import dev.vigil.inspector.data.WgQuick
import dev.vigil.inspector.engine.UpstreamStatus
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.UiText
import dev.vigil.inspector.ui.asString
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
    val upstreamWarning by ServiceState.upstreamWarning.collectAsStateWithLifecycle()
    val status by vm.status.collectAsStateWithLifecycle()
    val saved = settings.upstream
    val context = LocalContext.current

    // Edited locally and applied with Save, so half-typed proxy settings
    // never reach the engine. The draft (with the WireGuard private key or
    // proxy password) survives rotation in memory, never in the saved state.
    var draft by rememberRetained("upstream.draft") { saved }
    var portText by rememberRetained("upstream.port") { saved.socks5.port.toString() }
    var warnings by rememberRetained("upstream.warnings") { emptyList<UiText>() }
    var importError by rememberRetained("upstream.importError") { null as UiText? }
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
            importError = e.text
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            val (text, name) = readSmallText(context, uri) ?: run {
                importError = UiText.of(R.string.upstream_read_failed)
                return@rememberLauncherForActivityResult
            }
            import(text, name)
        }
    }

    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.upstream_title), nav)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Text(
                stringResource(R.string.upstream_intro),
                Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium,
            )
            Segmented(
                // Protocol names: not translated.
                listOf(
                    UpstreamSettings.MODE_DIRECT to stringResource(R.string.upstream_mode_direct),
                    UpstreamSettings.MODE_WIREGUARD to "WireGuard",
                    UpstreamSettings.MODE_SOCKS5 to "SOCKS5",
                ),
                draft.mode, { v -> draft = draft.copy(mode = v) },
            )
            if (saved.mode != UpstreamSettings.MODE_DIRECT && status is VpnStatus.Running) {
                stats?.upstream?.takeIf { it.mode == saved.mode }?.let { UpstreamStatusCard(it) }
                upstreamWarning?.let {
                    Text(
                        it,
                        Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }

            when (draft.mode) {
                UpstreamSettings.MODE_WIREGUARD -> {
                    SectionTitle("WireGuard")
                    val wg = draft.wireguard
                    if (wg == null) {
                        Text(stringResource(R.string.upstream_wg_import_hint),
                            Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall)
                    } else {
                        Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            if (wg.name.isNotEmpty()) Text(wg.name, style = MaterialTheme.typography.titleSmall)
                            Detail(stringResource(R.string.upstream_endpoint), wg.endpoint)
                            Detail(stringResource(R.string.upstream_addresses), wg.addresses.joinToString(", "))
                            val noDns = stringResource(R.string.upstream_dns_none)
                            Detail("DNS", wg.dns.joinToString(", ").ifEmpty { noDns })
                            Detail(stringResource(R.string.upstream_peer_key), wg.peerPublicKey)
                            Detail(stringResource(R.string.upstream_private_key), stringResource(R.string.upstream_private_key_value, "•".repeat(12)))
                            if (wg.presharedKey != null) Detail(stringResource(R.string.upstream_preshared_key), "•".repeat(12))
                            val everything = stringResource(R.string.upstream_routed_everything)
                            Detail(stringResource(R.string.upstream_routed), wg.allowedIps.joinToString(", ").ifEmpty { everything })
                            Detail("MTU", (wg.mtu ?: dev.vigil.inspector.vpn.ConfigFactory.DEFAULT_WG_MTU).toString())
                            Detail(
                                stringResource(R.string.upstream_keepalive),
                                if (wg.persistentKeepalive > 0) {
                                    stringResource(R.string.settings_duration_seconds, wg.persistentKeepalive)
                                } else {
                                    stringResource(R.string.upstream_keepalive_off)
                                },
                            )
                        }
                    }
                    warnings.forEach { Text("• ${it.asString()}", Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall) }
                    importError?.let { Text(it.asString(), Modifier.padding(horizontal = 16.dp), color = MaterialTheme.colorScheme.error) }
                    Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { picker.launch(arrayOf("*/*")) }) { Text(stringResource(R.string.upstream_import_file)) }
                        OutlinedButton(onClick = { pasting = true }) { Text(stringResource(R.string.upstream_paste_text)) }
                        if (wg != null) TextButton(onClick = { draft = draft.copy(wireguard = null); warnings = emptyList() }) { Text(stringResource(R.string.upstream_remove)) }
                    }
                    Text(
                        stringResource(R.string.upstream_wg_allowed_ips_note),
                        Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                UpstreamSettings.MODE_SOCKS5 -> {
                    SectionTitle(stringResource(R.string.upstream_socks5_title))
                    val s = draft.socks5
                    fun edit(t: (Socks5Settings) -> Socks5Settings) { draft = draft.copy(socks5 = t(draft.socks5)) }
                    Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(s.host, { v -> edit { it.copy(host = v.trim()) } }, Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.settings_field_host)) }, singleLine = true)
                        OutlinedTextField(
                            portText, { v -> portText = v.filter(Char::isDigit).take(5) }, Modifier.fillMaxWidth(),
                            label = { Text(stringResource(R.string.settings_field_port)) }, singleLine = true, isError = portText.toIntOrNull()?.takeIf { it in 1..65535 } == null,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        )
                        OutlinedTextField(s.username, { v -> edit { it.copy(username = v) } }, Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.upstream_username)) }, singleLine = true)
                        SecretField(s.password, { v -> edit { it.copy(password = v) } }, stringResource(R.string.upstream_password), Modifier.fillMaxWidth())
                    }
                    SettingRow(
                        stringResource(R.string.upstream_pass_domains_title),
                        stringResource(R.string.upstream_pass_domains_summary),
                        s.sendDomain, onChecked = { v -> edit { it.copy(sendDomain = v) } },
                    )
                    Text(stringResource(R.string.upstream_udp_label), Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodyMedium)
                    Segmented(listOf("auto" to stringResource(R.string.upstream_udp_relay), "block" to stringResource(R.string.common_block)), s.udp, { v -> edit { it.copy(udp = v) } })
                    Text(
                        stringResource(R.string.upstream_udp_note),
                        Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    SettingRow(
                        stringResource(R.string.upstream_proxy_app_title),
                        stringResource(R.string.upstream_proxy_app_summary, s.proxyApp ?: stringResource(R.string.upstream_proxy_app_none)),
                        onClick = { pickingApp = true },
                    )
                    Text(
                        stringResource(R.string.upstream_orbot_hint),
                        Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                else -> Text(
                    stringResource(R.string.upstream_direct_note),
                    Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall,
                )
            }

            if (draft.mode != UpstreamSettings.MODE_DIRECT) {
                SectionTitle(stringResource(R.string.upstream_down_section))
                SettingRow(
                    stringResource(R.string.upstream_fail_closed_title),
                    stringResource(if (draft.failClosed) R.string.upstream_fail_closed_on else R.string.upstream_fail_closed_off),
                    draft.failClosed, onChecked = { v -> draft = draft.copy(failClosed = v) },
                )
            }

            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (error != null) Text(error.asString(), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                else if (dirty) Text(stringResource(R.string.upstream_unsaved), style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = dirty && error == null, onClick = { vm.updateSettings { it.copy(upstream = candidate) } }) { Text(stringResource(R.string.common_save)) }
                    OutlinedButton(enabled = dirty, onClick = {
                        draft = saved
                        portText = saved.socks5.port.toString()
                        warnings = emptyList()
                        importError = null
                    }) { Text(stringResource(R.string.common_discard)) }
                }
            }
            Column(Modifier.padding(24.dp)) {}
        }
    }

    if (pasting) {
        // The pasted configuration contains the private key: retained in memory only.
        var text by rememberRetained("upstream.paste") { "" }
        val pastedName = stringResource(R.string.upstream_pasted_name)
        val closePaste = {
            pasting = false
            text = ""
        }
        AlertDialog(
            onDismissRequest = closePaste,
            title = { Text(stringResource(R.string.upstream_paste_title)) },
            text = {
                OutlinedTextField(
                    text, { text = it }, Modifier.fillMaxWidth().heightIn(min = 160.dp),
                    // Configuration file syntax: not translated.
                    placeholder = { Text("[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\nPublicKey = …\nEndpoint = …") },
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    // Holds a private key: keep it out of keyboard suggestions and learning.
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii, autoCorrectEnabled = false, capitalization = KeyboardCapitalization.None),
                )
            },
            confirmButton = {
                TextButton(enabled = text.isNotBlank(), onClick = { import(text, pastedName); closePaste() }) {
                    Text(stringResource(R.string.upstream_import))
                }
            },
            dismissButton = { TextButton(onClick = closePaste) { Text(stringResource(R.string.common_cancel)) } },
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
        Text(stringResource(R.string.upstream_detail_label, label), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun UpstreamStatusCard(s: UpstreamStatus) {
    Card(Modifier.fillMaxWidth().padding(16.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            val (label, color) = when (s.state) {
                "up" -> R.string.upstream_state_connected to VigilColors.Allow
                "connecting" -> R.string.upstream_state_connecting to VigilColors.Medium
                "idle" -> R.string.upstream_state_idle to MaterialTheme.colorScheme.onSurfaceVariant
                else -> R.string.upstream_state_down to VigilColors.Block
            }
            Text(stringResource(label), color = color, style = MaterialTheme.typography.titleMedium)
            s.endpoint?.let { Text(stringResource(R.string.upstream_status_endpoint, it), style = MaterialTheme.typography.bodySmall) }
            s.handshakeAgeS?.let { Text(stringResource(R.string.upstream_status_handshake, formatAge(it).asString()), style = MaterialTheme.typography.bodySmall) }
            if (s.txBytes != null && s.rxBytes != null) {
                Text(stringResource(R.string.upstream_status_traffic, formatBytes(s.txBytes), formatBytes(s.rxBytes)), style = MaterialTheme.typography.bodySmall)
            }
            // The engine's UDP relay state, after the protocol name: not translated.
            s.udp?.let { Text("UDP: $it", style = MaterialTheme.typography.bodySmall) }
            s.lastError?.let { Text(stringResource(R.string.settings_last_error, it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
        }
    }
}

internal fun formatAge(seconds: Long): UiText = when {
    seconds < 60 -> UiText.of(R.string.settings_duration_seconds, seconds)
    seconds < 3600 -> UiText.of(R.string.settings_duration_minutes, seconds / 60)
    else -> UiText.of(R.string.settings_duration_hours, seconds / 3600)
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
        title = { Text(stringResource(R.string.upstream_proxy_app_title)) },
        text = {
            val list = apps
            if (list == null) {
                Text(stringResource(R.string.upstream_loading))
            } else {
                LazyColumn(Modifier.heightIn(max = 400.dp)) {
                    item { ListItem(headlineContent = { Text(stringResource(R.string.upstream_proxy_app_none)) }, modifier = Modifier.clickable { onPick(null) }) }
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
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_cancel)) } },
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
