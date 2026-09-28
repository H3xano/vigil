package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.FeedCatalog
import dev.vigil.inspector.data.FeedEntity
import dev.vigil.inspector.data.AsnDatabase
import dev.vigil.inspector.data.FeedKinds
import dev.vigil.inspector.data.TaxiiCollection
import dev.vigil.inspector.ui.FeedWork
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.rememberRetained
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.components.Tag
import dev.vigil.inspector.ui.formatCount
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors
import kotlinx.coroutines.launch

@Composable
fun FeedsScreen(vm: MainViewModel, nav: NavController) {
    val feeds by vm.feeds.collectAsStateWithLifecycle()
    val loaded by vm.loadedFeeds.collectAsStateWithLifecycle()
    val work by vm.feedWork.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    // Open dialogs survive rotation: the Add feed draft in memory (it may hold credentials), the delete target by id.
    val adding = rememberRetained("feeds.add") { null as FeedDraft? }
    var confirmDeleteId by rememberSaveable { mutableStateOf<String?>(null) }
    val confirmDelete = confirmDeleteId?.let { id -> feeds.firstOrNull { it.id == id } }

    // Report when an update the user can see (running or waiting) finishes.
    var wasBusy by remember { mutableStateOf(false) }
    LaunchedEffect(work) {
        if (work != FeedWork.IDLE) {
            wasBusy = true
        } else if (wasBusy) {
            wasBusy = false
            vm.showMessage("Feed update finished")
        }
    }

    Column(Modifier.fillMaxSize()) {
        VigilTopBar("Threat intelligence", nav) {
            IconButton(onClick = {
                vm.refreshFeeds()
                vm.showMessage("Updating threat feeds…")
            }, enabled = work != FeedWork.RUNNING) { Icon(Icons.Default.Refresh, "Update all") }
            IconButton(onClick = { adding.value = FeedDraft() }) { Icon(Icons.Default.Add, "Add feed") }
        }
        when (work) {
            FeedWork.RUNNING -> Progress("Downloading feeds…")
            FeedWork.WAITING -> Progress("Feed update queued; waiting for a network connection…")
            FeedWork.IDLE -> {}
        }
        LazyColumn {
            item {
                Row(Modifier.padding(start = 16.dp, end = 8.dp, top = 16.dp, bottom = 8.dp)) {
                    Text(
                        "Hits on malware, phishing and C2 feeds raise high-severity alerts; tracking and ads lists only block. " +
                            "Enabled feeds are downloaded daily from their publishers (GitHub, abuse.ch, Spamhaus and others); " +
                            "turn a feed off to stop downloading it. Custom feeds accept hosts files, domain lists, " +
                            "AdGuard ||domain^ rules and IP/CIDR lists (for example a MISP text export with an API key in " +
                            "the Authorization header), JA4 fingerprint lists, and TAXII 2.1 collections (MISP, OpenCTI).",
                        Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    HelpIcon("C2", Glossary.C2)
                }
            }
            item {
                Ja4Settings(settings.blockJa4Matches, onBlock = vm::setBlockJa4Matches)
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
            val (taxii, lists) = feeds.partition { it.isTaxii }
            val groups = lists.groupBy { it.category }
            for (category in FeedCatalog.categories.filter { it in groups }) {
                item {
                    when (category) {
                        "ja4" -> SectionTitle("JA4 fingerprints")
                        AsnDatabase.CATEGORY -> Row(verticalAlignment = Alignment.CenterVertically) {
                            SectionTitle("Network (ASN) data")
                            HelpIcon("ASN", Glossary.ASN)
                        }
                        else -> SectionTitle(category)
                    }
                }
                items(groups.getValue(category), key = { it.id }) { f ->
                    FeedRow(f, active = f.id in loaded, onToggle = { vm.setFeedEnabled(f.id, it) }, onDelete = { confirmDeleteId = f.id })
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
            if (taxii.isNotEmpty()) {
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SectionTitle("TAXII collections")
                        HelpIcon("TAXII", Glossary.TAXII)
                    }
                }
                items(taxii, key = { it.id }) { f ->
                    FeedRow(f, active = f.id in loaded, onToggle = { vm.setFeedEnabled(f.id, it) }, onDelete = { confirmDeleteId = f.id })
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }

    confirmDelete?.let { f ->
        AlertDialog(
            onDismissRequest = { confirmDeleteId = null },
            title = { Text("Delete ${f.name}?") },
            text = { Text("The feed and its downloaded copy are removed. Its entries stop matching the next time inspection loads feeds.") },
            confirmButton = {
                TextButton(onClick = {
                    vm.deleteFeed(f.id)
                    vm.showMessage("Deleted ${f.name}")
                    confirmDeleteId = null
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDeleteId = null }) { Text("Cancel") } },
        )
    }

    if (adding.value != null) AddFeedDialog(vm, adding, onDismiss = { adding.value = null })
}

/** Explains JA4 matching and holds the block switch (alert-only by default). */
@Composable
private fun Ja4Settings(block: Boolean, onBlock: (Boolean) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
        Row(Modifier.padding(start = 16.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("JA4 fingerprint matching", Modifier.weight(1f), style = MaterialTheme.typography.titleSmall)
            HelpIcon("JA4 match", Glossary.JA4_MATCH)
        }
        Text(
            "Every TLS and QUIC connection's JA4 fingerprint is compared with the enabled JA4 feeds and the JA4 indicators " +
                "of TAXII collections. A match raises a high-severity alert naming the app and destination. Fingerprints " +
                "identify TLS libraries, so benign apps can match; blocking is therefore off by default.",
            Modifier.padding(horizontal = 16.dp),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(
            Modifier.fillMaxWidth().toggleable(value = block, role = Role.Switch, onValueChange = onBlock)
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f).padding(end = 12.dp)) {
                Text("Block matching connections", style = MaterialTheme.typography.bodyLarge)
                Text(
                    "Resets the connection before the handshake reaches the server. Allowlisted domains are exempt.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(checked = block, onCheckedChange = null)
        }
    }
}

/** The Add feed dialog's fields; kept across rotation in memory only (the credentials never go to the saved state). */
private data class FeedDraft(
    val kind: String = FeedKinds.LIST,
    val name: String = "",
    val url: String = "https://",
    val category: String = "malware",
    val auth: String = "",
    // TAXII
    val authMode: String = "none",
    val user: String = "",
    val headerName: String = "Authorization",
    val collections: List<TaxiiCollection>? = null,
    val chosen: TaxiiCollection? = null,
    val lookupError: String? = null,
)

@Composable
private fun AddFeedDialog(vm: MainViewModel, state: MutableState<FeedDraft?>, onDismiss: () -> Unit) {
    val d = state.value ?: return
    fun edit(t: (FeedDraft) -> FeedDraft) {
        state.value = state.value?.let(t)
    }
    // A lookup in flight is not retained: after a rotation, look up again.
    var looking by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    val trimmedUrl = d.url.trim()
    val urlOk = (trimmedUrl.startsWith("https://") || trimmedUrl.startsWith("http://")) && trimmedUrl.length > 10
    // TAXII credentials as (header name, value).
    fun taxiiAuth(): Pair<String?, String?> = when (d.authMode) {
        "basic" -> "Authorization" to if (d.user.isBlank() && d.auth.isBlank()) null else
            "Basic " + java.util.Base64.getEncoder().encodeToString("${d.user}:${d.auth}".toByteArray())
        "header" -> d.headerName.trim().ifEmpty { "Authorization" } to d.auth.takeIf { it.isNotBlank() }
        else -> null to null
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add feed") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Segmented(
                    listOf(FeedKinds.LIST to "Domains / IPs", FeedKinds.JA4 to "JA4", FeedKinds.TAXII to "TAXII"),
                    d.kind, { k -> edit { it.copy(kind = k, collections = null, chosen = null, lookupError = null) } }, Modifier,
                )
                OutlinedTextField(d.name, { v -> edit { it.copy(name = v) } }, label = { Text("Name") }, singleLine = true)
                OutlinedTextField(
                    d.url, { v -> edit { it.copy(url = v, collections = null, chosen = null) } },
                    label = { Text(if (d.kind == FeedKinds.TAXII) "Discovery or API root URL" else "URL") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                )
                when (d.kind) {
                    FeedKinds.LIST -> {
                        SecretField(d.auth, { v -> edit { it.copy(auth = v) } }, "Authorization header (optional)")
                        CleartextWarning(trimmedUrl, hasSecret = d.auth.isNotBlank(), isFeed = true)
                        Segmented(listOf("malware" to "Malware", "c2" to "C2", "phishing" to "Phish"), d.category, { v -> edit { it.copy(category = v) } }, Modifier)
                        Segmented(listOf("tracking" to "Tracking", "ads" to "Ads", "custom" to "Other"), d.category, { v -> edit { it.copy(category = v) } }, Modifier)
                    }
                    FeedKinds.JA4 -> {
                        SecretField(d.auth, { v -> edit { it.copy(auth = v) } }, "Authorization header (optional)")
                        CleartextWarning(trimmedUrl, hasSecret = d.auth.isNotBlank(), isFeed = true)
                        Hint(
                            "One JA4 fingerprint per line, optionally followed by a label, e.g.\n" +
                                "t13d190900_9dc949149365_97f8aa674fd9  Sliver\n" +
                                "Lines starting with # are comments. a_b_* matches any extension set.",
                        )
                    }
                    FeedKinds.TAXII -> {
                        Segmented(listOf("none" to "No auth", "basic" to "Basic", "header" to "API key"), d.authMode, { v -> edit { it.copy(authMode = v) } }, Modifier)
                        when (d.authMode) {
                            "basic" -> {
                                OutlinedTextField(d.user, { v -> edit { it.copy(user = v) } }, label = { Text("Username") }, singleLine = true)
                                SecretField(d.auth, { v -> edit { it.copy(auth = v) } }, "Password")
                            }
                            "header" -> {
                                OutlinedTextField(d.headerName, { v -> edit { it.copy(headerName = v) } }, label = { Text("Header name") }, singleLine = true)
                                SecretField(d.auth, { v -> edit { it.copy(auth = v) } }, "Header value", placeholder = "e.g. Bearer <token> or the MISP key")
                            }
                        }
                        CleartextWarning(trimmedUrl, hasSecret = d.authMode != "none", isFeed = true)
                        OutlinedButton(enabled = urlOk && !looking, onClick = {
                            looking = true
                            edit { it.copy(lookupError = null) }
                            val (h, v) = taxiiAuth()
                            scope.launch {
                                vm.taxiiCollections(trimmedUrl, h, v)
                                    .onSuccess { list ->
                                        edit {
                                            it.copy(
                                                collections = list,
                                                chosen = list.singleOrNull { c -> c.canRead },
                                                lookupError = if (list.isEmpty()) "The server lists no collections." else null,
                                            )
                                        }
                                    }
                                    .onFailure { e -> edit { it.copy(lookupError = e.message ?: e.javaClass.simpleName) } }
                                looking = false
                            }
                        }) { Text(if (looking) "Looking up…" else "Find collections") }
                        d.lookupError?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = VigilColors.Block) }
                        d.collections?.forEach { c ->
                            Row(
                                Modifier.fillMaxWidth()
                                    .selectable(selected = d.chosen == c, enabled = c.canRead, role = Role.RadioButton, onClick = { edit { it.copy(chosen = c) } }),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(selected = d.chosen == c, onClick = null, enabled = c.canRead)
                                Column(Modifier.padding(start = 8.dp)) {
                                    Text(c.title, style = MaterialTheme.typography.bodyMedium)
                                    Text(
                                        (if (c.canRead) "" else "not readable with these credentials · ") + c.id,
                                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                        if (d.chosen != null) {
                            Text("Treat its domains and IPs as", style = MaterialTheme.typography.bodySmall)
                            Segmented(listOf("malware" to "Malware", "c2" to "C2", "phishing" to "Phish"), d.category, { v -> edit { it.copy(category = v) } }, Modifier)
                        }
                        Hint(
                            "Uses indicators for domains, IP addresses and ranges, URLs (their host) and JA4 fingerprints. " +
                                "Polled with the daily feed update, incrementally.",
                        )
                    }
                }
            }
        },
        confirmButton = {
            val chosen = d.chosen
            val ready = d.name.isNotBlank() && urlOk && (d.kind != FeedKinds.TAXII || chosen != null)
            TextButton(enabled = ready, onClick = {
                if (d.kind == FeedKinds.TAXII && chosen != null) {
                    val (h, v) = taxiiAuth()
                    vm.addTaxii(d.name.trim(), chosen, d.category, h, v)
                } else {
                    vm.addFeed(d.name.trim(), trimmedUrl, d.category, d.auth, d.kind)
                }
                vm.showMessage("Added ${d.name.trim()}; downloading…")
                onDismiss()
            }) { Text("Add") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun Progress(text: String) {
    Column(Modifier.fillMaxWidth()) {
        LinearProgressIndicator(Modifier.fillMaxWidth())
        Text(text, Modifier.padding(horizontal = 16.dp, vertical = 6.dp), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun FeedRow(f: FeedEntity, active: Boolean, onToggle: (Boolean) -> Unit, onDelete: () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        // The text and switch form one toggle target announced with the feed name.
        Row(
            Modifier.weight(1f)
                .toggleable(value = f.enabled, role = Role.Switch, onValueChange = onToggle)
                .padding(start = 16.dp, end = if (f.builtin) 16.dp else 0.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f).padding(end = 12.dp)) {
                Text(f.name, style = MaterialTheme.typography.bodyLarge)
                if (f.description.isNotEmpty()) {
                    Text(f.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (f.isTaxii) {
                    Text(
                        "${f.url} · treated as ${f.category}",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (f.lastUpdated != null) {
                        Tag(
                            listOfNotNull(
                                f.domains.takeIf { it > 0 }?.let { "${formatCount(it.toLong())} domains" },
                                f.ipRanges.takeIf { it > 0 }?.let { "${formatCount(it.toLong())} ranges" },
                                f.ja4.takeIf { it > 0 }?.let { "${formatCount(it.toLong())} JA4" },
                            ).joinToString(" · ").ifEmpty { "empty" },
                        )
                        Tag("updated ${formatRelative(f.lastUpdated)}")
                    } else if (f.enabled) {
                        Tag("not downloaded", VigilColors.Low, filled = true)
                    }
                    if (active) Tag("active", VigilColors.Allow, filled = true)
                    if (f.url.startsWith("http://")) Tag("http", VigilColors.Medium, filled = true)
                }
                f.lastError?.let { Text("Error: $it", style = MaterialTheme.typography.bodySmall, color = VigilColors.Block) }
                if (!f.builtin && f.url.startsWith("http://")) {
                    Text(
                        "Downloaded without encryption: the list can be altered in transit" +
                            if (f.authHeader != null) ", and the credentials are sent in clear text." else ".",
                        style = MaterialTheme.typography.bodySmall, color = VigilColors.Medium,
                    )
                }
            }
            Switch(checked = f.enabled, onCheckedChange = null)
        }
        if (!f.builtin) IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, "Delete ${f.name}") }
    }
}

/**
 * A single-line field for tokens, passwords and Authorization headers,
 * masked until shown. The password keyboard type and disabled autocorrect
 * keep secrets out of keyboard suggestions and learned words.
 */
@Composable
fun SecretField(value: String, onChange: (String) -> Unit, label: String, modifier: Modifier = Modifier, placeholder: String? = null) {
    var visible by remember { mutableStateOf(false) }
    OutlinedTextField(
        value, onChange, modifier,
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it) } },
        singleLine = true,
        keyboardOptions = SECRET_KEYBOARD,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = {
            if (value.isNotEmpty()) TextButton(onClick = { visible = !visible }) { Text(if (visible) "Hide" else "Show") }
        },
    )
}

/** Keyboard for secrets: password type, no autocorrect or suggestions. */
val SECRET_KEYBOARD = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false)

/**
 * Warns about plain-http endpoints: credentials travel in clear text, and a
 * feed downloaded over http can be modified by anyone on the network path.
 */
@Composable
fun CleartextWarning(url: String, hasSecret: Boolean, isFeed: Boolean) {
    if (!url.startsWith("http://")) return
    val text = when {
        hasSecret -> "This URL uses http://: the Authorization header will be sent unencrypted, readable by anyone on the network path. Use https://."
        isFeed -> "This URL uses http://: the list can be altered in transit (to block or hide domains). Prefer https://."
        else -> "This URL uses http://: events are sent unencrypted. Prefer https:// outside a trusted network."
    }
    Text(text, style = MaterialTheme.typography.bodySmall, color = VigilColors.Medium)
}
