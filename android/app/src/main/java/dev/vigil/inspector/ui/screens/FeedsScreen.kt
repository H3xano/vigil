package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.FeedCatalog
import dev.vigil.inspector.data.FeedEntity
import dev.vigil.inspector.ui.FeedWork
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.components.Tag
import dev.vigil.inspector.ui.formatCount
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors

@Composable
fun FeedsScreen(vm: MainViewModel, nav: NavController) {
    val feeds by vm.feeds.collectAsStateWithLifecycle()
    val loaded by vm.loadedFeeds.collectAsStateWithLifecycle()
    val work by vm.feedWork.collectAsStateWithLifecycle()
    var adding by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf<FeedEntity?>(null) }

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
            IconButton(onClick = { adding = true }) { Icon(Icons.Default.Add, "Add feed") }
        }
        when (work) {
            FeedWork.RUNNING -> Progress("Downloading feeds…")
            FeedWork.WAITING -> Progress("Feed update queued; waiting for a network connection…")
            FeedWork.IDLE -> {}
        }
        LazyColumn {
            item {
                Row(Modifier.padding(start = 16.dp, end = 8.dp, top = 16.dp, bottom = 16.dp)) {
                    Text(
                        "Hits on malware, phishing and C2 feeds raise high-severity alerts; tracking and ads lists only block. " +
                            "Enabled feeds are downloaded daily from their publishers (GitHub, abuse.ch, Spamhaus and others); " +
                            "turn a feed off to stop downloading it. Custom feeds accept hosts files, domain lists, " +
                            "AdGuard ||domain^ rules and IP/CIDR lists (for example a MISP text export with an API key in " +
                            "the Authorization header).",
                        Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    HelpIcon("C2", Glossary.C2)
                }
            }
            val groups = feeds.groupBy { it.category }
            for (category in FeedCatalog.categories.filter { it in groups }) {
                item { SectionTitle(category) }
                items(groups.getValue(category), key = { it.id }) { f ->
                    FeedRow(f, active = f.id in loaded, onToggle = { vm.setFeedEnabled(f.id, it) }, onDelete = { confirmDelete = f })
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }

    confirmDelete?.let { f ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text("Delete ${f.name}?") },
            text = { Text("The feed and its downloaded copy are removed. Its entries stop matching the next time inspection loads feeds.") },
            confirmButton = {
                TextButton(onClick = {
                    vm.deleteFeed(f.id)
                    vm.showMessage("Deleted ${f.name}")
                    confirmDelete = null
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel") } },
        )
    }

    if (adding) {
        var name by remember { mutableStateOf("") }
        var url by remember { mutableStateOf("https://") }
        var category by remember { mutableStateOf("malware") }
        var auth by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { adding = false },
            title = { Text("Add feed") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true)
                    OutlinedTextField(url, { url = it }, label = { Text("URL") }, singleLine = true)
                    SecretField(auth, { auth = it }, "Authorization header (optional)")
                    CleartextWarning(url.trim(), hasSecret = auth.isNotBlank(), isFeed = true)
                    Segmented(listOf("malware" to "Malware", "c2" to "C2", "phishing" to "Phish"), category, { category = it }, Modifier)
                    Segmented(listOf("tracking" to "Tracking", "ads" to "Ads", "custom" to "Other"), category, { category = it }, Modifier)
                }
            },
            confirmButton = {
                TextButton(enabled = name.isNotBlank() && (url.startsWith("https://") || url.startsWith("http://")) && url.length > 10, onClick = {
                    vm.addFeed(name.trim(), url.trim(), category, auth)
                    vm.showMessage("Added ${name.trim()}; downloading…")
                    adding = false
                }) { Text("Add") }
            },
            dismissButton = { TextButton(onClick = { adding = false }) { Text("Cancel") } },
        )
    }
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
                Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (f.lastUpdated != null) {
                        Tag(listOfNotNull(
                            f.domains.takeIf { it > 0 }?.let { "${formatCount(it.toLong())} domains" },
                            f.ipRanges.takeIf { it > 0 }?.let { "${formatCount(it.toLong())} ranges" },
                        ).joinToString(" · "))
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
                            if (f.authHeader != null) ", and the Authorization header is sent in clear text." else ".",
                        style = MaterialTheme.typography.bodySmall, color = VigilColors.Medium,
                    )
                }
            }
            Switch(checked = f.enabled, onCheckedChange = null)
        }
        if (!f.builtin) IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, "Delete ${f.name}") }
    }
}

/** A single-line field for tokens and Authorization headers, masked until shown. */
@Composable
fun SecretField(value: String, onChange: (String) -> Unit, label: String, modifier: Modifier = Modifier, placeholder: String? = null) {
    var visible by remember { mutableStateOf(false) }
    OutlinedTextField(
        value, onChange, modifier,
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it) } },
        singleLine = true,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = {
            if (value.isNotEmpty()) TextButton(onClick = { visible = !visible }) { Text(if (visible) "Hide" else "Show") }
        },
    )
}

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
