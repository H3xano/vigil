package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.FeedCatalog
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.components.Tag
import dev.vigil.inspector.ui.formatCount
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.theme.VigilColors

@Composable
fun FeedsScreen(vm: MainViewModel, nav: NavController) {
    val feeds by vm.feeds.collectAsStateWithLifecycle()
    val loaded by vm.loadedFeeds.collectAsStateWithLifecycle()
    var adding by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        VigilTopBar("Threat intelligence", nav) {
            IconButton(onClick = { vm.refreshFeeds() }) { Icon(Icons.Default.Refresh, "Update all") }
            IconButton(onClick = { adding = true }) { Icon(Icons.Default.Add, "Add feed") }
        }
        LazyColumn {
            item {
                Text(
                    "Hits on malware, phishing and C2 feeds raise high-severity alerts; tracking and ads lists only block. " +
                        "Feeds update daily. Custom feeds accept hosts files, domain lists, AdGuard ||domain^ rules and IP/CIDR lists " +
                        "(for example a MISP text export with an API key in the Authorization header).",
                    Modifier.padding(16.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val groups = feeds.groupBy { it.category }
            for (category in FeedCatalog.categories.filter { it in groups }) {
                item { SectionTitle(category) }
                items(groups.getValue(category), key = { it.id }) { f ->
                    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
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
                                if (f.id in loaded) Tag("active", VigilColors.Allow, filled = true)
                            }
                            f.lastError?.let { Text("Error: $it", style = MaterialTheme.typography.bodySmall, color = VigilColors.Block) }
                        }
                        if (!f.builtin) IconButton(onClick = { vm.deleteFeed(f.id) }) { Icon(Icons.Default.Delete, "Delete") }
                        Switch(checked = f.enabled, onCheckedChange = { vm.setFeedEnabled(f.id, it) })
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
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
                    OutlinedTextField(auth, { auth = it }, label = { Text("Authorization header (optional)") }, singleLine = true)
                    Segmented(listOf("malware" to "Malware", "c2" to "C2", "phishing" to "Phish"), category, { category = it }, Modifier)
                    Segmented(listOf("tracking" to "Tracking", "ads" to "Ads", "custom" to "Other"), category, { category = it }, Modifier)
                }
            },
            confirmButton = {
                TextButton(enabled = name.isNotBlank() && (url.startsWith("https://") || url.startsWith("http://")) && url.length > 10, onClick = {
                    vm.addFeed(name.trim(), url.trim(), category, auth)
                    adding = false
                }) { Text("Add") }
            },
            dismissButton = { TextButton(onClick = { adding = false }) { Text("Cancel") } },
        )
    }
}
