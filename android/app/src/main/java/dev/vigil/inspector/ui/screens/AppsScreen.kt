package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.data.AsnDatabase
import dev.vigil.inspector.ui.MainViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import dev.vigil.inspector.ui.components.AppIcon
import dev.vigil.inspector.ui.components.EmptyState
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.components.SeverityDot
import dev.vigil.inspector.ui.components.StatTile
import dev.vigil.inspector.ui.components.Tag
import dev.vigil.inspector.ui.formatBytes
import dev.vigil.inspector.ui.formatCount
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.plural
import dev.vigil.inspector.ui.theme.VigilColors

@Composable
fun AppsScreen(vm: MainViewModel, nav: NavController) {
    val apps by vm.appsWeek.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    var query by rememberSaveable { mutableStateOf("") }
    val label = rememberAppLabels(vm, apps.map { it.pkg })
    val filtered = apps.filter { query.isBlank() || label(it.pkg).contains(query, true) || it.pkg.contains(query, true) }
    Column(Modifier.fillMaxSize()) {
        VigilTopBar("Apps · last 7 days")
        OutlinedTextField(
            value = query, onValueChange = { query = it }, singleLine = true, placeholder = { Text("Search apps") },
            leadingIcon = { Icon(Icons.Default.Search, null) },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        )
        if (apps.isEmpty()) {
            EmptyState("No apps yet", "Apps appear here once they use the network while inspection is running.")
            return@Column
        }
        if (filtered.isEmpty()) {
            EmptyState("No matches", "No app seen in the last 7 days matches “${query.trim()}”.")
            return@Column
        }
        LazyColumn {
            items(filtered, key = { it.pkg }) { a ->
                val name = label(a.pkg)
                Row(
                    Modifier.fillMaxWidth().clickable { nav.navigate("app/${a.pkg}") }.padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    AppIcon(a.pkg, name, 40.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            "${formatBytes(a.tx + a.rx)} · ${plural(a.destinations, "destination")} · ${formatRelative(a.lastSeen)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        if (a.pkg in settings.blockedPackages) Tag("NO NETWORK", VigilColors.Block, filled = true)
                        else if (a.blocked > 0) Tag("${formatCount(a.blocked)} blocked", VigilColors.Block, filled = true)
                    }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        }
    }
}

@Composable
fun AppDetailScreen(vm: MainViewModel, nav: NavController, pkg: String) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val destinations by remember(pkg) { vm.appDestinations(pkg) }.collectAsStateWithLifecycle(initialValue = emptyList())
    val flows by remember(pkg) { vm.appFlows(pkg) }.collectAsStateWithLifecycle(initialValue = emptyList())
    val dns by remember(pkg) { vm.appDns(pkg) }.collectAsStateWithLifecycle(initialValue = emptyList())
    val alerts by remember(pkg) { vm.appAlerts(pkg) }.collectAsStateWithLifecycle(initialValue = emptyList())
    // PackageManager lookups are IPC: resolve off the main thread.
    var info by remember(pkg) { mutableStateOf(AppInfo(pkg, null, vm.fallbackLabel(pkg), isSystem = false, isInstalledPackage = false)) }
    LaunchedEffect(pkg) { info = withContext(Dispatchers.IO) { vm.app.apps.byKey(pkg) } }
    var tab by rememberSaveable { mutableIntStateOf(0) }
    val blocked = pkg in settings.blockedPackages
    val canBlock = pkg != "unknown"

    Column(Modifier.fillMaxSize()) {
        VigilTopBar(info.label, nav)
        LazyColumn {
            item {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    AppIcon(pkg, info.label, 48.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(info.label, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
                        Text(pkg + (info.uid?.let { " · uid $it" } ?: ""), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (info.isSystem) Text("System component", style = MaterialTheme.typography.bodySmall, color = VigilColors.Low)
                    }
                }
            }
            if (canBlock) {
                item {
                    Row(
                        Modifier.fillMaxWidth()
                            .toggleable(value = blocked, role = Role.Switch, onValueChange = { vm.setAppBlocked(pkg, it) })
                            .padding(horizontal = 16.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f).padding(end = 12.dp)) {
                            Text("Block all network access", style = MaterialTheme.typography.bodyLarge)
                            Text(
                                "Connections are refused and DNS lookups sinkholed while inspection runs.",
                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(checked = blocked, onCheckedChange = null)
                    }
                }
            }
            item {
                Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatTile("Destinations", destinations.size.toString(), Modifier.weight(1f))
                    StatTile("Traffic", formatBytes(destinations.sumOf { it.bytes }), Modifier.weight(1f))
                    StatTile("Alerts", alerts.size.toString(), Modifier.weight(1f), accent = if (alerts.isNotEmpty()) VigilColors.Medium else MaterialTheme.colorScheme.primary)
                }
            }
            item {
                TabRow(selectedTabIndex = tab) {
                    listOf("Hosts", "Flows", "DNS", "Alerts").forEachIndexed { i, t ->
                        Tab(tab == i, onClick = { tab = i }, text = { Text(t, maxLines = 1) })
                    }
                }
            }
            when (tab) {
                0 -> {
                    if (destinations.isEmpty()) item { EmptyState("Nothing yet", "No destinations in the last 30 days.") }
                    items(destinations, key = { "d-" + it.destination }) { d ->
                        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(d.destination, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                    color = if (d.blocked == d.flows) VigilColors.Block else MaterialTheme.colorScheme.onSurface)
                                Text("${plural(d.flows, "connection")} · ${formatBytes(d.bytes)} · first ${formatRelative(d.firstSeen)}",
                                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                AsnDatabase.networksLabel(d.asns, d.asnName)?.let {
                                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }
                            }
                            if (d.blocked > 0) Tag("${d.blocked} blocked", VigilColors.Block, filled = true)
                        }
                    }
                }
                1 -> {
                    if (flows.isEmpty()) item { EmptyState("Nothing yet", "No recorded connections.") }
                    items(flows, key = { "f-" + it.id }) { f -> FlowRow(f, info.label) { nav.navigate("flow/${f.id}") } }
                }
                2 -> {
                    if (dns.isEmpty()) item { EmptyState("Nothing yet", "No recorded DNS lookups.") }
                    items(dns, key = { "q-" + it.id }) { d -> DnsRow(d, info.label) }
                }
                else -> {
                    if (alerts.isEmpty()) item { EmptyState("No alerts", "Nothing suspicious recorded for this app.") }
                    items(alerts, key = { "a-" + it.id }) { a ->
                        Row(Modifier.fillMaxWidth().padding(16.dp)) {
                            SeverityDot(a.severity)
                            Spacer(Modifier.width(10.dp))
                            Column {
                                Text(a.message, style = MaterialTheme.typography.bodyMedium)
                                Text(formatRelative(a.ts), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }
            item { SectionTitle(" ") }
        }
    }
}
