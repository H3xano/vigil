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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.TextButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.SecondaryTabRow
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
import androidx.compose.ui.platform.LocalContext
import android.content.Intent
import android.provider.Settings as AndroidSettings
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.R
import dev.vigil.inspector.data.AppDomainRule

import dev.vigil.inspector.data.AppInfo
import dev.vigil.inspector.data.AppRule
import dev.vigil.inspector.data.AppRules
import dev.vigil.inspector.data.AsnDatabase
import dev.vigil.inspector.ui.DomainNames
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
import dev.vigil.inspector.ui.AlertText
import dev.vigil.inspector.ui.asString
import dev.vigil.inspector.ui.theme.VigilColors

@Composable
fun AppsScreen(vm: MainViewModel, nav: NavController) {
    val apps by vm.appsWeek.collectAsStateWithLifecycle()
    val days by vm.appWindowDays.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val trackerCounts by vm.appTrackerCounts.collectAsStateWithLifecycle()
    var query by rememberSaveable { mutableStateOf("") }
    val label = rememberAppLabels(vm, apps.map { it.pkg })
    val filtered = apps.filter { query.isBlank() || label(it.pkg).contains(query, true) || it.pkg.contains(query, true) }
    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.apps_title, windowLabel(days)))
        OutlinedTextField(
            value = query, onValueChange = { query = it }, singleLine = true, placeholder = { Text(stringResource(R.string.apps_search)) },
            leadingIcon = { Icon(Icons.Default.Search, null) },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        )
        if (apps.isEmpty()) {
            EmptyState(stringResource(R.string.apps_empty_title), stringResource(R.string.apps_empty_body))
            return@Column
        }
        if (filtered.isEmpty()) {
            EmptyState(stringResource(R.string.apps_no_matches), pluralStringResource(R.plurals.apps_no_matches_body, days, days, query.trim()))
            return@Column
        }
        LazyColumn {
            items(filtered, key = { it.pkg }) { a ->
                val name = label(a.pkg)
                Row(
                    Modifier.fillMaxWidth().clickable { nav.openApp(a.pkg) }.padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    AppIcon(a.pkg, name, 40.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            listOf(
                                formatBytes(a.tx + a.rx),
                                pluralStringResource(R.plurals.apps_count_destinations, quantity(a.destinations), a.destinations.toString()),
                                formatRelative(a.lastSeen),
                            ).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                        val blockedAlways = a.pkg in settings.blockedPackages
                        trackerCounts[a.pkg]?.let { Tag(pluralStringResource(R.plurals.apps_count_trackers, it, it.toString()), VigilColors.Medium) }
                        if (!blockedAlways && settings.appRules[a.pkg]?.isEmpty == false) Tag(stringResource(R.string.apps_tag_rules), VigilColors.Medium)
                        if (!blockedAlways && a.blocked > 0) {
                            Tag(pluralStringResource(R.plurals.activity_count_blocked, quantity(a.blocked), formatCount(a.blocked)), VigilColors.Block, filled = true)
                        }
                        if (a.pkg != "unknown") {
                            // NetGuard-style one-tap block of all network access.
                            IconButton(onClick = { vm.setAppBlocked(a.pkg, !blockedAlways) }) {
                                Icon(
                                    Icons.Default.Lock,
                                    stringResource(if (blockedAlways) R.string.apps_allow_network else R.string.apps_block_network, name),
                                    tint = if (blockedAlways) VigilColors.Block else MaterialTheme.colorScheme.outlineVariant,
                                )
                            }
                        }
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
    val days by vm.appWindowDays.collectAsStateWithLifecycle()
    // Cached per app in the view model: coming back shows the last data at
    // once (and the list keeps its scroll position) while it refreshes.
    val data = remember(pkg) { vm.appDetail(pkg) }
    val destinationsOrNull by data.destinations.collectAsStateWithLifecycle()
    val flowsOrNull by data.flows.collectAsStateWithLifecycle()
    val dnsOrNull by data.dns.collectAsStateWithLifecycle()
    val alertsOrNull by data.alerts.collectAsStateWithLifecycle()
    val destinations = destinationsOrNull.orEmpty()
    val flows = flowsOrNull.orEmpty()
    val dns = dnsOrNull.orEmpty()
    val alerts = alertsOrNull.orEmpty()
    var dnsSheet by rememberSaveable { mutableStateOf<Long?>(null) }
    var hostSheet by rememberSaveable { mutableStateOf<String?>(null) }
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
                        Text(info.uid?.let { stringResource(R.string.apps_package_uid, pkg, it) } ?: pkg, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (info.isSystem) Text(stringResource(R.string.apps_system_component), style = MaterialTheme.typography.bodySmall, color = VigilColors.Low)
                    }
                }
            }
            if (canBlock) {
                item { NetworkAccessCard(vm, pkg, info.label, blocked, AppRules.rule(settings, pkg)) }
                item { AppDomainRulesCard(vm, pkg, info.label, AppRules.domainRules(settings, pkg)) }
            }
            item {
                Column(Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) {
                    ExportAppPacketsButton(vm, nav, info.uid, info.label)
                }
            }
            item {
                Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatTile(stringResource(R.string.apps_tile_destinations), destinations.size.toString(), Modifier.weight(1f), caption = windowLabel(days))
                    StatTile(stringResource(R.string.apps_tile_traffic), formatBytes(destinations.sumOf { it.bytes }), Modifier.weight(1f), caption = windowLabel(days))
                    StatTile(stringResource(R.string.apps_tile_alerts), alerts.size.toString(), Modifier.weight(1f), accent = if (alerts.isNotEmpty()) VigilColors.Medium else MaterialTheme.colorScheme.primary)
                }
            }
            item { AppTrackersSection(vm, pkg, days) }
            item {
                SecondaryTabRow(selectedTabIndex = tab) {
                    listOf(
                        stringResource(R.string.apps_tab_hosts),
                        stringResource(R.string.apps_tab_flows),
                        "DNS",
                        stringResource(R.string.apps_tab_alerts),
                    ).forEachIndexed { i, t ->
                        Tab(tab == i, onClick = { tab = i }, text = { Text(t, maxLines = 1) })
                    }
                }
            }
            when (tab) {
                0 -> {
                    if (destinationsOrNull?.isEmpty() == true) {
                        item {
                            EmptyState(stringResource(R.string.common_nothing_yet), pluralStringResource(R.plurals.apps_no_destinations, days, days))
                        }
                    }
                    items(destinations, key = { "d-" + it.destination }) { d ->
                        val named = DomainNames.isDomainName(d.destination)
                        Row(
                            Modifier.fillMaxWidth()
                                .then(if (named && canBlock) Modifier.clickable { hostSheet = d.destination } else Modifier)
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(d.destination, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                    color = if (d.blocked == d.flows) VigilColors.Block else MaterialTheme.colorScheme.onSurface)
                                Text(
                                    listOf(
                                        pluralStringResource(R.plurals.activity_count_connections, quantity(d.flows), d.flows.toString()),
                                        formatBytes(d.bytes),
                                        stringResource(R.string.apps_first_seen, formatRelative(d.firstSeen)),
                                    ).joinToString(" · "),
                                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                AsnDatabase.networksLabel(d.asns, d.asnName)?.let {
                                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }
                            }
                            AppRules.matchingDomainRule(settings, pkg, d.destination)?.let { r ->
                                Tag(stringResource(if (r.isBlock) R.string.apps_tag_blocked_for_app else R.string.apps_tag_allowed_for_app), if (r.isBlock) VigilColors.Block else VigilColors.Allow)
                                Spacer(Modifier.width(4.dp))
                            }
                            if (d.blocked > 0) Tag(pluralStringResource(R.plurals.activity_count_blocked, quantity(d.blocked), d.blocked.toString()), VigilColors.Block, filled = true)
                        }
                    }
                }
                1 -> {
                    if (flowsOrNull?.isEmpty() == true) item { EmptyState(stringResource(R.string.common_nothing_yet), stringResource(R.string.apps_no_connections)) }
                    items(flows, key = { "f-" + it.id }) { f -> FlowRow(f, info.label) { nav.navigate("flow/${f.id}") } }
                }
                2 -> {
                    if (dnsOrNull?.isEmpty() == true) item { EmptyState(stringResource(R.string.common_nothing_yet), stringResource(R.string.apps_no_lookups)) }
                    items(dns, key = { "q-" + it.id }) { d -> DnsRow(d, info.label) { dnsSheet = d.id } }
                }
                else -> {
                    if (alertsOrNull?.isEmpty() == true) item { EmptyState(stringResource(R.string.apps_no_alerts), stringResource(R.string.apps_no_alerts_body)) }
                    items(alerts, key = { "a-" + it.id }) { a ->
                        Row(Modifier.fillMaxWidth().padding(16.dp)) {
                            SeverityDot(a.severity)
                            Spacer(Modifier.width(10.dp))
                            Column {
                                Text(AlertText.message(a, info.label).asString(), style = MaterialTheme.typography.bodyMedium)
                                Text(formatRelative(a.ts), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }
            item { SectionTitle(" ") }
        }
    }
    dnsSheet?.let { id -> dns.firstOrNull { it.id == id } }?.let { d ->
        DomainSheet(d.qname, vm, nav, onDismiss = { dnsSheet = null }, pkg = pkg, knownReason = d.reason.takeIf { d.isBlocked }, loadReason = false)
    }
    hostSheet?.let { host ->
        DomainSheet(host, vm, nav, onDismiss = { hostSheet = null }, pkg = pkg, loadReason = true)
    }
}

/**
 * When the app may use the network: blocked always, or on Wi-Fi, on mobile
 * data, in the background or with the screen off (like NetGuard). The
 * engine applies the conditions to new and open connections alike.
 */
@Composable
private fun NetworkAccessCard(vm: MainViewModel, pkg: String, label: String, blockedAlways: Boolean, rule: AppRule) {
    val context = LocalContext.current
    val usageAccess = usageAccessGranted(vm)
    Card(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
        Column(Modifier.padding(vertical = 8.dp)) {
            Text(stringResource(R.string.apps_network_access), Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.titleMedium)
            RuleSwitch(stringResource(R.string.apps_block_always), stringResource(R.string.apps_block_always_detail), blockedAlways) {
                vm.setAppBlocked(pkg, it)
            }
            val conditional = if (blockedAlways) stringResource(R.string.apps_conditions_overridden) else null
            RuleSwitch(stringResource(R.string.apps_block_wifi), conditional, rule.blockWifi, enabled = !blockedAlways) {
                vm.setAppRule(pkg, rule.copy(blockWifi = it))
            }
            RuleSwitch(stringResource(R.string.apps_block_mobile), conditional, rule.blockCellular, enabled = !blockedAlways) {
                vm.setAppRule(pkg, rule.copy(blockCellular = it))
            }
            RuleSwitch(
                stringResource(R.string.apps_block_background),
                stringResource(R.string.apps_block_background_detail, label),
                rule.blockBackground, enabled = !blockedAlways,
            ) { vm.setAppRule(pkg, rule.copy(blockBackground = it)) }
            if (rule.blockBackground && !usageAccess) {
                Column(Modifier.padding(horizontal = 16.dp)) {
                    Text(
                        stringResource(R.string.apps_usage_access_needed),
                        style = MaterialTheme.typography.bodySmall, color = VigilColors.Medium,
                    )
                    TextButton(onClick = { context.startActivity(Intent(AndroidSettings.ACTION_USAGE_ACCESS_SETTINGS)) }) { Text(stringResource(R.string.apps_grant_usage_access)) }
                }
            }
            RuleSwitch(stringResource(R.string.apps_block_screen_off), null, rule.blockScreenOff, enabled = !blockedAlways) {
                vm.setAppRule(pkg, rule.copy(blockScreenOff = it))
            }
        }
    }
}

@Composable
private fun RuleSwitch(title: String, detail: String?, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth()
            .toggleable(value = checked, enabled = enabled, role = Role.Switch, onValueChange = onChange)
            .padding(horizontal = 16.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(end = 12.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge,
                color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant)
            if (detail != null) {
                Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Switch(checked = checked, onCheckedChange = null, enabled = enabled)
    }
}

/** The app's own domain rules (allow or block a name for this app only), with add and remove. */
@Composable
private fun AppDomainRulesCard(vm: MainViewModel, pkg: String, label: String, rules: List<AppDomainRule>) {
    var input by rememberSaveable(pkg) { mutableStateOf("") }
    val candidate = AppRules.normalize(input)
    val valid = DomainNames.isDomainName(candidate)
    Card(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.apps_rules_title), style = MaterialTheme.typography.titleMedium)
            Text(
                stringResource(R.string.apps_rules_body, label),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            rules.forEach { r ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tag(stringResource(if (r.isBlock) R.string.apps_tag_block else R.string.apps_tag_allow), if (r.isBlock) VigilColors.Block else VigilColors.Allow, filled = true)
                    Spacer(Modifier.width(8.dp))
                    Text(r.domain, Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                    IconButton(onClick = { vm.removeAppDomainRule(pkg, r.domain) }) { Icon(Icons.Default.Delete, stringResource(R.string.apps_remove_rule, r.domain)) }
                }
            }
            OutlinedTextField(
                input, { input = it }, Modifier.fillMaxWidth(), singleLine = true, placeholder = { Text("example.com") },
                isError = input.isNotBlank() && !valid, leadingIcon = { Icon(Icons.Default.Add, null) },
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = valid, onClick = { vm.setAppDomainRule(pkg, label, candidate, AppDomainRule.BLOCK); input = "" }) { Text(stringResource(R.string.common_block)) }
                OutlinedButton(enabled = valid, onClick = { vm.setAppDomainRule(pkg, label, candidate, AppDomainRule.ALLOW); input = "" }) { Text(stringResource(R.string.apps_action_allow)) }
            }
        }
    }
}

/** "last 7 days", "last day". */
@Composable
internal fun windowLabel(days: Int) = pluralStringResource(R.plurals.apps_window, days, days)
