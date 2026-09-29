package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.SecondaryTabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.annotation.PluralsRes
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.foundation.background
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.R
import dev.vigil.inspector.data.AsnDatabase
import dev.vigil.inspector.data.DnsEntity
import dev.vigil.inspector.data.FlowEntity
import dev.vigil.inspector.data.PathFilter
import dev.vigil.inspector.data.PathLabels
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.AppIcon
import dev.vigil.inspector.ui.components.BlockedTag
import dev.vigil.inspector.ui.components.EmptyState
import dev.vigil.inspector.ui.components.Tag
import dev.vigil.inspector.ui.formatBytes
import dev.vigil.inspector.ui.formatTime
import dev.vigil.inspector.ui.theme.VigilColors

@Composable
fun ActivityScreen(vm: MainViewModel, nav: NavController) {
    val tab by vm.activityTab.collectAsStateWithLifecycle()
    val paused by vm.activityPaused.collectAsStateWithLifecycle()
    Column(Modifier.fillMaxSize()) {
        VigilTopBar(stringResource(R.string.activity_title)) {
            // Paused: the lists stop following new traffic so rows do not move while reading.
            FilterChip(
                selected = paused,
                onClick = { vm.activityPaused.value = !paused },
                label = { Text(stringResource(if (paused) R.string.activity_paused else R.string.activity_live)) },
                leadingIcon = if (paused) {
                    { Icon(Icons.Default.PlayArrow, stringResource(R.string.activity_resume), Modifier.size(FilterChipDefaults.IconSize)) }
                } else {
                    null
                },
                modifier = Modifier.padding(end = 8.dp),
            )
        }
        SecondaryTabRow(selectedTabIndex = tab) {
            Tab(tab == 0, onClick = { vm.activityTab.value = 0 }, text = { Text(stringResource(R.string.activity_tab_connections)) })
            Tab(tab == 1, onClick = { vm.activityTab.value = 1 }, text = { Text("DNS") })
        }
        if (tab == 0) FlowList(vm, nav) else DnsList(vm, nav)
    }
}

/** Restricts both Activity lists to one app; the menu lists the apps seen recently. */
@Composable
private fun AppFilterChip(vm: MainViewModel) {
    val selected by vm.activityApp.collectAsStateWithLifecycle()
    val apps by vm.appsWeek.collectAsStateWithLifecycle()
    var open by remember { mutableStateOf(false) }
    val label = rememberAppLabels(vm, apps.map { it.pkg } + listOfNotNull(selected))
    Box {
        val current = selected
        FilterChip(
            selected = current != null,
            onClick = { if (current != null) vm.activityApp.value = null else open = true },
            label = {
                Text(if (current != null) label(current) else stringResource(R.string.activity_filter_app), maxLines = 1, overflow = TextOverflow.Ellipsis)
            },
            trailingIcon = if (current != null) {
                { Icon(Icons.Default.Close, stringResource(R.string.activity_filter_all_apps), Modifier.size(FilterChipDefaults.IconSize)) }
            } else {
                null
            },
        )
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            if (apps.isEmpty()) DropdownMenuItem(text = { Text(stringResource(R.string.activity_no_apps)) }, onClick = { open = false }, enabled = false)
            apps.sortedBy { label(it.pkg).lowercase() }.forEach { a ->
                DropdownMenuItem(
                    text = { Text(label(a.pkg), maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    leadingIcon = { AppIcon(a.pkg, label(a.pkg), 24.dp) },
                    onClick = {
                        vm.activityApp.value = a.pkg
                        open = false
                    },
                )
            }
        }
    }
}

@Composable
private fun SearchBar(query: String, onQuery: (String) -> Unit, blockedOnly: Boolean, onBlockedOnly: (Boolean) -> Unit, hint: String) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(
            value = query,
            onValueChange = onQuery,
            modifier = Modifier.weight(1f),
            singleLine = true,
            placeholder = { Text(hint) },
            leadingIcon = { Icon(Icons.Default.Search, null) },
        )
        Spacer(Modifier.width(8.dp))
        FilterChip(selected = blockedOnly, onClick = { onBlockedOnly(!blockedOnly) }, label = { Text(stringResource(R.string.state_blocked)) })
    }
}

@Composable
private fun FlowList(vm: MainViewModel, nav: NavController) {
    val flows by vm.flows.collectAsStateWithLifecycle()
    val query by vm.flowQuery.collectAsStateWithLifecycle()
    val blockedOnly by vm.flowBlockedOnly.collectAsStateWithLifecycle()
    val path by vm.flowPath.collectAsStateWithLifecycle()
    SearchBar(query, { vm.flowQuery.value = it }, blockedOnly, { vm.flowBlockedOnly.value = it }, stringResource(R.string.activity_search_connections))
    val app by vm.activityApp.collectAsStateWithLifecycle()
    Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        AppFilterChip(vm)
        for ((value, text) in listOf(PathFilter.TUNNEL to R.string.activity_path_tunnel, PathFilter.DIRECT to R.string.activity_path_direct)) {
            FilterChip(
                selected = path == value,
                onClick = { vm.flowPath.value = if (path == value) PathFilter.ALL else value },
                label = { Text(stringResource(text)) },
            )
        }
    }
    if (flows.isEmpty()) {
        EmptyState(
            stringResource(R.string.activity_no_connections),
            stringResource(
                if (query.isNotEmpty() || blockedOnly || path != PathFilter.ALL || app != null) R.string.activity_no_match else R.string.activity_no_connections_body,
            ),
        )
        return
    }
    val label = rememberAppLabels(vm, flows.map { it.pkg }.distinct())
    LazyColumn {
        items(flows, key = { it.id }) { f ->
            FlowRow(f, label(f.pkg)) { nav.navigate("flow/${f.id}") }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
        if (flows.size >= MainViewModel.ACTIVITY_LIMIT) item { LimitNote(R.plurals.activity_limit_connections) }
    }
}

@Composable
fun FlowRow(f: FlowEntity, appLabel: String, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        AppIcon(f.pkg, appLabel, 32.dp)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (f.isActive) {
                    val activeDescription = stringResource(R.string.activity_active_connection)
                    // Not colour alone: the dot is announced, and its presence is the signal.
                    Box(Modifier.size(7.dp).clip(CircleShape).background(VigilColors.Allow).semantics { contentDescription = activeDescription })
                    Spacer(Modifier.width(6.dp))
                }
                Text(
                    f.domain ?: "${f.dstIp}:${f.dstPort}",
                    style = MaterialTheme.typography.bodyLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    color = if (f.isBlocked) VigilColors.Block else MaterialTheme.colorScheme.onSurface,
                )
            }
            Text(
                listOfNotNull(appLabel, formatTime(f.ts), AsnDatabase.label(f.asn, f.asnName)).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.padding(top = 3.dp)) {
                if (f.isBlocked) BlockedTag()
                TrackerTag(f.domain)
                Tag((f.appProto ?: f.proto).uppercase())
                if (f.dstPort != 443 && f.dstPort != 80) Tag(":${f.dstPort}")
                if (PathLabels.isTunnelled(f.via)) PathLabels.via(f.via)?.let { Tag(it, VigilColors.Info, filled = true) }
                if (f.background == true) Tag(stringResource(R.string.activity_tag_background), VigilColors.Low, filled = true)
                f.tagList.forEach { t ->
                    when (t) {
                        "encrypted_dns" -> Tag("DoH/DoT", VigilColors.Medium, filled = true)
                        "plaintext_http" -> Tag(stringResource(R.string.activity_tag_cleartext), VigilColors.Low, filled = true)
                        "ech" -> Tag("ECH", VigilColors.Info, filled = true)
                    }
                }
            }
        }
        if (!f.isBlocked) {
            Column(horizontalAlignment = Alignment.End) {
                Text("↓ ${formatBytes(f.rx)}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                Text("↑ ${formatBytes(f.tx)}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun DnsList(vm: MainViewModel, nav: NavController) {
    val rows by vm.dns.collectAsStateWithLifecycle()
    val query by vm.dnsQuery.collectAsStateWithLifecycle()
    val blockedOnly by vm.dnsBlockedOnly.collectAsStateWithLifecycle()
    val app by vm.activityApp.collectAsStateWithLifecycle()
    // The row whose sheet is open (its id survives rotation; the row itself is looked up).
    var sheetFor by rememberSaveable { mutableStateOf<Long?>(null) }
    SearchBar(query, { vm.dnsQuery.value = it }, blockedOnly, { vm.dnsBlockedOnly.value = it }, stringResource(R.string.activity_search_lookups))
    Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 4.dp)) { AppFilterChip(vm) }
    if (rows.isEmpty()) {
        EmptyState(
            stringResource(R.string.activity_no_lookups),
            stringResource(if (query.isNotEmpty() || blockedOnly || app != null) R.string.activity_no_match else R.string.activity_no_lookups_body),
        )
        return
    }
    val label = rememberAppLabels(vm, rows.map { it.pkg }.distinct())
    LazyColumn {
        items(rows, key = { it.id }) { d ->
            DnsRow(d, label(d.pkg)) { sheetFor = d.id }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        }
        if (rows.size >= MainViewModel.ACTIVITY_LIMIT) item { LimitNote(R.plurals.activity_limit_lookups) }
    }
    sheetFor?.let { id -> rows.firstOrNull { it.id == id } }?.let { d ->
        DomainSheet(
            d.qname, vm, nav, onDismiss = { sheetFor = null }, pkg = d.pkg,
            knownReason = d.reason.takeIf { d.isBlocked }, loadReason = false, showLookups = query != d.qname,
        )
    }
}

@Composable
private fun LimitNote(@PluralsRes text: Int) {
    Text(
        pluralStringResource(text, MainViewModel.ACTIVITY_LIMIT, MainViewModel.ACTIVITY_LIMIT),
        Modifier.fillMaxWidth().padding(16.dp),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
fun DnsRow(d: DnsEntity, appLabel: String, onClick: (() -> Unit)? = null) {
    val clickable = if (onClick != null) Modifier.clickable(onClickLabel = stringResource(R.string.activity_block_or_allow), onClick = onClick)
 else Modifier
    Row(Modifier.fillMaxWidth().then(clickable).padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        AppIcon(d.pkg, appLabel, 32.dp)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                d.qname,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                color = if (d.isBlocked) VigilColors.Block else MaterialTheme.colorScheme.onSurface,
            )
            Text("$appLabel · ${formatTime(d.ts)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
            TrackerTag(d.qname)
            if (d.answers.isNotEmpty()) {
                Text(d.answers, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (d.isBlocked && d.reason != null) {
                Text(d.reason, style = MaterialTheme.typography.bodySmall, color = VigilColors.Block, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        Column(horizontalAlignment = Alignment.End) {
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                if (d.isBlocked) BlockedTag()
                when (d.upstream) {
                    "doh", "dot" -> Tag(PathLabels.dnsUpstream(d.upstream)!!, VigilColors.Allow, filled = true)
                    "tcp" -> Tag("TCP")
                }
                Tag(d.qtype)
            }
            if (d.server != "virtual") Text("→ ${d.server}", style = MaterialTheme.typography.labelSmall, color = VigilColors.Medium)
            else if (!d.isBlocked) Text("${d.latencyMs} ms", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
