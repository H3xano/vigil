package dev.vigil.inspector.ui.screens

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource

import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.ui.FeedWork
import dev.vigil.inspector.vpn.ServiceState
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.UiText
import dev.vigil.inspector.ui.asString
import dev.vigil.inspector.ui.components.AppIcon
import dev.vigil.inspector.ui.components.EmptyState
import dev.vigil.inspector.ui.components.ErrorCard
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.components.StatTile
import dev.vigil.inspector.ui.formatBytes
import dev.vigil.inspector.ui.formatCount
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.R
import dev.vigil.inspector.ui.theme.VigilColors
import dev.vigil.inspector.vpn.VpnStatus
import dev.vigil.inspector.ui.startActivitySafely

@Composable
fun DashboardScreen(vm: MainViewModel, nav: NavController, onStart: () -> Unit, onStop: () -> Unit) {
    val status by vm.status.collectAsStateWithLifecycle()
    val totals by vm.totals24h.collectAsStateWithLifecycle()
    val dnsCount by vm.dnsCount24h.collectAsStateWithLifecycle()
    val dnsBlocked by vm.dnsBlocked24h.collectAsStateWithLifecycle()
    val unseen by vm.unseenAlerts.collectAsStateWithLifecycle()
    val topApps by vm.topApps.collectAsStateWithLifecycle()
    val topBlocked by vm.topBlocked.collectAsStateWithLifecycle()
    val topTrackers by vm.topTrackerCompanies.collectAsStateWithLifecycle()
    val network by vm.network.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val feeds by vm.feeds.collectAsStateWithLifecycle()
    val feedWork by vm.feedWork.collectAsStateWithLifecycle()
    val configError by vm.configError.collectAsStateWithLifecycle()
    val upstreamWarning by ServiceState.upstreamWarning.collectAsStateWithLifecycle()
    val loadProblem by vm.app.settings.loadProblem.collectAsStateWithLifecycle()
    val usageAccess = usageAccessGranted(vm)
    // Per-second stats and throughput are read inside StatusCard only, so
    // they do not recompose the whole Overview.
    val shownApps = remember(topApps) { topApps.take(6) }
    val maxBytes = remember(topApps) { (topApps.maxOfOrNull { it.tx + it.rx } ?: 1L).coerceAtLeast(1L) }
    val missing = remember(feeds) { feeds.filter { it.enabled && it.lastUpdated == null } }
    val label = rememberAppLabels(vm, shownApps.map { it.pkg })
    val context = LocalContext.current
    var blockedSheet by rememberSaveable { mutableStateOf<String?>(null) }

    val running = status is VpnStatus.Running
    LazyColumn(Modifier.fillMaxSize().statusBarsPadding()) {
        item {
            Text(
                stringResource(R.string.app_name),
                Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
            )
        }
        item { StatusCard(vm, status, onStart, onStop) }

        // Actionable warnings.
        configError?.let { msg ->
            item { ConfigErrorCard(msg) { vm.dismissConfigError() } }
        }
        loadProblem?.let { msg ->
            item { Warning(
                    stringResource(R.string.dashboard_settings_unreadable_title), msg.asString(), stringResource(R.string.dashboard_settings_unreadable_action),
                ) { vm.app.settings.acknowledgeLoadProblem() } }
        }
        upstreamWarning?.let { msg ->
            item { Warning(stringResource(R.string.dashboard_upstream_warning_title), msg, stringResource(R.string.dashboard_open_settings)) { nav.navigate("upstream") } }
        }
        network.privateDnsStrictHost?.let { host ->
            item {
                Warning(
                    stringResource(R.string.dashboard_private_dns_title, host),
                    // Separate sentences, each translated whole.
                    listOfNotNull(
                        stringResource(R.string.dashboard_private_dns_body),
                        if (settings.encryptedDns.enabled) {
                            stringResource(R.string.dashboard_private_dns_encrypted, settings.encryptedDns.summary().asString())
                        } else {
                            stringResource(R.string.dashboard_private_dns_plain)
                        },
                        if (settings.blockEncryptedDns) stringResource(R.string.dashboard_private_dns_blocked) else null,
                    ).joinToString(" "),
                    stringResource(R.string.dashboard_open_settings),
                ) { context.startActivitySafely(Intent(Settings.ACTION_WIRELESS_SETTINGS)) }
            }
        }
        if (!usageAccess) {
            item {
                Warning(
                    stringResource(R.string.dashboard_usage_access_title),
                    stringResource(R.string.dashboard_usage_access_body),
                    stringResource(R.string.dashboard_usage_access_action),
                ) { context.startActivitySafely(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) }
            }
        }
        if (missing.isNotEmpty()) {
            item {
                Warning(
                    pluralStringResource(R.plurals.dashboard_feeds_missing_title, missing.size, missing.size),
                    when (feedWork) {
                        FeedWork.RUNNING -> stringResource(R.string.dashboard_feeds_downloading)
                        FeedWork.WAITING -> stringResource(R.string.dashboard_feeds_waiting)
                        FeedWork.IDLE -> missing.firstNotNullOfOrNull { it.lastError }?.let { stringResource(R.string.dashboard_feeds_last_error, it) }
                            ?: stringResource(R.string.dashboard_feeds_automatic)
                    },
                    stringResource(R.string.dashboard_feeds_update_now),
                    busy = feedWork != FeedWork.IDLE,
                ) {
                    vm.refreshFeeds()
                    vm.showMessage(UiText.of(R.string.dashboard_feeds_updating))
                }
            }
        }

        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SectionTitle(stringResource(R.string.dashboard_last_24_hours))
                HelpIcon(stringResource(R.string.dashboard_sinkholed), Glossary.SINKHOLED)
            }
        }
        item {
            Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatTile(
                        stringResource(R.string.dashboard_tile_connections), formatCount(totals.flows), Modifier.weight(1f), caption = "${formatBytes(totals.rx)} ↓  ${formatBytes(totals.tx)} ↑",
                        onClick = {
                            vm.clearActivityFilters()
                            vm.activityTab.value = 0
                            nav.navigateTab("activity")
                        },
                    )
                    StatTile(
                        stringResource(R.string.dashboard_tile_dns), formatCount(dnsCount), Modifier.weight(1f),
                        caption = pluralStringResource(R.plurals.dashboard_tile_dns_sinkholed, quantity(dnsBlocked), formatCount(dnsBlocked)),
                        onClick = {
                            vm.clearActivityFilters()
                            vm.activityTab.value = 1
                            nav.navigateTab("activity")
                        },
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatTile(
                        stringResource(R.string.dashboard_tile_blocked), formatCount(totals.blocked + dnsBlocked), Modifier.weight(1f), accent = VigilColors.Block,
                        caption = listOf(
                            pluralStringResource(R.plurals.activity_count_connections, quantity(totals.blocked), formatCount(totals.blocked)),
                            pluralStringResource(R.plurals.activity_count_lookups, quantity(dnsBlocked), formatCount(dnsBlocked)),
                        ).joinToString(" · "),
                        onClick = {
                            // Both Activity tabs show only blocked entries; open the one that has any.
                            vm.showBlockedActivity(preferDns = totals.blocked == 0L && dnsBlocked > 0)
                            nav.navigateTab("activity")
                        },
                    )
                    StatTile(
                        stringResource(R.string.dashboard_tile_unread_alerts), unseen.toString(), Modifier.weight(1f),
                        accent = if (unseen > 0) VigilColors.Medium else MaterialTheme.colorScheme.primary,
                        onClick = { nav.navigateTab("alerts") },
                    )
                }
            }
        }

        item {
            ListItem(
                headlineContent = { Text(stringResource(R.string.dashboard_health_check_title)) },
                supportingContent = { Text(stringResource(R.string.dashboard_health_check_body)) },
                modifier = Modifier.fillMaxWidth().clickable { nav.navigate("health") },
            )
        }

        item { SectionTitle(stringResource(R.string.dashboard_top_apps)) }
        if (topApps.isEmpty()) {
            item {
                EmptyState(
                    stringResource(R.string.dashboard_no_traffic_title),
                    stringResource(if (running) R.string.dashboard_no_traffic_running else R.string.dashboard_no_traffic_stopped),
                )
            }
        }
        items(shownApps, key = { it.pkg }) { a ->
            val name = label(a.pkg)
            Row(
                Modifier.fillMaxWidth().clickable { nav.openApp(a.pkg) }.padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                AppIcon(a.pkg, name)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Row {
                        Text(name, Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodyLarge)
                        Text(formatBytes(a.tx + a.rx), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    LinearProgressIndicator(
                        progress = { (a.tx + a.rx).toFloat() / maxBytes },
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).height(4.dp),
                        drawStopIndicator = {},
                    )
                    Text(
                        listOfNotNull(
                            pluralStringResource(R.plurals.activity_count_connections, quantity(a.flows), a.flows.toString()),
                            pluralStringResource(R.plurals.apps_count_destinations, quantity(a.destinations), a.destinations.toString()),
                            if (a.blocked > 0) pluralStringResource(R.plurals.activity_count_blocked, quantity(a.blocked), a.blocked.toString()) else null,
                        ).joinToString(" · "),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        if (topBlocked.isNotEmpty()) {
            item { SectionTitle(stringResource(R.string.dashboard_top_blocked)) }
            items(topBlocked, key = { "b-" + it.name }) { b ->
                Row(
                    Modifier.fillMaxWidth().clickable(onClickLabel = stringResource(R.string.dashboard_why_blocked)) { blockedSheet = b.name }
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                ) {
                    Text(b.name, Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(pluralStringResource(R.plurals.dashboard_blocked_hits, quantity(b.hits), b.hits), color = VigilColors.Block)
                }
            }
        }
        topTrackerCompanies(topTrackers, nav)
        item { Spacer(Modifier.height(24.dp)) }
    }
    blockedSheet?.let { name -> DomainSheet(name, vm, nav, onDismiss = { blockedSheet = null }, loadReason = true) }
}

/** The inspection switch with live counters; the only reader of the per-second stats. */
@Composable
private fun StatusCard(vm: MainViewModel, status: VpnStatus, onStart: () -> Unit, onStop: () -> Unit) {
    val running = status is VpnStatus.Running
    Card(
        Modifier.fillMaxWidth().padding(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (running) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerHigh,
        ),
    ) {
        val on = running || status == VpnStatus.Starting
        // One focus target: the whole row toggles inspection.
        Row(
            Modifier
                .toggleable(value = on, role = Role.Switch, onValueChange = { if (it) onStart() else onStop() })
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    stringResource(
                        when (status) {
                            is VpnStatus.Running -> R.string.dashboard_status_running
                            VpnStatus.Starting -> R.string.dashboard_status_starting
                            is VpnStatus.Failed -> R.string.dashboard_status_failed
                            VpnStatus.Stopped -> R.string.dashboard_status_stopped
                        },
                    ),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                )
                val sub = when (status) {
                    is VpnStatus.Running -> {
                        val stats by vm.stats.collectAsStateWithLifecycle()
                        val throughput by vm.throughput.collectAsStateWithLifecycle()
                        stats?.let {
                            val active = it.tcpActive + it.udpActive
                            pluralStringResource(
                                R.plurals.dashboard_status_live, quantity(active), active,
                                formatBytes(throughput.downBps), formatBytes(throughput.upBps),
                            )
                        } ?: stringResource(R.string.dashboard_status_since, formatRelative(status.since))
                    }
                    is VpnStatus.Failed -> status.message
                    else -> stringResource(R.string.dashboard_status_hint)
                }
                Text(
                    sub,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (status is VpnStatus.Failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(checked = on, onCheckedChange = null)
        }
    }
}

@Composable
internal fun Warning(title: String, body: String, action: String, busy: Boolean = false, onAction: () -> Unit) {
    Card(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = VigilColors.Low.copy(alpha = 0.12f)),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(body, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
            OutlinedButton(onClick = onAction, enabled = !busy, modifier = Modifier.padding(top = 8.dp)) { Text(action) }
        }
    }
}

@Composable
fun ConfigErrorCard(message: String, onDismiss: () -> Unit) = ErrorCard(
    stringResource(R.string.dashboard_config_error_title),
    stringResource(R.string.dashboard_config_error_body, message),
    onDismiss,
)

/** A count as a plural quantity (clamped to Int). */
internal fun quantity(n: Long): Int = n.coerceIn(0, Int.MAX_VALUE.toLong()).toInt()

/** Navigates to a bottom-bar destination the same way the navigation bar does. */
fun NavController.navigateTab(route: String) = navigate(route) {
    popUpTo("dashboard") { saveState = true }
    launchSingleTop = true
}
