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
import dev.vigil.inspector.ui.components.AppIcon
import dev.vigil.inspector.ui.components.EmptyState
import dev.vigil.inspector.ui.components.ErrorCard
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.components.StatTile
import dev.vigil.inspector.ui.formatBytes
import dev.vigil.inspector.ui.formatCount
import dev.vigil.inspector.ui.formatRelative
import dev.vigil.inspector.ui.plural
import dev.vigil.inspector.ui.theme.VigilColors
import dev.vigil.inspector.vpn.VpnStatus

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
                "vigil",
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
            item { Warning("Settings could not be read", msg, "Dismiss and start anyway") { vm.app.settings.acknowledgeLoadProblem() } }
        }
        upstreamWarning?.let { msg ->
            item { Warning("Route through VPN / proxy", msg, "Open settings") { nav.navigate("upstream") } }
        }
        network.privateDnsStrictHost?.let { host ->
            item {
                Warning(
                    "Private DNS is set to $host",
                    "Android encrypts DNS lookups before vigil can see them, so domain names come only from TLS/QUIC " +
                        "handshakes. " +
                        if (settings.encryptedDns.enabled) {
                            "vigil already sends lookups encrypted (${settings.encryptedDns.summary()}), so you can set " +
                                "Private DNS to Off or Automatic for full DNS inspection without losing privacy."
                        } else {
                            "Set Private DNS to Automatic or Off for full DNS inspection, and turn on Encrypted DNS in " +
                                "vigil's settings to keep lookups private."
                        } +
                        if (settings.blockEncryptedDns) " With “Block encrypted DNS” enabled, lookups will fail." else "",
                    "Open settings",
                ) { context.startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS)) }
            }
        }
        if (!usageAccess) {
            item {
                Warning(
                    "Background detection is off",
                    "Grant usage access so vigil can tell traffic from apps you are using apart from background traffic.",
                    "Grant",
                ) { context.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) }
            }
        }
        if (missing.isNotEmpty()) {
            item {
                Warning(
                    "${missing.size} threat feed${if (missing.size > 1) "s" else ""} not downloaded yet",
                    when (feedWork) {
                        FeedWork.RUNNING -> "Downloading feeds…"
                        FeedWork.WAITING -> "Feeds will download as soon as the device is online."
                        FeedWork.IDLE -> missing.firstNotNullOfOrNull { it.lastError }?.let { "Last error: $it" }
                            ?: "Feeds download automatically when the device is online."
                    },
                    "Update now",
                    busy = feedWork != FeedWork.IDLE,
                ) {
                    vm.refreshFeeds()
                    vm.showMessage("Updating threat feeds…")
                }
            }
        }

        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SectionTitle("Last 24 hours")
                HelpIcon("Sinkholed", Glossary.SINKHOLED)
            }
        }
        item {
            Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatTile(
                        "Connections", formatCount(totals.flows), Modifier.weight(1f), caption = "${formatBytes(totals.rx)} ↓  ${formatBytes(totals.tx)} ↑",
                        onClick = {
                            vm.clearActivityFilters()
                            vm.activityTab.value = 0
                            nav.navigateTab("activity")
                        },
                    )
                    StatTile(
                        "DNS lookups", formatCount(dnsCount), Modifier.weight(1f), caption = "${formatCount(dnsBlocked)} sinkholed",
                        onClick = {
                            vm.clearActivityFilters()
                            vm.activityTab.value = 1
                            nav.navigateTab("activity")
                        },
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatTile(
                        "Blocked", formatCount(totals.blocked + dnsBlocked), Modifier.weight(1f), accent = VigilColors.Block,
                        caption = "${formatCount(totals.blocked)} connections · ${formatCount(dnsBlocked)} lookups",
                        onClick = {
                            // Both Activity tabs show only blocked entries; open the one that has any.
                            vm.showBlockedActivity(preferDns = totals.blocked == 0L && dnsBlocked > 0)
                            nav.navigateTab("activity")
                        },
                    )
                    StatTile(
                        "Unread alerts", unseen.toString(), Modifier.weight(1f),
                        accent = if (unseen > 0) VigilColors.Medium else MaterialTheme.colorScheme.primary,
                        onClick = { nav.navigateTab("alerts") },
                    )
                }
            }
        }

        item { SectionTitle("Most active apps") }
        if (topApps.isEmpty()) {
            item { EmptyState("No traffic yet", if (running) "Connections will appear here as apps use the network." else "Start inspection to see which apps talk to whom.") }
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
                        "${plural(a.flows, "connection")} · ${plural(a.destinations, "destination")}" + if (a.blocked > 0) " · ${a.blocked} blocked" else "",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        if (topBlocked.isNotEmpty()) {
            item { SectionTitle("Most blocked domains") }
            items(topBlocked, key = { "b-" + it.name }) { b ->
                Row(
                    Modifier.fillMaxWidth().clickable(onClickLabel = "Why blocked") { blockedSheet = b.name }
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                ) {
                    Text(b.name, Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("${b.hits}×", color = VigilColors.Block)
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
                    when (status) {
                        is VpnStatus.Running -> "Inspecting traffic"
                        VpnStatus.Starting -> "Starting…"
                        is VpnStatus.Failed -> "Not running"
                        VpnStatus.Stopped -> "Inspection is off"
                    },
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                )
                val sub = when (status) {
                    is VpnStatus.Running -> {
                        val stats by vm.stats.collectAsStateWithLifecycle()
                        val throughput by vm.throughput.collectAsStateWithLifecycle()
                        stats?.let {
                            "${it.tcpActive + it.udpActive} active · ↓ ${formatBytes(throughput.downBps)}/s ↑ ${formatBytes(throughput.upBps)}/s"
                        } ?: "Since ${formatRelative(status.since)}"
                    }
                    is VpnStatus.Failed -> status.message
                    else -> "Tap the switch to start the on-device inspector"
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
    "Settings change not applied",
    "The inspector rejected the new settings and keeps running with the previous ones: $message",
    onDismiss,
)

/** Navigates to a bottom-bar destination the same way the navigation bar does. */
fun NavController.navigateTab(route: String) = navigate(route) {
    popUpTo("dashboard") { saveState = true }
    launchSingleTop = true
}
