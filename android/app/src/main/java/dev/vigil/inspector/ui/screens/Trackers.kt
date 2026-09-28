package dev.vigil.inspector.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.VigilApp
import dev.vigil.inspector.data.CompanyApps
import dev.vigil.inspector.data.CompanyHits
import dev.vigil.inspector.data.TrackerDatabase
import dev.vigil.inspector.data.TrackerIndex
import dev.vigil.inspector.data.TrackerMatch
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.Field
import dev.vigil.inspector.ui.components.HelpIcon
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.components.Tag
import dev.vigil.inspector.ui.formatCount
import dev.vigil.inspector.ui.plural
import dev.vigil.inspector.ui.theme.VigilColors

/** Explains tracker labels (help icons). */
internal const val TRACKER_HELP =
    "vigil names the company behind a destination from the AdGuard companiesdb tracker database, " +
        "downloaded to the device weekly and looked up locally. Advertising, analytics, telemetry and social " +
        "media trackers are highlighted; CDNs, hosting and other services are labelled but not counted as trackers. " +
        "Labels never block anything: use the tracking and ads feeds or block rules for that. " +
        "Data: ${TrackerDatabase.ATTRIBUTION}."

/** The loaded tracker labels (null when off or not downloaded); rows use it without a view model. */
@Composable
fun rememberTrackerIndex(): TrackerIndex? {
    val app = LocalContext.current.applicationContext as VigilApp
    val index by app.trackers.index.collectAsStateWithLifecycle()
    return index
}

@Composable
private fun rememberTrackerMatch(host: String?): TrackerMatch? {
    val index = rememberTrackerIndex()
    return remember(index, host) { index?.match(host) }
}

/** A small "Google · Advertising" tag for a destination; nothing when the name has no label. */
@Composable
fun TrackerTag(host: String?) {
    val m = rememberTrackerMatch(host) ?: return
    if (m.tracker.isTracking) Tag(TrackerDatabase.label(m.tracker), VigilColors.Medium, filled = true)
    else Tag(TrackerDatabase.label(m.tracker))
}

/** Tracker and company rows for the connection detail. */
@Composable
fun TrackerFields(host: String?) {
    val m = rememberTrackerMatch(host) ?: return
    val t = m.tracker
    Field("Tracker", "${t.name} · ${TrackerDatabase.categoryLabel(t.category)}" + if (m.domain != host?.lowercase()) " (listed as ${m.domain})" else "",
        help = TRACKER_HELP)
    Field("Company", t.companyName?.let { c -> c + (t.companyWebsite?.let { " · $it" } ?: "") })
}

/** Section title and attribution for the tracker labels in the feed catalogue. */
@Composable
fun TrackerLabelsHeader() {
    val index = rememberTrackerIndex()
    val uri = LocalUriHandler.current
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionTitle("Tracker labels")
            HelpIcon("Tracker labels", TRACKER_HELP)
        }
        Text(
            "Company and category of known tracker domains, shown next to connections, lookups and apps. " +
                "Downloaded by this device from AdGuard's repository; the database started from WhoTracks.me data " +
                "and is maintained by AdGuard." +
                (index?.let { " Loaded: ${formatCount(it.domainCount.toLong())} domains, ${formatCount(it.trackerCount.toLong())} trackers, " +
                    "${formatCount(it.companyCount.toLong())} companies." } ?: ""),
            Modifier.padding(horizontal = 16.dp),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(Modifier.padding(horizontal = 4.dp)) {
            TextButton(onClick = { uri.openUri(TrackerDatabase.SOURCE_URL) }) { Text("AdGuard companiesdb") }
            TextButton(onClick = { uri.openUri(TrackerDatabase.LICENSE_URL) }) { Text("CC BY-SA 4.0") }
        }
    }
}

/**
 * The app detail's "Trackers" section: companies [pkg] contacted in the
 * window, grouped with categories and counts; tapping a company lists its
 * domains. Emits nothing while loading.
 */
@Composable
fun AppTrackersSection(vm: MainViewModel, pkg: String, days: Int) {
    val source = remember(pkg) { vm.appTrackers(pkg) }
    val companiesOrOff by source.collectAsStateWithLifecycle(initialValue = LOADING)
    val companies = companiesOrOff
    if (companies === LOADING) return
    var open by rememberSaveable(pkg) { mutableStateOf<String?>(null) }
    var showAll by rememberSaveable(pkg) { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth()) {
        val tracking = companies?.count { it.tracking } ?: 0
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionTitle(if (companies == null) "Trackers" else "Trackers · ${plural(tracking.toLong(), "company", "companies")}")
            HelpIcon("Tracker labels", TRACKER_HELP)
        }
        when {
            companies == null -> Hint("Tracker labels are off or not downloaded yet (Settings → Threat intelligence feeds → Tracker labels).")
            companies.isEmpty() -> Hint("No known tracker or service domains in the ${windowLabel(days)}.")
            else -> {
                val shown = if (showAll) companies else companies.take(COLLAPSED)
                for (c in shown) CompanyRow(c, expanded = open == c.company, onClick = { open = if (open == c.company) null else c.company })
                if (companies.size > COLLAPSED) {
                    TextButton(onClick = { showAll = !showAll }, Modifier.padding(horizontal = 4.dp)) {
                        Text(if (showAll) "Show fewer" else "Show all ${companies.size}")
                    }
                }
            }
        }
    }
}

private const val COLLAPSED = 5

/** Marker for "not loaded yet" (null means tracker labels are unavailable). */
private val LOADING: List<CompanyHits> = ArrayList()

@Composable
private fun Hint(text: String) {
    Text(text, Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant)
}

private fun hitsText(flows: Long, lookups: Long, blocked: Long): String = listOfNotNull(
    flows.takeIf { it > 0 }?.let { plural(it, "connection") },
    lookups.takeIf { it > 0 }?.let { plural(it, "lookup") },
    blocked.takeIf { it > 0 }?.let { "${formatCount(it)} blocked" },
).joinToString(" · ")

@Composable
private fun CompanyRow(c: CompanyHits, expanded: Boolean, onClick: () -> Unit) {
    Column(
        Modifier.fillMaxWidth()
            .clickable(onClickLabel = if (expanded) "Hide domains" else "Show domains", role = Role.Button, onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(c.company, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis,
                fontWeight = if (c.tracking) FontWeight.Medium else null)
            when {
                c.allBlocked -> Tag("blocked", VigilColors.Block, filled = true)
                c.blocked > 0 -> Tag("partly blocked", VigilColors.Block)
                else -> Tag("allowed", VigilColors.Allow)
            }
        }
        Row(Modifier.padding(top = 3.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            for (cat in c.categories.take(3)) {
                if (TrackerDatabase.isTrackingCategory(cat)) Tag(TrackerDatabase.categoryLabel(cat), VigilColors.Medium, filled = true)
                else Tag(TrackerDatabase.categoryLabel(cat))
            }
        }
        Text(
            "${plural(c.domains.size.toLong(), "domain")} · ${hitsText(c.flows, c.lookups, c.blocked)}",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (expanded) {
            for (d in c.domains) {
                Column(Modifier.padding(start = 12.dp, top = 6.dp)) {
                    Text(d.domain, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis,
                        color = if (d.total > 0 && d.blocked >= d.total) VigilColors.Block else MaterialTheme.colorScheme.onSurface)
                    Text(
                        "${d.tracker.name} · ${TrackerDatabase.categoryLabel(d.tracker.category)} · ${hitsText(d.flows, d.lookups, d.blocked)}",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            c.website?.let { Text(it, Modifier.padding(start = 12.dp, top = 6.dp), style = MaterialTheme.typography.bodySmall, color = VigilColors.Info) }
        }
    }
}

/** Overview: the tracking companies contacted by the most apps in the last 24 hours. */
fun LazyListScope.topTrackerCompanies(companies: List<CompanyApps>, nav: NavController) {
    if (companies.isEmpty()) return
    item {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SectionTitle("Top tracker companies")
            HelpIcon("Tracker labels", TRACKER_HELP)
        }
    }
    items(companies, key = { "t-" + it.company }) { c ->
        Row(
            Modifier.fillMaxWidth().clickable(onClickLabel = "Open apps") { nav.navigateTab("apps") }.padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(c.company, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(c.categories.joinToString(", ") { TrackerDatabase.categoryLabel(it) }, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(plural(c.apps.toLong(), "app"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
