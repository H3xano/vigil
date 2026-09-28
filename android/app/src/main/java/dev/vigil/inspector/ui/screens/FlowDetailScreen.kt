package dev.vigil.inspector.ui.screens

import android.content.ClipData
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import dev.vigil.inspector.data.AsnDatabase
import dev.vigil.inspector.data.FlowEntity
import dev.vigil.inspector.ui.BlockReasons
import dev.vigil.inspector.ui.DomainNames
import dev.vigil.inspector.ui.Glossary
import dev.vigil.inspector.ui.MainViewModel
import dev.vigil.inspector.ui.components.EmptyState
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import dev.vigil.inspector.ui.components.AppIcon
import dev.vigil.inspector.ui.components.Field
import dev.vigil.inspector.ui.components.SectionTitle
import dev.vigil.inspector.ui.formatBytes
import dev.vigil.inspector.ui.formatDateTime
import dev.vigil.inspector.ui.formatDuration
import dev.vigil.inspector.ui.theme.VigilColors

@Composable
fun FlowDetailScreen(vm: MainViewModel, nav: NavController, id: Long) {
    // null while loading; Lookup(null) once the query says the row does not exist.
    val lookup by remember(id) { vm.flow(id).map { Lookup(it) } }.collectAsStateWithLifecycle(initialValue = null)
    val settings by vm.settings.collectAsStateWithLifecycle()
    val feeds by vm.feeds.collectAsStateWithLifecycle()
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxSize()) {
        VigilTopBar("Connection", nav)
        val loaded = lookup ?: return@Column
        val f = loaded.flow
        if (f == null) {
            EmptyState("Connection not found", "It may have been pruned by the history retention setting or cleared.")
            return@Column
        }
        val label = rememberAppLabels(vm, listOf(f.pkg))(f.pkg)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                AppIcon(f.pkg, label, 44.dp)
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(f.domain ?: f.dstIp, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold,
                        color = if (f.isBlocked) VigilColors.Block else MaterialTheme.colorScheme.onSurface)
                    Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            SectionTitle("Verdict")
            Field("Verdict", if (f.isBlocked) "Blocked" else "Allowed")
            Field("Reason", f.reason)
            Field("Error", f.error)
            SectionTitle("Destination")
            Field("Domain", f.domain)
            Field("Name source", when (f.domainSource) {
                "sni" -> "TLS ClientHello (SNI)"
                "quic" -> "QUIC Initial (SNI)"
                "http" -> "HTTP Host header"
                "dns" -> "Earlier DNS answer (hint)"
                else -> null
            }, help = Glossary.NAME_SOURCE + "\n\n" + Glossary.SNI)
            Field("Address", "${f.dstIp}:${f.dstPort}", mono = true)
            Field(
                "Network",
                AsnDatabase.label(f.asn, f.asnName)?.let { l -> l + (f.asnCountry?.let { " · registered in $it" } ?: "") },
                help = Glossary.ASN,
            )
            Field("Path", when (f.via) {
                "direct" -> "Direct"
                "wireguard" -> "Through the WireGuard tunnel"
                "socks5" -> "Through the SOCKS5 proxy"
                null -> null
                else -> f.via
            }, help = Glossary.VIA)
            Field("Transport", f.proto.uppercase())
            Field("Protocol", f.appProto?.uppercase())
            SectionTitle("Handshake")
            Field("TLS version", f.tlsVersion)
            Field("ALPN", f.alpn, help = Glossary.ALPN)
            Field("JA4", f.ja4, mono = true, help = Glossary.JA4)
            if (f.ja4Feed != null) {
                Field(
                    "JA4 match",
                    (f.ja4Label?.let { "Listed as “$it”" } ?: "Listed") + " by feed ${f.ja4Feed}" +
                        if (f.isBlocked && f.reason?.startsWith("ja4:") == true) "; connection blocked" else "",
                    help = Glossary.JA4_MATCH,
                )
            }
            Field("ECH", if (f.ech) "Offered — the real destination name is encrypted" else null, help = Glossary.ECH)
            Field("HTTP method", f.httpMethod)
            SectionTitle("Traffic")
            Field("Started", formatDateTime(f.ts))
            Field("Duration", f.durationMs?.let(::formatDuration) ?: if (f.isActive) "active" else null)
            Field("Received", formatBytes(f.rx))
            Field("Sent", formatBytes(f.tx))
            Field("App state", when (f.background) { true -> "Background"; false -> "Foreground"; null -> null })
            Field("Source", f.src, mono = true)
            Field("UID", f.uid?.toString())
            Field("Tags", f.tags.takeIf { it.isNotEmpty() })

            SectionTitle("Actions")
            val domain = f.domain
            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (domain != null) {
                    BlockDomainButtons(domain, settings, vm, pkg = f.pkg, appLabel = label)
                    if (DomainNames.matchingRule(domain, settings.denyDomains) == null && f.domainSource == "dns") {
                        Text(
                            "This name is a hint from an earlier DNS answer; other sites may share ${f.dstIp}. " +
                                "Blocking it blocks lookups of $domain (and connections that name it), not this IP address.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    val allowRule = DomainNames.matchingRule(domain, settings.allowDomains)
                    if (f.isBlocked && allowRule == null && !BlockReasons.isPerApp(f.reason)) {
                        OutlinedButton(onClick = { vm.allowDomainWithUndo(domain) }, Modifier.fillMaxWidth()) { Text("Always allow $domain") }
                    }
                    if (f.isBlocked) {
                        Text(
                            BlockReasons.explain(f.reason, feeds, label),
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else if (f.pkg != "unknown" && f.pkg !in settings.blockedPackages) {
                    // No name to block: vigil's rules match names, not single addresses.
                    OutlinedButton(onClick = { vm.blockApp(f.pkg, label) }, Modifier.fillMaxWidth()) { Text("Block all network access of $label") }
                    Text(
                        "vigil blocks by name; this connection has none, and single IP addresses cannot be blocked.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (f.pkg != "unknown") OutlinedButton(onClick = { nav.openApp(f.pkg) }, Modifier.fillMaxWidth()) { Text("Open $label") }
                OutlinedButton(onClick = {
                    val text = listOfNotNull(f.domain, "${f.dstIp}:${f.dstPort}", f.ja4).joinToString("\n")
                    scope.launch { clipboard.setClipEntry(ClipEntry(ClipData.newPlainText("indicators", text))) }
                }, Modifier.fillMaxWidth()) { Text("Copy indicators") }
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

private class Lookup(val flow: FlowEntity?)
