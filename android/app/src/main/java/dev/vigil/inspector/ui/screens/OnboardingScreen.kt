package dev.vigil.inspector.ui.screens

import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.vigil.inspector.ui.MainViewModel

private class Step(val icon: ImageVector, val title: String, val body: String)

private val steps = listOf(
    Step(
        Icons.Default.Search, "Welcome to vigil",
        "vigil shows which apps on this phone connect where: every connection and DNS lookup, per app, with threat-feed " +
            "alerts and optional blocking.\n\n" +
            "Encrypted traffic is never decrypted. vigil reads destination names from DNS lookups and the unencrypted " +
            "parts of TLS and QUIC handshakes.",
    ),
    Step(
        Icons.Default.Lock, "About the VPN key icon",
        "vigil uses Android's VPN interface as a local loop on this device: nothing is sent to a VPN server.\n\n" +
            "When you start inspection, Android asks for permission and warns that vigil \"can monitor network traffic\". " +
            "That is exactly what it does, and all of it stays on this device unless you set up SIEM export. " +
            "While it runs, a key icon appears in the status bar.",
    ),
    Step(
        Icons.Default.Refresh, "Threat feeds are downloaded",
        "To recognise malware, phishing and command-and-control servers, vigil downloads threat lists once a day " +
            "directly from their publishers (GitHub, abuse.ch and others). Those servers see your IP address and a " +
            "vigil user agent, nothing about your traffic.\n\n" +
            "You can turn each feed off in Settings → Threat intelligence feeds.",
    ),
    Step(
        Icons.Default.Settings, "Optional: usage access",
        "With usage access, vigil can tell traffic from the app you are using apart from background traffic. " +
            "It only reads which app is in the foreground. You can grant it later in Settings.",
    ),
    Step(
        Icons.Default.Notifications, "Optional: notifications",
        "vigil shows a notification while inspection runs, and can alert you about threat-feed hits and other " +
            "medium and high severity findings.",
    ),
    Step(
        Icons.Default.PlayArrow, "Start inspecting",
        "Android now asks for permission to show notifications (if not granted yet), then for permission to run " +
            "vigil's local VPN. Once both are answered, connections and DNS lookups start appearing on the Overview.\n\n" +
            "You can also start and stop inspection later with the switch on the Overview or the quick settings tile.",
    ),
)

/**
 * First-run onboarding: a few skippable steps, shown until [onFinish] is
 * called (which persists the `onboarded` setting). The last step starts
 * inspection ([onStartInspecting]: notification prompt, then VPN consent).
 */
@Composable
fun OnboardingScreen(
    vm: MainViewModel,
    notificationsGranted: Boolean,
    onRequestNotifications: () -> Unit,
    onFinish: () -> Unit,
    onStartInspecting: () -> Unit,
) {
    var index by rememberSaveable { mutableIntStateOf(0) }
    // System back goes to the previous step; on the first one it leaves the app.
    BackHandler(enabled = index > 0) { index-- }
    val step = steps[index]
    val last = index == steps.lastIndex
    val context = LocalContext.current
    val usageAccess = usageAccessGranted(vm)
    Surface(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                LinearProgressIndicator(progress = { (index + 1f) / steps.size }, modifier = Modifier.weight(1f), drawStopIndicator = {})
                TextButton(onClick = onFinish, modifier = Modifier.padding(start = 8.dp)) { Text("Skip") }
            }
            Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(top = 32.dp)) {
                Icon(step.icon, null, Modifier.size(48.dp), tint = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.height(16.dp))
                Text(step.title, Modifier.semantics { heading() }, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(12.dp))
                Text(step.body, style = MaterialTheme.typography.bodyLarge)
                Spacer(Modifier.height(20.dp))
                when (index) {
                    3 -> if (usageAccess) {
                        Text("Usage access is granted.", color = MaterialTheme.colorScheme.primary)
                    } else {
                        OutlinedButton(onClick = { context.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) }) { Text("Grant usage access") }
                    }
                    4 -> if (Build.VERSION.SDK_INT < 33 || notificationsGranted) {
                        Text("Notifications are allowed.", color = MaterialTheme.colorScheme.primary)
                    } else {
                        OutlinedButton(onClick = onRequestNotifications) { Text("Allow notifications") }
                    }
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                if (index > 0) TextButton(onClick = { index-- }) { Text("Back") } else Spacer(Modifier)
                if (last) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = onFinish) { Text("Not now") }
                        Button(onClick = onStartInspecting) { Text("Start inspecting") }
                    }
                } else {
                    Button(onClick = { index++ }) { Text("Next") }
                }
            }
        }
    }
}
