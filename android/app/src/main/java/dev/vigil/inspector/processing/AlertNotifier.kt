package dev.vigil.inspector.processing

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import dev.vigil.inspector.R
import dev.vigil.inspector.data.AlertEntity
import dev.vigil.inspector.data.AppResolver
import dev.vigil.inspector.ui.MainActivity

class AlertNotifier(private val context: Context, private val apps: AppResolver) {
    private val nm = context.getSystemService(NotificationManager::class.java)

    fun createChannels() {
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ALERTS, "Security alerts", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Threat hits, beaconing and other suspicious behaviour"
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_SERVICE, "Inspector status", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shown while vigil is inspecting traffic"
                setShowBadge(false)
            },
        )
    }

    fun notify(alert: AlertEntity) {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val app = apps.byKey(alert.pkg)
        val open = PendingIntent.getActivity(
            context, 1,
            Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_DESTINATION, "alerts")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(context, CHANNEL_ALERTS)
            .setSmallIcon(R.drawable.ic_stat_vigil)
            .setContentTitle("${app.label}: ${titleFor(alert.kind)}")
            .setContentText(alert.message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(alert.message))
            .setPriority(if (alert.severity == "high") NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setGroup(GROUP)
            .build()
        nm.notify((alert.kind + alert.pkg + alert.target).hashCode(), n)
    }

    companion object {
        const val CHANNEL_ALERTS = "alerts"
        const val CHANNEL_SERVICE = "service"
        private const val GROUP = "vigil-alerts"

        fun titleFor(kind: String) = when (kind) {
            "threat_domain" -> "threat domain blocked"
            "threat_ip" -> "threat IP blocked"
            "threat_ja4" -> "known malicious TLS fingerprint"
            "beacon" -> "periodic beaconing"
            "encrypted_dns" -> "encrypted DNS in use"
            "hardcoded_dns" -> "bypasses system DNS"
            "new_destination" -> "new destination"
            else -> kind.replace('_', ' ')
        }
    }
}
