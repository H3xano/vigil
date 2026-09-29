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
import dev.vigil.inspector.ui.AlertText
import dev.vigil.inspector.ui.MainActivity

class AlertNotifier(private val context: Context, private val apps: AppResolver) {
    private val nm = context.getSystemService(NotificationManager::class.java)

    fun createChannels() {
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ALERTS, context.getString(R.string.alert_channel_alerts_name), NotificationManager.IMPORTANCE_HIGH).apply {
                description = context.getString(R.string.alert_channel_alerts_description)
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_SERVICE, context.getString(R.string.alert_channel_service_name), NotificationManager.IMPORTANCE_LOW).apply {
                description = context.getString(R.string.alert_channel_service_description)
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
        // Shown in the app's language; the stored (and exported) message stays English.
        val title = context.getString(R.string.alert_notification_title, app.label, AlertText.title(alert.kind).resolve(context))
        val text = AlertText.message(alert, app.label).resolve(context)
        val n = NotificationCompat.Builder(context, CHANNEL_ALERTS)
            .setSmallIcon(R.drawable.ic_stat_vigil)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
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
    }
}
