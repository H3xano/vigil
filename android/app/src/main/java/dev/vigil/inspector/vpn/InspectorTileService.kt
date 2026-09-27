package dev.vigil.inspector.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import dev.vigil.inspector.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** Quick Settings toggle for the inspector. */
class InspectorTileService : TileService() {
    private var scope: CoroutineScope? = null

    override fun onStartListening() {
        val s = CoroutineScope(Job() + Dispatchers.Main)
        scope = s
        s.launch { ServiceState.status.collect { render(it) } }
    }

    override fun onStopListening() {
        scope?.cancel()
        scope = null
    }

    override fun onClick() {
        when (ServiceState.status.value) {
            is VpnStatus.Running, VpnStatus.Starting -> VigilVpnService.stop(this)
            else -> if (VpnService.prepare(this) == null) {
                VigilVpnService.start(this)
            } else {
                // Consent is needed: open the app to ask for it.
                val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                if (Build.VERSION.SDK_INT >= 34) {
                    startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
                } else {
                    @Suppress("DEPRECATION")
                    startActivityAndCollapse(intent)
                }
            }
        }
    }

    private fun render(status: VpnStatus) {
        val tile = qsTile ?: return
        tile.state = if (status is VpnStatus.Running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.subtitle = when (status) {
            is VpnStatus.Running -> "Inspecting"
            VpnStatus.Starting -> "Starting"
            is VpnStatus.Failed -> "Error"
            VpnStatus.Stopped -> "Off"
        }
        tile.updateTile()
    }
}
