package dev.vigil.inspector.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import java.util.concurrent.ConcurrentHashMap

data class AppInfo(
    /** Stable key stored with every event: a package name, `uid:<n>` or `unknown`. */
    val key: String,
    val uid: Int?,
    val label: String,
    val isSystem: Boolean,
    val isInstalledPackage: Boolean,
)

/** Maps Linux UIDs to apps, with caching. */
class AppResolver(context: Context) {
    private val pm = context.packageManager
    private val byUid = ConcurrentHashMap<Int, AppInfo>()
    private val byKey = ConcurrentHashMap<String, AppInfo>()

    fun resolve(uid: Int?): AppInfo {
        if (uid == null || uid < 0) return UNKNOWN
        return byUid.getOrPut(uid) { lookup(uid).also { byKey[it.key] = it } }
    }

    fun byKey(key: String): AppInfo = byKey[key] ?: run {
        when {
            key == UNKNOWN.key -> UNKNOWN
            key.startsWith("uid:") -> resolve(key.removePrefix("uid:").toIntOrNull())
            else -> fromPackage(key, null) ?: AppInfo(key, null, key, isSystem = false, isInstalledPackage = false)
        }.also { byKey[key] = it }
    }

    fun uidsFor(keys: Collection<String>): List<Int> = keys.mapNotNull { key ->
        if (key.startsWith("uid:")) key.removePrefix("uid:").toIntOrNull()
        else runCatching { pm.getApplicationInfo(key, 0).uid }.getOrNull()
    }.distinct()

    fun icon(key: String): Drawable? =
        if (key.contains('.') && !key.startsWith("uid:")) runCatching { pm.getApplicationIcon(key) }.getOrNull() else null

    fun invalidate() {
        byUid.clear()
        byKey.clear()
    }

    private fun lookup(uid: Int): AppInfo {
        val packages = pm.getPackagesForUid(uid)?.sorted().orEmpty()
        if (packages.size == 1) fromPackage(packages[0], uid)?.let { return it }
        if (packages.size > 1) {
            // Shared UID: prefer a launchable app for the label.
            val main = packages.firstOrNull { pm.getLaunchIntentForPackage(it) != null } ?: packages[0]
            val info = fromPackage(main, uid)
            if (info != null) {
                return info.copy(key = "uid:$uid", label = "${info.label} (+${packages.size - 1} shared)")
            }
        }
        val name = SPECIAL_UIDS[uid] ?: pm.getNameForUid(uid) ?: "UID $uid"
        return AppInfo("uid:$uid", uid, name, isSystem = uid < FIRST_APPLICATION_UID, isInstalledPackage = false)
    }

    private fun fromPackage(pkg: String, uid: Int?): AppInfo? = try {
        val ai = pm.getApplicationInfo(pkg, 0)
        AppInfo(
            key = pkg,
            uid = uid ?: ai.uid,
            label = pm.getApplicationLabel(ai).toString(),
            isSystem = ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
            isInstalledPackage = true,
        )
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    companion object {
        const val FIRST_APPLICATION_UID = 10_000
        val UNKNOWN = AppInfo("unknown", null, "Unattributed", isSystem = true, isInstalledPackage = false)
        val SPECIAL_UIDS = mapOf(
            0 to "Root",
            1000 to "Android system",
            1001 to "Telephony",
            1013 to "Media server",
            1020 to "mDNS",
            1021 to "GPS",
            1051 to "DNS resolver",
            1052 to "DNS (tethering)",
            1073 to "Network stack",
            9999 to "Nobody",
        )
    }
}
