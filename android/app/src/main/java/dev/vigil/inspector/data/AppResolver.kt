package dev.vigil.inspector.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import dev.vigil.inspector.R
import dev.vigil.inspector.ui.UiText
import java.util.concurrent.ConcurrentHashMap

data class AppInfo(
    /** Stable key stored with every event: a package name, `uid:<n>` or `unknown`. */
    val key: String,
    val uid: Int?,
    val label: String,
    val isSystem: Boolean,
    val isInstalledPackage: Boolean,
    /** Package whose icon represents this app (differs from key for shared UIDs). */
    val iconPackage: String? = null,
)

/** Maps Linux UIDs to apps, with caching. */
class AppResolver(private val context: Context) {
    private val pm = context.packageManager
    private val res = context.resources
    private val byUid = ConcurrentHashMap<Int, AppInfo>()
    private val byKey = ConcurrentHashMap<String, AppInfo>()

    fun resolve(uid: Int?): AppInfo {
        if (uid == null || uid < 0) return unknown()
        return byUid.getOrPut(uid) { lookup(uid).also { byKey[it.key] = it } }
    }

    fun byKey(key: String): AppInfo = byKey[key] ?: run {
        when {
            key == UNKNOWN.key -> unknown()
            key.startsWith("uid:") -> resolve(key.removePrefix("uid:").toIntOrNull())
            else -> fromPackage(key, null) ?: AppInfo(key, null, key, isSystem = false, isInstalledPackage = false)
        }.also { byKey[key] = it }
    }

    fun uidsFor(keys: Collection<String>): List<Int> = keys.mapNotNull { key ->
        if (key.startsWith("uid:")) key.removePrefix("uid:").toIntOrNull()
        else runCatching { pm.getApplicationInfo(key, 0).uid }.getOrNull()
    }.distinct()

    /** UID of one app key (package or `uid:<n>`), null if not installed. A PackageManager call. */
    fun uidFor(key: String): Int? = uidsFor(listOf(key)).firstOrNull()

    fun icon(key: String): Drawable? {
        val pkg = byKey(key).iconPackage ?: return null
        return runCatching { pm.getApplicationIcon(pkg) }.getOrNull()
    }

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
                val others = packages.size - 1
                val label = res.getQuantityString(R.plurals.app_label_shared_uid, others, info.label, others)
                return info.copy(key = "uid:$uid", label = label, iconPackage = main)
            }
        }
        val name = SPECIAL_UIDS[uid]?.resolve(context) ?: pm.getNameForUid(uid) ?: context.getString(R.string.app_label_uid, uid.toString())
        return AppInfo("uid:$uid", uid, name, isSystem = uid < FIRST_APPLICATION_UID, isInstalledPackage = false)
    }

    /** [UNKNOWN] with its label in the app's language. */
    private fun unknown(): AppInfo = UNKNOWN.copy(label = context.getString(R.string.app_label_unattributed))

    private fun fromPackage(pkg: String, uid: Int?): AppInfo? = try {
        val ai = pm.getApplicationInfo(pkg, 0)
        AppInfo(
            key = pkg,
            uid = uid ?: ai.uid,
            label = pm.getApplicationLabel(ai).toString(),
            isSystem = ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
            isInstalledPackage = true,
            iconPackage = pkg,
        )
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    companion object {
        const val FIRST_APPLICATION_UID = 10_000
        /**
         * Traffic without an app. Compare its [AppInfo.key]; the resolver
         * returns a copy labelled in the app's language (this English label
         * is only a fallback for code without a Context, e.g. tests).
         */
        val UNKNOWN = AppInfo("unknown", null, "Unattributed", isSystem = true, isInstalledPackage = false)
        /** Names of Android's system UIDs; mDNS and GPS are names and stay untranslated. */
        val SPECIAL_UIDS: Map<Int, UiText> = mapOf(
            0 to UiText.of(R.string.app_uid_root),
            1000 to UiText.of(R.string.app_uid_android_system),
            1001 to UiText.of(R.string.app_uid_telephony),
            1013 to UiText.of(R.string.app_uid_media_server),
            1020 to UiText.Raw("mDNS"),
            1021 to UiText.Raw("GPS"),
            1051 to UiText.of(R.string.app_uid_dns_resolver),
            1052 to UiText.of(R.string.app_uid_dns_tethering),
            1073 to UiText.of(R.string.app_uid_network_stack),
            9999 to UiText.of(R.string.app_uid_nobody),
        )
    }
}
