package dev.vigil.inspector.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.util.Log
import java.security.MessageDigest

/**
 * Installed packages with their signing certificates, for the health check.
 * Needs QUERY_ALL_PACKAGES (declared) to see every app on Android 11+.
 */
object InstalledApps {
    private const val TAG = "vigil.health"

    @Suppress("DEPRECATION") // the int-flag overloads, for API 29-32
    fun collect(context: Context): List<InstalledApp> {
        val pm = context.packageManager
        val packages = try {
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
            } else {
                pm.getInstalledPackages(PackageManager.GET_SIGNING_CERTIFICATES)
            }
        } catch (e: RuntimeException) {
            // A binder transaction too large for hundreds of packages: fall back to names only, then per package.
            Log.w(TAG, "listing packages with certificates failed: ${e.message}")
            pm.getInstalledPackages(0).mapNotNull { p -> runCatching { packageInfo(pm, p.packageName) }.getOrNull() }
        }
        return packages.map { p -> toApp(pm, p) }.sortedBy { it.pkg }
    }

    @Suppress("DEPRECATION")
    private fun packageInfo(pm: PackageManager, pkg: String): PackageInfo =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
        } else {
            pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        }

    private fun toApp(pm: PackageManager, p: PackageInfo): InstalledApp {
        val ai = p.applicationInfo
        val label = ai?.let { runCatching { pm.getApplicationLabel(it).toString() }.getOrNull() } ?: p.packageName
        val installer = runCatching {
            if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(p.packageName).installingPackageName else null
        }.getOrNull()
        return InstalledApp(
            pkg = p.packageName, label = label, certs = certificates(p),
            system = ai != null && (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            installer = installer, firstInstall = p.firstInstallTime.takeIf { it > 0 },
        )
    }

    /** SHA-1 and SHA-256 of every current signer and of the signing history (key rotation). */
    private fun certificates(p: PackageInfo): List<String> {
        val info = p.signingInfo ?: return emptyList()
        val sigs: Array<Signature> = (if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory) ?: return emptyList()
        return sigs.flatMap { s ->
            val der = s.toByteArray()
            listOf(
                AppCerts.of(AppCerts.SHA1, MessageDigest.getInstance("SHA-1").digest(der)),
                AppCerts.of(AppCerts.SHA256, MessageDigest.getInstance("SHA-256").digest(der)),
            )
        }.distinct()
    }
}
