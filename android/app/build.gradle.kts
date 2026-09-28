import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("com.google.devtools.ksp")
}

val rustDir = rootProject.projectDir.resolve("../core")
val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")
val rustAbis = (findProperty("vigil.abis") as String? ?: "arm64-v8a,armeabi-v7a,x86_64").split(",")

android {
    namespace = "dev.vigil.inspector"
    // API 37 is out; moving to it (with targetSdk 37 after reviewing the
    // Android 17 behaviour changes) unblocks the pinned AndroidX versions below.
    //noinspection GradleDependency
    compileSdk = 36
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "dev.vigil.inspector"
        // getConnectionOwnerUid (per-app attribution) requires Android 10.
        minSdk = 29
        //noinspection OldTargetApi: see compileSdk
        targetSdk = 36
        // versionCode = major * 10000 + minor * 100 + patch, kept as a literal
        // so F-Droid's update checker can read it. The APK is universal (no
        // ABI splits), so there are no per-ABI offsets. See docs/DEVELOPMENT.md.
        versionCode = 300
        versionName = "0.3.0"
        ndk { abiFilters += rustAbis }
    }

    signingConfigs {
        // Release builds are signed with a key from keystore.properties when
        // present, otherwise with the debug key so the APK stays installable.
        val propsFile = rootProject.file("keystore.properties")
        if (propsFile.exists()) {
            val p = Properties().apply { propsFile.inputStream().use { load(it) } }
            create("release") {
                storeFile = rootProject.file(p.getProperty("storeFile"))
                storePassword = p.getProperty("storePassword")
                keyAlias = p.getProperty("keyAlias")
                keyPassword = p.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // -Pvigil.unsignedRelease=true produces app-release-unsigned.apk,
            // for F-Droid, which signs or verifies the APK itself.
            signingConfig = if (findProperty("vigil.unsignedRelease") == "true") {
                null
            } else {
                signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
            }
            // Reproducible builds: keep git state out of the APK.
            vcsInfo.include = false
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        jniLibs { useLegacyPackaging = false }
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
    lint {
        abortOnError = true
        warningsAsErrors = false
        // The APK ships no 32-bit x86 library (see rustAbis), which ChromeOS on x86 would want.
        disable += "ChromeOsAbiSupport"
    }
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

// Builds the Rust engine (core/vigil-jni) into src/main/jniLibs with cargo-ndk.
// Pass -Pvigil.skipCargo=true to use prebuilt libraries.
val cargoBuild = tasks.register<Exec>("cargoBuild") {
    group = "build"
    description = "Cross-compiles libvigil.so for ${rustAbis.joinToString()}"
    onlyIf { findProperty("vigil.skipCargo") != "true" }
    workingDir = rustDir
    inputs.dir(rustDir.resolve("vigil-core/src"))
    inputs.dir(rustDir.resolve("vigil-jni/src"))
    inputs.dir(rustDir.resolve("vendor"))
    inputs.files(rustDir.resolve("Cargo.toml"), rustDir.resolve("Cargo.lock"))
    outputs.dir(jniLibsDir)
    val cargo = listOf(System.getenv("CARGO_HOME")?.let { "$it/bin/cargo" }, "${System.getProperty("user.home")}/.cargo/bin/cargo")
        .firstOrNull { it != null && file(it).exists() } ?: "cargo"
    val ndkDir = androidComponents.sdkComponents.ndkDirectory
    val args = mutableListOf(cargo, "ndk", "--platform", "29", "-o", jniLibsDir.asFile.absolutePath)
    rustAbis.forEach { args += listOf("-t", it) }
    // --locked: build exactly the dependency versions in Cargo.lock.
    args += listOf("build", "--release", "--locked", "-p", "vigil-jni")
    commandLine(args)
    doFirst {
        environment("ANDROID_NDK_HOME", ndkDir.get().asFile.absolutePath)
        // Reproducible builds: remap the checkout and cargo-home paths that
        // panic locations embed, and drop the linker's build-id note. Flags
        // already set in CARGO_ENCODED_RUSTFLAGS are kept.
        val cargoHome = System.getenv("CARGO_HOME") ?: "${System.getProperty("user.home")}/.cargo"
        val flags = listOfNotNull(
            System.getenv("CARGO_ENCODED_RUSTFLAGS")?.takeIf { it.isNotEmpty() },
            "--remap-path-prefix=${rustDir.canonicalPath}=/vigil/core",
            "--remap-path-prefix=${file(cargoHome).canonicalPath}=/cargo",
            "-Clink-arg=-Wl,--build-id=none",
        )
        environment("CARGO_ENCODED_RUSTFLAGS", flags.joinToString("\u001f"))
    }
}
tasks.named("preBuild") { dependsOn(cargoBuild) }

dependencies {
    // Newest releases that support compileSdk 36. Newer ones declare
    // minCompileSdk 37: Compose BOM 2026.08.00+ (UI 1.12), core 1.19,
    // lifecycle 2.11 (its compose artifacts; lifecycle versions are aligned),
    // navigation-compose 2.10.
    val composeBom = platform("androidx.compose:compose-bom:2026.06.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    debugImplementation("androidx.compose.ui:ui-tooling")

    //noinspection GradleDependency: needs compileSdk 37
    implementation("androidx.core:core-ktx:1.18.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    //noinspection GradleDependency: needs compileSdk 37
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    //noinspection GradleDependency: needs compileSdk 37
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    //noinspection GradleDependency: needs compileSdk 37
    implementation("androidx.lifecycle:lifecycle-service:2.10.0")
    //noinspection GradleDependency: needs compileSdk 37
    implementation("androidx.navigation:navigation-compose:2.9.8")
    implementation("androidx.work:work-runtime-ktx:2.12.0")

    implementation("androidx.room:room-runtime:2.8.5")
    implementation("androidx.room:room-ktx:2.8.5")
    ksp("androidx.room:room-compiler:2.8.5")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
}
