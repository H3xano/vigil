import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("com.google.devtools.ksp")
}

val rustDir = rootProject.projectDir.resolve("../core")
val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")
val rustAbis = (findProperty("vigil.abis") as String? ?: "arm64-v8a,armeabi-v7a,x86_64").split(",")

android {
    namespace = "dev.vigil.inspector"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "dev.vigil.inspector"
        // getConnectionOwnerUid (per-app attribution) requires Android 10.
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
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
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
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
    }
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

// Builds the Rust engine (core/vigil-jni) into src/main/jniLibs with cargo-ndk.
// Pass -Pvigil.skipCargo=true to use prebuilt libraries.
val cargoBuild by tasks.registering(Exec::class) {
    group = "build"
    description = "Cross-compiles libvigil.so for ${rustAbis.joinToString()}"
    onlyIf { findProperty("vigil.skipCargo") != "true" }
    workingDir = rustDir
    inputs.dir(rustDir.resolve("vigil-core/src"))
    inputs.dir(rustDir.resolve("vigil-jni/src"))
    inputs.files(rustDir.resolve("Cargo.toml"), rustDir.resolve("Cargo.lock"))
    outputs.dir(jniLibsDir)
    val cargo = listOf(System.getenv("CARGO_HOME")?.let { "$it/bin/cargo" }, "${System.getProperty("user.home")}/.cargo/bin/cargo")
        .firstOrNull { it != null && file(it).exists() } ?: "cargo"
    val args = mutableListOf(cargo, "ndk", "--platform", "29", "-o", jniLibsDir.asFile.absolutePath)
    rustAbis.forEach { args += listOf("-t", it) }
    args += listOf("build", "--release", "-p", "vigil-jni")
    commandLine(args)
    doFirst {
        environment("ANDROID_NDK_HOME", android.ndkDirectory.absolutePath)
    }
}
tasks.named("preBuild") { dependsOn(cargoBuild) }

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-service:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.5")
    implementation("androidx.work:work-runtime-ktx:2.10.0")

    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}
