# JNI: native code calls these by name.
-keep class dev.vigil.inspector.engine.VigilNative { *; }
-keep class dev.vigil.inspector.engine.PlatformBridge { *; }
# kotlinx.serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers @kotlinx.serialization.Serializable class ** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}
