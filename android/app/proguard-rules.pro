# ─── R8 Full Mode ────────────────────────────────────────────────────────────
-allowaccessmodification
-repackageclasses 'x'
-flattenpackagehierarchy 'y'
-overloadaggressively
-optimizationpasses 10
-dontusemixedcaseclassnames

# ─── Keep only what JNI & React Native bridge requires ───────────────────────
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

-keep class com.lalona.MainActivity { *; }
-keep,allowobfuscation class com.lalona.NativeCryptoModule {
    public <methods>;
}
-keepclassmembers class com.lalona.NativeCryptoModule {
    public native *;
}

# ─── Strip all logging ────────────────────────────────────────────────────────
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
    public static int wtf(...);
}

# ─── Strip stack traces & source attribution ─────────────────────────────────
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# ─── Prevent reflection-based attacks on class structure ─────────────────────
-dontskipnonpubliclibraryclassmembers

# ─── React Native internals ───────────────────────────────────────────────────
-keep class com.facebook.react.** { *; }
-keep class com.facebook.hermes.** { *; }
-dontwarn com.facebook.**
