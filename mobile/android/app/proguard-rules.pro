# Reglas ProGuard / R8 para SecureDeck

# Preservar clases de Flutter
-keep class io.flutter.app.** { *; }
-keep class io.flutter.plugin.**  { *; }
-keep class io.flutter.util.**  { *; }
-keep class io.flutter.view.**  { *; }
-keep class io.flutter.**  { *; }
-keep class io.flutter.plugins.**  { *; }

# Preservar llamadas nativas de Cryptography y Keystore
-keep class com.it_nomads.fluttersecurestorage.** { *; }
-keep class dev.steenbakker.mobile_scanner.** { *; }
-dontwarn javax.annotation.**

# Flutter Play Store Deferred Components (R8 missing classes suppression)
-dontwarn com.google.android.play.core.**
-dontwarn io.flutter.embedding.engine.deferredcomponents.**
-keep class com.google.android.play.core.** { *; }

# Flutter wrappers and plugins
-dontwarn io.flutter.app.**

# OkHttp3 optional TLS providers (used by ota_update)
-dontwarn org.bouncycastle.jsse.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**
-dontwarn okhttp3.**
-dontwarn okio.**

# Keep ota_update plugin classes and FileProvider
-keep class sk.fourq.otaupdate.** { *; }
