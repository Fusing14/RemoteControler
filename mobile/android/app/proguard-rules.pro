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
