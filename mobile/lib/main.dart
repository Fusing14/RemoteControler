import 'package:flutter/material.dart';

import 'crypto/key_manager.dart';
import 'services/secure_storage_adapter.dart';
import 'services/pairing_client.dart';
import 'services/saved_hosts_service.dart';
import 'ui/screens/scanner_screen.dart';
import 'ui/screens/deck_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // 1. Inicialización de la identidad criptográfica respaldada por Hardware Keystore / Keychain
  final storage = FlutterSecureStorageAdapter();
  final keyManager = KeyManager(storage: storage);
  await keyManager.ensureInitialized();

  // 2. Comprobar si ya existen ordenadores previamente vinculados
  final savedHostsService = SavedHostsService(storage: storage);
  await savedHostsService.ensureInitialized();
  final activeHost = await savedHostsService.getActiveHost();

  final pairingClient = PairingClient(
    keyManager: keyManager,
    storage: storage,
  );

  final pairedEndpoint =
      activeHost?.endpoint ?? await pairingClient.getPairedEndpoint();

  runApp(SecureDeckApp(
    keyManager: keyManager,
    pairingClient: pairingClient,
    initialEndpoint: pairedEndpoint,
  ));
}

/// Aplicación principal configurada con estética Stream Deck Dark Mode de alto contraste.
class SecureDeckApp extends StatelessWidget {
  final KeyManager keyManager;
  final PairingClient pairingClient;
  final String? initialEndpoint;

  const SecureDeckApp({
    super.key,
    required this.keyManager,
    required this.pairingClient,
    this.initialEndpoint,
  });

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SecureDeck',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF090A0F),
        primaryColor: const Color(0xFF6366F1),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF6366F1),
          secondary: Color(0xFF10B981),
          surface: Color(0xFF11141C),
          background: Color(0xFF090A0F),
        ),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF11141C),
          elevation: 0,
        ),
      ),
      home: initialEndpoint != null
          ? DeckScreen(
              hostEndpoint: initialEndpoint!,
              pairingClient: pairingClient,
              keyManager: keyManager,
            )
          : ScannerScreen(
              pairingClient: pairingClient,
              keyManager: keyManager,
            ),
    );
  }
}
