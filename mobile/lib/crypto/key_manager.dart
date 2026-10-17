/// Gestor del ciclo de vida de claves criptográficas en el dispositivo móvil.
/// Utiliza almacenamiento seguro de hardware (Android Keystore / iOS Keychain) vía SecureStorageAdapter.
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

import 'canonical.dart';

class SecurityStorageException implements Exception {
  final String message;
  const SecurityStorageException(this.message);

  @override
  String toString() => 'SecurityStorageException: $message';
}

/// Contrato abstracto para el almacén seguro de hardware.
/// Permite desacoplar el core criptográfico de los plugins específicos de Flutter (Keystore/Keychain).
abstract class SecureStorageAdapter {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// Implementación de almacenamiento en memoria para testing y entornos aislados.
class MemorySecureStorageAdapter implements SecureStorageAdapter {
  final Map<String, String> _data = {};

  @override
  Future<String?> read(String key) async => _data[key];

  @override
  Future<void> write(String key, String value) async => _data[key] = value;

  @override
  Future<void> delete(String key) async => _data.remove(key);
}

class KeyManager {
  static const String _privateKeyStorageKey = 'rc_ed25519_private_key_v1';

  final SecureStorageAdapter _storage;
  final Ed25519 _ed25519;
  final Sha256 _sha256;

  SimpleKeyPair? _keyPair;
  List<int>? _publicKeyBytes;
  String? _deviceId;

  KeyManager({
    required SecureStorageAdapter storage,
    Ed25519? ed25519,
    Sha256? sha256,
  })  : _storage = storage,
        _ed25519 = ed25519 ?? Ed25519(),
        _sha256 = sha256 ?? Sha256();

  /// Comprueba si el gestor criptográfico ha completado su inicialización.
  bool get isInitialized => _keyPair != null && _deviceId != null && _publicKeyBytes != null;

  /// Asegura de forma asíncrona e idempotente que las claves estén cargadas o generadas.
  Future<void> ensureInitialized() async {
    if (!isInitialized) {
      await initialize();
    }
  }

  /// Inicializa el gestor: recupera la clave de hardware o genera una nueva de forma persistente.
  Future<void> initialize() async {
    if (isInitialized) return;

    String? storedKeyHex;
    try {
      storedKeyHex = await _storage.read(_privateKeyStorageKey);
    } catch (_) {
      storedKeyHex = null;
    }

    if (storedKeyHex != null && storedKeyHex.isNotEmpty) {
      try {
        // Reconstruir el par de claves desde los 32 bytes de semilla privada
        final privBytes = _hexToBytes(storedKeyHex);
        _keyPair = await _ed25519.newKeyPairFromSeed(privBytes);
      } catch (_) {
        _keyPair = null;
      }
    }

    if (_keyPair == null) {
      // Generar nuevo par de claves criptográficas Ed25519
      _keyPair = await _ed25519.newKeyPair();
      final privBytes = await _keyPair!.extractPrivateKeyBytes();
      try {
        await _storage.write(_privateKeyStorageKey, _bytesToHex(privBytes));
      } catch (_) {}
    }

    final pubKey = await _keyPair!.extractPublicKey();
    _publicKeyBytes = pubKey.bytes;

    // Calcular deviceId: SHA-256 de los 32 bytes de la clave pública (idéntico al Host en Python)
    final digest = await _sha256.hash(_publicKeyBytes!);
    _deviceId = _bytesToHex(digest.bytes).toLowerCase();
  }

  /// Retorna el fingerprint SHA-256 determinista del dispositivo móvil (64 caracteres hex).
  String get deviceId {
    if (_deviceId == null) {
      throw const SecurityStorageException('KeyManager no ha sido inicializado.');
    }
    return _deviceId!;
  }

  /// Retorna los 32 bytes crudos de la clave pública Ed25519.
  List<int> get publicKeyBytes {
    if (_publicKeyBytes == null) {
      throw const SecurityStorageException('KeyManager no ha sido inicializado.');
    }
    return List.unmodifiable(_publicKeyBytes!);
  }

  /// Retorna la clave pública en formato hexadecimal (64 caracteres).
  String get publicKeyHex {
    return _bytesToHex(publicKeyBytes);
  }

  /// Firma digitalmente un payload canónico RFC 8785 y retorna la firma en Base64.
  Future<String> signPayload(Map<String, dynamic> canonicalDict) async {
    if (!isInitialized) {
      await ensureInitialized();
    }
    if (_keyPair == null) {
      throw const SecurityStorageException('KeyManager no ha sido inicializado.');
    }

    // 1. Canonicalización determinista RFC 8785
    final canonicalBytes = canonicalizeToBytes(canonicalDict);

    // 2. Firma asimétrica Ed25519
    final signature = await _ed25519.sign(
      canonicalBytes,
      keyPair: _keyPair!,
    );

    // 3. Codificación en Base64 estándar
    return base64.encode(signature.bytes);
  }

  static String _bytesToHex(List<int> bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  static Uint8List _hexToBytes(String hex) {
    final clean = hex.replaceAll(' ', '');
    final result = Uint8List(clean.length ~/ 2);
    for (var i = 0; i < result.length; i++) {
      result[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return result;
  }
}
