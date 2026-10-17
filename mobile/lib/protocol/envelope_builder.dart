/// Constructor y firmador del SignedEnvelope para el cliente móvil.
/// Ensambla mensajes criptográficos cumpliendo con la especificación del Host.
library;

import 'dart:convert';
import 'dart:math';

import '../crypto/key_manager.dart';

class EnvelopeBuilder {
  final KeyManager _keyManager;
  final Random _secureRandom;

  EnvelopeBuilder({
    required KeyManager keyManager,
    Random? secureRandom,
  })  : _keyManager = keyManager,
        _secureRandom = secureRandom ?? Random.secure();

  /// Construye y firma un SignedEnvelope listo para transmitirse por WebSocket.
  /// 
  /// Mitigación de Vectores de Ataque:
  /// 1. Replay Attacks: Genera un nonce único CSPRNG de 16 bytes y timestamp UTC actual.
  /// 2. Tampering: Sella el mensaje con firma Ed25519 sobre el diccionario canónico JCS.
  Future<Map<String, dynamic>> buildSignedEnvelope({
    required String commandId,
    required Map<String, dynamic> payload,
    int? customTimestamp,
    String? customNonce,
  }) async {
    final timestampUtc = customTimestamp ?? (DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000);
    // Nonce de 32 caracteres hexadecimales (16 bytes de entropía segura CSPRNG)
    final nonce = customNonce ?? _generateSecureNonce();

    // Garantizar que la identidad criptográfica esté cargada
    await _keyManager.ensureInitialized();
    final deviceId = _keyManager.deviceId;

    // Diccionario canónico que será firmado
    final canonicalMap = {
      'command_id': commandId,
      'device_id': deviceId,
      'nonce': nonce,
      'payload': payload,
      'timestamp_utc': timestampUtc,
    };

    // Firma criptográfica generada sobre canonicalMap serializado bajo RFC 8785
    final signature = await _keyManager.signPayload(canonicalMap);

    return {
      'command_id': commandId,
      'device_id': deviceId,
      'nonce': nonce,
      'payload': payload,
      'signature': signature,
      'timestamp_utc': timestampUtc,
    };
  }

  /// Generador de nonces de 16 bytes (32 hex chars) utilizando CSPRNG nativo del OS (dart:math Random.secure).
  String _generateSecureNonce() {
    final values = List<int>.generate(16, (i) => _secureRandom.nextInt(256));
    return values.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Construye el SignedEnvelope y lo serializa a string JSON.
  Future<String> buildSignedEnvelopeJson({
    required String commandId,
    required Map<String, dynamic> payload,
  }) async {
    final map = await buildSignedEnvelope(
      commandId: commandId,
      payload: payload,
    );
    return json.encode(map);
  }
}
