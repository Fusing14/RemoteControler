/// Constructor y firmador del SignedEnvelope para el cliente móvil.
/// Ensambla mensajes criptográficos cumpliendo con la especificación del Host.
library;

import 'dart:convert';
import 'package:uuid/uuid.dart';

import '../crypto/key_manager.dart';

class EnvelopeBuilder {
  final KeyManager _keyManager;
  final Uuid _uuid;

  EnvelopeBuilder({
    required KeyManager keyManager,
    Uuid? uuid,
  })  : _keyManager = keyManager,
        _uuid = uuid ?? const Uuid();

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
    // Nonce de 32 caracteres hexadecimales (16 bytes de entropía segura)
    final nonce = customNonce ?? _uuid.v4().replaceAll('-', '').toLowerCase();
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
