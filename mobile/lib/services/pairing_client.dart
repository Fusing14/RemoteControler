/// Cliente de emparejamiento seguro fuera de banda (QR Scanning & Pairing Exchange).
/// Valida la firma del Host antes de establecer la conexión o enviar credenciales.
library;

import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:cryptography/cryptography.dart';

import '../crypto/key_manager.dart';
import '../crypto/canonical.dart';

class PairingClient {
  static const String keyPairedEndpoint = 'rc_paired_endpoint_v1';
  static const String keyPairedHostDeviceId = 'rc_paired_host_device_id_v1';
  static const String keyPairedMacAddress = 'rc_paired_mac_address';
  static const String keyPairedBroadcastIp = 'rc_paired_broadcast_ip';

  final KeyManager _keyManager;
  final SecureStorageAdapter _storage;
  final http.Client _httpClient;

  PairingClient({
    required KeyManager keyManager,
    required SecureStorageAdapter storage,
    http.Client? httpClient,
  })  : _keyManager = keyManager,
        _storage = storage,
        _httpClient = httpClient ?? http.Client();

  KeyManager get keyManager => _keyManager;
  SecureStorageAdapter get storage => _storage;

  /// Procesa el contenido crudo escaneado desde el código QR:
  /// 1. Parsea el JSON del desafío emitido por el Host.
  /// 2. Comprueba que el token no haya expirado (TTL de 3 minutos).
  /// 3. Verifica criptográficamente la firma Ed25519 del Host.
  /// 4. Realiza la llamada HTTP POST /pair para intercambiar credenciales.
  /// 5. Persiste el endpoint de Tailscale y la identidad del Host en almacenamiento seguro.
  Future<String> pairWithQrContent(
    String qrContent, {
    String deviceLabel = 'Mobile Control Client',
  }) async {
    await _keyManager.ensureInitialized();

    Map<String, dynamic> challenge;
    try {
      challenge = json.decode(qrContent) as Map<String, dynamic>;
    } catch (e) {
      throw const SecurityStorageException(
          'El código QR escaneado no contiene un formato JSON válido.');
    }

    final requiredFields = [
      'host_device_id',
      'host_public_key_hex',
      'tailscale_endpoint',
      'pairing_token',
      'expires_at',
      'signature'
    ];
    for (final field in requiredFields) {
      if (!challenge.containsKey(field)) {
        throw SecurityStorageException(
            'Código QR incompleto: falta el campo obligatorio "$field".');
      }
    }

    // 1. Control de expiración del token
    final expiresAt = challenge['expires_at'] as int;
    final now = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    if (now > expiresAt) {
      throw const SecurityStorageException(
          'El código QR de emparejamiento ha expirado. Genera uno nuevo en el Host.');
    }

    // 2. Verificación criptográfica de la firma del Host
    final hostPubHex = challenge['host_public_key_hex'] as String;
    final hostPubBytes = _hexToBytes(hostPubHex);
    final hostPubKey = SimplePublicKey(hostPubBytes, type: KeyPairType.ed25519);

    final canonicalData = {
      'expires_at': expiresAt,
      'host_device_id': challenge['host_device_id'],
      'host_public_key_hex': hostPubHex,
      'pairing_token': challenge['pairing_token'],
      'tailscale_endpoint': challenge['tailscale_endpoint'],
      'version': challenge['version'] ?? 1,
    };

    final canonicalBytes = canonicalizeToBytes(canonicalData);
    final rawSignature = base64.decode(challenge['signature'] as String);

    final ed25519 = Ed25519();
    final isHostSignatureValid = await ed25519.verify(
      canonicalBytes,
      signature: Signature(rawSignature, publicKey: hostPubKey),
    );

    if (!isHostSignatureValid) {
      throw const SecurityStorageException(
        'ALERTA DE SEGURIDAD: La firma digital del Host en el QR no es válida. '
        'Posible código QR falsificado o ataque de suplantación en curso.',
      );
    }

    // 3. Intercambio HTTP seguro vía POST /pair
    final endpoint = challenge['tailscale_endpoint'] as String;
    final url = Uri.parse('http://$endpoint/pair');

    final requestBody = json.encode({
      'pairing_token': challenge['pairing_token'],
      'client_public_key_hex': _keyManager.publicKeyHex,
      'client_device_id': _keyManager.deviceId,
      'label': deviceLabel,
    });

    http.Response response;
    try {
      response = await _httpClient
          .post(
            url,
            headers: {'Content-Type': 'application/json'},
            body: requestBody,
          )
          .timeout(const Duration(seconds: 10));
    } catch (e) {
      throw SecurityStorageException(
        'Fallo de conexión al contactar el Host en $endpoint. '
        'Verifica que Tailscale esté activo y conectado en este teléfono.',
      );
    }

    if (response.statusCode != 200) {
      throw SecurityStorageException(
          'El Host rechazó el emparejamiento (HTTP ${response.statusCode}).');
    }

    // 4. Persistencia del endpoint verificado en Hardware Keystore / Keychain
    await _storage.write(keyPairedEndpoint, endpoint);
    await _storage.write(
        keyPairedHostDeviceId, challenge['host_device_id'] as String);

    if (challenge.containsKey('mac_address') &&
        challenge['mac_address'] != null) {
      await _storage.write(
          keyPairedMacAddress, challenge['mac_address'] as String);
    }
    if (challenge.containsKey('broadcast_ip') &&
        challenge['broadcast_ip'] != null) {
      await _storage.write(
          keyPairedBroadcastIp, challenge['broadcast_ip'] as String);
    }

    return endpoint;
  }

  /// Recupera el endpoint del Host emparejado previamente, si existe.
  Future<String?> getPairedEndpoint() async {
    return _storage.read(keyPairedEndpoint);
  }

  /// Recupera el device_id del Host emparejado.
  Future<String?> getPairedHostDeviceId() async {
    return _storage.read(keyPairedHostDeviceId);
  }

  /// Recupera la dirección MAC guardada para Wake-on-LAN.
  Future<String?> getPairedMacAddress() async {
    return _storage.read(keyPairedMacAddress);
  }

  /// Guarda o actualiza la dirección MAC para Wake-on-LAN.
  Future<void> savePairedMacAddress(String mac) async {
    await _storage.write(keyPairedMacAddress, mac);
  }

  /// Recupera la IP de difusión de la subred local.
  Future<String?> getPairedBroadcastIp() async {
    return _storage.read(keyPairedBroadcastIp);
  }

  /// Guarda la IP de difusión para Wake-on-LAN.
  Future<void> savePairedBroadcastIp(String ip) async {
    await _storage.write(keyPairedBroadcastIp, ip);
  }

  /// Desvincula el teléfono del Host y purga los secretos de sesión.
  Future<void> unpair() async {
    await _storage.delete(keyPairedEndpoint);
    await _storage.delete(keyPairedHostDeviceId);
    await _storage.delete(keyPairedMacAddress);
    await _storage.delete(keyPairedBroadcastIp);
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
