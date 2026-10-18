import 'dart:convert';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:cryptography/cryptography.dart';

import 'package:remote_controler_mobile/crypto/key_manager.dart';
import 'package:remote_controler_mobile/crypto/canonical.dart';
import 'package:remote_controler_mobile/services/pairing_client.dart';

void main() {
  group('PairingClient - Validación y Canje de Código QR', () {
    late MemorySecureStorageAdapter storage;
    late KeyManager keyManager;
    late SimpleKeyPair hostKeyPair;
    late List<int> hostPubBytes;
    late String hostPubHex;
    late String hostDeviceId;

    setUp(() async {
      storage = MemorySecureStorageAdapter();
      keyManager = KeyManager(storage: storage);
      await keyManager.initialize();

      // Generar identidad simulada del Host
      final ed25519 = Ed25519();
      hostKeyPair = await ed25519.newKeyPair();
      final pubKey = await hostKeyPair.extractPublicKey();
      hostPubBytes = pubKey.bytes;
      hostPubHex =
          hostPubBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

      final sha256 = Sha256();
      final digest = await sha256.hash(hostPubBytes);
      hostDeviceId =
          digest.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    });

    Future<String> createValidQrJson(
        {int? customExpiresAt, String? customToken}) async {
      final expiresAt = customExpiresAt ??
          ((DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000) + 180);
      final token = customToken ?? 'valid_pairing_token_123';

      final canonicalData = {
        'expires_at': expiresAt,
        'host_device_id': hostDeviceId,
        'host_public_key_hex': hostPubHex,
        'pairing_token': token,
        'tailscale_endpoint': '100.85.12.34:8443',
        'version': 1,
      };

      final canonicalBytes = canonicalizeToBytes(canonicalData);
      final ed25519 = Ed25519();
      final sig = await ed25519.sign(canonicalBytes, keyPair: hostKeyPair);

      final fullChallenge = {
        ...canonicalData,
        'signature': base64.encode(sig.bytes),
      };

      return json.encode(fullChallenge);
    }

    test('Emparejamiento exitoso con firma del Host verificada', () async {
      final qrString = await createValidQrJson();

      final mockHttp = MockClient((request) async {
        expect(request.url.toString(), equals('http://100.85.12.34:8443/pair'));
        final body = json.decode(request.body) as Map<String, dynamic>;
        expect(body['pairing_token'], equals('valid_pairing_token_123'));
        expect(body['client_device_id'], equals(keyManager.deviceId));
        expect(body['client_public_key_hex'], equals(keyManager.publicKeyHex));

        return http.Response(
          json.encode({'status': 'SUCCESS', 'message': 'Device registered'}),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final pairingClient = PairingClient(
        keyManager: keyManager,
        storage: storage,
        httpClient: mockHttp,
      );

      final endpoint = await pairingClient.pairWithQrContent(qrString);
      expect(endpoint, equals('100.85.12.34:8443'));

      // Verificar que el endpoint y host_device_id quedaron persistidos
      expect(
          await pairingClient.getPairedEndpoint(), equals('100.85.12.34:8443'));
      expect(await pairingClient.getPairedHostDeviceId(), equals(hostDeviceId));
    });

    test('Rechazo si el código QR ha expirado', () async {
      // Expiró hace 20 segundos
      final expiredTime =
          (DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000) - 20;
      final qrString = await createValidQrJson(customExpiresAt: expiredTime);

      final pairingClient = PairingClient(
        keyManager: keyManager,
        storage: storage,
      );

      expect(
        () => pairingClient.pairWithQrContent(qrString),
        throwsA(isA<SecurityStorageException>().having(
          (e) => e.message,
          'message',
          contains('expirado'),
        )),
      );
    });

    test(
        'Rechazo si la firma digital del Host ha sido manipulada (Anti-Spoofing)',
        () async {
      final qrString = await createValidQrJson();
      final map = json.decode(qrString) as Map<String, dynamic>;

      // Un atacante altera el endpoint para redirigir tráfico
      map['tailscale_endpoint'] = '100.99.99.99:8443';
      final tamperedQrString = json.encode(map);

      final pairingClient = PairingClient(
        keyManager: keyManager,
        storage: storage,
      );

      expect(
        () => pairingClient.pairWithQrContent(tamperedQrString),
        throwsA(isA<SecurityStorageException>().having(
          (e) => e.message,
          'message',
          contains('firma digital del Host en el QR no es válida'),
        )),
      );
    });

    test('Desvinculación (unpair) elimina los datos de sesión', () async {
      await storage.write(PairingClient.keyPairedEndpoint, '100.85.12.34:8443');
      await storage.write(PairingClient.keyPairedHostDeviceId, hostDeviceId);

      final pairingClient = PairingClient(
        keyManager: keyManager,
        storage: storage,
      );

      expect(await pairingClient.getPairedEndpoint(), isNotNull);
      await pairingClient.unpair();
      expect(await pairingClient.getPairedEndpoint(), isNull);
      expect(await pairingClient.getPairedHostDeviceId(), isNull);
    });
  });
}
