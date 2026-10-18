import 'dart:convert';
import 'package:test/test.dart';
import 'package:cryptography/cryptography.dart';

import 'package:remote_controler_mobile/crypto/canonical.dart';
import 'package:remote_controler_mobile/crypto/key_manager.dart';
import 'package:remote_controler_mobile/protocol/envelope_builder.dart';

void main() {
  group('RFC 8785 (JCS) Canonicalization in Dart', () {
    test('Ordenación estricta de claves por código UTF-16', () {
      final dictA = {'b': 2, 'a': 1, 'c': 3};
      final dictB = {'a': 1, 'c': 3, 'b': 2};
      final dictC = {'c': 3, 'b': 2, 'a': 1};

      final strA = canonicalizeJson(dictA);
      final strB = canonicalizeJson(dictB);
      final strC = canonicalizeJson(dictC);

      expect(strA, equals('{"a":1,"b":2,"c":3}'));
      expect(strA, equals(strB));
      expect(strB, equals(strC));
    });

    test(
        'Objetos anidados y estructuras complejas (Vectores idénticos a Python)',
        () {
      final nested = {
        'z': {'y': 2, 'x': 1},
        'a': [
          3,
          2,
          {'b': true, 'a': null}
        ]
      };
      const expected = '{"a":[3,2,{"a":null,"b":true}],"z":{"x":1,"y":2}}';
      expect(canonicalizeJson(nested), equals(expected));
    });

    test('Ausencia total de espacios en blanco', () {
      final data = {'key': 'value with spaces', 'number': 42};
      final result = canonicalizeJson(data);

      expect(result.contains(': '), isFalse);
      expect(result.contains(', '), isFalse);
      expect(result, equals('{"key":"value with spaces","number":42}'));
    });
  });

  group('KeyManager y Almacén Seguro', () {
    test('Inicialización y persistencia de clave en SecureStorageAdapter',
        () async {
      final storage = MemorySecureStorageAdapter();
      final keyManager1 = KeyManager(storage: storage);

      await keyManager1.initialize();
      final deviceId1 = keyManager1.deviceId;
      final pubKeyHex1 = keyManager1.publicKeyHex;

      expect(deviceId1.length, equals(64)); // SHA-256 hex string
      expect(pubKeyHex1.length, equals(64)); // 32 bytes hex

      // Simular reinicio de la app instanciando un segundo KeyManager con el mismo storage
      final keyManager2 = KeyManager(storage: storage);
      await keyManager2.initialize();

      expect(keyManager2.deviceId, equals(deviceId1));
      expect(keyManager2.publicKeyHex, equals(pubKeyHex1));
    });

    test('Firma digital asimétrica Ed25519 verificada con la clave pública',
        () async {
      final storage = MemorySecureStorageAdapter();
      final keyManager = KeyManager(storage: storage);
      await keyManager.initialize();

      final messageMap = {
        'action': 'PLAY_PAUSE',
        'timestamp': 1773715200,
        'force': false
      };

      final signatureB64 = await keyManager.signPayload(messageMap);
      expect(signatureB64.isNotEmpty, isTrue);

      // Verificación independiente con la librería de criptografía
      final canonicalBytes = canonicalizeToBytes(messageMap);
      final rawSignature = base64.decode(signatureB64);

      final ed25519 = Ed25519();
      final pubKey = SimplePublicKey(
        keyManager.publicKeyBytes,
        type: KeyPairType.ed25519,
      );

      final isValid = await ed25519.verify(
        canonicalBytes,
        signature: Signature(rawSignature, publicKey: pubKey),
      );

      expect(isValid, isTrue);
    });
  });

  group('EnvelopeBuilder y Contratos de Mensajería', () {
    test('Ensamblado y firma de SignedEnvelope para despacho al Host',
        () async {
      final storage = MemorySecureStorageAdapter();
      final keyManager = KeyManager(storage: storage);
      await keyManager.initialize();

      final builder = EnvelopeBuilder(keyManager: keyManager);
      final envelope = await builder.buildSignedEnvelope(
        commandId: 'MEDIA',
        payload: {'action': 'PLAY_PAUSE'},
        customTimestamp: 1773715200,
        customNonce: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
      );

      expect(envelope['command_id'], equals('MEDIA'));
      expect(envelope['device_id'], equals(keyManager.deviceId));
      expect(envelope['nonce'], equals('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'));
      expect(envelope['timestamp_utc'], equals(1773715200));
      expect(envelope['signature'], isA<String>());

      // Verificar que la firma cubre exactamente el sobre canónico
      final canonicalMap = {
        'command_id': 'MEDIA',
        'device_id': keyManager.deviceId,
        'nonce': 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
        'payload': {'action': 'PLAY_PAUSE'},
        'timestamp_utc': 1773715200,
      };

      final canonicalBytes = canonicalizeToBytes(canonicalMap);
      final rawSignature = base64.decode(envelope['signature'] as String);

      final ed25519 = Ed25519();
      final pubKey = SimplePublicKey(
        keyManager.publicKeyBytes,
        type: KeyPairType.ed25519,
      );

      final isValid = await ed25519.verify(
        canonicalBytes,
        signature: Signature(rawSignature, publicKey: pubKey),
      );

      expect(isValid, isTrue);
    });
  });
}
