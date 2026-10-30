import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'package:remote_controler_mobile/transport/certificate_pinning.dart';
import 'package:remote_controler_mobile/services/wol_service.dart';
import 'package:remote_controler_mobile/services/saved_hosts_service.dart';
import 'package:remote_controler_mobile/crypto/key_manager.dart';

void main() {
  group('Fase 1 #6 & #4 - Certificate Pinning SHA-256 y Tiempo Constante', () {
    test('Calcula SHA-256 síncrono correctamente y compara en tiempo constante', () {
      final sampleDer = Uint8List.fromList(utf8.encode('SecureDeck-Test-Certificate-DER'));
      final fp1 = CertificatePinningVerifier.computeSha256HexSync(sampleDer);
      final fp2 = CertificatePinningVerifier.computeSha256HexSync(sampleDer);

      expect(fp1.length, equals(64));
      expect(CertificatePinningVerifier.constantTimeEquals(fp1, fp2), isTrue);
      expect(
        CertificatePinningVerifier.constantTimeEquals(fp1, fp1.toUpperCase()),
        isTrue,
      );
      expect(
        CertificatePinningVerifier.constantTimeEquals(fp1, '0' * 64),
        isFalse,
      );
      expect(
        CertificatePinningVerifier.constantTimeEquals(fp1, ''),
        isFalse,
      );
    });

    test('verifyCertificateDer rechaza certificados sin pin o con huella distinta (MitM)', () {
      final legitimateDer = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final attackerDer = Uint8List.fromList([9, 9, 9, 9, 9, 9, 9, 9]);
      final pinnedHex = CertificatePinningVerifier.computeSha256HexSync(legitimateDer);

      // Certificado legítimo coincide con el pin del QR
      expect(
        CertificatePinningVerifier.verifyCertificateDer(legitimateDer, pinnedHex),
        isTrue,
      );

      // Certificado de atacante MitM es rechazado tajantemente
      expect(
        CertificatePinningVerifier.verifyCertificateDer(attackerDer, pinnedHex),
        isFalse,
      );

      // Sin fingerprint anclado se rechaza por defecto (Zero-Trust)
      expect(
        CertificatePinningVerifier.verifyCertificateDer(legitimateDer, null),
        isFalse,
      );
      expect(
        CertificatePinningVerifier.verifyCertificateDer(legitimateDer, ''),
        isFalse,
      );
    });
  });

  group('Fase 2 - Wake-on-LAN Multi-Ruta y Magic Packet', () {
    test('Construye Magic Packet de 102 bytes y limpia separadores (: - espacios)', () {
      final pkt1 = WolService.buildMagicPacket('30:56:0F:23:15:2C');
      final pkt2 = WolService.buildMagicPacket('30-56-0f-23-15-2c');
      final pkt3 = WolService.buildMagicPacket('3056 0F23 152C');

      expect(pkt1.length, equals(102));
      expect(pkt1, equals(pkt2));
      expect(pkt1, equals(pkt3));

      // Cabecera de 6 bytes 0xFF
      for (var i = 0; i < 6; i++) {
        expect(pkt1[i], equals(0xFF));
      }

      // 16 repeticiones de la MAC
      final expectedMac = [0x30, 0x56, 0x0F, 0x23, 0x15, 0x2C];
      for (var rep = 0; rep < 16; rep++) {
        for (var b = 0; b < 6; b++) {
          expect(pkt1[6 + rep * 6 + b], equals(expectedMac[b]));
        }
      }
    });

    test('Rechaza direcciones MAC inválidas, nulas o de broadcast', () {
      expect(() => WolService.buildMagicPacket('invalid'), throwsArgumentError);
      expect(() => WolService.buildMagicPacket('00:00:00:00:00:00'), throwsArgumentError);
      expect(() => WolService.buildMagicPacket('FF:FF:FF:FF:FF:FF'), throwsArgumentError);
    });

    test('Calcula destinos Multi-Ruta (Broadcast global, Subred LAN, Unicast LAN y Tailscale)', () {
      final targets = WolService.computeMultiRouteTargets(
        broadcastIp: '192.168.1.255',
        lanIp: '192.168.1.50',
        hostIpOrEndpoint: '100.88.44.12:8443',
        localInterfaceIps: ['192.168.0.15'],
      );

      expect(targets, contains('255.255.255.255'));
      expect(targets, contains('192.168.1.255'));
      expect(targets, contains('192.168.1.50'));
      expect(targets, contains('100.88.44.12'));
      expect(targets, contains('192.168.0.255'));
      expect( WolService.defaultWolPorts, containsAll([7, 9, 40000]));
    });

    test('wakeWithRetryAndPolling detecta encendido mediante polling /health', () async {
      var healthCalls = 0;
      final mockHttp = MockClient((http.Request req) async {
        healthCalls++;
        if (healthCalls >= 2 && req.url.path == '/health') {
          return http.Response('{"status":"OK"}', 200);
        }
        return http.Response('Offline', 503);
      });

      final progressSteps = <int>[];
      final woke = await WolService.wakeWithRetryAndPolling(
        macAddress: '30:56:0F:23:15:2C',
        broadcastIp: '192.168.1.255',
        lanIp: '192.168.1.50',
        hostIpOrEndpoint: '100.88.44.12:8443',
        retryInterval: const Duration(milliseconds: 20),
        totalDuration: const Duration(milliseconds: 100),
        onProgress: (attempt, _) => progressSteps.add(attempt),
        httpClient: mockHttp,
      );

      expect(woke, isTrue);
      expect(progressSteps, isNotEmpty);
    });
  });

  group('SavedHostsService - Persistencia de lanIp y certFingerprint', () {
    test('Guarda y recupera lanIp y certFingerprint en SavedHost', () async {
      final storage = MemorySecureStorageAdapter();
      final service = SavedHostsService(storage: storage);

      await service.addOrUpdateHost(
        endpoint: '100.75.10.20:8443',
        deviceId: 'host_dev_123',
        customName: 'PC Gaming',
        macAddress: 'AA:BB:CC:DD:EE:FF',
        broadcastIp: '192.168.1.255',
        lanIp: '192.168.1.100',
        certFingerprint: 'a' * 64,
      );

      final active = await service.getActiveHost();
      expect(active, isNotNull);
      expect(active!.lanIp, equals('192.168.1.100'));
      expect(active.broadcastIp, equals('192.168.1.255'));
      expect(active.macAddress, equals('AA:BB:CC:DD:EE:FF'));
      expect(active.certFingerprint, equals('a' * 64));
    });
  });
}
