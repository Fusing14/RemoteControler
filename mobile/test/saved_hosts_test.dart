import 'dart:convert';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'package:remote_controler_mobile/crypto/key_manager.dart';
import 'package:remote_controler_mobile/services/pairing_client.dart';
import 'package:remote_controler_mobile/services/saved_hosts_service.dart';

void main() {
  group('SavedHostsService - Multi-PC y Auto-Migración', () {
    late MemorySecureStorageAdapter storage;

    setUp(() {
      storage = MemorySecureStorageAdapter();
    });

    test('Auto-migración transparente desde almacenamiento legado', () async {
      await storage.write(PairingClient.keyPairedEndpoint, '100.85.12.34:8443');
      await storage.write(
          PairingClient.keyPairedHostDeviceId, 'host-device-abc');
      await storage.write(
          PairingClient.keyPairedMacAddress, '30:56:0F:23:15:2C');
      await storage.write(PairingClient.keyPairedBroadcastIp, '192.168.1.255');

      final service = SavedHostsService(storage: storage);
      await service.ensureInitialized();

      final hosts = await service.getHosts();
      expect(hosts.length, equals(1));
      expect(hosts.first.endpoint, equals('100.85.12.34:8443'));
      expect(hosts.first.deviceId, equals('host-device-abc'));
      expect(hosts.first.macAddress, equals('30:56:0F:23:15:2C'));
      expect(hosts.first.broadcastIp, equals('192.168.1.255'));

      final active = await service.getActiveHost();
      expect(active, isNotNull);
      expect(active!.endpoint, equals('100.85.12.34:8443'));
    });

    test('Añadir múltiples ordenadores y alternar el PC activo', () async {
      final service = SavedHostsService(storage: storage);

      await service.addOrUpdateHost(
        endpoint: '100.1.1.1:8443',
        deviceId: 'pc-1',
        customName: 'PC Sobremesa',
      );

      await service.addOrUpdateHost(
        endpoint: '100.2.2.2:8443',
        deviceId: 'pc-2',
        customName: 'Portátil Trabajo',
      );

      var hosts = await service.getHosts();
      expect(hosts.length, equals(2));

      // El último añadido queda como activo
      var active = await service.getActiveHost();
      expect(active?.id, equals('pc-2'));

      // Alternar al primer PC
      await service.setActiveHostId('pc-1');
      active = await service.getActiveHost();
      expect(active?.id, equals('pc-1'));
      expect(active?.customName, equals('PC Sobremesa'));

      // Comprobar compatibilidad con PairingClient
      expect(await storage.read(PairingClient.keyPairedEndpoint),
          equals('100.1.1.1:8443'));
    });

    test('Renombrar y eliminar ordenadores', () async {
      final service = SavedHostsService(storage: storage);

      await service.addOrUpdateHost(
        endpoint: '100.1.1.1:8443',
        deviceId: 'pc-1',
        customName: 'PC Viejo',
      );

      await service.renameHost('pc-1', 'PC Gaming Actualizado');
      var hosts = await service.getHosts();
      expect(hosts.first.customName, equals('PC Gaming Actualizado'));

      await service.removeHost('pc-1');
      hosts = await service.getHosts();
      expect(hosts.isEmpty, isTrue);

      final active = await service.getActiveHost();
      expect(active, isNull);
    });

    test('Ping de salud (/health) a través de mock client', () async {
      final mockClient = MockClient((request) async {
        if (request.url.path == '/health' &&
            request.url.host == '100.10.20.30') {
          return http.Response(json.encode({'status': 'ok'}), 200);
        }
        return http.Response('Not Found', 404);
      });

      final service = SavedHostsService(
        storage: storage,
        httpClient: mockClient,
      );

      final isOnline = await service.pingHost('100.10.20.30:8443');
      expect(isOnline, isTrue);

      final isOffline = await service.pingHost('100.99.99.99:8443');
      expect(isOffline, isFalse);
    });
  });
}
