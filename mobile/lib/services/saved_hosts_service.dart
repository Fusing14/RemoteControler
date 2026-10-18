/// Servicio de gestión y persistencia multi-PC (Multi-Host Manager).
/// Permite almacenar múltiples ordenadores vinculados, asignarles nombres personalizados,
/// monitorizar su estado de conexión mediante ping (/health) y alternar entre ellos.
library;

import 'dart:convert';
import 'package:http/http.dart' as http;

import '../crypto/key_manager.dart';
import 'secure_storage_adapter.dart';
import 'pairing_client.dart';

/// Modelo de datos que representa un ordenador (Host) guardado en el teléfono.
class SavedHost {
  final String id;
  final String customName;
  final String endpoint;
  final String deviceId;
  final String? macAddress;
  final String? broadcastIp;
  final int lastConnectedAt;

  const SavedHost({
    required this.id,
    required this.customName,
    required this.endpoint,
    required this.deviceId,
    this.macAddress,
    this.broadcastIp,
    required this.lastConnectedAt,
  });

  SavedHost copyWith({
    String? id,
    String? customName,
    String? endpoint,
    String? deviceId,
    String? macAddress,
    String? broadcastIp,
    int? lastConnectedAt,
  }) {
    return SavedHost(
      id: id ?? this.id,
      customName: customName ?? this.customName,
      endpoint: endpoint ?? this.endpoint,
      deviceId: deviceId ?? this.deviceId,
      macAddress: macAddress ?? this.macAddress,
      broadcastIp: broadcastIp ?? this.broadcastIp,
      lastConnectedAt: lastConnectedAt ?? this.lastConnectedAt,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'custom_name': customName,
        'endpoint': endpoint,
        'device_id': deviceId,
        'mac_address': macAddress,
        'broadcast_ip': broadcastIp,
        'last_connected_at': lastConnectedAt,
      };

  factory SavedHost.fromJson(Map<String, dynamic> json) => SavedHost(
        id: json['id'] as String? ??
            json['device_id'] as String? ??
            json['endpoint'] as String? ??
            'host_${DateTime.now().millisecondsSinceEpoch}',
        customName: json['custom_name'] as String? ?? 'Mi Ordenador',
        endpoint: json['endpoint'] as String? ?? '',
        deviceId: json['device_id'] as String? ?? '',
        macAddress: json['mac_address'] as String?,
        broadcastIp: json['broadcast_ip'] as String?,
        lastConnectedAt: json['last_connected_at'] as int? ?? 0,
      );
}

class SavedHostsService {
  static const String keyHostsList = 'rc_saved_hosts_list_v1';
  static const String keyActiveHostId = 'rc_active_host_id_v1';

  final SecureStorageAdapter _storage;
  final http.Client _httpClient;

  SavedHostsService({
    required SecureStorageAdapter storage,
    http.Client? httpClient,
  })  : _storage = storage,
        _httpClient = httpClient ?? http.Client();

  /// Inicializa y migra de forma transparente los datos del host individual anterior si existen.
  Future<void> ensureInitialized() async {
    final raw = await _storage.read(keyHostsList);
    if (raw != null && raw.trim().isNotEmpty) {
      return;
    }

    // Auto-migración desde las claves individuales anteriores de PairingClient
    final legacyEndpoint = await _storage.read(PairingClient.keyPairedEndpoint);
    if (legacyEndpoint != null && legacyEndpoint.trim().isNotEmpty) {
      final legacyDeviceId =
          await _storage.read(PairingClient.keyPairedHostDeviceId) ??
              'migrated-host';
      final legacyMac = await _storage.read(PairingClient.keyPairedMacAddress);
      final legacyBcast =
          await _storage.read(PairingClient.keyPairedBroadcastIp);

      final migratedHost = SavedHost(
        id: legacyDeviceId.isNotEmpty ? legacyDeviceId : legacyEndpoint,
        customName: 'Mi Ordenador Principal',
        endpoint: legacyEndpoint.trim(),
        deviceId: legacyDeviceId,
        macAddress: legacyMac,
        broadcastIp: legacyBcast,
        lastConnectedAt: DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000,
      );

      await saveHosts([migratedHost]);
      await setActiveHostId(migratedHost.id);
    }
  }

  /// Recupera la lista completa de ordenadores registrados.
  Future<List<SavedHost>> getHosts() async {
    await ensureInitialized();
    final raw = await _storage.read(keyHostsList);
    if (raw == null || raw.trim().isEmpty) {
      return [];
    }

    try {
      final list = json.decode(raw) as List<dynamic>;
      return list
          .whereType<Map<String, dynamic>>()
          .map((item) => SavedHost.fromJson(item))
          .toList();
    } catch (_) {
      return [];
    }
  }

  /// Guarda la lista completa de ordenadores.
  Future<void> saveHosts(List<SavedHost> hosts) async {
    final encoded = json.encode(hosts.map((h) => h.toJson()).toList());
    await _storage.write(keyHostsList, encoded);
  }

  /// Obtiene el identificador del ordenador actualmente activo.
  Future<String?> getActiveHostId() async {
    return _storage.read(keyActiveHostId);
  }

  /// Fija el ordenador activo y sincroniza las claves del PairingClient tradicional.
  Future<void> setActiveHostId(String hostId) async {
    await _storage.write(keyActiveHostId, hostId);

    // Sincronizar con las claves globales de PairingClient para compatibilidad retroactiva
    final hosts = await getHosts();
    final found = hosts.where((h) => h.id == hostId).firstOrNull;
    if (found != null) {
      await _storage.write(PairingClient.keyPairedEndpoint, found.endpoint);
      await _storage.write(PairingClient.keyPairedHostDeviceId, found.deviceId);
      if (found.macAddress != null) {
        await _storage.write(
            PairingClient.keyPairedMacAddress, found.macAddress!);
      }
      if (found.broadcastIp != null) {
        await _storage.write(
            PairingClient.keyPairedBroadcastIp, found.broadcastIp!);
      }
    }
  }

  /// Devuelve el Host actualmente seleccionado/activo.
  Future<SavedHost?> getActiveHost() async {
    final hosts = await getHosts();
    if (hosts.isEmpty) return null;

    final activeId = await getActiveHostId();
    if (activeId != null) {
      final match = hosts.where((h) => h.id == activeId).firstOrNull;
      if (match != null) return match;
    }

    return hosts.first;
  }

  /// Añade un nuevo ordenador o actualiza uno existente (por ID o endpoint).
  Future<SavedHost> addOrUpdateHost({
    required String endpoint,
    required String deviceId,
    String? customName,
    String? macAddress,
    String? broadcastIp,
  }) async {
    final hosts = await getHosts();
    final now = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    final hostId = deviceId.isNotEmpty ? deviceId : endpoint;

    final existingIndex =
        hosts.indexWhere((h) => h.id == hostId || h.endpoint == endpoint);

    SavedHost targetHost;
    if (existingIndex >= 0) {
      final prev = hosts[existingIndex];
      targetHost = prev.copyWith(
        endpoint: endpoint,
        deviceId: deviceId,
        customName: customName ?? prev.customName,
        macAddress: macAddress ?? prev.macAddress,
        broadcastIp: broadcastIp ?? prev.broadcastIp,
        lastConnectedAt: now,
      );
      hosts[existingIndex] = targetHost;
    } else {
      final defaultName = customName ?? 'PC ${hosts.length + 1}';
      targetHost = SavedHost(
        id: hostId,
        customName: defaultName,
        endpoint: endpoint,
        deviceId: deviceId,
        macAddress: macAddress,
        broadcastIp: broadcastIp,
        lastConnectedAt: now,
      );
      hosts.add(targetHost);
    }

    await saveHosts(hosts);
    await setActiveHostId(targetHost.id);
    return targetHost;
  }

  /// Renombra un ordenador guardado.
  Future<void> renameHost(String hostId, String newName) async {
    final hosts = await getHosts();
    final index = hosts.indexWhere((h) => h.id == hostId);
    if (index >= 0) {
      hosts[index] = hosts[index].copyWith(customName: newName.trim());
      await saveHosts(hosts);
    }
  }

  /// Elimina un ordenador de la lista.
  Future<void> removeHost(String hostId) async {
    final hosts = await getHosts();
    hosts.removeWhere((h) => h.id == hostId);
    await saveHosts(hosts);

    final activeId = await getActiveHostId();
    if (activeId == hostId) {
      if (hosts.isNotEmpty) {
        await setActiveHostId(hosts.first.id);
      } else {
        await _storage.delete(keyActiveHostId);
        await _storage.delete(PairingClient.keyPairedEndpoint);
        await _storage.delete(PairingClient.keyPairedHostDeviceId);
        await _storage.delete(PairingClient.keyPairedMacAddress);
        await _storage.delete(PairingClient.keyPairedBroadcastIp);
      }
    }
  }

  /// Comprueba en tiempo récord (timeout 1.5s) si un PC está encendido y accesible en la red.
  Future<bool> pingHost(String endpoint) async {
    if (endpoint.trim().isEmpty) return false;
    try {
      final clean = endpoint.trim().replaceAll(RegExp(r'^https?://'), '');
      final url = Uri.parse('http://$clean/health');
      final res = await _httpClient
          .get(url)
          .timeout(const Duration(milliseconds: 1500));
      return res.statusCode == 200;
    } catch (_) {
      return false;
    }
  }
}
