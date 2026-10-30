import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:http/http.dart' as http;

/// Servicio de encendido remoto en frío (Wake-on-LAN Multi-Ruta).
/// Resuelve el problema de Tailscale inactivo cuando el PC está apagado (S5)
/// enviando ráfagas simultáneas en los puertos UDP 7, 9 y 40000 hacia:
/// 1) 255.255.255.255 (Broadcast global LAN)
/// 2) El broadcast dirigido de la subred local del PC (ej. 192.168.1.255 / 192.168.0.255)
/// 3) Unicast directo a la IP LAN física del PC y a la IP de Tailscale (para Subnet Routers / ARP).
class WolService {
  static const List<int> defaultWolPorts = [7, 9, 40000];

  /// Normaliza y valida una dirección MAC (formato XX:XX:XX:XX:XX:XX).
  static String normalizeMacAddress(String macAddress) {
    final cleanMac =
        macAddress.replaceAll(RegExp(r'[^a-fA-F0-9]'), '').toUpperCase();
    if (cleanMac.length != 12) {
      throw ArgumentError(
          'Dirección MAC no válida (debe contener 12 dígitos hexadecimales): $macAddress');
    }
    if (cleanMac == '000000000000' || cleanMac == 'FFFFFFFFFFFF') {
      throw ArgumentError(
          'Dirección MAC nula o reservada no válida: $macAddress');
    }
    final pairs = <String>[];
    for (var i = 0; i < 12; i += 2) {
      pairs.add(cleanMac.substring(i, i + 2));
    }
    return pairs.join(':');
  }

  /// Construye un paquete mágico Wake-on-LAN estándar de 102 bytes:
  /// 6 bytes de 0xFF seguidos de 16 repeticiones de la dirección MAC de 6 bytes.
  static Uint8List buildMagicPacket(String macAddress) {
    final norm = normalizeMacAddress(macAddress).replaceAll(':', '');
    final macBytes = Uint8List(6);
    for (var i = 0; i < 6; i++) {
      macBytes[i] = int.parse(norm.substring(i * 2, i * 2 + 2), radix: 16);
    }

    final packet = Uint8List(102);
    for (var i = 0; i < 6; i++) {
      packet[i] = 0xFF;
    }
    for (var i = 0; i < 16; i++) {
      packet.setRange(6 + i * 6, 6 + (i + 1) * 6, macBytes);
    }

    return packet;
  }

  /// Calcula la lista deduplicada de destinos IPv4 (Broadcast global, Broadcast de subred,
  /// Unicast LAN y Unicast Tailscale) para la estrategia Multi-Ruta.
  static Set<String> computeMultiRouteTargets({
    String? broadcastIp,
    String? lanIp,
    String? hostIpOrEndpoint,
    Iterable<String> localInterfaceIps = const [],
  }) {
    final targets = <String>{'255.255.255.255'};

    void addIpAndSubnetBroadcast(String? rawIp, {bool includeUnicast = true}) {
      if (rawIp == null || rawIp.trim().isEmpty) return;
      final clean = rawIp
          .trim()
          .replaceAll(RegExp(r'^(https?|wss?)://'), '')
          .split('/')
          .first
          .split(':')
          .first
          .trim();
      final parts = clean.split('.');
      if (parts.length != 4) return;
      if (parts.any((p) => int.tryParse(p) == null)) return;
      if (clean.startsWith('127.')) return;

      if (includeUnicast) {
        targets.add(clean);
      }
      if (!clean.startsWith('100.') && !clean.endsWith('.255')) {
        targets.add('${parts[0]}.${parts[1]}.${parts[2]}.255');
      }
    }

    if (broadcastIp != null && broadcastIp.trim().isNotEmpty) {
      addIpAndSubnetBroadcast(broadcastIp, includeUnicast: true);
    }
    if (lanIp != null && lanIp.trim().isNotEmpty) {
      addIpAndSubnetBroadcast(lanIp, includeUnicast: true);
    }
    if (hostIpOrEndpoint != null && hostIpOrEndpoint.trim().isNotEmpty) {
      addIpAndSubnetBroadcast(hostIpOrEndpoint, includeUnicast: true);
    }
    for (final ifaceIp in localInterfaceIps) {
      addIpAndSubnetBroadcast(ifaceIp, includeUnicast: false);
    }

    return targets;
  }

  /// Envía ráfagas Multi-Ruta del Magic Packet por UDP en los puertos 7, 9 y 40000.
  static Future<int> wake({
    required String macAddress,
    String? broadcastIp,
    String? lanIp,
    String? hostIpOrEndpoint,
    List<int> ports = defaultWolPorts,
  }) async {
    final packet = buildMagicPacket(macAddress);
    final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    socket.broadcastEnabled = true;

    final localIps = <String>[];
    try {
      final interfaces = await NetworkInterface.list(
        type: InternetAddressType.IPv4,
        includeLoopback: false,
      );
      for (final iface in interfaces) {
        for (final addr in iface.addresses) {
          if (!addr.isLoopback) {
            localIps.add(addr.address);
          }
        }
      }
    } catch (_) {}

    final targetStrings = computeMultiRouteTargets(
      broadcastIp: broadcastIp,
      lanIp: lanIp,
      hostIpOrEndpoint: hostIpOrEndpoint,
      localInterfaceIps: localIps,
    );

    final targetAddresses = <InternetAddress>[];
    for (final ipStr in targetStrings) {
      try {
        final parsed = InternetAddress(ipStr);
        if (parsed.type == InternetAddressType.IPv4) {
          targetAddresses.add(parsed);
        }
      } catch (_) {}
    }

    var sentPackets = 0;
    try {
      // Dos ráfagas separadas por 80ms para despertar NICs con ahorro de energía (EEE / ARP Offload)
      for (var burst = 0; burst < 2; burst++) {
        for (final port in ports) {
          for (final target in targetAddresses) {
            try {
              final written = socket.send(packet, target, port);
              if (written > 0) {
                sentPackets++;
              }
            } catch (_) {}
          }
        }
        if (burst == 0) {
          await Future.delayed(const Duration(milliseconds: 80));
        }
      }
    } finally {
      socket.close();
    }
    return sentPackets;
  }

  /// Ejecuta el bucle de encendido resiliente: envía ráfagas Multi-Ruta cada [retryInterval]
  /// (por defecto 2 segundos) durante [totalDuration] (por defecto 15 segundos) mientras
  /// realiza polling activo al endpoint `/health` del Host para detectar cuándo ha encendido.
  static Future<bool> wakeWithRetryAndPolling({
    required String macAddress,
    String? broadcastIp,
    String? lanIp,
    String? hostIpOrEndpoint,
    Duration retryInterval = const Duration(seconds: 2),
    Duration totalDuration = const Duration(seconds: 15),
    void Function(int attempt, int maxAttempts)? onProgress,
    http.Client? httpClient,
  }) async {
    final client = httpClient ?? http.Client();
    final shouldCloseClient = httpClient == null;
    final maxAttempts =
        (totalDuration.inMilliseconds / retryInterval.inMilliseconds)
            .ceil()
            .clamp(1, 15);

    int port = 8443;
    String? cleanEndpointHost;
    if (hostIpOrEndpoint != null && hostIpOrEndpoint.trim().isNotEmpty) {
      final cleaned =
          hostIpOrEndpoint.trim().replaceAll(RegExp(r'^https?://'), '');
      final parts = cleaned.split(':');
      cleanEndpointHost = parts.first;
      if (parts.length > 1) {
        port = int.tryParse(parts[1]) ?? 8443;
      }
    }

    Future<bool> checkHealth(String? host) async {
      if (host == null || host.isEmpty || host.startsWith('127.')) return false;
      try {
        final uri = Uri.parse('http://$host:$port/health');
        final res =
            await client.get(uri).timeout(const Duration(milliseconds: 900));
        return res.statusCode == 200;
      } catch (_) {
        return false;
      }
    }

    try {
      for (var attempt = 1; attempt <= maxAttempts; attempt++) {
        onProgress?.call(attempt, maxAttempts);

        await wake(
          macAddress: macAddress,
          broadcastIp: broadcastIp,
          lanIp: lanIp,
          hostIpOrEndpoint: hostIpOrEndpoint,
        );

        // Comprobar si el Host ya responde por Tailscale o por IP LAN local
        if (await checkHealth(cleanEndpointHost)) {
          return true;
        }
        if (lanIp != null &&
            lanIp != cleanEndpointHost &&
            await checkHealth(lanIp)) {
          return true;
        }

        if (attempt < maxAttempts) {
          await Future.delayed(retryInterval);
        }
      }
      return false;
    } finally {
      if (shouldCloseClient) {
        client.close();
      }
    }
  }
}
