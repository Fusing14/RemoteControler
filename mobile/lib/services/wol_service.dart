import 'dart:io';
import 'dart:typed_data';

/// Servicio para enviar paquetes mágicos Wake-on-LAN (WoL) para encender
/// el PC en frío a través de difusión UDP en la red local.
class WolService {
  /// Construye un paquete mágico Wake-on-LAN estándar de 102 bytes:
  /// 6 bytes de 0xFF seguidos de 16 repeticiones de la dirección MAC de 6 bytes.
  static Uint8List buildMagicPacket(String macAddress) {
    final cleanMac = macAddress.replaceAll(RegExp(r'[^a-fA-F0-9]'), '');
    if (cleanMac.length != 12) {
      throw ArgumentError(
          'Dirección MAC no válida (debe contener 12 dígitos hexadecimales): $macAddress');
    }

    final macBytes = Uint8List(6);
    for (var i = 0; i < 6; i++) {
      macBytes[i] = int.parse(cleanMac.substring(i * 2, i * 2 + 2), radix: 16);
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

  /// Envía el paquete mágico Wake-on-LAN por difusión UDP en los puertos 9 y 7.
  /// Difunde a 255.255.255.255, a la IP de difusión de la subred local (/24 calculada o explícita).
  /// Realiza un reintento tras 100ms para asegurar la recepción en adaptadores en reposo.
  static Future<void> wake({
    required String macAddress,
    String? broadcastIp,
    String? hostIpOrEndpoint,
  }) async {
    final packet = buildMagicPacket(macAddress);
    final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    socket.broadcastEnabled = true;

    final targets = <InternetAddress>{
      InternetAddress('255.255.255.255'),
    };

    // 1. Detectar interfaces de red activas en el teléfono para calcular el broadcast Wi-Fi local
    try {
      final interfaces = await NetworkInterface.list(
        type: InternetAddressType.IPv4,
        includeLoopback: false,
      );
      for (final iface in interfaces) {
        for (final addr in iface.addresses) {
          if (!addr.isLoopback && !addr.address.startsWith('100.')) {
            final parts = addr.address.split('.');
            if (parts.length == 4) {
              final localBcast = '${parts[0]}.${parts[1]}.${parts[2]}.255';
              try {
                targets.add(InternetAddress(localBcast));
              } catch (_) {}
            }
          }
        }
      }
    } catch (_) {}

    if (broadcastIp != null && broadcastIp.trim().isNotEmpty) {
      try {
        final parsed = InternetAddress(broadcastIp.trim());
        if (parsed.type == InternetAddressType.IPv4) {
          targets.add(parsed);
        }
      } catch (_) {}
    }

    if (hostIpOrEndpoint != null && hostIpOrEndpoint.trim().isNotEmpty) {
      try {
        final clean =
            hostIpOrEndpoint.trim().replaceAll(RegExp(r'^https?://'), '');
        final hostPart = clean.split(':').first;
        final parts = hostPart.split('.');
        if (parts.length == 4 && !hostPart.startsWith('127.')) {
          final subnetBcast = '${parts[0]}.${parts[1]}.${parts[2]}.255';
          targets.add(InternetAddress(subnetBcast));
        }
      } catch (_) {}
    }

    try {
      // Transmitir en dos ráfagas consecutivas separadas por 100ms para despertar NICs en ahorro de energía
      for (var attempt = 0; attempt < 2; attempt++) {
        for (final port in const [9, 7]) {
          for (final target in targets) {
            try {
              socket.send(packet, target, port);
            } catch (_) {}
          }
        }
        if (attempt == 0) {
          await Future.delayed(const Duration(milliseconds: 100));
        }
      }
    } finally {
      socket.close();
    }
  }
}
