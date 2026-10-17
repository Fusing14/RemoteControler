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
  /// Difunde a 255.255.255.255 y a la IP de difusión de la subred local si se suministra.
  static Future<void> wake({
    required String macAddress,
    String? broadcastIp,
  }) async {
    final packet = buildMagicPacket(macAddress);
    final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    socket.broadcastEnabled = true;

    final targets = <InternetAddress>{
      InternetAddress('255.255.255.255'),
    };

    if (broadcastIp != null && broadcastIp.trim().isNotEmpty) {
      try {
        final parsed = InternetAddress(broadcastIp.trim());
        if (parsed.type == InternetAddressType.IPv4) {
          targets.add(parsed);
        }
      } catch (_) {}
    }

    try {
      // Enviar por puertos 9 y 7 (puertos estándar de Wake-on-LAN)
      for (final port in const [9, 7]) {
        for (final target in targets) {
          socket.send(packet, target, port);
        }
      }
    } finally {
      socket.close();
    }
  }
}
