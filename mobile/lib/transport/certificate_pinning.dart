/// Módulo de Certificate Pinning (TOFU / SHA-256) y comparación en tiempo constante.
/// Mitiga ataques Man-in-the-Middle (CWE-295) y ataques de canal lateral por tiempo (CWE-208).
/// Prohibido aceptar certificados autofirmados arbitrarios: badCertificateCallback SOLO
/// devuelve true cuando la huella SHA-256 del certificado coincide exactamente con
/// el cert_fingerprint firmado en el código QR del Host.
library;

import 'dart:io';
import 'dart:typed_data';

class CertificatePinningVerifier {
  /// Compara dos cadenas hexadecimales o tokens en tiempo constante (CWE-208)
  /// sin cortocircuitar en el primer byte distinto.
  static bool constantTimeEquals(String a, String b) {
    final normA = a.trim().toLowerCase().replaceAll(':', '');
    final normB = b.trim().toLowerCase().replaceAll(':', '');
    if (normA.isEmpty || normB.isEmpty) {
      return false;
    }
    final bytesA = normA.codeUnits;
    final bytesB = normB.codeUnits;
    if (bytesA.length != bytesB.length) {
      return false;
    }
    var diff = 0;
    for (var i = 0; i < bytesA.length; i++) {
      diff |= bytesA[i] ^ bytesB[i];
    }
    return diff == 0;
  }

  /// Calcula el digest SHA-256 de forma síncrona sobre los bytes DER de un certificado X.509
  /// para poder ejecutarse dentro de HttpClient.badCertificateCallback.
  static String computeSha256HexSync(Uint8List data) {
    const k = <int>[
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    var h0 = 0x6a09e667;
    var h1 = 0xbb67ae85;
    var h2 = 0x3c6ef372;
    var h3 = 0xa54ff53a;
    var h4 = 0x510e527f;
    var h5 = 0x9b05688c;
    var h6 = 0x1f83d9ab;
    var h7 = 0x5be0cd19;

    final bitLen = data.length * 8;
    final padLen = ((data.length + 9 + 63) ~/ 64) * 64;
    final padded = Uint8List(padLen);
    padded.setRange(0, data.length, data);
    padded[data.length] = 0x80;

    final bd = ByteData.sublistView(padded);
    bd.setUint32(padLen - 8, (bitLen ~/ 0x100000000) & 0xffffffff, Endian.big);
    bd.setUint32(padLen - 4, bitLen & 0xffffffff, Endian.big);

    final w = Uint32List(64);

    int rotr(int x, int n) => ((x & 0xffffffff) >>> n) | ((x << (32 - n)) & 0xffffffff);

    for (var chunkOffset = 0; chunkOffset < padLen; chunkOffset += 64) {
      for (var i = 0; i < 16; i++) {
        w[i] = bd.getUint32(chunkOffset + i * 4, Endian.big);
      }
      for (var i = 16; i < 64; i++) {
        final s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ ((w[i - 15] & 0xffffffff) >>> 3);
        final s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ ((w[i - 2] & 0xffffffff) >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
      }

      var a = h0;
      var b = h1;
      var c = h2;
      var d = h3;
      var e = h4;
      var f = h5;
      var g = h6;
      var h = h7;

      for (var i = 0; i < 64; i++) {
        final s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        final ch = (e & f) ^ ((~e & 0xffffffff) & g);
        final temp1 = (h + s1 + ch + k[i] + w[i]) & 0xffffffff;
        final s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        final maj = (a & b) ^ (a & c) ^ (b & c);
        final temp2 = (s0 + maj) & 0xffffffff;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) & 0xffffffff;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) & 0xffffffff;
      }

      h0 = (h0 + a) & 0xffffffff;
      h1 = (h1 + b) & 0xffffffff;
      h2 = (h2 + c) & 0xffffffff;
      h3 = (h3 + d) & 0xffffffff;
      h4 = (h4 + e) & 0xffffffff;
      h5 = (h5 + f) & 0xffffffff;
      h6 = (h6 + g) & 0xffffffff;
      h7 = (h7 + h) & 0xffffffff;
    }

    final words = [h0, h1, h2, h3, h4, h5, h6, h7];
    final sb = StringBuffer();
    for (final word in words) {
      sb.write(word.toUnsigned(32).toRadixString(16).padLeft(8, '0'));
    }
    return sb.toString();
  }

  /// Verifica si los bytes DER de un certificado X.509 coinciden exactamente
  /// con la huella SHA-256 anclada (pinnedFingerprint).
  static bool verifyCertificateDer(Uint8List certDerBytes, String? pinnedFingerprint) {
    if (pinnedFingerprint == null || pinnedFingerprint.trim().isEmpty) {
      return false;
    }
    final actualHex = computeSha256HexSync(certDerBytes);
    return constantTimeEquals(actualHex, pinnedFingerprint);
  }

  /// Crea un HttpClient con Certificate Pinning estricto.
  /// badCertificateCallback SOLO acepta un certificado autofirmado si su hash SHA-256
  /// coincide exactamente con pinnedFingerprint.
  static HttpClient createPinnedHttpClient({required String? pinnedFingerprint}) {
    final client = HttpClient();
    client.badCertificateCallback = (X509Certificate cert, String host, int port) {
      return verifyCertificateDer(cert.der, pinnedFingerprint);
    };
    return client;
  }
}
