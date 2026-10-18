/// Implementación de JSON Canonicalization Scheme (JCS) - RFC 8785 en Dart.
/// Garantiza representación byte a byte idéntica a la implementación en Python.
///
/// Reglas aplicadas:
/// 1. Claves ordenadas lexicográficamente por unidades de código UTF-16.
/// 2. Sin espacios en blanco entre separadores (',' y ':').
/// 3. Cadenas codificadas directamente en UTF-8 sin secuencias de escape innecesarias.
library;

import 'dart:convert';
import 'dart:typed_data';

/// Serializa cualquier objeto compatible con JSON a su representación canónica RFC 8785.
String canonicalizeJson(dynamic obj) {
  return _serializeJcs(obj);
}

/// Serializa un objeto a bytes UTF-8 canónicos listos para firma o hashing.
Uint8List canonicalizeToBytes(dynamic obj) {
  return Uint8List.fromList(utf8.encode(canonicalizeJson(obj)));
}

String _serializeJcs(dynamic obj) {
  if (obj == null) {
    return 'null';
  } else if (obj is bool) {
    return obj ? 'true' : 'false';
  } else if (obj is int) {
    return obj.toString();
  } else if (obj is double) {
    if (obj.isNaN || obj.isInfinite) {
      throw const FormatException('NaN e Infinito no son serializables en JCS');
    }
    // Si el double representa un entero exacto (ej. 5.0)
    if (obj == obj.roundToDouble() && obj.abs() < 9007199254740992) {
      return obj.toInt().toString();
    }
    return json.encode(obj);
  } else if (obj is String) {
    // json.encode en Dart maneja los escapes estándar de JSON (< 0x20, ", \)
    // y mantiene los caracteres UTF-8 sin secuencias innecesarias.
    return json.encode(obj);
  } else if (obj is List) {
    final buffer = StringBuffer('[');
    for (var i = 0; i < obj.length; i++) {
      if (i > 0) buffer.write(',');
      buffer.write(_serializeJcs(obj[i]));
    }
    buffer.write(']');
    return buffer.toString();
  } else if (obj is Map) {
    // Ordenación estricta de claves por código UTF-16 (Dart String.compareTo)
    final sortedKeys = obj.keys.map((k) => k.toString()).toList()
      ..sort((a, b) => a.compareTo(b));

    final buffer = StringBuffer('{');
    for (var i = 0; i < sortedKeys.length; i++) {
      if (i > 0) buffer.write(',');
      final key = sortedKeys[i];
      buffer.write(json.encode(key));
      buffer.write(':');
      buffer.write(_serializeJcs(obj[key]));
    }
    buffer.write('}');
    return buffer.toString();
  } else {
    throw FormatException(
        'Tipo de dato no serializable para JCS: ${obj.runtimeType}');
  }
}
