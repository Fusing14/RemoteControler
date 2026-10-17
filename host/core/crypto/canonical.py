"""
Implementación de JSON Canonicalization Scheme (JCS) - RFC 8785.
Asegura serialización idéntica byte a byte entre Python, Dart (Flutter) y cualquier otro runtime.

Reglas RFC 8785:
1. Separadores sin espacios: ',' y ':'.
2. Claves de objetos ordenadas por unidades de código UTF-16.
3. Cadenas codificadas en UTF-8 sin secuencias de escape innecesarias (ej. '/' no se escapa).
4. Sin formato flotante redundante o espacios en blanco residuales.
"""

import json
from typing import Any


def _utf16_sort_key(s: str) -> bytes:
    """
    Ordena cadenas según sus unidades de código UTF-16 (RFC 8785 sección 3.2.3).
    Para cadenas ASCII o BMP coincide con el orden lexicográfico ordinario.
    Para caracteres fuera del BMP (astrales), se codifica en UTF-16-BE.
    """
    return s.encode("utf-16-be")


def canonicalize(obj: Any) -> bytes:
    """
    Serializa un objeto JSON a bytes UTF-8 canónicos de acuerdo con RFC 8785 (JCS).
    
    Mitigación de Vectores de Ataque:
    - Previene discrepancias de firma ('Signature Mismatch') causadas por orden no determinista
      de claves o diferencias de espaciado/escape entre diferentes lenguajes (Python vs Dart).
    """
    canonical_str = _serialize_jcs(obj)
    return canonical_str.encode("utf-8")


def _serialize_jcs(obj: Any) -> str:
    """Función recursiva para serializar datos a formato canónico JCS."""
    if obj is None:
        return "null"
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif isinstance(obj, int):
        # En Python, bool es subclase de int, por eso el check de bool va antes
        return str(obj)
    elif isinstance(obj, float):
        # Manejo estándar de floats según RFC 8785
        if not (-1e21 < obj < 1e21) or obj.is_integer():
            # Formato estándar para números enteros representados como float
            return f"{int(obj)}"
        # Para floats generales, json.dumps estándar sin espacios
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    elif isinstance(obj, str):
        # json.dumps maneja correctamente los escapes obligatorios (< 0x20, ", \)
        # ensure_ascii=False asegura que los caracteres UTF-8 no se conviertan en \uXXXX
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    elif isinstance(obj, list):
        items = [_serialize_jcs(item) for item in obj]
        return "[" + ",".join(items) + "]"
    elif isinstance(obj, dict):
        # Ordenación estricta de claves por código UTF-16
        sorted_keys = sorted(obj.keys(), key=_utf16_sort_key)
        items = [
            f"{json.dumps(k, separators=(',', ':'), ensure_ascii=False)}:{_serialize_jcs(obj[k])}"
            for k in sorted_keys
        ]
        return "{" + ",".join(items) + "}"
    else:
        raise TypeError(f"Tipo de dato no serializable para JCS: {type(obj).__name__}")
