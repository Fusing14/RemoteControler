"""
Pruebas de canonicalización RFC 8785 (JCS).
Verifica que el ordenamiento de claves, formato de espacios y codificación UTF-8
sean estrictamente deterministas.
"""

from host.core.crypto.canonical import canonicalize


def test_jcs_key_ordering():
    """El orden de inserción en el diccionario no debe alterar el resultado canónico."""
    dict_a = {"b": 2, "a": 1, "c": 3}
    dict_b = {"a": 1, "c": 3, "b": 2}
    dict_c = {"c": 3, "b": 2, "a": 1}

    bytes_a = canonicalize(dict_a)
    bytes_b = canonicalize(dict_b)
    bytes_c = canonicalize(dict_c)

    assert bytes_a == bytes_b == bytes_c
    assert bytes_a == b'{"a":1,"b":2,"c":3}'


def test_jcs_nested_objects():
    """Garantiza ordenamiento recursivo en objetos anidados."""
    nested = {
        "z": {"y": 2, "x": 1},
        "a": [3, 2, {"b": True, "a": None}]
    }
    expected = b'{"a":[3,2,{"a":null,"b":true}],"z":{"x":1,"y":2}}'
    assert canonicalize(nested) == expected


def test_jcs_whitespace_elimination():
    """Comprueba la ausencia total de espacios entre separadores."""
    data = {"key": "value with spaces", "number": 42}
    result = canonicalize(data)
    assert b": " not in result
    assert b", " not in result
    assert result == b'{"key":"value with spaces","number":42}'
