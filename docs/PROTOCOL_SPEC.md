# RemoteControler Protocol Specification (v1.0)
## Zero-Trust Cryptographic Communication Protocol

---

## 1. Introducción y Principios de Diseño

El protocolo de comunicación entre el cliente móvil (**RemoteControler Mobile**) y el demonio en la estación de trabajo (**RemoteControler Host**) está diseñado bajo un modelo de **Zero-Trust**:
- Se asume un canal de transporte potencialmente interceptable, incluso dentro de redes privadas.
- La integridad, autenticidad y frescura de cada comando se garantiza a nivel de aplicación (Capa 7) independientemente de la seguridad del transporte (WireGuard/Tailscale).
- **No se permite estado implícito de confianza**: Cada comando es una unidad criptográficamente autosuficiente y verificable.

---

## 2. Vectores de Ataque Mitigados

| Vector de Ataque | Mecanismo de Mitigación en el Protocolo |
| :--- | :--- |
| **Man-in-the-Middle (MitM) & Tampering** | Firmas digitales **Ed25519** sobre el payload canonicalizado. Cualquier bit alterado en tránsito invalida la firma. |
| **Replay Attacks (Ataques de Repetición)** | Combinación estricta de **Timestamp UTC** ($\pm 30$ s de tolerancia) y **Nonce criptográfico único** (16 bytes) verificado en ventana deslizante LRU en el Host. |
| **Discrepancia de Serialización (Signature Mismatch)** | Adopción estricta de **RFC 8785: JSON Canonicalization Scheme (JCS)**. Garantiza representación byte a byte idéntica en Python, Dart/Flutter y cualquier otro runtime. |
| **Suplantación de Dispositivo (Spoofing)** | **Device Pinning**: El Host almacena la huella SHA-256 (`device_id`) y clave pública del dispositivo móvil autorizado. Peticiones de dispositivos no registrados se rechazan en $O(1)$ antes de procesar criptografía costosa. |
| **Inyección de Comandos (RCE)** | Contratos estrictos (**Typed Enums**). Prohibido el paso de strings libres ejecutables. Solo parámetros fuertemente validados contra esquema. |

---

## 3. Especificación del "Signed Envelope"

Cada mensaje transmitido desde el cliente hacia el host debe encapsularse en la siguiente estructura JSON:

### 3.1 Estructura del Envelope

```json
{
  "device_id": "<hex-sha256-public-key-fingerprint>",
  "timestamp_utc": 1773715200,
  "nonce": "3f8b1c4e2a9d4f6a8e1b2c3d4e5f6a7b",
  "command_id": "SYS_POWER",
  "payload": {
    "action": "SUSPEND",
    "force": false
  },
  "signature": "<base64-ed25519-signature>"
}
```

### 3.2 Definición de Campos

| Campo | Tipo | Restricción / Formato | Propósito |
| :--- | :--- | :--- | :--- |
| `device_id` | `string` | 64 caracteres hexadecimales (`^[a-f0-9]{64}$`). SHA-256 de la clave pública Ed25519 cruda (32 bytes). | Identificación inmediata del dispositivo contra la lista blanca local (Allowlist). |
| `timestamp_utc` | `integer` | Entero Unix Epoch en segundos UTC. | Control de frescura temporal. El Host descarta mensajes con $|T_{host} - T_{msg}| > 30$ segundos. |
| `nonce` | `string` | 32 caracteres hexadecimales (16 bytes de entropía segura generados vía CSPRNG). | Unicidad del mensaje dentro de la ventana de validez. Evita repetición. |
| `command_id` | `string` | Enum cerrado (`MEDIA`, `SYS_POWER`, `APP_LAUNCH`). | Discriminador de tipo para el esquema de deserialización del payload. |
| `payload` | `object` | Objeto JSON que cumple el esquema estricto correspondiente a `command_id`. | Parámetros del comando. Sin parámetros arbitrarios. |
| `signature` | `string` | Base64 estándar de 64 bytes (longitud aproximada 88 caracteres). | Firma Ed25519 generada por la clave privada del cliente. |

---

## 4. Canonicalización Determinista (RFC 8785 - JCS)

### 4.1 La Necesidad de JCS
En JSON estándar, dos objetos semánticamente idénticos pueden tener distintas representaciones en bytes debido a:
- Orden de claves en diccionarios (`{"a": 1, "b": 2}` vs `{"b": 2, "a": 1}`).
- Espacios en blanco y saltos de línea.
- Formateo de números flotantes y codificación Unicode (ej. `\u00e1` vs `á`).

Si el cliente (Dart) y el host (Python) serializan el payload con discrepancias de bytes, **la verificación de la firma Ed25519 fallará**.

### 4.2 Reglas de Canonicalización para la Firma
La firma digital Ed25519 se calcula **únicamente** sobre los datos que forman el mensaje legítimo, excluyendo el campo `signature`.

El objeto a firmar (**Canonical Payload**) consta de:
```json
{
  "command_id": "SYS_POWER",
  "device_id": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "nonce": "3f8b1c4e2a9d4f6a8e1b2c3d4e5f6a7b",
  "payload": {
    "action": "SUSPEND",
    "force": false
  },
  "timestamp_utc": 1773715200
}
```

Reglas RFC 8785 aplicadas:
1. **Orden lexicográfico de claves**: Las claves del objeto se ordenan por su valor de punto de código UTF-16 (equivalente a orden por bytes UTF-8 para cadenas ASCII).
2. **Sin espacios en blanco**: Separador de elementos `,`, separador clave-valor `:`. Sin saltos de línea ni indentación.
3. **Codificación UTF-8**: Sin BOM (Byte Order Mark). Los caracteres se serializan directamente en UTF-8 sin secuencias de escape innecesarias (ej. `\u002F`).
4. **Números**: Enteros sin ceros no significativos; punto flotante según estándar IEEE 754 de menor representación.

---

## 5. Ciclo de Vida de una Petición (Request Lifecycle)

```
[ Cliente Móvil ]                                          [ Host Daemon (PC) ]
       |                                                            |
       | 1. Genera Nonce CSPRNG (16 bytes hex)                      |
       | 2. Obtiene Timestamp UTC actual                            |
       | 3. Ensambla Canonical Data Dictionary                      |
       | 4. Canonicaliza según RFC 8785                             |
       | 5. Firma bytes con Ed25519 Private Key                     |
       | 6. Construye SignedEnvelope                                |
       |                                                            |
       | -------- POST /api/v1/command (SignedEnvelope) --------->  |
       |                                                            |
       |                                 7. Validación de Estructura Pydantic
       |                                 8. Verificación de Device Pinning:
       |                                    ¿`device_id` está en Allowlist?
       |                                    NO -> 403 Forbidden (Audit Log)
       |                                 9. Verificación de Ventana Temporal:
       |                                    |T_host - T_msg| <= 30s
       |                                    NO -> 400 Bad Request (Clock Skew)
       |                                10. Verificación Anti-Replay:
       |                                    ¿`nonce` ya existe en Cache?
       |                                    SÍ -> 409 Conflict (Replay Ban)
       |                                    NO -> Almacenar `nonce` con TTL 60s
       |                                11. Canonicalizar según RFC 8785
       |                                12. Verificar firma Ed25519 con PubKey
       |                                    INVÁLIDA -> 401 Unauthorized (Ban)
       |                                13. Despachar a Native Win32 Handler
       |                                14. Registrar en Audit Log Inmutable
       |                                                            |
       | <------- 200 OK {"status": "SUCCESS", ...} --------------- |
```

---

## 6. Respuestas del Servidor

El servidor responde siempre con códigos HTTP estándar y envolturas JSON tipadas. Bajo ninguna circunstancia se devuelven trazas internas de error del sistema o rutas de archivos en los mensajes de respuesta:

- **200 OK**: Comando validado y ejecutado exitosamente.
- **400 Bad Request**: Desfase temporal detectado (`ClockSkewError`) o esquema de comando inválido.
- **401 Unauthorized**: Firma criptográfica inválida (`InvalidSignatureError`). Desencadena penalización en el Rate Limiter.
- **403 Forbidden**: Dispositivo no registrado en la lista blanca (`UntrustedDeviceError`).
- **409 Conflict**: Ataque de repetición detectado (`ReplayAttackDetectedError`). Nonce duplicado.
- **429 Too Many Requests**: Excedido el límite de peticiones o IP en lista de castigo temporal.
- **500 Internal Server Error**: Error en la ejecución interna de la API Win32 (mensaje ofuscado y registrado en log local).
