# Informe de Auditoría Ofensiva/Defensiva Zero-Trust y Cambios de Ingeniería — SecureDeck / RemoteControler

---

## 1. FASE 1 (PRIORIDAD CRÍTICA #1): Blindaje de Ciberseguridad Zero-Trust (12 Vulnerabilidades Mitigadas)

| # | Vulnerabilidad / CWE | Vector Detectado | Mitigación Implementada (Host & Mobile) |
| :--- | :--- | :--- | :--- |
| **1** | **RCE por Inyección de Comandos del SO (`CWE-78`)** | Interpolación de rutas en scripts PowerShell (`create_desktop_shortcut`) y riesgo de rutas arbitrarias o UNC en lanzamiento de aplicaciones. | Eliminada toda interpolación en PowerShell (paso de rutas por variables de entorno `SD_SHORTCUT_PATH`, `SD_TARGET_PATH`, `SD_WORK_DIR`). Cero uso de `shell=True`. Validación de lista blanca y bloqueo de rutas UNC (`\\`), secuencias `..` y metacaracteres en `AppLaunchPayload` y `launch_system_app`. |
| **2** | **Secuestro de WebSockets / CSWSH y Bypass (`CWE-306`)** | Conexiones WebSocket/HTTP desde navegadores locales maliciosos o sesiones que permanecían abiertas tras revocar un dispositivo. | Middleware HTTP y filtro de handshake en `/ws/control` que rechaza cabeceras `Origin` de navegadores (`403 Forbidden` / `1008 Policy Violation`). Revalidación criptográfica Ed25519 en cada trama y **cierre inmediato en caliente (`1008 Policy Violation`)** mediante callback en `TrustedDeviceStore.revoke_device()`. |
| **3** | **Ataques de Repetición (`CWE-294`)** | Reenvío de tramas capturadas de `UNLOCK_PC` o `SYS_POWER`. | Ventana temporal estricta de `±30s`, caché acotada de nonces únicos (`max_cache_size = 10000`) y verificación `compute_session_hmac` / `verify_session_hmac` (HMAC-SHA256) en tiempo constante en `host/core/security/anti_replay.py`. |
| **4** | **Ataques de Timing en Comparación de Secretos (`CWE-208`)** | Comparaciones con `==` en tokens, IDs o huellas. | Sustituidas todas las comparaciones sensibles por `hmac.compare_digest` en Python (`pairing.py`, `device_store.py`, `unlock.py`, `tls_pinning.py`, `logger.py`) y `CertificatePinningVerifier.constantTimeEquals` en Dart (`certificate_pinning.dart`). |
| **5** | **Fuerza Bruta y Enumeración de Emparejamiento/PIN (`CWE-307`)** | Intentos automatizados contra `/pair` o `UNLOCK_PC`. | `RateLimiter` por IP y por `device_id` con **Exponential Backoff** (el tiempo de bloqueo se duplica en cada reincidencia: `5m -> 10m -> 20m -> 60m`) y **rotación automática del token QR** (`rotate_pairing_challenge`) ante fallos repetidos o caducidad. |
| **6** | **Man-in-the-Middle por Certificados sin Pinning (`CWE-295`)** | Aceptación ciega de certificados autofirmados en redes LAN/Wi-Fi. | Creado `host/core/security/tls_pinning.py` (generación de certificado X.509 autofirmado con clave privada cifrada en DPAPI y huella SHA-256 incluida en el QR y en `HOST_INFO`) y `mobile/lib/transport/certificate_pinning.dart` (`badCertificateCallback` solo devuelve `true` si el SHA-256 DER coincide en tiempo constante con `pinnedFingerprint`). |
| **7** | **Escalación de Privilegios Local y Rutas sin Entrecomillar (`CWE-426 / CWE-427`)** | Invocación de `powershell`, `schtasks`, `reg`, `ipconfig`, `taskkill`, `tscon` sin ruta absoluta o tareas programadas sin comillas. | Creado `host/core/security/path_security.py` (`resolve_system_binary` verificando `%SystemRoot%\System32`, `quote_executable_path`, `NoDefaultCurrentDirectoryInExePath=1` y `enforce_restrictive_acls` con `icacls.exe`). |
| **8** | **Exposición de Credenciales/PIN en Disco o Logs (`CWE-312 / CWE-532`)** | Riesgo de almacenar el PIN sin entropía de aplicación o filtrar secretos en logs. | PIN cifrado con **Windows DPAPI (`CryptProtectData`) + entropía de aplicación (`PIN_DPAPI_ENTROPY`)** y borrado seguro con sobrescritura de ceros. Filtro global `SensitiveDataRedactingFilter` y `redact_sensitive_dict` que enmascara cualquier PIN, password, token o clave privada como `***REDACTED***`. |
| **9** | **Denegación de Servicio por Memoria/Hilos (`CWE-400`)** | Payloads gigantes en HTTP o WebSocket y exceso de conexiones abiertas. | Límite estricto de `64 KB` tanto en tramas WebSocket (`MESSAGE_TOO_LARGE`) como en cuerpos HTTP (`413 Payload Too Large`), límite de clientes concurrentes (`MAX_CONCURRENT_WS_CLIENTS = 10`), timeout de inactividad y heartbeat `PING`/`PONG` cada 15s. |
| **10** | **Secuestro de Actualizaciones y Zip Slip (`CWE-22 / CWE-494`)** | Archivos ZIP con rutas `../../Windows/...` o descargas sin validar HTTPS. | Creado `host/core/updater.py` con `validate_https_github_url` (solo HTTPS hacia `github.com`) y `extract_zip_safely` (validación previa de cada entrada con `os.path.commonpath` antes de extraer un solo byte, más backup previo en `logs/backup_pre_update`). |
| **11** | **Inyección de Input Descontrolada (`CWE-20`)** | Posibilidad de inyectar teclas arbitrarias en endpoints multimedia o caracteres de control en el PIN. | Lista blanca cerrada `ALLOWED_MEDIA_VK_CODES` (`0xAD`..`0xB3`) en `send_virtual_key()` y sanitización estricta en `sanitize_unlock_credential()` y `UnlockPcPayload` (prohibidos caracteres de control `\x00`..`\x1f`, `\x7f`). |
| **12** | **Fuga de Información en Respuestas de Error (`CWE-209`)** | Exposición potencial de rutas locales o errores internos al cliente. | Middleware global de captura de excepciones en `server.py` y sanitización en `dispatcher.py` y `process_manager.py`, devolviendo únicamente códigos y mensajes estandarizados al cliente. |

---

## 2. FASE 2 (PRIORIDAD CRÍTICA #2): Solución Definitiva a Wake-on-LAN con PC Apagado (Cold Boot S5)

### Causa Raíz Identificada
1. **Tailscale inactivo con el PC apagado (S5):** Al emparejar por Tailscale (`100.x.y.z`), la app móvil desconocía la IP LAN física del PC (`192.168.x.y`), y los paquetes de broadcast `255.255.255.255` no atraviesan túneles WireGuard/Tailscale cuando el PC está apagado.
2. **Inicio Rápido de Windows 10/11 (`HiberbootEnabled = 1`):** El apagado híbrido (estado S4) apaga el controlador de red en muchas placas base e impide despertar por Magic Packet.
3. **Adaptadores virtuales:** La presencia de interfaces virtuales (`Tailscale`, `ZeroTier`, `WSL`, `Hyper-V`, `Docker`, `VMware`, `VirtualBox`) podía interferir en la detección de la MAC física.

### Solución Implementada
- **Detección Física Estricta (`host/core/network/wol.py`):** Filtra 22 tipos de adaptadores virtuales y prioriza adaptadores **Ethernet cableados con puerta de enlace activa** sobre Wi-Fi, obteniendo `mac`, `lan_ip`, `broadcast_ip` y `subnet`.
- **Autoconfiguración de Energía y NIC en Windows (`configure_windows_wol`):**
  - Desactiva Inicio Rápido en el Registro (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\HiberbootEnabled = 0`).
  - Activa `Enable-NetAdapterPowerManagement -WakeOnMagicPacket` y las propiedades avanzadas del driver (`*WakeOnMagicPacket = 1`, `*PMARPOffload = 1`, `*WakeOnPattern = 1`).
- **Estrategia Multi-Ruta en Flutter (`mobile/lib/services/wol_service.dart`):**
  - El payload del código QR y el comando `HOST_INFO` ahora incluyen `lan_ip`, `broadcast_ip`, `mac_address` y `cert_fingerprint`, persistidos en `SavedHost` y `PairingClient`.
  - `WolService.wakeWithRetryAndPolling()` transmite ráfagas UDP por los puertos **7, 9 y 40000** simultáneamente hacia:
    1. `255.255.255.255` (Broadcast global LAN).
    2. El broadcast dirigido de la subred del PC (`192.168.x.255`) y de la interfaz Wi-Fi actual del móvil.
    3. Unicast directo a la IP LAN física del PC (`lan_ip`) y a la IP de Tailscale (`100.x.y.z`).
  - Reintenta automáticamente cada 2 segundos mientras hace polling a `/health` y reconecta el WebSocket en cuanto el PC responde.

---

## 3. FASE 3 (PRIORIDAD CRÍTICA #3): Desbloqueo de Sesión de Windows 11 (Pre-Login y Bloqueo Normal)

### Causa Raíz Identificada
En la versión anterior de `host/engine/handlers/unlock.py`, `execute_unlock_pc()` ejecutaba `tscon.exe <session_id> /dest:console` y, como `tscon.exe` devuelve código `0` en una sesión de consola local bloqueada (`Win+L`) sin quitar la pantalla de bloqueo `Winlogon`, la función hacía `if tscon_success: return` en la línea 315 **sin llegar jamás a levantar la cortina de bloqueo ni escribir el PIN**.

### Solución Implementada
1. **Arranque Pre-Login y Post-Login Elevado (`host/core/autostart.py`):**
   - Registra `SecureDeckHostAutoStart` (`/SC ONLOGON /RL HIGHEST`) y `SecureDeckHostBootStart` (`/SC ONSTART /RU "NT AUTHORITY\SYSTEM" /RL HIGHEST`) con rutas absolutas entrecomilladas.
2. **Desbloqueo en 1 Toque con PIN Cifrado en DPAPI + Entropía (`unlock.py` y `deck_screen.dart`):**
   - Añadido botón **"⚡ Desbloqueo Rápido en 1 Toque (PIN DPAPI)"** en la app móvil (`use_stored_pin: true`) además de la entrada manual de PIN/contraseña en tiempo real.
3. **Secuencia Infalible de 5 Pasos para Windows 11 (`_inject_win32_unlock_sequence`):**
   - **Paso 1 (Despertar Monitor):** `SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)` + movimiento de ratón + pulsación `Shift`.
   - **Paso 2 (Acoplar al Escritorio Seguro):** `OpenInputDesktop` -> `OpenDesktopW("Winlogon")` -> `SetThreadDesktop`.
   - **Paso 3 (Levantar la Cortina de Bloqueo):** Envía `Escape` + `Space` + clic izquierdo y espera `650ms` para que la caja de texto de PIN de Windows 11 reciba el foco.
   - **Paso 4 (Inyección de Hardware Scan Codes):** Limpia el campo (`Ctrl+A` -> `Backspace`), inyecta cada dígito mediante `SendInput` con `KEYEVENTF_SCANCODE` con cadencia de `40ms` entre teclas, y pulsa `Enter`.
   - **Paso 5 (Verificación Post-Inyección):** Espera `1.5s`, comprueba `is_workstation_locked()` y devuelve `UNLOCK_SUCCESS` o `UNLOCK_FAILED` al teléfono.

---

## 4. FASE 4: Reparación del Actualizador del Servidor (Error Git 128) y Scripts de Inicio

- **Solución al error `Command ['git', 'rev-parse', ...] returned non-zero exit status 128` (`host/core/updater.py`):**
  - Si la carpeta del proyecto fue descargada como ZIP y no contiene `.git`, `repair_and_update_git_repo()` ejecuta automáticamente `git init`, vincula el remoto oficial `https://github.com/marcosat03/RemoteControler.git`, hace `git fetch origin main --depth=1` y sincroniza el árbol de trabajo sin borrar configuraciones locales (`.venv`, `logs`, `host_config.json`, `trusted_devices.json`, `unlock_pin.dat`).
  - Si `git` no está instalado en el PC, `update_via_https_zip()` descarga automáticamente el paquete ZIP oficial por HTTPS, valida cada ruta contra **Zip Slip (`CWE-22`)** con `os.path.commonpath` y actualiza los archivos.
- **Scripts Blindados (`Iniciar_SecureDeck.bat` e `install_host.ps1`):**
  - Detectan automáticamente carpetas anidadas (`RemoteControler\RemoteControler`), fijan el directorio de trabajo con `cd /d "%~dp0"`, instalan desde `host\requirements.txt`, configuran las reglas de Firewall TCP (`8443`, `8000`) y UDP (`7`, `9`, `40000`), y registran cualquier error de arranque en `logs\startup_error.log`.

---

## 5. Instrucciones Rápidas de Uso

1. **Instalación / Puesta a punto inicial (ejecutar una vez en PowerShell como Administrador):**
   ```powershell
   .\install_host.ps1
   ```
   Esto instalará las dependencias, desactivará el Inicio Rápido de Windows (`HiberbootEnabled = 0`), activará `Wake on Magic Packet` en tu tarjeta de red física, abrirá los puertos en el Firewall y creará el acceso directo **`SecureDeck Host.lnk`** en tu Escritorio.
2. **Iniciar el Host:**
   Haz doble clic en **`SecureDeck Host.lnk`** en el Escritorio (o ejecuta `Iniciar_SecureDeck.bat`).
3. **Configurar el PIN para Desbloqueo en 1 Toque:**
   En la ventana de RemoteControler Host, pulsa **"Configurar PIN"** e introduce tu PIN de Windows Hello. Quedará cifrado con Windows DPAPI + entropía de aplicación.
4. **Vincular o Actualizar Datos en el Teléfono:**
   Si ya tenías el teléfono vinculado, simplemente abre la app móvil: al conectarse recibirá automáticamente la nueva información de red (`lan_ip`, `broadcast_ip`, `mac_address`, `cert_fingerprint` y `has_stored_pin`) mediante `HOST_INFO`. Si deseas vincular un teléfono nuevo, pulsa **"Vincular nuevo teléfono (Mostrar QR)"**.

---

## 6. Registro de Verificación Convergente (Protocolo de Doble Vuelta Limpia)

Antes del commit final se ejecutó el bucle de verificación convergente (`VUELTAS_LIMPIAS_CONSECUTIVAS == 2`):

- **Correcciones previas al inicio de las vueltas limpias:**
  1. `host/core/updater.py`: Corregido argumento `" branch"` -> `"branch"` en la llamada a `git branch -M` durante la auto-reparación del repositorio Git.
  2. `host/transport/server.py`: Actualizada constante de estado HTTP `413` a `getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413)` para eliminar warnings de deprecación de Starlette.
  3. `mobile/lib/ui/screens/deck_screen.dart`: Eliminada cláusula `default:` redundante en el `switch (event.status)` exhaustivo sobre `OtaStatus`.
- **Vuelta Limpia #1 (`VUELTAS_LIMPIAS_CONSECUTIVAS = 1`):**
  - Compilación estática de Python (`py_compile`): **59/59 módulos compilados sin errores**.
  - Auditoría estática de seguridad: **0 ocurrencias de `shell=True` o `os.system()`** en todo `host/`.
  - Suite completa de tests del Host (`pytest`): **122 passed** (incluyendo los 19 tests de auditoría Zero-Trust, WoL y Unlock en `tests/test_zero_trust_audit.py`).
  - Análisis estático Dart (`dart analyze`) y suite de tests móviles (`crypto_test.dart`, `pairing_test.dart`, `saved_hosts_test.dart`, `zero_trust_wol_test.dart`): **0 issues, 21/21 tests pasando**.
  - Modificaciones requeridas durante la Vuelta 1: **0 líneas**.
- **Vuelta Limpia #2 (`VUELTAS_LIMPIAS_CONSECUTIVAS = 2`):**
  - Re-inspección integral de contratos Host ↔ Mobile (`CommandCatalog`: 16 comandos registrados == 16 manejados en `CommandDispatcher`, 13 comandos invocados desde Mobile 100% alineados).
  - Validación de sintaxis AST de PowerShell (`PSParser::Tokenize` sobre `install_host.ps1`): **0 errores**.
  - Re-ejecución completa de `py_compile` (59 archivos), `pytest` (**122 passed**), `dart analyze` (**0 issues**) y los 4 archivos de test de Dart (**21/21 passed**).
  - Modificaciones requeridas durante la Vuelta 2: **0 líneas**.

---

## 7. Arquitectura de Interacción Táctil 1:1 (Touch-to-Mouse Mapping) y Auditoría Post-Implementación

### 7.1 Arquitectura Matemática y Nativa de Extremo a Extremo
1. **Cliente Móvil (`mobile/lib/ui/utils/touch_coordinate_mapper.dart` + `screen_viewer_screen.dart`):**
   - **Compensación de Escena (`InteractiveViewer`):** Convierte las coordenadas locales del toque a coordenadas de escena mediante `_transformationController.toScene(localPosition)` para deshacer cualquier nivel de zoom o paneo activo.
   - **Compensación de `BoxFit.contain` (Letterboxing / Pillarboxing):** `TouchCoordinateMapper.calculateNormalizedCoordinates()` calcula el factor de escala real `containScale = min(containerW / imageW, containerH / imageH)`, el tamaño renderizado `(renderedW, renderedH)` y los márgenes de centrado `(dx, dy)`. Si el toque cae en las bandas negras exteriores, retorna `null` y lo descarta; si cae dentro del escritorio, proyecta al rango normalizado `[0.0, 1.0]`.
   - **Sincronización Dinámica de Dimensiones JPEG:** Además de leer `width` y `height` de los metadatos de `SCREEN_FRAME`, `TouchCoordinateMapper.extractJpegDimensions()` analiza las cabeceras binarias JPEG (`SOF0`/`SOF1`/`SOF2`) de cada fotograma recibido para garantizar que `_imageWidth` y `_imageHeight` reflejen siempre el aspect ratio exacto del monitor activo.
   - **Prevención de Conflictos de Gestos Multi-Touch:** Se incorporó seguimiento de punteros activos (`_activePointers`) mediante `Listener` y detección de cambio de matriz en `InteractiveViewer` (`_isMultiTouchGesture`, `_didPanOrZoomInGesture` y ventana de enfriamiento de `180ms` post-zoom/pan) para impedir que pellizcar o arrastrar la pantalla dispare clics accidentales.
   - **Feedback Visual Reactivo:** `RipplePainter` dibuja ondas expansivas codificadas por color (Cyan para clic izquierdo, Esmeralda para doble clic, Violeta con vibración háptica para clic derecho).
2. **Transporte Asíncrono Concurrente (`mobile/lib/transport/control_client.dart`):**
   - Implementada cola FIFO de `Completer` indexada por `command_id` (`_pendingCommandCompleters`) con bloque `try / finally` que garantiza la limpieza determinista de listas y claves vacías tanto al completarse como en caso de timeout o desconexión, evitando que el bucle continuo de `SCREEN_FRAME` interfiera con los paquetes de `MOUSE_CLICK`.
3. **Host Windows (`host/engine/handlers/mouse.py` + `commands.py` + `dispatcher.py`):**
   - **Contrato Zero-Trust (`MouseClickPayload`):** Valida rangos estrictos `x, y ∈ [0.0, 1.0]`, acciones permitidas (`left`, `right`, `middle`, `double_left`, `move`) y `monitor_index ∈ [0, 16]`.
   - **Conciencia de Escalado Físico (Per-Monitor DPI Aware V2):** `make_process_dpi_aware()` invoca `SetProcessDpiAwarenessContext(-4)` (con fallbacks a `SetProcessDpiAwareness(2)` y `SetProcessDPIAware()`) para evitar desvíos de coordenadas cuando Windows aplica escalados del 125%, 150% o 200%.
   - **Mapeo Multimonitor y Sincronización de Escritorio:** `get_monitor_geometry(monitor_index)` obtiene el rectángulo exacto `(left, top, width, height)` del monitor en `mss`, `_sync_input_desktop()` acopla el hilo al escritorio de entrada activo de forma no bloqueante, `SetCursorPos(target_x, target_y)` posiciona el cursor en el píxel físico exacto y `_send_mouse_event()` inyecta los eventos `SendInput` (`dx=0, dy=0`) con pausa nativa de `15ms` en `double_left`.

### 7.2 Registro del Bucle de Verificación Convergente Post-Mouse Mapping (`VUELTAS_LIMPIAS_CONSECUTIVAS == 2`)
- **Correcciones aplicadas antes del bucle limpio:**
  1. **`mobile/lib/services/updater_service.dart` + `flutter_updater_adapter.dart` + `mobile/test/updater_test.dart`:** Desacoplado `UpdaterService` de los plugins nativos de Flutter mediante la interfaz `UpdaterPlatformAdapter` (`DefaultUpdaterPlatformAdapter` en Dart puro y `FlutterUpdaterPlatformAdapter` en `deck_screen.dart`), solucionando el fallo de `updater_test.dart` en ejecución directa con Dart SDK.
  2. **`mobile/lib/transport/control_client.dart`:** Añadido bloque `try / finally` en `sendCommand()` para eliminar fugas de memoria en `_pendingCommandCompleters` y aislado el enrutamiento por `cmdId` para que respuestas tardías nunca resuelvan completers de otro comando.
  3. **`mobile/lib/ui/screens/screen_viewer_screen.dart` + `touch_coordinate_mapper.dart`:** Añadido bloqueo de clics durante/tras gestos de zoom o paneo (`Listener` + `InteractiveViewer.onInteraction*`) y parser binario de dimensiones JPEG (`extractJpegDimensions`).
  4. **`host/engine/handlers/mouse.py` + `host/engine/dispatcher.py`:** Añadida sincronización no bloqueante con el escritorio de entrada (`_sync_input_desktop`), pausa nativa de `15ms` para `double_left` y captura explícita de `MouseExecutionError` en `CommandDispatcher`.
- **Vuelta Limpia #1 (`VUELTAS_LIMPIAS_CONSECUTIVAS = 1`):**
  - `py_compile`: **60/60 archivos Python compilados sin errores**.
  - `pytest tests`: **131/131 tests en verde**.
  - `dart analyze` + 6 suites en `mobile/test/` (`crypto_test.dart`, `pairing_test.dart`, `saved_hosts_test.dart`, `touch_coordinate_mapper_test.dart`, `updater_test.dart`, `zero_trust_wol_test.dart`): **0 issues, 35/35 tests en verde**.
  - Modificaciones realizadas durante la Vuelta 1: **0 líneas**.
- **Vuelta Limpia #2 (`VUELTAS_LIMPIAS_CONSECUTIVAS = 2`):**
  - Re-ejecución íntegra de `py_compile` (**60/60 OK**), `pytest tests` (**131/131 passed**), `dart analyze` (**0 issues**) y las 6 suites de `mobile/test/` (**35/35 passed**).
  - Modificaciones realizadas durante la Vuelta 2: **0 líneas**.


