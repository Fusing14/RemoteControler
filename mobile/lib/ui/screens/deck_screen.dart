import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../transport/control_client.dart';
import '../../services/pairing_client.dart';
import '../../protocol/envelope_builder.dart';
import '../../crypto/key_manager.dart';
import '../widgets/deck_button.dart';
import 'scanner_screen.dart';
import 'screen_viewer_screen.dart';
import 'camera_viewer_screen.dart';
import 'games_screen.dart';
import 'apps_screen.dart';
import '../../services/updater_service.dart';
import '../../services/wol_service.dart';
import '../../services/saved_hosts_service.dart';
import 'hosts_manager_screen.dart';

/// Pantalla principal estilo Stream Deck con cuadrícula táctil reactiva.
class DeckScreen extends StatefulWidget {
  final String hostEndpoint;
  final PairingClient pairingClient;
  final KeyManager? keyManager;
  final bool allowLoopback;

  const DeckScreen({
    super.key,
    required this.hostEndpoint,
    required this.pairingClient,
    this.keyManager,
    this.allowLoopback = true,
  });

  @override
  State<DeckScreen> createState() => _DeckScreenState();
}

class _DeckScreenState extends State<DeckScreen> with WidgetsBindingObserver {
  RemoteControlClient? _controlClient;
  StreamSubscription<DeckConnectionState>? _stateSubscription;
  DeckConnectionState _connectionState = DeckConnectionState.disconnected;
  final UpdaterService _updaterService = UpdaterService();
  late final SavedHostsService _savedHostsService =
      SavedHostsService(storage: widget.pairingClient.storage);
  late String _currentEndpoint = widget.hostEndpoint;
  Timer? _updateTimer;
  bool _isPlaying = true;

  // Estado del micrófono (Intercom en tiempo real)
  bool _isMicStreaming = false;
  StreamSubscription? _micStreamSub;
  static const MethodChannel _micMethodChannel =
      MethodChannel('com.remotecontroler.securedeck/mic');
  static const EventChannel _micEventChannel =
      EventChannel('com.remotecontroler.securedeck/mic_stream');

  @override
  void initState() {
    super.initState();
    _currentEndpoint = widget.hostEndpoint;
    WidgetsBinding.instance.addObserver(this);
    _savedHostsService.ensureInitialized();
    _initControlClient(_currentEndpoint);
    _checkForUpdates(silent: true);
    _updateTimer = Timer.periodic(
      const Duration(minutes: 30),
      (_) => _checkForUpdates(silent: true),
    );
  }

  Future<void> _initControlClient([String? endpoint]) async {
    final targetEndpoint = endpoint ?? _currentEndpoint;
    _currentEndpoint = targetEndpoint;

    final km = widget.keyManager ?? widget.pairingClient.keyManager;
    await km.ensureInitialized();

    final builder = EnvelopeBuilder(keyManager: km);

    await _stateSubscription?.cancel();
    _controlClient?.dispose();

    final client = RemoteControlClient(
      hostEndpoint: targetEndpoint,
      envelopeBuilder: builder,
      allowLoopback: widget.allowLoopback,
    );

    _stateSubscription = client.stateStream.listen((state) {
      if (mounted) {
        setState(() => _connectionState = state);
        if (state == DeckConnectionState.connected) {
          _fetchHostInfo();
        }
      }
    });

    if (mounted) {
      setState(() {
        _controlClient = client;
      });
    } else {
      _controlClient = client;
    }

    await client.connect();
  }

  Future<void> _openHostsManager() async {
    final selectedHost = await Navigator.of(context).push<SavedHost>(
      MaterialPageRoute(
        builder: (_) => HostsManagerScreen(
          savedHostsService: _savedHostsService,
          pairingClient: widget.pairingClient,
          keyManager: widget.keyManager ?? widget.pairingClient.keyManager,
          currentActiveEndpoint: _currentEndpoint,
        ),
      ),
    );

    if (selectedHost != null &&
        selectedHost.endpoint.isNotEmpty &&
        selectedHost.endpoint != _currentEndpoint &&
        mounted) {
      setState(() {
        _currentEndpoint = selectedHost.endpoint;
      });
      await _initControlClient(selectedHost.endpoint);
    }
  }

  @override
  void dispose() {
    _updateTimer?.cancel();
    _stopMic();
    WidgetsBinding.instance.removeObserver(this);
    _stateSubscription?.cancel();
    _controlClient?.dispose();
    super.dispose();
  }

  Future<void> _toggleMic() async {
    if (_isMicStreaming) {
      await _stopMic();
    } else {
      await _startMic();
    }
  }

  Future<void> _startMic() async {
    try {
      final hasPerm =
          await _micMethodChannel.invokeMethod<bool>('hasPermission') ?? false;
      if (!hasPerm) {
        await _micMethodChannel.invokeMethod('requestPermission');
        final granted =
            await _micMethodChannel.invokeMethod<bool>('hasPermission') ??
                false;
        if (!granted) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text(
                    'Permiso de micrófono requerido para transmitir audio.'),
                backgroundColor: Color(0xFFEF4444),
              ),
            );
          }
          return;
        }
      }

      _micStreamSub = _micEventChannel.receiveBroadcastStream().listen(
        (chunk) {
          if (_isMicStreaming &&
              _controlClient != null &&
              chunk is String &&
              chunk.isNotEmpty) {
            _controlClient?.sendStreamPacket(
              commandId: 'MIC_AUDIO_CHUNK',
              payload: {
                'audio_b64': chunk,
                'sample_rate': 16000,
                'channels': 1,
              },
            );
          }
        },
        onError: (err) {
          debugPrint('[MicStream] Error: $err');
          _stopMic();
        },
      );

      await _micMethodChannel.invokeMethod('startMic');
      if (mounted) {
        setState(() {
          _isMicStreaming = true;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Micrófono activado. Hablando en vivo al PC...'),
            backgroundColor: Color(0xFF10B981),
            duration: Duration(seconds: 2),
          ),
        );
      }
    } catch (e) {
      debugPrint('[Mic] Excepción al iniciar micrófono: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error al iniciar micrófono: $e'),
            backgroundColor: const Color(0xFFEF4444),
          ),
        );
      }
      _stopMic();
    }
  }

  Future<void> _stopMic() async {
    await _micStreamSub?.cancel();
    _micStreamSub = null;
    try {
      await _micMethodChannel.invokeMethod('stopMic');
    } catch (_) {}
    if (mounted) {
      setState(() {
        _isMicStreaming = false;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Transmisión de micrófono detenida.'),
          duration: Duration(seconds: 1),
        ),
      );
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _controlClient?.ensureConnected();
      _checkForUpdates(silent: true);
    }
  }

  Future<void> _sendCommand(
      String commandId, Map<String, dynamic> payload) async {
    if (_controlClient == null) {
      final km = widget.keyManager ?? widget.pairingClient.keyManager;
      await km.ensureInitialized();
      if (_controlClient == null) {
        await _initControlClient();
      }
    }

    try {
      final res = await _controlClient!.sendCommand(
        commandId: commandId,
        payload: payload,
      );

      final status = res['status'] as String?;
      if (status != 'SUCCESS') {
        throw Exception(res['message'] ?? 'Comando rechazado por el Host.');
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text(
              e.toString().replaceAll('Exception: ', ''),
              style: const TextStyle(
                  color: Colors.white, fontWeight: FontWeight.w600),
            ),
            duration: const Duration(seconds: 2),
          ),
        );
      }
      rethrow;
    }
  }

  Future<void> _mediaPrevious() async {
    if (_controlClient == null) {
      final km = widget.keyManager ?? widget.pairingClient.keyManager;
      await km.ensureInitialized();
      if (_controlClient == null) {
        await _initControlClient();
      }
    }
    try {
      await _controlClient!.mediaPrevious();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text(
              e.toString().replaceAll('Exception: ', ''),
              style: const TextStyle(
                  color: Colors.white, fontWeight: FontWeight.w600),
            ),
            duration: const Duration(seconds: 2),
          ),
        );
      }
      rethrow;
    }
  }

  Future<void> _mediaPlayPause() async {
    setState(() {
      _isPlaying = !_isPlaying;
    });
    if (_controlClient == null) {
      final km = widget.keyManager ?? widget.pairingClient.keyManager;
      await km.ensureInitialized();
      if (_controlClient == null) {
        await _initControlClient();
      }
    }
    try {
      await _controlClient!.mediaPlayPause();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text(
              e.toString().replaceAll('Exception: ', ''),
              style: const TextStyle(
                  color: Colors.white, fontWeight: FontWeight.w600),
            ),
            duration: const Duration(seconds: 2),
          ),
        );
      }
      rethrow;
    }
  }

  Future<void> _mediaNext() async {
    if (_controlClient == null) {
      final km = widget.keyManager ?? widget.pairingClient.keyManager;
      await km.ensureInitialized();
      if (_controlClient == null) {
        await _initControlClient();
      }
    }
    try {
      await _controlClient!.mediaNext();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text(
              e.toString().replaceAll('Exception: ', ''),
              style: const TextStyle(
                  color: Colors.white, fontWeight: FontWeight.w600),
            ),
            duration: const Duration(seconds: 2),
          ),
        );
      }
      rethrow;
    }
  }

  void _confirmCriticalAction({
    required String title,
    required String message,
    required VoidCallback onConfirm,
  }) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E2230),
        title: Text(title,
            style: const TextStyle(
                color: Colors.white, fontWeight: FontWeight.bold)),
        content:
            Text(message, style: const TextStyle(color: Color(0xFF94A3B8))),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child:
                const Text('Cancelar', style: TextStyle(color: Colors.white54)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFEF4444)),
            onPressed: () {
              Navigator.pop(ctx);
              onConfirm();
            },
            child:
                const Text('Ejecutar', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );
  }

  void _showUnlockPcDialog() {
    final passwordController = TextEditingController();
    bool obscureText = true;

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (context, setDialogState) {
          return AlertDialog(
            backgroundColor: const Color(0xFF161A23),
            shape:
                RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
            title: const Row(
              children: [
                Icon(Icons.lock_open_rounded,
                    color: Color(0xFF06B6D4), size: 26),
                SizedBox(width: 10),
                Text(
                  'Desbloquear PC',
                  style: TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.bold),
                ),
              ],
            ),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Introduce tu PIN de Windows Hello o contraseña de Windows para autenticar y desbloquear:',
                  style: TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: passwordController,
                  obscureText: obscureText,
                  autofocus: true,
                  style: const TextStyle(color: Colors.white, fontSize: 14),
                  decoration: InputDecoration(
                    hintText: 'PIN o Contraseña de Windows',
                    hintStyle:
                        const TextStyle(color: Colors.white30, fontSize: 14),
                    filled: true,
                    fillColor: const Color(0xFF0F1117),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(10),
                      borderSide: BorderSide.none,
                    ),
                    suffixIcon: IconButton(
                      icon: Icon(
                        obscureText ? Icons.visibility_off : Icons.visibility,
                        color: Colors.white54,
                        size: 20,
                      ),
                      onPressed: () {
                        setDialogState(() {
                          obscureText = !obscureText;
                        });
                      },
                    ),
                  ),
                ),
              ],
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Cancelar',
                    style: TextStyle(color: Colors.white54)),
              ),
              ElevatedButton.icon(
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF06B6D4),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8)),
                ),
                icon: const Icon(Icons.check, size: 18, color: Colors.white),
                label: const Text('Desbloquear',
                    style: TextStyle(
                        color: Colors.white, fontWeight: FontWeight.bold)),
                onPressed: () async {
                  final pwd = passwordController.text;
                  if (pwd.isEmpty) return;
                  Navigator.pop(ctx);
                  await _sendCommand('UNLOCK_PC', {'password': pwd});
                },
              ),
            ],
          );
        },
      ),
    );
  }

  void _showOpenUrlDialog() {
    final urlController = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161A23),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Row(
          children: [
            Icon(Icons.open_in_browser_rounded,
                color: Color(0xFF0EA5E9), size: 26),
            SizedBox(width: 10),
            Text(
              'Abrir URL en el PC',
              style: TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.bold),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Escribe o pega un enlace para abrirlo inmediatamente en el navegador predeterminado de tu ordenador:',
              style: TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
            ),
            const SizedBox(height: 14),
            TextField(
              controller: urlController,
              keyboardType: TextInputType.url,
              style: const TextStyle(color: Colors.white, fontSize: 14),
              decoration: InputDecoration(
                hintText: 'https://ejemplo.com',
                hintStyle: const TextStyle(color: Colors.white30, fontSize: 14),
                filled: true,
                fillColor: const Color(0xFF0F1117),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                  borderSide: BorderSide.none,
                ),
                suffixIcon: IconButton(
                  icon: const Icon(Icons.paste_rounded,
                      color: Color(0xFF0EA5E9), size: 20),
                  tooltip: 'Pegar del portapapeles',
                  onPressed: () async {
                    final clip = await Clipboard.getData(Clipboard.kTextPlain);
                    if (clip?.text != null && clip!.text!.isNotEmpty) {
                      urlController.text = clip.text!.trim();
                    }
                  },
                ),
              ),
            ),
            const SizedBox(height: 14),
            const Text(
              'Accesos directos rápidos:',
              style: TextStyle(
                  color: Color(0xFF64748B),
                  fontSize: 11,
                  fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            Wrap(
              spacing: 6,
              runSpacing: 6,
              children: [
                _buildUrlShortcutChip(
                    'YouTube', 'https://youtube.com', urlController),
                _buildUrlShortcutChip(
                    'GitHub', 'https://github.com', urlController),
                _buildUrlShortcutChip(
                    'Twitch', 'https://twitch.tv', urlController),
                _buildUrlShortcutChip(
                    'Google', 'https://google.com', urlController),
                _buildUrlShortcutChip(
                    'ChatGPT', 'https://chatgpt.com', urlController),
              ],
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child:
                const Text('Cancelar', style: TextStyle(color: Colors.white54)),
          ),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF0EA5E9),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8)),
            ),
            icon:
                const Icon(Icons.launch_rounded, size: 18, color: Colors.white),
            label: const Text('Abrir en PC',
                style: TextStyle(
                    color: Colors.white, fontWeight: FontWeight.bold)),
            onPressed: () async {
              final raw = urlController.text.trim();
              if (raw.isEmpty) return;
              Navigator.pop(ctx);
              await _sendCommand('OPEN_URL', {'url': raw});
            },
          ),
        ],
      ),
    );
  }

  Widget _buildUrlShortcutChip(
      String label, String url, TextEditingController controller) {
    return InkWell(
      onTap: () => controller.text = url,
      borderRadius: BorderRadius.circular(6),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        decoration: BoxDecoration(
          color: const Color(0xFF0F1117),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: const Color(0xFF1E2230)),
        ),
        child: Text(
          label,
          style: const TextStyle(
              color: Color(0xFFCBD5E1),
              fontSize: 11,
              fontWeight: FontWeight.w600),
        ),
      ),
    );
  }

  Future<void> _fetchHostInfo() async {
    try {
      final res = await _controlClient?.sendCommand(
        commandId: 'HOST_INFO',
        payload: {},
      );
      if (res != null && res['status'] == 'SUCCESS') {
        final data = res['data'] as Map<String, dynamic>?;
        if (data != null) {
          final mac = data['mac_address'] as String?;
          final bcast = data['broadcast_ip'] as String?;
          if (mac != null && mac.trim().isNotEmpty) {
            await widget.pairingClient.savePairedMacAddress(mac.trim());
          }
          if (bcast != null && bcast.trim().isNotEmpty) {
            await widget.pairingClient.savePairedBroadcastIp(bcast.trim());
          }
        }
      }
    } catch (e) {
      debugPrint('[DeckScreen] No se pudo obtener HOST_INFO: $e');
    }
  }

  Future<void> _wakeOnLan() async {
    String? mac = await widget.pairingClient.getPairedMacAddress();
    final bcast = await widget.pairingClient.getPairedBroadcastIp();

    if (mac == null || mac.trim().isEmpty) {
      if (!mounted) return;
      final enteredMac = await showDialog<String>(
        context: context,
        builder: (ctx) {
          final ctrl = TextEditingController();
          return AlertDialog(
            backgroundColor: const Color(0xFF161A23),
            shape:
                RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
            title: const Row(
              children: [
                Icon(Icons.power_rounded, color: Color(0xFF10B981)),
                SizedBox(width: 8),
                Text('Wake-on-LAN',
                    style: TextStyle(
                        color: Colors.white,
                        fontSize: 18,
                        fontWeight: FontWeight.bold)),
              ],
            ),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Introduce la dirección MAC física de la tarjeta de red del PC (ej: 30:56:0F:23:15:2C):',
                  style: TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: ctrl,
                  style: const TextStyle(
                      color: Colors.white, fontFamily: 'Consolas'),
                  decoration: InputDecoration(
                    hintText: 'XX:XX:XX:XX:XX:XX',
                    hintStyle: const TextStyle(color: Colors.white38),
                    filled: true,
                    fillColor: const Color(0xFF0F1117),
                    border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8)),
                  ),
                ),
              ],
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Cancelar',
                    style: TextStyle(color: Colors.white54)),
              ),
              ElevatedButton(
                style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF10B981)),
                onPressed: () => Navigator.pop(ctx, ctrl.text.trim()),
                child: const Text('Guardar y Encender',
                    style: TextStyle(
                        color: Colors.white, fontWeight: FontWeight.bold)),
              ),
            ],
          );
        },
      );
      if (enteredMac == null || enteredMac.trim().isEmpty) return;
      mac = enteredMac.trim();
      await widget.pairingClient.savePairedMacAddress(mac);
    }

    try {
      await WolService.wake(
        macAddress: mac,
        broadcastIp: bcast,
        hostIpOrEndpoint: _currentEndpoint,
      );
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFF10B981),
            content: Row(
              children: [
                const Icon(Icons.bolt_rounded, color: Colors.white, size: 20),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Paquete Mágico Wake-on-LAN transmitido a $mac',
                    style: const TextStyle(
                        color: Colors.white, fontWeight: FontWeight.bold),
                  ),
                ),
              ],
            ),
            duration: const Duration(seconds: 3),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text(
              'Error Wake-on-LAN: ${e.toString().replaceAll('ArgumentError: ', '')}',
              style: const TextStyle(
                  color: Colors.white, fontWeight: FontWeight.bold),
            ),
            duration: const Duration(seconds: 3),
          ),
        );
      }
    }
  }

  Future<void> _checkForUpdates({bool silent = false}) async {
    try {
      if (!silent && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            backgroundColor: Color(0xFF1E2230),
            content: Text(
              'Buscando actualizaciones...',
              style: TextStyle(color: Colors.white),
            ),
            duration: Duration(seconds: 1),
          ),
        );
      }

      final info = await _updaterService.checkForUpdate();
      if (!mounted) return;

      if (info.hasUpdate) {
        if (silent) {
          await _updaterService.showUpdateNotification(info);
        } else {
          _showUpdateDialog(info);
        }
      } else if (!silent) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFF10B981),
            content: Text(
              'Ya tienes la versión más reciente (v${info.currentVersion})',
              style: const TextStyle(
                  color: Colors.white, fontWeight: FontWeight.w600),
            ),
            duration: const Duration(seconds: 2),
          ),
        );
      }
    } catch (e) {
      if (!silent && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text(
              'Error al buscar actualizaciones: ${e.toString().replaceAll('Exception: ', '')}',
              style: const TextStyle(
                  color: Colors.white, fontWeight: FontWeight.w600),
            ),
            duration: const Duration(seconds: 3),
          ),
        );
      }
    }
  }

  void _showUpdateDialog(UpdateInfo info) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161A23),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Row(
          children: [
            Icon(Icons.system_update_alt, color: Color(0xFF6366F1), size: 28),
            SizedBox(width: 12),
            Expanded(
              child: Text(
                'Actualización Disponible',
                style: TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 18),
              ),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: const Color(0xFF0F1117),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Actual: v${info.currentVersion}',
                    style: const TextStyle(color: Colors.white60, fontSize: 13),
                  ),
                  const Icon(Icons.arrow_forward,
                      color: Color(0xFF6366F1), size: 16),
                  Text(
                    'Nueva: v${info.latestVersion}',
                    style: const TextStyle(
                      color: Color(0xFF10B981),
                      fontWeight: FontWeight.bold,
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
            ),
            if (info.releaseNotes != null &&
                info.releaseNotes!.trim().isNotEmpty) ...[
              const SizedBox(height: 14),
              const Text(
                'Notas de la versión:',
                style: TextStyle(
                    color: Colors.white70,
                    fontWeight: FontWeight.w600,
                    fontSize: 12),
              ),
              const SizedBox(height: 6),
              Container(
                constraints: const BoxConstraints(maxHeight: 140),
                width: double.infinity,
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xFF0F1117),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SingleChildScrollView(
                  child: Text(
                    info.releaseNotes!,
                    style:
                        const TextStyle(color: Color(0xFF94A3B8), fontSize: 12),
                  ),
                ),
              ),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Más tarde',
                style: TextStyle(color: Colors.white54)),
          ),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF6366F1),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8)),
            ),
            icon: const Icon(Icons.download, size: 18, color: Colors.white),
            label: const Text('Actualizar ahora',
                style: TextStyle(color: Colors.white)),
            onPressed: () {
              Navigator.pop(ctx);
              final url = info.downloadUrl;
              if (url != null && url.startsWith('https://')) {
                debugPrint(
                    '[OTA] Usuario confirmó actualización. Iniciando descarga: $url');
                _startDownloadAndInstall(url);
              } else {
                debugPrint(
                    '[OTA] Error: URL de descarga nula o no segura: $url');
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      backgroundColor: Color(0xFFEF4444),
                      content: Text(
                          'Error: La URL de descarga no es válida o segura.'),
                    ),
                  );
                }
              }
            },
          ),
        ],
      ),
    );
  }

  void _startDownloadAndInstall(String downloadUrl) {
    debugPrint(
        '[OTA] Iniciando flujo de actualización OTA desde: $downloadUrl');
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (dialogCtx) {
        double progress = 0.0;
        String statusText = 'Iniciando descarga...';
        bool hasError = false;
        bool isDialogActive = true;
        StreamSubscription<OtaEvent>? otaSub;

        return StatefulBuilder(
          builder: (context, setModalState) {
            void safeSetState(VoidCallback fn) {
              if (isDialogActive && dialogCtx.mounted) {
                setModalState(fn);
              }
            }

            void closeDialog() {
              if (isDialogActive) {
                isDialogActive = false;
                otaSub?.cancel();
                if (dialogCtx.mounted) {
                  Navigator.of(dialogCtx, rootNavigator: true).pop();
                }
              }
            }

            try {
              otaSub ??= _updaterService.startOtaUpdate(downloadUrl).listen(
                (event) {
                  debugPrint(
                      '[OTA] Cambio de estado OtaUpdate: status=${event.status.name}, value=${event.value}');
                  switch (event.status) {
                    case OtaStatus.DOWNLOADING:
                      final val = int.tryParse(event.value ?? '0') ?? 0;
                      debugPrint('[OTA] Progreso de descarga: $val%');
                      safeSetState(() {
                        progress = val / 100.0;
                        statusText = 'Descargando actualización: $val%';
                      });
                      break;
                    case OtaStatus.INSTALLING:
                      debugPrint(
                          '[OTA] Descarga completada al 100%. Invocando instalador nativo de Android...');
                      safeSetState(() {
                        progress = 1.0;
                        statusText =
                            'Abriendo instalador de Android... Sigue las instrucciones del sistema.';
                      });
                      Future.delayed(const Duration(seconds: 2), () {
                        closeDialog();
                      });
                      break;
                    case OtaStatus.PERMISSION_NOT_GRANTED_ERROR:
                      debugPrint(
                          '[OTA] ERROR: Permiso para instalar apps de origen desconocido no concedido.');
                      safeSetState(() {
                        hasError = true;
                        statusText =
                            'Permiso denegado. Habilita "Instalar apps desconocidas" para SecureDeck en Ajustes de Android.';
                      });
                      break;
                    case OtaStatus.ALREADY_RUNNING_ERROR:
                      debugPrint(
                          '[OTA] ERROR: Ya existe una descarga o actualización en curso.');
                      safeSetState(() {
                        hasError = true;
                        statusText = 'Ya hay una actualización en curso.';
                      });
                      break;
                    case OtaStatus.INTERNAL_ERROR:
                      debugPrint(
                          '[OTA] ERROR INTERNO en OtaUpdate: ${event.value}');
                      safeSetState(() {
                        hasError = true;
                        statusText =
                            'Error al actualizar: ${event.value ?? event.status.name}';
                      });
                      break;
                    default:
                      debugPrint(
                          '[OTA] Estado no controlado: ${event.status.name} (valor: ${event.value})');
                      safeSetState(() {
                        hasError = true;
                        statusText =
                            'Estado: ${event.status.name} (${event.value ?? ""})';
                      });
                      break;
                  }
                },
                onError: (err, stackTrace) {
                  debugPrint(
                      '[OTA] Error capturado en stream OtaUpdate: $err\n$stackTrace');
                  safeSetState(() {
                    hasError = true;
                    statusText = 'Error en la actualización: $err';
                  });
                },
                onDone: () {
                  debugPrint(
                      '[OTA] Stream de OtaUpdate finalizado exitosamente (onDone).');
                },
                cancelOnError: true,
              );
            } catch (e, stackTrace) {
              debugPrint(
                  '[OTA] Excepción síncrona al conectar stream: $e\n$stackTrace');
              safeSetState(() {
                hasError = true;
                statusText = 'Error al iniciar descarga: $e';
              });
            }

            return AlertDialog(
              backgroundColor: const Color(0xFF161A23),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(16)),
              title: const Row(
                children: [
                  Icon(Icons.system_update_alt, color: Color(0xFF6366F1)),
                  SizedBox(width: 12),
                  Text(
                    'Instalando actualización',
                    style: TextStyle(
                        color: Colors.white,
                        fontSize: 16,
                        fontWeight: FontWeight.bold),
                  ),
                ],
              ),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    statusText,
                    style: TextStyle(
                      color: hasError
                          ? const Color(0xFFEF4444)
                          : const Color(0xFFCBD5E1),
                      fontSize: 13,
                    ),
                  ),
                  const SizedBox(height: 16),
                  LinearProgressIndicator(
                    value: (progress > 0 && progress <= 1.0 && !hasError)
                        ? progress
                        : null,
                    backgroundColor: const Color(0xFF0F1117),
                    valueColor: AlwaysStoppedAnimation<Color>(
                      hasError
                          ? const Color(0xFFEF4444)
                          : const Color(0xFF6366F1),
                    ),
                  ),
                ],
              ),
              actions: [
                if (hasError || progress >= 1.0)
                  TextButton(
                    onPressed: closeDialog,
                    child: const Text('Cerrar',
                        style: TextStyle(color: Colors.white54)),
                  ),
              ],
            );
          },
        );
      },
    );
  }

  Widget _buildStatusIndicator() {
    Color color;
    String label;

    switch (_connectionState) {
      case DeckConnectionState.connected:
        color = const Color(0xFF10B981); // Verde esmeralda
        label = _currentEndpoint;
        break;
      case DeckConnectionState.connecting:
      case DeckConnectionState.reconnecting:
        color = const Color(0xFFF59E0B); // Ámbar
        label = 'Conectando...';
        break;
      case DeckConnectionState.disconnected:
        color = const Color(0xFFEF4444); // Rojo
        label = 'Desconectado';
        break;
    }

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 9,
          height: 9,
          decoration: BoxDecoration(
            color: color,
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: color.withOpacity(0.6),
                blurRadius: 6,
                spreadRadius: 1,
              ),
            ],
          ),
        ),
        const SizedBox(width: 8),
        Text(
          label,
          style: const TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w600,
              color: Color(0xFFCBD5E1)),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF090A0F),
      appBar: AppBar(
        backgroundColor: const Color(0xFF11141C),
        elevation: 0,
        title: _buildStatusIndicator(),
        actions: [
          IconButton(
            icon: const Icon(Icons.devices_rounded, color: Color(0xFF6366F1)),
            tooltip: 'Mis Ordenadores',
            onPressed: _openHostsManager,
          ),
          IconButton(
            icon: const Icon(Icons.system_update, color: Colors.white70),
            tooltip: 'Buscar actualizaciones',
            onPressed: () => _checkForUpdates(silent: false),
          ),
          IconButton(
            icon: const Icon(Icons.refresh, color: Colors.white70),
            tooltip: 'Reconectar',
            onPressed: () => _controlClient?.connect(),
          ),
          IconButton(
            icon: const Icon(Icons.link_off, color: Color(0xFFEF4444)),
            tooltip: 'Desvincular Host',
            onPressed: () {
              _confirmCriticalAction(
                title: 'Desvincular Host',
                message:
                    '¿Estás seguro de que deseas desvincular este teléfono del PC?',
                onConfirm: () async {
                  await widget.pairingClient.unpair();
                  if (mounted) {
                    Navigator.of(context).pushReplacement(
                      MaterialPageRoute(
                        builder: (_) =>
                            ScannerScreen(pairingClient: widget.pairingClient),
                      ),
                    );
                  }
                },
              );
            },
          ),
        ],
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Sección Multimedia
              const Text(
                'MULTIMEDIA',
                style: TextStyle(
                  color: Color(0xFF64748B),
                  fontSize: 11,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 1.2,
                ),
              ),
              const SizedBox(height: 12),
              // Controles de Reproducción Clásicos (Anterior, Pausar/Reanudar, Siguiente)
              Row(
                children: [
                  Expanded(
                    child: DeckButton(
                      label: 'Anterior',
                      icon: Icons.skip_previous_rounded,
                      accentColor: const Color(0xFF818CF8),
                      onPressed: () => _mediaPrevious(),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: DeckButton(
                      label: _isPlaying ? 'Pausar' : 'Reanudar',
                      icon: _isPlaying
                          ? Icons.pause_circle_filled_rounded
                          : Icons.play_circle_filled_rounded,
                      accentColor: const Color(0xFF6366F1),
                      onPressed: () => _mediaPlayPause(),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: DeckButton(
                      label: 'Siguiente',
                      icon: Icons.skip_next_rounded,
                      accentColor: const Color(0xFF818CF8),
                      onPressed: () => _mediaNext(),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              // Controles de Volumen
              Row(
                children: [
                  Expanded(
                    child: DeckButton(
                      label: 'Mute',
                      icon: Icons.volume_off_rounded,
                      accentColor: const Color(0xFF8B5CF6),
                      onPressed: () =>
                          _sendCommand('MEDIA', {'action': 'VOLUME_MUTE'}),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: DeckButton(
                      label: 'Volumen +',
                      icon: Icons.volume_up_rounded,
                      accentColor: const Color(0xFF3B82F6),
                      onPressed: () =>
                          _sendCommand('MEDIA', {'action': 'VOLUME_UP'}),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: DeckButton(
                      label: 'Volumen -',
                      icon: Icons.volume_down_rounded,
                      accentColor: const Color(0xFF0EA5E9),
                      onPressed: () =>
                          _sendCommand('MEDIA', {'action': 'VOLUME_DOWN'}),
                    ),
                  ),
                ],
              ),

              const SizedBox(height: 24),

              // Sección Sistema & Energía
              const Text(
                'ENERGÍA & SISTEMA',
                style: TextStyle(
                  color: Color(0xFF64748B),
                  fontSize: 11,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 1.2,
                ),
              ),
              const SizedBox(height: 12),
              GridView.count(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                crossAxisCount: 2,
                mainAxisSpacing: 12,
                crossAxisSpacing: 12,
                childAspectRatio: 1.4,
                children: [
                  DeckButton(
                    label: 'Bloquear PC',
                    subtitle: 'LockWorkStation',
                    icon: Icons.lock_rounded,
                    accentColor: const Color(0xFFF59E0B), // Ámbar
                    onPressed: () =>
                        _sendCommand('SYS_POWER', {'action': 'LOCK'}),
                  ),
                  DeckButton(
                    label: 'Suspender',
                    subtitle: 'SetSuspendState',
                    icon: Icons.bedtime_rounded,
                    accentColor: const Color(0xFF06B6D4), // Cyan
                    onPressed: () => _sendCommand(
                        'SYS_POWER', {'action': 'SLEEP', 'force': false}),
                  ),
                  DeckButton(
                    label: 'Reiniciar',
                    icon: Icons.restart_alt_rounded,
                    accentColor: const Color(0xFFF97316), // Naranja
                    onPressed: () {
                      _confirmCriticalAction(
                        title: 'Reiniciar PC',
                        message: '¿Confirmas reiniciar el equipo de inmediato?',
                        onConfirm: () => _sendCommand(
                            'SYS_POWER', {'action': 'REBOOT', 'force': true}),
                      );
                      return Future.value();
                    },
                  ),
                  DeckButton(
                    label: 'Apagar PC',
                    icon: Icons.power_settings_new_rounded,
                    accentColor: const Color(0xFFEF4444), // Rojo
                    onPressed: () {
                      _confirmCriticalAction(
                        title: 'Apagar PC',
                        message: '¿Confirmas el apagado del PC?',
                        onConfirm: () => _sendCommand(
                            'SYS_POWER', {'action': 'SHUTDOWN', 'force': true}),
                      );
                      return Future.value();
                    },
                  ),
                  DeckButton(
                    label: 'Desbloquear PC',
                    subtitle: 'PIN o Contraseña',
                    icon: Icons.lock_open_rounded,
                    accentColor: const Color(0xFF06B6D4), // Cyan
                    onPressed: () {
                      _showUnlockPcDialog();
                      return Future.value();
                    },
                  ),
                  DeckButton(
                    label: 'Encender PC',
                    subtitle: 'Wake-on-LAN',
                    icon: Icons.power_rounded,
                    accentColor: const Color(0xFF10B981), // Esmeralda
                    onPressed: () {
                      _wakeOnLan();
                      return Future.value();
                    },
                  ),
                ],
              ),

              const SizedBox(height: 24),

              // Sección Pantalla en Vivo y Aplicaciones
              const Text(
                'PANTALLA Y BIBLIOTECA',
                style: TextStyle(
                  color: Color(0xFF64748B),
                  fontSize: 11,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 1.2,
                ),
              ),
              const SizedBox(height: 12),
              GridView.count(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                crossAxisCount: 2,
                mainAxisSpacing: 12,
                crossAxisSpacing: 12,
                childAspectRatio: 1.4,
                children: [
                  DeckButton(
                    label: 'Ver Pantalla',
                    subtitle: 'Transmisión en vivo',
                    icon: Icons.monitor_rounded,
                    accentColor: const Color(0xFF8B5CF6), // Púrpura
                    onPressed: () {
                      if (_controlClient != null) {
                        Navigator.of(context).push(
                          MaterialPageRoute(
                            builder: (_) => ScreenViewerScreen(
                                controlClient: _controlClient!),
                          ),
                        );
                      }
                      return Future.value();
                    },
                  ),
                  DeckButton(
                    label: 'Ver Cámara',
                    subtitle: 'Webcam en vivo',
                    icon: Icons.videocam_rounded,
                    accentColor: const Color(0xFF14B8A6), // Teal
                    onPressed: () {
                      if (_controlClient != null) {
                        Navigator.of(context).push(
                          MaterialPageRoute(
                            builder: (_) => CameraViewerScreen(
                                controlClient: _controlClient!),
                          ),
                        );
                      }
                      return Future.value();
                    },
                  ),
                  DeckButton(
                    label:
                        _isMicStreaming ? 'Micrófono (ON)' : 'Micrófono al PC',
                    subtitle: _isMicStreaming
                        ? 'Transmitiendo en vivo'
                        : 'Intercom / Walkie-Talkie',
                    icon: _isMicStreaming
                        ? Icons.mic_rounded
                        : Icons.mic_none_rounded,
                    accentColor: _isMicStreaming
                        ? const Color(0xFFEF4444)
                        : const Color(0xFFEC4899), // Rojo si activo / Rosa
                    onPressed: () {
                      _toggleMic();
                      return Future.value();
                    },
                  ),
                  DeckButton(
                    label: 'Juegos Instalados',
                    subtitle: 'Steam y Epic Games',
                    icon: Icons.sports_esports_rounded,
                    accentColor: const Color(0xFF10B981), // Esmeralda
                    onPressed: () {
                      if (_controlClient != null) {
                        Navigator.of(context).push(
                          MaterialPageRoute(
                            builder: (_) =>
                                GamesScreen(controlClient: _controlClient!),
                          ),
                        );
                      }
                      return Future.value();
                    },
                  ),
                  DeckButton(
                    label: 'Aplicaciones',
                    subtitle: 'Programas de Windows',
                    icon: Icons.apps_rounded,
                    accentColor: const Color(0xFF6366F1), // Indigo
                    onPressed: () {
                      if (_controlClient != null) {
                        Navigator.of(context).push(
                          MaterialPageRoute(
                            builder: (_) =>
                                AppsScreen(controlClient: _controlClient!),
                          ),
                        );
                      }
                      return Future.value();
                    },
                  ),
                  DeckButton(
                    label: 'Abrir URL',
                    subtitle: 'Navegador del PC',
                    icon: Icons.open_in_browser_rounded,
                    accentColor: const Color(0xFF0EA5E9), // Sky
                    onPressed: () {
                      _showOpenUrlDialog();
                      return Future.value();
                    },
                  ),
                ],
              ),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }
}
