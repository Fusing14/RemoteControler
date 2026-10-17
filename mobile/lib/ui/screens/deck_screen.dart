import 'dart:async';
import 'package:flutter/material.dart';

import '../../transport/control_client.dart';
import '../../services/pairing_client.dart';
import '../../protocol/envelope_builder.dart';
import '../../crypto/key_manager.dart';
import '../widgets/deck_button.dart';
import 'scanner_screen.dart';

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
  late final RemoteControlClient _controlClient;
  StreamSubscription<DeckConnectionState>? _stateSubscription;
  DeckConnectionState _connectionState = DeckConnectionState.disconnected;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);

    // Inicializar cliente WebSocket
    final km = widget.keyManager ?? KeyManager(storage: MemorySecureStorageAdapter());
    final builder = EnvelopeBuilder(keyManager: km);

    _controlClient = RemoteControlClient(
      hostEndpoint: widget.hostEndpoint,
      envelopeBuilder: builder,
      allowLoopback: widget.allowLoopback,
    );

    _stateSubscription = _controlClient.stateStream.listen((state) {
      if (mounted) {
        setState(() => _connectionState = state);
      }
    });

    _controlClient.connect();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stateSubscription?.cancel();
    _controlClient.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Pausar/desconectar ordenadamente cuando la app pasa a background
    if (state == AppLifecycleState.paused) {
      _controlClient.dispose();
    } else if (state == AppLifecycleState.resumed) {
      _controlClient.connect();
    }
  }

  Future<void> _sendCommand(String commandId, Map<String, dynamic> payload) async {
    try {
      final res = await _controlClient.sendCommand(
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
              style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600),
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
        title: Text(title, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
        content: Text(message, style: const TextStyle(color: Color(0xFF94A3B8))),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancelar', style: TextStyle(color: Colors.white54)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFEF4444)),
            onPressed: () {
              Navigator.pop(ctx);
              onConfirm();
            },
            child: const Text('Ejecutar', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );
  }

  void _showCustomSteamAppDialog() {
    final textController = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E2230),
        title: const Text('Lanzar Juego de Steam', style: TextStyle(color: Colors.white)),
        content: TextField(
          controller: textController,
          keyboardType: TextInputType.number,
          style: const TextStyle(color: Colors.white),
          decoration: InputDecoration(
            hintText: 'Steam AppID (ej: 730 para CS2)',
            hintStyle: const TextStyle(color: Colors.white24),
            filled: true,
            fillColor: const Color(0xFF0F1117),
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(10), borderSide: BorderSide.none),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancelar', style: TextStyle(color: Colors.white54)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF10B981)),
            onPressed: () {
              Navigator.pop(ctx);
              final appId = int.tryParse(textController.text.trim());
              if (appId != null && appId > 0) {
                _sendCommand('APP_LAUNCH', {'platform': 'STEAM', 'app_id': appId});
              }
            },
            child: const Text('Lanzar', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );
  }

  Widget _buildStatusIndicator() {
    Color color;
    String label;

    switch (_connectionState) {
      case DeckConnectionState.connected:
        color = const Color(0xFF10B981); // Verde esmeralda
        label = widget.hostEndpoint;
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
          style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: Color(0xFFCBD5E1)),
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
            icon: const Icon(Icons.refresh, color: Colors.white70),
            tooltip: 'Reconectar',
            onPressed: () => _controlClient.connect(),
          ),
          IconButton(
            icon: const Icon(Icons.link_off, color: Color(0xFFEF4444)),
            tooltip: 'Desvincular Host',
            onPressed: () {
              _confirmCriticalAction(
                title: 'Desvincular Host',
                message: '¿Estás seguro de que deseas desvincular este teléfono del PC?',
                onConfirm: () async {
                  await widget.pairingClient.unpair();
                  if (mounted) {
                    Navigator.of(context).pushReplacement(
                      MaterialPageRoute(
                        builder: (_) => ScannerScreen(pairingClient: widget.pairingClient),
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
              GridView.count(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                crossAxisCount: 2,
                mainAxisSpacing: 12,
                crossAxisSpacing: 12,
                childAspectRatio: 1.4,
                children: [
                  DeckButton(
                    label: 'Play / Pause',
                    icon: Icons.play_arrow_rounded,
                    accentColor: const Color(0xFF6366F1), // Indigo
                    onPressed: () => _sendCommand('MEDIA', {'action': 'PLAY_PAUSE'}),
                  ),
                  DeckButton(
                    label: 'Mute',
                    icon: Icons.volume_off_rounded,
                    accentColor: const Color(0xFF8B5CF6), // Violeta
                    onPressed: () => _sendCommand('MEDIA', {'action': 'VOLUME_MUTE'}),
                  ),
                  DeckButton(
                    label: 'Volumen +',
                    icon: Icons.volume_up_rounded,
                    accentColor: const Color(0xFF3B82F6), // Azul
                    onPressed: () => _sendCommand('MEDIA', {'action': 'VOLUME_UP'}),
                  ),
                  DeckButton(
                    label: 'Volumen -',
                    icon: Icons.volume_down_rounded,
                    accentColor: const Color(0xFF0EA5E9), // Sky
                    onPressed: () => _sendCommand('MEDIA', {'action': 'VOLUME_DOWN'}),
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
                    onPressed: () => _sendCommand('SYS_POWER', {'action': 'LOCK'}),
                  ),
                  DeckButton(
                    label: 'Suspender',
                    subtitle: 'SetSuspendState',
                    icon: Icons.bedtime_rounded,
                    accentColor: const Color(0xFF06B6D4), // Cyan
                    onPressed: () => _sendCommand('SYS_POWER', {'action': 'SLEEP', 'force': false}),
                  ),
                  DeckButton(
                    label: 'Reiniciar',
                    icon: Icons.restart_alt_rounded,
                    accentColor: const Color(0xFFF97316), // Naranja
                    onPressed: () {
                      _confirmCriticalAction(
                        title: 'Reiniciar PC',
                        message: '¿Confirmas reiniciar el equipo de inmediato?',
                        onConfirm: () => _sendCommand('SYS_POWER', {'action': 'REBOOT', 'force': true}),
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
                        onConfirm: () => _sendCommand('SYS_POWER', {'action': 'SHUTDOWN', 'force': true}),
                      );
                      return Future.value();
                    },
                  ),
                ],
              ),

              const SizedBox(height: 24),

              // Sección Lanzamiento de Juegos Steam
              const Text(
                'STEAM QUICK-LAUNCH',
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
                    label: 'Counter-Strike 2',
                    subtitle: 'AppID 730',
                    icon: Icons.sports_esports_rounded,
                    accentColor: const Color(0xFF10B981), // Esmeralda
                    onPressed: () => _sendCommand('APP_LAUNCH', {'platform': 'STEAM', 'app_id': 730}),
                  ),
                  DeckButton(
                    label: 'Otro Juego',
                    subtitle: 'Ingresar AppID',
                    icon: Icons.add_circle_outline_rounded,
                    accentColor: const Color(0xFF14B8A6), // Teal
                    onPressed: () {
                      _showCustomSteamAppDialog();
                      return Future.value();
                    },
                  ),
                ],
              ),
              const SizedBox(height: 16),
            ],
          ),
        ),
      ),
    );
  }
}
