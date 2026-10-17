/// Cliente de transporte WebSocket para RemoteControler Mobile.
/// Gestiona la conexión en tiempo real hacia la IP de Tailscale del Host.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'package:web_socket_channel/web_socket_channel.dart';

import '../protocol/envelope_builder.dart';

class NetworkConnectionException implements Exception {
  final String message;
  const NetworkConnectionException(this.message);

  @override
  String toString() => 'NetworkConnectionException: $message';
}

class HostRejectedError implements Exception {
  final String message;
  final String? errorCode;
  const HostRejectedError(this.message, {this.errorCode});

  @override
  String toString() => 'HostRejectedError: $message (código: $errorCode)';
}

/// Estado de la conexión del cliente con el daemon.
enum DeckConnectionState {
  disconnected,
  connecting,
  connected,
  reconnecting,
}

class RemoteControlClient {
  final String hostEndpoint; // Ej: "100.85.12.34:8443" o "127.0.0.1:8443"
  final EnvelopeBuilder envelopeBuilder;
  final bool allowLoopback;

  WebSocketChannel? _channel;
  StreamSubscription? _subscription;
  Timer? _heartbeatTimer;
  Timer? _reconnectTimer;

  DeckConnectionState _state = DeckConnectionState.disconnected;
  final StreamController<DeckConnectionState> _stateController =
      StreamController<DeckConnectionState>.broadcast();

  Completer<Map<String, dynamic>>? _activeCommandCompleter;

  int _reconnectAttempts = 0;
  bool _isDisposed = false;

  RemoteControlClient({
    required this.hostEndpoint,
    required this.envelopeBuilder,
    this.allowLoopback = false,
  }) {
    _validateEndpoint(hostEndpoint);
  }

  Stream<DeckConnectionState> get stateStream => _stateController.stream;
  DeckConnectionState get state => _state;
  bool get isConnected => _state == DeckConnectionState.connected;

  /// Valida que el hostEndpoint apunte exclusivamente a la red Tailscale o localhost en modo dev.
  void _validateEndpoint(String endpoint) {
    final clean = endpoint
        .trim()
        .replaceAll('http://', '')
        .replaceAll('https://', '')
        .replaceAll('ws://', '')
        .replaceAll('wss://', '');
    final parts = clean.split(':');
    final ip = parts[0];

    // Verificar si es IP de Tailscale (100.64.0.0 a 100.127.255.255)
    final isTailscale = _isTailscaleIp(ip);
    final isLoopback = ip == '127.0.0.1' || ip == 'localhost';

    if (isTailscale) return;
    if (allowLoopback && isLoopback) return;

    throw NetworkConnectionException(
      'Política Zero-Trust violada: El endpoint "$endpoint" no pertenece a Tailscale (100.64.0.0/10).',
    );
  }

  static bool _isTailscaleIp(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) return false;
    final b0 = int.tryParse(parts[0]);
    final b1 = int.tryParse(parts[1]);
    if (b0 == null || b1 == null) return false;
    // 100.64.0.0/10 significa primer byte = 100 y segundo byte entre 64 y 127
    return b0 == 100 && b1 >= 64 && b1 <= 127;
  }

  /// Establece la conexión WebSocket segura con el Host.
  Future<void> connect() async {
    if (_isDisposed) return;
    _setState(DeckConnectionState.connecting);

    final wsUrl = Uri.parse('ws://$hostEndpoint/ws/control');

    try {
      _channel = WebSocketChannel.connect(wsUrl);
      await _channel!.ready;

      _setState(DeckConnectionState.connected);
      _reconnectAttempts = 0;
      _reconnectTimer?.cancel();
      _reconnectTimer = null;

      _subscription = _channel!.stream.listen(
        _onMessageReceived,
        onError: _onConnectionError,
        onDone: _onConnectionClosed,
        cancelOnError: true,
      );

      _startHeartbeat();
    } catch (e) {
      _scheduleReconnect();
    }
  }

  /// Reconecta de inmediato si la sesión no está conectada o se perdió por cambio de ciclo de vida.
  Future<void> ensureConnected() async {
    if (_isDisposed) return;
    if (_state == DeckConnectionState.connected ||
        _state == DeckConnectionState.connecting) {
      return;
    }
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    await connect();
  }

  void _onMessageReceived(dynamic data) {
    try {
      final jsonMap = json.decode(data as String) as Map<String, dynamic>;

      // Los paquetes de streaming (como chunks de audio) no deben resolver completers de otros comandos
      final cmdId = jsonMap['command_id'] as String?;
      if (cmdId == 'MIC_AUDIO_CHUNK') {
        return;
      }

      if (_activeCommandCompleter != null &&
          !_activeCommandCompleter!.isCompleted) {
        _activeCommandCompleter!.complete(jsonMap);
        _activeCommandCompleter = null;
      }
    } catch (_) {
      // Ignorar mensajes no conformes
    }
  }

  void _onConnectionError(dynamic error) {
    _cleanupConnection();
    _scheduleReconnect();
  }

  void _onConnectionClosed() {
    _cleanupConnection();
    _scheduleReconnect();
  }

  void _cleanupConnection() {
    _heartbeatTimer?.cancel();
    _subscription?.cancel();
    _subscription = null;
    _channel = null;

    if (_activeCommandCompleter != null &&
        !_activeCommandCompleter!.isCompleted) {
      _activeCommandCompleter!.completeError(
        const NetworkConnectionException(
            'Conexión cerrada durante la espera de respuesta.'),
      );
      _activeCommandCompleter = null;
    }
  }

  void _scheduleReconnect() {
    if (_isDisposed) return;
    _setState(DeckConnectionState.reconnecting);

    _reconnectAttempts++;
    // Backoff resiliente: 1s, 2s, 3s, máx 5s
    final delaySeconds = min(5, max(1, _reconnectAttempts));

    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(Duration(seconds: delaySeconds), () {
      if (!_isDisposed && _state == DeckConnectionState.reconnecting) {
        connect();
      }
    });
  }

  void _startHeartbeat() {
    _heartbeatTimer?.cancel();
    _heartbeatTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (_state == DeckConnectionState.connected && _channel != null) {
        // Enviar ping pasivo o keep-alive
      }
    });
  }

  /// Envía un comando firmado y espera la confirmación (ExecutionResult) del Host.
  Future<Map<String, dynamic>> sendCommand({
    required String commandId,
    required Map<String, dynamic> payload,
    Duration timeout = const Duration(seconds: 5),
  }) async {
    if (_state != DeckConnectionState.connected || _channel == null) {
      throw const NetworkConnectionException(
          'No hay conexión activa con el Host.');
    }

    if (_activeCommandCompleter != null &&
        !_activeCommandCompleter!.isCompleted) {
      throw const NetworkConnectionException(
          'Ya hay una petición en tránsito.');
    }

    final envelopeJson = await envelopeBuilder.buildSignedEnvelopeJson(
      commandId: commandId,
      payload: payload,
    );

    final completer = Completer<Map<String, dynamic>>();
    _activeCommandCompleter = completer;

    _channel!.sink.add(envelopeJson);

    return completer.future.timeout(
      timeout,
      onTimeout: () {
        if (_activeCommandCompleter == completer) {
          _activeCommandCompleter = null;
        }
        throw const NetworkConnectionException(
            'Timeout esperando respuesta del Host.');
      },
    );
  }

  /// Transmite paquetes de streaming continuo (ej. fragmentos de audio de micrófono PCM)
  /// en modo 'fire-and-forget' sin bloquear _activeCommandCompleter ni requerir confirmación síncrona.
  Future<void> sendStreamPacket({
    required String commandId,
    required Map<String, dynamic> payload,
  }) async {
    if (_state != DeckConnectionState.connected || _channel == null) {
      return;
    }

    try {
      final envelopeJson = await envelopeBuilder.buildSignedEnvelopeJson(
        commandId: commandId,
        payload: payload,
      );
      _channel?.sink.add(envelopeJson);
    } catch (_) {
      // Ignorar caídas de paquetes individuales en streaming para evitar cortes de audio
    }
  }

  void _setState(DeckConnectionState newState) {
    if (_state != newState) {
      _state = newState;
      _stateController.add(newState);
    }
  }

  /// Cierra de forma ordenada los sockets y cancela temporizadores.
  Future<void> dispose() async {
    _isDisposed = true;
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    _cleanupConnection();
    _setState(DeckConnectionState.disconnected);
    await _stateController.close();
  }
}
