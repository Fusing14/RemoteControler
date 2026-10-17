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
enum ConnectionState {
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

  ConnectionState _state = ConnectionState.disconnected;
  final StreamController<ConnectionState> _stateController =
      StreamController<ConnectionState>.broadcast();

  final Completer<Map<String, dynamic>>? _pendingResponseCompleter = null;
  Completer<Map<String, dynamic>>? _activeCommandCompleter;

  int _reconnectAttempts = 0;
  final Random _random = Random();
  bool _isDisposed = false;

  RemoteControlClient({
    required this.hostEndpoint,
    required this.envelopeBuilder,
    this.allowLoopback = false,
  }) {
    _validateEndpoint(hostEndpoint);
  }

  Stream<ConnectionState> get stateStream => _stateController.stream;
  ConnectionState get state => _state;

  /// Valida que el hostEndpoint apunte exclusivamente a la red Tailscale o localhost en modo dev.
  void _validateEndpoint(String endpoint) {
    final clean = endpoint.trim().replaceAll('http://', '').replaceAll('https://', '').replaceAll('ws://', '').replaceAll('wss://', '');
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
    _setState(ConnectionState.connecting);

    final wsUrl = Uri.parse('ws://$hostEndpoint/ws/control');

    try {
      _channel = WebSocketChannel.connect(wsUrl);
      await _channel!.ready;

      _setState(ConnectionState.connected);
      _reconnectAttempts = 0;

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

  void _onMessageReceived(dynamic data) {
    try {
      final jsonMap = json.decode(data as String) as Map<String, dynamic>;

      if (_activeCommandCompleter != null && !_activeCommandCompleter!.isCompleted) {
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

    if (_activeCommandCompleter != null && !_activeCommandCompleter!.isCompleted) {
      _activeCommandCompleter!.completeError(
        const NetworkConnectionException('Conexión cerrada durante la espera de respuesta.'),
      );
      _activeCommandCompleter = null;
    }
  }

  void _scheduleReconnect() {
    if (_isDisposed) return;
    _setState(ConnectionState.reconnecting);

    _reconnectAttempts++;
    // Backoff exponencial con jitter: min(30s, 1s * 1.5^intentos + jitter)
    final delaySeconds = min(30.0, pow(1.5, _reconnectAttempts) + _random.nextDouble());

    Timer(Duration(milliseconds: (delaySeconds * 1000).toInt()), () {
      if (!_isDisposed && _state == ConnectionState.reconnecting) {
        connect();
      }
    });
  }

  void _startHeartbeat() {
    _heartbeatTimer?.cancel();
    _heartbeatTimer = Timer.periodic(const Duration(seconds: 25), (_) {
      if (_state == ConnectionState.connected && _channel != null) {
        // Ping pasivo o sondeo
      }
    });
  }

  /// Envía un comando firmado y espera la confirmación (ExecutionResult) del Host.
  Future<Map<String, dynamic>> sendCommand({
    required String commandId,
    required Map<String, dynamic> payload,
    Duration timeout = const Duration(seconds: 5),
  }) async {
    if (_state != ConnectionState.connected || _channel == null) {
      throw const NetworkConnectionException('No hay conexión activa con el Host.');
    }

    if (_activeCommandCompleter != null && !_activeCommandCompleter!.isCompleted) {
      throw const NetworkConnectionException('Ya hay una petición en tránsito.');
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
        throw const NetworkConnectionException('Timeout esperando respuesta del Host.');
      },
    );
  }

  void _setState(ConnectionState newState) {
    if (_state != newState) {
      _state = newState;
      _stateController.add(newState);
    }
  }

  /// Cierra de forma ordenada los sockets y cancela temporizadores.
  Future<void> dispose() async {
    _isDisposed = true;
    _cleanupConnection();
    _setState(ConnectionState.disconnected);
    await _stateController.close();
  }
}
