import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';

import '../../transport/control_client.dart';

/// Pantalla para visualización del escritorio del PC en tiempo real con zoom interactivo
/// y soporte dinámico para múltiples monitores (Pantalla 1, Pantalla 2, Todas).
class ScreenViewerScreen extends StatefulWidget {
  final RemoteControlClient controlClient;

  const ScreenViewerScreen({
    super.key,
    required this.controlClient,
  });

  @override
  State<ScreenViewerScreen> createState() => _ScreenViewerScreenState();
}

class _ScreenViewerScreenState extends State<ScreenViewerScreen> {
  bool _isStreaming = true;
  Uint8List? _currentFrame;
  int _fps = 0;
  int _frameCount = 0;
  DateTime _lastFpsCheck = DateTime.now();
  int _latencyMs = 0;
  bool _isLoading = true;
  String? _errorMessage;
  int _monitorIndex = 1;
  int _monitorCount = 1;
  final TransformationController _transformationController = TransformationController();

  @override
  void initState() {
    super.initState();
    _startStreamingLoop();
  }

  @override
  void dispose() {
    _isStreaming = false;
    _transformationController.dispose();
    super.dispose();
  }

  Future<void> _startStreamingLoop() async {
    while (mounted && _isStreaming) {
      final stopwatch = Stopwatch()..start();
      try {
        final res = await widget.controlClient.sendCommand(
          commandId: 'SCREEN_FRAME',
          payload: {
            'max_width': 1280,
            'max_height': 720,
            'quality': 65,
            'monitor_index': _monitorIndex,
          },
        );
        stopwatch.stop();

        final status = res['status'] as String?;
        if (status == 'SUCCESS') {
          final data = res['data'] as Map<String, dynamic>?;
          final frameB64 = data?['frame'] as String?;
          final detectedCount = data?['monitor_count'] as int? ?? 1;

          if (frameB64 != null && mounted) {
            final bytes = base64Decode(frameB64);
            setState(() {
              _currentFrame = bytes;
              _monitorCount = detectedCount;
              _latencyMs = stopwatch.elapsedMilliseconds;
              _isLoading = false;
              _errorMessage = null;
            });

            _frameCount++;
            final now = DateTime.now();
            if (now.difference(_lastFpsCheck).inMilliseconds >= 1000) {
              setState(() {
                _fps = _frameCount;
                _frameCount = 0;
                _lastFpsCheck = now;
              });
            }
          }
        } else {
          if (mounted) {
            setState(() {
              _errorMessage = res['message'] as String? ?? 'Error al capturar pantalla.';
              _isLoading = false;
            });
          }
        }
      } catch (e) {
        if (mounted) {
          setState(() {
            _errorMessage = e.toString().replaceAll('Exception: ', '');
            _isLoading = false;
          });
        }
        await Future.delayed(const Duration(milliseconds: 1000));
      }

      // Pequeño descanso entre frames para no saturar la CPU ni el enlace de red
      await Future.delayed(const Duration(milliseconds: 120));
    }
  }

  void _resetZoom() {
    _transformationController.value = Matrix4.identity();
  }

  void _selectMonitor(int index) {
    if (_monitorIndex == index) return;
    setState(() {
      _monitorIndex = index;
      _isLoading = true;
      _errorMessage = null;
    });
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          index == 0 ? 'Mostrando todas las pantallas combinadas' : 'Cambiando a Pantalla $index',
        ),
        duration: const Duration(seconds: 1),
        backgroundColor: const Color(0xFF8B5CF6),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final titleText = _monitorIndex == 0
        ? 'Todas las Pantallas'
        : 'Pantalla $_monitorIndex${_monitorCount > 1 ? "/$_monitorCount" : ""}';

    return Scaffold(
      backgroundColor: const Color(0xFF090A0F),
      appBar: AppBar(
        backgroundColor: const Color(0xFF11141C),
        elevation: 0,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              titleText,
              style: const TextStyle(fontSize: 15, fontWeight: FontWeight.bold, color: Colors.white),
            ),
            if (!_isLoading && _errorMessage == null)
              Text(
                '$_fps FPS • ${_latencyMs}ms',
                style: const TextStyle(fontSize: 11, color: Color(0xFF10B981), fontWeight: FontWeight.w600),
              ),
          ],
        ),
        actions: [
          if (_monitorCount > 1)
            PopupMenuButton<int>(
              icon: const Icon(Icons.screenshot_monitor_rounded, color: Color(0xFF8B5CF6)),
              tooltip: 'Cambiar Pantalla',
              initialValue: _monitorIndex,
              onSelected: _selectMonitor,
              itemBuilder: (ctx) {
                final items = <PopupMenuEntry<int>>[];
                for (int i = 1; i <= _monitorCount; i++) {
                  items.add(
                    PopupMenuItem<int>(
                      value: i,
                      child: Row(
                        children: [
                          Icon(
                            _monitorIndex == i ? Icons.check_circle_rounded : Icons.desktop_windows_rounded,
                            color: _monitorIndex == i ? const Color(0xFF10B981) : Colors.white70,
                            size: 20,
                          ),
                          const SizedBox(width: 10),
                          Text('Pantalla $i${i == 1 ? " (Principal)" : ""}'),
                        ],
                      ),
                    ),
                  );
                }
                items.add(
                  PopupMenuItem<int>(
                    value: 0,
                    child: Row(
                      children: [
                        Icon(
                          _monitorIndex == 0 ? Icons.check_circle_rounded : Icons.grid_view_rounded,
                          color: _monitorIndex == 0 ? const Color(0xFF10B981) : Colors.white70,
                          size: 20,
                        ),
                        const SizedBox(width: 10),
                        const Text('Todas las pantallas'),
                      ],
                    ),
                  ),
                );
                return items;
              },
            ),
          IconButton(
            icon: const Icon(Icons.zoom_out_map, color: Colors.white70),
            tooltip: 'Restablecer Zoom',
            onPressed: _resetZoom,
          ),
          IconButton(
            icon: Icon(
              _isStreaming ? Icons.pause_circle_outline : Icons.play_circle_outline,
              color: _isStreaming ? const Color(0xFF10B981) : Colors.white70,
            ),
            tooltip: _isStreaming ? 'Pausar transmisión' : 'Reanudar transmisión',
            onPressed: () {
              setState(() {
                _isStreaming = !_isStreaming;
              });
              if (_isStreaming) {
                _startStreamingLoop();
              }
            },
          ),
        ],
      ),
      bottomNavigationBar: _monitorCount > 1
          ? Container(
              color: const Color(0xFF11141C),
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: SafeArea(
                child: SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      for (int i = 1; i <= _monitorCount; i++) ...[
                        ChoiceChip(
                          label: Text('Pantalla $i${i == 1 ? " (Principal)" : ""}'),
                          selected: _monitorIndex == i,
                          selectedColor: const Color(0xFF8B5CF6),
                          backgroundColor: const Color(0xFF1E2230),
                          labelStyle: TextStyle(
                            color: _monitorIndex == i ? Colors.white : const Color(0xFF94A3B8),
                            fontWeight: FontWeight.bold,
                            fontSize: 12,
                          ),
                          onSelected: (val) {
                            if (val) _selectMonitor(i);
                          },
                        ),
                        const SizedBox(width: 8),
                      ],
                      ChoiceChip(
                        label: const Text('Todas (0)'),
                        selected: _monitorIndex == 0,
                        selectedColor: const Color(0xFF8B5CF6),
                        backgroundColor: const Color(0xFF1E2230),
                        labelStyle: TextStyle(
                          color: _monitorIndex == 0 ? Colors.white : const Color(0xFF94A3B8),
                          fontWeight: FontWeight.bold,
                          fontSize: 12,
                        ),
                        onSelected: (val) {
                          if (val) _selectMonitor(0);
                        },
                      ),
                    ],
                  ),
                ),
              ),
            )
          : null,
      body: SafeArea(
        child: Center(
          child: _isLoading && _currentFrame == null
              ? const Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    CircularProgressIndicator(color: Color(0xFF8B5CF6)),
                    SizedBox(height: 16),
                    Text(
                      'Conectando al monitor del PC...',
                      style: TextStyle(color: Colors.white70, fontSize: 13),
                    ),
                  ],
                )
              : _errorMessage != null && _currentFrame == null
                  ? Padding(
                      padding: const EdgeInsets.all(24),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(Icons.error_outline, size: 48, color: Color(0xFFEF4444)),
                          const SizedBox(height: 12),
                          Text(
                            _errorMessage!,
                            textAlign: TextAlign.center,
                            style: const TextStyle(color: Colors.white, fontSize: 14),
                          ),
                          const SizedBox(height: 16),
                          ElevatedButton.icon(
                            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF8B5CF6)),
                            icon: const Icon(Icons.refresh, color: Colors.white),
                            label: const Text('Reintentar', style: TextStyle(color: Colors.white)),
                            onPressed: () {
                              setState(() {
                                _isLoading = true;
                                _errorMessage = null;
                                _isStreaming = true;
                              });
                              _startStreamingLoop();
                            },
                          ),
                        ],
                      ),
                    )
                  : InteractiveViewer(
                      transformationController: _transformationController,
                      minScale: 0.5,
                      maxScale: 5.0,
                      boundaryMargin: const EdgeInsets.all(32),
                      child: Image.memory(
                        _currentFrame!,
                        gaplessPlayback: true,
                        fit: BoxFit.contain,
                      ),
                    ),
        ),
      ),
    );
  }
}
