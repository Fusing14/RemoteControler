import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';

import '../../transport/control_client.dart';

/// Pantalla para visualización de la webcam del PC en tiempo real.
class CameraViewerScreen extends StatefulWidget {
  final RemoteControlClient controlClient;

  const CameraViewerScreen({
    super.key,
    required this.controlClient,
  });

  @override
  State<CameraViewerScreen> createState() => _CameraViewerScreenState();
}

class _CameraViewerScreenState extends State<CameraViewerScreen> {
  bool _isStreaming = true;
  Uint8List? _currentFrame;
  int _fps = 0;
  int _frameCount = 0;
  DateTime _lastFpsCheck = DateTime.now();
  int _latencyMs = 0;
  bool _isLoading = true;
  String? _errorMessage;
  int _cameraIndex = 0;
  final TransformationController _transformationController =
      TransformationController();

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
          commandId: 'CAMERA_FRAME',
          payload: {
            'camera_index': _cameraIndex,
            'max_width': 854,
            'max_height': 480,
            'quality': 65,
          },
        );
        stopwatch.stop();

        final status = res['status'] as String?;
        if (status == 'SUCCESS') {
          final data = res['data'] as Map<String, dynamic>?;
          final frameB64 = data?['frame'] as String?;
          if (frameB64 != null && mounted) {
            final bytes = base64Decode(frameB64);
            setState(() {
              _currentFrame = bytes;
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
              _errorMessage =
                  res['message'] as String? ?? 'Error al capturar webcam.';
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

      // Intervalo entre fotogramas para rendimiento fluido (~12-15 FPS)
      await Future.delayed(const Duration(milliseconds: 80));
    }
  }

  void _resetZoom() {
    _transformationController.value = Matrix4.identity();
  }

  void _switchCamera() {
    setState(() {
      _cameraIndex = (_cameraIndex + 1) % 4; // Cicla entre 0, 1, 2, 3
      _isLoading = true;
      _errorMessage = null;
    });
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Cambiando a Cámara $_cameraIndex'),
        duration: const Duration(seconds: 1),
        backgroundColor: const Color(0xFF14B8A6),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF090A0F),
      appBar: AppBar(
        backgroundColor: const Color(0xFF11141C),
        elevation: 0,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Webcam en Vivo (Cam $_cameraIndex)',
              style: const TextStyle(
                  fontSize: 15,
                  fontWeight: FontWeight.bold,
                  color: Colors.white),
            ),
            if (!_isLoading && _errorMessage == null)
              Text(
                '$_fps FPS • ${_latencyMs}ms',
                style: const TextStyle(
                    fontSize: 11,
                    color: Color(0xFF14B8A6),
                    fontWeight: FontWeight.w600),
              ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.cameraswitch_rounded, color: Colors.white70),
            tooltip: 'Cambiar Cámara (Dispositivo $_cameraIndex)',
            onPressed: _switchCamera,
          ),
          IconButton(
            icon: const Icon(Icons.zoom_out_map, color: Colors.white70),
            tooltip: 'Restablecer Zoom',
            onPressed: _resetZoom,
          ),
          IconButton(
            icon: Icon(
              _isStreaming
                  ? Icons.pause_circle_outline
                  : Icons.play_circle_outline,
              color: _isStreaming ? const Color(0xFF14B8A6) : Colors.white70,
            ),
            tooltip:
                _isStreaming ? 'Pausar transmisión' : 'Reanudar transmisión',
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
      body: SafeArea(
        child: Center(
          child: _isLoading && _currentFrame == null
              ? const Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    CircularProgressIndicator(color: Color(0xFF14B8A6)),
                    SizedBox(height: 16),
                    Text(
                      'Conectando a la webcam del PC...',
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
                          const Icon(Icons.videocam_off_rounded,
                              size: 48, color: Color(0xFFEF4444)),
                          const SizedBox(height: 12),
                          Text(
                            _errorMessage!,
                            textAlign: TextAlign.center,
                            style: const TextStyle(
                                color: Colors.white, fontSize: 14),
                          ),
                          const SizedBox(height: 16),
                          ElevatedButton.icon(
                            style: ElevatedButton.styleFrom(
                                backgroundColor: const Color(0xFF14B8A6)),
                            icon:
                                const Icon(Icons.refresh, color: Colors.white),
                            label: const Text('Reintentar',
                                style: TextStyle(color: Colors.white)),
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
