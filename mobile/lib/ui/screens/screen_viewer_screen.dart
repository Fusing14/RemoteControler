import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../transport/control_client.dart';
import '../utils/touch_coordinate_mapper.dart';

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

class _ScreenViewerScreenState extends State<ScreenViewerScreen>
    with WidgetsBindingObserver {
  bool _isStreaming = true;
  bool _pausedByLifecycle = false;
  Uint8List? _currentFrame;
  int _fps = 0;
  int _frameCount = 0;
  DateTime _lastFpsCheck = DateTime.now();
  int _latencyMs = 0;
  bool _isLoading = true;
  String? _errorMessage;
  int _monitorIndex = 1;
  int _monitorCount = 1;
  int _imageWidth = 1280;
  int _imageHeight = 720;
  final TransformationController _transformationController =
      TransformationController();

  // Control de gestos concurrentes para evitar clics accidentales durante zoom/pan
  int _activePointers = 0;
  bool _isMultiTouchGesture = false;
  bool _didPanOrZoomInGesture = false;
  Matrix4? _matrixAtInteractionStart;
  DateTime _lastZoomOrPanEndTime = DateTime.fromMillisecondsSinceEpoch(0);

  // Lista de efectos visuales táctiles (ripple pulsante)
  final List<ClickRippleEffect> _ripples = [];
  Timer? _rippleTimer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _startStreamingLoop();
  }

  @override
  void dispose() {
    _isStreaming = false;
    _rippleTimer?.cancel();
    _rippleTimer = null;
    _ripples.clear();
    WidgetsBinding.instance.removeObserver(this);
    _transformationController.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.inactive ||
        state == AppLifecycleState.hidden) {
      if (_isStreaming) {
        _pausedByLifecycle = true;
        _isStreaming = false;
      }
    } else if (state == AppLifecycleState.resumed) {
      if (_pausedByLifecycle && mounted) {
        _pausedByLifecycle = false;
        setState(() {
          _isStreaming = true;
        });
        _startStreamingLoop();
      }
    }
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
          final w = data?['width'] as int?;
          final h = data?['height'] as int?;

          if (frameB64 != null && mounted) {
            final bytes = base64Decode(frameB64);
            final jpegDims = TouchCoordinateMapper.extractJpegDimensions(bytes);
            setState(() {
              _currentFrame = bytes;
              _monitorCount = detectedCount;
              if (w != null && h != null && w > 0 && h > 0) {
                _imageWidth = w;
                _imageHeight = h;
              } else if (jpegDims != null) {
                _imageWidth = jpegDims.width;
                _imageHeight = jpegDims.height;
              }
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
                  res['message'] as String? ?? 'Error al capturar pantalla.';
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

  void _triggerRipple(Offset screenPosition, Color color) {
    final ripple = ClickRippleEffect(position: screenPosition, color: color);
    setState(() {
      _ripples.add(ripple);
    });

    _rippleTimer?.cancel();
    _rippleTimer = Timer.periodic(const Duration(milliseconds: 16), (timer) {
      if (!mounted) {
        timer.cancel();
        return;
      }
      final now = DateTime.now();
      _ripples
          .removeWhere((r) => now.difference(r.startTime).inMilliseconds > 450);
      if (_ripples.isEmpty) {
        timer.cancel();
        _rippleTimer = null;
      }
      setState(() {});
    });
  }

  bool _hasMatrixChangedSignificantly(Matrix4? a, Matrix4 b) {
    if (a == null) return false;
    for (int i = 0; i < 16; i++) {
      if ((a.storage[i] - b.storage[i]).abs() > 1.5) {
        return true;
      }
    }
    return false;
  }

  void _handleTouch({
    required Offset localPosition,
    required Size containerSize,
    required String button,
    required Color feedbackColor,
  }) {
    // 0. Evitar clics accidentales si el usuario está haciendo o acaba de hacer pinch-to-zoom o pan
    final elapsedSinceZoom =
        DateTime.now().difference(_lastZoomOrPanEndTime).inMilliseconds;
    if (_activePointers > 1 ||
        _isMultiTouchGesture ||
        _didPanOrZoomInGesture ||
        elapsedSinceZoom < 180) {
      return;
    }

    // 1. Convertir coordenadas locales a escena (deshaciendo zoom y pan de InteractiveViewer)
    final scenePoint = _transformationController.toScene(localPosition);

    // 2. Mapear a coordenadas normalizadas [0.0, 1.0] compensando letterboxing/pillarboxing
    final normPoint = TouchCoordinateMapper.calculateNormalizedCoordinates(
      touchX: scenePoint.dx,
      touchY: scenePoint.dy,
      containerWidth: containerSize.width,
      containerHeight: containerSize.height,
      imageWidth: _imageWidth.toDouble(),
      imageHeight: _imageHeight.toDouble(),
    );

    // Si el toque cayó en las bandas negras de BoxFit.contain, se ignora
    if (normPoint == null) {
      return;
    }

    // 3. Feedback visual instantáneo exactamente en la posición tocada de la pantalla
    _triggerRipple(localPosition, feedbackColor);

    // 4. Inyección remota de ratón con coordenadas [0.0, 1.0]
    _sendMouseClick(normPoint.x, normPoint.y, button);
  }

  Future<void> _sendMouseClick(
      double xNorm, double yNorm, String button) async {
    try {
      await widget.controlClient.sendMouseClick(
        x: xNorm,
        y: yNorm,
        button: button,
        monitorIndex: _monitorIndex,
      );
    } catch (e) {
      debugPrint('Error enviando interacción de ratón: $e');
    }
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
          index == 0
              ? 'Mostrando todas las pantallas combinadas'
              : 'Cambiando a Pantalla $index',
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
                    color: Color(0xFF10B981),
                    fontWeight: FontWeight.w600),
              ),
          ],
        ),
        actions: [
          if (_monitorCount > 1)
            PopupMenuButton<int>(
              icon: const Icon(Icons.screenshot_monitor_rounded,
                  color: Color(0xFF8B5CF6)),
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
                            _monitorIndex == i
                                ? Icons.check_circle_rounded
                                : Icons.desktop_windows_rounded,
                            color: _monitorIndex == i
                                ? const Color(0xFF10B981)
                                : Colors.white70,
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
                          _monitorIndex == 0
                              ? Icons.check_circle_rounded
                              : Icons.grid_view_rounded,
                          color: _monitorIndex == 0
                              ? const Color(0xFF10B981)
                              : Colors.white70,
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
              _isStreaming
                  ? Icons.pause_circle_outline
                  : Icons.play_circle_outline,
              color: _isStreaming ? const Color(0xFF10B981) : Colors.white70,
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
                          label: Text(
                              'Pantalla $i${i == 1 ? " (Principal)" : ""}'),
                          selected: _monitorIndex == i,
                          selectedColor: const Color(0xFF8B5CF6),
                          backgroundColor: const Color(0xFF1E2230),
                          labelStyle: TextStyle(
                            color: _monitorIndex == i
                                ? Colors.white
                                : const Color(0xFF94A3B8),
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
                          color: _monitorIndex == 0
                              ? Colors.white
                              : const Color(0xFF94A3B8),
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
                          const Icon(Icons.error_outline,
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
                                backgroundColor: const Color(0xFF8B5CF6)),
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
                  : LayoutBuilder(
                      builder: (context, constraints) {
                        final containerSize =
                            Size(constraints.maxWidth, constraints.maxHeight);

                        return Listener(
                          onPointerDown: (_) {
                            _activePointers++;
                            if (_activePointers > 1) {
                              _isMultiTouchGesture = true;
                              _lastZoomOrPanEndTime = DateTime.now();
                            }
                          },
                          onPointerUp: (_) {
                            _activePointers =
                                (_activePointers - 1).clamp(0, 10);
                            if (_activePointers == 0) {
                              if (_isMultiTouchGesture ||
                                  _didPanOrZoomInGesture) {
                                _lastZoomOrPanEndTime = DateTime.now();
                              }
                              _isMultiTouchGesture = false;
                              _didPanOrZoomInGesture = false;
                            }
                          },
                          onPointerCancel: (_) {
                            _activePointers =
                                (_activePointers - 1).clamp(0, 10);
                            if (_activePointers == 0) {
                              _isMultiTouchGesture = false;
                              _didPanOrZoomInGesture = false;
                            }
                          },
                          child: GestureDetector(
                            behavior: HitTestBehavior.opaque,
                            onTapUp: (details) {
                              _handleTouch(
                                localPosition: details.localPosition,
                                containerSize: containerSize,
                                button: 'left',
                                feedbackColor:
                                    const Color(0xFF06B6D4), // Cyan brillante
                              );
                            },
                            onDoubleTapDown: (details) {
                              _handleTouch(
                                localPosition: details.localPosition,
                                containerSize: containerSize,
                                button: 'double_left',
                                feedbackColor: const Color(
                                    0xFF10B981), // Esmeralda brillante
                              );
                            },
                            onLongPressStart: (details) {
                              if (_activePointers > 1 ||
                                  _isMultiTouchGesture ||
                                  _didPanOrZoomInGesture) {
                                return;
                              }
                              HapticFeedback.mediumImpact();
                              _handleTouch(
                                localPosition: details.localPosition,
                                containerSize: containerSize,
                                button: 'right',
                                feedbackColor: const Color(
                                    0xFF8B5CF6), // Violeta brillante
                              );
                            },
                            child: Stack(
                              fit: StackFit.expand,
                              children: [
                                InteractiveViewer(
                                  transformationController:
                                      _transformationController,
                                  minScale: 0.5,
                                  maxScale: 5.0,
                                  boundaryMargin: const EdgeInsets.all(32),
                                  onInteractionStart: (details) {
                                    _matrixAtInteractionStart =
                                        _transformationController.value.clone();
                                    if (details.pointerCount > 1) {
                                      _isMultiTouchGesture = true;
                                      _lastZoomOrPanEndTime = DateTime.now();
                                    }
                                  },
                                  onInteractionUpdate: (details) {
                                    if (details.pointerCount > 1 ||
                                        (details.scale - 1.0).abs() > 0.02) {
                                      _isMultiTouchGesture = true;
                                      _lastZoomOrPanEndTime = DateTime.now();
                                    }
                                    if (_hasMatrixChangedSignificantly(
                                      _matrixAtInteractionStart,
                                      _transformationController.value,
                                    )) {
                                      _didPanOrZoomInGesture = true;
                                      _lastZoomOrPanEndTime = DateTime.now();
                                    }
                                  },
                                  onInteractionEnd: (_) {
                                    if (_isMultiTouchGesture ||
                                        _didPanOrZoomInGesture) {
                                      _lastZoomOrPanEndTime = DateTime.now();
                                    }
                                    _matrixAtInteractionStart = null;
                                  },
                                  child: Image.memory(
                                    _currentFrame!,
                                    gaplessPlayback: true,
                                    fit: BoxFit.contain,
                                    width: containerSize.width,
                                    height: containerSize.height,
                                  ),
                                ),
                                if (_ripples.isNotEmpty)
                                  Positioned.fill(
                                    child: IgnorePointer(
                                      child: CustomPaint(
                                        painter:
                                            RipplePainter(ripples: _ripples),
                                      ),
                                    ),
                                  ),
                              ],
                            ),
                          ),
                        );
                      },
                    ),
        ),
      ),
    );
  }
}

/// Modelo de datos para feedback visual táctil reactivo.
class ClickRippleEffect {
  final Offset position;
  final Color color;
  final double maxRadius;
  final DateTime startTime;

  ClickRippleEffect({
    required this.position,
    required this.color,
    this.maxRadius = 32.0,
    DateTime? startTime,
  }) : startTime = startTime ?? DateTime.now();
}

/// CustomPainter para dibujar el pulso/ripple exactamente bajo el dedo del usuario.
class RipplePainter extends CustomPainter {
  final List<ClickRippleEffect> ripples;

  RipplePainter({required this.ripples});

  @override
  void paint(Canvas canvas, Size size) {
    final now = DateTime.now();
    for (final ripple in ripples) {
      final elapsed = now.difference(ripple.startTime).inMilliseconds;
      if (elapsed > 450) continue;
      final progress = (elapsed / 450.0).clamp(0.0, 1.0);
      final radius = ripple.maxRadius * (0.2 + 0.8 * progress);
      final opacity = (1.0 - progress).clamp(0.0, 1.0);

      // Aro exterior expansivo
      final strokePaint = Paint()
        ..color = ripple.color.withOpacity(opacity * 0.85)
        ..style = PaintingStyle.stroke
        ..strokeWidth = 3.0 * (1.0 - progress * 0.5);
      canvas.drawCircle(ripple.position, radius, strokePaint);

      // Resplandor interior suave
      final fillPaint = Paint()
        ..color = ripple.color.withOpacity(opacity * 0.3)
        ..style = PaintingStyle.fill;
      canvas.drawCircle(ripple.position, radius * 0.65, fillPaint);

      // Núcleo central blanco brillante
      final corePaint = Paint()
        ..color = Colors.white.withOpacity(opacity * 0.95)
        ..style = PaintingStyle.fill;
      canvas.drawCircle(
          ripple.position, 3.5 * (1.0 - progress * 0.3), corePaint);
    }
  }

  @override
  bool shouldRepaint(covariant RipplePainter oldDelegate) => true;
}
