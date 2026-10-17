import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Botón táctil reactivo estilo Stream Deck con microanimación de escala y vibración háptica.
class DeckButton extends StatefulWidget {
  final String label;
  final IconData icon;
  final Color accentColor;
  final Future<void> Function() onPressed;
  final String? subtitle;

  const DeckButton({
    super.key,
    required this.label,
    required this.icon,
    required this.onPressed,
    this.accentColor = const Color(0xFF6366F1), // Indigo por defecto
    this.subtitle,
  });

  @override
  State<DeckButton> createState() => _DeckButtonState();
}

class _DeckButtonState extends State<DeckButton> with SingleTickerProviderStateMixin {
  bool _isPressed = false;
  bool _isLoading = false;
  bool _isError = false;

  Future<void> _handleTap() async {
    if (_isLoading) return;

    // Feedback háptico instantáneo al toque
    HapticFeedback.lightImpact();

    setState(() {
      _isLoading = true;
      _isError = false;
    });

    try {
      await widget.onPressed();
    } catch (_) {
      if (mounted) {
        setState(() {
          _isError = true;
        });
        HapticFeedback.heavyImpact();
      }
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final effectiveColor = _isError ? const Color(0xFFEF4444) : widget.accentColor;

    return GestureDetector(
      onTapDown: (_) => setState(() => _isPressed = true),
      onTapUp: (_) => setState(() => _isPressed = false),
      onTapCancel: () => setState(() => _isPressed = false),
      onTap: _handleTap,
      child: AnimatedScale(
        scale: _isPressed ? 0.94 : 1.0,
        duration: const Duration(milliseconds: 100),
        curve: Curves.easeOutCubic,
        child: Container(
          decoration: BoxDecoration(
            color: const Color(0xFF161821),
            borderRadius: BorderRadius.circular(18),
            border: Border.all(
              color: effectiveColor.withOpacity(_isLoading ? 0.8 : 0.25),
              width: 1.5,
            ),
            boxShadow: [
              BoxShadow(
                color: effectiveColor.withOpacity(_isPressed ? 0.3 : 0.08),
                blurRadius: _isPressed ? 16 : 8,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(18),
            child: Stack(
              children: [
                // Resplandor de fondo suave
                Positioned(
                  top: -20,
                  right: -20,
                  child: Container(
                    width: 70,
                    height: 70,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: effectiveColor.withOpacity(0.06),
                    ),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 16),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      // Icono o Spinner de ejecución
                      Center(
                        child: AnimatedSwitcher(
                          duration: const Duration(milliseconds: 200),
                          child: _isLoading
                              ? SizedBox(
                                  width: 34,
                                  height: 34,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 3,
                                    valueColor: AlwaysStoppedAnimation<Color>(effectiveColor),
                                  ),
                                )
                              : Icon(
                                  widget.icon,
                                  size: 34,
                                  color: effectiveColor,
                                ),
                        ),
                      ),
                      const SizedBox(height: 12),
                      // Título del botón
                      Text(
                        widget.label,
                        textAlign: TextAlign.center,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                          color: Color(0xFFF1F5F9),
                          fontSize: 14,
                          fontWeight: FontWeight.w700,
                          letterSpacing: 0.2,
                        ),
                      ),
                      if (widget.subtitle != null) ...[
                        const SizedBox(height: 2),
                        Text(
                          widget.subtitle!,
                          textAlign: TextAlign.center,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: const Color(0xFF94A3B8).withOpacity(0.8),
                            fontSize: 10,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
