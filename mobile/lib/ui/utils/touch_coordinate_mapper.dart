import 'dart:math' as math;

/// Punto con coordenadas normalizadas en el rango [0.0, 1.0].
class NormalizedPoint {
  final double x;
  final double y;

  const NormalizedPoint(this.x, this.y);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is NormalizedPoint &&
          runtimeType == other.runtimeType &&
          x == other.x &&
          y == other.y;

  @override
  int get hashCode => Object.hash(x, y);

  @override
  String toString() => 'NormalizedPoint(x: $x, y: $y)';
}

/// Mapper matemático con precisión milimétrica (1:1 Touch-to-Mouse Mapping).
/// Convierte coordenadas táctiles del visor móvil a coordenadas normalizadas [0.0, 1.0],
/// compensando letterboxing (barras negras horizontales), pillarboxing (barras negras verticales)
/// y matrices de transformación (zoom y desplazamiento).
class TouchCoordinateMapper {
  /// Calcula las coordenadas normalizadas [0.0, 1.0] correspondientes a un toque.
  /// Retorna `null` si el toque cae dentro de las barras negras fuera de la imagen renderizada.
  static NormalizedPoint? calculateNormalizedCoordinates({
    required double touchX,
    required double touchY,
    required double containerWidth,
    required double containerHeight,
    required double imageWidth,
    required double imageHeight,
    double scale = 1.0,
    double translationX = 0.0,
    double translationY = 0.0,
  }) {
    if (containerWidth <= 0 ||
        containerHeight <= 0 ||
        imageWidth <= 0 ||
        imageHeight <= 0 ||
        scale <= 0) {
      return null;
    }

    // 1. Deshacer transformación de zoom y desplazamiento si se proporciona
    final double sceneX = (touchX - translationX) / scale;
    final double sceneY = (touchY - translationY) / scale;

    // 2. Calcular factor de escala de BoxFit.contain:
    // BoxFit.contain escala la imagen para que quepa totalmente dentro del contenedor
    // preservando el aspect ratio original.
    final double scaleX = containerWidth / imageWidth;
    final double scaleY = containerHeight / imageHeight;
    final double containScale = math.min(scaleX, scaleY);

    final double renderedWidth = imageWidth * containScale;
    final double renderedHeight = imageHeight * containScale;

    if (renderedWidth <= 0 || renderedHeight <= 0) {
      return null;
    }

    // 3. Compensar el desplazamiento de las bandas negras (centrado simétrico)
    final double dx = (containerWidth - renderedWidth) / 2.0;
    final double dy = (containerHeight - renderedHeight) / 2.0;

    // 4. Si el toque cae fuera del área de la imagen (en las bandas negras), ignorarlo
    if (sceneX < dx ||
        sceneX > (dx + renderedWidth) ||
        sceneY < dy ||
        sceneY > (dy + renderedHeight)) {
      return null;
    }

    // 5. Normalizar al rango [0.0, 1.0] con clamping de seguridad
    final double xNorm = ((sceneX - dx) / renderedWidth).clamp(0.0, 1.0);
    final double yNorm = ((sceneY - dy) / renderedHeight).clamp(0.0, 1.0);

    return NormalizedPoint(xNorm, yNorm);
  }
}
