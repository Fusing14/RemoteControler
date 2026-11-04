import 'dart:math' as math;
import 'dart:typed_data';

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

  /// Extrae las dimensiones reales (width, height) directamente de la cabecera binaria JPEG (SOF0/SOF1/SOF2).
  /// Garantiza que el aspect ratio de la imagen se actualice dinámicamente en cada fotograma.
  static ({int width, int height})? extractJpegDimensions(Uint8List bytes) {
    if (bytes.length < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8) {
      return null;
    }

    int offset = 2;
    while (offset + 8 < bytes.length) {
      if (bytes[offset] != 0xFF) {
        offset++;
        continue;
      }

      final int marker = bytes[offset + 1];
      if (marker == 0xFF) {
        offset++;
        continue;
      }

      // Marcadores sin longitud de segmento (RSTn, SOI, EOI, TEM)
      if (marker == 0xD8 ||
          marker == 0xD9 ||
          marker == 0x01 ||
          (marker >= 0xD0 && marker <= 0xD7)) {
        offset += 2;
        continue;
      }

      if (offset + 3 >= bytes.length) break;
      final int segmentLength = (bytes[offset + 2] << 8) | bytes[offset + 3];
      if (segmentLength < 2) break;

      // Marcadores Start Of Frame (SOF0 = 0xC0, SOF1 = 0xC1, SOF2 = 0xC2)
      if (marker == 0xC0 || marker == 0xC1 || marker == 0xC2) {
        if (offset + 8 < bytes.length) {
          final int height = (bytes[offset + 5] << 8) | bytes[offset + 6];
          final int width = (bytes[offset + 7] << 8) | bytes[offset + 8];
          if (width > 0 && height > 0) {
            return (width: width, height: height);
          }
        }
        break;
      }

      offset += 2 + segmentLength;
    }

    return null;
  }
}
