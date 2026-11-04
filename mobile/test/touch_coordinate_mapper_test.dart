import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:remote_controler_mobile/ui/utils/touch_coordinate_mapper.dart';

void main() {
  group('TouchCoordinateMapper (1:1 Touch-to-Mouse Mapping)', () {
    test('Letterboxing horizontal (barras negras arriba y abajo)', () {
      // Contenedor cuadrado 1000x1000, imagen 16:9 de 1600x900
      // containScale = 1000 / 1600 = 0.625
      // renderedWidth = 1000, renderedHeight = 562.5
      // dy = (1000 - 562.5) / 2 = 218.75
      const containerW = 1000.0;
      const containerH = 1000.0;
      const imageW = 1600.0;
      const imageH = 900.0;

      // 1. Toque en la barra negra superior -> Ignorado (null)
      final topBar = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: 500.0,
        touchY: 100.0,
        containerWidth: containerW,
        containerHeight: containerH,
        imageWidth: imageW,
        imageHeight: imageH,
      );
      expect(topBar, isNull);

      // 2. Toque en la barra negra inferior -> Ignorado (null)
      final bottomBar = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: 500.0,
        touchY: 900.0,
        containerWidth: containerW,
        containerHeight: containerH,
        imageWidth: imageW,
        imageHeight: imageH,
      );
      expect(bottomBar, isNull);

      // 3. Toque en el borde superior de la imagen (y = 218.75)
      final topEdge = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: 500.0,
        touchY: 218.75,
        containerWidth: containerW,
        containerHeight: containerH,
        imageWidth: imageW,
        imageHeight: imageH,
      );
      expect(topEdge, isNotNull);
      expect(topEdge!.x, closeTo(0.5, 0.001));
      expect(topEdge.y, closeTo(0.0, 0.001));

      // 4. Toque en el centro exacto (x = 500, y = 500)
      final center = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: 500.0,
        touchY: 500.0,
        containerWidth: containerW,
        containerHeight: containerH,
        imageWidth: imageW,
        imageHeight: imageH,
      );
      expect(center, isNotNull);
      expect(center!.x, closeTo(0.5, 0.001));
      expect(center.y, closeTo(0.5, 0.001));

      // 5. Toque en el borde inferior de la imagen (y = 781.25)
      final bottomEdge = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: 500.0,
        touchY: 781.25,
        containerWidth: containerW,
        containerHeight: containerH,
        imageWidth: imageW,
        imageHeight: imageH,
      );
      expect(bottomEdge, isNotNull);
      expect(bottomEdge!.x, closeTo(0.5, 0.001));
      expect(bottomEdge.y, closeTo(1.0, 0.001));
    });

    test('Pillarboxing vertical (barras negras a izquierda y derecha)', () {
      // Contenedor ultra-panorámico 2000x500, imagen 16:9 de 1600x900
      // containScale = 500 / 900 = 0.55555...
      // renderedHeight = 500
      // renderedWidth = 1600 * (500 / 900) = 888.888...
      // dx = (2000 - 888.888) / 2 = 555.555...
      const containerW = 2000.0;
      const containerH = 500.0;
      const imageW = 1600.0;
      const imageH = 900.0;

      // 1. Toque en la barra negra izquierda (x = 100) -> null
      final leftBar = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: 100.0,
        touchY: 250.0,
        containerWidth: containerW,
        containerHeight: containerH,
        imageWidth: imageW,
        imageHeight: imageH,
      );
      expect(leftBar, isNull);

      // 2. Toque en la barra negra derecha (x = 1800) -> null
      final rightBar = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: 1800.0,
        touchY: 250.0,
        containerWidth: containerW,
        containerHeight: containerH,
        imageWidth: imageW,
        imageHeight: imageH,
      );
      expect(rightBar, isNull);

      // 3. Toque en el centro (x = 1000, y = 250)
      final center = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: 1000.0,
        touchY: 250.0,
        containerWidth: containerW,
        containerHeight: containerH,
        imageWidth: imageW,
        imageHeight: imageH,
      );
      expect(center, isNotNull);
      expect(center!.x, closeTo(0.5, 0.001));
      expect(center.y, closeTo(0.5, 0.001));

      // 4. Toque en la esquina superior izquierda de la imagen (x = 555.555, y = 0)
      final topLeft = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: (2000.0 - 1600.0 * (500.0 / 900.0)) / 2.0,
        touchY: 0.0,
        containerWidth: containerW,
        containerHeight: containerH,
        imageWidth: imageW,
        imageHeight: imageH,
      );
      expect(topLeft, isNotNull);
      expect(topLeft!.x, closeTo(0.0, 0.001));
      expect(topLeft.y, closeTo(0.0, 0.001));
    });

    test('Zoom interactivo y desplazamiento (InteractiveViewer pan & scale)',
        () {
      // Contenedor 1000x1000, imagen 1000x1000
      // Zoom 2.0x, desplazado 200px a la derecha y 100px abajo
      const containerW = 1000.0;
      const containerH = 1000.0;
      const imageW = 1000.0;
      const imageH = 1000.0;
      const scale = 2.0;
      const tx = 200.0;
      const ty = 100.0;

      // Si el usuario toca en (x=700, y=600):
      // sceneX = (700 - 200) / 2 = 250 -> x_norm = 0.25
      // sceneY = (600 - 100) / 2 = 250 -> y_norm = 0.25
      final point = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: 700.0,
        touchY: 600.0,
        containerWidth: containerW,
        containerHeight: containerH,
        imageWidth: imageW,
        imageHeight: imageH,
        scale: scale,
        translationX: tx,
        translationY: ty,
      );

      expect(point, isNotNull);
      expect(point!.x, closeTo(0.25, 0.001));
      expect(point.y, closeTo(0.25, 0.001));
    });

    test('Validación defensiva de bordes y dimensiones inválidas', () {
      // Dimensiones nulas o negativas deben retornar null
      expect(
        TouchCoordinateMapper.calculateNormalizedCoordinates(
          touchX: 10,
          touchY: 10,
          containerWidth: 0,
          containerHeight: 100,
          imageWidth: 100,
          imageHeight: 100,
        ),
        isNull,
      );

      expect(
        TouchCoordinateMapper.calculateNormalizedCoordinates(
          touchX: 10,
          touchY: 10,
          containerWidth: 100,
          containerHeight: 100,
          imageWidth: -50,
          imageHeight: 100,
        ),
        isNull,
      );

      // Clamping estricto en los bordes matemáticos
      final edge = TouchCoordinateMapper.calculateNormalizedCoordinates(
        touchX: 1000.0,
        touchY: 1000.0,
        containerWidth: 1000.0,
        containerHeight: 1000.0,
        imageWidth: 1000.0,
        imageHeight: 1000.0,
      );
      expect(edge, isNotNull);
      expect(edge!.x, equals(1.0));
      expect(edge.y, equals(1.0));
    });

    test('Extracción de dimensiones reales desde cabecera binaria JPEG (SOF0)',
        () {
      // Construir cabecera JPEG mínima con marcador SOI (FF D8), APP0 (FF E0) y SOF0 (FF C0) para 1920x1080
      // 1920 = 0x0780, 1080 = 0x0438
      final jpegBytes = Uint8List.fromList([
        0xFF, 0xD8, // SOI
        0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00, // APP0 dummy (len 4)
        0xFF, 0xC0, 0x00, 0x11, 0x08, // SOF0 marker + len + precision
        0x04, 0x38, // Height = 1080
        0x07, 0x80, // Width = 1920
        0x03, 0x01, 0x22, 0x00,
      ]);

      final dims = TouchCoordinateMapper.extractJpegDimensions(jpegBytes);
      expect(dims, isNotNull);
      expect(dims!.width, equals(1920));
      expect(dims.height, equals(1080));

      // Bytes inválidos deben devolver null de forma segura
      expect(
        TouchCoordinateMapper.extractJpegDimensions(
            Uint8List.fromList([1, 2, 3])),
        isNull,
      );
    });
  });
}
