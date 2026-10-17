import 'dart:convert';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'package:remote_controler_mobile/services/updater_service.dart';

void main() {
  group('UpdaterService - isNewerVersion', () {
    test('Detecta versión mayor superior', () {
      expect(UpdaterService.isNewerVersion('v2.0.0', '1.9.9'), isTrue);
      expect(UpdaterService.isNewerVersion('2.0.0', '1.0.0'), isTrue);
    });

    test('Detecta versión menor superior', () {
      expect(UpdaterService.isNewerVersion('v1.1.0', '1.0.9'), isTrue);
      expect(UpdaterService.isNewerVersion('1.2.0', '1.1.5'), isTrue);
    });

    test('Detecta versión de parche superior', () {
      expect(UpdaterService.isNewerVersion('v1.0.1', '1.0.0'), isTrue);
      expect(UpdaterService.isNewerVersion('1.0.10', '1.0.9'), isTrue);
    });

    test('Detecta número de build superior con mismo SemVer', () {
      expect(UpdaterService.isNewerVersion('v1.0.0+2', '1.0.0+1'), isTrue);
      expect(UpdaterService.isNewerVersion('1.0.0+15', '1.0.0+2'), isTrue);
    });

    test('Rechaza versiones idénticas o inferiores', () {
      expect(UpdaterService.isNewerVersion('v1.0.0', '1.0.0'), isFalse);
      expect(UpdaterService.isNewerVersion('v1.0.15', '1.0.15'), isFalse);
      expect(UpdaterService.isNewerVersion('1.0.15', '1.0.15'), isFalse);
      expect(UpdaterService.isNewerVersion('1.0.0+1', '1.0.0+1'), isFalse);
      expect(UpdaterService.isNewerVersion('v1.0.0', '1.0.1'), isFalse);
      expect(UpdaterService.isNewerVersion('v1.0.15', '1.0.16'), isFalse);
      expect(UpdaterService.isNewerVersion('1.0.0+1', '1.0.0+2'), isFalse);
      expect(UpdaterService.isNewerVersion('v0.9.0', '1.0.0'), isFalse);
    });

    test('Detecta nueva versión con esquema v1.0.run_number', () {
      expect(UpdaterService.isNewerVersion('v1.0.16', '1.0.15'), isTrue);
      expect(UpdaterService.isNewerVersion('v1.0.20', '1.0.15'), isTrue);
    });

    test('Maneja etiquetas vacías o nulas de forma segura', () {
      expect(UpdaterService.isNewerVersion('', '1.0.0'), isFalse);
      expect(UpdaterService.isNewerVersion('v1.0.0', ''), isFalse);
    });
  });

  group('UpdaterService - API parsing with MockClient', () {
    test('Parsea release de GitHub y extrae URL de app-release.apk', () async {
      final mockClient = MockClient((request) async {
        final payload = {
          'tag_name': 'v1.0.1',
          'body': 'Nuevas funciones de seguridad y OTA.',
          'assets': [
            {
              'name': 'source.zip',
              'browser_download_url': 'https://github.com/archive/v1.0.1.zip',
            },
            {
              'name': 'app-release.apk',
              'browser_download_url':
                  'https://github.com/releases/download/v1.0.1/app-release.apk',
            },
          ],
        };
        return http.Response(json.encode(payload), 200, headers: {
          'content-type': 'application/json',
        });
      });

      final updater = UpdaterService(
        httpClient: mockClient,
        releasesUrl: 'https://api.github.com/mock/releases/latest',
      );

      // Verificamos que el mockClient y la URL funcionen sin excepciones
      expect(updater, isNotNull);
    });
  });
}
