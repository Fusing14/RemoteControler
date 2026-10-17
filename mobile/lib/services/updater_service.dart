/// Servicio de actualización automática dentro de la app (In-App OTA Updater).
/// Consulta los releases públicos de GitHub, descarga el APK en streaming y
/// ejecuta la instalación nativa controlada mediante MethodChannel y FileProvider.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:package_info_plus/package_info_plus.dart';

/// Estados posibles durante el proceso de actualización OTA.
enum OtaStatus {
  DOWNLOADING,
  INSTALLING,
  ALREADY_RUNNING_ERROR,
  PERMISSION_NOT_GRANTED_ERROR,
  INTERNAL_ERROR,
}

/// Evento emitido durante la descarga e instalación del APK.
class OtaEvent {
  final OtaStatus status;
  final String? value;

  const OtaEvent(this.status, [this.value]);
}

class UpdateInfo {
  final bool hasUpdate;
  final String currentVersion;
  final String latestVersion;
  final String? downloadUrl;
  final String? releaseNotes;

  const UpdateInfo({
    required this.hasUpdate,
    required this.currentVersion,
    required this.latestVersion,
    this.downloadUrl,
    this.releaseNotes,
  });
}

class UpdaterService {
  static const String _defaultReleasesUrl =
      'https://api.github.com/repos/Fusing14/RemoteControler/releases/latest';
  static const MethodChannel _installerChannel =
      MethodChannel('com.remotecontroler.securedeck/installer');

  final http.Client _httpClient;
  final String _releasesUrl;
  bool _isUpdating = false;

  UpdaterService({
    http.Client? httpClient,
    String? releasesUrl,
  })  : _httpClient = httpClient ?? http.Client(),
        _releasesUrl = releasesUrl ?? _defaultReleasesUrl;

  /// Consulta la versión instalada y la compara con la última publicada en GitHub Releases.
  Future<UpdateInfo> checkForUpdate() async {
    final packageInfo = await PackageInfo.fromPlatform();
    final currentVersion = packageInfo.version;
    final currentBuild = packageInfo.buildNumber;
    final fullCurrent = currentBuild.isNotEmpty
        ? '$currentVersion+$currentBuild'
        : currentVersion;

    debugPrint('[UpdaterService] Comprobando actualizaciones... Versión instalada: $fullCurrent');

    final response = await _httpClient.get(
      Uri.parse(_releasesUrl),
      headers: {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'RemoteControler-App',
      },
    ).timeout(const Duration(seconds: 10));

    if (response.statusCode != 200) {
      throw Exception(
        'No se pudo consultar el repositorio de actualizaciones (HTTP ${response.statusCode}).',
      );
    }

    final data = json.decode(response.body) as Map<String, dynamic>;
    final tagName = data['tag_name'] as String? ?? '';
    final releaseNotes = data['body'] as String? ?? 'Sin notas de versión.';
    final assets = data['assets'] as List<dynamic>? ?? [];

    String? apkDownloadUrl;

    // 1. Priorizar explícitamente el artefacto oficial 'app-release.apk'
    for (final asset in assets) {
      if (asset is Map<String, dynamic>) {
        final name = asset['name'] as String? ?? '';
        final url = asset['browser_download_url'] as String? ?? '';
        if (name == 'app-release.apk' && url.startsWith('https://')) {
          apkDownloadUrl = url;
          debugPrint('[UpdaterService] Encontrado asset oficial app-release.apk: $url');
          break;
        }
      }
    }

    // 2. Fallback seguro a cualquier asset con extensión .apk y protocolo HTTPS
    if (apkDownloadUrl == null) {
      for (final asset in assets) {
        if (asset is Map<String, dynamic>) {
          final name = asset['name'] as String? ?? '';
          final url = asset['browser_download_url'] as String? ?? '';
          if (name.toLowerCase().endsWith('.apk') && url.startsWith('https://')) {
            apkDownloadUrl = url;
            debugPrint('[UpdaterService] Encontrado asset APK alternativo: $name ($url)');
            break;
          }
        }
      }
    }

    final hasUpdate = isNewerVersion(tagName, currentVersion) && apkDownloadUrl != null;

    debugPrint('[UpdaterService] Resultado: instalada=$currentVersion, última=$tagName, hasUpdate=$hasUpdate, url=$apkDownloadUrl');

    return UpdateInfo(
      hasUpdate: hasUpdate,
      currentVersion: fullCurrent,
      latestVersion: tagName.replaceAll(RegExp(r'^[vV]'), ''),
      downloadUrl: apkDownloadUrl,
      releaseNotes: releaseNotes,
    );
  }

  /// Descarga el APK en streaming y lanza el instalador nativo seguro.
  Stream<OtaEvent> startOtaUpdate(String downloadUrl) async* {
    if (_isUpdating) {
      yield const OtaEvent(
        OtaStatus.ALREADY_RUNNING_ERROR,
        'Ya existe una descarga o actualización en curso.',
      );
      return;
    }

    final cleanUrl = downloadUrl.trim();
    final uri = Uri.tryParse(cleanUrl);
    if (uri == null || !uri.isScheme('https') || !cleanUrl.toLowerCase().endsWith('.apk')) {
      debugPrint('[UpdaterService] Error: URL de descarga no válida (debe ser HTTPS y terminar en .apk): $cleanUrl');
      yield const OtaEvent(
        OtaStatus.INTERNAL_ERROR,
        'URL de descarga no válida (se requiere HTTPS terminado en .apk)',
      );
      return;
    }

    _isUpdating = true;
    IOSink? sink;
    File? apkFile;

    try {
      yield const OtaEvent(OtaStatus.DOWNLOADING, '0');

      final request = http.Request('GET', uri);
      request.headers['User-Agent'] = 'RemoteControler-App';
      final response = await _httpClient.send(request).timeout(const Duration(seconds: 15));

      if (response.statusCode != 200) {
        yield OtaEvent(
          OtaStatus.INTERNAL_ERROR,
          'Fallo al descargar el archivo de actualización (HTTP ${response.statusCode})',
        );
        return;
      }

      final contentLength = response.contentLength ?? 0;
      final tempDir = Directory.systemTemp;
      apkFile = File('${tempDir.path}/securedeck_update.apk');

      if (await apkFile.exists()) {
        try {
          await apkFile.delete();
        } catch (_) {}
      }

      sink = apkFile.openWrite();
      var receivedBytes = 0;
      var lastReportedPercent = -1;

      await for (final chunk in response.stream) {
        sink.add(chunk);
        receivedBytes += chunk.length;
        if (contentLength > 0) {
          final percent = ((receivedBytes / contentLength) * 100).clamp(0, 100).toInt();
          if (percent > lastReportedPercent) {
            lastReportedPercent = percent;
            yield OtaEvent(OtaStatus.DOWNLOADING, percent.toString());
          }
        }
      }

      await sink.flush();
      await sink.close();
      sink = null;

      yield const OtaEvent(OtaStatus.INSTALLING, '100');

      // Invocar el instalador nativo seguro mediante MethodChannel
      try {
        final installResult = await _installerChannel.invokeMethod<String>(
          'installApk',
          {'filePath': apkFile.path},
        );

        if (installResult == 'PERMISSION_REQUIRED') {
          yield const OtaEvent(
            OtaStatus.PERMISSION_NOT_GRANTED_ERROR,
            'Permiso requerido para instalar aplicaciones de fuentes desconocidas.',
          );
        } else if (installResult == 'INSTALL_STARTED') {
          yield const OtaEvent(
            OtaStatus.INSTALLING,
            'Instalador de Android abierto exitosamente.',
          );
        } else {
          yield OtaEvent(
            OtaStatus.INTERNAL_ERROR,
            installResult ?? 'Error al iniciar la instalación nativa.',
          );
        }
      } catch (channelError) {
        debugPrint('[UpdaterService] Error al invocar canal nativo installer: $channelError');
        yield OtaEvent(
          OtaStatus.INTERNAL_ERROR,
          'Error en el instalador nativo: $channelError',
        );
      }
    } catch (e, stackTrace) {
      debugPrint('[UpdaterService] Error en flujo de actualización: $e\n$stackTrace');
      yield OtaEvent(OtaStatus.INTERNAL_ERROR, e.toString());
    } finally {
      if (sink != null) {
        try {
          await sink.close();
        } catch (_) {}
      }
      _isUpdating = false;
    }
  }

  /// Compara si latestTag es estrictamente superior a currentVersion (SemVer + Build).
  static bool isNewerVersion(String latestTag, String currentVersion) {
    final cleanLatest = latestTag.replaceAll(RegExp(r'^[vV]'), '').trim();
    final cleanCurrent = currentVersion.replaceAll(RegExp(r'^[vV]'), '').trim();

    if (cleanLatest.isEmpty || cleanCurrent.isEmpty) return false;

    final latestParts = cleanLatest.split('+');
    final currentParts = cleanCurrent.split('+');

    final latestSemver = latestParts[0]
        .split('.')
        .map((e) => int.tryParse(e) ?? 0)
        .toList();
    final currentSemver = currentParts[0]
        .split('.')
        .map((e) => int.tryParse(e) ?? 0)
        .toList();

    while (latestSemver.length < 3) {
      latestSemver.add(0);
    }
    while (currentSemver.length < 3) {
      currentSemver.add(0);
    }

    for (var i = 0; i < 3; i++) {
      if (latestSemver[i] > currentSemver[i]) return true;
      if (latestSemver[i] < currentSemver[i]) return false;
    }

    // Si SemVer es idéntico (ej: 1.0.15 == 1.0.15), comparar build number solo si ambos lo tienen
    final latestBuild =
        latestParts.length > 1 ? (int.tryParse(latestParts[1]) ?? 0) : 0;
    final currentBuild =
        currentParts.length > 1 ? (int.tryParse(currentParts[1]) ?? 0) : 0;

    if (latestBuild > 0 && currentBuild > 0) {
      return latestBuild > currentBuild;
    }

    return false;
  }
}
