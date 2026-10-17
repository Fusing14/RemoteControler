/// Servicio de actualización automática dentro de la app (In-App OTA Updater).
/// Consulta los releases públicos de GitHub y descarga/ejecuta la instalación del APK.
library;

import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:package_info_plus/package_info_plus.dart';
import 'package:ota_update/ota_update.dart';

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

  final http.Client _httpClient;
  final String _releasesUrl;

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

  /// Inicia la descarga y la instalación nativa del APK mediante FileProvider.
  /// Envuelto en bloques try-catch asíncronos para evitar cierres inesperados (crashes).
  Stream<OtaEvent> startOtaUpdate(String downloadUrl) async* {
    final cleanUrl = downloadUrl.trim();
    final uri = Uri.tryParse(cleanUrl);
    if (uri == null || !uri.isScheme('https') || !cleanUrl.toLowerCase().endsWith('.apk')) {
      debugPrint('[UpdaterService] Error: URL de descarga no válida (debe ser HTTPS y terminar en .apk): $cleanUrl');
      yield OtaEvent(
        OtaStatus.INTERNAL_ERROR,
        'URL de descarga no válida (se requiere HTTPS terminado en .apk)',
      );
      return;
    }

    debugPrint('[UpdaterService] Invocando OtaUpdate().execute con URL: $cleanUrl');
    Stream<OtaEvent> otaStream;
    try {
      otaStream = OtaUpdate().execute(
        cleanUrl,
        destinationFilename: 'app-release.apk',
      );
    } catch (e, stackTrace) {
      debugPrint('[UpdaterService] Excepción síncrona al iniciar OtaUpdate().execute: $e\n$stackTrace');
      yield OtaEvent(OtaStatus.INTERNAL_ERROR, e.toString());
      return;
    }

    try {
      await for (final event in otaStream) {
        debugPrint('[UpdaterService] OtaEvent: status=${event.status.name}, value=${event.value}');
        yield event;
      }
    } catch (e, stackTrace) {
      debugPrint('[UpdaterService] Excepción en stream de OtaUpdate: $e\n$stackTrace');
      final errStr = e.toString().toLowerCase();
      if (errStr.contains('permission') || errStr.contains('not_granted') || errStr.contains('install')) {
        yield OtaEvent(
          OtaStatus.PERMISSION_NOT_GRANTED_ERROR,
          'Permiso de instalación denegado por el sistema.',
        );
      } else if (errStr.contains('already_running') || errStr.contains('running')) {
        yield OtaEvent(
          OtaStatus.ALREADY_RUNNING_ERROR,
          'La actualización ya se encuentra en ejecución.',
        );
      } else {
        yield OtaEvent(
          OtaStatus.INTERNAL_ERROR,
          'Fallo nativo durante la actualización: $e',
        );
      }
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
