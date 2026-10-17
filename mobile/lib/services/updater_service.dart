/// Servicio de actualización automática dentro de la app (In-App OTA Updater).
/// Consulta los releases públicos de GitHub y descarga/ejecuta la instalación del APK.
library;

import 'dart:async';
import 'dart:convert';
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
    for (final asset in assets) {
      if (asset is Map<String, dynamic>) {
        final name = asset['name'] as String? ?? '';
        if (name == 'app-release.apk' || name.toLowerCase().endsWith('.apk')) {
          apkDownloadUrl = asset['browser_download_url'] as String?;
          break;
        }
      }
    }

    final hasUpdate = isNewerVersion(tagName, currentVersion) && apkDownloadUrl != null;

    return UpdateInfo(
      hasUpdate: hasUpdate,
      currentVersion: fullCurrent,
      latestVersion: tagName.replaceAll(RegExp(r'^[vV]'), ''),
      downloadUrl: apkDownloadUrl,
      releaseNotes: releaseNotes,
    );
  }

  /// Inicia la descarga y la instalación nativa del APK mediante FileProvider.
  Stream<OtaEvent> startOtaUpdate(String downloadUrl) {
    try {
      return OtaUpdate().execute(
        downloadUrl,
        destinationFilename: 'app-release.apk',
      );
    } catch (e) {
      throw Exception('Fallo al inicializar la actualización OTA: $e');
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
