/// Adaptador nativo de Flutter para UpdaterService (PackageInfo + MethodChannel).
library;

import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:package_info_plus/package_info_plus.dart';

import 'updater_service.dart';

class FlutterUpdaterPlatformAdapter implements UpdaterPlatformAdapter {
  static const MethodChannel _installerChannel =
      MethodChannel('com.remotecontroler.securedeck/installer');
  static const MethodChannel _updaterChannel =
      MethodChannel('com.remotecontroler.securedeck/updater');

  const FlutterUpdaterPlatformAdapter();

  @override
  Future<({String version, String buildNumber})> getInstalledVersion() async {
    final packageInfo = await PackageInfo.fromPlatform();
    return (
      version: packageInfo.version,
      buildNumber: packageInfo.buildNumber,
    );
  }

  @override
  Future<String?> installApk(String filePath) async {
    return await _installerChannel.invokeMethod<String>(
      'installApk',
      {'filePath': filePath},
    );
  }

  @override
  Future<void> showUpdateNotification(UpdateInfo info) async {
    if (!Platform.isAndroid || !info.hasUpdate) return;
    try {
      await _updaterChannel.invokeMethod('showUpdateNotification', {
        'title': 'Actualización disponible (v${info.latestVersion})',
        'message':
            'Una nueva versión de SecureDeck está disponible para instalar.',
        'downloadUrl': info.downloadUrl,
      });
    } catch (e) {
      debugPrint('[UpdaterService] No se pudo mostrar notificación nativa: $e');
    }
  }
}
