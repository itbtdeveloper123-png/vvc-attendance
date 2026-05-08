import 'dart:io';

import 'package:flutter/services.dart';

class ApkInstallerService {
  static const MethodChannel _channel = MethodChannel('app.vvc/app_update');

  static Future<bool> installApk(String filePath) async {
    if (!Platform.isAndroid) {
      throw UnsupportedError('APK installation is only supported on Android.');
    }

    final didLaunchInstaller = await _channel.invokeMethod<bool>('installApk', {
      'path': filePath,
    });

    return didLaunchInstaller == true;
  }
}
