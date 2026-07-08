import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

import 'apk_installer_service.dart';

typedef AppUpdateProgress = void Function(double progress, String status);

class AppUpdateService {
  static Future<String?> downloadAndInstallApk(
    String url, {
    required AppUpdateProgress onProgress,
  }) async {
    try {
      final trimmedUrl = url.trim();
      if (trimmedUrl.isEmpty) {
        return 'មិនមានតំណទាញយក APK ទេ។';
      }

      final directory = await getTemporaryDirectory();
      final savePath = '${directory.path}/vvc_attendance_update.apk';

      await Dio().download(
        trimmedUrl,
        savePath,
        onReceiveProgress: (received, total) {
          if (total > 0) {
            onProgress(received / total, 'កំពុងទាញយកឯកសារ...');
          }
        },
      );

      onProgress(1.0, 'ទាញយកជោគជ័យ! កំពុងបើកផ្ទាំងដំឡើង...');

      final openedInstaller = await ApkInstallerService.installApk(savePath);
      if (!openedInstaller) {
        return 'មិនអាចបើកផ្ទាំងដំឡើងបានទេ។';
      }

      return null;
    } on PlatformException catch (e) {
      if (e.code == 'install_permission_required') {
        return 'សូមអនុញ្ញាត Install unknown apps សិន រួចចុចអាប់ដេតម្ដងទៀត។';
      }
      return 'មិនអាចបើកការដំឡើងបានទេ៖ ${e.message ?? e.code}';
    } catch (e) {
      return 'មានបញ្ហាក្នុងការអាប់ដេត៖ $e';
    }
  }
}
