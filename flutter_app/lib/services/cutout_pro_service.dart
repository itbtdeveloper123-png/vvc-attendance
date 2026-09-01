import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';
import 'api_service.dart';

/// Cutout.pro Service with Gateway Pool & Auto Failover
/// Supports: Human Matting (Cutout), ID Photo Maker (Suits & Backgrounds), Photo Enhancer HD
class CutoutProService {
  static final CutoutProService _instance = CutoutProService._internal();
  factory CutoutProService() => _instance;
  CutoutProService._internal();

  /// Cutout.pro Human Matting / Background Cutout
  Future<Uint8List?> removeBackgroundBytes(
    Uint8List imageBytes, {
    String? bgColor,
    int mattingType = 6, // 6 = General Human/Universal, 2 = Head Cutout
  }) async {
    return await _processCutoutProGateway(
      imageBytes: imageBytes,
      taskType: 'matting',
      bgColor: bgColor,
      mattingType: mattingType,
    );
  }

  /// Cutout.pro ID Photo Maker & Suit Fitting
  Future<Uint8List?> generatePassportIdPhoto(
    Uint8List imageBytes, {
    String? bgColor,
    String? clothId,
  }) async {
    return await _processCutoutProGateway(
      imageBytes: imageBytes,
      taskType: 'idphoto',
      bgColor: bgColor,
      clothId: clothId,
    );
  }

  /// Cutout.pro Photo Enhancer HD (Face Restoration & Sharpening)
  Future<Uint8List?> enhancePhotoHD(Uint8List imageBytes) async {
    return await _processCutoutProGateway(
      imageBytes: imageBytes,
      taskType: 'enhance',
    );
  }

  /// Gateway call via backend with automatic key pool rotation & failover
  Future<Uint8List?> _processCutoutProGateway({
    required Uint8List imageBytes,
    required String taskType,
    String? bgColor,
    String? clothId,
    int? mattingType,
  }) async {
    try {
      final url = Uri.parse(ApiService.baseUrl.replaceAll('api.php', 'admin_api.php'));
      final base64Input = base64Encode(imageBytes);

      final postBody = <String, String>{
        'action': 'cutout_pro',
        'task_type': taskType,
        'image_base64': base64Input,
      };

      if (bgColor != null && bgColor.isNotEmpty && bgColor != 'transparent') {
        postBody['bg_color'] = bgColor.replaceAll('#', '');
      }
      if (clothId != null && clothId.isNotEmpty) {
        postBody['cloth_id'] = clothId;
      }
      if (mattingType != null) {
        postBody['matting_type'] = mattingType.toString();
      }

      final response = await http.post(url, body: postBody).timeout(const Duration(seconds: 35));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        if (data['success'] == true && data['image_base64'] != null) {
          String b64 = data['image_base64'];
          if (b64.contains(',')) {
            b64 = b64.split(',').last;
          }
          return base64Decode(b64);
        }
      }
    } catch (e) {
      debugPrint('Cutout.pro Gateway error: $e');
    }

    return null;
  }

  /// Remove background from File and return new File
  Future<File?> removeBackgroundFile(
    File inputFile, {
    String? bgColor,
    int mattingType = 6,
  }) async {
    try {
      final bytes = await inputFile.readAsBytes();
      final resultBytes = await removeBackgroundBytes(bytes, bgColor: bgColor, mattingType: mattingType);

      if (resultBytes != null && resultBytes.isNotEmpty) {
        final tempDir = await getTemporaryDirectory();
        final outPath = '${tempDir.path}/cutout_${DateTime.now().millisecondsSinceEpoch}.png';
        final outFile = File(outPath);
        await outFile.writeAsBytes(resultBytes);
        return outFile;
      }
    } catch (e) {
      debugPrint('Cutout.pro file remove background failed: $e');
    }
    return null;
  }
}
