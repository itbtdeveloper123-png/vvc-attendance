import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';
import 'api_service.dart';

/// Remove.bg Service with 6-Key Pool Auto-Rotation & Failover
class RemoveBgService {
  static final RemoveBgService _instance = RemoveBgService._internal();
  factory RemoveBgService() => _instance;
  RemoveBgService._internal();

  /// 6-Key Pool (300 Free Calls / Month + 6 Full-Res Credits)
  static const List<String> apiKeysPool = [
    'LM9UPg8HqRKeZ89FeM2hhaCR',
    'vjGJwAVwwP6sf4jAEPCDBaTk',
    'p62EWpwcfDcd1B4qtXukUGwg',
    'NKubVSGei8HsVra9WX376EoY',
    '92T5eCko8pibyavULgw9bHZk',
    '63PW2Mr8UXx2tMyHY8VT8XQv',
  ];

  /// Remove background from Uint8List and return processed PNG bytes
  Future<Uint8List?> removeBackgroundBytes(
    Uint8List imageBytes, {
    String? bgColor,
    String size = 'preview',
  }) async {
    // 1. Try Backend Gateway first (which manages shared pool and caching)
    try {
      final url = Uri.parse(ApiService.baseUrl.replaceAll('api.php', 'admin_api.php'));
      final base64Input = base64Encode(imageBytes);

      final response = await http.post(
        url,
        body: {
          'action': 'remove_background',
          'image_base64': base64Input,
          if (bgColor != null && bgColor.isNotEmpty) 'bg_color': bgColor,
          'size': size,
        },
      ).timeout(const Duration(seconds: 25));

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
      debugPrint('Backend rmbg error, falling back to direct key pool: $e');
    }

    // 2. Direct Client-Side Failover across 6-Key Pool
    return await _directRemoveBgFailover(imageBytes, bgColor: bgColor, size: size);
  }

  /// Direct Remove.bg API Call with Auto-Rotation across all 6 Keys
  Future<Uint8List?> _directRemoveBgFailover(
    Uint8List imageBytes, {
    String? bgColor,
    String size = 'preview',
  }) async {
    for (int i = 0; i < apiKeysPool.length; i++) {
      final apiKey = apiKeysPool[i];
      try {
        final request = http.MultipartRequest(
          'POST',
          Uri.parse('https://api.remove.bg/v1.0/removebg'),
        );

        request.headers['X-Api-Key'] = apiKey;
        request.fields['size'] = size;

        if (bgColor != null && bgColor.isNotEmpty && bgColor != 'transparent') {
          final cleanColor = bgColor.replaceAll('#', '');
          request.fields['bg_color'] = cleanColor;
        }

        request.files.add(
          http.MultipartFile.fromBytes(
            'image_file',
            imageBytes,
            filename: 'input.png',
          ),
        );

        final streamedResponse = await request.send().timeout(const Duration(seconds: 20));
        final response = await http.Response.fromStream(streamedResponse);

        if (response.statusCode == 200 && response.bodyBytes.isNotEmpty) {
          debugPrint('Remove.bg success using Key #${i + 1}');
          return response.bodyBytes;
        }

        // If 402 (Out of credits) or 429 (Rate limit), rotate to next key
        if (response.statusCode == 402 || response.statusCode == 429) {
          debugPrint('Key #${i + 1} exhausted/rate-limited (HTTP ${response.statusCode}), rotating to next key...');
          continue;
        }

        debugPrint('Remove.bg error with Key #${i + 1}: ${response.statusCode} -> ${response.body}');
      } catch (e) {
        debugPrint('Error with Key #${i + 1}: $e, trying next key...');
      }
    }

    return null;
  }

  /// Remove background from File and save to a new File
  Future<File?> removeBackgroundFile(
    File inputFile, {
    String? bgColor,
    String size = 'preview',
  }) async {
    try {
      final bytes = await inputFile.readAsBytes();
      final resultBytes = await removeBackgroundBytes(bytes, bgColor: bgColor, size: size);

      if (resultBytes != null && resultBytes.isNotEmpty) {
        final tempDir = await getTemporaryDirectory();
        final outPath = '${tempDir.path}/rmbg_${DateTime.now().millisecondsSinceEpoch}.png';
        final outFile = File(outPath);
        await outFile.writeAsBytes(resultBytes);
        return outFile;
      }
    } catch (e) {
      debugPrint('Failed to remove background from file: $e');
    }
    return null;
  }
}
