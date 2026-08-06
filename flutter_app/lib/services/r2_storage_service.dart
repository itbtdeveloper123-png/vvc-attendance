import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:path/path.dart' as path;

/// Cloudflare R2 Storage Service (S3-Compatible, Zero Egress Fees)
class R2StorageService {
  static final R2StorageService _instance = R2StorageService._internal();
  factory R2StorageService() => _instance;
  R2StorageService._internal();

  /// Cloudflare R2 Credentials & Configuration
  static const String _r2Endpoint = 'https://media.vvc.asia'; // Public Custom Domain or R2 Bucket Endpoint
  static const String _r2ApiBase = 'https://app.vvc.asia/flutter/upload_r2.php'; // PHP Proxy or Direct Presigned Upload

  /// Upload file to Cloudflare R2
  /// Returns public URL of the uploaded media file
  Future<String?> uploadMedia({
    required File file,
    required String folder, // e.g. 'chat_images', 'chat_files', 'voice_notes'
  }) async {
    try {
      final fileName = '${DateTime.now().millisecondsSinceEpoch}_${path.basename(file.path)}';
      
      final request = http.MultipartRequest('POST', Uri.parse(_r2ApiBase))
        ..fields['folder'] = folder
        ..fields['filename'] = fileName
        ..files.add(await http.MultipartFile.fromPath('file', file.path));

      final streamedResponse = await request.send();
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        // Return full public Cloudflare R2 URL
        return '$_r2Endpoint/$folder/$fileName';
      } else {
        debugPrint('R2 Upload failed status ${response.statusCode}: ${response.body}');
        return null;
      }
    } catch (e) {
      debugPrint('R2 Upload Exception: $e');
      return null;
    }
  }
}
