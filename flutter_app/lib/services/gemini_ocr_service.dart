import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:google_generative_ai/google_generative_ai.dart';
import 'api_service.dart';
import 'docx_generator_service.dart';

/// Result from AI Gemini Khmer OCR
class GeminiOcrResult {
  final bool success;
  final String fullText;
  final List<String> pageTexts;
  final String? errorMessage;
  final String? documentTitle;

  GeminiOcrResult({
    required this.success,
    required this.fullText,
    required this.pageTexts,
    this.errorMessage,
    this.documentTitle,
  });
}

/// Advanced Gemini Vision AI Service for High-Accuracy Khmer OCR & Document Digitization.
/// Accurately recognizes Khmer consonants, subscript consonants (ជើងអក្សរ),
/// vowels, numbers, tables, and maintains original document layout.
class GeminiOcrService {
  static List<String>? _cachedKeys;
  static int _currentKeyIndex = 0;

  /// Fetch active Gemini keys dynamically from server admin panel or local cache
  static Future<List<String>> getAvailableGeminiKeys() async {
    if (_cachedKeys != null && _cachedKeys!.isNotEmpty) {
      return _cachedKeys!;
    }

    final keys = <String>[];

    // 1. Check user key from SharedPreferences
    try {
      final prefs = await SharedPreferences.getInstance();
      final userKey = prefs.getString('gemini_api_key') ?? prefs.getString('ocr_api_key');
      if (userKey != null && userKey.trim().isNotEmpty && !userKey.contains('!@#') && !userKey.startsWith('AIzaSyDsX')) {
        keys.add(userKey.trim());
      }

      // Also check locally cached keys from previous server fetch
      final localCached = prefs.getStringList('cached_gemini_keys');
      if (localCached != null && localCached.isNotEmpty) {
        for (final k in localCached) {
          if (!keys.contains(k) && !k.startsWith('AIzaSyDsX')) {
            keys.add(k);
          }
        }
      }
    } catch (_) {}

    // 2. Fetch active keys pool dynamically from Admin API database
    try {
      final adminUrl = ApiService.baseUrl.replaceAll('api.php', 'admin_api.php');
      final res = await http.get(
        Uri.parse('$adminUrl?action=get_api_keys&service_name=gemini'),
      ).timeout(const Duration(seconds: 4));

      if (res.statusCode == 200) {
        final data = jsonDecode(res.body);
        if (data['status'] == 'success' && data['keys'] is List) {
          final serverKeys = <String>[];
          for (final item in data['keys']) {
            final k = item['api_key']?.toString().trim();
            if (k != null && k.isNotEmpty && !keys.contains(k) && !k.startsWith('AIzaSyDsX')) {
              keys.add(k);
              serverKeys.add(k);
            }
          }
          if (serverKeys.isNotEmpty) {
            try {
              final prefs = await SharedPreferences.getInstance();
              await prefs.setStringList('cached_gemini_keys', serverKeys);
            } catch (_) {}
          }
        }
      }
    } catch (e) {
      if (kDebugMode) print('Could not fetch Gemini keys from server: $e');
    }

    _cachedKeys = keys;
    return keys;
  }

  /// Specialized prompt that commands Gemini to extract Khmer text with 100% fidelity
  /// to subscript feet (ជើង), vowels, tables, checkboxes, and original document structure.
  static const String _khmerDocumentPrompt = '''
អ្នកជាអ្នកជំនាញផ្នែកស្កេន និងបម្លែងឯកសារខ្មែរ (Khmer Document & OCR Expert)។
សូមធ្វើការអាន និងស្រង់អត្ថបទទាំងអស់ពីឯកសាររូបភាពនេះជាភាសាខ្មែរឱ្យបានសុក្រឹត ១០០%។

ការណែនាំសំខាន់បំផុតដើម្បីរក្សាទម្រង់ដើម និងអក្សរខ្មែរ៖
១. ត្រូវស្គាល់ឱ្យច្បាស់នូវព្យញ្ជនៈ ស្រៈពេញតួ ស្រៈនិស្ស័យ ជើងអក្សរទាំងអស់ (ដូចជា ្ក, ្ខ, ្គ, ្ង, ្ច, ្ជ, ្ញ, ្ដ, ្ឋ, ្ឌ, ្ឍ, ្ណ, ្ត, ្ថ, ្ទ, ្ធ, ្ន, ្ប, ្ផ, ្ព, ្ភ, ្ម, ្យ, ្រ, ្ល, ្វ, ្ស, ្ហ, ្អ) និងសញ្ញាទាំងអស់ (ដូចជា ំ, ះ, ៈ, ៉, ៊, ់, ៌, ៍, ៎, ៏, ័, ៑, ៗ, ៕, ៖, ។ល។)។ មិនត្រូវបាត់បង់ជើងអក្សរឡើយ!
២. រក្សាទម្រង់ដើមនៃឯកសារ ១០០% (Document Layout Preservation)៖
   - ចំណងជើងធំ ឬឈ្មោះក្រុមហ៊ុន (ដូចជា VAN VAN CAMBODIA) និងចំណងជើងពាក្យសុំ (ដូចជា APPLICATION FOR LEAVE) សូមដាក់កណ្តាល។
   - ប្រអប់ Checkbox: ប្រសិនបើមានធីក (Checked) សូមសរសេរ [x] ប្រសិនបើទទេ (Unchecked) សូមសរសេរ [ ]។
   - ព័ត៌មានបែប Key-Value (ដូចជា ឈ្មោះ (Name): ..., អត្តលេខ (ID): ...) សូមរក្សាទម្រង់ស្លាកនិងតម្លៃនោះ។
   - ប្រសិនបើមានផ្នែកព័ត៌មាន ឬហត្ថលេខាច្រើនជួរឈរ (Columns) ឬតារាង សូមស្រង់ជាទម្រង់ Markdown Table (| ជួរ១ | ជួរ២ | ជួរ៣ |) ដើម្បីរក្សាលំនាំជួរឈរឱ្យស្មើគ្នា។
   - កាលបរិច្ឆេទ ត្រា ឬហត្ថលេខាខាងក្រោម សូមរក្សាទីតាំងត្រឹមត្រូវ។
៣. បញ្ចេញតែអត្ថបទឯកសារដែលបានស្រង់ប៉ុណ្ណោះ មិនបាច់ដាក់ពាក្យពន្យល់នាំមុខ ឬ Markdown code blocks (```) ឡើយ។
''';

  /// Process multi-page document images using Gemini AI with automatic key rotation
  static Future<GeminiOcrResult> processKhmerDocument({
    required List<String> imagePaths,
    void Function(int current, int total)? onProgress,
  }) async {
    if (imagePaths.isEmpty) {
      return GeminiOcrResult(
        success: false,
        fullText: '',
        pageTexts: [],
        errorMessage: 'មិនមានរូបភាពសម្រាប់ស្កេនឡើយ',
      );
    }

    final pageTexts = <String>[];
    String? detectedDocTitle;
    final keys = await getAvailableGeminiKeys();

    try {
      for (int i = 0; i < imagePaths.length; i++) {
        if (onProgress != null) {
          onProgress(i + 1, imagePaths.length);
        }

        final imagePath = imagePaths[i];
        String pageText = '';
        String? lastError;

        // Try with key rotation
        for (int attempt = 0; attempt < keys.length && attempt < 5; attempt++) {
          final currentKey = keys[(_currentKeyIndex + attempt) % keys.length];
          try {
            pageText = await _extractWithRestApi(imagePath, currentKey);
            if (pageText.isNotEmpty) {
              _currentKeyIndex = (_currentKeyIndex + attempt) % keys.length;
              break;
            }
          } catch (e) {
            lastError = e.toString();
            if (kDebugMode) print('Gemini REST attempt failed ($attempt): $e');
            try {
              pageText = await _extractWithGeminiSdk(imagePath, currentKey);
              if (pageText.isNotEmpty) {
                _currentKeyIndex = (_currentKeyIndex + attempt) % keys.length;
                break;
              }
            } catch (sdkErr) {
              lastError = sdkErr.toString();
            }
          }
        }

        // If direct REST failed, try SDK or PHP backend
        if (pageText.isEmpty) {
          try {
            pageText = await _extractWithBackend(imagePath);
          } catch (backendError) {
            if (kDebugMode) print('Backend OCR fallback also failed: $backendError');
          }
        }

        if (pageText.isEmpty) {
          return GeminiOcrResult(
            success: false,
            fullText: '',
            pageTexts: [],
            errorMessage: 'មិនអាចស្រង់អត្ថបទពីទំព័រ ${i + 1} បានឡើយ៖ $lastError',
          );
        }

        // Clean up markdown markers and conversational preambles
        pageText = _cleanExtractedText(pageText);
        pageTexts.add(pageText);

        // Detect document title from first page
        if (i == 0 && pageText.isNotEmpty) {
          final lines = pageText.split('\n');
          for (final line in lines) {
            final t = line.trim();
            if (t.startsWith('**') && t.endsWith('**')) {
              detectedDocTitle = t.replaceAll('**', '').trim();
              break;
            } else if (t.startsWith('# ')) {
              detectedDocTitle = t.replaceFirst('# ', '').trim();
              break;
            } else if (t.isNotEmpty && t.length < 50 && (t.toUpperCase() == t || t.contains('ពាក្យសុំ') || t.contains('លិខិត'))) {
              detectedDocTitle = t;
              break;
            }
          }
        }
      }

      final fullText = pageTexts.join('\n\n--- [ទំព័រថ្មី] ---\n\n');

      return GeminiOcrResult(
        success: fullText.trim().isNotEmpty,
        fullText: fullText,
        pageTexts: pageTexts,
        documentTitle: detectedDocTitle,
      );
    } catch (e) {
      return GeminiOcrResult(
        success: false,
        fullText: '',
        pageTexts: [],
        errorMessage: 'ដំណើរការស្កេន AI បរាជ័យ៖ $e',
      );
    }
  }

  /// Clean extracted text from conversational filler, preambles, and code fences
  static String _cleanExtractedText(String text) {
    var cleaned = text.replaceAll('```markdown', '').replaceAll('```', '').trim();

    final lines = cleaned.split('\n');
    final keptLines = <String>[];
    for (final line in lines) {
      final t = line.trim();
      // Remove conversational introduction from Gemini
      if (t.startsWith('នេះជាអត្ថបទ') ||
          t.startsWith('ខាងក្រោមនេះជា') ||
          t.startsWith('ក្នុងនាមជាអ្នកជំនាញ') ||
          t.startsWith('Here is the extracted') ||
          t.startsWith('Below is the')) {
        continue;
      }
      keptLines.add(line);
    }

    return keptLines.join('\n').trim();
  }

  /// Extract using official google_generative_ai package
  static Future<String> _extractWithGeminiSdk(String imagePath, String apiKey) async {
    final model = GenerativeModel(
      model: 'gemini-2.5-flash',
      apiKey: apiKey,
    );

    final file = File(imagePath);
    final bytes = await file.readAsBytes();
    final mimeType = _getMimeType(imagePath);

    final content = [
      Content.multi([
        TextPart(_khmerDocumentPrompt),
        DataPart(mimeType, bytes),
      ])
    ];

    final response = await model.generateContent(content);
    final text = response.text;
    if (text == null || text.trim().isEmpty) {
      throw Exception('Gemini returned empty response');
    }
    return text.trim();
  }

  /// Extract using direct REST API endpoint
  static Future<String> _extractWithRestApi(String imagePath, String apiKey) async {
    final file = File(imagePath);
    final bytes = await file.readAsBytes();
    final base64Image = base64Encode(bytes);
    final mimeType = _getMimeType(imagePath);

    final url = Uri.parse(
      'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=$apiKey',
    );

    final body = jsonEncode({
      'contents': [
        {
          'parts': [
            {'text': _khmerDocumentPrompt},
            {
              'inline_data': {
                'mime_type': mimeType,
                'data': base64Image,
              }
            }
          ]
        }
      ]
    });

    final res = await http.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: body,
    ).timeout(const Duration(seconds: 45));

    if (res.statusCode == 200) {
      final json = jsonDecode(res.body);
      final text = json['candidates']?[0]?['content']?['parts']?[0]?['text'];
      if (text != null && text.toString().trim().isNotEmpty) {
        return text.toString().trim();
      }
    }
    throw Exception('REST API failed with code ${res.statusCode}: ${res.body}');
  }

  /// Fallback: call PHP backend (/api/ocr-khmer.php)
  static Future<String> _extractWithBackend(String imagePath) async {
    final url = Uri.parse('${ApiService.effectiveBaseUrl}/ocr-khmer.php');
    final request = http.MultipartRequest('POST', url);
    request.files.add(await http.MultipartFile.fromPath('image_file', imagePath));

    final prefs = await SharedPreferences.getInstance();
    final ocrKey = prefs.getString('ocr_api_key') ?? 'ocr!@#';
    request.headers['Authorization'] = 'Bearer $ocrKey';

    final streamedRes = await request.send().timeout(const Duration(seconds: 60));
    final res = await http.Response.fromStream(streamedRes);

    if (res.statusCode == 200) {
      final json = jsonDecode(res.body);
      if (json['status'] == 'success' && json['extracted_text'] != null) {
        return json['extracted_text'].toString().trim();
      }
    }
    throw Exception('Backend OCR failed: ${res.body}');
  }

  /// Export extracted result directly to Microsoft Word (.docx)
  static Future<File> exportToDocx({
    required GeminiOcrResult result,
    required String outputPath,
  }) async {
    return await DocxGeneratorService.generateDocx(
      title: result.documentTitle ?? '',
      content: result.fullText,
      multiPageContents: result.pageTexts,
      outputPath: outputPath,
    );
  }

  static String _getMimeType(String path) {
    final ext = path.split('.').last.toLowerCase();
    switch (ext) {
      case 'png':
        return 'image/png';
      case 'webp':
        return 'image/webp';
      case 'heic':
        return 'image/heic';
      case 'jpg':
      case 'jpeg':
      default:
        return 'image/jpeg';
    }
  }
}
