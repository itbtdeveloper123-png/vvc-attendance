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
  // Built-in fallback key configured in project system
  static const String _defaultGeminiKey = 'AIzaSyDsXpw8-opIVvWUA72xAdiQcC3HKDy24SU';

  /// Get the active Gemini API key from Local Settings, SharedPreferences, or fallback
  static Future<String> getActiveGeminiKey() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final userKey = prefs.getString('gemini_api_key') ?? prefs.getString('ocr_api_key');
      if (userKey != null && userKey.trim().isNotEmpty && !userKey.contains('!@#')) {
        return userKey.trim();
      }
    } catch (_) {}
    return _defaultGeminiKey;
  }

  /// Specialized prompt that commands Gemini to extract Khmer text with 100% fidelity
  /// to subscript feet (ជើង), vowels, tables, and original document structure.
  static const String _khmerDocumentPrompt = '''
អ្នកជាអ្នកជំនាញផ្នែកស្កេន និងបម្លែងឯកសារខ្មែរ (Khmer Document & OCR Expert)។
សូមធ្វើការអាន និងស្រង់អត្ថបទទាំងអស់ពីឯកសាររូបភាពនេះជាភាសាខ្មែរឱ្យបានសុក្រឹត ១០០%។

ការណែនាំសំខាន់បំផុតដើម្បីរក្សាទម្រង់ដើម និងអក្សរខ្មែរ៖
១. ត្រូវស្គាល់ឱ្យច្បាស់នូវព្យញ្ជនៈ ស្រៈពេញតួ ស្រៈនិស្ស័យ ជើងអក្សរទាំងអស់ (ដូចជា ្ក, ្ខ, ្គ, ្ង, ្ច, ្ជ, ្ញ, ្ដ, ្ឋ, ្ឌ, ្ឍ, ្ណ, ្ត, ្ថ, ្ទ, ្ធ, ្ន, ្ប, ្ផ, ្ព, ្ភ, ្ម, ្យ, ្រ, ្ល, ្វ, ្ស, ្ហ, ្អ) និងសញ្ញាទាំងអស់ (ដូចជា ំ, ះ, ៈ, ៉, ៊, ់, ៌, ៍, ៎, ៏, ័, ៑, ៗ, ៕, ៖, ។ល។)។ មិនត្រូវបាត់បង់ជើងអក្សរឡើយ!
២. រក្សាទម្រង់ដើមនៃឯកសារ ១០០% (Document Layout Preservation)៖
   - ចំណងជើងធំផ្នែកខាងលើ (ដូចជា ព្រះរាជាណាចក្រកម្ពុជា ជាតិ សាសនា ព្រះមហាក្សត្រ) សូមដាក់នៅកណ្តាល។
   - ចំណងជើងឯកសារ (ដូចជា ប័ណ្ណប្រកាសអាពាហ៍ពិពាហ៍ ឬ លិខិតបញ្ជាក់...) សូមដាក់សញ្ញា **ចំណងជើង**។
   - ប្រសិនបើមានតារាងទិន្នន័យ (Table) សូមស្រង់ជាទម្រង់ Markdown Table (| ជួរឈរ១ | ជួរឈរ២ |) ឱ្យមានជួរឈរ និងជួរដេកត្រឹមត្រូវតាមឯកសារពិត។
   - បន្ទាត់ព័ត៌មានបែប Key-Value (ដូចជា ឈ្មោះ: ..., ថ្ងៃខែឆ្នាំ: ...) សូមរក្សាទម្រង់ស្លាកនិងតម្លៃនោះ។
   - កាលបរិច្ឆេទ ត្រា ឬហត្ថលេខាខាងក្រោម (ដូចជា ធ្វើនៅ... ថ្ងៃទី... ចៅសង្កាត់...) សូមដាក់នៅចុងបញ្ចប់។
៣. បញ្ចេញតែអត្ថបទឯកសារដែលបានស្រង់ប៉ុណ្ណោះ មិនបាច់ដាក់ពាក្យពន្យល់ ឬ Markdown code blocks (```) ឡើយ។
''';

  /// Process multi-page document images using Gemini AI
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
    String docTitle = 'ឯកសារស្កេន';

    try {
      final apiKey = await getActiveGeminiKey();

      for (int i = 0; i < imagePaths.length; i++) {
        if (onProgress != null) {
          onProgress(i + 1, imagePaths.length);
        }

        final imagePath = imagePaths[i];
        String pageText = '';

        // Try direct Gemini Vision API first
        try {
          pageText = await _extractWithGeminiSdk(imagePath, apiKey);
        } catch (sdkError) {
          if (kDebugMode) print('Gemini SDK error, trying REST API: $sdkError');
          // Fallback to REST API
          try {
            pageText = await _extractWithRestApi(imagePath, apiKey);
          } catch (restError) {
            if (kDebugMode) print('Gemini REST error, trying PHP backend: $restError');
            // Fallback to Backend PHP OCR endpoint
            pageText = await _extractWithBackend(imagePath);
          }
        }

        // Clean up markdown markers if present
        pageText = pageText.replaceAll('```markdown', '').replaceAll('```', '').trim();
        pageTexts.add(pageText);

        // Detect document title from first page
        if (i == 0 && pageText.isNotEmpty) {
          final lines = pageText.split('\n');
          for (final line in lines) {
            final t = line.trim();
            if (t.startsWith('**') && t.endsWith('**')) {
              docTitle = t.replaceAll('**', '').trim();
              break;
            } else if (t.startsWith('# ')) {
              docTitle = t.replaceFirst('# ', '').trim();
              break;
            }
          }
        }
      }

      final fullText = pageTexts.join('\n\n--- [ទំព័រថ្មី] ---\n\n');

      return GeminiOcrResult(
        success: true,
        fullText: fullText,
        pageTexts: pageTexts,
        documentTitle: docTitle,
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
      title: result.documentTitle ?? 'ឯកសារស្កេន',
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
