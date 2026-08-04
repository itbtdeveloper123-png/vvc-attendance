import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:google_generative_ai/google_generative_ai.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:path/path.dart' as p;

/// Gemini AI Meeting Secretary Service
/// Analyzes audio files and transcripts using google_generative_ai package
/// Generates professional meeting summaries in formal Khmer in standard Markdown format.
class GeminiMeetingService {
  static const String systemPrompt = '''
អ្នកគឺជា "AI លេខាកិច្ចប្រជុំអាជីព" ដែលទទួលបន្ទុកវិភាគសំឡេងសន្ទនា ឬអត្ថបទប្រជុំ រួចរៀបចំជា "សេចក្តីសង្ខេបដោយ AI" ជាភាសាខ្មែរផ្លូវការ ងាយស្រួលអាន និងមានរចនាសម្ព័ន្ធច្បាស់លាស់។

សូមធ្វើការវិភាគសំឡេង/អត្ថបទប្រជុំដែលបានផ្តល់ជូន រួចបង្កើតលទ្ធផលតាមទម្រង់ (Markdown Format) ដូចខាងក្រោម៖

📌 ១. សង្ខេបជារួម (Executive Summary)
[សង្ខេបខ្លឹមសារ និងគោលបំណងធំៗនៃកិច្ចប្រជុំ ក្នុងចន្លោះ ២ ទៅ ៤ បន្ទាត់ឲ្យចំ point]

សកម្មភាព និងប្រធានបទសំខាន់ៗ (Key Discussion Points)
• [ប្រធានបទទី១]: [ការពិភាក្សា និងដំណោះស្រាយ/ការសម្រេចចិត្ត]
• [ប្រធានបទទី២]: [ការពិភាក្សា និងដំណោះស្រាយ/ការសម្រេចចិត្ត]
• [ប្រធានបទទី៣]: [ការពិភាក្សា និងដំណោះស្រាយ/ការសម្រេចចិត្ត]

កិច្ចការត្រូវធ្វើបន្ត (Action Items)
1. [សកម្មភាពត្រូវធ្វើ] - [អ្នកទទួលខុសត្រូវ (បើមាន)] - [កាលបរិច្ឆេទ/Deadline (បើមាន)]
2. [សកម្មភាពត្រូវធ្វើ] - [អ្នកទទួលខុសត្រូវ (បើមាន)] - [កាលបរិច្ឆេទ/Deadline (បើមាន)]

📝 កត់ត្រាបន្ថែម (Other Notes)
• [បញ្ហាប្រឈម គំនិតផ្ដួចផ្ដើមថ្មី ឬចំណុចដែលត្រូវប្រជុំលើកក្រោយ]

---
លក្ខខណ្ឌបន្ថែម៖
- ប្រើប្រាស់ភាសាខ្មែរផ្លូវការ ត្រឹមត្រូវតាមអក្ខរាវិរុទ្ធ និងងាយស្រួលយល់។
- ប្រសិនបើក្នុងសំឡេងមាននិយាយភាសាអង់គ្លេស បារាំង ឬថៃ សូមបកប្រែខ្លឹមសារទាំងនោះមកជាភាសាខ្មែរទាំងអស់។
- ប្រសិនបើសំឡេងមិនសូវច្បាស់ ឬមានផ្នែកណាមិនប្រាកដ សូមសរសេរតែអ្វីដែលលឺច្បាស់លាស់ ប៉ុណ្ណោះ។
''';

  static const String defaultApiKey = 'AIzaSyBzM-ugi_MHu15HPduhMh-YwVnHIvbQcR8';

  /// Get stored Gemini API key
  static Future<String> getApiKey() async {
    final prefs = await SharedPreferences.getInstance();
    final key = prefs.getString('gemini_api_key') ?? prefs.getString('meeting_api_key') ?? '';
    return key.isNotEmpty ? key : defaultApiKey;
  }

  /// Save Gemini API key
  static Future<void> saveApiKey(String key) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('gemini_api_key', key);
    await prefs.setString('meeting_api_key', key);
  }

  /// Analyze audio file directly with Gemini 1.5 Flash using google_generative_ai
  Future<String> summarizeAudioFile({
    required File audioFile,
    String? apiKey,
    String? meetingTitle,
    String? department,
  }) async {
    final effectiveKey = (apiKey != null && apiKey.isNotEmpty) ? apiKey : await getApiKey();
    if (effectiveKey.isEmpty) {
      throw Exception('មិនទាន់កំណត់ Gemini API Key ទេ។ សូមកំណត់ API Key ជាមុនសិន។');
    }

    try {
      final bytes = await audioFile.readAsBytes();
      final extension = p.extension(audioFile.path).toLowerCase().replaceAll('.', '');
      final mimeType = _getMimeType(extension);

      final model = GenerativeModel(
        model: 'gemini-1.5-flash',
        apiKey: effectiveKey,
      );

      final promptText = StringBuffer(systemPrompt);
      if (meetingTitle != null && meetingTitle.trim().isNotEmpty) {
        promptText.writeln('\nប្រធានបទកិច្ចប្រជុំ៖ $meetingTitle');
      }
      if (department != null && department.trim().isNotEmpty) {
        promptText.writeln('នាយកដ្ឋាន/ផ្នែក៖ $department');
      }

      final content = [
        Content.multi([
          TextPart(promptText.toString()),
          DataPart(mimeType, bytes),
        ]),
      ];

      final response = await model.generateContent(content);
      final textResult = response.text;

      if (textResult == null || textResult.trim().isEmpty) {
        throw Exception('Gemini មិនបានឆ្លើយតបព័ត៌មានទេ។');
      }

      return textResult.trim();
    } catch (e) {
      debugPrint('Gemini Audio Summarization Error: $e');
      throw Exception('បរាជ័យក្នុងការវិភាគសំឡេងជាមួយ Gemini AI៖ $e');
    }
  }

  /// Analyze text transcript with Gemini 1.5 Flash using google_generative_ai
  Future<String> summarizeTranscript({
    required String transcriptText,
    String? apiKey,
    String? meetingTitle,
    String? department,
  }) async {
    final effectiveKey = (apiKey != null && apiKey.isNotEmpty) ? apiKey : await getApiKey();
    if (effectiveKey.isEmpty) {
      throw Exception('មិនទាន់កំណត់ Gemini API Key ទេ។ សូមកំណត់ API Key ជាមុនសិន។');
    }

    try {
      final model = GenerativeModel(
        model: 'gemini-1.5-flash',
        apiKey: effectiveKey,
      );

      final promptText = StringBuffer(systemPrompt);
      if (meetingTitle != null && meetingTitle.trim().isNotEmpty) {
        promptText.writeln('\nប្រធានបទកិច្ចប្រជុំ៖ $meetingTitle');
      }
      if (department != null && department.trim().isNotEmpty) {
        promptText.writeln('នាយកដ្ឋាន/ផ្នែក៖ $department');
      }
      promptText.writeln('\n--- អត្ថបទប្រជុំ/កត់ត្រាសំឡេង (Meeting Transcript) ---');
      promptText.writeln(transcriptText);

      final content = [Content.text(promptText.toString())];
      final response = await model.generateContent(content);
      final textResult = response.text;

      if (textResult == null || textResult.trim().isEmpty) {
        throw Exception('Gemini មិនបានឆ្លើយតបព័ត៌មានទេ។');
      }

      return textResult.trim();
    } catch (e) {
      debugPrint('Gemini Text Summarization Error: $e');
      throw Exception('បរាជ័យក្នុងការវិភាគអត្ថបទជាមួយ Gemini AI៖ $e');
    }
  }

  String _getMimeType(String ext) {
    switch (ext) {
      case 'm4a':
        return 'audio/m4a';
      case 'mp3':
        return 'audio/mp3';
      case 'wav':
        return 'audio/wav';
      case 'aac':
        return 'audio/aac';
      case 'ogg':
        return 'audio/ogg';
      case 'mp4':
        return 'audio/mp4';
      default:
        return 'audio/m4a';
    }
  }
}
