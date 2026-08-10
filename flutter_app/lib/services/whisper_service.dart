import 'dart:convert';
import 'dart:io';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

class WhisperSegment {
  final double start;
  final double end;
  final String text;

  WhisperSegment({
    required this.start,
    required this.end,
    required this.text,
  });

  factory WhisperSegment.fromJson(Map<String, dynamic> json) {
    return WhisperSegment(
      start: (json['start'] as num?)?.toDouble() ?? 0.0,
      end: (json['end'] as num?)?.toDouble() ?? 0.0,
      text: (json['text'] as String?)?.trim() ?? '',
    );
  }

  String get formattedTimestamp {
    final startMin = (start ~/ 60).toString().padLeft(2, '0');
    final startSec = (start % 60).toInt().toString().padLeft(2, '0');
    final endMin = (end ~/ 60).toString().padLeft(2, '0');
    final endSec = (end % 60).toInt().toString().padLeft(2, '0');
    return '$startMin:$startSec -> $endMin:$endSec';
  }
}

class WhisperTranscriptionResult {
  final String status;
  final String language;
  final List<WhisperSegment> segments;

  WhisperTranscriptionResult({
    required this.status,
    required this.language,
    required this.segments,
  });

  factory WhisperTranscriptionResult.fromJson(Map<String, dynamic> json) {
    final rawSegments = json['segments'] as List<dynamic>? ?? [];
    final List<WhisperSegment> parsedSegments = [];
    for (var item in rawSegments) {
      if (item is Map) {
        parsedSegments.add(WhisperSegment.fromJson(Map<String, dynamic>.from(item)));
      }
    }
    return WhisperTranscriptionResult(
      status: json['status'] as String? ?? 'success',
      language: json['language'] as String? ?? 'km',
      segments: parsedSegments,
    );
  }

  String get fullText => segments.map((s) => s.text).join(' ');
}

class WhisperService {
  final Dio _dio = Dio(
    BaseOptions(
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(minutes: 10),
      sendTimeout: const Duration(minutes: 5),
    ),
  );

  /// Transcribe audio file using FastAPI OpenAI Whisper Large-v3 backend
  Future<WhisperTranscriptionResult> transcribeMeeting(
    String filePath,
    String apiUrl,
  ) async {
    final file = File(filePath);
    if (!await file.exists()) {
      throw Exception('មិនរកឃើញឯកសារសម្លេងនៅទីតាំងនេះទេ ($filePath)');
    }

    String formattedUrl = apiUrl.trim();
    if (formattedUrl.contains('ngrok-free.de') && !formattedUrl.contains('ngrok-free.dev')) {
      formattedUrl = formattedUrl.replaceAll('ngrok-free.de', 'ngrok-free.dev');
    }
    if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
      formattedUrl = 'https://$formattedUrl';
    }

    final Uri uri = Uri.parse(formattedUrl);
    String endpoint = formattedUrl;
    if (!uri.path.endsWith('/transcribe')) {
      endpoint = formattedUrl.endsWith('/')
          ? '${formattedUrl}transcribe'
          : '$formattedUrl/transcribe';
    }

    try {
      final String fileName = filePath.split(Platform.pathSeparator).last;

      final formData = FormData.fromMap({
        'file': await MultipartFile.fromFile(
          filePath,
          filename: fileName,
        ),
      });

      final response = await _dio.post(
        endpoint,
        data: formData,
        options: Options(
          headers: {
            'ngrok-skip-browser-warning': 'true',
            'Accept': 'application/json',
          },
          responseType: ResponseType.json,
        ),
      );

      if (response.statusCode == 200 && response.data != null) {
        final rawData = response.data;
        final Map<String, dynamic> data;
        if (rawData is Map) {
          data = Map<String, dynamic>.from(rawData);
        } else if (rawData is String) {
          data = Map<String, dynamic>.from(jsonDecode(rawData));
        } else {
          throw Exception('ទម្រង់ទិន្នន័យ Server មិនត្រឹមត្រូវ');
        }
        return WhisperTranscriptionResult.fromJson(data);
      } else {
        throw Exception('Server error: ${response.statusCode} - ${response.statusMessage}');
      }
    } on DioException catch (e) {
      debugPrint('WhisperService DioError: ${e.message}');
      if (e.type == DioExceptionType.connectionTimeout ||
          e.type == DioExceptionType.receiveTimeout ||
          e.type == DioExceptionType.sendTimeout) {
        throw Exception('ការតភ្ជាប់មានការយឺតយ៉ាវ (Timeout)។ សូមពិនិត្យមើល Ngrok Server។');
      } else if (e.response != null) {
        throw Exception('Server error (${e.response?.statusCode}): ${e.response?.data}');
      } else {
        throw Exception('មិនអាចភ្ជាប់ទៅកាន់ Server បានទេ៖ ${e.message}');
      }
    } catch (e) {
      debugPrint('WhisperService Exception: $e');
      throw Exception('កំហុសបច្ចេកទេសក្នុងការបកប្រែសម្លេង៖ $e');
    }
  }
}
