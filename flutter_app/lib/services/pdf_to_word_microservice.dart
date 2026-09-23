import 'dart:io';
import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:path_provider/path_provider.dart';
import 'package:archive/archive.dart';
import 'api_service.dart';

/// Result object of PDF to Word Microservice conversion
class PdfToWordConversionResult {
  final bool success;
  final String? errorMessage;
  final File? docxFile;
  final File? photoFile;
  final String? docxUrl;
  final String? fileName;
  final int fileSize;
  final int pages;
  final double elapsedSeconds;
  final String fontApplied;
  final String extractedText;

  const PdfToWordConversionResult({
    required this.success,
    this.errorMessage,
    this.docxFile,
    this.photoFile,
    this.docxUrl,
    this.fileName,
    this.fileSize = 0,
    this.pages = 1,
    this.elapsedSeconds = 0.0,
    this.fontApplied = 'Khmer OS Battambang',
    this.extractedText = '',
  });
}

/// Client Service for the High-Fidelity PDF to Word Microservice
/// Preserves 100% genuine vector layout, embedded images/photos, and tables.
class PdfToWordMicroservice {
  static String get _endpointUrl {
    return ApiService.baseUrl.replaceAll('api.php', 'api/convert-pdf-word.php');
  }

  /// Whether the microservice vector backend (iLovePDF / Server) is enabled.
  /// When true, high-fidelity vector conversion is prioritized.
  /// When false, the system falls back directly to AI Gemini OCR.
  static bool isServerEnabled = true;

  /// Check if the backend microservice engine is online and responsive
  static Future<bool> isServiceAvailable() async {
    try {
      final dio = Dio(BaseOptions(
        connectTimeout: const Duration(seconds: 5),
        receiveTimeout: const Duration(seconds: 5),
      ));
      final response = await dio.get(_endpointUrl);
      if (response.statusCode == 200 && response.data != null) {
        final status = response.data['status']?.toString();
        return status == 'online';
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  /// Convert PDF to high-fidelity Word (.docx) preserving original layout and photos
  static Future<PdfToWordConversionResult> convertPdfToDocx({
    required String pdfPath,
    String khmerFont = 'Khmer OS Battambang',
    void Function(double progress, String statusText)? onProgress,
  }) async {
    final pdfFile = File(pdfPath);
    if (!await pdfFile.exists()) {
      return const PdfToWordConversionResult(
        success: false,
        errorMessage: 'ឯកសារ PDF មិនមាននៅក្នុងឧបករណ៍ឡើយ',
      );
    }

    try {
      onProgress?.call(0.1, 'កំពុងផ្ញើឯកសារ PDF ទៅកាន់ Microservice Server...');

      final dio = Dio(BaseOptions(
        connectTimeout: const Duration(seconds: 30),
        receiveTimeout: const Duration(minutes: 5), // Large PDFs may take up to 2-3 mins
      ));

      final formData = FormData.fromMap({
        'pdf_file': await MultipartFile.fromFile(
          pdfPath,
          filename: pdfPath.split(Platform.pathSeparator).last,
        ),
        'khmer_font': khmerFont,
      });

      final response = await dio.post(
        _endpointUrl,
        data: formData,
        onSendProgress: (sent, total) {
          if (total > 0) {
            final uploadFraction = sent / total;
            // 10% to 50% for upload phase
            final pct = 0.1 + (uploadFraction * 0.4);
            onProgress?.call(pct, 'កំពុង Upload ឯកសារ (${(uploadFraction * 100).toInt()}%)...');
          }
        },
      );

      if (response.statusCode != 200 || response.data == null) {
        final errorMsg = response.data?['message']?.toString() ?? 'Server ឆ្លើយតបកំហុស (${response.statusCode})';
        return PdfToWordConversionResult(
          success: false,
          errorMessage: errorMsg,
        );
      }

      final data = response.data;
      if (data['status'] != 'success') {
        return PdfToWordConversionResult(
          success: false,
          errorMessage: data['message']?.toString() ?? 'ការបម្លែងឯកសារមិនជោគជ័យ',
        );
      }

      onProgress?.call(0.75, 'កំពុងទាញយកឯកសារ Word (.docx) ដែលបម្លែងរួច...');

      final docxUrl = data['docx_url']?.toString() ?? '';
      final downloadUrl = data['download_url']?.toString() ?? docxUrl;
      final serverFileName = data['file_name']?.toString() ?? 'document.docx';
      final totalPages = (data['pages'] as num?)?.toInt() ?? 1;
      final elapsed = (data['elapsed_seconds'] as num?)?.toDouble() ?? 0.0;
      final fontApplied = data['font_applied']?.toString() ?? khmerFont;
      final fileSize = (data['file_size'] as num?)?.toInt() ?? 0;

      // Download .docx to temporary app directory
      final tempDir = await getTemporaryDirectory();
      final localDocxPath = '${tempDir.path}/$serverFileName';
      final localDocxFile = File(localDocxPath);

      if (downloadUrl.isNotEmpty) {
        await dio.download(
          downloadUrl,
          localDocxPath,
          onReceiveProgress: (received, total) {
            if (total > 0) {
              final dlFraction = received / total;
              final pct = 0.75 + (dlFraction * 0.2);
              onProgress?.call(pct, 'កំពុងទាញយក Word (${(dlFraction * 100).toInt()}%)...');
            }
          },
        );
      }

      onProgress?.call(0.95, 'កំពុងស្រង់អត្ថបទ និងរូបថតសម្រាប់បង្ហាញ Preview...');

      // Extract plain text and photo for the A4 Preview Sheet
      String extractedText = '';
      File? extractedPhoto;
      if (await localDocxFile.exists()) {
        final extraction = await _extractDocxData(localDocxFile, tempDir);
        extractedText = extraction.text;
        extractedPhoto = extraction.photoFile;
      }

      onProgress?.call(1.0, 'រួចរាល់ ១០០%!');

      return PdfToWordConversionResult(
        success: true,
        docxFile: localDocxFile,
        photoFile: extractedPhoto,
        docxUrl: docxUrl,
        fileName: serverFileName,
        fileSize: fileSize,
        pages: totalPages,
        elapsedSeconds: elapsed,
        fontApplied: fontApplied,
        extractedText: extractedText,
      );
    } on DioException catch (dioErr) {
      String msg = 'កំហុសបណ្តាញតភ្ជាប់: ';
      if (dioErr.type == DioExceptionType.connectionTimeout) {
        msg += 'ផុតកំណត់ការភ្ជាប់ (Connection Timeout)';
      } else if (dioErr.type == DioExceptionType.receiveTimeout) {
        msg += 'Server ត្រូវការពេលយូរជាងការរំពឹងទុក (Receive Timeout)';
      } else if (dioErr.response?.data != null && dioErr.response?.data is Map) {
        msg += dioErr.response?.data['message']?.toString() ?? dioErr.message.toString();
      } else {
        msg += dioErr.message ?? 'Unknown connection error';
      }
      return PdfToWordConversionResult(
        success: false,
        errorMessage: msg,
      );
    } catch (e) {
      return PdfToWordConversionResult(
        success: false,
        errorMessage: 'កំហុសមិនបានរំពឹងទុក: $e',
      );
    }
  }

  /// Extracts readable text and embedded photo from a .docx file by unzipping
  static Future<({String text, File? photoFile})> _extractDocxData(File docxFile, Directory tempDir) async {
    try {
      final bytes = await docxFile.readAsBytes();
      final archive = ZipDecoder().decodeBytes(bytes);

      // 1. Extract embedded 3x4 photo from word/media/ (pick largest image file to avoid small icons/spacers)
      File? photoFile;
      final imageFiles = archive.files.where((file) {
        final lower = file.name.toLowerCase();
        final ext = lower.split('.').last;
        return (lower.startsWith('word/media/') || lower.contains('/media/')) &&
            ['jpg', 'jpeg', 'png', 'webp'].contains(ext) &&
            (file.content as List<int>).length > 200; // Skip tiny 0-byte or 1x1 spacer dots
      }).toList();

      if (imageFiles.isNotEmpty) {
        // Sort descending by size to ensure candidate's portrait photo is selected
        imageFiles.sort((a, b) => (b.content as List<int>).length.compareTo((a.content as List<int>).length));
        final bestImage = imageFiles.first;
        final ext = bestImage.name.split('.').last.toLowerCase();
        final photoPath = '${tempDir.path}/cv_photo_${DateTime.now().millisecondsSinceEpoch}.$ext';
        final pFile = File(photoPath);
        await pFile.writeAsBytes(bestImage.content as List<int>);
        photoFile = pFile;
      }

      // 2. Extract and parse word/document.xml
      final docFile = archive.findFile('word/document.xml');
      if (docFile == null) return (text: '', photoFile: photoFile);

      final xmlStr = utf8.decode(docFile.content as List<int>, allowMalformed: true);

      // Clean tags while preserving table structure
      final cleaned = xmlStr
          .replaceAll(RegExp(r'</w:tc>'), '\t')
          .replaceAll(RegExp(r'</w:tr>'), '\n')
          .replaceAll(RegExp(r'</w:p>'), '\n')
          .replaceAll(RegExp(r'<[^>]*>'), ' ')
          .replaceAll(RegExp(r'&amp;'), '&')
          .replaceAll(RegExp(r'&lt;'), '<')
          .replaceAll(RegExp(r'&gt;'), '>')
          .replaceAll(RegExp(r'&quot;'), '"')
          .replaceAll(RegExp(r'&#39;'), "'")
          .replaceAll(RegExp(r' +'), ' ')
          .trim();

      final normalized = normalizeExtractedCvText(cleaned);
      return (text: normalized, photoFile: photoFile);
    } catch (_) {
      return (text: '', photoFile: null);
    }
  }

  /// Normalizes CV lines that were split into separate lines by colons or tables
  static String normalizeExtractedCvText(String text) {
    // Strip invisible zero-width spaces that break Khmer string comparisons
    final cleanText = text.replaceAll(RegExp(r'[\u200B-\u200D\uFEFF]'), '');
    final lines = cleanText.split('\n').map((l) => l.trim()).toList();
    final result = <String>[];
    int i = 0;
    while (i < lines.length) {
      final line = lines[i];
      if (line.isEmpty) {
        if (result.isNotEmpty && result.last.isNotEmpty) {
          result.add('');
        }
        i++;
        continue;
      }

      // If current line contains tabs from table columns (e.g. multi-column CV rows)
      if (line.contains('\t')) {
        final cols = line.split('\t').map((c) => c.trim()).where((c) => c.isNotEmpty).toList();
        
        // Check if row has multiple [Label, :, Value] pairs (e.g. 2-column CV layout)
        int cIdx = 0;
        bool handled = false;
        while (cIdx + 2 < cols.length && cols[cIdx + 1] == ':') {
          result.add('${cols[cIdx]} : ${cols[cIdx + 2]}');
          cIdx += 3;
          handled = true;
        }

        if (handled) {
          while (cIdx < cols.length) {
            result.add(cols[cIdx]);
            cIdx++;
          }
          i++;
          continue;
        }

        if (cols.length >= 3 && cols[1] == ':') {
          result.add('${cols[0]} : ${cols.sublist(2).join(' ')}');
          i++;
          continue;
        } else if (cols.length == 2) {
          result.add('${cols[0]} : ${cols[1]}');
          i++;
          continue;
        } else if (cols.isNotEmpty) {
          result.add(cols.join(' '));
          i++;
          continue;
        }
      }

      // If current line is ":" and previous line exists and next line exists
      if ((line == ':' || line == '៖' || line == ':-') && result.isNotEmpty && i + 1 < lines.length) {
        final prev = result.removeLast();
        final next = lines[i + 1];
        result.add('$prev : $next');
        i += 2;
        continue;
      }

      // If current line starts with ": " or " : "
      if ((line.startsWith(': ') || line.startsWith(' : ') || line.startsWith('៖ ')) && result.isNotEmpty) {
        final prev = result.removeLast();
        final val = line.replaceFirst(RegExp(r'^\s*[:៖]\s*'), '');
        result.add('$prev : $val');
        i++;
        continue;
      }

      result.add(line);
      i++;
    }
    return result.join('\n');
  }
}
