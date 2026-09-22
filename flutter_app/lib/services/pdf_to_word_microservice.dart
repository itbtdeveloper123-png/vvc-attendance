import 'dart:io';
import 'package:dio/dio.dart';
import 'package:path_provider/path_provider.dart';
import 'package:archive/archive.dart';
import 'api_service.dart';

/// Result object of PDF to Word Microservice conversion
class PdfToWordConversionResult {
  final bool success;
  final String? errorMessage;
  final File? docxFile;
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

      onProgress?.call(0.95, 'កំពុងស្រង់អត្ថបទសម្រាប់បង្ហាញ Preview...');

      // Extract plain text for the A4 Preview Sheet
      String extractedText = '';
      if (await localDocxFile.exists()) {
        extractedText = await _extractTextFromDocx(localDocxFile);
      }

      onProgress?.call(1.0, 'រួចរាល់ ១០០%!');

      return PdfToWordConversionResult(
        success: true,
        docxFile: localDocxFile,
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

  /// Extracts readable text from a .docx file by unzipping and parsing word/document.xml
  static Future<String> _extractTextFromDocx(File docxFile) async {
    try {
      final bytes = await docxFile.readAsBytes();
      final archive = ZipDecoder().decodeBytes(bytes);
      final docFile = archive.findFile('word/document.xml');
      if (docFile == null) return '';

      final xmlStr = String.fromCharCodes(docFile.content as List<int>);
      
      // Clean tags while preserving paragraph spacing
      final cleaned = xmlStr
          .replaceAll(RegExp(r'</w:p>'), '\n\n')
          .replaceAll(RegExp(r'</w:tr>'), '\n')
          .replaceAll(RegExp(r'</w:tc>'), '\t')
          .replaceAll(RegExp(r'<[^>]*>'), ' ')
          .replaceAll(RegExp(r'&amp;'), '&')
          .replaceAll(RegExp(r'&lt;'), '<')
          .replaceAll(RegExp(r'&gt;'), '>')
          .replaceAll(RegExp(r'&quot;'), '"')
          .replaceAll(RegExp(r'&#39;'), "'")
          .replaceAll(RegExp(r' +'), ' ')
          .trim();

      return cleaned;
    } catch (_) {
      return '';
    }
  }
}
