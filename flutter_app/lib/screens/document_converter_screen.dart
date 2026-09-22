import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:file_picker/file_picker.dart';
import 'package:image_picker/image_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import 'package:image/image.dart' as img;
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import '../services/gemini_ocr_service.dart';
import '../services/document_conversion_service.dart';
import '../services/docx_generator_service.dart';
import '../services/pdf_to_word_microservice.dart';
import 'document_scanner_screen.dart';

/// Supported conversion tools
enum ConverterTool {
  pdfToWord,
  wordToPdf,
  imageToPdf,
  pdfToImage,
  geminiKhmerDocx,
  geminiKhmerText,
  mergePdf,
  compressPdf,
}

class DocumentConverterScreen extends StatefulWidget {
  final ConverterTool? initialTool;

  const DocumentConverterScreen({
    super.key,
    this.initialTool,
  });

  @override
  State<DocumentConverterScreen> createState() => _DocumentConverterScreenState();
}

class _DocumentConverterScreenState extends State<DocumentConverterScreen> {
  bool _isProcessing = false;
  String _progressMessage = '';
  double _progressValue = 0.0;

  @override
  void initState() {
    super.initState();
    if (widget.initialTool != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _launchTool(widget.initialTool!);
      });
    }
  }

  void _showToast(String message, {bool isError = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          message,
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13),
        ),
        backgroundColor: isError ? const Color(0xFFE11D48) : const Color(0xFF0284C7),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        margin: const EdgeInsets.all(16),
        duration: const Duration(seconds: 3),
      ),
    );
  }

  // ===========================================================================
  // LAUNCH TOOLS
  // ===========================================================================

  void _launchTool(ConverterTool tool) {
    switch (tool) {
      case ConverterTool.geminiKhmerDocx:
        _startGeminiOcr(exportToDocx: true);
        break;
      case ConverterTool.geminiKhmerText:
        _startGeminiOcr(exportToDocx: false);
        break;
      case ConverterTool.imageToPdf:
        _startImageToPdf();
        break;
      case ConverterTool.pdfToWord:
        _startPdfToWord();
        break;
      case ConverterTool.wordToPdf:
        _startWordToPdf();
        break;
      case ConverterTool.pdfToImage:
        _startPdfToImage();
        break;
      case ConverterTool.mergePdf:
        _startMergePdf();
        break;
      case ConverterTool.compressPdf:
        _startCompressPdf();
        break;
    }
  }

  // 1. AI Gemini Khmer OCR -> Word (.docx) or Text (Multi-page)
  Future<void> _startGeminiOcr({required bool exportToDocx}) async {
    final imagePaths = await _pickMultipleImagesDialog(
      title: 'ស្កេនអក្សរខ្មែរដោយ AI Gemini',
      subtitle: 'ស្គាល់គ្រប់ព្យញ្ជនៈ ស្រៈ ជើងអក្សរ និងតារាង មិនឱ្យបាត់ទម្រង់ដើម',
    );
    if (imagePaths == null || imagePaths.isEmpty) return;

    setState(() {
      _isProcessing = true;
      _progressMessage = 'AI Gemini កំពុងអានឯកសារខ្មែរ (ទំព័រ ១/${imagePaths.length})...';
      _progressValue = 0.2;
    });

    try {
      final result = await GeminiOcrService.processKhmerDocument(
        imagePaths: imagePaths,
        onProgress: (cur, total) {
          if (mounted) {
            setState(() {
              _progressMessage = 'AI Gemini កំពុងអានឯកសារខ្មែរ (ទំព័រ $cur/$total)...';
              _progressValue = cur / total;
            });
          }
        },
      );

      if (!result.success) {
        throw Exception(result.errorMessage ?? 'មិនអាចអានឯកសារបានឡើយ');
      }

      final tempDir = await getTemporaryDirectory();
      final timeStamp = DateTime.now().millisecondsSinceEpoch;

      if (exportToDocx) {
        // Generate real Word (.docx) document
        setState(() {
          _progressMessage = 'កំពុងបង្កើតឯកសារ Word (.docx)...';
          _progressValue = 0.9;
        });

        final initialFormat = result.detectedPageFormat ?? const DetectedPageFormat(
          paperSize: DocxPaperSize.a4,
          orientation: DocxPageOrientation.portrait,
          widthPt: 595.28,
          heightPt: 841.89,
        );

        final docxPath = '${tempDir.path}/Doc_${result.documentTitle ?? "Khmer"}_$timeStamp.docx';
        final docxFile = await GeminiOcrService.exportToDocx(
          result: result,
          outputPath: docxPath,
          pageSize: initialFormat.paperSize,
          orientation: initialFormat.orientation,
        );

        if (mounted) {
          setState(() => _isProcessing = false);
          _showResultSheet(
            title: 'បម្លែងជា Word (.docx) ជោគជ័យ!',
            subtitle: 'ឯកសាររក្សាទម្រង់ដើម (${initialFormat.summaryLabel}) និងអក្សរខ្មែរយូនីកូដបានយ៉ាងត្រឹមត្រូវ',
            filePath: docxFile.path,
            extractedText: result.fullText,
            isDocx: true,
            detectedFormat: initialFormat,
            multiImagePaths: imagePaths,
          );
        }
      } else {
        if (mounted) {
          setState(() => _isProcessing = false);
          _showResultSheet(
            title: 'ស្រង់អត្ថបទខ្មែរជោគជ័យ!',
            subtitle: 'ស្គាល់គ្រប់ជើង និងស្រៈខ្មែរត្រឹមត្រូវ ១០០%',
            extractedText: result.fullText,
            isDocx: false,
          );
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isProcessing = false);
        _showToast('កំហុសស្កេន AI: $e', isError: true);
      }
    }
  }

  // 2. Images to PDF (Multi-page, 100% full bleed)
  Future<void> _startImageToPdf() async {
    final imagePaths = await _pickMultipleImagesDialog(
      title: 'បំប្លែងរូបភាពទៅជា PDF',
      subtitle: 'គាំទ្រច្រើនទំព័រ ពេញក្រដាស ១០០% គ្មានគែមសរំខាន',
    );
    if (imagePaths == null || imagePaths.isEmpty) return;

    setState(() {
      _isProcessing = true;
      _progressMessage = 'កំពុងបម្លែងរូបភាព ${imagePaths.length} សន្លឹកទៅជា PDF...';
      _progressValue = 0.3;
    });

    try {
      final tempDir = await getTemporaryDirectory();
      final timeStamp = DateTime.now().millisecondsSinceEpoch;
      final pdfPath = '${tempDir.path}/Images_Scan_$timeStamp.pdf';

      final pdfFile = await DocumentConversionService.convertImagesToPdf(
        imagePaths: imagePaths,
        outputPath: pdfPath,
        onProgress: (cur, total) {
          if (mounted) {
            setState(() {
              _progressMessage = 'កំពុងដំណើរការទំព័រ $cur/$total...';
              _progressValue = cur / total;
            });
          }
        },
      );

      if (mounted) {
        setState(() => _isProcessing = false);
        _showResultSheet(
          title: 'បម្លែងជា PDF ជោគជ័យ!',
          subtitle: 'ឯកសារ PDF បង្ហាញពេញក្រដាស ១០០% គ្មានគែមស',
          filePath: pdfFile.path,
          multiImagePaths: imagePaths,
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isProcessing = false);
        _showToast('កំហុសបម្លែង PDF: $e', isError: true);
      }
    }
  }

  // 3. PDF to Word (.docx) (Smart Automatic Engine - One-Tap Conversion)
  Future<void> _startPdfToWord() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['pdf'],
      allowMultiple: false,
    );
    if (result == null || result.files.isEmpty || result.files.first.path == null) return;
    final pdfPath = result.files.first.path!;

    if (!mounted) return;
    await _convertPdfAuto(pdfPath);
  }

  /// Extracts or crops a 3x4 photo from a document page (top-right area for CVs) as fallback
  Future<File?> _tryExtractPhotoFromPage(String pageImagePath) async {
    try {
      final bytes = await File(pageImagePath).readAsBytes();
      final decoded = img.decodeImage(bytes);
      if (decoded == null) return null;

      final cropX = (decoded.width * 0.64).toInt();
      final cropY = (decoded.height * 0.08).toInt();
      final cropW = (decoded.width * 0.28).toInt();
      final cropH = (decoded.height * 0.24).toInt();

      if (cropX + cropW <= decoded.width && cropY + cropH <= decoded.height) {
        final cropped = img.copyCrop(decoded, x: cropX, y: cropY, width: cropW, height: cropH);
        final tempDir = await getTemporaryDirectory();
        final photoFile = File('${tempDir.path}/cropped_cv_photo_${DateTime.now().millisecondsSinceEpoch}.jpg');
        await photoFile.writeAsBytes(img.encodeJpg(cropped, quality: 92));
        return photoFile;
      }
    } catch (_) {}
    return null;
  }

  /// High-Fidelity Automatic Pipeline:
  /// Prioritizes iLovePDF Cloud API & Microservice vector engine to preserve 100% genuine
  /// formatting, tables, borders, colors, fonts, and real candidate photos for both Khmer and English.
  /// Automatically falls back to Gemini OCR only if vector conversion fails (e.g. pure image scans).
  Future<void> _convertPdfAuto(String pdfPath) async {
    setState(() {
      _isProcessing = true;
      _progressMessage = 'កំពុងវិភាគទម្រង់ និងបម្លែងតាម iLovePDF / Microservice...';
      _progressValue = 0.15;
    });

    try {
      final detectedFormat = await DocumentConversionService.detectPdfPageFormat(pdfPath);

      final result = await PdfToWordMicroservice.convertPdfToDocx(
        pdfPath: pdfPath,
        onProgress: (pct, msg) {
          if (mounted) {
            setState(() {
              _progressValue = pct;
              _progressMessage = msg;
            });
          }
        },
      );

      // Primary High-Fidelity Success: Word document generated with 100% genuine vector layout!
      if (result.success && result.docxFile != null && result.docxFile!.existsSync()) {
        List<String>? previewImages;
        try {
          final tempDir = await getTemporaryDirectory();
          final previewDir = Directory('${tempDir.path}/preview_pdf_${DateTime.now().millisecondsSinceEpoch}');
          await previewDir.create(recursive: true);
          previewImages = await DocumentConversionService.convertPdfToImages(
            pdfPath: pdfPath,
            outputDir: previewDir.path,
          );
        } catch (_) {}

        File? photo = result.photoFile;
        // Fallback photo extraction from page render if CV and no photo found in docx media
        if (photo == null && previewImages != null && previewImages.isNotEmpty) {
          final isCv = result.extractedText.contains('ប្រវត្តិរូប') ||
              result.extractedText.toUpperCase().contains('CURRICULUM VITAE') ||
              result.extractedText.toUpperCase().contains('RESUME');
          if (isCv) {
            photo = await _tryExtractPhotoFromPage(previewImages.first);
          }
        }

        if (mounted) {
          setState(() => _isProcessing = false);
          _showResultSheet(
            title: 'បម្លែងជា Word (.docx) ជោគជ័យ!',
            subtitle: 'រក្សាទម្រង់ដើម ពណ៌ តារាង និងរូបថត ១០០% (ទំព័រ: ${result.pages})',
            filePath: result.docxFile!.path,
            extractedText: result.extractedText,
            isDocx: true,
            detectedFormat: detectedFormat,
            multiImagePaths: previewImages,
            sourcePdfPath: pdfPath,
            initialPhotoFile: photo,
          );
        }
        return;
      }

      // Secondary Fallback: Only for pure scanned image PDFs where vector extraction fails
      if (mounted) {
        setState(() {
          _progressMessage = 'ឯកសារស្កេនរូបភាព៖ កំពុងដំណើរការ AI Gemini OCR អានអក្សរ...';
          _progressValue = 0.4;
        });
      }
      await _convertPdfWithGeminiOcr(pdfPath);
    } catch (_) {
      // Graceful fallback to Gemini OCR if service is unavailable
      if (mounted) {
        setState(() {
          _progressMessage = 'កំពុងដំណើរការ AI Gemini OCR អានអក្សរ...';
          _progressValue = 0.4;
        });
      }
      await _convertPdfWithGeminiOcr(pdfPath);
    }
  }

  /// Convert PDF using AI Gemini OCR (for scanned images / copy papers)
  Future<void> _convertPdfWithGeminiOcr(String pdfPath) async {
    setState(() {
      _isProcessing = true;
      _progressMessage = 'កំពុងបម្លែងទំព័រ PDF ទៅជារូបភាពដើម្បីដំណើរការ AI...';
      _progressValue = 0.2;
    });

    try {
      final detectedFormat = await DocumentConversionService.detectPdfPageFormat(pdfPath);

      final tempDir = await getTemporaryDirectory();
      final outputDir = Directory('${tempDir.path}/pdf_pages_${DateTime.now().millisecondsSinceEpoch}');
      await outputDir.create(recursive: true);

      final imagePaths = await DocumentConversionService.convertPdfToImages(
        pdfPath: pdfPath,
        outputDir: outputDir.path,
      );

      if (imagePaths.isEmpty) {
        throw Exception('មិនមានទំព័រក្នុងឯកសារ PDF ឡើយ');
      }

      setState(() {
        _progressMessage = 'AI Gemini កំពុងស្រង់ទម្រង់ឯកសារ និងអក្សរខ្មែរ (${detectedFormat.summaryLabel})...';
        _progressValue = 0.5;
      });

      final ocrResult = await GeminiOcrService.processKhmerDocument(
        imagePaths: imagePaths,
        onProgress: (cur, total) {
          if (mounted) {
            setState(() {
              _progressMessage = 'AI Gemini កំពុងអានទំព័រ $cur/$total...';
              _progressValue = 0.5 + (cur / total) * 0.4;
            });
          }
        },
      );

      if (!ocrResult.success || ocrResult.fullText.trim().isEmpty) {
        throw Exception(ocrResult.errorMessage ?? 'មិនអាចស្រង់អត្ថបទពីឯកសារ PDF បានឡើយ។');
      }

      final timeStamp = DateTime.now().millisecondsSinceEpoch;
      final docxPath = '${tempDir.path}/PDF_to_Word_$timeStamp.docx';
      final docxFile = await GeminiOcrService.exportToDocx(
        result: ocrResult,
        outputPath: docxPath,
        pageSize: detectedFormat.paperSize,
        orientation: detectedFormat.orientation,
      );

      if (mounted) {
        setState(() => _isProcessing = false);
        _showResultSheet(
          title: 'បម្លែង PDF ទៅជា Word ជោគជ័យ!',
          subtitle: 'ឯកសារ Word (.docx) ត្រូវតាមទំហំដើម (${detectedFormat.summaryLabel}) និងអក្សរខ្មែរយ៉ាងពេញលេញ',
          filePath: docxFile.path,
          extractedText: ocrResult.fullText,
          isDocx: true,
          detectedFormat: detectedFormat,
          multiImagePaths: imagePaths,
          sourcePdfPath: pdfPath,
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isProcessing = false);
        _showToast('កំហុសបម្លែង PDF to Word: $e', isError: true);
      }
    }
  }

  // 4. Word (.docx) to PDF (Multi-page)
  Future<void> _startWordToPdf() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['docx', 'doc', 'txt'],
      allowMultiple: false,
    );
    if (result == null || result.files.isEmpty || result.files.first.path == null) return;
    final filePath = result.files.first.path!;

    setState(() {
      _isProcessing = true;
      _progressMessage = 'កំពុងបម្លែង Word ទៅជា PDF...';
      _progressValue = 0.5;
    });

    try {
      final tempDir = await getTemporaryDirectory();
      final timeStamp = DateTime.now().millisecondsSinceEpoch;
      final pdfPath = '${tempDir.path}/Word_to_Pdf_$timeStamp.pdf';

      final pdfFile = await DocumentConversionService.convertWordToPdf(
        docxOrTextPath: filePath,
        outputPath: pdfPath,
      );

      if (mounted) {
        setState(() => _isProcessing = false);
        _showResultSheet(
          title: 'បម្លែង Word ទៅជា PDF ជោគជ័យ!',
          subtitle: 'ឯកសារ PDF បានបង្កើតរួចរាល់ជាមួយពុម្ពអក្សរខ្មែរស្អាត',
          filePath: pdfFile.path,
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isProcessing = false);
        _showToast('កំហុសបម្លែង Word to PDF: $e', isError: true);
      }
    }
  }

  // 5. PDF to Images (Multi-page)
  Future<void> _startPdfToImage() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['pdf'],
      allowMultiple: false,
    );
    if (result == null || result.files.isEmpty || result.files.first.path == null) return;
    final pdfPath = result.files.first.path!;

    setState(() {
      _isProcessing = true;
      _progressMessage = 'កំពុងស្រង់រូបភាពពីឯកសារ PDF...';
      _progressValue = 0.4;
    });

    try {
      final tempDir = await getTemporaryDirectory();
      final timeStamp = DateTime.now().millisecondsSinceEpoch;
      final outputDir = Directory('${tempDir.path}/pdf_images_$timeStamp');
      await outputDir.create(recursive: true);

      final images = await DocumentConversionService.convertPdfToImages(
        pdfPath: pdfPath,
        outputDir: outputDir.path,
        onProgress: (cur, total) {
          if (mounted) {
            setState(() {
              _progressMessage = 'កំពុងស្រង់រូបភាពទំព័រ $cur...';
            });
          }
        },
      );

      if (mounted) {
        setState(() => _isProcessing = false);
        if (images.isNotEmpty) {
          _showResultSheet(
            title: 'ស្រង់រូបភាពបានជោគជ័យ!',
            subtitle: 'ទទួលបានរូបភាពចំនួន ${images.length} សន្លឹកកម្រិត Ultra-HD',
            filePath: images.first,
            multiImagePaths: images,
          );
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isProcessing = false);
        _showToast('កំហុសបម្លែង PDF to Image: $e', isError: true);
      }
    }
  }

  // 6. Merge PDF (Multi-page)
  Future<void> _startMergePdf() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['pdf'],
      allowMultiple: true,
    );
    if (result == null || result.files.length < 2) {
      _showToast('សូមជ្រើសរើសឯកសារ PDF យ៉ាងតិច ២ ដើម្បីបញ្ចូលគ្នា');
      return;
    }

    final paths = result.files.map((f) => f.path).whereType<String>().toList();

    setState(() {
      _isProcessing = true;
      _progressMessage = 'កំពុងបញ្ចូល ${paths.length} ឯកសារ PDF ចូលគ្នា...';
      _progressValue = 0.3;
    });

    try {
      final tempDir = await getTemporaryDirectory();
      final timeStamp = DateTime.now().millisecondsSinceEpoch;
      final outPath = '${tempDir.path}/Merged_Doc_$timeStamp.pdf';

      final mergedFile = await DocumentConversionService.mergePdfs(
        pdfPaths: paths,
        outputPdfPath: outPath,
        onProgress: (cur, total) {
          if (mounted) {
            setState(() {
              _progressMessage = 'កំពុងបញ្ចូលឯកសារ $cur/$total...';
              _progressValue = cur / total;
            });
          }
        },
      );

      if (mounted) {
        setState(() => _isProcessing = false);
        _showResultSheet(
          title: 'បញ្ចូល PDF ចូលគ្នាជោគជ័យ!',
          subtitle: 'ឯកសារ PDF ទាំងអស់ត្រូវបានបង្រួបបង្រួមជាឯកសារតែមួយយ៉ាងរលូន',
          filePath: mergedFile.path,
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isProcessing = false);
        _showToast('កំហុសបញ្ចូល PDF: $e', isError: true);
      }
    }
  }

  // 7. Compress PDF
  Future<void> _startCompressPdf() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['pdf'],
      allowMultiple: false,
    );
    if (result == null || result.files.isEmpty || result.files.first.path == null) return;
    final pdfPath = result.files.first.path!;

    setState(() {
      _isProcessing = true;
      _progressMessage = 'កំពុងបង្រួមទំហំឯកសារ PDF...';
      _progressValue = 0.3;
    });

    try {
      final tempDir = await getTemporaryDirectory();
      final timeStamp = DateTime.now().millisecondsSinceEpoch;
      final outPath = '${tempDir.path}/Compressed_$timeStamp.pdf';

      final compressedFile = await DocumentConversionService.compressPdf(
        inputPdfPath: pdfPath,
        outputPdfPath: outPath,
        jpegQuality: 70,
        onProgress: (cur, total) {
          if (mounted) {
            setState(() {
              _progressMessage = 'កំពុងកាត់បន្ថយទំហំទំព័រ $cur...';
            });
          }
        },
      );

      final originalSize = File(pdfPath).lengthSync();
      final newSize = compressedFile.lengthSync();
      final savedPercent = (((originalSize - newSize) / originalSize) * 100).clamp(0, 99).toInt();

      if (mounted) {
        setState(() => _isProcessing = false);
        _showResultSheet(
          title: 'បង្រួម PDF ជោគជ័យ!',
          subtitle: 'កាត់បន្ថយទំហំបាន ~$savedPercent% ងាយស្រួលផ្ញើតាម Telegram/Email',
          filePath: compressedFile.path,
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isProcessing = false);
        _showToast('កំហុសបង្រួម PDF: $e', isError: true);
      }
    }
  }

  // Helper dialog to pick single or multiple images
  Future<List<String>?> _pickMultipleImagesDialog({
    required String title,
    required String subtitle,
  }) async {
    return await showModalBottomSheet<List<String>>(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (ctx) {
        final isDark = Theme.of(ctx).brightness == Brightness.dark || AppTheme.isDarkMode;
        return Container(
          padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
          decoration: BoxDecoration(
            color: isDark ? const Color(0xFF1E293B) : Colors.white,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.1),
                blurRadius: 20,
                offset: const Offset(0, -4),
              ),
            ],
          ),
          child: SafeArea(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 40,
                  height: 4,
                  margin: const EdgeInsets.only(bottom: 16),
                  decoration: BoxDecoration(
                    color: AppTheme.border,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
                Text(
                  title,
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? Colors.white : AppTheme.textPrimary,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  subtitle,
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textMuted,
                    fontSize: 12,
                  ),
                ),
                const SizedBox(height: 20),
                // Option 1: Gallery Multi-image
                ListTile(
                  onTap: () async {
                    final picker = ImagePicker();
                    final images = await picker.pickMultiImage(imageQuality: 100);
                    if (images.isNotEmpty && ctx.mounted) {
                      Navigator.pop(ctx, images.map((x) => x.path).toList());
                    }
                  },
                  tileColor: isDark ? const Color(0xFF0F172A) : const Color(0xFFF8FAFC),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14),
                    side: BorderSide(color: AppTheme.border),
                  ),
                  leading: Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF2563EB).withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Icon(Icons.photo_library_rounded, color: Color(0xFF2563EB), size: 22),
                  ),
                  title: Text(
                    'ជ្រើសរូបភាពច្រើនសន្លឹក (Gallery Multi-select)',
                    style: GoogleFonts.kantumruyPro(
                      color: isDark ? Colors.white : AppTheme.textPrimary,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  subtitle: Text(
                    'ជ្រើសរូបភាពឯកសារ ១ ឬ ច្រើនសន្លឹកក្នុងពេលតែមួយ',
                    style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 11),
                  ),
                  trailing: const Icon(Icons.chevron_right_rounded, color: Color(0xFF94A3B8)),
                ),
                const SizedBox(height: 10),
                // Option 2: Camera Multi-page Scan
                ListTile(
                  onTap: () async {
                    Navigator.pop(ctx);
                    Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (_) => const DocumentScannerScreen(),
                      ),
                    );
                  },
                  tileColor: isDark ? const Color(0xFF0F172A) : const Color(0xFFF8FAFC),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14),
                    side: BorderSide(color: AppTheme.border),
                  ),
                  leading: Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0D9488).withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Icon(Icons.camera_alt_rounded, color: Color(0xFF0D9488), size: 22),
                  ),
                  title: Text(
                    'ស្កេនផ្ទាល់ពីកាមេរ៉ា (Smart Camera)',
                    style: GoogleFonts.kantumruyPro(
                      color: isDark ? Colors.white : AppTheme.textPrimary,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  subtitle: Text(
                    'ថតស្កេន និងកាត់គែមស្វ័យប្រវត្តិកម្រិត HD',
                    style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 11),
                  ),
                  trailing: const Icon(Icons.chevron_right_rounded, color: Color(0xFF94A3B8)),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  // ===========================================================================
  // RESULT SHEET & PREVIEW
  // ===========================================================================

  void _showResultSheet({
    required String title,
    required String subtitle,
    String? filePath,
    String? extractedText,
    bool isDocx = false,
    List<String>? multiImagePaths,
    DetectedPageFormat? detectedFormat,
    String? sourcePdfPath,
    File? initialPhotoFile,
  }) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) {
        final isDark = Theme.of(ctx).brightness == Brightness.dark || AppTheme.isDarkMode;
        final hasOriginalScan = multiImagePaths != null &&
            multiImagePaths.isNotEmpty &&
            File(multiImagePaths.first).existsSync();

        int activeTab = 0; // 0: Preview, 1: Original Scan (if available) or Raw Text, 2: Raw Text
        String currentText = PdfToWordMicroservice.normalizeExtractedCvText(extractedText ?? '');
        String? currentFilePath = filePath;
        File? cvPhotoFile = initialPhotoFile;
        bool isFitScreen = true; // Proportional fit-to-mobile width by default
        bool showOriginalLayout = hasOriginalScan; // Default to authentic 100% original layout when available

        DocxPaperSize currentPaperSize = detectedFormat?.paperSize ?? DocxPaperSize.a4;
        DocxPageOrientation currentOrientation = detectedFormat?.orientation ?? DocxPageOrientation.portrait;
        DocxPageMargin currentMargin = DocxPageMargin.normal;
        bool isRegenerating = false;

        return StatefulBuilder(
          builder: (modalContext, setModalState) {
            final hasText = currentText.trim().isNotEmpty;

            // Pick 3x4 Photo for CV
            Future<void> pickCvPhoto() async {
              final picker = ImagePicker();
              final source = await showModalBottomSheet<ImageSource>(
                context: ctx,
                backgroundColor: isDark ? const Color(0xFF1E293B) : Colors.white,
                shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(18))),
                builder: (bCtx) => SafeArea(
                  child: Padding(
                    padding: const EdgeInsets.symmetric(vertical: 16, horizontal: 20),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          'ជ្រើសរើសរូបថត 3x4 សម្រាប់ CV',
                          style: GoogleFonts.kantumruyPro(fontSize: 14, fontWeight: FontWeight.bold),
                        ),
                        const SizedBox(height: 14),
                        ListTile(
                          leading: const Icon(Icons.photo_library_rounded, color: Color(0xFF2563EB)),
                          title: Text('ជ្រើសពីវិចិត្រសាល (Gallery)', style: GoogleFonts.kantumruyPro(fontSize: 13)),
                          onTap: () => Navigator.pop(bCtx, ImageSource.gallery),
                        ),
                        ListTile(
                          leading: const Icon(Icons.camera_alt_rounded, color: Color(0xFF10B981)),
                          title: Text('ថតរូបថ្មី (Camera)', style: GoogleFonts.kantumruyPro(fontSize: 13)),
                          onTap: () => Navigator.pop(bCtx, ImageSource.camera),
                        ),
                        if (cvPhotoFile != null)
                          ListTile(
                            leading: const Icon(Icons.delete_outline_rounded, color: Color(0xFFE11D48)),
                            title: Text('លុបរូបថតចេញ', style: GoogleFonts.kantumruyPro(fontSize: 13, color: const Color(0xFFE11D48))),
                            onTap: () {
                              Navigator.pop(bCtx);
                              setModalState(() => cvPhotoFile = null);
                            },
                          ),
                      ],
                    ),
                  ),
                ),
              );

              if (source != null) {
                final picked = await picker.pickImage(source: source, imageQuality: 90);
                if (picked != null) {
                  setModalState(() {
                    cvPhotoFile = File(picked.path);
                  });
                  _showToast('បានជ្រើសរើសរូបថត 3x4 រួចរាល់!');
                }
              }
            }

            // Re-generate DOCX when format, orientation, or text changes
            Future<void> reGenerateDocx({
              DocxPaperSize? newSize,
              DocxPageOrientation? newOrient,
              DocxPageMargin? newMargin,
              String? newContent,
            }) async {
              final targetSize = newSize ?? currentPaperSize;
              final targetOrient = newOrient ?? currentOrientation;
              final targetMargin = newMargin ?? currentMargin;
              final targetContent = newContent ?? currentText;

              setModalState(() {
                currentPaperSize = targetSize;
                currentOrientation = targetOrient;
                currentMargin = targetMargin;
                if (newContent != null) currentText = newContent;
                isRegenerating = true;
              });

              try {
                final tempDir = await getTemporaryDirectory();
                final timeStamp = DateTime.now().millisecondsSinceEpoch;
                final updatedPath = '${tempDir.path}/Doc_${targetSize.name}_${targetOrient.name}_$timeStamp.docx';
                final newDocx = await DocxGeneratorService.generateDocx(
                  title: 'ពាក្យសុំច្បាប់ឈប់សម្រាក',
                  content: targetContent,
                  outputPath: updatedPath,
                  pageSize: targetSize,
                  orientation: targetOrient,
                  margin: targetMargin,
                );
                setModalState(() {
                  currentFilePath = newDocx.path;
                  isRegenerating = false;
                });
                _showToast('បានរៀបចំជា ${targetSize.name} (${targetOrient == DocxPageOrientation.landscape ? "ផ្តេក" : "បញ្ឈរ"}) រួចរាល់!');
              } catch (e) {
                setModalState(() => isRegenerating = false);
                _showToast('កំហុសរៀបចំ Word ឡើងវិញ: $e', isError: true);
              }
            }

            // Launch Fullscreen A4 Document View
            void openFullScreen() {
              Navigator.push(
                ctx,
                MaterialPageRoute(
                  builder: (fsCtx) => A4DocumentFullscreenViewer(
                    initialText: currentText,
                    paperSize: currentPaperSize,
                    orientation: currentOrientation,
                    photoFile: cvPhotoFile,
                    filePath: currentFilePath,
                    onPickPhoto: pickCvPhoto,
                    paperBuilder: (text, size, orient, photo, onPick) => _buildA4PaperContent(
                      text,
                      isDark,
                      paperSize: size,
                      orientation: orient,
                      photoFile: photo,
                      onPickPhoto: onPick,
                    ),
                    onSaveText: (newText) async {
                      await reGenerateDocx(newContent: newText);
                    },
                  ),
                ),
              );
            }

            return Container(
              height: MediaQuery.of(ctx).size.height * 0.92,
              decoration: BoxDecoration(
                color: isDark ? const Color(0xFF1E293B) : Colors.white,
                borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
              ),
              child: Column(
                children: [
                  // Sheet Handle
                  Center(
                    child: Container(
                      width: 40,
                      height: 4,
                      margin: const EdgeInsets.symmetric(vertical: 10),
                      decoration: BoxDecoration(
                        color: AppTheme.border,
                        borderRadius: BorderRadius.circular(2),
                      ),
                    ),
                  ),

                  // Title Header
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 4),
                    child: Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: const Color(0xFF10B981).withValues(alpha: 0.15),
                            shape: BoxShape.circle,
                          ),
                          child: const Icon(Icons.check_circle_rounded, color: Color(0xFF10B981), size: 22),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                title,
                                style: GoogleFonts.kantumruyPro(
                                  color: isDark ? Colors.white : AppTheme.textPrimary,
                                  fontSize: 15,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                              Text(
                                subtitle,
                                style: GoogleFonts.kantumruyPro(
                                  color: AppTheme.textMuted,
                                  fontSize: 11.5,
                                ),
                              ),
                            ],
                          ),
                        ),
                        IconButton(
                          icon: const Icon(Icons.close_rounded),
                          color: AppTheme.textMuted,
                          onPressed: () => Navigator.pop(ctx),
                        ),
                      ],
                    ),
                  ),



                  // Segmented Tabs (Preview Word | Original Scan | Raw Text)
                  if (hasText) ...[
                    const SizedBox(height: 6),
                    Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 20),
                      child: Container(
                        height: 38,
                        padding: const EdgeInsets.all(3),
                        decoration: BoxDecoration(
                          color: isDark ? const Color(0xFF0F172A) : const Color(0xFFF1F5F9),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: AppTheme.border),
                        ),
                        child: Row(
                          children: [
                            // Tab 0: Word Preview
                            Expanded(
                              child: GestureDetector(
                                onTap: () => setModalState(() => activeTab = 0),
                                child: Container(
                                  decoration: BoxDecoration(
                                    color: activeTab == 0
                                        ? (isDark ? const Color(0xFF2563EB) : Colors.white)
                                        : Colors.transparent,
                                    borderRadius: BorderRadius.circular(8),
                                    boxShadow: activeTab == 0 && !isDark
                                        ? [BoxShadow(color: Colors.black.withValues(alpha: 0.05), blurRadius: 4)]
                                        : null,
                                  ),
                                  alignment: Alignment.center,
                                  child: Row(
                                    mainAxisAlignment: MainAxisAlignment.center,
                                    children: [
                                      Icon(
                                        Icons.description_rounded,
                                        size: 14,
                                        color: activeTab == 0
                                            ? (isDark ? Colors.white : const Color(0xFF2563EB))
                                            : AppTheme.textMuted,
                                      ),
                                      const SizedBox(width: 5),
                                      Text(
                                        'ទិដ្ឋភាព Word',
                                        style: GoogleFonts.kantumruyPro(
                                          fontSize: 11.5,
                                          fontWeight: activeTab == 0 ? FontWeight.bold : FontWeight.w500,
                                          color: activeTab == 0
                                              ? (isDark ? Colors.white : const Color(0xFF2563EB))
                                              : AppTheme.textMuted,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ),

                            // Tab 1: Original Scan Image (Only if original scan exists)
                            if (hasOriginalScan) ...[
                              Expanded(
                                child: GestureDetector(
                                  onTap: () => setModalState(() => activeTab = 1),
                                  child: Container(
                                    decoration: BoxDecoration(
                                      color: activeTab == 1
                                          ? (isDark ? const Color(0xFF2563EB) : Colors.white)
                                          : Colors.transparent,
                                      borderRadius: BorderRadius.circular(8),
                                      boxShadow: activeTab == 1 && !isDark
                                          ? [BoxShadow(color: Colors.black.withValues(alpha: 0.05), blurRadius: 4)]
                                          : null,
                                    ),
                                    alignment: Alignment.center,
                                    child: Row(
                                      mainAxisAlignment: MainAxisAlignment.center,
                                      children: [
                                        Icon(
                                          Icons.image_search_rounded,
                                          size: 14,
                                          color: activeTab == 1
                                              ? (isDark ? Colors.white : const Color(0xFF2563EB))
                                              : AppTheme.textMuted,
                                        ),
                                        const SizedBox(width: 5),
                                        Text(
                                          'ឯកសារដើម',
                                          style: GoogleFonts.kantumruyPro(
                                            fontSize: 11.5,
                                            fontWeight: activeTab == 1 ? FontWeight.bold : FontWeight.w500,
                                            color: activeTab == 1
                                                ? (isDark ? Colors.white : const Color(0xFF2563EB))
                                                : AppTheme.textMuted,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                ),
                              ),
                            ],

                            // Tab Raw Text
                            Expanded(
                              child: GestureDetector(
                                onTap: () => setModalState(() => activeTab = hasOriginalScan ? 2 : 1),
                                child: Container(
                                  decoration: BoxDecoration(
                                    color: activeTab == (hasOriginalScan ? 2 : 1)
                                        ? (isDark ? const Color(0xFF2563EB) : Colors.white)
                                        : Colors.transparent,
                                    borderRadius: BorderRadius.circular(8),
                                    boxShadow: activeTab == (hasOriginalScan ? 2 : 1) && !isDark
                                        ? [BoxShadow(color: Colors.black.withValues(alpha: 0.05), blurRadius: 4)]
                                        : null,
                                  ),
                                  alignment: Alignment.center,
                                  child: Row(
                                    mainAxisAlignment: MainAxisAlignment.center,
                                    children: [
                                      Icon(
                                        Icons.text_fields_rounded,
                                        size: 14,
                                        color: activeTab == (hasOriginalScan ? 2 : 1)
                                            ? (isDark ? Colors.white : const Color(0xFF2563EB))
                                            : AppTheme.textMuted,
                                      ),
                                      const SizedBox(width: 5),
                                      Text(
                                        'អត្ថបទសុទ្ធ',
                                        style: GoogleFonts.kantumruyPro(
                                          fontSize: 11.5,
                                          fontWeight: activeTab == (hasOriginalScan ? 2 : 1) ? FontWeight.bold : FontWeight.w500,
                                          color: activeTab == (hasOriginalScan ? 2 : 1)
                                              ? (isDark ? Colors.white : const Color(0xFF2563EB))
                                              : AppTheme.textMuted,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],

                  // Dynamic Paper Format & Orientation Controls (Only for Word .docx)
                  if (isDocx && hasText) ...[
                    const SizedBox(height: 8),
                    Container(
                      margin: const EdgeInsets.symmetric(horizontal: 20),
                      padding: const EdgeInsets.fromLTRB(12, 8, 12, 8),
                      decoration: BoxDecoration(
                        color: isDark ? const Color(0xFF0F172A).withValues(alpha: 0.8) : const Color(0xFFF8FAFC),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: AppTheme.border.withValues(alpha: 0.7)),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          // Header + Auto-detect Badge + Loading
                          Row(
                            children: [
                              const Icon(Icons.tune_rounded, size: 15, color: Color(0xFF2563EB)),
                              const SizedBox(width: 6),
                              Text(
                                'ទម្រង់ក្រដាស Word (Paper Layout)',
                                style: GoogleFonts.kantumruyPro(
                                  fontSize: 11,
                                  fontWeight: FontWeight.bold,
                                  color: isDark ? Colors.white : AppTheme.textPrimary,
                                ),
                              ),
                              if (detectedFormat != null) ...[
                                const SizedBox(width: 6),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF10B981).withValues(alpha: 0.15),
                                    borderRadius: BorderRadius.circular(6),
                                    border: Border.all(color: const Color(0xFF10B981).withValues(alpha: 0.3)),
                                  ),
                                  child: Row(
                                    mainAxisSize: MainAxisSize.min,
                                    children: [
                                      const Icon(Icons.auto_awesome, size: 10, color: Color(0xFF10B981)),
                                      const SizedBox(width: 3),
                                      Text(
                                        'ដើម៖ ${detectedFormat.summaryLabel}',
                                        style: GoogleFonts.kantumruyPro(
                                          fontSize: 9.5,
                                          fontWeight: FontWeight.bold,
                                          color: const Color(0xFF10B981),
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ],
                              const Spacer(),
                              if (isRegenerating)
                                const SizedBox(
                                  width: 14,
                                  height: 14,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    valueColor: AlwaysStoppedAnimation(Color(0xFF2563EB)),
                                  ),
                                ),
                            ],
                          ),
                          const SizedBox(height: 6),

                          // Horizontal scrollable options
                          SingleChildScrollView(
                            scrollDirection: Axis.horizontal,
                            physics: const BouncingScrollPhysics(),
                            child: Row(
                              children: [
                                // Orientation 1: Portrait
                                _buildOrientationPill(
                                  label: 'បញ្ឈរ (Portrait)',
                                  icon: Icons.stay_current_portrait_rounded,
                                  isSelected: currentOrientation == DocxPageOrientation.portrait,
                                  onTap: () => reGenerateDocx(newOrient: DocxPageOrientation.portrait),
                                  isDark: isDark,
                                ),
                                const SizedBox(width: 5),

                                // Orientation 2: Landscape
                                _buildOrientationPill(
                                  label: 'ផ្តេក (Landscape)',
                                  icon: Icons.stay_current_landscape_rounded,
                                  isSelected: currentOrientation == DocxPageOrientation.landscape,
                                  onTap: () => reGenerateDocx(newOrient: DocxPageOrientation.landscape),
                                  isDark: isDark,
                                ),
                                const SizedBox(width: 8),

                                Container(width: 1, height: 20, color: AppTheme.border),
                                const SizedBox(width: 8),

                                // Paper Sizes: A4, Letter, Legal, A5, A3
                                ...DocxPaperSize.values.map((size) {
                                  final isSelected = currentPaperSize == size;
                                  return Padding(
                                    padding: const EdgeInsets.only(right: 5),
                                    child: ChoiceChip(
                                      label: Text(
                                        '${size.name} (${size.dimensions})',
                                        style: GoogleFonts.kantumruyPro(
                                          fontSize: 10,
                                          fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                                          color: isSelected ? Colors.white : (isDark ? Colors.white70 : AppTheme.textPrimary),
                                        ),
                                      ),
                                      selected: isSelected,
                                      selectedColor: const Color(0xFF2563EB),
                                      backgroundColor: isDark ? const Color(0xFF1E293B) : Colors.white,
                                      visualDensity: VisualDensity.compact,
                                      padding: const EdgeInsets.symmetric(horizontal: 4),
                                      shape: RoundedRectangleBorder(
                                        borderRadius: BorderRadius.circular(8),
                                        side: BorderSide(
                                          color: isSelected ? const Color(0xFF2563EB) : AppTheme.border,
                                        ),
                                      ),
                                      onSelected: (_) => reGenerateDocx(newSize: size),
                                    ),
                                  );
                                }),

                                const SizedBox(width: 4),
                                Container(width: 1, height: 20, color: AppTheme.border),
                                const SizedBox(width: 8),

                                // Margin selectors: Normal, Narrow, Wide
                                ...DocxPageMargin.values.map((m) {
                                  final isSelected = currentMargin == m;
                                  return Padding(
                                    padding: const EdgeInsets.only(right: 5),
                                    child: ChoiceChip(
                                      label: Text(
                                        m.label,
                                        style: GoogleFonts.kantumruyPro(
                                          fontSize: 10,
                                          fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                                          color: isSelected ? Colors.white : (isDark ? Colors.white70 : AppTheme.textPrimary),
                                        ),
                                      ),
                                      selected: isSelected,
                                      selectedColor: const Color(0xFF0D9488),
                                      backgroundColor: isDark ? const Color(0xFF1E293B) : Colors.white,
                                      visualDensity: VisualDensity.compact,
                                      padding: const EdgeInsets.symmetric(horizontal: 4),
                                      shape: RoundedRectangleBorder(
                                        borderRadius: BorderRadius.circular(8),
                                        side: BorderSide(
                                          color: isSelected ? const Color(0xFF0D9488) : AppTheme.border,
                                        ),
                                      ),
                                      onSelected: (_) => reGenerateDocx(newMargin: m),
                                    ),
                                  );
                                }),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],

                  const SizedBox(height: 8),

                  // Main Content View
                  Expanded(
                    child: Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 20),
                      child: hasText
                          ? (activeTab == 0
                              ? _buildDocumentPreviewCard(
                                  currentText,
                                  isDark,
                                  paperSize: currentPaperSize,
                                  orientation: currentOrientation,
                                  isFitScreen: isFitScreen,
                                  photoFile: cvPhotoFile,
                                  originalScanImagePath: hasOriginalScan ? multiImagePaths.first : null,
                                  showOriginalLayout: showOriginalLayout,
                                  onToggleLayoutMode: hasOriginalScan
                                      ? () => setModalState(() => showOriginalLayout = !showOriginalLayout)
                                      : null,
                                  onPickPhoto: pickCvPhoto,
                                  onToggleFitScreen: () => setModalState(() => isFitScreen = !isFitScreen),
                                  onOpenFullScreen: openFullScreen,
                                )
                              : (hasOriginalScan && activeTab == 1
                                  ? _buildOriginalScanView(multiImagePaths.first, isDark)
                                  : Container(
                                      width: double.infinity,
                                      padding: const EdgeInsets.all(14),
                                      decoration: BoxDecoration(
                                        color: isDark ? const Color(0xFF0F172A) : const Color(0xFFF8FAFC),
                                        borderRadius: BorderRadius.circular(14),
                                        border: Border.all(color: AppTheme.border),
                                      ),
                                      child: SingleChildScrollView(
                                        child: SelectableText(
                                          currentText,
                                          style: GoogleFonts.kantumruyPro(
                                            color: isDark ? Colors.white : AppTheme.textPrimary,
                                            fontSize: 12.5,
                                            height: 1.6,
                                          ),
                                        ),
                                      ),
                                    )))
                          : Center(
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  Icon(
                                    isDocx ? Icons.description_rounded : Icons.picture_as_pdf_rounded,
                                    size: 54,
                                    color: isDocx ? const Color(0xFF2563EB) : const Color(0xFFE11D48),
                                  ),
                                  const SizedBox(height: 12),
                                  Text(
                                    currentFilePath?.split('/').last ?? 'ឯកសារបម្លែងរួចរាល់',
                                    textAlign: TextAlign.center,
                                    style: GoogleFonts.kantumruyPro(
                                      color: isDark ? Colors.white : AppTheme.textPrimary,
                                      fontSize: 14,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  const SizedBox(height: 4),
                                  Text(
                                    'ឯកសារត្រៀមរួចជាស្រេចសម្រាប់ការទាញយក ឬផ្ញើ',
                                    style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 12),
                                  ),
                                ],
                              ),
                            ),
                    ),
                  ),

                  // Bottom Action Buttons
                  SafeArea(
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(20, 12, 20, 16),
                      child: Row(
                        children: [

                          if (hasText) ...[
                            // Copy Text Button
                            IconButton.filledTonal(
                              tooltip: 'ចម្លងអត្ថបទ',
                              onPressed: () {
                                Clipboard.setData(ClipboardData(text: currentText));
                                _showToast('បានចម្លងអត្ថបទទៅ Clipboard');
                              },
                              icon: const Icon(Icons.copy_rounded, size: 18),
                              style: IconButton.styleFrom(
                                padding: const EdgeInsets.all(12),
                                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                              ),
                            ),
                            const SizedBox(width: 8),

                            // Quick Edit Button
                            OutlinedButton.icon(
                              onPressed: () async {
                                final edited = await _showEditTextDialog(
                                  context: ctx,
                                  initialText: currentText,
                                );
                                if (edited != null && edited.trim().isNotEmpty) {
                                  await reGenerateDocx(newContent: edited);
                                }
                              },
                              icon: const Icon(Icons.edit_note_rounded, size: 18),
                              label: Text(
                                'កែប្រែ',
                                style: GoogleFonts.kantumruyPro(fontSize: 12, fontWeight: FontWeight.w600),
                              ),
                              style: OutlinedButton.styleFrom(
                                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                                side: BorderSide(color: AppTheme.border),
                                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                              ),
                            ),
                            const SizedBox(width: 8),
                          ],

                          // Share / Open in Word Button
                          Expanded(
                            child: ElevatedButton.icon(
                              onPressed: () async {
                                if (currentFilePath != null) {
                                  await Share.shareXFiles(
                                    [XFile(currentFilePath!)],
                                    text: 'ឯកសារបម្លែងពី VVC Attendance',
                                  );
                                } else if (hasText) {
                                  await Share.share(currentText);
                                }
                              },
                              icon: const Icon(Icons.share_rounded, size: 17, color: Colors.white),
                              label: Text(
                                isDocx ? 'ចែករំលែក / បើកក្នុង Word' : 'ចែករំលែក / ផ្ញើ',
                                style: GoogleFonts.kantumruyPro(
                                  fontSize: 12.5,
                                  fontWeight: FontWeight.bold,
                                  color: Colors.white,
                                ),
                              ),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: isDocx ? const Color(0xFF2563EB) : const Color(0xFF0284C7),
                                padding: const EdgeInsets.symmetric(vertical: 12),
                                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                                elevation: 0,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }

  /// Helper widget to build Orientation selector pill
  Widget _buildOrientationPill({
    required String label,
    required IconData icon,
    required bool isSelected,
    required VoidCallback onTap,
    required bool isDark,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
        decoration: BoxDecoration(
          color: isSelected
              ? const Color(0xFF2563EB)
              : (isDark ? const Color(0xFF1E293B) : Colors.white),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: isSelected ? const Color(0xFF2563EB) : AppTheme.border,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              size: 13,
              color: isSelected ? Colors.white : (isDark ? Colors.white70 : AppTheme.textMuted),
            ),
            const SizedBox(width: 4),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                fontSize: 10,
                fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                color: isSelected ? Colors.white : (isDark ? Colors.white70 : AppTheme.textPrimary),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDocumentPreviewCard(
    String text,
    bool isDark, {
    DocxPaperSize paperSize = DocxPaperSize.a4,
    DocxPageOrientation orientation = DocxPageOrientation.portrait,
    bool isFitScreen = true,
    File? photoFile,
    String? originalScanImagePath,
    bool showOriginalLayout = true,
    VoidCallback? onToggleLayoutMode,
    VoidCallback? onPickPhoto,
    VoidCallback? onToggleFitScreen,
    VoidCallback? onOpenFullScreen,
  }) {
    final isLandscape = orientation == DocxPageOrientation.landscape;
    final paperWidth = isLandscape ? 877.0 : 620.0;
    final isCv = text.contains('ប្រវត្តិរូបសង្ខេប') ||
        text.toUpperCase().contains('CURRICULUM VITAE') ||
        text.toUpperCase().contains('RESUME');

    final isShowingAuthentic = showOriginalLayout &&
        originalScanImagePath != null &&
        File(originalScanImagePath).existsSync();

    final paperContent = isShowingAuthentic
        ? Container(
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(6),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: isDark ? 0.4 : 0.15),
                  blurRadius: 16,
                  offset: const Offset(0, 5),
                ),
              ],
              border: Border.all(
                color: isDark ? const Color(0xFF334155) : const Color(0xFFCBD5E1),
                width: 1.2,
              ),
            ),
            clipBehavior: Clip.antiAlias,
            child: Image.file(
              File(originalScanImagePath),
              fit: BoxFit.contain,
            ),
          )
        : _buildA4PaperContent(
            text,
            isDark,
            paperSize: paperSize,
            orientation: orientation,
            photoFile: photoFile,
            onPickPhoto: onPickPhoto,
          );

    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF0F172A) : const Color(0xFFF1F5F9),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: AppTheme.border),
      ),
      child: Column(
        children: [
          // Top Control Toolbar for Document Preview
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
            decoration: BoxDecoration(
              color: isDark ? const Color(0xFF1E293B) : Colors.white,
              borderRadius: const BorderRadius.vertical(top: Radius.circular(14)),
              border: Border(bottom: BorderSide(color: AppTheme.border.withValues(alpha: 0.6))),
            ),
            child: Row(
              children: [
                // Mode 1: Fit Screen
                InkWell(
                  onTap: () {
                    if (!isFitScreen && onToggleFitScreen != null) onToggleFitScreen();
                  },
                  borderRadius: BorderRadius.circular(7),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: isFitScreen
                          ? const Color(0xFF2563EB)
                          : (isDark ? const Color(0xFF0F172A) : const Color(0xFFF1F5F9)),
                      borderRadius: BorderRadius.circular(7),
                      border: Border.all(
                        color: isFitScreen ? const Color(0xFF2563EB) : AppTheme.border,
                      ),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.fit_screen_rounded,
                          size: 13,
                          color: isFitScreen ? Colors.white : AppTheme.textMuted,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          'សមស្របអេក្រង់',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 10.5,
                            fontWeight: isFitScreen ? FontWeight.bold : FontWeight.w500,
                            color: isFitScreen ? Colors.white : (isDark ? Colors.white70 : AppTheme.textPrimary),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(width: 6),

                // Mode 2: True A4 (Pinch-to-zoom)
                InkWell(
                  onTap: () {
                    if (isFitScreen && onToggleFitScreen != null) onToggleFitScreen();
                  },
                  borderRadius: BorderRadius.circular(7),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: !isFitScreen
                          ? const Color(0xFF2563EB)
                          : (isDark ? const Color(0xFF0F172A) : const Color(0xFFF1F5F9)),
                      borderRadius: BorderRadius.circular(7),
                      border: Border.all(
                        color: !isFitScreen ? const Color(0xFF2563EB) : AppTheme.border,
                      ),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.zoom_in_rounded,
                          size: 13,
                          color: !isFitScreen ? Colors.white : AppTheme.textMuted,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          'ក្រដាស A4 ពិត (Zoom)',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 10.5,
                            fontWeight: !isFitScreen ? FontWeight.bold : FontWeight.w500,
                            color: !isFitScreen ? Colors.white : (isDark ? Colors.white70 : AppTheme.textPrimary),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),

                // Mode 3: Genuine Layout vs Editable Text (Only if original scan is available)
                if (originalScanImagePath != null && onToggleLayoutMode != null) ...[
                  const SizedBox(width: 6),
                  InkWell(
                    onTap: onToggleLayoutMode,
                    borderRadius: BorderRadius.circular(7),
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                      decoration: BoxDecoration(
                        color: showOriginalLayout
                            ? const Color(0xFF10B981)
                            : (isDark ? const Color(0xFF0F172A) : const Color(0xFFF1F5F9)),
                        borderRadius: BorderRadius.circular(7),
                        border: Border.all(
                          color: showOriginalLayout ? const Color(0xFF10B981) : AppTheme.border,
                        ),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            showOriginalLayout ? Icons.auto_awesome_rounded : Icons.edit_note_rounded,
                            size: 13,
                            color: showOriginalLayout ? Colors.white : AppTheme.textMuted,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            showOriginalLayout ? 'ប្លង់ដើម ១០០%' : 'ទម្រង់អត្ថបទ',
                            style: GoogleFonts.kantumruyPro(
                              fontSize: 10.5,
                              fontWeight: FontWeight.bold,
                              color: showOriginalLayout
                                  ? Colors.white
                                  : (isDark ? Colors.white70 : AppTheme.textPrimary),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],

                const Spacer(),

                // Add Photo Button (for CV)
                if (isCv && onPickPhoto != null) ...[
                  IconButton(
                    tooltip: 'ជ្រើសរើសរូបថត 3x4',
                    icon: Icon(
                      photoFile != null ? Icons.photo_camera_rounded : Icons.add_a_photo_rounded,
                      size: 16,
                      color: photoFile != null ? const Color(0xFF10B981) : const Color(0xFF2563EB),
                    ),
                    visualDensity: VisualDensity.compact,
                    onPressed: onPickPhoto,
                  ),
                ],

                // Fullscreen Button
                if (onOpenFullScreen != null) ...[
                  IconButton(
                    tooltip: 'មើលពេញអេក្រង់ (Full Screen)',
                    icon: const Icon(
                      Icons.open_in_full_rounded,
                      size: 15,
                      color: Color(0xFF2563EB),
                    ),
                    visualDensity: VisualDensity.compact,
                    onPressed: onOpenFullScreen,
                  ),
                ],
              ],
            ),
          ),

          // Main Viewport (Fit Screen with FittedBox vs Full 1:1 with InteractiveViewer)
          Expanded(
            child: isFitScreen
                ? LayoutBuilder(
                    builder: (layoutCtx, constraints) {
                      return SingleChildScrollView(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                        physics: const BouncingScrollPhysics(),
                        child: Center(
                          child: FittedBox(
                            fit: BoxFit.contain,
                            alignment: Alignment.topCenter,
                            child: SizedBox(
                              width: paperWidth,
                              child: paperContent,
                            ),
                          ),
                        ),
                      );
                    },
                  )
                : Stack(
                    children: [
                      InteractiveViewer(
                        minScale: 0.35,
                        maxScale: 3.5,
                        boundaryMargin: const EdgeInsets.symmetric(horizontal: 40, vertical: 80),
                        constrained: false,
                        child: Center(
                          child: Padding(
                            padding: const EdgeInsets.all(12),
                            child: SizedBox(
                              width: paperWidth,
                              child: paperContent,
                            ),
                          ),
                        ),
                      ),
                      Positioned(
                        bottom: 10,
                        right: 12,
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4.5),
                          decoration: BoxDecoration(
                            color: Colors.black.withValues(alpha: 0.75),
                            borderRadius: BorderRadius.circular(20),
                            boxShadow: [
                              BoxShadow(color: Colors.black.withValues(alpha: 0.2), blurRadius: 4),
                            ],
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const Icon(Icons.pinch_rounded, size: 12, color: Colors.white70),
                              const SizedBox(width: 4),
                              Text(
                                'Pinch ដើម្បីពង្រីក/បង្រួម',
                                style: GoogleFonts.kantumruyPro(fontSize: 10, color: Colors.white),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
          ),
        ],
      ),
    );
  }

  /// Builds the full-dimensioned authentic A4 paper sheet
  Widget _buildA4PaperContent(
    String text,
    bool isDark, {
    DocxPaperSize paperSize = DocxPaperSize.a4,
    DocxPageOrientation orientation = DocxPageOrientation.portrait,
    File? photoFile,
    VoidCallback? onPickPhoto,
  }) {
    final normalizedText = PdfToWordMicroservice.normalizeExtractedCvText(text);
    final lines = normalizedText.split('\n');
    final isLandscape = orientation == DocxPageOrientation.landscape;
    final isCv = normalizedText.contains('ប្រវត្តិរូបសង្ខេប') ||
        normalizedText.toUpperCase().contains('CURRICULUM VITAE') ||
        normalizedText.toUpperCase().contains('RESUME');

    return Container(
      padding: EdgeInsets.fromLTRB(isLandscape ? 32 : 28, 26, isLandscape ? 32 : 28, 30),
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF1E293B) : Colors.white,
        borderRadius: BorderRadius.circular(8),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.12),
            blurRadius: 16,
            offset: const Offset(0, 5),
          ),
        ],
        border: Border.all(
          color: isDark ? const Color(0xFF334155) : const Color(0xFFCBD5E1),
          width: 1.2,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Dynamic Paper watermark / header banner
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: const Color(0xFF2563EB).withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.description_rounded, size: 12, color: Color(0xFF2563EB)),
                    const SizedBox(width: 4),
                    Text(
                      '${paperSize.name} • ${isLandscape ? "ផ្តេក (Landscape)" : "បញ្ឈរ (Portrait)"}',
                      style: GoogleFonts.kantumruyPro(
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                        color: const Color(0xFF2563EB),
                      ),
                    ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: const Color(0xFF10B981).withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.auto_awesome, size: 12, color: Color(0xFF10B981)),
                    const SizedBox(width: 4),
                    Text(
                      'ទម្រង់ក្រដាសពិត ១០០%',
                      style: GoogleFonts.kantumruyPro(
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                        color: const Color(0xFF10B981),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const Divider(height: 20),
          if (isCv) ...[
            Container(
              height: 3.5,
              width: double.infinity,
              margin: const EdgeInsets.only(bottom: 10),
              decoration: BoxDecoration(
                color: const Color(0xFF0E3B66),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ],

          // Document Body Elements (Matches 1-page Word sheet)
          ..._buildPreviewElements(lines, isDark, photoFile: photoFile, onPickPhoto: onPickPhoto),
        ],
      ),
    );
  }

  List<Widget> _buildPreviewElements(
    List<String> lines,
    bool isDark, {
    File? photoFile,
    VoidCallback? onPickPhoto,
  }) {
    final bodyWidgets = <Widget>[];
    int idx = 0;
    bool hasEmittedFooterLine = false;
    final isCv = lines.any((l) =>
        l.contains('ប្រវត្តិរូបសង្ខេប') ||
        l.toUpperCase().contains('CURRICULUM VITAE') ||
        l.toUpperCase().contains('RESUME'));

    while (idx < lines.length) {
      final rawLine = lines[idx];
      final trimmed = rawLine.trim();

      if (trimmed.isEmpty) {
        idx++;
        continue;
      }

      // 1. Detect consecutive Markdown Table lines (| col1 | col2 |)
      if (trimmed.startsWith('|') && trimmed.endsWith('|') && trimmed.contains('|')) {
        final tableLines = <String>[];
        while (idx < lines.length && lines[idx].trim().startsWith('|') && lines[idx].trim().endsWith('|')) {
          tableLines.add(lines[idx].trim());
          idx++;
        }
        bodyWidgets.add(_buildPreviewTableWidget(tableLines, isDark));
        continue;
      }

      // 2. Explicit Divider (--- or ___)
      if (trimmed == '---' || trimmed == '___' || RegExp(r'^-{3,}$').hasMatch(trimmed)) {
        if (isCv) {
          bodyWidgets.add(_buildNavyDividerLine());
        } else {
          bodyWidgets.add(_buildGoldenDividerLine());
        }
        idx++;
        continue;
      }

      // 3. Section Banners (CV Category Bars: ព័ត៌មានផ្ទាល់ខ្លួន, ប្រវត្តិសិក្សា, ប្រវត្តិការងារ, ជំនាញ...)
      if (_isSectionBanner(trimmed)) {
        bodyWidgets.add(_buildSectionBannerWidget(trimmed, isDark));
        idx++;
        continue;
      }

      // 4. CV / Resume Main Title & Header Profile with Photo Frame
      final cleanTitleCheck = trimmed.replaceAll(RegExp(r'[\u200B-\u200D\uFEFF]'), '');
      if (cleanTitleCheck.contains('ប្រវត្តិរូបសង្ខេប') ||
          cleanTitleCheck.contains('ប្រវត្តិរូប') ||
          cleanTitleCheck.toUpperCase().contains('CURRICULUM VITAE') ||
          cleanTitleCheck.toUpperCase().contains('RESUME')) {
        final cleanTitle = trimmed.replaceAll(RegExp(r'^#+\s*'), '').trim();
        bodyWidgets.add(
          Padding(
            padding: const EdgeInsets.only(top: 4, bottom: 6),
            child: Text(
              cleanTitle,
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                fontSize: 16.5,
                fontWeight: FontWeight.bold,
                letterSpacing: 0.8,
                color: isDark ? Colors.white : const Color(0xFF0F172A),
              ),
            ),
          ),
        );
        idx++;

        // Collect subsequent contact lines before first section banner or divider
        final contactLines = <String>[];
        while (idx < lines.length) {
          final nextTrimmed = lines[idx].trim();
          if (nextTrimmed.isEmpty) {
            idx++;
            continue;
          }
          if (_isSectionBanner(nextTrimmed) ||
              nextTrimmed.startsWith('|') ||
              nextTrimmed == '---' ||
              nextTrimmed == '___' ||
              RegExp(r'^[-*•]\s+').hasMatch(nextTrimmed)) {
            break;
          }
          contactLines.add(nextTrimmed);
          idx++;
        }

        final headerContact = <String>[];
        final extraPersonal = <String>[];

        for (final line in contactLines) {
          final lTrim = line.replaceAll('[PHOTO]', '').trim();
          if (lTrim.isEmpty) continue;

          final isHeaderField = lTrim.contains('នាម-គោត្តនាម') ||
              lTrim.contains('អាសយដ្ឋាន') ||
              lTrim.contains('ទូរស័ព្ទ') ||
              lTrim.contains('Telegram') ||
              lTrim.contains('@') ||
              lTrim.contains('Email') ||
              (headerContact.length < 3 &&
                  !lTrim.contains('ភេទ') &&
                  !lTrim.contains('សញ្ជាតិ') &&
                  !lTrim.contains('កំណើត'));

          if (isHeaderField && extraPersonal.isEmpty) {
            headerContact.add(lTrim);
          } else {
            extraPersonal.add(lTrim);
          }
        }

        if (headerContact.isNotEmpty) {
          bodyWidgets.add(_buildCvHeaderWidget(
            headerContact,
            isDark,
            photoFile: photoFile,
            onPickPhoto: onPickPhoto,
          ));
          bodyWidgets.add(_buildNavyDividerLine());
        }

        if (extraPersonal.isNotEmpty) {
          bodyWidgets.add(_buildSectionBannerWidget('ព័ត៌មានផ្ទាល់ខ្លួននិងទីកន្លែងរស់នៅ', isDark));
          for (final item in extraPersonal) {
            bodyWidgets.add(_buildBulletItemWidget(item, isDark));
          }
        }
        continue;
      }

      // 5. Bullet or List items (*, -, •)
      if (RegExp(r'^[-*•]\s+').hasMatch(trimmed)) {
        bodyWidgets.add(_buildBulletItemWidget(trimmed, isDark));
        idx++;
        continue;
      }

      // 6. Centered Company Title with Golden Header Line
      if (trimmed.toUpperCase().contains('VAN VAN CAMBODIA') ||
          trimmed.contains('វ៉ាន់ វ៉ាន់ ខេមបូឌា')) {
        bodyWidgets.add(
          Padding(
            padding: const EdgeInsets.only(top: 4, bottom: 2),
            child: Text(
              trimmed,
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                fontSize: 14.5,
                fontWeight: FontWeight.bold,
                letterSpacing: 0.8,
                color: isDark ? Colors.white : const Color(0xFF0F172A),
              ),
            ),
          ),
        );
        bodyWidgets.add(_buildGoldenDividerLine());
        idx++;
        continue;
      }

      // 7. Centered Document Titles / Subtitles
      if (trimmed.contains('ព្រះរាជាណាចក្រកម្ពុជា') ||
          trimmed.contains('ជាតិ សាសនា ព្រះមហាក្សត្រ') ||
          trimmed.contains('APPLICATION FOR LEAVE') ||
          trimmed.contains('ពាក្យសុំច្បាប់ឈប់សម្រាក') ||
          trimmed.contains('ពាក្យសុំច្បាប់របស់បុគ្គលិក') ||
          trimmed.contains('សំណុំបែបបទស្នើសុំ') ||
          trimmed.startsWith('# ')) {
        final display = trimmed.startsWith('# ') ? trimmed.substring(2) : trimmed;
        final isMainTitle = display.contains('ពាក្យសុំច្បាប់') || display.contains('APPLICATION');
        bodyWidgets.add(
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 3),
            child: Text(
              display,
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                fontSize: isMainTitle ? 14 : 11.5,
                fontWeight: isMainTitle ? FontWeight.bold : FontWeight.w600,
                color: isDark
                    ? (isMainTitle ? Colors.white : Colors.white70)
                    : (isMainTitle ? const Color(0xFF0F172A) : const Color(0xFF334155)),
              ),
            ),
          ),
        );
        idx++;
        continue;
      }

      // 8. Checkboxes ([x], [ ], ☑, ☐) - Grouped into compact pills
      if (RegExp(r'^\s*(\[[ xX]\]|[☑☐])\s*').hasMatch(trimmed)) {
        final checkboxGroup = <Map<String, dynamic>>[];
        while (idx < lines.length && RegExp(r'^\s*(\[[ xX]\]|[☑☐])\s*').hasMatch(lines[idx].trim())) {
          final cLine = lines[idx].trim();
          final isChecked = cLine.contains('[x]') || cLine.contains('[X]') || cLine.contains('☑');
          final itemText = cLine.replaceFirst(RegExp(r'^\s*(\[[ xX]\]|[☑☐])\s*'), '').trim();
          checkboxGroup.add({'text': itemText, 'isChecked': isChecked});
          idx++;
        }
        bodyWidgets.add(_buildCompactCheckboxPills(checkboxGroup, isDark));
        continue;
      }

      // 9. Footer Address & Contact Info with Golden Footer Line
      if (trimmed.contains('ផ្ទះលេខ') ||
          trimmed.contains('No.1AEo') ||
          trimmed.contains('Sangkat Tuol Svay') ||
          trimmed.contains('សង្កាត់ទួលស្វាយព្រៃ') ||
          trimmed.contains('No.030') ||
          (trimmed.contains('ទូរស័ព្ទ:') && trimmed.length > 25)) {
        if (!hasEmittedFooterLine) {
          bodyWidgets.add(_buildGoldenDividerLine(topMargin: 12));
          hasEmittedFooterLine = true;
        }
        bodyWidgets.add(
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 2),
            child: Text(
              trimmed,
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                fontSize: 10,
                fontWeight: FontWeight.w500,
                color: isDark ? const Color(0xFFF59E0B) : const Color(0xFFB45309),
                height: 1.4,
              ),
            ),
          ),
        );
        idx++;
        continue;
      }

      // 10. Multi-column lines (Signatures or wide spaces)
      final multiCols = trimmed.split(RegExp(r'\s{3,}|\t+')).where((c) => c.trim().isNotEmpty).toList();
      if (multiCols.length >= 2 && !trimmed.startsWith('|')) {
        bodyWidgets.add(
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 4),
            child: Row(
              children: multiCols.map((c) {
                return Expanded(
                  child: Container(
                    margin: const EdgeInsets.symmetric(horizontal: 4),
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    alignment: Alignment.center,
                    child: Text(
                      c,
                      textAlign: TextAlign.center,
                      style: GoogleFonts.kantumruyPro(
                        fontSize: 10.5,
                        fontWeight: c.contains('(') || c.contains('Verified') || c.contains('Requested')
                            ? FontWeight.bold
                            : FontWeight.normal,
                        color: isDark ? Colors.white : AppTheme.textPrimary,
                      ),
                    ),
                  ),
                );
              }).toList(),
            ),
          ),
        );
        idx++;
        continue;
      }

      // 11. Key-Value pairs (Label: Value)
      if (trimmed.contains(': ') || trimmed.contains(' : ') || trimmed.contains('៖ ')) {
        if (isCv) {
          bodyWidgets.add(_buildBulletItemWidget(trimmed, isDark));
        } else {
          final delim = trimmed.contains(' : ') ? ' : ' : (trimmed.contains('៖ ') ? '៖ ' : ': ');
          final parts = trimmed.split(delim);
          final label = parts[0];
          final val = parts.sublist(1).join(delim);

          bodyWidgets.add(
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 2),
              child: RichText(
                text: TextSpan(
                  children: [
                    TextSpan(
                      text: '$label$delim',
                      style: GoogleFonts.kantumruyPro(
                        fontSize: 11.5,
                        fontWeight: FontWeight.bold,
                        color: isDark ? Colors.white : const Color(0xFF0F172A),
                      ),
                    ),
                    TextSpan(
                      text: val,
                      style: GoogleFonts.kantumruyPro(
                        fontSize: 11.5,
                        fontWeight: FontWeight.w500,
                        color: isDark ? const Color(0xFF93C5FD) : const Color(0xFF1E40AF),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          );
        }
        idx++;
        continue;
      }

      // 12. Section headings (**Title**)
      if (trimmed.startsWith('**') && trimmed.endsWith('**')) {
        final heading = trimmed.substring(2, trimmed.length - 2);
        bodyWidgets.add(
          Padding(
            padding: const EdgeInsets.only(top: 6, bottom: 3),
            child: Text(
              heading,
              style: GoogleFonts.kantumruyPro(
                fontSize: 12,
                fontWeight: FontWeight.bold,
                color: isDark ? Colors.white : const Color(0xFF0F172A),
              ),
            ),
          ),
        );
        idx++;
        continue;
      }

      // 13. Regular text
      bodyWidgets.add(
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 2),
          child: Text(
            trimmed,
            style: GoogleFonts.kantumruyPro(
              fontSize: 11.5,
              color: isDark ? Colors.white70 : AppTheme.textPrimary,
              height: 1.45,
            ),
          ),
        ),
      );
      idx++;
    }

    return bodyWidgets;
  }

  /// Builds a golden decorative divider line (Header & Footer lines)
  Widget _buildGoldenDividerLine({double topMargin = 6, double bottomMargin = 6}) {
    return Container(
      margin: EdgeInsets.only(top: topMargin, bottom: bottomMargin),
      height: 2.2,
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [
            Color(0xFFB45309),
            Color(0xFFF59E0B),
            Color(0xFFFDE68A),
            Color(0xFFF59E0B),
            Color(0xFFB45309),
          ],
        ),
        borderRadius: BorderRadius.circular(1.5),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFFD97706).withValues(alpha: 0.3),
            blurRadius: 3,
            offset: const Offset(0, 1),
          ),
        ],
      ),
    );
  }

  /// Builds a dark navy divider line for CVs (#184E77)
  Widget _buildNavyDividerLine({double topMargin = 6, double bottomMargin = 8}) {
    return Container(
      margin: EdgeInsets.only(top: topMargin, bottom: bottomMargin),
      height: 1.8,
      decoration: BoxDecoration(
        color: const Color(0xFF184E77),
        borderRadius: BorderRadius.circular(1),
      ),
    );
  }

  /// Check if a line is a Section Banner Heading (CV categories, official headings)
  bool _isSectionBanner(String trimmed) {
    if (trimmed.contains('[BANNER]')) return true;
    final clean = trimmed
        .replaceAll(RegExp(r'[\u200B-\u200D\uFEFF]'), '')
        .replaceAll(RegExp(r'^#+\s*'), '')
        .replaceAll(RegExp(r'\[BANNER\]', caseSensitive: false), '')
        .trim();
    if (clean.isEmpty) return false;
    final lower = clean.toLowerCase();
    return lower.contains('ព័ត៌មាន') ||
        lower.contains('ផ្ទាល់ខ្លួន') ||
        lower.contains('ជីវប្រវត្តិ') ||
        lower.contains('ប្រវត្តិសិក្សា') ||
        lower.contains('កម្រិតសិក្សា') ||
        lower.contains('ប្រវត្តិការងារ') ||
        lower.contains('ប្រវត្តការងារ') ||
        lower.contains('បទពិសោធន៍') ||
        lower.contains('ជំនាញ') ||
        lower.contains('ចំណេះដឹង') ||
        lower.contains('ភាសាបរទេស') ||
        lower.contains('សេចក្តីបញ្ជាក់') ||
        lower.contains('personal') ||
        lower.contains('education') ||
        lower.contains('experience') ||
        lower.contains('skills') ||
        lower.contains('languages') ||
        lower.contains('references');
  }

  /// Builds a solid Navy Blue Section Banner with bold white text
  Widget _buildSectionBannerWidget(String title, bool isDark) {
    final cleanTitle = title
        .replaceAll(RegExp(r'^#+\s*'), '')
        .replaceAll(RegExp(r'\[BANNER\]', caseSensitive: false), '')
        .trim();

    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(top: 10, bottom: 6),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: const Color(0xFF184E77),
        borderRadius: BorderRadius.circular(4),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF184E77).withValues(alpha: 0.25),
            blurRadius: 3,
            offset: const Offset(0, 1),
          ),
        ],
      ),
      child: Text(
        cleanTitle,
        style: GoogleFonts.kantumruyPro(
          fontSize: 12,
          fontWeight: FontWeight.bold,
          color: Colors.white,
          letterSpacing: 0.3,
        ),
      ),
    );
  }

  /// Builds a 2-column CV Header (Left: Contact Info, Right: 3x4 Passport Photo Frame)
  Widget _buildCvHeaderWidget(
    List<String> contactLines,
    bool isDark, {
    File? photoFile,
    VoidCallback? onPickPhoto,
  }) {
    final displayLines = contactLines
        .where((l) => !l.toUpperCase().contains('[PHOTO]'))
        .toList();

    return Padding(
      padding: const EdgeInsets.only(top: 4, bottom: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Left Column: Contact details (Expanded)
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: displayLines.map((line) {
                final trimmed = line.trim();
                if (trimmed.isEmpty) return const SizedBox.shrink();

                if (trimmed.contains(': ') || trimmed.contains(' : ') || trimmed.contains('៖ ')) {
                  final delim = trimmed.contains(' : ') ? ' : ' : (trimmed.contains('៖ ') ? '៖ ' : ': ');
                  final parts = trimmed.split(delim);
                  final key = parts[0].trim();
                  final val = parts.sublist(1).join(delim).trim();
                  final isTelegram = val.contains('@') || val.toLowerCase().contains('telegram');

                  return Padding(
                    padding: const EdgeInsets.symmetric(vertical: 3),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        SizedBox(
                          width: 110,
                          child: Text(
                            key,
                            style: GoogleFonts.kantumruyPro(
                              fontSize: 11.5,
                              fontWeight: FontWeight.bold,
                              color: isDark ? Colors.white : const Color(0xFF0F172A),
                            ),
                          ),
                        ),
                        Text(
                          ':   ',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 11.5,
                            fontWeight: FontWeight.bold,
                            color: isDark ? Colors.white70 : const Color(0xFF334155),
                          ),
                        ),
                        Expanded(
                          child: Row(
                            children: [
                              Flexible(
                                child: Text(
                                  val,
                                  style: GoogleFonts.kantumruyPro(
                                    fontSize: 11.5,
                                    fontWeight: FontWeight.w600,
                                    color: isDark ? const Color(0xFF93C5FD) : const Color(0xFF1E40AF),
                                    height: 1.35,
                                  ),
                                ),
                              ),
                              if (isTelegram) ...[
                                const SizedBox(width: 5),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1.5),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF0284C7).withValues(alpha: 0.15),
                                    borderRadius: BorderRadius.circular(4),
                                    border: Border.all(color: const Color(0xFF0284C7).withValues(alpha: 0.3)),
                                  ),
                                  child: Row(
                                    mainAxisSize: MainAxisSize.min,
                                    children: [
                                      const Icon(Icons.send_rounded, size: 10, color: Color(0xFF0284C7)),
                                      const SizedBox(width: 3),
                                      Text(
                                        'Telegram',
                                        style: GoogleFonts.kantumruyPro(
                                          fontSize: 9,
                                          fontWeight: FontWeight.bold,
                                          color: const Color(0xFF0284C7),
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ],
                            ],
                          ),
                        ),
                      ],
                    ),
                  );
                }

                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 2.5),
                  child: Text(
                    trimmed,
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 11.5,
                      fontWeight: FontWeight.w500,
                      color: isDark ? Colors.white70 : AppTheme.textPrimary,
                    ),
                  ),
                );
              }).toList(),
            ),
          ),

          const SizedBox(width: 14),

          // Right Column: 3x4 Passport Photo Frame (Matches Image 1)
          GestureDetector(
            onTap: onPickPhoto,
            child: Container(
              width: 88,
              height: 118,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: const Color(0xFF184E77), width: 1.5),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.15),
                    blurRadius: 6,
                    offset: const Offset(0, 2),
                  ),
                ],
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(3),
                child: photoFile != null
                    ? Stack(
                        fit: StackFit.expand,
                        children: [
                          Image.file(photoFile, fit: BoxFit.cover),
                          Positioned(
                            bottom: 0,
                            left: 0,
                            right: 0,
                            child: Container(
                              padding: const EdgeInsets.symmetric(vertical: 2),
                              color: Colors.black.withValues(alpha: 0.6),
                              child: Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  const Icon(Icons.photo_camera_rounded, size: 10, color: Colors.white),
                                  const SizedBox(width: 3),
                                  Text(
                                    'ប្តូររូប',
                                    style: GoogleFonts.kantumruyPro(
                                      fontSize: 8.5,
                                      fontWeight: FontWeight.bold,
                                      color: Colors.white,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ],
                      )
                    : Container(
                        decoration: const BoxDecoration(
                          gradient: LinearGradient(
                            begin: Alignment.topCenter,
                            end: Alignment.bottomCenter,
                            colors: [
                              Color(0xFF1E3A8A),
                              Color(0xFF184E77),
                              Color(0xFF0F172A),
                            ],
                          ),
                        ),
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            const Icon(
                              Icons.person_rounded,
                              size: 40,
                              color: Colors.white,
                            ),
                            const SizedBox(height: 3),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1.5),
                              decoration: BoxDecoration(
                                color: Colors.white.withValues(alpha: 0.2),
                                borderRadius: BorderRadius.circular(3),
                              ),
                              child: Text(
                                'រូបថត 3x4',
                                style: GoogleFonts.kantumruyPro(
                                  fontSize: 9,
                                  fontWeight: FontWeight.bold,
                                  color: Colors.white,
                                ),
                              ),
                            ),
                            const SizedBox(height: 3),
                            Text(
                              '+ បញ្ចូលរូប',
                              style: GoogleFonts.kantumruyPro(
                                fontSize: 7.5,
                                fontWeight: FontWeight.w600,
                                color: const Color(0xFF93C5FD),
                              ),
                            ),
                          ],
                        ),
                      ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  /// Builds a cleanly aligned bullet item (• Key : Value) with generous A4 width
  Widget _buildBulletItemWidget(String text, bool isDark) {
    final clean = text.replaceFirst(RegExp(r'^[-*•]\s*'), '').trim();

    if (clean.contains(' : ') || clean.contains(': ') || clean.contains('៖ ')) {
      final delim = clean.contains(' : ') ? ' : ' : (clean.contains('៖ ') ? '៖ ' : ': ');
      final parts = clean.split(delim);
      final key = parts[0].trim();
      final val = parts.sublist(1).join(delim).trim();

      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 2.8, horizontal: 2),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              margin: const EdgeInsets.only(top: 6.5, right: 8),
              width: 5,
              height: 5,
              decoration: const BoxDecoration(
                color: Color(0xFF184E77),
                shape: BoxShape.circle,
              ),
            ),
            SizedBox(
              width: 125,
              child: Text(
                key,
                style: GoogleFonts.kantumruyPro(
                  fontSize: 11.5,
                  fontWeight: FontWeight.bold,
                  color: isDark ? Colors.white : const Color(0xFF0F172A),
                ),
              ),
            ),
            Text(
              ':   ',
              style: GoogleFonts.kantumruyPro(
                fontSize: 11.5,
                fontWeight: FontWeight.bold,
                color: isDark ? Colors.white70 : const Color(0xFF334155),
              ),
            ),
            Expanded(
              child: Text(
                val,
                style: GoogleFonts.kantumruyPro(
                  fontSize: 11.5,
                  fontWeight: FontWeight.w500,
                  color: isDark ? const Color(0xFF93C5FD) : const Color(0xFF1E293B),
                  height: 1.35,
                ),
              ),
            ),
          ],
        ),
      );
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2.8, horizontal: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            margin: const EdgeInsets.only(top: 6.5, right: 8),
            width: 5,
            height: 5,
            decoration: const BoxDecoration(
              color: Color(0xFF184E77),
              shape: BoxShape.circle,
            ),
          ),
          Expanded(
            child: Text(
              clean,
              style: GoogleFonts.kantumruyPro(
                fontSize: 11.5,
                fontWeight: FontWeight.w500,
                color: isDark ? Colors.white70 : AppTheme.textPrimary,
                height: 1.35,
              ),
            ),
          ),
        ],
      ),
    );
  }

  /// Displays the original scanned PDF image with interactive pinch-to-zoom
  Widget _buildOriginalScanView(String imagePath, bool isDark) {
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF0F172A) : const Color(0xFFF1F5F9),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: AppTheme.border),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(14),
        child: Stack(
          children: [
            InteractiveViewer(
              minScale: 0.5,
              maxScale: 4.0,
              boundaryMargin: const EdgeInsets.all(40),
              child: Center(
                child: SingleChildScrollView(
                  physics: const BouncingScrollPhysics(),
                  padding: const EdgeInsets.all(12),
                  child: Container(
                    decoration: BoxDecoration(
                      color: Colors.white, // Real white paper canvas so PDF text and colors display 100% accurately
                      borderRadius: BorderRadius.circular(6),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: isDark ? 0.4 : 0.15),
                          blurRadius: 12,
                          offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    clipBehavior: Clip.antiAlias,
                    child: Image.file(
                      File(imagePath),
                      fit: BoxFit.contain,
                    ),
                  ),
                ),
              ),
            ),
            Positioned(
              top: 10,
              right: 10,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.75),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.pinch_rounded, size: 13, color: Colors.white70),
                    const SizedBox(width: 4),
                    Text(
                      'Pinch-to-zoom ដើម្បីពង្រីកមើល',
                      style: GoogleFonts.kantumruyPro(fontSize: 10, color: Colors.white),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Builds compact multi-column checkbox pills to fit cleanly on a single page
  Widget _buildCompactCheckboxPills(List<Map<String, dynamic>> items, bool isDark) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Wrap(
        spacing: 6,
        runSpacing: 6,
        children: items.map((item) {
          final isChecked = item['isChecked'] as bool;
          final text = item['text'] as String;
          return Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
            decoration: BoxDecoration(
              color: isChecked
                  ? (isDark ? const Color(0xFF78350F).withValues(alpha: 0.35) : const Color(0xFFFEF3C7))
                  : (isDark ? const Color(0xFF1E293B) : const Color(0xFFF8FAFC)),
              borderRadius: BorderRadius.circular(6),
              border: Border.all(
                color: isChecked
                    ? const Color(0xFFD97706)
                    : (isDark ? const Color(0xFF334155) : const Color(0xFFE2E8F0)),
                width: isChecked ? 1.4 : 1,
              ),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  isChecked ? Icons.check_box_rounded : Icons.check_box_outline_blank_rounded,
                  size: 14,
                  color: isChecked
                      ? const Color(0xFFD97706)
                      : (isDark ? Colors.white38 : const Color(0xFF94A3B8)),
                ),
                const SizedBox(width: 5),
                Text(
                  text,
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 10.5,
                    fontWeight: isChecked ? FontWeight.bold : FontWeight.w500,
                    color: isChecked
                        ? (isDark ? const Color(0xFFFDE68A) : const Color(0xFF92400E))
                        : (isDark ? Colors.white70 : const Color(0xFF334155)),
                  ),
                ),
                if (isChecked) ...[
                  const SizedBox(width: 4),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                    decoration: BoxDecoration(
                      color: const Color(0xFFD97706),
                      borderRadius: BorderRadius.circular(3),
                    ),
                    child: Text(
                      'ជ្រើសរើស',
                      style: GoogleFonts.kantumruyPro(
                        fontSize: 8,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                      ),
                    ),
                  ),
                ],
              ],
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _buildPreviewTableWidget(List<String> tableLines, bool isDark) {
    final rows = <List<String>>[];
    for (final line in tableLines) {
      if (RegExp(r'^\|[\s\-:|]+\|$').hasMatch(line)) continue;
      final raw = line.split('|');
      if (raw.length >= 2) {
        final cells = raw.sublist(1, raw.length - 1).map((c) => c.trim()).toList();
        if (cells.isNotEmpty) rows.add(cells);
      }
    }
    if (rows.isEmpty) return const SizedBox.shrink();

    final maxCols = rows.map((r) => r.length).reduce((a, b) => a > b ? a : b);

    return Container(
      margin: const EdgeInsets.symmetric(vertical: 6),
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF0F172A) : Colors.white,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(
          color: isDark ? const Color(0xFF475569) : const Color(0xFF0F172A),
          width: 1.1,
        ),
      ),
      child: Table(
        border: TableBorder.all(
          color: isDark ? const Color(0xFF334155) : const Color(0xFFCBD5E1),
          width: 0.8,
        ),
        columnWidths: {
          for (int c = 0; c < maxCols; c++) c: const FlexColumnWidth(),
        },
        children: rows.map((r) {
          final isHeaderRow = r == rows.first;
          return TableRow(
            decoration: BoxDecoration(
              color: isHeaderRow
                  ? (isDark ? const Color(0xFF78350F).withValues(alpha: 0.3) : const Color(0xFFFEF3C7))
                  : Colors.transparent,
            ),
            children: List.generate(maxCols, (colIdx) {
              final text = colIdx < r.length ? r[colIdx] : '';
              final isKey = isHeaderRow ||
                  text.contains('៖') ||
                  text.contains(':') ||
                  text.contains('ឈ្មោះ') ||
                  text.contains('ផ្នែក') ||
                  text.contains('ថ្ងៃ') ||
                  text.contains('បញ្ជាក់') ||
                  text.contains('ហត្ថលេខា');
              return Container(
                color: (!isHeaderRow && isKey)
                    ? (isDark ? const Color(0xFF1E293B) : const Color(0xFFFEF9C3).withValues(alpha: 0.7))
                    : Colors.transparent,
                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 5),
                child: Text(
                  text,
                  textAlign: (isHeaderRow || text.contains('ថ្ងៃ') || text.contains(':00') || text.length <= 10)
                      ? TextAlign.center
                      : TextAlign.left,
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 10,
                    fontWeight: isKey ? FontWeight.bold : FontWeight.w500,
                    color: isDark ? Colors.white : const Color(0xFF0F172A),
                  ),
                ),
              );
            }),
          );
        }).toList(),
      ),
    );
  }

  /// Dialog to allow user to tweak extracted text before re-generating docx
  Future<String?> _showEditTextDialog({
    required BuildContext context,
    required String initialText,
  }) async {
    final controller = TextEditingController(text: initialText);
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;

    return await showDialog<String>(
      context: context,
      builder: (dlgCtx) {
        return AlertDialog(
          backgroundColor: isDark ? const Color(0xFF1E293B) : Colors.white,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
          title: Row(
            children: [
              const Icon(Icons.edit_note_rounded, color: Color(0xFF2563EB)),
              const SizedBox(width: 8),
              Text(
                'កែសម្រួលអត្ថបទឯកសារ',
                style: GoogleFonts.kantumruyPro(fontSize: 15, fontWeight: FontWeight.bold),
              ),
            ],
          ),
          content: SizedBox(
            width: double.maxFinite,
            height: 380,
            child: TextField(
              controller: controller,
              maxLines: null,
              expands: true,
              style: GoogleFonts.kantumruyPro(fontSize: 12.5, height: 1.5),
              decoration: InputDecoration(
                filled: true,
                fillColor: isDark ? const Color(0xFF0F172A) : const Color(0xFFF8FAFC),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide(color: AppTheme.border),
                ),
                hintText: 'បញ្ចូល ឬកែសម្រួលអត្ថបទនៅទីនេះ...',
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dlgCtx, null),
              child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted)),
            ),
            ElevatedButton(
              onPressed: () => Navigator.pop(dlgCtx, controller.text),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF2563EB),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
              child: Text(
                'រក្សាទុក & បង្កើត Word ឡើងវិញ',
                style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold),
              ),
            ),
          ],
        );
      },
    );
  }

  // ===========================================================================
  // BUILD MAIN UI
  // ===========================================================================

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;
    final topInset = MediaQuery.paddingOf(context).top;
    final headerTotalHeight = topInset + 60.0;

    return VvcLiquidGlassScaffold(
      showHeader: true,
      showTopTransitionZone: true,
      topTransitionZoneHeight: headerTotalHeight,
      alwaysShowTitle: true,
      alwaysShowGlass: true,
      backgroundColor: isDark ? const Color(0xFF0F172A) : const Color(0xFFF8FAFC),
      title: 'បំប្លែងឯកសារ & AI',
      leading: IconButton(
        icon: Icon(
          Icons.arrow_back_ios_new_rounded,
          size: 19,
          color: isDark ? Colors.white : AppTheme.textPrimary,
        ),
        onPressed: () => Navigator.pop(context),
      ),
      body: Stack(
        children: [
          CustomScrollView(
            physics: const BouncingScrollPhysics(),
            slivers: [
              // 0. Top spacing for floating liquid glass header
              SliverToBoxAdapter(
                child: SizedBox(height: headerTotalHeight + 6.0),
              ),

              // 1. Hero AI & Converter Banner
              SliverToBoxAdapter(
                child: _buildHeroBanner(isDark),
              ),

              // 2. Section: AI Gemini Khmer OCR
              SliverToBoxAdapter(
                child: _buildSectionHeader(
                  title: 'AI Gemini ស្កេនអក្សរខ្មែរ (Khmer AI Vision)',
                  subtitle: 'ស្គាល់គ្រប់ព្យញ្ជនៈ ស្រៈ ជើងអក្សរ និងតារាង មិនបាត់ទម្រង់ដើម',
                  badgeText: 'ឆ្លាតវៃខ្ពស់',
                  badgeColor: const Color(0xFF8B5CF6),
                  icon: Icons.auto_awesome_rounded,
                  isDark: isDark,
                ),
              ),
              SliverPadding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                sliver: SliverGrid.count(
                  crossAxisCount: 2,
                  mainAxisSpacing: 12,
                  crossAxisSpacing: 12,
                  childAspectRatio: 1.35,
                  children: [
                    _buildToolCard(
                      title: 'ស្កេនខ្មែរ -> Word (.docx)',
                      subtitle: 'បម្លែងទៅ Word រក្សាទម្រង់ដើម',
                      icon: Icons.description_rounded,
                      accentColor: const Color(0xFF7C3AED),
                      badge: 'ណែនាំ',
                      isDark: isDark,
                      onTap: () => _launchTool(ConverterTool.geminiKhmerDocx),
                    ),
                    _buildToolCard(
                      title: 'ស្កេនខ្មែរ -> អត្ថបទ (Text)',
                      subtitle: 'ស្រង់អត្ថបទ Copy ដាក់ Telegram',
                      icon: Icons.text_snippet_rounded,
                      accentColor: const Color(0xFF0284C7),
                      isDark: isDark,
                      onTap: () => _launchTool(ConverterTool.geminiKhmerText),
                    ),
                  ],
                ),
              ),

              const SliverToBoxAdapter(child: SizedBox(height: 18)),

              // 3. Section: Multi-Page Document Conversion
              SliverToBoxAdapter(
                child: _buildSectionHeader(
                  title: 'បំប្លែងឯកសារ (Document Conversion)',
                  subtitle: 'គាំទ្រ Multi-Page ច្រើនទំព័រទាំងអស់ក្នុងពេលតែមួយ',
                  badgeText: 'Multi-Page',
                  badgeColor: const Color(0xFF0284C7),
                  icon: Icons.transform_rounded,
                  isDark: isDark,
                ),
              ),
              SliverPadding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                sliver: SliverGrid.count(
                  crossAxisCount: 2,
                  mainAxisSpacing: 12,
                  crossAxisSpacing: 12,
                  childAspectRatio: 1.35,
                  children: [
                    _buildToolCard(
                      title: 'PDF ទៅជា Word (.docx)',
                      subtitle: 'បម្លែង PDF ច្រើនទំព័រទៅ Word',
                      icon: Icons.picture_as_pdf_rounded,
                      accentColor: const Color(0xFF2563EB),
                      isDark: isDark,
                      onTap: () => _launchTool(ConverterTool.pdfToWord),
                    ),
                    _buildToolCard(
                      title: 'Word ទៅជា PDF (.docx)',
                      subtitle: 'បម្លែង Word ទៅជា PDF ស្តង់ដារ',
                      icon: Icons.article_rounded,
                      accentColor: const Color(0xFF0D9488),
                      isDark: isDark,
                      onTap: () => _launchTool(ConverterTool.wordToPdf),
                    ),
                    _buildToolCard(
                      title: 'រូបភាព JPG ទៅ PDF',
                      subtitle: 'ពេញក្រដាស ១០០% គ្មានគែមស',
                      icon: Icons.photo_library_rounded,
                      accentColor: const Color(0xFFE11D48),
                      badge: 'ពេញក្រដាស',
                      isDark: isDark,
                      onTap: () => _launchTool(ConverterTool.imageToPdf),
                    ),
                    _buildToolCard(
                      title: 'PDF ទៅជារូបភាព JPG',
                      subtitle: 'ស្រង់គ្រប់ទំព័រជារូបភាព HD',
                      icon: Icons.image_rounded,
                      accentColor: const Color(0xFFD97706),
                      isDark: isDark,
                      onTap: () => _launchTool(ConverterTool.pdfToImage),
                    ),
                  ],
                ),
              ),

              const SliverToBoxAdapter(child: SizedBox(height: 18)),

              // 4. Section: Advanced PDF Utilities
              SliverToBoxAdapter(
                child: _buildSectionHeader(
                  title: 'ឧបករណ៍ PDF កម្រិតខ្ពស់ (PDF Utilities)',
                  subtitle: 'រៀបចំ ផ្គុំ និងកាត់បន្ថយទំហំឯកសារ',
                  icon: Icons.build_rounded,
                  isDark: isDark,
                ),
              ),
              SliverPadding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                sliver: SliverGrid.count(
                  crossAxisCount: 2,
                  mainAxisSpacing: 12,
                  crossAxisSpacing: 12,
                  childAspectRatio: 1.35,
                  children: [
                    _buildToolCard(
                      title: 'បញ្ចូល PDF ច្រើនចូលគ្នា',
                      subtitle: 'ផ្គុំឯកសារ PDF ច្រើនជាឯកសារតែមួយ',
                      icon: Icons.layers_rounded,
                      accentColor: const Color(0xFF10B981),
                      isDark: isDark,
                      onTap: () => _launchTool(ConverterTool.mergePdf),
                    ),
                    _buildToolCard(
                      title: 'បង្រួមទំហំ PDF (Compress)',
                      subtitle: 'កាត់បន្ថយ MB ងាយស្រួលផ្ញើតាម Chat',
                      icon: Icons.compress_rounded,
                      accentColor: const Color(0xFF6366F1),
                      isDark: isDark,
                      onTap: () => _launchTool(ConverterTool.compressPdf),
                    ),
                  ],
                ),
              ),

              const SliverToBoxAdapter(child: SizedBox(height: 40)),
            ],
          ),

          // Processing Loading Overlay
          if (_isProcessing)
            Container(
              color: Colors.black.withValues(alpha: 0.5),
              child: Center(
                child: Container(
                  margin: const EdgeInsets.symmetric(horizontal: 32),
                  padding: const EdgeInsets.all(24),
                  decoration: BoxDecoration(
                    color: isDark ? const Color(0xFF1E293B) : Colors.white,
                    borderRadius: BorderRadius.circular(20),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: 0.2),
                        blurRadius: 20,
                      ),
                    ],
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const CircularProgressIndicator(
                        valueColor: AlwaysStoppedAnimation<Color>(Color(0xFF0284C7)),
                      ),
                      const SizedBox(height: 18),
                      Text(
                        _progressMessage,
                        textAlign: TextAlign.center,
                        style: GoogleFonts.kantumruyPro(
                          color: isDark ? Colors.white : AppTheme.textPrimary,
                          fontSize: 13.5,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 12),
                      ClipRRect(
                        borderRadius: BorderRadius.circular(6),
                        child: LinearProgressIndicator(
                          value: _progressValue > 0 ? _progressValue : null,
                          backgroundColor: AppTheme.border,
                          valueColor: const AlwaysStoppedAnimation<Color>(Color(0xFF0284C7)),
                          minHeight: 6,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  // Hero Banner Widget
  Widget _buildHeroBanner(bool isDark) {
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(20),
        gradient: const LinearGradient(
          colors: [Color(0xFF4338CA), Color(0xFF2563EB)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF2563EB).withValues(alpha: 0.3),
            blurRadius: 14,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.2),
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.auto_awesome, color: Color(0xFFFDE047), size: 12),
                      const SizedBox(width: 4),
                      Text(
                        'បច្ចេកវិទ្យា AI Gemini Vision',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 10.5,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  'បំប្លែងឯកសារ & ស្កេនអក្សរខ្មែរ',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontSize: 16.5,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  'បម្លែង PDF, Word, រូបភាព Multi-Page និងស្គាល់ជើងអក្សរខ្មែរសុក្រឹត ១០០%',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white.withValues(alpha: 0.85),
                    fontSize: 11,
                    height: 1.35,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 12),
          Container(
            width: 58,
            height: 58,
            decoration: BoxDecoration(
              color: Colors.white.withValues(alpha: 0.15),
              shape: BoxShape.circle,
              border: Border.all(color: Colors.white.withValues(alpha: 0.3), width: 1.5),
            ),
            child: const Icon(Icons.document_scanner_rounded, color: Colors.white, size: 30),
          ),
        ],
      ),
    );
  }

  // Section Header Widget
  Widget _buildSectionHeader({
    required String title,
    required String subtitle,
    required IconData icon,
    String? badgeText,
    Color? badgeColor,
    required bool isDark,
  }) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(18, 6, 18, 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 17, color: badgeColor ?? const Color(0xFF0284C7)),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  title,
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? Colors.white : AppTheme.textPrimary,
                    fontSize: 13.5,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              if (badgeText != null && badgeColor != null)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                  decoration: BoxDecoration(
                    color: badgeColor.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: badgeColor.withValues(alpha: 0.3)),
                  ),
                  child: Text(
                    badgeText,
                    style: GoogleFonts.kantumruyPro(
                      color: badgeColor,
                      fontSize: 10,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 3),
          Text(
            subtitle,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textMuted,
              fontSize: 11,
            ),
          ),
        ],
      ),
    );
  }

  // Tool Card Widget
  Widget _buildToolCard({
    required String title,
    required String subtitle,
    required IconData icon,
    required Color accentColor,
    String? badge,
    required bool isDark,
    required VoidCallback onTap,
  }) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(16),
        child: Container(
          padding: const EdgeInsets.all(13),
          decoration: BoxDecoration(
            color: isDark ? const Color(0xFF1E293B) : AppTheme.bgCard,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: AppTheme.border.withValues(alpha: isDark ? 0.6 : 0.8),
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: isDark ? 0.2 : 0.03),
                blurRadius: 10,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Container(
                    width: 38,
                    height: 38,
                    decoration: BoxDecoration(
                      color: accentColor.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(11),
                    ),
                    child: Icon(icon, color: accentColor, size: 21),
                  ),
                  if (badge != null)
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: accentColor.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        badge,
                        style: GoogleFonts.kantumruyPro(
                          color: accentColor,
                          fontSize: 9.5,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                ],
              ),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: GoogleFonts.kantumruyPro(
                      color: isDark ? Colors.white : AppTheme.textPrimary,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    subtitle,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textMuted,
                      fontSize: 10,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Dedicated full-screen viewer for A4 Document with zoom, pan, rotation, and photo insertion
class A4DocumentFullscreenViewer extends StatefulWidget {
  final String initialText;
  final DocxPaperSize paperSize;
  final DocxPageOrientation orientation;
  final File? photoFile;
  final String? filePath;
  final VoidCallback? onPickPhoto;
  final Future<void> Function(String newText)? onSaveText;
  final Widget Function(
    String text,
    DocxPaperSize paperSize,
    DocxPageOrientation orientation,
    File? photoFile,
    VoidCallback? onPickPhoto,
  ) paperBuilder;

  const A4DocumentFullscreenViewer({
    super.key,
    required this.initialText,
    required this.paperSize,
    required this.orientation,
    required this.paperBuilder,
    this.photoFile,
    this.filePath,
    this.onPickPhoto,
    this.onSaveText,
  });

  @override
  State<A4DocumentFullscreenViewer> createState() => _A4DocumentFullscreenViewerState();
}

class _A4DocumentFullscreenViewerState extends State<A4DocumentFullscreenViewer> {
  late TransformationController _transformController;
  late DocxPageOrientation _orientation;
  late String _currentText;
  double _currentScale = 1.0;
  bool _isDarkDesk = true;

  @override
  void initState() {
    super.initState();
    _transformController = TransformationController();
    _orientation = widget.orientation;
    _currentText = widget.initialText;
    _transformController.addListener(_onTransformationChanged);
  }

  void _onTransformationChanged() {
    final scale = _transformController.value.getMaxScaleOnAxis();
    if ((scale - _currentScale).abs() > 0.05) {
      setState(() {
        _currentScale = scale;
      });
    }
  }

  @override
  void dispose() {
    _transformController.removeListener(_onTransformationChanged);
    _transformController.dispose();
    super.dispose();
  }

  void _zoomIn() {
    final newScale = (_currentScale * 1.25).clamp(0.4, 3.5);
    _transformController.value = Matrix4.diagonal3Values(newScale, newScale, 1.0);
  }

  void _zoomOut() {
    final newScale = (_currentScale / 1.25).clamp(0.4, 3.5);
    _transformController.value = Matrix4.diagonal3Values(newScale, newScale, 1.0);
  }

  void _resetZoom() {
    _transformController.value = Matrix4.identity();
  }

  void _toggleOrientation() {
    setState(() {
      _orientation = _orientation == DocxPageOrientation.portrait
          ? DocxPageOrientation.landscape
          : DocxPageOrientation.portrait;
    });
  }

  @override
  Widget build(BuildContext context) {
    final isLandscape = _orientation == DocxPageOrientation.landscape;
    final paperWidth = isLandscape ? 877.0 : 620.0;

    return Scaffold(
      backgroundColor: _isDarkDesk ? const Color(0xFF0B1120) : const Color(0xFFE2E8F0),
      appBar: AppBar(
        backgroundColor: _isDarkDesk ? const Color(0xFF0F172A) : Colors.white,
        elevation: 0.5,
        leading: IconButton(
          icon: Icon(
            Icons.arrow_back_ios_new_rounded,
            size: 18,
            color: _isDarkDesk ? Colors.white : AppTheme.textPrimary,
          ),
          onPressed: () => Navigator.pop(context),
        ),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'ទិដ្ឋភាពក្រដាស A4 ពេញលេញ',
              style: GoogleFonts.kantumruyPro(
                fontSize: 14,
                fontWeight: FontWeight.bold,
                color: _isDarkDesk ? Colors.white : AppTheme.textPrimary,
              ),
            ),
            Text(
              '${widget.paperSize.name} • ${_orientation.label} • (${(_currentScale * 100).toInt()}%)',
              style: GoogleFonts.kantumruyPro(
                fontSize: 10.5,
                color: AppTheme.textMuted,
              ),
            ),
          ],
        ),
        actions: [
          // Dark/Light Desk Toggle
          IconButton(
            tooltip: _isDarkDesk ? 'ផ្ទៃតុពណ៌ភ្លឺ' : 'ផ្ទៃតុពណ៌ងងឹត',
            icon: Icon(
              _isDarkDesk ? Icons.light_mode_rounded : Icons.dark_mode_rounded,
              size: 19,
              color: _isDarkDesk ? Colors.white70 : AppTheme.textPrimary,
            ),
            onPressed: () => setState(() => _isDarkDesk = !_isDarkDesk),
          ),
          // Rotate Orientation
          IconButton(
            tooltip: 'បង្វិលទិសដៅក្រដាស',
            icon: Icon(
              isLandscape ? Icons.stay_current_portrait_rounded : Icons.stay_current_landscape_rounded,
              size: 19,
              color: _isDarkDesk ? Colors.white70 : AppTheme.textPrimary,
            ),
            onPressed: _toggleOrientation,
          ),
          // Share Button
          if (widget.filePath != null)
            IconButton(
              tooltip: 'ចែករំលែក / បើកក្នុង Word',
              icon: const Icon(Icons.share_rounded, size: 19, color: Color(0xFF2563EB)),
              onPressed: () async {
                await Share.shareXFiles([XFile(widget.filePath!)], text: 'ឯកសារបម្លែងពី VVC Attendance');
              },
            ),
        ],
      ),
      body: Stack(
        children: [
          // Interactive A4 Viewer
          InteractiveViewer(
            transformationController: _transformController,
            minScale: 0.35,
            maxScale: 3.5,
            boundaryMargin: const EdgeInsets.symmetric(horizontal: 60, vertical: 100),
            constrained: false,
            child: Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: SizedBox(
                  width: paperWidth,
                  child: widget.paperBuilder(
                    _currentText,
                    widget.paperSize,
                    _orientation,
                    widget.photoFile,
                    widget.onPickPhoto,
                  ),
                ),
              ),
            ),
          ),

          // Floating Bottom Control Dock
          Positioned(
            bottom: 24,
            left: 20,
            right: 20,
            child: Center(
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                decoration: BoxDecoration(
                  color: (_isDarkDesk ? const Color(0xFF1E293B) : Colors.white).withValues(alpha: 0.95),
                  borderRadius: BorderRadius.circular(30),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: 0.25),
                      blurRadius: 16,
                      offset: const Offset(0, 4),
                    ),
                  ],
                  border: Border.all(
                    color: _isDarkDesk ? const Color(0xFF334155) : const Color(0xFFCBD5E1),
                  ),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Zoom Out
                    IconButton(
                      tooltip: 'បង្រួម (-)',
                      icon: const Icon(Icons.remove_circle_outline_rounded, size: 20),
                      color: _isDarkDesk ? Colors.white70 : AppTheme.textPrimary,
                      onPressed: _zoomOut,
                      visualDensity: VisualDensity.compact,
                    ),

                    // Reset 100%
                    InkWell(
                      onTap: _resetZoom,
                      borderRadius: BorderRadius.circular(12),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: const Color(0xFF2563EB).withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Text(
                          '${(_currentScale * 100).toInt()}%',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                            color: const Color(0xFF2563EB),
                          ),
                        ),
                      ),
                    ),

                    // Zoom In
                    IconButton(
                      tooltip: 'ពង្រីក (+)',
                      icon: const Icon(Icons.add_circle_outline_rounded, size: 20),
                      color: _isDarkDesk ? Colors.white70 : AppTheme.textPrimary,
                      onPressed: _zoomIn,
                      visualDensity: VisualDensity.compact,
                    ),

                    Container(width: 1, height: 20, color: AppTheme.border, margin: const EdgeInsets.symmetric(horizontal: 4)),

                    // Change Photo Button
                    if (widget.onPickPhoto != null)
                      IconButton(
                        tooltip: 'ប្តូររូបថត 3x4',
                        icon: const Icon(Icons.photo_camera_rounded, size: 19),
                        color: const Color(0xFF10B981),
                        onPressed: widget.onPickPhoto,
                        visualDensity: VisualDensity.compact,
                      ),

                    // Fit Width
                    IconButton(
                      tooltip: 'សមស្របនឹងអេក្រង់',
                      icon: const Icon(Icons.fit_screen_rounded, size: 19),
                      color: const Color(0xFF0284C7),
                      onPressed: _resetZoom,
                      visualDensity: VisualDensity.compact,
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
