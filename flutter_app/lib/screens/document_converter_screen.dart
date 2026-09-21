import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:file_picker/file_picker.dart';
import 'package:image_picker/image_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import '../services/gemini_ocr_service.dart';
import '../services/document_conversion_service.dart';
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

        final docxPath = '${tempDir.path}/Doc_${result.documentTitle ?? "Khmer"}_$timeStamp.docx';
        final docxFile = await GeminiOcrService.exportToDocx(
          result: result,
          outputPath: docxPath,
        );

        if (mounted) {
          setState(() => _isProcessing = false);
          _showResultSheet(
            title: 'បម្លែងជា Word (.docx) ជោគជ័យ!',
            subtitle: 'ឯកសាររក្សាទម្រង់ដើម តារាង និងអក្សរខ្មែរយូនីកូដបានយ៉ាងត្រឹមត្រូវ',
            filePath: docxFile.path,
            extractedText: result.fullText,
            isDocx: true,
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
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isProcessing = false);
        _showToast('កំហុសបម្លែង PDF: $e', isError: true);
      }
    }
  }

  // 3. PDF to Word (.docx) (Multi-page)
  Future<void> _startPdfToWord() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['pdf'],
      allowMultiple: false,
    );
    if (result == null || result.files.isEmpty || result.files.first.path == null) return;
    final pdfPath = result.files.first.path!;

    setState(() {
      _isProcessing = true;
      _progressMessage = 'កំពុងបម្លែងទំព័រ PDF ទៅជារូបភាពដើម្បីដំណើរការ AI...';
      _progressValue = 0.2;
    });

    try {
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
        _progressMessage = 'AI Gemini កំពុងស្រង់ទម្រង់ឯកសារ និងអក្សរខ្មែរ...';
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

      final timeStamp = DateTime.now().millisecondsSinceEpoch;
      final docxPath = '${tempDir.path}/PDF_to_Word_$timeStamp.docx';
      final docxFile = await GeminiOcrService.exportToDocx(
        result: ocrResult,
        outputPath: docxPath,
      );

      if (mounted) {
        setState(() => _isProcessing = false);
        _showResultSheet(
          title: 'បម្លែង PDF ទៅជា Word ជោគជ័យ!',
          subtitle: 'ឯកសារ Word (.docx) រក្សាទម្រង់ តារាង និងអក្សរខ្មែរយ៉ាងពេញលេញ',
          filePath: docxFile.path,
          extractedText: ocrResult.fullText,
          isDocx: true,
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
  }) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) {
        final isDark = Theme.of(ctx).brightness == Brightness.dark || AppTheme.isDarkMode;
        return Container(
          height: MediaQuery.of(ctx).size.height * 0.75,
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
                  margin: const EdgeInsets.symmetric(vertical: 12),
                  decoration: BoxDecoration(
                    color: AppTheme.border,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ),

              // Title Header
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: const Color(0xFF10B981).withValues(alpha: 0.15),
                        shape: BoxShape.circle,
                      ),
                      child: const Icon(Icons.check_circle_rounded, color: Color(0xFF10B981), size: 24),
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

              const Divider(height: 24),

              // Content Preview / Text
              Expanded(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 20),
                  child: Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: isDark ? const Color(0xFF0F172A) : const Color(0xFFF8FAFC),
                      borderRadius: BorderRadius.circular(14),
                      border: Border.all(color: AppTheme.border),
                    ),
                    child: extractedText != null && extractedText.isNotEmpty
                        ? SingleChildScrollView(
                            child: SelectableText(
                              extractedText,
                              style: GoogleFonts.kantumruyPro(
                                color: isDark ? Colors.white : AppTheme.textPrimary,
                                fontSize: 12.5,
                                height: 1.6,
                              ),
                            ),
                          )
                        : Center(
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Icon(
                                  isDocx ? Icons.description_rounded : Icons.picture_as_pdf_rounded,
                                  size: 48,
                                  color: isDocx ? const Color(0xFF2563EB) : const Color(0xFFE11D48),
                                ),
                                const SizedBox(height: 10),
                                Text(
                                  filePath?.split('/').last ?? 'ឯកសារបម្លែងរួចរាល់',
                                  textAlign: TextAlign.center,
                                  style: GoogleFonts.kantumruyPro(
                                    color: isDark ? Colors.white : AppTheme.textPrimary,
                                    fontSize: 13,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ],
                            ),
                          ),
                  ),
                ),
              ),

              // Bottom Action Buttons
              SafeArea(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(20, 14, 20, 16),
                  child: Row(
                    children: [
                      // Copy Button (if text available)
                      if (extractedText != null && extractedText.isNotEmpty)
                        Expanded(
                          child: OutlinedButton.icon(
                            onPressed: () {
                              Clipboard.setData(ClipboardData(text: extractedText));
                              _showToast('បានចម្លងអត្ថបទទៅ Clipboard');
                            },
                            icon: const Icon(Icons.copy_rounded, size: 16),
                            label: Text(
                              'ចម្លងអត្ថបទ',
                              style: GoogleFonts.kantumruyPro(fontSize: 12, fontWeight: FontWeight.w600),
                            ),
                            style: OutlinedButton.styleFrom(
                              padding: const EdgeInsets.symmetric(vertical: 12),
                              side: BorderSide(color: AppTheme.border),
                              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                            ),
                          ),
                        ),
                      if (extractedText != null && extractedText.isNotEmpty) const SizedBox(width: 10),

                      // Share / Open File Button
                      Expanded(
                        child: ElevatedButton.icon(
                          onPressed: () async {
                            if (filePath != null) {
                              await Share.shareXFiles(
                                [XFile(filePath)],
                                text: 'ឯកសារបម្លែងពី VVC Attendance',
                              );
                            } else if (extractedText != null) {
                              await Share.share(extractedText);
                            }
                          },
                          icon: const Icon(Icons.share_rounded, size: 16, color: Colors.white),
                          label: Text(
                            'ចែករំលែក / ផ្ញើ',
                            style: GoogleFonts.kantumruyPro(
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                              color: Colors.white,
                            ),
                          ),
                          style: ElevatedButton.styleFrom(
                            backgroundColor: const Color(0xFF0284C7),
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
  }

  // ===========================================================================
  // BUILD MAIN UI
  // ===========================================================================

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;

    return Scaffold(
      backgroundColor: isDark ? const Color(0xFF0F172A) : AppTheme.bgSurface,
      appBar: VvcAppBar(
        backgroundColor: isDark ? const Color(0xFF0F172A) : AppTheme.bgSurface,
        elevation: 0,
        centerTitle: true,
        title: Text(
          'បំប្លែងឯកសារ & AI',
          style: GoogleFonts.kantumruyPro(
            fontSize: 17,
            fontWeight: FontWeight.bold,
            color: isDark ? Colors.white : AppTheme.textPrimary,
          ),
        ),
        leading: IconButton(
          icon: Icon(
            Icons.arrow_back_ios_new_rounded,
            size: 19,
            color: isDark ? Colors.white : AppTheme.textPrimary,
          ),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: Stack(
        children: [
          CustomScrollView(
            physics: const BouncingScrollPhysics(),
            slivers: [
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
