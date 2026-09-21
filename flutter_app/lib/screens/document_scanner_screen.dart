import 'dart:io';
import 'dart:async';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cunning_document_scanner/cunning_document_scanner.dart';
import 'package:image_picker/image_picker.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import 'package:path_provider/path_provider.dart';
import 'package:image/image.dart' as img;
import 'package:path/path.dart' as path;
import 'package:intl/intl.dart';
import 'package:gal/gal.dart';
import 'package:share_plus/share_plus.dart';
import '../services/ocr_service.dart' as ocr;
import '../services/document_history_service.dart';
import '../widgets/export_modal.dart';
import 'passport_photo_screen.dart';
import 'digital_ink_screen.dart';
import 'document_converter_screen.dart';
import '../widgets/app_widgets.dart';
import '../utils/app_theme.dart';

/// Document Scanner Screen - Premium UI with Native Document Scanning
/// 
/// Features:
/// - Dark theme with subtle gradients
/// - Native document scanning (ML Kit for Android, VisionKit for iOS)
/// - Auto-cropped, color-enhanced, and straightened images
/// - Refined filter selection
/// - Modern action buttons with gradients
/// - Blur effects and shadows for depth
/// - OCR text extraction with copy to clipboard
class DocumentScannerScreen extends StatefulWidget {
  final List<String>? existingImagePaths;
  final int? existingDocumentId;

  const DocumentScannerScreen({
    super.key,
    this.existingImagePaths,
    this.existingDocumentId,
  });

  @override
  State<DocumentScannerScreen> createState() => _DocumentScannerScreenState();
}

class _DocumentScannerScreenState extends State<DocumentScannerScreen> {
  // Step tracking
  ScannerStep _currentStep = ScannerStep.selectImage;
  
  // Image paths
  String? _scannedImagePath;
  String? _filteredImagePath;
  
  // Multi-page scanning
  List<String> _scannedImagePaths = [];
  // ignore: unused_field
  bool _isMultiPageMode = false;
  int _currentPageIndex = 0;
  late PageController _pageController;
  
  // History scanning lists and controllers
  List<Map<String, dynamic>> _recentDocuments = [];
  List<Map<String, dynamic>> _filteredDocuments = [];
  final TextEditingController _searchController = TextEditingController();
  int? _activeDocumentId;
  
  // Processing state
  bool _isProcessing = false;
  String? _errorMessage;
  
  // OCR results
  ocr.OCRResult? _ocrResult;
  final ocr.OCRService _ocrService = ocr.OCRService();
  final DocumentHistoryService _historyService = DocumentHistoryService();
  
  // Selected filter - defaults to CamScanner-style Magic Color for crystal clear documents
  ImageFilter _selectedFilter = ImageFilter.magicColor;

  // Page rotations (index -> angle degrees: 0, 90, 180, 270)
  final Map<int, int> _pageRotations = {};

  /// CamScanner-Grade Magic Color Document Enhancement:
  /// 1. White Background Normalization: Flattens paper shadows and yellowish/gray tint into bright clean white (245-255).
  /// 2. Khmer Text Deepening: Darkens printed & handwritten ink so letters and small diacritics stand out boldly.
  /// 3. Stamp & Signature Protection: Retains official red seals and blue ink signatures with rich, vibrant saturation.
  /// 4. 3x3 Unsharp Mask Sharpening: Sharpens fine Khmer vowels (◌ិ, ◌ី, ◌ឹ, ◌ឺ, ◌ុ, ◌ូ) and subscript feet (ជើង).
  static img.Image enhanceDocumentMagicColor(img.Image src) {
    for (final frame in src.frames) {
      for (final p in frame) {
        final r = p.r.toDouble();
        final g = p.g.toDouble();
        final b = p.b.toDouble();

        // Calculate perceived luminance (standard Rec.601)
        final lum = 0.299 * r + 0.587 * g + 0.114 * b;

        // Detect colored seals/stamps and signatures
        final isRedStamp = (r > g + 26) && (r > b + 26);
        final isBlueSignature = (b > r + 18) && (b > g + 18);

        if (isRedStamp) {
          // Vivid official red seal
          p.r = (r * 1.25).clamp(0, 255);
          p.g = (g * 0.85).clamp(0, 255);
          p.b = (b * 0.85).clamp(0, 255);
        } else if (isBlueSignature) {
          // Vivid blue pen signature
          p.r = (r * 0.85).clamp(0, 255);
          p.g = (g * 0.95).clamp(0, 255);
          p.b = (b * 1.30).clamp(0, 255);
        } else {
          // Document paper vs text ink
          if (lum > 140) {
            // Background paper: push smoothly towards pure white (255)
            final factor = (lum - 140) / (255 - 140);
            final targetLum = 225.0 + factor * 30.0; // 225..255
            final scale = targetLum / (lum > 0 ? lum : 1);
            p.r = (r * scale).clamp(0, 255);
            p.g = (g * scale).clamp(0, 255);
            p.b = (b * scale).clamp(0, 255);
          } else {
            // Text and borders: deepen ink to sharp dark
            final scale = math.pow(lum / 140, 1.45).toDouble();
            p.r = (r * scale).clamp(0, 255);
            p.g = (g * scale).clamp(0, 255);
            p.b = (b * scale).clamp(0, 255);
          }
        }
      }
    }

    // Apply unsharp mask sharpening convolution for crisp text edges
    return img.convolution(
      src,
      filter: [
        0, -0.3, 0,
        -0.3, 2.2, -0.3,
        0, -0.3, 0,
      ],
      div: 1.0,
    );
  }

  /// Clean High-Contrast B&W Document (Photocopy Mode):
  /// Removes all paper shadows and background noise, leaving pure crisp black text on pure white paper.
  static img.Image enhanceDocumentBW(img.Image src) {
    src = img.grayscale(src);
    for (final frame in src.frames) {
      for (final p in frame) {
        final lum = p.r.toDouble();
        if (lum > 140) {
          p.r = 255;
          p.g = 255;
          p.b = 255;
        } else {
          final darkVal = (lum * 0.55).clamp(0, 255);
          p.r = darkVal;
          p.g = darkVal;
          p.b = darkVal;
        }
      }
    }
    return img.convolution(
      src,
      filter: [
        0, -0.25, 0,
        -0.25, 2.0, -0.25,
        0, -0.25, 0,
      ],
      div: 1.0,
    );
  }

  /// Super HD Sharpening & Contrast Enhancement:
  /// Eliminates blurriness from slight phone shake and boosts document clarity.
  static img.Image enhanceDocumentSuperHD(img.Image src) {
    src = img.adjustColor(src, contrast: 1.35, brightness: 1.08, saturation: 1.20);
    return img.convolution(
      src,
      filter: [
        0, -0.4, 0,
        -0.4, 2.6, -0.4,
        0, -0.4, 0,
      ],
      div: 1.0,
    );
  }

  /// Helper to prepare processed image paths (baking filters and rotation)
  Future<List<String>> _prepareProcessedImagePaths() async {
    final List<String> processedPaths = [];
    for (int i = 0; i < _scannedImagePaths.length; i++) {
      final path = _scannedImagePaths[i];
      final rotation = _pageRotations[i] ?? 0;
      if (_selectedFilter == ImageFilter.original && rotation == 0) {
        processedPaths.add(path);
      } else {
        final processedFile = await _bakeImageEffects(path, rotation, _selectedFilter);
        processedPaths.add(processedFile.path);
      }
    }
    return processedPaths.isNotEmpty ? processedPaths : [_scannedImagePath ?? ''];
  }

  /// Bake rotation and filter effects into a temporary JPG file with Ultra-HD 98% quality
  Future<File> _bakeImageEffects(String imagePath, int rotationDegrees, ImageFilter filter) async {
    try {
      final bytes = await File(imagePath).readAsBytes();
      img.Image? image = img.decodeImage(bytes);
      if (image == null) return File(imagePath);

      if (rotationDegrees != 0) {
        image = img.copyRotate(image, angle: rotationDegrees);
      }

      if (filter == ImageFilter.blackAndWhite) {
        image = enhanceDocumentBW(image);
      } else if (filter == ImageFilter.magicColor) {
        image = enhanceDocumentMagicColor(image);
      } else if (filter == ImageFilter.enhanced) {
        image = enhanceDocumentSuperHD(image);
      }

      final tempDir = await getTemporaryDirectory();
      final outPath = '${tempDir.path}/proc_${DateTime.now().millisecondsSinceEpoch}_${path.basename(imagePath)}';
      // Ultra-HD Quality 98% eliminates JPEG ringing artifacts and preserves fine Khmer fonts
      final encodedJpg = img.encodeJpg(image, quality: 98);
      final outFile = File(outPath);
      await outFile.writeAsBytes(encodedJpg);
      return outFile;
    } catch (e) {
      debugPrint('Error baking image effects: $e');
      return File(imagePath);
    }
  }

  /// Open crop dialog for current page
  Future<void> _cropCurrentImage() async {
    if (_scannedImagePaths.isEmpty) return;

    final currentPath = _scannedImagePaths[_currentPageIndex];
    final currentRotation = _pageRotations[_currentPageIndex] ?? 0;

    final croppedPath = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) => ImageCropperDialog(
        imagePath: currentPath,
        initialRotation: currentRotation,
      ),
    );

    if (croppedPath != null && mounted) {
      setState(() {
        _scannedImagePaths[_currentPageIndex] = croppedPath;
        _filteredImagePath = croppedPath;
        _pageRotations[_currentPageIndex] = 0;
      });
    }
  }

  @override
  void initState() {
    super.initState();
    _pageController = PageController();
    _loadRecentDocuments();

    // Load existing images if editing
    if (widget.existingImagePaths != null && widget.existingImagePaths!.isNotEmpty) {
      _scannedImagePaths = List.from(widget.existingImagePaths!);
      _scannedImagePath = _scannedImagePaths.first;
      _filteredImagePath = _scannedImagePaths.first;
      _isMultiPageMode = _scannedImagePaths.length > 1;
      _currentStep = ScannerStep.filterSelection;
      _activeDocumentId = widget.existingDocumentId;
    }
  }

  @override
  void dispose() {
    _ocrService.dispose();
    _pageController.dispose();
    _searchController.dispose();
    _cleanupTempFiles();
    super.dispose();
  }

  /// Clean up temporary files
  Future<void> _cleanupTempFiles() async {
    try {
      for (final path in _scannedImagePaths) {
        final file = File(path);
        if (await file.exists()) {
          await file.delete();
        }
      }
      if (_scannedImagePath != null) {
        final file = File(_scannedImagePath!);
        if (await file.exists()) {
          await file.delete();
        }
      }
      if (_filteredImagePath != null) {
        final file = File(_filteredImagePath!);
        if (await file.exists()) {
          await file.delete();
        }
      }
    } catch (e) {
      // Ignore cleanup errors
    }
  }

  /// Step 1: Open native document scanner
  Future<void> _openNativeScanner() async {
    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      // Open the native document scanner using multi-page support with camera + gallery
      final scannedImages = await CunningDocumentScanner.getPictures(
        noOfPages: 50, // Allow up to 50 pages (must be > 0)
        scannerSource: ScannerSource.cameraAndGallery,
        androidScannerMode: AndroidScannerMode.full,
        iosScannerOptions: const IosScannerOptions(
          imageFormat: IosImageFormat.png,
          jpgCompressionQuality: 1.0,
        ),
      );

      if (scannedImages != null && scannedImages.isNotEmpty) {
        setState(() {
          // Append new pages to existing ones
          _scannedImagePaths.addAll(scannedImages);
          _scannedImagePath = _scannedImagePaths.first;
          _filteredImagePath = _scannedImagePaths.first;
          _selectedFilter = ImageFilter.magicColor; // Auto-enhance to crystal clear Magic Color
          _currentStep = ScannerStep.filterSelection;
          _isMultiPageMode = _scannedImagePaths.length > 1;
          _currentPageIndex = _scannedImagePaths.length - 1; // Jump to last page
          _isProcessing = false;
        });
        
        // Jump to the newly added page safely after layout rebuild
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (_pageController.hasClients) {
            _pageController.jumpToPage(_currentPageIndex);
          }
        });
      } else {
        // User cancelled or closed camera: stay on the dashboard smoothly without error
        setState(() {
          _isProcessing = false;
        });
      }
    } catch (e) {
      setState(() {
        _isProcessing = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'មិនអាចបើកកាមេរ៉ាស្កេនបានទេ៖ $e',
              style: GoogleFonts.kantumruyPro(),
            ),
            backgroundColor: Colors.redAccent,
          ),
        );
      }
    }
  }

  /// Import images from Gallery with full native document scanning and boundary detection
  Future<void> _importFromGallery() async {
    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      // 1. Launch native document scanner directly on gallery pictures (MLKit / VisionKit auto boundary & enhancement)
      final scannedImages = await CunningDocumentScanner.getPictures(
        noOfPages: 50,
        scannerSource: ScannerSource.gallery,
        androidScannerMode: AndroidScannerMode.full,
        iosScannerOptions: const IosScannerOptions(
          imageFormat: IosImageFormat.png,
          jpgCompressionQuality: 1.0,
        ),
      );

      if (scannedImages != null && scannedImages.isNotEmpty) {
        setState(() {
          _scannedImagePaths.addAll(scannedImages);
          _scannedImagePath = _scannedImagePaths.first;
          _filteredImagePath = _scannedImagePaths.first;
          _selectedFilter = ImageFilter.magicColor;
          _currentStep = ScannerStep.filterSelection;
          _isMultiPageMode = _scannedImagePaths.length > 1;
          _currentPageIndex = _scannedImagePaths.length - 1;
          _isProcessing = false;
        });

        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (_pageController.hasClients) {
            _pageController.jumpToPage(_currentPageIndex);
          }
        });
        return;
      }
    } catch (e) {
      debugPrint('Native gallery scanner fallback: $e');
    }

    // 2. Fallback: If native gallery scanner was canceled or unsupported, use ImagePicker with interactive cropper
    final ImagePicker picker = ImagePicker();
    try {
      final List<XFile> images = await picker.pickMultiImage(imageQuality: 100);
      if (images.isNotEmpty) {
        final List<String> paths = images.map((e) => e.path).toList();
        setState(() {
          _scannedImagePaths.addAll(paths);
          _scannedImagePath = _scannedImagePaths.first;
          _filteredImagePath = _scannedImagePaths.first;
          _selectedFilter = ImageFilter.magicColor;
          _currentStep = ScannerStep.filterSelection;
          _isMultiPageMode = _scannedImagePaths.length > 1;
          _currentPageIndex = _scannedImagePaths.length - 1;
          _isProcessing = false;
        });

        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (_pageController.hasClients) {
            _pageController.jumpToPage(_currentPageIndex);
          }
        });

        // Automatically prompt document corner unwarper for single image uploads
        if (paths.length == 1 && mounted) {
          _cropCurrentImage();
        }
      } else {
        setState(() {
          _isProcessing = false;
        });
      }
    } catch (e) {
      setState(() {
        _isProcessing = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'ការនាំចូលរូបភាពបានបរាជ័យ៖ $e',
              style: GoogleFonts.kantumruyPro(),
            ),
            backgroundColor: Colors.redAccent,
          ),
        );
      }
    }
  }

  /// Apply image filter (updates color filter live on preview)
  Future<void> _applyFilter(ImageFilter filter) async {
    if (_scannedImagePaths.isEmpty) return;

    setState(() {
      _selectedFilter = filter;
      _filteredImagePath = _scannedImagePaths[_currentPageIndex];
    });
  }

  /// Extract text from scanned document using OCR
  /// Uses Khmer OCR backend for better accuracy with Khmer text
  Future<void> _extractText() async {
    if (_scannedImagePaths.isEmpty) return;

    // Capture ScaffoldMessenger before async gap
    final scaffoldMessenger = ScaffoldMessenger.of(context);

    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      // Use the current page for OCR
      final currentImagePath = _scannedImagePaths[_currentPageIndex];
      // Use Khmer OCR backend for better accuracy
      final result = await _ocrService.extractTextKhmer(currentImagePath);
      
      setState(() {
        _ocrResult = result;
        _isProcessing = false;
      });
      
      // Show bottom sheet with extracted text
      if (result.success && result.fullText.isNotEmpty) {
        _showOCRResultBottomSheet(result);
      } else {
        scaffoldMessenger.showSnackBar(
          const SnackBar(
            content: Text('No text detected in the image'),
            backgroundColor: Colors.orange,
          ),
        );
      }
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _errorMessage = 'OCR failed: $e';
      });
      scaffoldMessenger.showSnackBar(
        SnackBar(
          content: Text('OCR failed: $e'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

  /// Show bottom sheet with OCR results
  void _showOCRResultBottomSheet(ocr.OCRResult result) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => Container(
        decoration: const BoxDecoration(
          color: Color(0xFF1A1A1A),
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                border: Border(
                  bottom: BorderSide(
                    color: Colors.white.withValues(alpha: 0.1),
                    width: 1,
                  ),
                ),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Text(
                    'Extracted Text',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close, color: Colors.white),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
            ),
            // Stats
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              child: Row(
                children: [
                  const Icon(Icons.text_fields, size: 16, color: Colors.orange),
                  const SizedBox(width: 8),
                  Text(
                    '${result.wordCount} words',
                    style: const TextStyle(color: Colors.grey, fontSize: 12),
                  ),
                  const SizedBox(width: 16),
                  const Icon(Icons.abc, size: 16, color: Colors.orange),
                  const SizedBox(width: 8),
                  Text(
                    '${result.charCount} characters',
                    style: const TextStyle(color: Colors.grey, fontSize: 12),
                  ),
                ],
              ),
            ),
            // Text content with Khmer font
            Container(
              constraints: const BoxConstraints(maxHeight: 400),
              padding: const EdgeInsets.all(16),
              child: SingleChildScrollView(
                child: SelectableText(
                  result.fullText,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontSize: 14,
                    height: 1.6,
                  ),
                ),
              ),
            ),
            // Action buttons
            Container(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: result.fullText));
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('Text copied to clipboard'),
                            duration: Duration(seconds: 2),
                          ),
                        );
                      },
                      icon: const Icon(Icons.copy, size: 18),
                      label: const Text('Copy'),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: Colors.orange,
                        side: const BorderSide(color: Colors.orange),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: () => Navigator.pop(context),
                      icon: const Icon(Icons.close, size: 18),
                      label: const Text('Close'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: Colors.orange,
                        foregroundColor: Colors.white,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            SizedBox(height: MediaQuery.of(context).padding.bottom),
          ],
        ),
      ),
    );
  }

  /// Export scanned document to PDF
  Future<void> _exportToPDF() async {
    if (_scannedImagePaths.isEmpty && _scannedImagePath == null) return;

    final imagePaths = await _prepareProcessedImagePaths();
    
    // Show export modal
    if (mounted) {
      showModalBottomSheet(
        context: context,
        isScrollControlled: true,
        backgroundColor: Colors.transparent,
        builder: (context) => ExportModal(
          imagePaths: imagePaths,
          ocrText: _ocrResult?.fullText,
          onExport: (fileName, format, {includeWatermark = false, watermarkText = 'VVC OFFICIAL DOCUMENT', pageSize = PdfPageSize.autoFit}) =>
              _handleExport(fileName, format, imagePaths,
                  includeWatermark: includeWatermark, watermarkText: watermarkText, pageSize: pageSize),
          onSaveToPhone: (fileName, format, paths, {includeWatermark = false, watermarkText = 'VVC OFFICIAL DOCUMENT', pageSize = PdfPageSize.autoFit}) =>
              _handleSaveToPhone(fileName, format, paths,
                  includeWatermark: includeWatermark, watermarkText: watermarkText, pageSize: pageSize),
        ),
      );
    }
  }

  /// Handle direct save to phone based on selected format
  Future<void> _handleSaveToPhone(
    String fileName,
    ExportFormat format,
    List<String> imagePaths, {
    bool includeWatermark = false,
    String watermarkText = 'VVC OFFICIAL DOCUMENT',
    PdfPageSize pageSize = PdfPageSize.autoFit,
  }) async {
    switch (format) {
      case ExportFormat.images:
        await _saveImagesToPhone(fileName, imagePaths);
        break;
      case ExportFormat.pdf:
        await _savePDFToPhone(
          fileName,
          imagePaths,
          includeWatermark: includeWatermark,
          watermarkText: watermarkText,
          pageSize: pageSize,
        );
        break;
      case ExportFormat.text:
        await _exportAsText(fileName);
        break;
    }
  }

  /// Handle export based on selected format
  Future<void> _handleExport(
    String fileName,
    ExportFormat format,
    List<String> imagePaths, {
    bool includeWatermark = false,
    String watermarkText = 'VVC OFFICIAL DOCUMENT',
    PdfPageSize pageSize = PdfPageSize.autoFit,
  }) async {
    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      final processedPaths = await _prepareProcessedImagePaths();

      switch (format) {
        case ExportFormat.pdf:
          await _exportAsPDF(
            fileName,
            processedPaths,
            includeWatermark: includeWatermark,
            watermarkText: watermarkText,
            pageSize: pageSize,
          );
          break;
        case ExportFormat.images:
          await _exportAsImages(fileName, processedPaths);
          break;
        case ExportFormat.text:
          await _exportAsText(fileName);
          break;
      }

      // Save to history
      await _saveToHistory(fileName, processedPaths);

      if (mounted) {
        final formatText = format == ExportFormat.images
            ? 'រូបភាព JPG'
            : format.name.toUpperCase();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'នាំចេញបានជោគជ័យជា $formatText',
              style: GoogleFonts.kantumruyPro(),
            ),
            backgroundColor: const Color(0xFF16A34A),
          ),
        );
      }
    } catch (e) {
      setState(() {
        _errorMessage = 'Export failed: $e';
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Export failed: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    } finally {
      setState(() {
        _isProcessing = false;
      });
    }
  }

  /// Generate PDF Document bytes
  Future<Uint8List> _generatePdfBytes(
    List<String> imagePaths, {
    bool includeWatermark = false,
    String watermarkText = 'VVC OFFICIAL DOCUMENT',
    PdfPageSize pageSize = PdfPageSize.autoFit,
  }) async {
    final pdf = pw.Document();

    for (final imagePath in imagePaths) {
      final imageFile = File(imagePath);
      final imageBytes = await imageFile.readAsBytes();
      final pdfImage = pw.MemoryImage(imageBytes);

      // Determine dimensions for auto-orientation & scaling
      final decoded = img.decodeImage(imageBytes);
      final int imgW = decoded?.width ?? 1200;
      final int imgH = decoded?.height ?? 1600;
      final bool isLandscape = imgW > imgH;

      PdfPageFormat format;
      pw.BoxFit fitMode;
      pw.EdgeInsets margin;

      switch (pageSize) {
        case PdfPageSize.autoFit:
          // Standard document width based on A4 standard (595.28 pt) scaled to exact aspect ratio
          // Result: ZERO white margins, 100% full bleed, 100% original document aspect ratio (0% distortion)
          final double baseWidth = PdfPageFormat.a4.width; // 595.28 pt
          final double pageW = isLandscape ? (baseWidth * (imgW / imgH)) : baseWidth;
          final double pageH = isLandscape ? baseWidth : (baseWidth * (imgH / imgW));
          format = PdfPageFormat(pageW, pageH, marginAll: 0);
          margin = pw.EdgeInsets.zero;
          fitMode = pw.BoxFit.fill;
          break;

        case PdfPageSize.a4Full:
          // Full A4 page (standard 210mm x 297mm) with zero margin
          format = isLandscape ? PdfPageFormat.a4.landscape : PdfPageFormat.a4;
          margin = pw.EdgeInsets.zero;
          fitMode = pw.BoxFit.fill;
          break;

        case PdfPageSize.a4Margin:
          format = isLandscape ? PdfPageFormat.a4.landscape : PdfPageFormat.a4;
          margin = const pw.EdgeInsets.all(8);
          fitMode = pw.BoxFit.contain;
          break;
      }

      pdf.addPage(
        pw.Page(
          pageFormat: format,
          margin: margin,
          build: (pw.Context context) {
            return pw.Stack(
              alignment: pw.Alignment.center,
              children: [
                pw.FullPage(
                  ignoreMargins: true,
                  child: pw.Image(
                    pdfImage,
                    fit: fitMode,
                    width: format.width,
                    height: format.height,
                  ),
                ),
                if (includeWatermark)
                  pw.Transform.rotate(
                    angle: -0.45,
                    child: pw.Container(
                      padding: const pw.EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                      decoration: pw.BoxDecoration(
                        border: pw.Border.all(
                          color: const PdfColor(0.85, 0.2, 0.2, 0.28),
                          width: 2.5,
                        ),
                        borderRadius: const pw.BorderRadius.all(pw.Radius.circular(10)),
                      ),
                      child: pw.Column(
                        mainAxisSize: pw.MainAxisSize.min,
                        children: [
                          pw.Text(
                            watermarkText.toUpperCase(),
                            style: pw.TextStyle(
                              fontSize: 26,
                              fontWeight: pw.FontWeight.bold,
                              color: const PdfColor(0.85, 0.2, 0.2, 0.28),
                            ),
                          ),
                          pw.SizedBox(height: 4),
                          pw.Text(
                            "VERIFIED & PROTECTED",
                            style: pw.TextStyle(
                              fontSize: 10,
                              fontWeight: pw.FontWeight.bold,
                              letterSpacing: 2,
                              color: const PdfColor(0.85, 0.2, 0.2, 0.22),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
              ],
            );
          },
        ),
      );
    }

    // If OCR text exists, add it as a separate page
    if (_ocrResult != null && _ocrResult!.fullText.isNotEmpty) {
      pdf.addPage(
        pw.Page(
          build: (pw.Context context) {
            return pw.Padding(
              padding: const pw.EdgeInsets.all(32),
              child: pw.Text(
                _ocrResult!.fullText,
                style: const pw.TextStyle(fontSize: 12),
              ),
            );
          },
        ),
      );
    }

    return await pdf.save();
  }

  /// Export as multi-page PDF with options for page format and full-bleed fit
  Future<void> _exportAsPDF(
    String fileName,
    List<String> imagePaths, {
    bool includeWatermark = false,
    String watermarkText = 'VVC OFFICIAL DOCUMENT',
    PdfPageSize pageSize = PdfPageSize.autoFit,
  }) async {
    final pdfBytes = await _generatePdfBytes(
      imagePaths,
      includeWatermark: includeWatermark,
      watermarkText: watermarkText,
      pageSize: pageSize,
    );
    await Printing.sharePdf(bytes: pdfBytes, filename: '$fileName.pdf');
  }

  /// Save PDF file to device storage
  Future<void> _savePDFToPhone(
    String fileName,
    List<String> imagePaths, {
    bool includeWatermark = false,
    String watermarkText = 'VVC OFFICIAL DOCUMENT',
    PdfPageSize pageSize = PdfPageSize.autoFit,
  }) async {
    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      final pdfBytes = await _generatePdfBytes(
        imagePaths,
        includeWatermark: includeWatermark,
        watermarkText: watermarkText,
        pageSize: pageSize,
      );

      final Directory appDocDir = await getApplicationDocumentsDirectory();
      final File file = File('${appDocDir.path}/$fileName.pdf');
      await file.writeAsBytes(pdfBytes);

      // Save to history
      await _saveToHistory(fileName, imagePaths);

      // Also share so user can choose "Save to Files" or any destination
      await Share.shareXFiles(
        [XFile(file.path, mimeType: 'application/pdf', name: '$fileName.pdf')],
        text: fileName,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                const Icon(Icons.check_circle_rounded, color: Colors.white),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'បានរក្សាទុកឯកសារ PDF ដោយជោគជ័យ!',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
            ),
            backgroundColor: const Color(0xFF059669),
            duration: const Duration(seconds: 4),
            behavior: SnackBarBehavior.floating,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          ),
        );
      }
    } catch (e) {
      debugPrint('Error saving PDF: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('មិនអាចរក្សាទុក PDF បានទេ: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isProcessing = false;
        });
      }
    }
  }

  /// Export as images (individual files) via native Share Sheet
  Future<void> _exportAsImages(String fileName, List<String> imagePaths) async {
    final tempDir = await getTemporaryDirectory();
    final List<XFile> xFiles = [];

    for (int i = 0; i < imagePaths.length; i++) {
      final srcFile = File(imagePaths[i]);
      if (!await srcFile.exists()) continue;

      final String safeName = imagePaths.length == 1
          ? '$fileName.jpg'
          : '${fileName}_page_${i + 1}.jpg';
      final destFile = File('${tempDir.path}/$safeName');
      await srcFile.copy(destFile.path);

      xFiles.add(XFile(
        destFile.path,
        mimeType: 'image/jpeg',
        name: safeName,
      ));
    }

    if (xFiles.isEmpty) {
      throw Exception('រកមិនឃើញរូបភាពសម្រាប់នាំចេញទេ');
    }

    // Share via share_plus
    // On iOS, sharing image/jpeg files natively displays thumbnail + "Save Image" / "Save X Images"
    await Share.shareXFiles(
      xFiles,
      text: 'ឯកសារស្កេន: $fileName',
      subject: fileName,
    );
  }

  /// Directly save scanned images to the phone's Photo Album / Gallery
  Future<void> _saveImagesToPhone(String fileName, List<String> imagePaths) async {
    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      int savedCount = 0;
      final tempDir = await getTemporaryDirectory();

      for (int i = 0; i < imagePaths.length; i++) {
        final srcFile = File(imagePaths[i]);
        if (!await srcFile.exists()) continue;

        final String safeName = imagePaths.length == 1
            ? '$fileName.jpg'
            : '${fileName}_${i + 1}.jpg';
        final destFile = File('${tempDir.path}/$safeName');
        await srcFile.copy(destFile.path);

        // Put image into native gallery (album: 'VVC Scanner')
        try {
          await Gal.putImage(destFile.path, album: 'VVC Scanner');
        } catch (_) {
          await Gal.putImage(destFile.path);
        }
        savedCount++;
      }

      if (savedCount == 0) {
        throw Exception('រកមិនឃើញរូបភាពសម្រាប់រក្សាទុកទេ');
      }

      // Also save to history
      await _saveToHistory(fileName, imagePaths);

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                const Icon(Icons.check_circle_rounded, color: Colors.white),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    savedCount == 1
                        ? 'បានរក្សាទុករូបភាពក្នុងទូរស័ព្ទ (Photos) ដោយជោគជ័យ!'
                        : 'បានរក្សាទុកចំនួន $savedCount រូបភាពក្នុងទូរស័ព្ទ (Photos) ដោយជោគជ័យ!',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
            ),
            backgroundColor: const Color(0xFF059669),
            duration: const Duration(seconds: 4),
            behavior: SnackBarBehavior.floating,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          ),
        );
      }
    } catch (e) {
      debugPrint('Error saving to phone: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'មិនអាចរក្សាទុកក្នុងទូរស័ព្ទបានទេ: $e',
              style: GoogleFonts.kantumruyPro(color: Colors.white),
            ),
            backgroundColor: Colors.red,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isProcessing = false;
        });
      }
    }
  }

  /// Quick save current scanned image(s) to phone gallery from toolbar
  Future<void> _quickSaveCurrentToPhone() async {
    final imagePaths = await _prepareProcessedImagePaths();
    if (!mounted) return;
    if (imagePaths.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'គ្មានរូបភាពសម្រាប់រក្សាទុកទេ',
            style: GoogleFonts.kantumruyPro(),
          ),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    final now = DateTime.now();
    final formatter = DateFormat('dd-MM-yyyy_HHmm');
    final fileName = 'Scan_${formatter.format(now)}';

    await _saveImagesToPhone(fileName, imagePaths);
  }

  /// Export as text
  Future<void> _exportAsText(String fileName) async {
    if (_ocrResult == null) {
      throw Exception('No OCR text available');
    }

    final output = await getTemporaryDirectory();
    final file = File('${output.path}/$fileName.txt');
    await file.writeAsString(_ocrResult!.fullText);

    // Share the text file (using platform-specific method)
  }

  /// Save document to history
  Future<void> _saveToHistory(String fileName, List<String> imagePaths) async {
    try {
      final docId = _activeDocumentId ?? widget.existingDocumentId;
      if (docId != null) {
        // Update existing document
        await _historyService.updateDocumentPages(
          docId,
          imagePaths,
        );
        await _historyService.updateDocumentName(
          docId,
          fileName,
        );
        if (_ocrResult?.fullText != null) {
          await _historyService.updateOCRText(
            docId,
            _ocrResult!.fullText,
          );
        }
      } else {
        // Create new document
        await _historyService.saveDocument(
          customName: fileName,
          imagePaths: imagePaths,
          thumbnailPath: imagePaths.first,
          ocrText: _ocrResult?.fullText,
        );
      }
    } catch (e) {
      // Log error but don't fail export
      debugPrint('Failed to save to history: $e');
    }
  }

  /// Load recent scans from local history database
  Future<void> _loadRecentDocuments() async {
    try {
      final docs = await _historyService.getAllDocuments();
      setState(() {
        _recentDocuments = docs;
        _filteredDocuments = docs;
      });
    } catch (e) {
      debugPrint('Error loading documents from history: $e');
    }
  }

  /// Search query filter
  void _onSearchChanged(String query) {
    if (query.isEmpty) {
      setState(() {
        _filteredDocuments = _recentDocuments;
      });
    } else {
      setState(() {
        _filteredDocuments = _recentDocuments.where((doc) {
          final name = (doc['custom_name'] ?? '').toString().toLowerCase();
          return name.contains(query.toLowerCase());
        }).toList();
      });
    }
  }

  /// Open selected document from recents list
  void _openDocument(Map<String, dynamic> doc) {
    final String pathsStr = doc['file_paths'] ?? '';
    final List<String> paths = pathsStr.split(',').where((e) => e.isNotEmpty).toList();
    
    if (paths.isNotEmpty) {
      setState(() {
        _scannedImagePaths = List.from(paths);
        _scannedImagePath = paths.first;
        _filteredImagePath = paths.first;
        _currentPageIndex = 0;
        _isMultiPageMode = paths.length > 1;
        _activeDocumentId = doc['id'];
        _currentStep = ScannerStep.filterSelection;
      });
      
      // Re-initialize PageController for page view
      _pageController = PageController(initialPage: 0);
    }
  }

  /// Delete document from history
  Future<void> _deleteDocument(int id) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(18),
          side: BorderSide(color: AppTheme.border),
        ),
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.redAccent.withValues(alpha: 0.12),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.delete_outline_rounded, color: Colors.redAccent, size: 20),
            ),
            const SizedBox(width: 10),
            Text(
              'លុបឯកសារ',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
          ],
        ),
        content: Text(
          'តើអ្នកពិតជាចង់លុបឯកសារនេះចេញពីប្រវត្តិមែនទេ?',
          style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.redAccent,
              foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              elevation: 0,
            ),
            onPressed: () => Navigator.pop(context, true),
            child: Text('លុប', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await _historyService.deleteDocument(id);
      await _loadRecentDocuments();
    }
  }

  /// Rename document in history
  Future<void> _renameDocument(int id, String currentName) async {
    final controller = TextEditingController(text: currentName);
    final newName = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(18),
          side: BorderSide(color: AppTheme.border),
        ),
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: const Color(0xFF0284C7).withValues(alpha: 0.12),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.edit_rounded, color: Color(0xFF0284C7), size: 20),
            ),
            const SizedBox(width: 10),
            Text(
              'ប្តូរឈ្មោះឯកសារ',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
          ],
        ),
        content: TextField(
          controller: controller,
          autofocus: true,
          style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 14),
          decoration: InputDecoration(
            hintText: 'បញ្ចូលឈ្មោះឯកសារថ្មី',
            hintStyle: GoogleFonts.kantumruyPro(color: AppTheme.textMuted),
            enabledBorder: UnderlineInputBorder(borderSide: BorderSide(color: AppTheme.border)),
            focusedBorder: const UnderlineInputBorder(borderSide: BorderSide(color: Color(0xFF0284C7), width: 1.5)),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF0284C7),
              foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              elevation: 0,
            ),
            onPressed: () => Navigator.pop(context, controller.text.trim()),
            child: Text('យល់ព្រម', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );

    if (newName != null && newName.isNotEmpty) {
      await _historyService.updateDocumentName(id, newName);
      await _loadRecentDocuments();
    }
  }

  /// Reset scanner to start over
  void _resetScanner() {
    setState(() {
      _currentStep = ScannerStep.selectImage;
      _scannedImagePath = null;
      _filteredImagePath = null;
      _scannedImagePaths = [];
      _pageRotations.clear();
      _isMultiPageMode = false;
      _currentPageIndex = 0;
      _ocrResult = null;
      _selectedFilter = ImageFilter.original;
      _errorMessage = null;
      _activeDocumentId = null;
    });
    _searchController.clear();
    _loadRecentDocuments();
    if (_pageController.hasClients) {
      _pageController.jumpToPage(0);
    }
  }

  /// Show all documents in a bottom sheet (grid view)
  void _showAllDocumentsSheet() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => DraggableScrollableSheet(
        initialChildSize: 0.75,
        minChildSize: 0.4,
        maxChildSize: 0.95,
        builder: (_, scrollController) => Container(
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(20)),
            border: Border.all(color: AppTheme.border),
          ),
          child: Column(
            children: [
              // Handle bar
              Container(
                margin: const EdgeInsets.only(top: 10, bottom: 12),
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: AppTheme.textMuted.withValues(alpha: 0.3),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              // Title
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
                child: Row(
                  children: [
                    Text(
                      'ឯកសារទាំងអស់ (${_recentDocuments.length})',
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary,
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const Spacer(),
                    IconButton(
                      icon: Icon(Icons.close_rounded, color: AppTheme.textSecondary, size: 20),
                      onPressed: () => Navigator.pop(ctx),
                    ),
                  ],
                ),
              ),
              Divider(color: AppTheme.border, height: 1),
              // Documents grid
              Expanded(
                child: _recentDocuments.isEmpty
                    ? Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(Icons.folder_open_rounded,
                                size: 56, color: AppTheme.textMuted.withValues(alpha: 0.4)),
                            const SizedBox(height: 12),
                            Text(
                              'មិនទាន់មានឯកសារទេ',
                              style: GoogleFonts.kantumruyPro(
                                  color: AppTheme.textMuted, fontSize: 14),
                            ),
                          ],
                        ),
                      )
                    : GridView.builder(
                        controller: scrollController,
                        padding: const EdgeInsets.all(16),
                        gridDelegate:
                            const SliverGridDelegateWithFixedCrossAxisCount(
                          crossAxisCount: 3,
                          mainAxisSpacing: 12,
                          crossAxisSpacing: 12,
                          childAspectRatio: 0.72,
                        ),
                        itemCount: _recentDocuments.length,
                        itemBuilder: (context, index) {
                          final doc = _recentDocuments[index];
                          final String title = doc['custom_name'] ?? 'គ្មានឈ្មោះ';
                          final String thumbnailPath = doc['thumbnail_path'] ?? '';
                          final thumbnailFile = File(thumbnailPath);
                          final bool fileExists = thumbnailFile.existsSync();
                          return GestureDetector(
                            onTap: () {
                              Navigator.pop(ctx);
                              _openDocument(doc);
                            },
                            child: Column(
                              children: [
                                Expanded(
                                  child: Container(
                                    decoration: BoxDecoration(
                                      color: AppTheme.bgSurface,
                                      borderRadius: BorderRadius.circular(10),
                                      border: Border.all(
                                          color: AppTheme.border),
                                    ),
                                    child: ClipRRect(
                                      borderRadius: BorderRadius.circular(9),
                                      child: fileExists
                                          ? Image.file(thumbnailFile, fit: BoxFit.cover)
                                          : Container(
                                              color: const Color(0xFF0D9488).withValues(alpha: 0.1),
                                              child: const Icon(
                                                Icons.description_rounded,
                                                color: Color(0xFF0D9488),
                                                size: 36,
                                              ),
                                            ),
                                    ),
                                  ),
                                ),
                                const SizedBox(height: 6),
                                Text(
                                  title,
                                  maxLines: 2,
                                  overflow: TextOverflow.ellipsis,
                                  textAlign: TextAlign.center,
                                  style: GoogleFonts.kantumruyPro(
                                    color: AppTheme.textPrimary,
                                    fontSize: 11,
                                    fontWeight: FontWeight.w500,
                                  ),
                                ),
                              ],
                            ),
                          );
                        },
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;
    final isDashboard = _currentStep == ScannerStep.selectImage;
    final showFab = isDashboard && !_isProcessing;
    return Scaffold(
      backgroundColor: isDark ? const Color(0xFF0F172A) : AppTheme.bgSurface,
      extendBodyBehindAppBar: false,
      appBar: VvcAppBar(
        backgroundColor: isDark ? const Color(0xFF0F172A) : AppTheme.bgSurface,
        elevation: 0,
        centerTitle: true,
        title: Text(
          _currentStep == ScannerStep.selectImage
              ? 'ស្កេនឯកសារ'
              : _currentStep == ScannerStep.filterSelection
                  ? 'កែតម្រូវពណ៌'
                  : 'លទ្ធផល',
          style: GoogleFonts.kantumruyPro(
            fontSize: 18,
            fontWeight: FontWeight.bold,
            color: isDark ? Colors.white : AppTheme.textPrimary,
          ),
        ),
        leading: IconButton(
          icon: Icon(
            Icons.arrow_back_ios_new_rounded,
            size: 20,
            color: isDark ? Colors.white : AppTheme.textPrimary,
          ),
          onPressed: () {
            if (_currentStep != ScannerStep.selectImage) {
              _resetScanner();
            } else {
              Navigator.pop(context);
            }
          },
        ),
        actions: [
          if (_currentStep != ScannerStep.selectImage)
            Padding(
              padding: const EdgeInsets.only(right: 16, top: 8, bottom: 8),
              child: IconButton(
                style: IconButton.styleFrom(
                  backgroundColor: isDark ? Colors.white.withValues(alpha: 0.08) : Colors.black.withValues(alpha: 0.05),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                icon: const Icon(Icons.refresh_rounded, size: 20),
                onPressed: _resetScanner,
                tooltip: 'Start Over',
                color: isDark ? Colors.white : AppTheme.textPrimary,
              ),
            ),
        ],
      ),
      body: SafeArea(
        child: _buildBody(),
      ),
      floatingActionButton: showFab
          ? FloatingActionButton.extended(
              onPressed: _openNativeScanner,
              backgroundColor: const Color(0xFF0284C7),
              elevation: 4,
              icon: const Icon(Icons.camera_alt_rounded, color: Colors.white, size: 22),
              label: Text(
                'ស្កេនថ្មី',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 13.5,
                ),
              ),
            )
          : null,
    );
  }

  Widget _buildBody() {
    if (_isProcessing) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const CircularProgressIndicator(
              valueColor: AlwaysStoppedAnimation<Color>(Colors.orange),
            ),
            const SizedBox(height: 20),
            Text(
              'កំពុងអានអក្សរខ្មែរ...',
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 15),
            ),
          ],
        ),
      );
    }

    // Never replace the Home Dashboard (selectImage) with full-screen error
    if (_errorMessage != null && _currentStep != ScannerStep.selectImage) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: Colors.red.withValues(alpha: 0.1),
                  shape: BoxShape.circle,
                ),
                child: const Icon(Icons.error_outline_rounded, size: 50, color: Colors.redAccent),
              ),
              const SizedBox(height: 24),
              Text(
                'មានបញ្ហាក្នុងការបើកកាមេរ៉ាស្កេន',
                style: GoogleFonts.kantumruyPro(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
              const SizedBox(height: 10),
              Text(
                _errorMessage!,
                textAlign: TextAlign.center,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.grey[400],
                  fontSize: 13,
                  height: 1.5,
                ),
              ),
              const SizedBox(height: 32),
              _buildGradientButton(
                icon: Icons.refresh_rounded,
                label: 'ព្យាយាមម្តងទៀត',
                onTap: _openNativeScanner,
                gradient: const LinearGradient(
                  colors: [Color(0xFFFF6B35), Color(0xFFFFB74D)],
                ),
              ),
              const SizedBox(height: 16),
              GestureDetector(
                onTap: _importFromGallery,
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.05),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(Icons.photo_library_rounded, size: 18, color: Colors.orangeAccent),
                      const SizedBox(width: 8),
                      Text(
                        'ជ្រើសរើសរូបភាពពីវិចិត្រសាល',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.orangeAccent,
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 20),
              TextButton(
                onPressed: _resetScanner,
                child: Text(
                  'ត្រឡប់ក្រោយ',
                  style: GoogleFonts.kantumruyPro(color: Colors.grey),
                ),
              ),
            ],
          ),
        ),
      );
    }

    switch (_currentStep) {
      case ScannerStep.selectImage:
        return _buildSelectImageStep();
      case ScannerStep.filterSelection:
        return _buildFilterSelectionStep();
      case ScannerStep.result:
        return _buildResultStep();
      case ScannerStep.edgeDetection:
      case ScannerStep.manualCrop:
        return _buildSelectImageStep(); // Fallback
    }
  }

  /// Step 1: CamScanner-style Dashboard with Search and History Scans
  Widget _buildSelectImageStep() {
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;
    return RefreshIndicator(
      onRefresh: () async {
        await _loadRecentDocuments();
      },
      color: const Color(0xFF0284C7),
      child: CustomScrollView(
        physics: const AlwaysScrollableScrollPhysics(
          parent: BouncingScrollPhysics(),
        ),
        slivers: [
          // 1. Clean Full-Width Search Bar
          SliverToBoxAdapter(
            child: _buildSearchBar(isDark),
          ),

          // 2. Hero Scan Feature Banner
          SliverToBoxAdapter(
            child: _buildHeroBanner(isDark),
          ),

          // 3. Quick Actions Surface Card (ឧបករណ៍ និងមុខងារជំនួយ)
          SliverToBoxAdapter(
            child: _buildQuickActionsCard(isDark),
          ),

          // 4. Recents Header
          SliverToBoxAdapter(
            child: _buildRecentsHeader(isDark),
          ),

          // 5. Recents List or Empty State
          if (_filteredDocuments.isEmpty)
            SliverToBoxAdapter(
              child: _buildEmptyState(isDark),
            )
          else
            SliverPadding(
              padding: const EdgeInsets.symmetric(horizontal: 16.0),
              sliver: SliverList(
                delegate: SliverChildBuilderDelegate(
                  (context, index) {
                    return _buildRecentCard(_filteredDocuments[index], isDark);
                  },
                  childCount: _filteredDocuments.length,
                ),
              ),
            ),

          // Bottom padding for FloatingActionButton
          const SliverToBoxAdapter(
            child: SizedBox(height: 85),
          ),
        ],
      ),
    );
  }

  /// 1. Modern Search Bar
  Widget _buildSearchBar(bool isDark) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 6),
      child: Container(
        height: 46,
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: AppTheme.border.withValues(alpha: isDark ? 0.6 : 0.9),
            width: 1,
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.2 : 0.03),
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: TextField(
          controller: _searchController,
          onChanged: _onSearchChanged,
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontSize: 13.5,
          ),
          cursorColor: const Color(0xFF0284C7),
          decoration: InputDecoration(
            hintText: 'ស្វែងរកឯកសារស្កេនតាមឈ្មោះ...',
            hintStyle: GoogleFonts.kantumruyPro(
              color: AppTheme.textMuted,
              fontSize: 13,
            ),
            prefixIcon: Icon(
              Icons.search_rounded,
              color: AppTheme.textMuted,
              size: 20,
            ),
            suffixIcon: _searchController.text.isNotEmpty
                ? IconButton(
                    icon: Icon(Icons.clear_rounded, size: 18, color: AppTheme.textMuted),
                    onPressed: () {
                      _searchController.clear();
                      _onSearchChanged('');
                    },
                  )
                : null,
            border: InputBorder.none,
            contentPadding: const EdgeInsets.symmetric(vertical: 12, horizontal: 14),
          ),
        ),
      ),
    );
  }

  /// 2. Hero Scan Feature Banner
  Widget _buildHeroBanner(bool isDark) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(22),
        gradient: LinearGradient(
          colors: isDark
              ? [const Color(0xFF1E293B), const Color(0xFF0F172A)]
              : [const Color(0xFF1E3A8A), const Color(0xFF0284C7)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        boxShadow: [
          BoxShadow(
            color: (isDark ? Colors.black : const Color(0xFF0284C7)).withValues(alpha: 0.25),
            blurRadius: 16,
            offset: const Offset(0, 6),
          ),
        ],
      ),
      child: Stack(
        children: [
          Positioned(
            right: -20,
            top: -20,
            child: Container(
              width: 120,
              height: 120,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: Colors.white.withValues(alpha: 0.08),
              ),
            ),
          ),
          Positioned(
            right: 40,
            bottom: -25,
            child: Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: Colors.white.withValues(alpha: 0.05),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(18.0),
            child: Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.18),
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(color: Colors.white.withValues(alpha: 0.25)),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.auto_awesome_rounded, color: Color(0xFFFDE047), size: 12),
                            const SizedBox(width: 4),
                            Text(
                              'ស្កេនរហ័ស & ច្បាស់កម្រិត HD',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white,
                                fontSize: 10.5,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'ស្កេនឯកសារឆ្លាតវៃ',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                          letterSpacing: 0.2,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'កាត់គែមស្វ័យប្រវត្តិ តម្រង់ក្រដាស និងបម្លែងជា PDF ភ្លាមៗ',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white.withValues(alpha: 0.85),
                          fontSize: 11.5,
                          height: 1.35,
                        ),
                      ),
                      const SizedBox(height: 14),
                      Row(
                        children: [
                          GestureDetector(
                            onTap: _openNativeScanner,
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                              decoration: BoxDecoration(
                                color: Colors.white,
                                borderRadius: BorderRadius.circular(12),
                                boxShadow: [
                                  BoxShadow(
                                    color: Colors.black.withValues(alpha: 0.12),
                                    blurRadius: 6,
                                    offset: const Offset(0, 2),
                                  ),
                                ],
                              ),
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  const Icon(Icons.camera_alt_rounded, color: Color(0xFF1E3A8A), size: 16),
                                  const SizedBox(width: 6),
                                  Text(
                                    'ស្កេនឥឡូវ',
                                    style: GoogleFonts.kantumruyPro(
                                      color: const Color(0xFF1E3A8A),
                                      fontSize: 12,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                          const SizedBox(width: 8),
                          GestureDetector(
                            onTap: _importFromGallery,
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                              decoration: BoxDecoration(
                                color: Colors.white.withValues(alpha: 0.15),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: Colors.white.withValues(alpha: 0.3)),
                              ),
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  const Icon(Icons.photo_library_rounded, color: Colors.white, size: 15),
                                  const SizedBox(width: 6),
                                  Text(
                                    'ជ្រើសរូបភាព',
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.white,
                                      fontSize: 12,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                Container(
                  width: 66,
                  height: 66,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: Colors.white.withValues(alpha: 0.12),
                    border: Border.all(color: Colors.white.withValues(alpha: 0.3), width: 1.5),
                  ),
                  child: const Center(
                    child: Icon(
                      Icons.document_scanner_rounded,
                      size: 34,
                      color: Colors.white,
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

  /// 3. Quick Actions Surface Card
  Widget _buildQuickActionsCard(bool isDark) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      padding: const EdgeInsets.fromLTRB(14, 14, 14, 16),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppTheme.border.withValues(alpha: isDark ? 0.6 : 0.8)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.25 : 0.03),
            blurRadius: 12,
            offset: const Offset(0, 3),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(left: 4, bottom: 12),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(6),
                  decoration: BoxDecoration(
                    color: const Color(0xFF0D9488).withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(
                    Icons.widgets_rounded,
                    size: 16,
                    color: Color(0xFF0D9488),
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  'ឧបករណ៍ និងមុខងារជំនួយ',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontSize: 13.5,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
          ),
          _buildQuickActionsGrid(isDark),
        ],
      ),
    );
  }

  /// Grid view for Quick Actions (2 rows x 4 columns) - Clean & Balanced
  Widget _buildQuickActionsGrid(bool isDark) {
    return Column(
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            _buildQuickActionItem(
              icon: Icons.document_scanner_rounded,
              label: 'ស្កេនឆ្លាតវៃ',
              color: const Color(0xFF0D9488),
              onTap: _openNativeScanner,
              isDark: isDark,
            ),
            _buildQuickActionItem(
              icon: Icons.transform_rounded,
              label: 'បំប្លែងឯកសារ',
              color: const Color(0xFF6366F1),
              onTap: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const DocumentConverterScreen(),
                  ),
                );
              },
              isDark: isDark,
            ),
            _buildQuickActionItem(
              icon: Icons.auto_awesome_rounded,
              label: 'ស្កេន AI ខ្មែរ',
              color: const Color(0xFF8B5CF6),
              onTap: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const DocumentConverterScreen(
                      initialTool: ConverterTool.geminiKhmerDocx,
                    ),
                  ),
                );
              },
              isDark: isDark,
            ),
            _buildQuickActionItem(
              icon: Icons.add_photo_alternate_rounded,
              label: 'នាំចូលរូបភាព',
              color: const Color(0xFF2563EB),
              onTap: _importFromGallery,
              isDark: isDark,
            ),
          ],
        ),
        const SizedBox(height: 12),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            _buildQuickActionItem(
              icon: Icons.picture_as_pdf_rounded,
              label: 'ឧបករណ៍ PDF',
              color: const Color(0xFFE11D48),
              onTap: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const DocumentConverterScreen(
                      initialTool: ConverterTool.imageToPdf,
                    ),
                  ),
                );
              },
              isDark: isDark,
            ),
            _buildQuickActionItem(
              icon: Icons.badge_rounded,
              label: 'រូប 4x6 / 3x4',
              color: const Color(0xFF0284C7),
              onTap: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => PassportPhotoScreen(
                      initialImagePath: _scannedImagePaths.isNotEmpty ? _scannedImagePaths[_currentPageIndex] : null,
                    ),
                  ),
                );
              },
              isDark: isDark,
            ),
            _buildQuickActionItem(
              icon: Icons.draw_rounded,
              label: 'សរសេរដៃ',
              color: const Color(0xFFD97706),
              onTap: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const DigitalInkScreen()),
                );
              },
              isDark: isDark,
            ),
            _buildQuickActionItem(
              icon: Icons.grid_view_rounded,
              label: 'ទាំងអស់',
              color: const Color(0xFF475569),
              onTap: _showAllDocumentsSheet,
              isDark: isDark,
            ),
          ],
        ),
      ],
    );
  }

  /// Individual Quick Action item builder
  Widget _buildQuickActionItem({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
    required bool isDark,
  }) {
    return Expanded(
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(14),
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 6.0, horizontal: 2.0),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: isDark ? 0.18 : 0.1),
                    borderRadius: BorderRadius.circular(15),
                    border: Border.all(
                      color: color.withValues(alpha: isDark ? 0.35 : 0.22),
                      width: 1.2,
                    ),
                  ),
                  child: Icon(icon, color: color, size: 23),
                ),
                const SizedBox(height: 7),
                Text(
                  label,
                  textAlign: TextAlign.center,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  /// 4. Recents Header
  Widget _buildRecentsHeader(bool isDark) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 16, 18, 10),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              Text(
                'ឯកសារថ្មីៗ',
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(
                  color: const Color(0xFF0284C7).withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  '${_filteredDocuments.length}',
                  style: GoogleFonts.kantumruyPro(
                    color: const Color(0xFF0284C7),
                    fontSize: 11.5,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          ),
          if (_searchController.text.isNotEmpty)
            GestureDetector(
              onTap: () {
                _searchController.clear();
                _onSearchChanged('');
              },
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 4, horizontal: 8),
                child: Text(
                  'សម្អាត',
                  style: GoogleFonts.kantumruyPro(
                    color: const Color(0xFF0284C7),
                    fontSize: 12.5,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            )
          else if (_recentDocuments.isNotEmpty)
            GestureDetector(
              onTap: _showAllDocumentsSheet,
              child: Row(
                children: [
                  Text(
                    'មើលទាំងអស់',
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFF0284C7),
                      fontSize: 12.5,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(width: 2),
                  const Icon(Icons.chevron_right_rounded, size: 18, color: Color(0xFF0284C7)),
                ],
              ),
            ),
        ],
      ),
    );
  }

  /// 5. Recent Document Card
  Widget _buildRecentCard(Map<String, dynamic> doc, bool isDark) {
    final int id = doc['id'] as int;
    final String title = doc['custom_name'] ?? 'គ្មានឈ្មោះ';
    final int pageCount = doc['page_count'] ?? 1;
    final String thumbnailPath = doc['thumbnail_path'] ?? '';
    final String dateStr = doc['scan_date'] ?? '';

    String formattedDate = dateStr;
    try {
      final dateTime = DateTime.parse(dateStr);
      formattedDate =
          '${dateTime.year}-${dateTime.month.toString().padLeft(2, '0')}-${dateTime.day.toString().padLeft(2, '0')} ${dateTime.hour.toString().padLeft(2, '0')}:${dateTime.minute.toString().padLeft(2, '0')}';
    } catch (_) {}

    final thumbnailFile = File(thumbnailPath);
    final bool fileExists = thumbnailFile.existsSync();

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: AppTheme.border.withValues(alpha: isDark ? 0.6 : 0.8),
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.2 : 0.03),
            blurRadius: 10,
            offset: const Offset(0, 3),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: () => _openDocument(doc),
          borderRadius: BorderRadius.circular(16),
          child: Padding(
            padding: const EdgeInsets.all(12.0),
            child: Row(
              children: [
                // Thumbnail with rounded corners
                Container(
                  width: 56,
                  height: 56,
                  decoration: BoxDecoration(
                    color: AppTheme.bgSurface,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: AppTheme.border),
                  ),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(11),
                    child: fileExists
                        ? Image.file(thumbnailFile, fit: BoxFit.cover)
                        : Container(
                            color: const Color(0xFF0D9488).withValues(alpha: 0.1),
                            child: const Icon(
                              Icons.description_rounded,
                              color: Color(0xFF0D9488),
                              size: 28,
                            ),
                          ),
                  ),
                ),
                const SizedBox(width: 14),

                // Title and Details
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontSize: 14,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Row(
                        children: [
                          Icon(
                            Icons.access_time_rounded,
                            size: 12,
                            color: AppTheme.textMuted,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            formattedDate,
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.textMuted,
                              fontSize: 11.5,
                            ),
                          ),
                          const SizedBox(width: 10),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: const Color(0xFF0284C7).withValues(alpha: 0.1),
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const Icon(Icons.file_copy_outlined, size: 10, color: Color(0xFF0284C7)),
                                const SizedBox(width: 4),
                                Text(
                                  '$pageCount ទំព័រ',
                                  style: GoogleFonts.kantumruyPro(
                                    color: const Color(0xFF0284C7),
                                    fontSize: 10.5,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),

                // Action Menu
                PopupMenuButton<String>(
                  icon: Container(
                    padding: const EdgeInsets.all(6),
                    decoration: BoxDecoration(
                      color: AppTheme.bgSurface,
                      shape: BoxShape.circle,
                    ),
                    child: Icon(Icons.more_vert_rounded, color: AppTheme.textSecondary, size: 18),
                  ),
                  color: AppTheme.bgCard,
                  elevation: 4,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14),
                    side: BorderSide(color: AppTheme.border),
                  ),
                  onSelected: (action) {
                    if (action == 'open') {
                      _openDocument(doc);
                    } else if (action == 'rename') {
                      _renameDocument(id, title);
                    } else if (action == 'delete') {
                      _deleteDocument(id);
                    }
                  },
                  itemBuilder: (context) => [
                    PopupMenuItem(
                      value: 'open',
                      child: Row(
                        children: [
                          Icon(Icons.visibility_outlined, color: AppTheme.textSecondary, size: 16),
                          const SizedBox(width: 8),
                          Text('បើកមើល', style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 13)),
                        ],
                      ),
                    ),
                    PopupMenuItem(
                      value: 'rename',
                      child: Row(
                        children: [
                          Icon(Icons.drive_file_rename_outline_rounded, color: AppTheme.textSecondary, size: 16),
                          const SizedBox(width: 8),
                          Text('ប្តូរឈ្មោះ', style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 13)),
                        ],
                      ),
                    ),
                    PopupMenuItem(
                      value: 'delete',
                      child: Row(
                        children: [
                          const Icon(Icons.delete_outline_rounded, color: Colors.redAccent, size: 16),
                          const SizedBox(width: 8),
                          Text('លុប', style: GoogleFonts.kantumruyPro(color: Colors.redAccent, fontSize: 13)),
                        ],
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }


  /// 6. Empty State Card
  Widget _buildEmptyState(bool isDark) {
    final hasSearch = _searchController.text.isNotEmpty;
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppTheme.border.withValues(alpha: isDark ? 0.6 : 0.8)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.2 : 0.03),
            blurRadius: 10,
            offset: const Offset(0, 3),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 68,
            height: 68,
            decoration: BoxDecoration(
              color: (hasSearch ? const Color(0xFFE11D48) : const Color(0xFF0284C7)).withValues(alpha: 0.1),
              shape: BoxShape.circle,
            ),
            child: Icon(
              hasSearch ? Icons.search_off_rounded : Icons.document_scanner_outlined,
              size: 36,
              color: hasSearch ? const Color(0xFFE11D48) : const Color(0xFF0284C7),
            ),
          ),
          const SizedBox(height: 16),
          Text(
            hasSearch ? 'រកមិនឃើញឯកសារដែលត្រូវគ្នាទេ' : 'មិនទាន់មានឯកសារស្កេននៅឡើយទេ',
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary,
              fontSize: 15,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            hasSearch
                ? 'សូមសាកល្បងស្វែងរកឈ្មោះផ្សេងទៀត ឬសម្អាតការស្វែងរក'
                : 'ស្កេនឯកសារ វិក្កយបត្រ ឬលិខិតស្នាមផ្សេងៗ ដើម្បីរក្សាទុក និងបម្លែងជា PDF យ៉ាងងាយស្រួល',
            textAlign: TextAlign.center,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textSecondary,
              fontSize: 12.5,
              height: 1.4,
            ),
          ),
          const SizedBox(height: 20),
          if (hasSearch)
            ElevatedButton.icon(
              onPressed: () {
                _searchController.clear();
                _onSearchChanged('');
              },
              icon: const Icon(Icons.refresh_rounded, size: 16),
              label: Text(
                'សម្អាតការស្វែងរក',
                style: GoogleFonts.kantumruyPro(fontSize: 13, fontWeight: FontWeight.bold),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF0284C7),
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                elevation: 0,
              ),
            )
          else
            ElevatedButton.icon(
              onPressed: _openNativeScanner,
              icon: const Icon(Icons.camera_alt_rounded, size: 18),
              label: Text(
                'ចាប់ផ្ដើមស្កេនឥឡូវនេះ',
                style: GoogleFonts.kantumruyPro(fontSize: 13.5, fontWeight: FontWeight.bold),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF0284C7),
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                elevation: 2,
              ),
            ),
        ],
      ),
    );
  }

  /// Step 2: CamScanner-style Filter Edit Screen (Theme-aware Studio Canvas)
  Widget _buildFilterSelectionStep() {
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;
    return Column(
      children: [
        // ── 1. Large image preview (Canvas) ───────────────────────────
        Expanded(
          child: Stack(
            children: [
              Container(
                color: isDark ? const Color(0xFF090D16) : const Color(0xFFF1F5F9), // Theme-adaptive studio canvas
                child: _scannedImagePaths.isNotEmpty
                    ? PageView.builder(
                        controller: _pageController,
                        onPageChanged: (index) {
                          setState(() {
                            _currentPageIndex = index;
                            _filteredImagePath = _scannedImagePaths[index];
                          });
                        },
                        itemCount: _scannedImagePaths.length,
                        itemBuilder: (context, index) {
                          final rotation = _pageRotations[index] ?? 0;
                          return InteractiveViewer(
                            minScale: 0.5,
                            maxScale: 4.0,
                            child: Center(
                              child: Container(
                                margin: const EdgeInsets.all(16),
                                decoration: BoxDecoration(
                                  borderRadius: BorderRadius.circular(6),
                                  boxShadow: [
                                    BoxShadow(
                                      color: Colors.black.withValues(alpha: isDark ? 0.65 : 0.15),
                                      blurRadius: 24,
                                      offset: const Offset(0, 8),
                                    ),
                                  ],
                                ),
                                child: Transform.rotate(
                                  angle: rotation * (math.pi / 180),
                                  child: ColorFiltered(
                                    colorFilter: _getColorFilter(_selectedFilter),
                                    child: Image.file(
                                      File(_scannedImagePaths[index]),
                                      fit: BoxFit.contain,
                                    ),
                                  ),
                                ),
                              ),
                            ),
                          );
                        },
                      )
                    : Center(
                        child: Icon(Icons.image_not_supported_rounded,
                            size: 60, color: isDark ? Colors.white24 : AppTheme.textMuted),
                      ),
              ),

              // Delete current page button (top-left) - shown when multi-page
              if (_scannedImagePaths.length > 1)
                Positioned(
                  top: 14,
                  left: 14,
                  child: GestureDetector(
                    onTap: () async {
                      setState(() {
                        _scannedImagePaths.removeAt(_currentPageIndex);
                        if (_currentPageIndex >= _scannedImagePaths.length) {
                          _currentPageIndex = _scannedImagePaths.length - 1;
                        }
                        _filteredImagePath = _scannedImagePaths[_currentPageIndex];
                        _isMultiPageMode = _scannedImagePaths.length > 1;
                      });
                      WidgetsBinding.instance.addPostFrameCallback((_) {
                        if (_pageController.hasClients) {
                          _pageController.jumpToPage(_currentPageIndex);
                        }
                      });
                    },
                    child: Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: isDark ? const Color(0xFF1E293B).withValues(alpha: 0.9) : Colors.white.withValues(alpha: 0.95),
                        shape: BoxShape.circle,
                        border: Border.all(color: AppTheme.border),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withValues(alpha: 0.08),
                            blurRadius: 6,
                          ),
                        ],
                      ),
                      child: const Icon(Icons.delete_outline_rounded,
                          color: Colors.redAccent, size: 20),
                    ),
                  ),
                ),
            ],
          ),
        ),

        // ── 2. Page navigation bar ─────────────────────────────────────
        Container(
          padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 16),
          decoration: BoxDecoration(
            color: isDark ? const Color(0xFF0F172A) : AppTheme.bgCard,
            border: Border(
              top: BorderSide(color: AppTheme.border.withValues(alpha: isDark ? 0.6 : 0.8)),
              bottom: BorderSide(color: AppTheme.border.withValues(alpha: isDark ? 0.6 : 0.8)),
            ),
          ),
          child: Row(
            children: [
              // Previous page button
              IconButton(
                icon: Icon(Icons.chevron_left_rounded,
                    color: isDark ? Colors.white : AppTheme.textPrimary, size: 26),
                onPressed: _currentPageIndex > 0
                    ? () {
                        _pageController.previousPage(
                          duration: const Duration(milliseconds: 250),
                          curve: Curves.easeInOut,
                        );
                      }
                    : null,
              ),
              // Page count indicator
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 5),
                decoration: BoxDecoration(
                  color: isDark ? const Color(0xFF1E293B) : const Color(0xFFF8FAFC),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: AppTheme.border),
                ),
                child: Text(
                  _scannedImagePaths.isNotEmpty
                      ? '${_currentPageIndex + 1}/${_scannedImagePaths.length}'
                      : '0/0',
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? Colors.white : AppTheme.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              // Next page button
              IconButton(
                icon: Icon(Icons.chevron_right_rounded,
                    color: isDark ? Colors.white : AppTheme.textPrimary, size: 26),
                onPressed: _currentPageIndex < _scannedImagePaths.length - 1
                    ? () {
                        _pageController.nextPage(
                          duration: const Duration(milliseconds: 250),
                          curve: Curves.easeInOut,
                        );
                      }
                    : null,
              ),
              const Spacer(),
              // "រៀបចំជួរ" / Arrange pages button
              GestureDetector(
                onTap: _openNativeScanner,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  decoration: BoxDecoration(
                    color: isDark ? const Color(0xFF1E293B) : const Color(0xFFF8FAFC),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: AppTheme.border),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.grid_view_rounded,
                          color: Color(0xFF0284C7), size: 15),
                      const SizedBox(width: 6),
                      Text(
                        'រៀបចំជួរ',
                        style: GoogleFonts.kantumruyPro(
                          color: isDark ? Colors.white : AppTheme.textPrimary,
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),

        // ── 3. Filter thumbnail strip ──────────────────────────────────
        Container(
          height: 94,
          decoration: BoxDecoration(
            color: isDark ? const Color(0xFF0F172A) : AppTheme.bgCard,
            border: Border(
              bottom: BorderSide(color: AppTheme.border.withValues(alpha: isDark ? 0.6 : 0.8)),
            ),
          ),
          child: ListView.builder(
            scrollDirection: Axis.horizontal,
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
            itemCount: ImageFilter.values.length,
            itemBuilder: (context, index) {
              final filter = ImageFilter.values[index];
              final isSelected = _selectedFilter == filter;
              final currentRotation = _pageRotations[_currentPageIndex] ?? 0;
              return GestureDetector(
                onTap: () => _applyFilter(filter),
                child: Container(
                  width: 68,
                  margin: const EdgeInsets.only(right: 10),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                      color: isSelected
                          ? const Color(0xFF0284C7)
                          : (isDark ? const Color(0xFF1E293B) : AppTheme.border),
                      width: isSelected ? 2.5 : 1,
                    ),
                    boxShadow: isSelected
                        ? [
                            BoxShadow(
                              color: const Color(0xFF0284C7).withValues(alpha: 0.35),
                              blurRadius: 8,
                              offset: const Offset(0, 2),
                            ),
                          ]
                        : null,
                  ),
                  child: Stack(
                    children: [
                      ClipRRect(
                        borderRadius: BorderRadius.circular(8),
                        child: _scannedImagePaths.isNotEmpty
                            ? ColorFiltered(
                                colorFilter: _getColorFilter(filter),
                                child: Transform.rotate(
                                  angle: currentRotation * (math.pi / 180),
                                  child: Image.file(
                                    File(_scannedImagePaths[_currentPageIndex]),
                                    width: 68,
                                    height: 76,
                                    fit: BoxFit.cover,
                                  ),
                                ),
                              )
                            : Container(
                                color: isDark ? Colors.white.withValues(alpha: 0.05) : const Color(0xFFF1F5F9),
                                width: 68,
                                height: 76,
                                child: Icon(Icons.image_rounded,
                                    color: isDark ? Colors.white24 : AppTheme.textMuted),
                              ),
                      ),
                      Positioned(
                        left: 0,
                        right: 0,
                        bottom: 0,
                        child: Container(
                          padding: const EdgeInsets.symmetric(vertical: 3),
                          decoration: BoxDecoration(
                            color: isSelected
                                ? const Color(0xFF0284C7)
                                : Colors.black.withValues(alpha: 0.7),
                            borderRadius: const BorderRadius.vertical(
                                bottom: Radius.circular(8)),
                          ),
                          child: Text(
                            _getFilterLabel(filter),
                            textAlign: TextAlign.center,
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 10,
                              fontWeight: isSelected
                                  ? FontWeight.bold
                                  : FontWeight.w500,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              );
            },
          ),
        ),

        // ── 4. Bottom action toolbar ───────────────────────────────────
        Container(
          padding: EdgeInsets.only(
            left: 10,
            right: 14,
            top: 10,
            bottom: MediaQuery.of(context).padding.bottom + 10,
          ),
          decoration: BoxDecoration(
            color: isDark ? const Color(0xFF0B0F19) : AppTheme.bgCard,
            border: Border(
              top: BorderSide(color: AppTheme.border.withValues(alpha: isDark ? 0.6 : 0.8)),
            ),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              // Add Page
              _buildToolbarItem(
                icon: Icons.add_photo_alternate_rounded,
                label: 'បន្ថែមទំព័រ',
                onTap: _openNativeScanner,
                isDark: isDark,
              ),
              // Crop
              _buildToolbarItem(
                icon: Icons.crop_rounded,
                label: 'កាត់គែម',
                onTap: _cropCurrentImage,
                isDark: isDark,
              ),
              // Rotate
              _buildToolbarItem(
                icon: Icons.rotate_right_rounded,
                label: 'បង្វិល',
                onTap: () {
                  setState(() {
                    final currentRot = _pageRotations[_currentPageIndex] ?? 0;
                    _pageRotations[_currentPageIndex] = (currentRot + 90) % 360;
                  });
                },
                isDark: isDark,
              ),
              // OCR
              _buildToolbarItem(
                icon: Icons.document_scanner_rounded,
                label: 'ស្រង់អក្សរ',
                onTap: _extractText,
                iconColor: const Color(0xFF38BDF8),
                isDark: isDark,
              ),
              // Save to Phone (Direct 1-tap save)
              _buildToolbarItem(
                icon: Icons.download_rounded,
                label: 'រក្សាទុក',
                onTap: _quickSaveCurrentToPhone,
                iconColor: const Color(0xFF10B981),
                isDark: isDark,
              ),
              // Confirm / Done FAB
              GestureDetector(
                onTap: _exportToPDF,
                child: Container(
                  width: 52,
                  height: 52,
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [Color(0xFF0284C7), Color(0xFF0A84FF)],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFF0284C7).withValues(alpha: 0.45),
                        blurRadius: 14,
                        offset: const Offset(0, 4),
                      ),
                    ],
                  ),
                  child: const Icon(
                    Icons.check_rounded,
                    color: Colors.white,
                    size: 28,
                  ),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  /// Modern Bottom toolbar icon item
  Widget _buildToolbarItem({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
    Color? iconColor,
    required bool isDark,
  }) {
    final finalIconColor = iconColor ?? (isDark ? Colors.white : AppTheme.textPrimary);
    return GestureDetector(
      onTap: onTap,
      behavior: HitTestBehavior.opaque,
      child: SizedBox(
        width: 54,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                color: isDark ? const Color(0xFF1E293B) : const Color(0xFFF1F5F9),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: isDark ? const Color(0xFF334155).withValues(alpha: 0.6) : AppTheme.border,
                ),
              ),
              child: Icon(icon, color: finalIconColor, size: 20),
            ),
            const SizedBox(height: 5),
            Text(
              label,
              textAlign: TextAlign.center,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: GoogleFonts.kantumruyPro(
                color: isDark ? const Color(0xFF94A3B8) : AppTheme.textMuted,
                fontSize: 10,
                fontWeight: FontWeight.w500,
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Returns a ColorFilter based on the selected ImageFilter
  ColorFilter _getColorFilter(ImageFilter filter) {
    switch (filter) {
      case ImageFilter.original:
        return const ColorFilter.mode(Colors.transparent, BlendMode.dst);
      case ImageFilter.magicColor:
        // Enhanced contrast, whiter paper background, and vibrant colored seals/ink
        return const ColorFilter.matrix(<double>[
          1.55,  0.0,  0.0, 0.0, -25,
          0.0,  1.55,  0.0, 0.0, -25,
          0.0,  0.0,  1.55, 0.0, -25,
          0.0,  0.0,  0.0, 1.0,   0,
        ]);
      case ImageFilter.blackAndWhite:
        // Clean High-Contrast Document B&W
        return const ColorFilter.matrix(<double>[
          0.7,  0.7,  0.7, 0.0, -110,
          0.7,  0.7,  0.7, 0.0, -110,
          0.7,  0.7,  0.7, 0.0, -110,
          0.0,  0.0,  0.0, 1.0,    0,
        ]);
      case ImageFilter.enhanced:
        // High Definition text sharpening & contrast
        return const ColorFilter.matrix(<double>[
          1.7, -0.35, -0.35, 0.0, -15,
         -0.35,  1.7, -0.35, 0.0, -15,
         -0.35, -0.35,  1.7, 0.0, -15,
          0.0,   0.0,   0.0, 1.0,   0,
        ]);
    }
  }

  Widget _buildGradientButton({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
    required LinearGradient gradient,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          gradient: gradient,
          borderRadius: BorderRadius.circular(12),
          boxShadow: [
            BoxShadow(
              color: const Color(0xFFFF6B35).withValues(alpha: 0.3),
              blurRadius: 12,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, size: 20, color: Colors.white),
            const SizedBox(width: 8),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 13,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Step 3: Result UI
  Widget _buildResultStep() {
    return DefaultTabController(
      length: 2,
      child: Column(
        children: [
          const TabBar(
            tabs: [
              Tab(text: 'Image', icon: Icon(Icons.image)),
              Tab(text: 'Text', icon: Icon(Icons.text_fields)),
            ],
          ),
          Expanded(
            child: TabBarView(
              children: [
                // Image tab
                _filteredImagePath != null
                    ? Image.file(
                        File(_filteredImagePath!),
                        fit: BoxFit.contain,
                      )
                    : const Center(child: Text('No image')),
                // Text tab
                _ocrResult != null
                    ? SingleChildScrollView(
                        padding: const EdgeInsets.all(16),
                        child: Text(
                          _ocrResult!.fullText,
                          style: const TextStyle(color: Colors.white),
                        ),
                      )
                    : const Center(
                        child: Text(
                          'No text extracted',
                          style: TextStyle(color: Colors.grey),
                        ),
                      ),
              ],
            ),
          ),
          Container(
            padding: EdgeInsets.only(
              left: 20,
              right: 20,
              bottom: MediaQuery.of(context).padding.bottom + 20,
            ),
            child: _buildGradientButton(
              icon: Icons.picture_as_pdf_rounded,
              label: 'នាំចេញ PDF',
              onTap: _exportToPDF,
              gradient: const LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [Color(0xFF6C63FF), Color(0xFF48CAE4)],
              ),
            ),
          ),
        ],
      ),
    );
  }

  String _getFilterLabel(ImageFilter filter) {
    switch (filter) {
      case ImageFilter.original:
        return 'ដើម';
      case ImageFilter.magicColor:
        return 'ពណ៌ Magic';
      case ImageFilter.blackAndWhite:
        return 'ខ្មៅ-ស';
      case ImageFilter.enhanced:
        return 'ច្បាស់ឡើង';
    }
  }
}

/// Scanner workflow steps
enum ScannerStep {
  selectImage,
  edgeDetection,
  manualCrop,
  filterSelection,
  result,
}

/// Available image filters
enum ImageFilter {
  original,
  magicColor,
  blackAndWhite,
  enhanced,
}

/// Interactive Image Cropper Dialog with 4-Corner Perspective Unwarping (CamScanner Style)
class ImageCropperDialog extends StatefulWidget {
  final String imagePath;
  final int initialRotation;

  const ImageCropperDialog({
    super.key,
    required this.imagePath,
    this.initialRotation = 0,
  });

  @override
  State<ImageCropperDialog> createState() => _ImageCropperDialogState();
}

class _ImageCropperDialogState extends State<ImageCropperDialog> {
  // 4 corners normalized (0.0 to 1.0): Top-Left, Top-Right, Bottom-Right, Bottom-Left
  Offset _tl = const Offset(0.02, 0.02);
  Offset _tr = const Offset(0.98, 0.02);
  Offset _br = const Offset(0.98, 0.98);
  Offset _bl = const Offset(0.02, 0.98);
  bool _isProcessing = false;
  int? _imageWidth;
  int? _imageHeight;

  @override
  void initState() {
    super.initState();
    _loadImageDimensions();
  }

  Future<void> _loadImageDimensions() async {
    try {
      final bytes = await File(widget.imagePath).readAsBytes();
      final decoded = img.decodeImage(bytes);
      if (decoded != null && mounted) {
        setState(() {
          if (widget.initialRotation % 180 != 0) {
            _imageWidth = decoded.height;
            _imageHeight = decoded.width;
          } else {
            _imageWidth = decoded.width;
            _imageHeight = decoded.height;
          }
        });
      }
    } catch (_) {}
  }

  void _resetCrop() {
    setState(() {
      _tl = const Offset(0.0, 0.0);
      _tr = const Offset(1.0, 0.0);
      _br = const Offset(1.0, 1.0);
      _bl = const Offset(0.0, 1.0);
    });
  }

  void _applyDefaultAutoQuad() {
    setState(() {
      _tl = const Offset(0.02, 0.02);
      _tr = const Offset(0.98, 0.02);
      _br = const Offset(0.98, 0.98);
      _bl = const Offset(0.02, 0.98);
    });
  }

  void _applyAspectRatio(double? ratio) {
    if (ratio == null) {
      _resetCrop();
      return;
    }
    setState(() {
      double w = 0.92;
      double h = w / ratio;
      if (h > 0.92) {
        h = 0.92;
        w = h * ratio;
      }
      double left = 0.5 - w / 2;
      double right = 0.5 + w / 2;
      double top = 0.5 - h / 2;
      double bottom = 0.5 + h / 2;

      _tl = Offset(left, top);
      _tr = Offset(right, top);
      _br = Offset(right, bottom);
      _bl = Offset(left, bottom);
    });
  }

  Future<void> _confirmCrop() async {
    setState(() {
      _isProcessing = true;
    });

    try {
      final bytes = await File(widget.imagePath).readAsBytes();
      img.Image? decoded = img.decodeImage(bytes);
      if (decoded == null) {
        if (mounted) Navigator.pop(context, null);
        return;
      }

      if (widget.initialRotation != 0) {
        decoded = img.copyRotate(decoded, angle: widget.initialRotation);
      }

      final double imgW = decoded.width.toDouble();
      final double imgH = decoded.height.toDouble();

      final pTL = Offset((_tl.dx * imgW).clamp(0.0, imgW - 1), (_tl.dy * imgH).clamp(0.0, imgH - 1));
      final pTR = Offset((_tr.dx * imgW).clamp(0.0, imgW - 1), (_tr.dy * imgH).clamp(0.0, imgH - 1));
      final pBR = Offset((_br.dx * imgW).clamp(0.0, imgW - 1), (_br.dy * imgH).clamp(0.0, imgH - 1));
      final pBL = Offset((_bl.dx * imgW).clamp(0.0, imgW - 1), (_bl.dy * imgH).clamp(0.0, imgH - 1));

      final unwarped = _warpPerspective(decoded, pTL, pTR, pBR, pBL);

      final tempDir = await getTemporaryDirectory();
      final outPath = '${tempDir.path}/unwarped_${DateTime.now().millisecondsSinceEpoch}.jpg';
      // Save with Ultra-HD Quality 98% to preserve full sharpness
      final croppedJpg = img.encodeJpg(unwarped, quality: 98);
      final outFile = File(outPath);
      await outFile.writeAsBytes(croppedJpg);

      if (mounted) {
        Navigator.pop(context, outPath);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('តម្រង់រូបភាពមិនបានជោគជ័យ៖ $e', style: GoogleFonts.kantumruyPro())),
        );
        Navigator.pop(context, null);
      }
    }
  }

  /// 4-Point Homography Perspective Transform Algorithm
  img.Image _warpPerspective(img.Image src, Offset pTL, Offset pTR, Offset pBR, Offset pBL) {
    final double x0 = pTL.dx, y0 = pTL.dy;
    final double x1 = pTR.dx, y1 = pTR.dy;
    final double x2 = pBR.dx, y2 = pBR.dy;
    final double x3 = pBL.dx, y3 = pBL.dy;

    final double w1 = math.sqrt((x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0));
    final double w2 = math.sqrt((x2 - x3) * (x2 - x3) + (y2 - y3) * (y2 - y3));
    final int dstW = math.max(10, math.max(w1, w2).round());

    final double h1 = math.sqrt((x3 - x0) * (x3 - x0) + (y3 - y0) * (y3 - y0));
    final double h2 = math.sqrt((x2 - x1) * (x2 - x1) + (y2 - y1) * (y2 - y1));
    final int dstH = math.max(10, math.max(h1, h2).round());

    final double dx = x0 - x1 + x2 - x3;
    final double dy = y0 - y1 + y2 - y3;

    final double a = dstW * (x2 - x1);
    final double b = dstH * (x2 - x3);
    final double c = dstW * (y2 - y1);
    final double d = dstH * (y2 - y3);

    final double det = a * d - b * c;

    double h20 = 0.0;
    double h21 = 0.0;
    if (det.abs() > 1e-7) {
      h20 = (dx * d - b * dy) / det;
      h21 = (a * dy - dx * c) / det;
    }

    final double h00 = (x1 - x0 + dstW * x1 * h20) / dstW;
    final double h10 = (y1 - y0 + dstW * y1 * h20) / dstW;
    final double h01 = (x3 - x0 + dstH * x3 * h21) / dstH;
    final double h11 = (y3 - y0 + dstH * y3 * h21) / dstH;
    final double h02 = x0;
    final double h12 = y0;

    final img.Image dst = img.Image(width: dstW, height: dstH);
    final int srcW = src.width;
    final int srcH = src.height;

    for (int v = 0; v < dstH; v++) {
      for (int u = 0; u < dstW; u++) {
        final double den = u * h20 + v * h21 + 1.0;
        final double srcX = (u * h00 + v * h01 + h02) / den;
        final double srcY = (u * h10 + v * h11 + h12) / den;

        if (srcX >= 0 && srcX < srcW && srcY >= 0 && srcY < srcH) {
          final int xFloor = srcX.floor();
          final int yFloor = srcY.floor();
          final int xCeil = math.min(xFloor + 1, srcW - 1);
          final int yCeil = math.min(yFloor + 1, srcH - 1);

          final double fx = srcX - xFloor;
          final double fy = srcY - yFloor;

          final p1 = src.getPixel(xFloor, yFloor);
          final p2 = src.getPixel(xCeil, yFloor);
          final p3 = src.getPixel(xFloor, yCeil);
          final p4 = src.getPixel(xCeil, yCeil);

          final r = ((1 - fx) * (1 - fy) * p1.r + fx * (1 - fy) * p2.r + (1 - fx) * fy * p3.r + fx * fy * p4.r).round().clamp(0, 255);
          final g = ((1 - fx) * (1 - fy) * p1.g + fx * (1 - fy) * p2.g + (1 - fx) * fy * p3.g + fx * fy * p4.g).round().clamp(0, 255);
          final b = ((1 - fx) * (1 - fy) * p1.b + fx * (1 - fy) * p2.b + (1 - fx) * fy * p3.b + fx * fy * p4.b).round().clamp(0, 255);
          final aVal = ((1 - fx) * (1 - fy) * p1.a + fx * (1 - fy) * p2.a + (1 - fx) * fy * p3.a + fx * fy * p4.a).round().clamp(0, 255);

          dst.setPixelRgba(u, v, r, g, b, aVal);
        }
      }
    }

    return dst;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0A0A),
      appBar: VvcAppBar(
        backgroundColor: const Color(0xFF141428),
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.close, color: Colors.white),
          onPressed: () => Navigator.pop(context, null),
        ),
        title: Text(
          'តម្រង់ និងកាត់ក្រដាស (4-Corner Warp)',
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 15, fontWeight: FontWeight.bold),
        ),
        actions: [
          TextButton(
            onPressed: _resetCrop,
            child: Text(
              'រូបពេញ',
              style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.check_rounded, color: Color(0xFF0D9488), size: 28),
            onPressed: _isProcessing ? null : _confirmCrop,
          ),
        ],
      ),
      body: _isProcessing
          ? Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const CircularProgressIndicator(color: Color(0xFF0D9488)),
                  const SizedBox(height: 16),
                  Text('កំពុងតម្រង់ក្រដាសរលូនស្អាត...', style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14)),
                ],
              ),
            )
          : Column(
              children: [
                Expanded(
                  child: Container(
                    margin: const EdgeInsets.all(16),
                    child: LayoutBuilder(
                      builder: (context, constraints) {
                        final maxWidth = constraints.maxWidth;
                        final maxHeight = constraints.maxHeight;

                        double renderW = maxWidth;
                        double renderH = maxHeight;
                        double leftOffset = 0;
                        double topOffset = 0;

                        if (_imageWidth != null && _imageHeight != null && _imageWidth! > 0 && _imageHeight! > 0) {
                          final imgAspect = _imageWidth! / _imageHeight!;
                          final containerAspect = maxWidth / maxHeight;

                          if (imgAspect > containerAspect) {
                            renderW = maxWidth;
                            renderH = maxWidth / imgAspect;
                            leftOffset = 0;
                            topOffset = (maxHeight - renderH) / 2;
                          } else {
                            renderH = maxHeight;
                            renderW = maxHeight * imgAspect;
                            leftOffset = (maxWidth - renderW) / 2;
                            topOffset = 0;
                          }
                        }

                        return Stack(
                          clipBehavior: Clip.none,
                          children: [
                            Positioned(
                              left: leftOffset,
                              top: topOffset,
                              width: renderW,
                              height: renderH,
                              child: Stack(
                                clipBehavior: Clip.none,
                                children: [
                                  // Base Image (precisely scaled to rendered bounds, zero letterbox offset)
                                  Positioned.fill(
                                    child: Transform.rotate(
                                      angle: widget.initialRotation * (math.pi / 180),
                                      child: Image.file(
                                        File(widget.imagePath),
                                        fit: BoxFit.fill,
                                      ),
                                    ),
                                  ),

                                  // Overlay Polygon Dimming
                                  Positioned.fill(
                                    child: CustomPaint(
                                      painter: PolygonCropOverlayPainter(
                                        tl: _tl,
                                        tr: _tr,
                                        br: _br,
                                        bl: _bl,
                                      ),
                                    ),
                                  ),

                                  // Corner Handle: Top-Left
                                  _buildCornerWidget(
                                    pos: _tl,
                                    maxWidth: renderW,
                                    maxHeight: renderH,
                                    onDrag: (newPos) {
                                      setState(() {
                                        _tl = newPos;
                                      });
                                    },
                                  ),

                                  // Corner Handle: Top-Right
                                  _buildCornerWidget(
                                    pos: _tr,
                                    maxWidth: renderW,
                                    maxHeight: renderH,
                                    onDrag: (newPos) {
                                      setState(() {
                                        _tr = newPos;
                                      });
                                    },
                                  ),

                                  // Corner Handle: Bottom-Right
                                  _buildCornerWidget(
                                    pos: _br,
                                    maxWidth: renderW,
                                    maxHeight: renderH,
                                    onDrag: (newPos) {
                                      setState(() {
                                        _br = newPos;
                                      });
                                    },
                                  ),

                                  // Corner Handle: Bottom-Left
                                  _buildCornerWidget(
                                    pos: _bl,
                                    maxWidth: renderW,
                                    maxHeight: renderH,
                                    onDrag: (newPos) {
                                      setState(() {
                                        _bl = newPos;
                                      });
                                    },
                                  ),
                                ],
                              ),
                            ),
                          ],
                        );
                      },
                    ),
                  ),
                ),

                // Preset Controls Bar
                Container(
                  color: const Color(0xFF141428),
                  padding: EdgeInsets.only(
                    top: 12,
                    bottom: MediaQuery.of(context).padding.bottom + 12,
                    left: 16,
                    right: 16,
                  ),
                  child: SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        _buildRatioItem('តម្រង់ស្វ័យប្រវត្តិ', _applyDefaultAutoQuad, isPrimary: true),
                        const SizedBox(width: 10),
                        _buildRatioItem('រូបពេញ', () => _applyAspectRatio(null)),
                        const SizedBox(width: 10),
                        _buildRatioItem('1:1', () => _applyAspectRatio(1.0)),
                        const SizedBox(width: 10),
                        _buildRatioItem('3:4', () => _applyAspectRatio(3 / 4)),
                        const SizedBox(width: 10),
                        _buildRatioItem('4:3', () => _applyAspectRatio(4 / 3)),
                      ],
                    ),
                  ),
                ),
              ],
            ),
    );
  }

  Widget _buildCornerWidget({
    required Offset pos,
    required double maxWidth,
    required double maxHeight,
    required ValueChanged<Offset> onDrag,
  }) {
    return Positioned(
      left: (pos.dx * maxWidth) - 22,
      top: (pos.dy * maxHeight) - 22,
      child: GestureDetector(
        onPanUpdate: (details) {
          final newDx = (pos.dx * maxWidth + details.delta.dx) / maxWidth;
          final newDy = (pos.dy * maxHeight + details.delta.dy) / maxHeight;
          onDrag(Offset(newDx.clamp(0.0, 1.0), newDy.clamp(0.0, 1.0)));
        },
        child: Container(
          width: 44,
          height: 44,
          decoration: BoxDecoration(
            color: const Color(0xFF0D9488).withValues(alpha: 0.85),
            shape: BoxShape.circle,
            border: Border.all(color: Colors.white, width: 2.5),
            boxShadow: const [
              BoxShadow(color: Colors.black54, blurRadius: 6, spreadRadius: 1),
            ],
          ),
          child: Center(
            child: Container(
              width: 8,
              height: 8,
              decoration: const BoxDecoration(
                color: Colors.white,
                shape: BoxShape.circle,
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildRatioItem(String label, VoidCallback onTap, {bool isPrimary = false}) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
        decoration: BoxDecoration(
          color: isPrimary ? const Color(0xFF0D9488) : Colors.white.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: isPrimary ? const Color(0xFF0D9488) : Colors.white.withValues(alpha: 0.15)),
        ),
        child: Text(
          label,
          style: GoogleFonts.kantumruyPro(
            color: Colors.white,
            fontSize: 12,
            fontWeight: isPrimary ? FontWeight.bold : FontWeight.w600,
          ),
        ),
      ),
    );
  }
}

class PolygonCropOverlayPainter extends CustomPainter {
  final Offset tl;
  final Offset tr;
  final Offset br;
  final Offset bl;

  PolygonCropOverlayPainter({
    required this.tl,
    required this.tr,
    required this.br,
    required this.bl,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final pTL = Offset(tl.dx * size.width, tl.dy * size.height);
    final pTR = Offset(tr.dx * size.width, tr.dy * size.height);
    final pBR = Offset(br.dx * size.width, br.dy * size.height);
    final pBL = Offset(bl.dx * size.width, bl.dy * size.height);

    final bgPath = Path()..addRect(Rect.fromLTWH(0, 0, size.width, size.height));

    final polyPath = Path()
      ..moveTo(pTL.dx, pTL.dy)
      ..lineTo(pTR.dx, pTR.dy)
      ..lineTo(pBR.dx, pBR.dy)
      ..lineTo(pBL.dx, pBL.dy)
      ..close();

    final darkPath = Path.combine(PathOperation.difference, bgPath, polyPath);
    final maskPaint = Paint()..color = Colors.black.withValues(alpha: 0.65);
    canvas.drawPath(darkPath, maskPaint);

    final borderPaint = Paint()
      ..color = const Color(0xFF0D9488)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.5
      ..strokeCap = StrokeCap.round;
    canvas.drawPath(polyPath, borderPaint);
  }

  @override
  bool shouldRepaint(covariant PolygonCropOverlayPainter oldDelegate) {
    return oldDelegate.tl != tl || oldDelegate.tr != tr || oldDelegate.br != br || oldDelegate.bl != bl;
  }
}
