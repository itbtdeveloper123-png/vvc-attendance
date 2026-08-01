import 'dart:io';
import 'dart:async';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cunning_document_scanner/cunning_document_scanner.dart';
import 'package:image_picker/image_picker.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import 'package:path_provider/path_provider.dart';
import '../services/ocr_service.dart' as ocr;
import '../services/document_history_service.dart';
import '../widgets/export_modal.dart';

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

class _DocumentScannerScreenState extends State<DocumentScannerScreen> with TickerProviderStateMixin {
  // Step tracking
  ScannerStep _currentStep = ScannerStep.selectImage;
  
  // Image paths
  String? _scannedImagePath;
  String? _filteredImagePath;
  
  // Multi-page scanning
  List<String> _scannedImagePaths = [];
  bool _isMultiPageMode = false;
  int _currentPageIndex = 0;
  late PageController _pageController;
  
  // Auto-crop animation
  bool _isAnimatingCrop = false;
  late AnimationController _cropAnimationController;
  late Animation<double> _cropAnimation;
  
  // Processing state
  bool _isProcessing = false;
  String? _errorMessage;
  
  // OCR results
  ocr.OCRResult? _ocrResult;
  final ocr.OCRService _ocrService = ocr.OCRService();
  final DocumentHistoryService _historyService = DocumentHistoryService();
  
  // Selected filter
  ImageFilter _selectedFilter = ImageFilter.original;

  @override
  void initState() {
    super.initState();
    _cropAnimationController = AnimationController(
      duration: const Duration(milliseconds: 1500),
      vsync: this,
    );
    _cropAnimation = CurvedAnimation(
      parent: _cropAnimationController,
      curve: Curves.easeInOut,
    );
    _pageController = PageController();

    // Load existing images if editing
    if (widget.existingImagePaths != null && widget.existingImagePaths!.isNotEmpty) {
      _scannedImagePaths = List.from(widget.existingImagePaths!);
      _scannedImagePath = _scannedImagePaths.first;
      _filteredImagePath = _scannedImagePaths.first;
      _isMultiPageMode = _scannedImagePaths.length > 1;
      _currentStep = ScannerStep.filterSelection;
      _startCornerAnimation();
    }
  }

  @override
  void dispose() {
    _ocrService.dispose();
    _cropAnimationController.dispose();
    _pageController.dispose();
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
      // Open the native document scanner using multi-page support
      final scannedImages = await CunningDocumentScanner.getPictures(
        noOfPages: 50, // Allow up to 50 pages (must be > 0)
        scannerSource: ScannerSource.camera,
      );

      if (scannedImages != null && scannedImages.isNotEmpty) {
        setState(() {
          // Append new pages to existing ones
          _scannedImagePaths.addAll(scannedImages);
          _scannedImagePath = _scannedImagePaths.first;
          _filteredImagePath = _scannedImagePaths.first;
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
        
        // Start corner animation to show successful scan
        _startCornerAnimation();
      } else {
        setState(() {
          _isProcessing = false;
          _errorMessage = 'គ្មានរូបភាពត្រូវបានស្កេនទេ';
        });
      }
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _errorMessage = 'មិនអាចបើកកាមេរ៉ាស្កេនបានទេ៖ $e';
      });
    }
  }

  /// Import images from Gallery (Fallback when native scanner is unavailable)
  Future<void> _importFromGallery() async {
    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    final ImagePicker picker = ImagePicker();
    try {
      final List<XFile> images = await picker.pickMultiImage();
      if (images.isNotEmpty) {
        setState(() {
          _scannedImagePaths = images.map((e) => e.path).toList();
          _scannedImagePath = _scannedImagePaths.first;
          _filteredImagePath = _scannedImagePaths.first;
          _currentStep = ScannerStep.filterSelection;
          _isMultiPageMode = _scannedImagePaths.length > 1;
          _currentPageIndex = 0;
          _isProcessing = false;
        });
        
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (_pageController.hasClients) {
            _pageController.jumpToPage(0);
          }
        });
        
        _startCornerAnimation();
      } else {
        setState(() {
          _isProcessing = false;
        });
      }
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _errorMessage = 'ការនាំចូលរូបភាពបានបរាជ័យ៖ $e';
      });
    }
  }

  /// Apply image filter (simplified - mostly for visual feedback)
  Future<void> _applyFilter(ImageFilter filter) async {
    if (_scannedImagePaths.isEmpty) return;

    setState(() {
      _selectedFilter = filter;
      _isProcessing = true;
    });

    try {
      // For now, just use the scanned image as-is
      // The native scanner already provides color enhancement
      // Future: Add more sophisticated filter processing if needed
      setState(() {
        _filteredImagePath = _scannedImagePaths[_currentPageIndex];
        _isProcessing = false;
      });
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _errorMessage = 'Filter application failed: $e';
      });
    }
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

    final imagePaths = _isMultiPageMode ? _scannedImagePaths : [_scannedImagePath!];
    
    // Show export modal
    if (mounted) {
      showModalBottomSheet(
        context: context,
        isScrollControlled: true,
        backgroundColor: Colors.transparent,
        builder: (context) => ExportModal(
          imagePaths: imagePaths,
          ocrText: _ocrResult?.fullText,
          onExport: (fileName, format) => _handleExport(fileName, format, imagePaths),
        ),
      );
    }
  }

  /// Handle export based on selected format
  Future<void> _handleExport(String fileName, ExportFormat format, List<String> imagePaths) async {
    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      switch (format) {
        case ExportFormat.pdf:
          await _exportAsPDF(fileName, imagePaths);
          break;
        case ExportFormat.images:
          await _exportAsImages(fileName, imagePaths);
          break;
        case ExportFormat.text:
          await _exportAsText(fileName);
          break;
      }

      // Save to history
      await _saveToHistory(fileName, imagePaths);

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Exported successfully as ${format.name.toUpperCase()}'),
            backgroundColor: Colors.green,
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

  /// Export as multi-page PDF
  Future<void> _exportAsPDF(String fileName, List<String> imagePaths) async {
    final pdf = pw.Document();

    for (final imagePath in imagePaths) {
      final imageFile = File(imagePath);
      final imageBytes = await imageFile.readAsBytes();
      final pdfImage = pw.MemoryImage(imageBytes);

      pdf.addPage(
        pw.Page(
          build: (pw.Context context) {
            return pw.Center(
              child: pw.Image(
                pdfImage,
                fit: pw.BoxFit.contain,
              ),
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

    await Printing.sharePdf(bytes: await pdf.save(), filename: '$fileName.pdf');
  }

  /// Export as images (individual files)
  Future<void> _exportAsImages(String fileName, List<String> imagePaths) async {
    // For now, export as PDF since sharing multiple images is complex
    // This is a simplified version - in production, you'd use platform-specific sharing
    await _exportAsPDF(fileName, imagePaths);
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
      if (widget.existingDocumentId != null) {
        // Update existing document
        await _historyService.updateDocumentPages(
          widget.existingDocumentId!,
          imagePaths,
        );
        await _historyService.updateDocumentName(
          widget.existingDocumentId!,
          fileName,
        );
        if (_ocrResult?.fullText != null) {
          await _historyService.updateOCRText(
            widget.existingDocumentId!,
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

  /// Reset scanner to start over
  void _resetScanner() {
    setState(() {
      _currentStep = ScannerStep.selectImage;
      _scannedImagePath = null;
      _filteredImagePath = null;
      _scannedImagePaths = [];
      _isMultiPageMode = false;
      _currentPageIndex = 0;
      _ocrResult = null;
      _selectedFilter = ImageFilter.original;
      _errorMessage = null;
    });
    if (_pageController.hasClients) {
      _pageController.jumpToPage(0);
    }
  }

  /// Start corner pulsing animation
  void _startCornerAnimation() {
    setState(() {
      _isAnimatingCrop = true;
    });
    _cropAnimationController.forward().then((_) {
      setState(() {
        _isAnimatingCrop = false;
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A), // Luxury Dark Slate
      extendBodyBehindAppBar: false,
      appBar: AppBar(
        backgroundColor: const Color(0xFF0F172A),
        elevation: 0,
        centerTitle: true,
        title: Text(
          'Document Scanner',
          style: GoogleFonts.kantumruyPro(
            fontSize: 18,
            fontWeight: FontWeight.bold,
            letterSpacing: 0.5,
            color: Colors.white,
          ),
        ),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 20),
          onPressed: () => Navigator.pop(context),
          color: Colors.white,
        ),
        actions: [
          if (_currentStep != ScannerStep.selectImage)
            Container(
              margin: const EdgeInsets.only(right: 16, top: 8, bottom: 8),
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(12),
              ),
              child: IconButton(
                icon: const Icon(Icons.refresh_rounded, size: 20),
                onPressed: _resetScanner,
                tooltip: 'Start Over',
                color: Colors.white,
              ),
            ),
        ],
      ),
      body: SafeArea(
        child: _buildBody(),
      ),
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

    if (_errorMessage != null) {
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

  /// Step 1: Select Image UI - Beautiful Design with Fallbacks
  Widget _buildSelectImageStep() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 24.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(28),
              decoration: BoxDecoration(
                color: Colors.orange.withValues(alpha: 0.08),
                shape: BoxShape.circle,
                border: Border.all(color: Colors.orange.withValues(alpha: 0.15), width: 1.5),
              ),
              child: const Icon(
                Icons.document_scanner_rounded,
                size: 70,
                color: Colors.orange,
              ),
            ),
            const SizedBox(height: 32),
            Text(
              'ស្កេនឯកសារអាជីព',
              style: GoogleFonts.kantumruyPro(
                fontSize: 22,
                fontWeight: FontWeight.bold,
                color: Colors.white,
                letterSpacing: 0.5,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'ស្កេន កែសម្រួល ស្រង់អក្សរ និងនាំចេញជា PDF',
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                fontSize: 13.5,
                color: Colors.grey[400],
                height: 1.5,
              ),
            ),
            const SizedBox(height: 48),
            _buildGradientButton(
              icon: Icons.camera_alt_rounded,
              label: 'បើកកាមេរ៉ាស្កេន',
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
                    const Icon(Icons.photo_library_rounded, size: 18, color: Colors.white),
                    const SizedBox(width: 8),
                    Text(
                      'ជ្រើសរើសរូបភាពពីវិចិត្រសាល',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontSize: 14,
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
    );
  }

  /// Step 2: Filter Selection UI - Modern Design
  Widget _buildFilterSelectionStep() {
    return Column(
      children: [
        // Image preview with overlay
        Expanded(
          child: Stack(
            children: [
              // Document image with PageView for multi-page
              _scannedImagePaths.isNotEmpty
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
                        return Image.file(
                          File(_scannedImagePaths[index]),
                          fit: BoxFit.contain,
                        );
                      },
                    )
                  : const Center(child: Text('No image')),
              // Page indicator overlay
              if (_scannedImagePaths.length > 1)
                Positioned(
                  top: 20,
                  left: 0,
                  right: 0,
                  child: Center(
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                      decoration: BoxDecoration(
                        color: Colors.black.withValues(alpha: 0.6),
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: Text(
                        '${_currentPageIndex + 1} / ${_scannedImagePaths.length}',
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ),
                ),
              // Corner handles overlay (showing it was cropped)
              if (_filteredImagePath != null)
                Positioned.fill(
                  child: IgnorePointer(
                    child: CustomPaint(
                      painter: _CornerOverlayPainter(
                        _isAnimatingCrop,
                        _cropAnimation,
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
        // Bottom control panel with blur effect
        Container(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [
                Colors.black.withValues(alpha: 0.0),
                Colors.black.withValues(alpha: 0.3),
                Colors.black.withValues(alpha: 0.8),
              ],
            ),
          ),
          child: Padding(
            padding: EdgeInsets.only(
              left: 20,
              right: 20,
              top: 20,
              bottom: MediaQuery.of(context).padding.bottom + 20,
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // Thumbnail history bar
                if (_scannedImagePaths.isNotEmpty)
                  Container(
                    height: 80,
                    margin: const EdgeInsets.only(bottom: 20),
                    child: Row(
                      children: [
                        // Add page button
                        GestureDetector(
                          onTap: _openNativeScanner,
                          child: Container(
                            width: 60,
                            height: 60,
                            decoration: BoxDecoration(
                              color: Colors.orange.withValues(alpha: 0.2),
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(
                                color: Colors.orange,
                                width: 2,
                              ),
                            ),
                            child: const Icon(
                              Icons.add,
                              color: Colors.orange,
                              size: 32,
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        // Thumbnails
                        Expanded(
                          child: ListView.builder(
                            scrollDirection: Axis.horizontal,
                            itemCount: _scannedImagePaths.length,
                            itemBuilder: (context, index) {
                              final isSelected = index == _currentPageIndex;
                              return GestureDetector(
                                onTap: () {
                                  _pageController.animateToPage(
                                    index,
                                    duration: const Duration(milliseconds: 300),
                                    curve: Curves.easeInOut,
                                  );
                                },
                                child: Container(
                                  width: 60,
                                  height: 60,
                                  margin: const EdgeInsets.only(right: 12),
                                  decoration: BoxDecoration(
                                    border: Border.all(
                                      color: isSelected
                                          ? Colors.orange
                                          : Colors.white.withValues(alpha: 0.3),
                                      width: isSelected ? 3 : 2,
                                    ),
                                    borderRadius: BorderRadius.circular(12),
                                  ),
                                  child: ClipRRect(
                                    borderRadius: BorderRadius.circular(10),
                                    child: Stack(
                                      children: [
                                        Image.file(
                                          File(_scannedImagePaths[index]),
                                          fit: BoxFit.cover,
                                        ),
                                        if (isSelected)
                                          Container(
                                            decoration: BoxDecoration(
                                              color: Colors.orange.withValues(alpha: 0.3),
                                              borderRadius: BorderRadius.circular(10),
                                            ),
                                          ),
                                      ],
                                    ),
                                  ),
                                ),
                              );
                            },
                          ),
                        ),
                      ],
                    ),
                  ),
                // Filter selection
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: Colors.white.withValues(alpha: 0.2),
                      width: 1,
                    ),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: ImageFilter.values.map((filter) {
                      final isSelected = _selectedFilter == filter;
                      return Expanded(
                        child: GestureDetector(
                          onTap: () => _applyFilter(filter),
                          child: AnimatedContainer(
                            duration: const Duration(milliseconds: 200),
                            margin: const EdgeInsets.symmetric(horizontal: 4),
                            padding: const EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 10,
                            ),
                            decoration: BoxDecoration(
                              color: isSelected
                                  ? Colors.orange.withValues(alpha: 0.8)
                                  : Colors.transparent,
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              _getFilterLabel(filter),
                              textAlign: TextAlign.center,
                              style: TextStyle(
                                color: isSelected
                                    ? Colors.white
                                    : Colors.white.withValues(alpha: 0.7),
                                fontSize: 11,
                                fontWeight: isSelected
                                    ? FontWeight.w600
                                    : FontWeight.w400,
                              ),
                            ),
                          ),
                        ),
                      );
                    }).toList(),
                  ),
                ),
                const SizedBox(height: 20),
                // Action buttons with gradient
                Row(
                  children: [
                    Expanded(
                      child: _buildGradientButton(
                        icon: Icons.text_fields,
                        label: 'Extract Text',
                        onTap: _extractText,
                        gradient: const LinearGradient(
                          colors: [Color(0xFFFF6B35), Color(0xFFFFB74D)],
                        ),
                      ),
                    ),
                    const SizedBox(width: 20),
                    Expanded(
                      child: _buildGradientButton(
                        icon: Icons.picture_as_pdf,
                        label: 'Export PDF',
                        onTap: _exportToPDF,
                        gradient: const LinearGradient(
                          colors: [Color(0xFFFF6B35), Color(0xFFFFB74D)],
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ],
    );
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
              style: const TextStyle(
                color: Colors.white,
                fontSize: 14,
                fontWeight: FontWeight.w600,
                letterSpacing: 0.5,
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
              icon: Icons.picture_as_pdf,
              label: 'Export PDF',
              onTap: _exportToPDF,
              gradient: const LinearGradient(
                colors: [Color(0xFFFF6B35), Color(0xFFFFB74D)],
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
        return 'Orig';
      case ImageFilter.magicColor:
        return 'Magic';
      case ImageFilter.blackAndWhite:
        return 'B&W';
      case ImageFilter.enhanced:
        return 'Enh';
    }
  }
}

/// Modern corner overlay painter with pulsing animation
class _CornerOverlayPainter extends CustomPainter {
  final bool isAnimating;
  final Animation<double> animation;

  _CornerOverlayPainter(this.isAnimating, this.animation);

  @override
  void paint(Canvas canvas, Size size) {
    // Calculate pulsing effect
    final pulse = isAnimating 
        ? math.sin(animation.value * math.pi * 2) * 0.3 + 0.7
        : 1.0;
    
    final cornerSize = 16.0 * pulse;
    final lineThickness = 2.0 * pulse;
    
    // Draw corner handles at document edges
    final corners = [
      const Offset(20, 20), // top-left
      Offset(size.width - 20, 20), // top-right
      Offset(size.width - 20, size.height - 20), // bottom-right
      Offset(20, size.height - 20), // bottom-left
    ];
    
    final paint = Paint()
      ..color = Colors.orange.withValues(alpha: 0.8 * pulse)
      ..style = PaintingStyle.fill;
    
    final borderPaint = Paint()
      ..color = Colors.orange.withValues(alpha: pulse)
      ..style = PaintingStyle.stroke
      ..strokeWidth = lineThickness;
    
    // Draw corner handles
    for (final corner in corners) {
      canvas.drawCircle(corner, cornerSize, paint);
      canvas.drawCircle(corner, cornerSize, borderPaint);
    }
    
    // Draw connecting lines between corners
    final path = Path()
      ..moveTo(corners[0].dx, corners[0].dy)
      ..lineTo(corners[1].dx, corners[1].dy)
      ..lineTo(corners[2].dx, corners[2].dy)
      ..lineTo(corners[3].dx, corners[3].dy)
      ..close();
    
    canvas.drawPath(path, borderPaint);
  }

  @override
  bool shouldRepaint(_CornerOverlayPainter oldDelegate) {
    return oldDelegate.isAnimating != isAnimating || 
           oldDelegate.animation != animation;
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
