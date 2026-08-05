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
import 'package:image/image.dart' as img;
import 'package:path/path.dart' as path;
import '../services/ocr_service.dart' as ocr;
import '../services/document_history_service.dart';
import '../widgets/export_modal.dart';
import 'passport_photo_screen.dart';
import 'digital_ink_screen.dart';

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
  
  // Selected filter
  ImageFilter _selectedFilter = ImageFilter.original;

  // Page rotations (index -> angle degrees: 0, 90, 180, 270)
  final Map<int, int> _pageRotations = {};

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

  /// Bake rotation and filter effects into a temporary JPG file
  Future<File> _bakeImageEffects(String imagePath, int rotationDegrees, ImageFilter filter) async {
    try {
      final bytes = await File(imagePath).readAsBytes();
      img.Image? image = img.decodeImage(bytes);
      if (image == null) return File(imagePath);

      if (rotationDegrees != 0) {
        image = img.copyRotate(image, angle: rotationDegrees);
      }

      if (filter == ImageFilter.blackAndWhite) {
        image = img.grayscale(image);
      } else if (filter == ImageFilter.magicColor) {
        image = img.adjustColor(image, contrast: 1.25, saturation: 1.25);
      } else if (filter == ImageFilter.enhanced) {
        image = img.adjustColor(image, contrast: 1.4, amount: 1.1);
      }

      final tempDir = await getTemporaryDirectory();
      final outPath = '${tempDir.path}/proc_${DateTime.now().millisecondsSinceEpoch}_${path.basename(imagePath)}';
      final encodedJpg = img.encodeJpg(image, quality: 92);
      final outFile = File(outPath);
      await outFile.writeAsBytes(encodedJpg);
      return outFile;
    } catch (e) {
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
      final processedPaths = await _prepareProcessedImagePaths();

      switch (format) {
        case ExportFormat.pdf:
          await _exportAsPDF(fileName, processedPaths);
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
        backgroundColor: const Color(0xFF1E293B),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Text(
          'លុបឯកសារ',
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16),
        ),
        content: Text(
          'តើអ្នកពិតជាចង់លុបឯកសារនេះមែនទេ?',
          style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: Colors.grey)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text('លុប', style: GoogleFonts.kantumruyPro(color: Colors.redAccent, fontWeight: FontWeight.bold)),
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
        backgroundColor: const Color(0xFF1E293B),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Text(
          'ប្តូរឈ្មោះឯកសារ',
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16),
        ),
        content: TextField(
          controller: controller,
          autofocus: true,
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14),
          decoration: InputDecoration(
            hintText: 'បញ្ចូលឈ្មោះឯកសារថ្មី',
            hintStyle: GoogleFonts.kantumruyPro(color: Colors.white24),
            enabledBorder: const UnderlineInputBorder(borderSide: BorderSide(color: Colors.white24)),
            focusedBorder: const UnderlineInputBorder(borderSide: BorderSide(color: Colors.tealAccent)),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: Colors.grey)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, controller.text.trim()),
            child: Text('យល់ព្រម', style: GoogleFonts.kantumruyPro(color: Colors.tealAccent, fontWeight: FontWeight.bold)),
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
          decoration: const BoxDecoration(
            color: Color(0xFF1A1A2E),
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          child: Column(
            children: [
              // Handle bar
              Container(
                margin: const EdgeInsets.only(top: 10, bottom: 12),
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: Colors.white24,
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
                        color: Colors.white,
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.close_rounded, color: Colors.white54, size: 20),
                      onPressed: () => Navigator.pop(ctx),
                    ),
                  ],
                ),
              ),
              const Divider(color: Colors.white12, height: 1),
              // Documents grid
              Expanded(
                child: _recentDocuments.isEmpty
                    ? Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.folder_open_rounded,
                                size: 56, color: Colors.white24),
                            const SizedBox(height: 12),
                            Text(
                              'មិនទាន់មានឯកសារទេ',
                              style: GoogleFonts.kantumruyPro(
                                  color: Colors.white38, fontSize: 14),
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
                                      color: Colors.white.withValues(alpha: 0.04),
                                      borderRadius: BorderRadius.circular(10),
                                      border: Border.all(
                                          color: Colors.white.withValues(alpha: 0.08)),
                                    ),
                                    child: ClipRRect(
                                      borderRadius: BorderRadius.circular(9),
                                      child: fileExists
                                          ? Image.file(thumbnailFile, fit: BoxFit.cover)
                                          : Container(
                                              color: Colors.teal.withValues(alpha: 0.1),
                                              child: const Icon(
                                                Icons.description_rounded,
                                                color: Colors.tealAccent,
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
                                    color: Colors.white70,
                                    fontSize: 10,
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
    final showFab = _currentStep == ScannerStep.selectImage && !_isProcessing;
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A), // Luxury Dark Slate
      extendBodyBehindAppBar: false,
      appBar: AppBar(
        backgroundColor: const Color(0xFF0F172A),
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
            color: Colors.white,
          ),
        ),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 20),
          onPressed: () {
            if (_currentStep != ScannerStep.selectImage) {
              _resetScanner();
            } else {
              Navigator.pop(context);
            }
          },
          color: Colors.white,
        ),
        actions: [
          if (_currentStep != ScannerStep.selectImage)
            Padding(
              padding: const EdgeInsets.only(right: 16, top: 8, bottom: 8),
              child: IconButton(
                style: IconButton.styleFrom(
                  backgroundColor: Colors.white.withValues(alpha: 0.08),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
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
      floatingActionButton: showFab
          ? FloatingActionButton(
              onPressed: _openNativeScanner,
              backgroundColor: const Color(0xFF0D9488), // Teal color like CamScanner
              elevation: 4,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(50)),
              child: const Icon(Icons.camera_alt_rounded, color: Colors.white, size: 28),
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

  /// Step 1: CamScanner-style Dashboard with Search and History Scans
  Widget _buildSelectImageStep() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // 1. Search Bar and Top Icons Row
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20.0, vertical: 16.0),
          child: Row(
            children: [
              Expanded(
                child: SizedBox(
                  height: 42,
                  child: TextField(
                    controller: _searchController,
                    onChanged: _onSearchChanged,
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                    cursorColor: const Color(0xFF0E7490),
                    decoration: InputDecoration(
                      hintText: 'ស្វែងរកឯកសារ...',
                      hintStyle: GoogleFonts.kantumruyPro(color: Colors.white38, fontSize: 12.5),
                      prefixIcon: const Icon(Icons.search_rounded, color: Colors.white38, size: 20),
                      filled: true,
                      fillColor: Colors.white.withValues(alpha: 0.08),
                      isDense: true,
                      contentPadding: const EdgeInsets.symmetric(vertical: 10, horizontal: 16),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(22),
                        borderSide: BorderSide.none,
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(22),
                        borderSide: BorderSide.none,
                      ),
                      focusedBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(22),
                        borderSide: BorderSide(color: Colors.tealAccent.withValues(alpha: 0.5), width: 1.0),
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              // Cloud Sync icon
              IconButton(
                icon: const Icon(Icons.cloud_done_rounded, color: Colors.tealAccent, size: 24),
                onPressed: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('ការរក្សាទុកពពកត្រូវបានធ្វើសមកាលកម្មរួចរាល់', style: GoogleFonts.kantumruyPro()),
                      backgroundColor: Colors.teal,
                    ),
                  );
                },
              ),
              // Premium Gold Badge
              IconButton(
                icon: const Icon(Icons.workspace_premium_rounded, color: Colors.amber, size: 24),
                onPressed: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('អ្នកកំពុងប្រើប្រាស់ VVC Scanner Premium', style: GoogleFonts.kantumruyPro()),
                      backgroundColor: Colors.amber.shade800,
                    ),
                  );
                },
              ),
            ],
          ),
        ),

        // 2. Quick Actions Grid (2 rows x 4 columns)
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
          child: _buildQuickActionsGrid(),
        ),

        const SizedBox(height: 24),

        // 3. Recents Header
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20.0),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'ឯកសារថ្មីៗ (${_filteredDocuments.length})',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
              if (_searchController.text.isNotEmpty)
                GestureDetector(
                  onTap: () {
                    _searchController.clear();
                    _onSearchChanged('');
                  },
                  child: Text(
                    'សម្អាត',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.tealAccent,
                      fontSize: 12.5,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
            ],
          ),
        ),

        const SizedBox(height: 12),

        // 4. Recents List or Empty State
        Expanded(
          child: _filteredDocuments.isEmpty
              ? Center(
                  child: SingleChildScrollView(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Container(
                          padding: const EdgeInsets.all(24),
                          decoration: BoxDecoration(
                            color: Colors.white.withValues(alpha: 0.02),
                            shape: BoxShape.circle,
                          ),
                          child: Icon(
                            _searchController.text.isNotEmpty
                                ? Icons.search_off_rounded
                                : Icons.document_scanner_outlined,
                            size: 60,
                            color: Colors.white24,
                          ),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          _searchController.text.isNotEmpty
                              ? 'រកមិនឃើញឯកសារដែលត្រូវគ្នាទេ'
                              : 'មិនទាន់មានឯកសារស្កេនទេ',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white38,
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          _searchController.text.isNotEmpty
                              ? 'សូមសាកល្បងស្វែងរកឈ្មោះផ្សេងទៀត'
                              : 'ចុចប៊ូតុងកាមេរ៉ាខាងក្រោមដើម្បីចាប់ផ្តើមស្កេន',
                          textAlign: TextAlign.center,
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white24,
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                )
              : ListView.separated(
                  padding: const EdgeInsets.symmetric(horizontal: 20.0, vertical: 8.0),
                  itemCount: _filteredDocuments.length,
                  separatorBuilder: (context, index) => Divider(
                    color: Colors.white.withValues(alpha: 0.05),
                    height: 1,
                  ),
                  itemBuilder: (context, index) {
                    return _buildRecentItem(_filteredDocuments[index]);
                  },
                ),
        ),
      ],
    );
  }

  /// Helper Grid view for Quick Actions
  Widget _buildQuickActionsGrid() {
    return Column(
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            _buildQuickActionItem(
              icon: Icons.qr_code_scanner_rounded,
              label: 'ស្កេនឆ្លាតវៃ',
              color: Colors.tealAccent,
              onTap: _openNativeScanner,
            ),
            _buildQuickActionItem(
              icon: Icons.picture_as_pdf_rounded,
              label: 'ឧបករណ៍ PDF',
              color: Colors.redAccent,
              onTap: () async {
                // Import image from gallery then export PDF directly
                await _importFromGallery();
                if (_scannedImagePaths.isNotEmpty && mounted) {
                  await _exportToPDF();
                }
              },
            ),
            _buildQuickActionItem(
              icon: Icons.image_rounded,
              label: 'នាំចូលរូបភាព',
              color: Colors.blueAccent,
              onTap: _importFromGallery,
            ),
            _buildQuickActionItem(
              icon: Icons.folder_copy_rounded,
              label: 'នាំចូលឯកសារ',
              color: Colors.purpleAccent,
              onTap: _importFromGallery, // Fallback: gallery is most compatible cross-platform
            ),
          ],
        ),
        const SizedBox(height: 16),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            _buildQuickActionItem(
              icon: Icons.portrait_rounded,
              label: 'រូប 4x6 / 3x4',
              color: Colors.cyanAccent,
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
            ),
            _buildQuickActionItem(
              icon: Icons.draw_rounded,
              label: 'សរសេរដៃ',
              color: Colors.orangeAccent,
              onTap: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const DigitalInkScreen()),
                );
              },
            ),
            _buildQuickActionItem(
              icon: Icons.text_fields_rounded,
              label: 'អត្ថបទ OCR',
              color: Colors.pinkAccent,
              onTap: () async {
                if (_scannedImagePaths.isEmpty) {
                  await _importFromGallery();
                }
                if (_scannedImagePaths.isNotEmpty) {
                  await _extractText();
                }
              },
            ),
            _buildQuickActionItem(
              icon: Icons.grid_view_rounded,
              label: 'ទាំងអស់',
              color: Colors.grey,
              onTap: () => _showAllDocumentsSheet(),
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
  }) {
    return Expanded(
      child: GestureDetector(
        onTap: onTap,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 50,
              height: 50,
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.08),
                shape: BoxShape.circle,
                border: Border.all(color: color.withValues(alpha: 0.12), width: 1.5),
              ),
              child: Icon(icon, color: color, size: 24),
            ),
            const SizedBox(height: 8),
            Text(
              label,
              textAlign: TextAlign.center,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white.withValues(alpha: 0.7),
                fontSize: 10.5,
                fontWeight: FontWeight.w500,
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Recent Scan item row builder
  Widget _buildRecentItem(Map<String, dynamic> doc) {
    final int id = doc['id'] as int;
    final String title = doc['custom_name'] ?? 'គ្មានឈ្មោះ';
    final int pageCount = doc['page_count'] ?? 1;
    final String thumbnailPath = doc['thumbnail_path'] ?? '';
    final String dateStr = doc['scan_date'] ?? '';
    
    // Format the date nicely
    String formattedDate = dateStr;
    try {
      final dateTime = DateTime.parse(dateStr);
      formattedDate = '${dateTime.year}-${dateTime.month.toString().padLeft(2, '0')}-${dateTime.day.toString().padLeft(2, '0')} ${dateTime.hour.toString().padLeft(2, '0')}:${dateTime.minute.toString().padLeft(2, '0')}';
    } catch (_) {}

    final thumbnailFile = File(thumbnailPath);
    final bool fileExists = thumbnailFile.existsSync();

    return InkWell(
      onTap: () => _openDocument(doc),
      borderRadius: BorderRadius.circular(12),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 10.0, horizontal: 4.0),
        child: Row(
          children: [
            // Thumbnail or doc icon placeholder
            Container(
              width: 58,
              height: 58,
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.04),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(7),
                child: fileExists
                    ? Image.file(thumbnailFile, fit: BoxFit.cover)
                    : Container(
                        color: Colors.teal.withValues(alpha: 0.1),
                        child: const Icon(Icons.description_rounded, color: Colors.tealAccent, size: 28),
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
                      color: Colors.white.withValues(alpha: 0.9),
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Row(
                    children: [
                      Text(
                        formattedDate,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white30,
                          fontSize: 11.5,
                        ),
                      ),
                      const SizedBox(width: 12),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.06),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.pages_rounded, size: 10, color: Colors.white38),
                            const SizedBox(width: 4),
                            Text(
                              '$pageCount ទំព័រ',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white38,
                                fontSize: 10,
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
            // Actions Popup Menu
            PopupMenuButton<String>(
              icon: const Icon(Icons.more_vert_rounded, color: Colors.white38, size: 20),
              color: const Color(0xFF1E293B),
              elevation: 4,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              onSelected: (action) {
                if (action == 'rename') {
                  _renameDocument(id, title);
                } else if (action == 'delete') {
                  _deleteDocument(id);
                }
              },
              itemBuilder: (context) => [
                PopupMenuItem(
                  value: 'rename',
                  child: Row(
                    children: [
                      const Icon(Icons.edit_rounded, color: Colors.white70, size: 16),
                      const SizedBox(width: 8),
                      Text('ប្តូរឈ្មោះ', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13)),
                    ],
                  ),
                ),
                PopupMenuItem(
                  value: 'delete',
                  child: Row(
                    children: [
                      const Icon(Icons.delete_rounded, color: Colors.redAccent, size: 16),
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
    );
  }

  /// Step 2: CamScanner-style Filter Edit Screen
  Widget _buildFilterSelectionStep() {
    return Column(
      children: [
        // ── 1. Large image preview ──────────────────────────────────────
        Expanded(
          child: Stack(
            children: [
              Container(
                color: const Color(0xFF0A0A0A),
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
                                margin: const EdgeInsets.all(12),
                                decoration: BoxDecoration(
                                  boxShadow: [
                                    BoxShadow(
                                      color: Colors.black.withValues(alpha: 0.5),
                                      blurRadius: 20,
                                      offset: const Offset(0, 6),
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
                    : const Center(
                        child: Icon(Icons.image_not_supported_rounded,
                            size: 60, color: Colors.white24),
                      ),
              ),

              // Delete current page button (top-left) - shown when multi-page
              if (_scannedImagePaths.isNotEmpty)
                Positioned(
                  top: 12,
                  left: 12,
                  child: GestureDetector(
                    onTap: () async {
                      if (_scannedImagePaths.length == 1) {
                        _resetScanner();
                        return;
                      }
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
                        color: Colors.black.withValues(alpha: 0.5),
                        shape: BoxShape.circle,
                      ),
                      child: const Icon(Icons.delete_outline_rounded,
                          color: Colors.white, size: 22),
                    ),
                  ),
                ),
            ],
          ),
        ),

        // ── 2. Page navigation bar ─────────────────────────────────────
        Container(
          color: const Color(0xFF1A1A2E),
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Previous page button
              IconButton(
                icon: const Icon(Icons.chevron_left_rounded,
                    color: Colors.white70, size: 28),
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
                padding:
                    const EdgeInsets.symmetric(horizontal: 20, vertical: 6),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Text(
                  _scannedImagePaths.isNotEmpty
                      ? '${_currentPageIndex + 1}/${_scannedImagePaths.length}'
                      : '0/0',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              // Next page button
              IconButton(
                icon: const Icon(Icons.chevron_right_rounded,
                    color: Colors.white70, size: 28),
                onPressed:
                    _currentPageIndex < _scannedImagePaths.length - 1
                        ? () {
                            _pageController.nextPage(
                              duration: const Duration(milliseconds: 250),
                              curve: Curves.easeInOut,
                            );
                          }
                        : null,
              ),
              const Spacer(),
              // "Sort pages" / arrange button
              GestureDetector(
                onTap: _openNativeScanner,
                child: Container(
                  margin: const EdgeInsets.only(right: 16),
                  padding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.08),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                        color: Colors.white.withValues(alpha: 0.15)),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.view_module_rounded,
                          color: Colors.white60, size: 16),
                      const SizedBox(width: 6),
                      Text(
                        'រៀបចំផ្ដូរ',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white60,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),

        // ── 3. Filter thumbnail strip (like CamScanner) ──────────────
        Container(
          color: const Color(0xFF141428),
          height: 100,
          child: ListView.builder(
            scrollDirection: Axis.horizontal,
            padding:
                const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            itemCount: ImageFilter.values.length,
            itemBuilder: (context, index) {
              final filter = ImageFilter.values[index];
              final isSelected = _selectedFilter == filter;
              final currentRotation = _pageRotations[_currentPageIndex] ?? 0;
              return GestureDetector(
                onTap: () => _applyFilter(filter),
                child: Container(
                  width: 70,
                  margin: const EdgeInsets.only(right: 8),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: isSelected
                          ? const Color(0xFF0D9488)
                          : Colors.transparent,
                      width: 2,
                    ),
                  ),
                  child: Stack(
                    children: [
                      // Filter preview thumbnail
                      ClipRRect(
                        borderRadius: BorderRadius.circular(6),
                        child: _scannedImagePaths.isNotEmpty
                            ? ColorFiltered(
                                colorFilter: _getColorFilter(filter),
                                child: Transform.rotate(
                                  angle: currentRotation * (math.pi / 180),
                                  child: Image.file(
                                    File(_scannedImagePaths[_currentPageIndex]),
                                    width: 70,
                                    height: 80,
                                    fit: BoxFit.cover,
                                  ),
                                ),
                              )
                            : Container(
                                color: Colors.white.withValues(alpha: 0.05),
                                width: 70,
                                height: 80,
                                child: const Icon(Icons.image_rounded,
                                    color: Colors.white24),
                              ),
                      ),
                      // Filter name overlay at bottom
                      Positioned(
                        left: 0,
                        right: 0,
                        bottom: 0,
                        child: Container(
                          padding: const EdgeInsets.symmetric(vertical: 3),
                          decoration: BoxDecoration(
                            color: isSelected
                                ? const Color(0xFF0D9488)
                                : Colors.black.withValues(alpha: 0.65),
                            borderRadius: const BorderRadius.vertical(
                                bottom: Radius.circular(6)),
                          ),
                          child: Text(
                            _getFilterLabel(filter),
                            textAlign: TextAlign.center,
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 9.5,
                              fontWeight: isSelected
                                  ? FontWeight.bold
                                  : FontWeight.w400,
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
          decoration: const BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [
                Color(0xFF141428), // blends seamlessly with filter strip above
                Color(0xFF0B0B1A),
              ],
            ),
          ),
          padding: EdgeInsets.only(
            left: 8,
            right: 8,
            top: 10,
            bottom: MediaQuery.of(context).padding.bottom + 10,
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              // Add Page (camera)
              _buildToolbarItem(
                icon: Icons.add_photo_alternate_rounded,
                label: 'បន្ថែមទំព័រ',
                onTap: _openNativeScanner,
              ),
              // Crop
              _buildToolbarItem(
                icon: Icons.crop_rounded,
                label: 'កាត់',
                onTap: _cropCurrentImage,
              ),
              // Rotate
              _buildToolbarItem(
                icon: Icons.rotate_90_degrees_ccw_rounded,
                label: 'បង្វិល',
                onTap: () {
                  setState(() {
                    final currentRot = _pageRotations[_currentPageIndex] ?? 0;
                    _pageRotations[_currentPageIndex] = (currentRot + 90) % 360;
                  });
                },
              ),
              // OCR - Extract Text
              _buildToolbarItem(
                icon: Icons.text_fields_rounded,
                label: 'ស្រង់អក្សរ',
                onTap: _extractText,
                color: Colors.orangeAccent,
              ),
              // Export PDF
              _buildToolbarItem(
                icon: Icons.picture_as_pdf_rounded,
                label: 'PDF',
                onTap: _exportToPDF,
                color: Colors.redAccent,
              ),
              // Confirm / Done button (Teal like CamScanner)
              GestureDetector(
                onTap: _exportToPDF,
                child: Container(
                  width: 52,
                  height: 52,
                  decoration: BoxDecoration(
                    color: const Color(0xFF0D9488),
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFF0D9488).withValues(alpha: 0.4),
                        blurRadius: 12,
                        offset: const Offset(0, 4),
                      ),
                    ],
                  ),
                  child: const Icon(Icons.check_rounded,
                      color: Colors.white, size: 28),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  /// Bottom toolbar icon item
  Widget _buildToolbarItem({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
    Color color = Colors.white70,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: SizedBox(
        width: 56,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: color, size: 26),
            const SizedBox(height: 4),
            Text(
              label,
              textAlign: TextAlign.center,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: GoogleFonts.kantumruyPro(
                color: color,
                fontSize: 9.5,
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
        // Enhanced contrast and color saturation
        return const ColorFilter.matrix(<double>[
          1.5,  0.0,  0.0, 0.0, -30,
          0.0,  1.5,  0.0, 0.0, -30,
          0.0,  0.0,  1.5, 0.0, -30,
          0.0,  0.0,  0.0, 1.0,   0,
        ]);
      case ImageFilter.blackAndWhite:
        // Grayscale
        return const ColorFilter.matrix(<double>[
          0.33, 0.59, 0.11, 0.0, 0.0,
          0.33, 0.59, 0.11, 0.0, 0.0,
          0.33, 0.59, 0.11, 0.0, 0.0,
          0.00, 0.00, 0.00, 1.0, 0.0,
        ]);
      case ImageFilter.enhanced:
        // High contrast sharpened
        return const ColorFilter.matrix(<double>[
          2.0, -0.5, -0.5, 0.0, -20,
         -0.5,  2.0, -0.5, 0.0, -20,
         -0.5, -0.5,  2.0, 0.0, -20,
          0.0,  0.0,  0.0, 1.0,   0,
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
  Offset _tl = const Offset(0.06, 0.06);
  Offset _tr = const Offset(0.94, 0.06);
  Offset _br = const Offset(0.94, 0.94);
  Offset _bl = const Offset(0.06, 0.94);
  bool _isProcessing = false;

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
      _tl = const Offset(0.06, 0.06);
      _tr = const Offset(0.94, 0.06);
      _br = const Offset(0.94, 0.94);
      _bl = const Offset(0.06, 0.94);
    });
  }

  void _applyAspectRatio(double? ratio) {
    if (ratio == null) {
      _resetCrop();
      return;
    }
    setState(() {
      double w = 0.88;
      double h = w / ratio;
      if (h > 0.88) {
        h = 0.88;
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
      final croppedJpg = img.encodeJpg(unwarped, quality: 92);
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
      appBar: AppBar(
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

                        return Stack(
                          clipBehavior: Clip.none,
                          children: [
                            // Base Image
                            Positioned.fill(
                              child: Transform.rotate(
                                angle: widget.initialRotation * (math.pi / 180),
                                child: Image.file(
                                  File(widget.imagePath),
                                  fit: BoxFit.contain,
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
                              maxWidth: maxWidth,
                              maxHeight: maxHeight,
                              onDrag: (newPos) {
                                setState(() {
                                  _tl = newPos;
                                });
                              },
                            ),

                            // Corner Handle: Top-Right
                            _buildCornerWidget(
                              pos: _tr,
                              maxWidth: maxWidth,
                              maxHeight: maxHeight,
                              onDrag: (newPos) {
                                setState(() {
                                  _tr = newPos;
                                });
                              },
                            ),

                            // Corner Handle: Bottom-Right
                            _buildCornerWidget(
                              pos: _br,
                              maxWidth: maxWidth,
                              maxHeight: maxHeight,
                              onDrag: (newPos) {
                                setState(() {
                                  _br = newPos;
                                });
                              },
                            ),

                            // Corner Handle: Bottom-Left
                            _buildCornerWidget(
                              pos: _bl,
                              maxWidth: maxWidth,
                              maxHeight: maxHeight,
                              onDrag: (newPos) {
                                setState(() {
                                  _bl = newPos;
                                });
                              },
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
