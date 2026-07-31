import 'dart:io';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:path/path.dart' as path;
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import 'package:opencv_dart/opencv_dart.dart' as cv;
import '../services/opencv_service.dart';
import '../services/ocr_service.dart' as ocr;

/// Document Scanner Screen - CamScanner Clone
/// 
/// Workflow:
/// 1. Capture/Select Image
/// 2. OpenCV Edge Detection & Crop
/// 3. OpenCV Image Enhancement Filters
/// 4. ML Kit OCR / PDF Export
class DocumentScannerScreen extends StatefulWidget {
  const DocumentScannerScreen({super.key});

  @override
  State<DocumentScannerScreen> createState() => _DocumentScannerScreenState();
}

class _DocumentScannerScreenState extends State<DocumentScannerScreen> {
  // Step tracking
  ScannerStep _currentStep = ScannerStep.selectImage;
  
  // Image paths
  String? _originalImagePath;
  String? _croppedImagePath;
  String? _filteredImagePath;
  
  // Manual crop corners
  List<Offset>? _manualCropCorners;
  
  // Processing state
  bool _isProcessing = false;
  String? _errorMessage;
  
  // OCR results
  ocr.OCRResult? _ocrResult;
  final ocr.OCRService _ocrService = ocr.OCRService();
  
  // Selected filter
  ImageFilter _selectedFilter = ImageFilter.original;
  
  // Controllers
  final ImagePicker _imagePicker = ImagePicker();

  @override
  void dispose() {
    _ocrService.dispose();
    _cleanupTempFiles();
    super.dispose();
  }

  /// Clean up temporary files
  Future<void> _cleanupTempFiles() async {
    try {
      if (_originalImagePath != null) {
        final file = File(_originalImagePath!);
        if (await file.exists()) {
          await file.delete();
        }
      }
      if (_croppedImagePath != null) {
        final file = File(_croppedImagePath!);
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

  /// Get a temporary file path
  Future<String> _getTempFilePath(String extension) async {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final tempDir = await getTemporaryDirectory();
    return path.join(tempDir.path, 'doc_$timestamp.$extension');
  }

  /// Step 1: Select or capture image
  Future<void> _selectImage() async {
    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      final XFile? image = await _imagePicker.pickImage(
        source: ImageSource.camera,
        imageQuality: 90,
      );

      if (image == null) {
        setState(() {
          _isProcessing = false;
        });
        return;
      }

      // Save to temp directory
      final tempPath = await _getTempFilePath('jpg');
      await File(image.path).copy(tempPath);

      setState(() {
        _originalImagePath = tempPath;
        _currentStep = ScannerStep.edgeDetection;
        _isProcessing = false;
      });

      // Auto-proceed to edge detection
      _detectEdges();
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _errorMessage = 'Failed to select image: $e';
      });
    }
  }

  /// Step 2: Detect edges and crop document
  Future<void> _detectEdges() async {
    if (_originalImagePath == null) return;

    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      // Detect document edges using OpenCV
      final corners = await OpenCVService.detectDocumentEdges(_originalImagePath!);
      
      // If edge detection failed (empty corners), offer manual crop
      if (corners.isEmpty) {
        // Get image dimensions for corner initialization
        final image = cv.imread(_originalImagePath!);
        final width = image.cols;
        final height = image.rows;
        image.dispose();
        
        setState(() {
          _isProcessing = false;
          _currentStep = ScannerStep.manualCrop;
          _errorMessage = 'Auto-crop failed. Please adjust the corners manually.';
          // Initialize corners to image bounds
          _manualCropCorners = [
            const Offset(50.0, 50.0), // top-left
            Offset(width.toDouble() - 50.0, 50.0), // top-right
            Offset(width.toDouble() - 50.0, height.toDouble() - 50.0), // bottom-right
            Offset(50.0, height.toDouble() - 50.0), // bottom-left
          ];
        });
        return;
      }
      
      // Apply perspective transform to crop and straighten
      try {
        final croppedPath = await _getTempFilePath('jpg');
        await OpenCVService.perspectiveTransform(
          _originalImagePath!,
          corners,
          croppedPath,
        );

        // Resize to reasonable dimensions
        final resizedPath = await _getTempFilePath('jpg');
        await OpenCVService.resizeImage(
          croppedPath,
          resizedPath,
          maxWidth: 2000,
        );

        setState(() {
          _croppedImagePath = resizedPath;
          _filteredImagePath = resizedPath; // Initially same as cropped
          _currentStep = ScannerStep.filterSelection;
          _isProcessing = false;
        });
      } catch (e) {
        // If perspective transform fails, offer manual crop
        // Get image dimensions for corner initialization
        final image = cv.imread(_originalImagePath!);
        final width = image.cols;
        final height = image.rows;
        image.dispose();
        
        setState(() {
          _isProcessing = false;
          _currentStep = ScannerStep.manualCrop;
          _errorMessage = 'Auto-crop failed. Please adjust the corners manually.';
          // Initialize corners to image bounds
          _manualCropCorners = [
            const Offset(50.0, 50.0), // top-left
            Offset(width.toDouble() - 50.0, 50.0), // top-right
            Offset(width.toDouble() - 50.0, height.toDouble() - 50.0), // bottom-right
            Offset(50.0, height.toDouble() - 50.0), // bottom-left
          ];
        });
      }
    } catch (e) {
      // If any error occurs, offer manual crop
      // Get image dimensions for corner initialization
      final image = cv.imread(_originalImagePath!);
      final width = image.cols;
      final height = image.rows;
      image.dispose();
      
      setState(() {
        _isProcessing = false;
        _currentStep = ScannerStep.manualCrop;
        _errorMessage = 'Processing failed. Please adjust the corners manually.';
        // Initialize corners to image bounds
        _manualCropCorners = [
          const Offset(50.0, 50.0), // top-left
          Offset(width.toDouble() - 50.0, 50.0), // top-right
          Offset(width.toDouble() - 50.0, height.toDouble() - 50.0), // bottom-right
          Offset(50.0, height.toDouble() - 50.0), // bottom-left
        ];
      });
    }
  }

  /// Step 3: Apply selected filter
  Future<void> _applyFilter(ImageFilter filter) async {
    if (_croppedImagePath == null) return;

    setState(() {
      _isProcessing = true;
      _selectedFilter = filter;
      _errorMessage = null;
    });

    try {
      String filteredPath;

      switch (filter) {
        case ImageFilter.original:
          filteredPath = _croppedImagePath!;
          break;
        case ImageFilter.magicColor:
          filteredPath = await _getTempFilePath('jpg');
          await OpenCVService.applyMagicColorFilter(
            _croppedImagePath!,
            filteredPath,
          );
          break;
        case ImageFilter.blackAndWhite:
          filteredPath = await _getTempFilePath('jpg');
          await OpenCVService.applyBWFilter(
            _croppedImagePath!,
            filteredPath,
          );
          break;
        case ImageFilter.enhanced:
          filteredPath = await _getTempFilePath('jpg');
          await OpenCVService.adjustContrastBrightness(
            _croppedImagePath!,
            filteredPath,
            alpha: 1.3,
            beta: 30.0,
          );
          break;
      }

      setState(() {
        _filteredImagePath = filteredPath;
        _isProcessing = false;
      });
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _errorMessage = 'Filter application failed: $e';
      });
    }
  }

  /// Step 4: Extract text using OCR
  Future<void> _extractText() async {
    if (_filteredImagePath == null) return;

    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      final result = await _ocrService.extractText(_filteredImagePath!);

      setState(() {
        _ocrResult = result;
        _currentStep = ScannerStep.result;
        _isProcessing = false;
      });
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _errorMessage = 'OCR failed: $e';
      });
    }
  }

  /// Export to PDF
  Future<void> _exportToPDF() async {
    if (_filteredImagePath == null) return;

    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      final imageFile = File(_filteredImagePath!);
      final imageBytes = await imageFile.readAsBytes();

      // Create PDF document
      final pdf = pw.Document();
      
      final pdfImage = pw.MemoryImage(imageBytes);
      
      pdf.addPage(
        pw.Page(
          build: (pw.Context context) {
            return pw.Center(
              child: pw.Image(pdfImage, fit: pw.BoxFit.contain),
            );
          },
        ),
      );

      // If OCR text exists, add it as a second page
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

      // Show print/share dialog
      await Printing.sharePdf(
        bytes: await pdf.save(),
        filename: 'scanned_document_${DateTime.now().millisecondsSinceEpoch}.pdf',
      );

      setState(() {
        _isProcessing = false;
      });
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _errorMessage = 'PDF export failed: $e';
      });
    }
  }

  /// Reset scanner to start over
  void _resetScanner() {
    setState(() {
      _currentStep = ScannerStep.selectImage;
      _originalImagePath = null;
      _croppedImagePath = null;
      _filteredImagePath = null;
      _ocrResult = null;
      _selectedFilter = ImageFilter.original;
      _errorMessage = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Document Scanner'),
        actions: [
          if (_currentStep != ScannerStep.selectImage)
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: _resetScanner,
              tooltip: 'Start Over',
            ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_isProcessing) {
      return const Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 16),
            Text('Processing...'),
          ],
        ),
      );
    }

    if (_errorMessage != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.error_outline, size: 48, color: Colors.red),
              const SizedBox(height: 16),
              Text(
                _errorMessage!,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.red),
              ),
              const SizedBox(height: 16),
              ElevatedButton(
                onPressed: _resetScanner,
                child: const Text('Try Again'),
              ),
            ],
          ),
        ),
      );
    }

    switch (_currentStep) {
      case ScannerStep.selectImage:
        return _buildSelectImageStep();
      case ScannerStep.edgeDetection:
        return _buildEdgeDetectionStep();
      case ScannerStep.manualCrop:
        return _buildManualCropStep();
      case ScannerStep.filterSelection:
        return _buildFilterSelectionStep();
      case ScannerStep.result:
        return _buildResultStep();
    }
  }

  /// Step 1: Select Image UI
  Widget _buildSelectImageStep() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(
            Icons.document_scanner_outlined,
            size: 100,
            color: Colors.grey,
          ),
          const SizedBox(height: 24),
          const Text(
            'Scan a Document',
            style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          const Text(
            'Take a photo of a document to scan',
            style: TextStyle(color: Colors.grey),
          ),
          const SizedBox(height: 32),
          ElevatedButton.icon(
            onPressed: _selectImage,
            icon: const Icon(Icons.camera_alt),
            label: const Text('Take Photo'),
            style: ElevatedButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
            ),
          ),
        ],
      ),
    );
  }

  /// Step 2: Edge Detection UI
  Widget _buildEdgeDetectionStep() {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          CircularProgressIndicator(),
          SizedBox(height: 16),
          Text('Detecting document edges...'),
          SizedBox(height: 8),
          Text(
            'Finding document boundaries',
            style: TextStyle(color: Colors.grey, fontSize: 12),
          ),
        ],
      ),
    );
  }

  /// Step 2.5: Manual Crop UI
  Widget _buildManualCropStep() {
    return Column(
      children: [
        // Image preview with manual crop controls
        Expanded(
          child: _originalImagePath != null
              ? _buildManualCropWidget()
              : const Center(child: Text('No image')),
        ),
        // Manual crop controls
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: Colors.white,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.1),
                blurRadius: 10,
              ),
            ],
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Manual Crop',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 16),
              const Text(
                'Drag the corners to adjust the document area',
                style: TextStyle(color: Colors.grey, fontSize: 12),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: _skipManualCrop,
                      icon: const Icon(Icons.skip_next),
                      label: const Text('Skip Crop'),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: _applyManualCrop,
                      icon: const Icon(Icons.crop),
                      label: const Text('Apply Crop'),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ],
    );
  }

  /// Manual crop widget with draggable corners
  Widget _buildManualCropWidget() {
    return Stack(
      children: [
        // Image display
        Positioned.fill(
          child: Image.file(
            File(_originalImagePath!),
            fit: BoxFit.contain,
          ),
        ),
        // Crop overlay
        if (_manualCropCorners != null && _manualCropCorners!.length == 4)
          Positioned.fill(
            child: CustomPaint(
              painter: _CropOverlayPainter(_manualCropCorners!),
            ),
          ),
        // Corner handles
        if (_manualCropCorners != null && _manualCropCorners!.length == 4)
          ..._manualCropCorners!.asMap().entries.map((entry) {
            final index = entry.key;
            final corner = entry.value;
            return Positioned(
              left: corner.dx - 20,
              top: corner.dy - 20,
              child: GestureDetector(
                onPanUpdate: (details) {
                  _updateCorner(index, details);
                },
                child: Container(
                  width: 40,
                  height: 40,
                  decoration: BoxDecoration(
                    color: Colors.orange,
                    shape: BoxShape.circle,
                    border: Border.all(color: Colors.white, width: 2),
                  ),
                  child: const Icon(Icons.circle, color: Colors.white, size: 12),
                ),
              ),
            );
          }),
      ],
    );
  }

  /// Update corner position during drag
  void _updateCorner(int index, DragUpdateDetails details) {
    if (_manualCropCorners == null || _manualCropCorners!.length != 4) return;
    
    setState(() {
      _manualCropCorners![index] = details.localPosition;
    });
  }

  /// Apply manual crop
  Future<void> _applyManualCrop() async {
    if (_manualCropCorners == null || _manualCropCorners!.length != 4) return;

    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      // Convert Offset corners to OpenCV points
      final corners = _manualCropCorners!.map((offset) {
        return cv.Point(offset.dx.toInt(), offset.dy.toInt());
      }).toList();

      // Apply perspective transform
      final croppedPath = await _getTempFilePath('jpg');
      await OpenCVService.perspectiveTransform(
        _originalImagePath!,
        corners,
        croppedPath,
      );

      // Resize to reasonable dimensions
      final resizedPath = await _getTempFilePath('jpg');
      await OpenCVService.resizeImage(
        croppedPath,
        resizedPath,
        maxWidth: 2000,
      );

      setState(() {
        _croppedImagePath = resizedPath;
        _filteredImagePath = resizedPath;
        _currentStep = ScannerStep.filterSelection;
        _isProcessing = false;
        _manualCropCorners = null;
      });
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _errorMessage = 'Manual crop failed: $e';
      });
    }
  }

  /// Skip manual crop and use original image
  Future<void> _skipManualCrop() async {
    setState(() {
      _isProcessing = true;
      _errorMessage = null;
    });

    try {
      final resizedPath = await _getTempFilePath('jpg');
      await OpenCVService.resizeImage(
        _originalImagePath!,
        resizedPath,
        maxWidth: 2000,
      );

      setState(() {
        _croppedImagePath = resizedPath;
        _filteredImagePath = resizedPath;
        _currentStep = ScannerStep.filterSelection;
        _isProcessing = false;
        _manualCropCorners = null;
      });
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _errorMessage = 'Failed to process image: $e';
      });
    }
  }

  /// Step 3: Filter Selection UI
  Widget _buildFilterSelectionStep() {
    return Column(
      children: [
        // Image preview
        Expanded(
          child: _filteredImagePath != null
              ? Image.file(
                  File(_filteredImagePath!),
                  fit: BoxFit.contain,
                )
              : const Center(child: Text('No image')),
        ),
        // Filter options
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: Colors.white,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.1),
                blurRadius: 10,
              ),
            ],
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Select Filter',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 16),
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
                  children: ImageFilter.values.map((filter) {
                    return Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 8),
                      child: FilterChip(
                        label: Text(_getFilterLabel(filter)),
                        selected: _selectedFilter == filter,
                        onSelected: (selected) {
                          if (selected) {
                            _applyFilter(filter);
                          }
                        },
                        selectedColor: Theme.of(context).primaryColor.withValues(alpha: 0.2),
                      ),
                    );
                  }).toList(),
                ),
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: _extractText,
                      icon: const Icon(Icons.text_fields),
                      label: const Text('Extract Text'),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: _exportToPDF,
                      icon: const Icon(Icons.picture_as_pdf),
                      label: const Text('Export PDF'),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ],
    );
  }

  /// Step 4: Result UI
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
                    ? Padding(
                        padding: const EdgeInsets.all(16.0),
                        child: SingleChildScrollView(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              if (_ocrResult!.success) ...[
                                Row(
                                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                  children: [
                                    Text(
                                      'Words: ${_ocrResult!.wordCount}',
                                      style: const TextStyle(color: Colors.grey),
                                    ),
                                    Text(
                                      'Characters: ${_ocrResult!.charCount}',
                                      style: const TextStyle(color: Colors.grey),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 16),
                                SelectableText(
                                  _ocrResult!.fullText.isNotEmpty
                                      ? _ocrResult!.fullText
                                      : 'No text detected',
                                  style: const TextStyle(fontSize: 16),
                                ),
                              ] else
                                Text(
                                  _ocrResult?.error ?? 'OCR failed',
                                  style: const TextStyle(color: Colors.red),
                                ),
                            ],
                          ),
                        ),
                      )
                    : const Center(child: Text('No OCR result')),
              ],
            ),
          ),
          // Action buttons
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.white,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.1),
                  blurRadius: 10,
                ),
              ],
            ),
            child: Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () {
                      setState(() {
                        _currentStep = ScannerStep.filterSelection;
                      });
                    },
                    icon: const Icon(Icons.filter_list),
                    label: const Text('Change Filter'),
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _exportToPDF,
                    icon: const Icon(Icons.picture_as_pdf),
                    label: const Text('Export PDF'),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _getFilterLabel(ImageFilter filter) {
    switch (filter) {
      case ImageFilter.original:
        return 'Original';
      case ImageFilter.magicColor:
        return 'Magic Color';
      case ImageFilter.blackAndWhite:
        return 'B&W';
      case ImageFilter.enhanced:
        return 'Enhanced';
    }
  }
}

/// Custom painter for crop overlay
class _CropOverlayPainter extends CustomPainter {
  final List<Offset> corners;

  _CropOverlayPainter(this.corners);

  @override
  void paint(Canvas canvas, Size size) {
    if (corners.length != 4) return;

    final paint = Paint()
      ..color = Colors.orange.withValues(alpha: 0.3)
      ..style = PaintingStyle.fill;

    final borderPaint = Paint()
      ..color = Colors.orange
      ..style = PaintingStyle.stroke
      ..strokeWidth = 3;

    final path = Path()
      ..moveTo(corners[0].dx, corners[0].dy)
      ..lineTo(corners[1].dx, corners[1].dy)
      ..lineTo(corners[2].dx, corners[2].dy)
      ..lineTo(corners[3].dx, corners[3].dy)
      ..close();

    canvas.drawPath(path, paint);
    canvas.drawPath(path, borderPaint);

    // Draw corner handles
    for (final corner in corners) {
      canvas.drawCircle(corner, 10, borderPaint);
    }
  }

  @override
  bool shouldRepaint(_CropOverlayPainter oldDelegate) {
    return oldDelegate.corners != corners;
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
