import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:image/image.dart' as img;
import 'package:image_picker/image_picker.dart';
import 'package:cunning_document_scanner/cunning_document_scanner.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import 'package:path_provider/path_provider.dart';
import '../widgets/app_widgets.dart';

/// Multi-Page Review Screen
/// Allows users to reorder, rotate, filter, preview, add, delete, and export multi-page scanned documents to PDF.
class MultiPageReviewScreen extends StatefulWidget {
  final List<String> imagePaths;
  final Function(List<String>) onPagesUpdated;
  final Function(String) onPageEdit;

  const MultiPageReviewScreen({
    super.key,
    required this.imagePaths,
    required this.onPagesUpdated,
    required this.onPageEdit,
  });

  @override
  State<MultiPageReviewScreen> createState() => _MultiPageReviewScreenState();
}

class _MultiPageReviewScreenState extends State<MultiPageReviewScreen> {
  late List<String> _pages;
  final ImagePicker _picker = ImagePicker();
  bool _isProcessing = false;
  String _processingMessage = '';
  int _imageVersion = 0; // Incremented on image edits to bust Image.file cache

  @override
  void initState() {
    super.initState();
    _pages = List<String>.from(widget.imagePaths);
  }

  // ==================== IMAGE MANIPULATION ====================

  /// Rotate a page 90 degrees clockwise or counter-clockwise
  Future<void> _rotatePage(int index, {bool clockwise = true}) async {
    if (index < 0 || index >= _pages.length) return;
    final path = _pages[index];
    final file = File(path);
    if (!file.existsSync()) return;

    setState(() {
      _isProcessing = true;
      _processingMessage = 'កំពុងបង្វិលទំព័រ...';
    });

    try {
      final bytes = await file.readAsBytes();
      final decoded = img.decodeImage(bytes);
      if (decoded != null) {
        final rotated = img.copyRotate(decoded, angle: clockwise ? 90 : -90);
        final encoded = img.encodeJpg(rotated, quality: 90);
        await file.writeAsBytes(encoded);
        setState(() {
          _imageVersion++;
        });
        if (mounted) {
          _showToast('បានបង្វិលទំព័រ ${index + 1} រួចរាល់');
        }
      }
    } catch (e) {
      if (mounted) {
        _showToast('មានបញ្ហាក្នុងការបង្វិល: $e', isError: true);
      }
    } finally {
      if (mounted) {
        setState(() {
          _isProcessing = false;
        });
      }
    }
  }

  /// Apply image filter preset (Grayscale, High-contrast Document B&W, Contrast Boost)
  Future<void> _applyFilter(int index, String filterType) async {
    if (index < 0 || index >= _pages.length) return;
    final path = _pages[index];
    final file = File(path);
    if (!file.existsSync()) return;

    setState(() {
      _isProcessing = true;
      _processingMessage = 'កំពុងកែសម្រួលពណ៌រូបភាព...';
    });

    try {
      final bytes = await file.readAsBytes();
      final decoded = img.decodeImage(bytes);
      if (decoded != null) {
        img.Image processed;
        switch (filterType) {
          case 'grayscale':
            processed = img.grayscale(decoded);
            break;
          case 'document_bw':
            // High contrast document filter for sharp text
            final gray = img.grayscale(decoded);
            processed = img.contrast(gray, contrast: 150);
            break;
          case 'boost':
            // Brighten and boost contrast
            processed = img.adjustColor(
              decoded,
              contrast: 1.25,
              brightness: 1.1,
              saturation: 1.15,
            );
            break;
          default:
            processed = decoded;
        }

        final encoded = img.encodeJpg(processed, quality: 92);
        await file.writeAsBytes(encoded);
        setState(() {
          _imageVersion++;
        });
        if (mounted) {
          _showToast('បានកែសម្រួល Filter លើទំព័រ ${index + 1}');
        }
      }
    } catch (e) {
      if (mounted) {
        _showToast('មានបញ្ហាក្នុងការកែ Filter: $e', isError: true);
      }
    } finally {
      if (mounted) {
        setState(() {
          _isProcessing = false;
        });
      }
    }
  }

  /// Duplicate a page
  Future<void> _duplicatePage(int index) async {
    if (index < 0 || index >= _pages.length) return;
    final path = _pages[index];
    final file = File(path);
    if (!file.existsSync()) return;

    setState(() {
      _isProcessing = true;
      _processingMessage = 'កំពុងស្ទួនទំព័រ...';
    });

    try {
      final tempDir = await getTemporaryDirectory();
      final newPath =
          '${tempDir.path}/scanned_copy_${DateTime.now().millisecondsSinceEpoch}_${index + 1}.jpg';
      await file.copy(newPath);

      setState(() {
        _pages.insert(index + 1, newPath);
      });
      if (mounted) {
        _showToast('បានស្ទួនទំព័រ ${index + 1} ដោយជោគជ័យ');
      }
    } catch (e) {
      if (mounted) {
        _showToast('មិនអាចស្ទួនបានទេ: $e', isError: true);
      }
    } finally {
      if (mounted) {
        setState(() {
          _isProcessing = false;
        });
      }
    }
  }

  // ==================== PAGE REORDERING ====================

  void _movePage(int fromIndex, int toIndex) {
    if (fromIndex == toIndex ||
        fromIndex < 0 ||
        fromIndex >= _pages.length ||
        toIndex < 0 ||
        toIndex >= _pages.length) {
      return;
    }
    setState(() {
      final item = _pages.removeAt(fromIndex);
      _pages.insert(toIndex, item);
    });
    HapticFeedback.mediumImpact();
  }

  void _deletePage(int index) {
    if (index < 0 || index >= _pages.length) return;
    final removedPath = _pages[index];
    setState(() {
      _pages.removeAt(index);
    });
    HapticFeedback.lightImpact();

    ScaffoldMessenger.of(context).clearSnackBars();
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: const Color(0xFF2C2C2E),
        content: Text(
          'បានលុបទំព័រ ${index + 1}',
          style: GoogleFonts.inter(color: Colors.white),
        ),
        action: SnackBarAction(
          label: 'ត្រឡប់វិញ (Undo)',
          textColor: Colors.orange,
          onPressed: () {
            setState(() {
              _pages.insert(index, removedPath);
            });
          },
        ),
        duration: const Duration(seconds: 4),
      ),
    );
  }

  // ==================== ADDING NEW PAGES ====================

  /// Scan with Cunning Native Document Scanner
  Future<void> _scanWithNativeScanner() async {
    setState(() {
      _isProcessing = true;
      _processingMessage = 'កំពុងបើក Scanner...';
    });

    try {
      final scannedImages = await CunningDocumentScanner.getPictures(
        noOfPages: 20,
        scannerSource: ScannerSource.camera,
      );

      if (scannedImages != null && scannedImages.isNotEmpty) {
        setState(() {
          _pages.addAll(scannedImages);
        });
        if (mounted) {
          _showToast('បានបន្ថែម ${scannedImages.length} ទំព័រថ្មី');
        }
      }
    } catch (e) {
      if (mounted) {
        _showToast('មិនអាចស្កេនបានទេ: $e', isError: true);
      }
    } finally {
      if (mounted) {
        setState(() {
          _isProcessing = false;
        });
      }
    }
  }

  /// Capture with Camera
  Future<void> _pickFromCamera() async {
    try {
      final XFile? photo = await _picker.pickImage(
        source: ImageSource.camera,
        imageQuality: 92,
      );

      if (photo != null) {
        setState(() {
          _pages.add(photo.path);
        });
        if (mounted) {
          _showToast('បានបន្ថែមទំព័រថ្មីពីកាមេរ៉ា');
        }
      }
    } catch (e) {
      if (mounted) {
        _showToast('មិនអាចថតរូបបានទេ: $e', isError: true);
      }
    }
  }

  /// Pick from Gallery
  Future<void> _pickFromGallery() async {
    try {
      final List<XFile> images = await _picker.pickMultiImage(
        imageQuality: 92,
      );

      if (images.isNotEmpty) {
        setState(() {
          _pages.addAll(images.map((f) => f.path));
        });
        if (mounted) {
          _showToast('បាននាំចូល ${images.length} រូបភាពពីវិចិត្រសាល');
        }
      }
    } catch (e) {
      if (mounted) {
        _showToast('មិនអាចជ្រើសរូបភាពបានទេ: $e', isError: true);
      }
    }
  }

  void _showAddPageDialog() {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E1E1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (context) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 44,
                height: 5,
                margin: const EdgeInsets.only(bottom: 20),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(3),
                ),
              ),
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: Colors.orange.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: const Icon(Icons.add_photo_alternate,
                        color: Colors.orange, size: 22),
                  ),
                  const SizedBox(width: 14),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'បន្ថែមទំព័រថ្មី',
                        style: GoogleFonts.inter(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      Text(
                        'ជ្រើសរើសប្រភពដើម្បីស្កេន ឬជ្រើសរើសរូបភាព',
                        style: GoogleFonts.inter(
                          color: Colors.white.withValues(alpha: 0.6),
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 20),
              _buildModalTile(
                icon: Icons.document_scanner,
                title: 'ស្កេនឯកសារដោយស្វ័យប្រវត្តិ (Smart Scanner)',
                subtitle: 'ស្កេនឯកសារច្រើនទំព័រដោយកាត់គែមស្វ័យប្រវត្តិ',
                color: Colors.orange,
                onTap: () {
                  Navigator.pop(context);
                  _scanWithNativeScanner();
                },
              ),
              const SizedBox(height: 10),
              _buildModalTile(
                icon: Icons.camera_alt,
                title: 'ថតរូបដោយកាមេរ៉ា (Camera)',
                subtitle: 'ថតទំព័រថ្មីដោយផ្ទាល់ពីកាមេរ៉ាទូរស័ព្ទ',
                color: Colors.blueAccent,
                onTap: () {
                  Navigator.pop(context);
                  _pickFromCamera();
                },
              ),
              const SizedBox(height: 10),
              _buildModalTile(
                icon: Icons.photo_library,
                title: 'ជ្រើសពីវិចិត្រសាល (Gallery)',
                subtitle: 'នាំចូលរូបភាពច្រើនសន្លឹកពី Photos/Gallery',
                color: Colors.greenAccent,
                onTap: () {
                  Navigator.pop(context);
                  _pickFromGallery();
                },
              ),
              const SizedBox(height: 12),
            ],
          ),
        ),
      ),
    );
  }

  // ==================== PDF GENERATION & EXPORT ====================

  Future<void> _exportAsPdf() async {
    if (_pages.isEmpty) {
      _showToast('មិនមានទំព័រសម្រាប់បង្កើត PDF ទេ', isError: true);
      return;
    }

    setState(() {
      _isProcessing = true;
      _processingMessage = 'កំពុងបង្កើតឯកសារ PDF...';
    });

    try {
      final pdf = pw.Document();

      for (int i = 0; i < _pages.length; i++) {
        final file = File(_pages[i]);
        if (await file.exists()) {
          final bytes = await file.readAsBytes();
          final imageProvider = pw.MemoryImage(bytes);
          pdf.addPage(
            pw.Page(
              pageFormat: PdfPageFormat.a4,
              margin: pw.EdgeInsets.zero,
              build: (pw.Context context) {
                return pw.FullPage(
                  ignoreMargins: true,
                  child: pw.Center(
                    child: pw.Image(
                      imageProvider,
                      fit: pw.BoxFit.contain,
                    ),
                  ),
                );
              },
            ),
          );
        }
      }

      final Uint8List pdfBytes = await pdf.save();

      if (mounted) {
        setState(() {
          _isProcessing = false;
        });
        _showPdfExportOptions(pdfBytes);
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isProcessing = false;
        });
        _showToast('មិនអាចបង្កើត PDF បានទេ: $e', isError: true);
      }
    }
  }

  void _showPdfExportOptions(Uint8List pdfBytes) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E1E1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (context) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 44,
                height: 5,
                margin: const EdgeInsets.only(bottom: 20),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(3),
                ),
              ),
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.redAccent.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(14),
                    ),
                    child: const Icon(Icons.picture_as_pdf,
                        color: Colors.redAccent, size: 28),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'ឯកសារ PDF បានរួចរាល់',
                          style: GoogleFonts.inter(
                            color: Colors.white,
                            fontSize: 18,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        Text(
                          'ចំនួន ${_pages.length} ទំព័រ • ${(pdfBytes.lengthInBytes / (1024 * 1024)).toStringAsFixed(2)} MB',
                          style: GoogleFonts.inter(
                            color: Colors.white.withValues(alpha: 0.6),
                            fontSize: 13,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 24),
              _buildModalTile(
                icon: Icons.print,
                title: 'មើល និងបោះពុម្ព (Print & Preview)',
                subtitle: 'មើលឯកសារ PDF និងផ្ញើទៅកាន់ម៉ាស៊ីនព្រីន',
                color: Colors.orange,
                onTap: () async {
                  Navigator.pop(context);
                  await Printing.layoutPdf(
                    onLayout: (PdfPageFormat format) async => pdfBytes,
                    name: 'VVC_Scanned_Document_${DateTime.now().millisecondsSinceEpoch}.pdf',
                  );
                },
              ),
              const SizedBox(height: 10),
              _buildModalTile(
                icon: Icons.share,
                title: 'ចែករំលែក PDF (Share Document)',
                subtitle: 'ផ្ញើទៅកាន់ Telegram, Email, ឬកម្មវិធីផ្សេងៗ',
                color: Colors.blueAccent,
                onTap: () async {
                  Navigator.pop(context);
                  await Printing.sharePdf(
                    bytes: pdfBytes,
                    filename: 'VVC_Scanned_Document_${DateTime.now().millisecondsSinceEpoch}.pdf',
                  );
                },
              ),
              const SizedBox(height: 10),
              _buildModalTile(
                icon: Icons.save_alt,
                title: 'រក្សាទុកក្នុងទូរស័ព្ទ (Save to Files)',
                subtitle: 'រក្សាទុកឯកសារជា PDF ក្នុង Memory',
                color: Colors.greenAccent,
                onTap: () async {
                  Navigator.pop(context);
                  try {
                    final outputDir = await getApplicationDocumentsDirectory();
                    final file = File(
                      '${outputDir.path}/VVC_Doc_${DateTime.now().millisecondsSinceEpoch}.pdf',
                    );
                    await file.writeAsBytes(pdfBytes);
                    if (mounted) {
                      _showToast('បានរក្សាទុកក្នុង: ${file.path}');
                    }
                  } catch (e) {
                    if (mounted) {
                      _showToast('កំហុសក្នុងការរក្សាទុក: $e', isError: true);
                    }
                  }
                },
              ),
              const SizedBox(height: 12),
            ],
          ),
        ),
      ),
    );
  }

  // ==================== FULLSCREEN PREVIEW ====================

  void _openFullscreenPreview(int initialIndex) {
    if (initialIndex < 0 || initialIndex >= _pages.length) return;

    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => _FullscreenPageViewer(
          pages: _pages,
          initialIndex: initialIndex,
          imageVersion: _imageVersion,
          onRotate: (index) async {
            await _rotatePage(index);
          },
          onFilter: (index, filter) async {
            await _applyFilter(index, filter);
          },
          onDelete: (index) {
            _deletePage(index);
          },
          onEdit: (path) {
            widget.onPageEdit(path);
          },
        ),
      ),
    ).then((_) {
      setState(() {});
    });
  }

  // ==================== HELPER WIDGETS ====================

  void _showToast(String message, {bool isError = false}) {
    ScaffoldMessenger.of(context).clearSnackBars();
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: isError ? Colors.redAccent : const Color(0xFF2C2C2E),
        content: Row(
          children: [
            Icon(
              isError ? Icons.error_outline : Icons.check_circle_outline,
              color: isError ? Colors.white : Colors.orange,
              size: 20,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                message,
                style: GoogleFonts.inter(color: Colors.white, fontSize: 13),
              ),
            ),
          ],
        ),
        duration: const Duration(seconds: 3),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
    );
  }

  Widget _buildModalTile({
    required IconData icon,
    required String title,
    required String subtitle,
    required Color color,
    required VoidCallback onTap,
  }) {
    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF252528),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: Colors.white.withValues(alpha: 0.05),
        ),
      ),
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
        leading: Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: color.withValues(alpha: 0.15),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Icon(icon, color: color, size: 22),
        ),
        title: Text(
          title,
          style: GoogleFonts.inter(
            color: Colors.white,
            fontSize: 15,
            fontWeight: FontWeight.w600,
          ),
        ),
        subtitle: Text(
          subtitle,
          style: GoogleFonts.inter(
            color: Colors.white.withValues(alpha: 0.5),
            fontSize: 12,
          ),
        ),
        trailing: Icon(
          Icons.arrow_forward_ios,
          color: Colors.white.withValues(alpha: 0.3),
          size: 14,
        ),
        onTap: onTap,
      ),
    );
  }

  void _showFilterSelectionDialog(int index) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E1E1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (context) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 40,
                height: 4,
                margin: const EdgeInsets.only(bottom: 20),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              Text(
                'កែសម្រួលពណ៌ទំព័រ ${index + 1}',
                style: GoogleFonts.inter(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 20),
              _buildOptionTile(
                icon: Icons.document_scanner,
                label: 'Black & White Document (អក្សរដិតច្បាស់)',
                color: Colors.white,
                onTap: () {
                  Navigator.pop(context);
                  _applyFilter(index, 'document_bw');
                },
              ),
              _buildOptionTile(
                icon: Icons.filter_b_and_w,
                label: 'Grayscale (ពណ៌ប្រផេះ)',
                color: Colors.grey,
                onTap: () {
                  Navigator.pop(context);
                  _applyFilter(index, 'grayscale');
                },
              ),
              _buildOptionTile(
                icon: Icons.auto_fix_high,
                label: 'Magic Color Boost (ពន្លឺ និងកម្រិតពណ៌)',
                color: Colors.orange,
                onTap: () {
                  Navigator.pop(context);
                  _applyFilter(index, 'boost');
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showPageOptions(int index, String path) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E1E1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (context) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 40,
                  height: 4,
                  margin: const EdgeInsets.only(bottom: 16),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.2),
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
                Text(
                  'ជម្រើសទំព័រ ${index + 1}',
                  style: GoogleFonts.inter(
                    color: Colors.white,
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 16),
                _buildOptionTile(
                  icon: Icons.fullscreen,
                  label: 'មើលពេញអេក្រង់ (Fullscreen Preview)',
                  color: Colors.cyanAccent,
                  onTap: () {
                    Navigator.pop(context);
                    _openFullscreenPreview(index);
                  },
                ),
                _buildOptionTile(
                  icon: Icons.rotate_right,
                  label: 'បង្វិល 90° តាមទ្រនិចនាឡិកា (Rotate)',
                  color: Colors.orange,
                  onTap: () {
                    Navigator.pop(context);
                    _rotatePage(index, clockwise: true);
                  },
                ),
                _buildOptionTile(
                  icon: Icons.photo_filter,
                  label: 'កែសម្រួលពណ៌ / Filters',
                  color: Colors.blueAccent,
                  onTap: () {
                    Navigator.pop(context);
                    _showFilterSelectionDialog(index);
                  },
                ),
                _buildOptionTile(
                  icon: Icons.edit,
                  label: 'កាត់តម្រឹមទំព័រ (Crop & Edit)',
                  color: Colors.white,
                  onTap: () {
                    Navigator.pop(context);
                    widget.onPageEdit(path);
                  },
                ),
                _buildOptionTile(
                  icon: Icons.copy,
                  label: 'ស្ទួនទំព័រនេះ (Duplicate Page)',
                  color: Colors.purpleAccent,
                  onTap: () {
                    Navigator.pop(context);
                    _duplicatePage(index);
                  },
                ),
                if (index > 0)
                  _buildOptionTile(
                    icon: Icons.arrow_upward,
                    label: 'ផ្លាស់ទីទៅលើ (Move Up)',
                    color: Colors.white70,
                    onTap: () {
                      Navigator.pop(context);
                      _movePage(index, index - 1);
                    },
                  ),
                if (index < _pages.length - 1)
                  _buildOptionTile(
                    icon: Icons.arrow_downward,
                    label: 'ផ្លាស់ទីចុះក្រោម (Move Down)',
                    color: Colors.white70,
                    onTap: () {
                      Navigator.pop(context);
                      _movePage(index, index + 1);
                    },
                  ),
                _buildOptionTile(
                  icon: Icons.delete,
                  label: 'លុបទំព័រនេះចេញ (Delete Page)',
                  color: Colors.redAccent,
                  onTap: () {
                    Navigator.pop(context);
                    _deletePage(index);
                  },
                ),
                const SizedBox(height: 10),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildOptionTile({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
    Color? color,
  }) {
    return ListTile(
      leading: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: (color ?? Colors.white).withValues(alpha: 0.1),
          borderRadius: BorderRadius.circular(10),
        ),
        child: Icon(icon, color: color ?? Colors.white, size: 20),
      ),
      title: Text(
        label,
        style: GoogleFonts.inter(
          color: color ?? Colors.white,
          fontSize: 15,
          fontWeight: FontWeight.w500,
        ),
      ),
      onTap: onTap,
    );
  }

  void _applyChanges() {
    widget.onPagesUpdated(_pages);
    Navigator.pop(context);
  }

  // ==================== BUILD METHOD ====================

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF121212),
      appBar: VvcAppBar(
        backgroundColor: const Color(0xFF1E1E1E),
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new, color: Colors.white, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          'ពិនិត្យទំព័រឯកសារ (${_pages.length})',
          style: GoogleFonts.inter(
            color: Colors.white,
            fontSize: 18,
            fontWeight: FontWeight.w600,
          ),
        ),
        actions: [
          IconButton(
            tooltip: 'នាំចេញជា PDF',
            icon: const Icon(Icons.picture_as_pdf, color: Colors.redAccent, size: 22),
            onPressed: _pages.isNotEmpty ? _exportAsPdf : null,
          ),
          IconButton(
            tooltip: 'បន្ថែមទំព័រថ្មី',
            icon: const Icon(Icons.add_circle, color: Colors.orange, size: 24),
            onPressed: _showAddPageDialog,
          ),
        ],
      ),
      body: Stack(
        children: [
          Column(
            children: [
              // Instruction & Info Banner
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                margin: const EdgeInsets.fromLTRB(16, 12, 16, 10),
                decoration: BoxDecoration(
                  color: Colors.orange.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(
                    color: Colors.orange.withValues(alpha: 0.25),
                    width: 1,
                  ),
                ),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(6),
                      decoration: BoxDecoration(
                        color: Colors.orange.withValues(alpha: 0.15),
                        shape: BoxShape.circle,
                      ),
                      child: const Icon(Icons.touch_app, color: Colors.orange, size: 18),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'ចុចលើទំព័រដើម្បីមើល និងកែសម្រួល ឬប្រើសញ្ញាព្រួញដើម្បីប្តូរលំដាប់ទំព័រ។',
                        style: GoogleFonts.inter(
                          color: Colors.white.withValues(alpha: 0.85),
                          fontSize: 12.5,
                          height: 1.3,
                        ),
                      ),
                    ),
                  ],
                ),
              ),

              // Pages Grid / Empty State
              Expanded(
                child: _pages.isEmpty
                    ? _buildEmptyState()
                    : GridView.builder(
                        padding: const EdgeInsets.fromLTRB(16, 6, 16, 20),
                        gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                          crossAxisCount: 2,
                          mainAxisSpacing: 14,
                          crossAxisSpacing: 14,
                          childAspectRatio: 0.72,
                        ),
                        itemCount: _pages.length,
                        itemBuilder: (context, index) {
                          final path = _pages[index];
                          return _buildPageCard(index, path);
                        },
                      ),
              ),

              // Bottom Action Bar
              Container(
                padding: EdgeInsets.only(
                  left: 16,
                  right: 16,
                  top: 14,
                  bottom: MediaQuery.of(context).padding.bottom + 14,
                ),
                decoration: BoxDecoration(
                  color: const Color(0xFF1E1E1E),
                  border: Border(
                    top: BorderSide(
                      color: Colors.white.withValues(alpha: 0.08),
                      width: 1,
                    ),
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: 0.4),
                      blurRadius: 12,
                      offset: const Offset(0, -4),
                    ),
                  ],
                ),
                child: Row(
                  children: [
                    // PDF Button
                    Expanded(
                      flex: 1,
                      child: OutlinedButton.icon(
                        onPressed: _pages.isNotEmpty ? _exportAsPdf : null,
                        style: OutlinedButton.styleFrom(
                          foregroundColor: Colors.white,
                          side: BorderSide(
                            color: Colors.white.withValues(alpha: 0.2),
                          ),
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(14),
                          ),
                        ),
                        icon: const Icon(Icons.picture_as_pdf, color: Colors.redAccent, size: 20),
                        label: Text(
                          'PDF',
                          style: GoogleFonts.inter(
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    // Apply Changes Button
                    Expanded(
                      flex: 2,
                      child: ElevatedButton.icon(
                        onPressed: _pages.isNotEmpty ? _applyChanges : null,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.orange,
                          foregroundColor: Colors.white,
                          disabledBackgroundColor: Colors.orange.withValues(alpha: 0.3),
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          elevation: 0,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(14),
                          ),
                        ),
                        icon: const Icon(Icons.check, size: 20),
                        label: Text(
                          'រក្សាទុកការផ្លាស់ប្តូរ (${_pages.length})',
                          style: GoogleFonts.inter(
                            fontSize: 14,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),

          // Processing Overlay
          if (_isProcessing)
            Container(
              color: Colors.black.withValues(alpha: 0.7),
              child: Center(
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 22),
                  decoration: BoxDecoration(
                    color: const Color(0xFF252528),
                    borderRadius: BorderRadius.circular(18),
                    border: Border.all(
                      color: Colors.white.withValues(alpha: 0.1),
                    ),
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const CircularProgressIndicator(
                        color: Colors.orange,
                        strokeWidth: 3,
                      ),
                      const SizedBox(height: 16),
                      Text(
                        _processingMessage.isNotEmpty
                            ? _processingMessage
                            : 'កំពុងដំណើរការ...',
                        style: GoogleFonts.inter(
                          color: Colors.white,
                          fontSize: 14,
                          fontWeight: FontWeight.w500,
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

  Widget _buildEmptyState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: Colors.orange.withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: const Icon(
                Icons.document_scanner_outlined,
                size: 56,
                color: Colors.orange,
              ),
            ),
            const SizedBox(height: 20),
            Text(
              'មិនទាន់មានទំព័រឯកសារទេ',
              style: GoogleFonts.inter(
                color: Colors.white,
                fontSize: 18,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'សូមបន្ថែមទំព័រតាមរយៈការស្កេន ឬជ្រើសរើសរូបភាពពីវិចិត្រសាល',
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(
                color: Colors.grey,
                fontSize: 13,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: _showAddPageDialog,
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.orange,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                ),
              ),
              icon: const Icon(Icons.add, size: 20),
              label: Text(
                'បន្ថែមទំព័រឥឡូវនេះ',
                style: GoogleFonts.inter(
                  fontSize: 14,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPageCard(int index, String path) {
    final file = File(path);
    final exists = file.existsSync();

    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF1E1E1E),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: Colors.white.withValues(alpha: 0.1),
          width: 1.2,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.25),
            blurRadius: 8,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      clipBehavior: Clip.antiAlias,
      child: Stack(
        fit: StackFit.expand,
        children: [
          // Image Preview
          if (exists)
            GestureDetector(
              onTap: () => _openFullscreenPreview(index),
              child: Image.file(
                file,
                fit: BoxFit.cover,
                key: ValueKey('$path-$_imageVersion'),
                errorBuilder: (context, error, stackTrace) => Container(
                  color: const Color(0xFF2C2C2E),
                  child: const Center(
                    child: Icon(Icons.broken_image, color: Colors.grey, size: 36),
                  ),
                ),
              ),
            )
          else
            Container(
              color: const Color(0xFF2C2C2E),
              child: const Center(
                child: Icon(Icons.image_not_supported, color: Colors.grey, size: 36),
              ),
            ),

          // Gradient overlay at top and bottom for readability
          Positioned(
            top: 0,
            left: 0,
            right: 0,
            height: 48,
            child: Container(
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter,
                  colors: [
                    Colors.black.withValues(alpha: 0.75),
                    Colors.transparent,
                  ],
                ),
              ),
            ),
          ),
          Positioned(
            bottom: 0,
            left: 0,
            right: 0,
            height: 52,
            child: Container(
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.bottomCenter,
                  end: Alignment.topCenter,
                  colors: [
                    Colors.black.withValues(alpha: 0.85),
                    Colors.transparent,
                  ],
                ),
              ),
            ),
          ),

          // Page Number Badge
          Positioned(
            top: 8,
            left: 8,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.75),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: Colors.orange.withValues(alpha: 0.6),
                  width: 1,
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.description, color: Colors.orange, size: 12),
                  const SizedBox(width: 4),
                  Text(
                    'ទំព័រ ${index + 1}',
                    style: GoogleFonts.inter(
                      color: Colors.white,
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ],
              ),
            ),
          ),

          // Options Menu Button
          Positioned(
            top: 6,
            right: 6,
            child: Material(
              color: Colors.transparent,
              child: InkWell(
                onTap: () => _showPageOptions(index, path),
                borderRadius: BorderRadius.circular(20),
                child: Container(
                  padding: const EdgeInsets.all(5),
                  decoration: BoxDecoration(
                    color: Colors.black.withValues(alpha: 0.65),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(
                    Icons.more_vert,
                    color: Colors.white,
                    size: 18,
                  ),
                ),
              ),
            ),
          ),

          // Bottom Controls: Quick Action Buttons (Rotate, Edit, Delete)
          Positioned(
            bottom: 6,
            left: 6,
            right: 6,
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                // Quick Rotate
                _buildQuickActionBtn(
                  icon: Icons.rotate_right,
                  tooltip: 'បង្វិល',
                  onTap: () => _rotatePage(index, clockwise: true),
                ),
                // Quick Filter
                _buildQuickActionBtn(
                  icon: Icons.photo_filter,
                  tooltip: 'Filter',
                  onTap: () => _showFilterSelectionDialog(index),
                ),
                // Quick Fullscreen Preview
                _buildQuickActionBtn(
                  icon: Icons.fullscreen,
                  tooltip: 'មើលពេញ',
                  onTap: () => _openFullscreenPreview(index),
                ),
                // Quick Delete
                _buildQuickActionBtn(
                  icon: Icons.delete_outline,
                  tooltip: 'លុប',
                  color: Colors.redAccent,
                  onTap: () => _deletePage(index),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQuickActionBtn({
    required IconData icon,
    required String tooltip,
    required VoidCallback onTap,
    Color? color,
  }) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(16),
        child: Container(
          padding: const EdgeInsets.all(6),
          decoration: BoxDecoration(
            color: Colors.black.withValues(alpha: 0.65),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: Colors.white.withValues(alpha: 0.15),
              width: 0.8,
            ),
          ),
          child: Icon(
            icon,
            color: color ?? Colors.white,
            size: 15,
          ),
        ),
      ),
    );
  }
}

// ==================== FULLSCREEN PAGE VIEWER ====================

class _FullscreenPageViewer extends StatefulWidget {
  final List<String> pages;
  final int initialIndex;
  final int imageVersion;
  final Future<void> Function(int) onRotate;
  final Future<void> Function(int, String) onFilter;
  final Function(int) onDelete;
  final Function(String) onEdit;

  const _FullscreenPageViewer({
    required this.pages,
    required this.initialIndex,
    required this.imageVersion,
    required this.onRotate,
    required this.onFilter,
    required this.onDelete,
    required this.onEdit,
  });

  @override
  State<_FullscreenPageViewer> createState() => _FullscreenPageViewerState();
}

class _FullscreenPageViewerState extends State<_FullscreenPageViewer> {
  late PageController _pageController;
  late int _currentIndex;
  late int _version;

  @override
  void initState() {
    super.initState();
    _currentIndex = widget.initialIndex;
    _version = widget.imageVersion;
    _pageController = PageController(initialPage: widget.initialIndex);
  }

  @override
  void dispose() {
    _pageController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (widget.pages.isEmpty) {
      Navigator.pop(context);
      return const SizedBox.shrink();
    }

    final safeIndex = _currentIndex.clamp(0, widget.pages.length - 1);
    final currentPath = widget.pages[safeIndex];

    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black.withValues(alpha: 0.85),
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.close, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          'ទំព័រ ${safeIndex + 1} នៃ ${widget.pages.length}',
          style: GoogleFonts.inter(
            color: Colors.white,
            fontSize: 16,
            fontWeight: FontWeight.w600,
          ),
        ),
        centerTitle: true,
        actions: [
          IconButton(
            tooltip: 'កាត់តម្រឹម (Crop)',
            icon: const Icon(Icons.crop, color: Colors.white),
            onPressed: () {
              widget.onEdit(currentPath);
            },
          ),
          IconButton(
            tooltip: 'លុបទំព័រ',
            icon: const Icon(Icons.delete, color: Colors.redAccent),
            onPressed: () {
              final deletedIdx = safeIndex;
              widget.onDelete(deletedIdx);
              if (widget.pages.isEmpty) {
                Navigator.pop(context);
              } else {
                setState(() {
                  _currentIndex = (_currentIndex - 1).clamp(0, widget.pages.length - 1);
                });
              }
            },
          ),
        ],
      ),
      body: Column(
        children: [
          // Main Interactive Zoomable Viewer
          Expanded(
            child: PageView.builder(
              controller: _pageController,
              itemCount: widget.pages.length,
              onPageChanged: (index) {
                setState(() {
                  _currentIndex = index;
                });
              },
              itemBuilder: (context, index) {
                final file = File(widget.pages[index]);
                return Center(
                  child: InteractiveViewer(
                    panEnabled: true,
                    minScale: 0.8,
                    maxScale: 4.0,
                    child: Image.file(
                      file,
                      key: ValueKey('${widget.pages[index]}-$_version'),
                      fit: BoxFit.contain,
                      errorBuilder: (context, error, stackTrace) => const Center(
                        child: Icon(Icons.broken_image, color: Colors.grey, size: 64),
                      ),
                    ),
                  ),
                );
              },
            ),
          ),

          // Bottom Interactive Tool Bar
          Container(
            padding: EdgeInsets.only(
              left: 20,
              right: 20,
              top: 14,
              bottom: MediaQuery.of(context).padding.bottom + 14,
            ),
            decoration: BoxDecoration(
              color: const Color(0xFF1E1E1E),
              border: Border(
                top: BorderSide(
                  color: Colors.white.withValues(alpha: 0.1),
                  width: 0.5,
                ),
              ),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceAround,
              children: [
                _buildViewerAction(
                  icon: Icons.rotate_left,
                  label: 'បង្វិលឆ្វេង',
                  onTap: () async {
                    await widget.onRotate(safeIndex);
                    setState(() {
                      _version++;
                    });
                  },
                ),
                _buildViewerAction(
                  icon: Icons.rotate_right,
                  label: 'បង្វិលស្តាំ',
                  onTap: () async {
                    await widget.onRotate(safeIndex);
                    setState(() {
                      _version++;
                    });
                  },
                ),
                _buildViewerAction(
                  icon: Icons.document_scanner,
                  label: 'B&W Doc',
                  onTap: () async {
                    await widget.onFilter(safeIndex, 'document_bw');
                    setState(() {
                      _version++;
                    });
                  },
                ),
                _buildViewerAction(
                  icon: Icons.filter_b_and_w,
                  label: 'Grayscale',
                  onTap: () async {
                    await widget.onFilter(safeIndex, 'grayscale');
                    setState(() {
                      _version++;
                    });
                  },
                ),
                _buildViewerAction(
                  icon: Icons.auto_fix_high,
                  label: 'Boost',
                  color: Colors.orange,
                  onTap: () async {
                    await widget.onFilter(safeIndex, 'boost');
                    setState(() {
                      _version++;
                    });
                  },
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildViewerAction({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
    Color? color,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: color ?? Colors.white, size: 22),
            const SizedBox(height: 4),
            Text(
              label,
              style: GoogleFonts.inter(
                color: color ?? Colors.white.withValues(alpha: 0.8),
                fontSize: 11,
                fontWeight: FontWeight.w500,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
