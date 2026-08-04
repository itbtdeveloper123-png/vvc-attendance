import 'dart:io';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:image_picker/image_picker.dart';
import 'package:image/image.dart' as img;
import 'package:path_provider/path_provider.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import '../services/subject_segmentation_service.dart';

/// Passport Photo Studio Screen (Subject Segmentation + 4x6 / 3x4 ID Sizing)
class PassportPhotoScreen extends StatefulWidget {
  final String? initialImagePath;

  const PassportPhotoScreen({super.key, this.initialImagePath});

  @override
  State<PassportPhotoScreen> createState() => _PassportPhotoScreenState();
}

class _PassportPhotoScreenState extends State<PassportPhotoScreen> {
  final SubjectSegmentationService _segmentationService = SubjectSegmentationService();
  final ImagePicker _picker = ImagePicker();

  String? _imagePath;
  String? _processedImagePath;
  bool _isProcessing = false;
  String? _statusText;

  // Passport presets: 4x6 cm, 3x4 cm, 2x3 cm, 5x5 cm
  PassportPreset _selectedPreset = PassportPreset.size4x6;
  Color _selectedBgColor = Colors.white;

  final List<Color> _presetColors = [
    Colors.white,
    const Color(0xFF0D47A1), // Deep Blue (Official Cambodian ID/Work)
    const Color(0xFF29B6F6), // Light Sky Blue
    const Color(0xFFD32F2F), // Red
    const Color(0xFF2E7D32), // Green
    Colors.grey.shade300,
  ];

  @override
  void initState() {
    super.initState();
    if (widget.initialImagePath != null) {
      _imagePath = widget.initialImagePath;
      _processSegmentation();
    }
  }

  @override
  void dispose() {
    _segmentationService.dispose();
    super.dispose();
  }

  Future<void> _pickImage(ImageSource source) async {
    try {
      final XFile? picked = await _picker.pickImage(source: source);
      if (picked != null) {
        setState(() {
          _imagePath = picked.path;
          _processedImagePath = null;
        });
        await _processSegmentation();
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('មិនអាចជ្រើសរើសរូបភាពបានទេ៖ $e', style: GoogleFonts.kantumruyPro())),
        );
      }
    }
  }

  Future<void> _processSegmentation() async {
    if (_imagePath == null) return;

    setState(() {
      _isProcessing = true;
      _statusText = 'កំពុងបំបែកមនុស្ស និងផ្ទៃខាងក្រោយ...';
    });

    try {
      final result = await _segmentationService.segmentSubject(_imagePath!);
      
      final mask = result?.foregroundConfidenceMask;
      final subject = (result?.subjects.isNotEmpty ?? false) ? result!.subjects.first : null;
      final maskW = subject?.width;
      final maskH = subject?.height;

      setState(() {
        _statusText = 'កំពុងផ្លាស់ប្តូរ Background ទៅជាពណ៌ ${_getBgColorName(_selectedBgColor)}...';
      });

      final outFile = await _segmentationService.createPassportBackground(
        imagePath: _imagePath!,
        backgroundColor: _selectedBgColor,
        confidenceMask: mask,
        maskW: maskW,
        maskH: maskH,
      );

      // Crop according to selected preset aspect ratio
      final croppedFile = await _cropToPresetRatio(outFile.path, _selectedPreset);

      setState(() {
        _processedImagePath = croppedFile.path;
        _isProcessing = false;
        _statusText = null;
      });
    } catch (e) {
      setState(() {
        _isProcessing = false;
        _statusText = null;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('ការបំបែក Background បានបរាជ័យ៖ $e', style: GoogleFonts.kantumruyPro())),
        );
      }
    }
  }

  Future<File> _cropToPresetRatio(String srcPath, PassportPreset preset) async {
    final bytes = await File(srcPath).readAsBytes();
    img.Image? original = img.decodeImage(bytes);
    if (original == null) return File(srcPath);

    double targetRatio = preset.ratio;
    int srcW = original.width;
    int srcH = original.height;

    int cropW = srcW;
    int cropH = (cropW / targetRatio).round();

    if (cropH > srcH) {
      cropH = srcH;
      cropW = (cropH * targetRatio).round();
    }

    int cropX = ((srcW - cropW) / 2).round().clamp(0, srcW - 1);
    int cropY = ((srcH - cropH) / 2).round().clamp(0, srcH - 1);

    final cropped = img.copyCrop(original, x: cropX, y: cropY, width: cropW, height: cropH);
    final tempDir = await getTemporaryDirectory();
    final outPath = '${tempDir.path}/cropped_passport_${DateTime.now().millisecondsSinceEpoch}.jpg';
    final jpgBytes = img.encodeJpg(cropped, quality: 95);
    final outFile = File(outPath);
    await outFile.writeAsBytes(jpgBytes);
    return outFile;
  }

  Future<void> _exportPrintSheet() async {
    if (_processedImagePath == null) return;

    setState(() {
      _isProcessing = true;
      _statusText = 'កំពុងរៀបចំសន្លឹកព្រីន 4x6 / 3x4...';
    });

    try {
      final pdf = pw.Document();
      final imageBytes = await File(_processedImagePath!).readAsBytes();
      final pdfImage = pw.MemoryImage(imageBytes);

      // Create printable A4 page filled with 8 or 12 grid passport photos
      pdf.addPage(
        pw.Page(
          pageFormat: PdfPageFormat.a4,
          build: (pw.Context ctx) {
            return pw.Center(
              child: pw.Wrap(
                spacing: 12,
                runSpacing: 12,
                children: List.generate(8, (index) {
                  return pw.Container(
                    width: _selectedPreset == PassportPreset.size4x6 ? 113.38 : 85.03, // approx 4cm or 3cm in pt
                    height: _selectedPreset == PassportPreset.size4x6 ? 170.07 : 113.38, // approx 6cm or 4cm in pt
                    decoration: pw.BoxDecoration(
                      border: pw.Border.all(color: const PdfColor(0.8, 0.8, 0.8), width: 0.5),
                    ),
                    child: pw.Image(pdfImage, fit: pw.BoxFit.cover),
                  );
                }),
              ),
            );
          },
        ),
      );

      await Printing.sharePdf(
        bytes: await pdf.save(),
        filename: 'Passport_Photos_${_selectedPreset.label}.pdf',
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('មិនអាចបង្កើតសន្លឹកព្រីនបានទេ៖ $e', style: GoogleFonts.kantumruyPro())),
        );
      }
    } finally {
      setState(() {
        _isProcessing = false;
        _statusText = null;
      });
    }
  }

  String _getBgColorName(Color c) {
    if (c == Colors.white) return 'ពណ៌ស (Passport)';
    if (c == const Color(0xFF0D47A1)) return 'ពណ៌ខៀវចាស់ (ID Card)';
    if (c == const Color(0xFF29B6F6)) return 'ពណ៌ខៀវខ្ចី';
    if (c == const Color(0xFFD32F2F)) return 'ពណ៌ក្រហម';
    if (c == const Color(0xFF2E7D32)) return 'ពណ៌បៃតង';
    return 'ប្រផេះ';
  }

  @override
  Widget build(BuildContext context) {
    final displayPath = _processedImagePath ?? _imagePath;

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF0F172A),
        elevation: 0,
        centerTitle: true,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 20),
          onPressed: () => Navigator.pop(context, _processedImagePath),
        ),
        title: Text(
          'រូបថត 4x6 / 3x4 Studio',
          style: GoogleFonts.kantumruyPro(fontSize: 17, fontWeight: FontWeight.bold, color: Colors.white),
        ),
        actions: [
          if (_processedImagePath != null)
            IconButton(
              icon: const Icon(Icons.print_rounded, color: Colors.tealAccent),
              tooltip: 'ព្រីនសន្លឹក 4x6 / 3x4',
              onPressed: _exportPrintSheet,
            ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            // Image Preview Area
            Expanded(
              child: Container(
                margin: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.black,
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
                ),
                child: Stack(
                  children: [
                    if (displayPath != null)
                      Center(
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(12),
                          child: AspectRatio(
                            aspectRatio: _selectedPreset.ratio,
                            child: Image.file(
                              File(displayPath),
                              fit: BoxFit.cover,
                            ),
                          ),
                        ),
                      )
                    else
                      Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.portrait_rounded, size: 70, color: Colors.white24),
                            const SizedBox(height: 12),
                            Text(
                              'ជ្រើសរើសរូបថតដើម្បីបង្កើតរូប 4x6 / 3x4',
                              style: GoogleFonts.kantumruyPro(color: Colors.white38, fontSize: 13),
                            ),
                            const SizedBox(height: 16),
                            Row(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                ElevatedButton.icon(
                                  onPressed: () => _pickImage(ImageSource.camera),
                                  icon: const Icon(Icons.camera_alt_rounded, size: 18),
                                  label: const Text('ថតរូប'),
                                  style: ElevatedButton.styleFrom(
                                    backgroundColor: const Color(0xFF0D9488),
                                    foregroundColor: Colors.white,
                                  ),
                                ),
                                const SizedBox(width: 12),
                                OutlinedButton.icon(
                                  onPressed: () => _pickImage(ImageSource.gallery),
                                  icon: const Icon(Icons.photo_library_rounded, size: 18),
                                  label: const Text('វិចិត្រសាល'),
                                  style: OutlinedButton.styleFrom(
                                    foregroundColor: Colors.tealAccent,
                                    side: const BorderSide(color: Colors.tealAccent),
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),

                    // Processing overlay spinner
                    if (_isProcessing)
                      Container(
                        color: Colors.black87,
                        child: Center(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const CircularProgressIndicator(color: Color(0xFF0D9488)),
                              const SizedBox(height: 16),
                              Text(
                                _statusText ?? 'កំពុងដំណើរការ...',
                                style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13),
                              ),
                            ],
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ),

            // Controls Bar
            if (_imagePath != null)
              Container(
                color: const Color(0xFF141428),
                padding: EdgeInsets.only(
                  left: 16,
                  right: 16,
                  top: 12,
                  bottom: MediaQuery.of(context).padding.bottom + 12,
                ),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Size Preset Selection
                    Text(
                      'ជ្រើសរើសទំហំរូបថតផ្លូវការ៖',
                      style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.w600),
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: PassportPreset.values.map((preset) {
                        final isSelected = _selectedPreset == preset;
                        return Expanded(
                          child: GestureDetector(
                            onTap: () {
                              setState(() {
                                _selectedPreset = preset;
                              });
                              _processSegmentation();
                            },
                            child: Container(
                              margin: const EdgeInsets.symmetric(horizontal: 3),
                              padding: const EdgeInsets.symmetric(vertical: 8),
                              decoration: BoxDecoration(
                                color: isSelected ? const Color(0xFF0D9488) : Colors.white.withValues(alpha: 0.08),
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(
                                  color: isSelected ? const Color(0xFF0D9488) : Colors.white.withValues(alpha: 0.15),
                                ),
                              ),
                              child: Text(
                                preset.label,
                                textAlign: TextAlign.center,
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white,
                                  fontSize: 11,
                                  fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                                ),
                              ),
                            ),
                          ),
                        );
                      }).toList(),
                    ),

                    const SizedBox(height: 14),

                    // Background Color Selection
                    Row(
                      children: [
                        Text(
                          'ផ្ទៃខាងក្រោយ (Background)៖',
                          style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.w600),
                        ),
                        const Spacer(),
                        IconButton(
                          icon: const Icon(Icons.refresh_rounded, color: Colors.white54, size: 18),
                          onPressed: () => _pickImage(ImageSource.gallery),
                          tooltip: 'ប្តូរប្លង់ថតថ្មី',
                        ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceAround,
                      children: _presetColors.map((color) {
                        final isSelected = _selectedBgColor == color;
                        return GestureDetector(
                          onTap: () {
                            setState(() {
                              _selectedBgColor = color;
                            });
                            _processSegmentation();
                          },
                          child: Container(
                            width: 38,
                            height: 38,
                            decoration: BoxDecoration(
                              color: color,
                              shape: BoxShape.circle,
                              border: Border.all(
                                color: isSelected ? Colors.tealAccent : Colors.white24,
                                width: isSelected ? 3 : 1,
                              ),
                              boxShadow: isSelected
                                  ? [BoxShadow(color: Colors.tealAccent.withValues(alpha: 0.4), blurRadius: 8)]
                                  : null,
                            ),
                            child: isSelected ? const Icon(Icons.check, size: 20, color: Colors.black87) : null,
                          ),
                        );
                      }).toList(),
                    ),

                    const SizedBox(height: 16),

                    // Print Sheet Action Button
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _exportPrintSheet,
                        icon: const Icon(Icons.print_rounded, size: 20),
                        label: Text(
                          'ទាញយកសន្លឹកព្រីនរូបថត (Print Sheet 8x)',
                          style: GoogleFonts.kantumruyPro(fontSize: 13, fontWeight: FontWeight.bold),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF0D9488),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 13),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }
}

enum PassportPreset {
  size4x6,
  size3x4,
  size2x3,
  size5x5,
}

extension PassportPresetExt on PassportPreset {
  String get label {
    switch (this) {
      case PassportPreset.size4x6:
        return '4x6 cm';
      case PassportPreset.size3x4:
        return '3x4 cm';
      case PassportPreset.size2x3:
        return '2x3 cm';
      case PassportPreset.size5x5:
        return '5x5 cm';
    }
  }

  double get ratio {
    switch (this) {
      case PassportPreset.size4x6:
        return 4.0 / 6.0;
      case PassportPreset.size3x4:
        return 3.0 / 4.0;
      case PassportPreset.size2x3:
        return 2.0 / 3.0;
      case PassportPreset.size5x5:
        return 1.0;
    }
  }
}
