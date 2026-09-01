import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:google_mlkit_face_detection/google_mlkit_face_detection.dart';
import 'package:image_picker/image_picker.dart';
import 'package:image/image.dart' as img;
import 'package:path_provider/path_provider.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import '../services/cutout_pro_service.dart';
import '../services/remove_bg_service.dart';
import '../services/subject_segmentation_service.dart';
import '../widgets/app_widgets.dart';

enum SuitCategory { all, male, female, student }

class SuitPresetInfo {
  final String label;
  final String assetPath;
  final IconData icon;
  final SuitCategory category;

  const SuitPresetInfo({
    required this.label,
    required this.assetPath,
    required this.icon,
    required this.category,
  });
}

/// Passport Photo Studio Screen (Subject Segmentation + 4x6 / 3x4 ID Sizing + Virtual Suit)
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
  Uint8List? _cutoutForegroundBytes; // Cached transparent PNG from Remove.bg

  bool _isFlipped = false;
  Timer? _debounceTimer;

  void _debouncedRenderComposite() {
    _debounceTimer?.cancel();
    _debounceTimer = Timer(const Duration(milliseconds: 50), () {
      _renderCompositeFromCutout();
    });
  }

  // Virtual Suit Overlay State
  SuitCategory _selectedSuitCategory = SuitCategory.all;
  String? _selectedSuitKey;
  double _suitScale = 1.0;
  double _suitOffsetY = 0.0;
  double _suitOffsetX = 0.0;
  bool _hasAutoFittedSuit = false;

  final Map<String, SuitPresetInfo> _suitPresets = {
    'cutout_man_1': const SuitPresetInfo(label: 'អាវបុរសទី 1', assetPath: 'assets/suits/cutout_man_1.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_2': const SuitPresetInfo(label: 'អាវបុរសទី 2', assetPath: 'assets/suits/cutout_man_2.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_3': const SuitPresetInfo(label: 'អាវបុរសទី 3', assetPath: 'assets/suits/cutout_man_3.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_4': const SuitPresetInfo(label: 'អាវបុរសទី 4', assetPath: 'assets/suits/cutout_man_4.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_5': const SuitPresetInfo(label: 'អាវបុរសទី 5', assetPath: 'assets/suits/cutout_man_5.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_6': const SuitPresetInfo(label: 'អាវបុរសទី 6', assetPath: 'assets/suits/cutout_man_6.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_7': const SuitPresetInfo(label: 'អាវបុរសទី 7', assetPath: 'assets/suits/cutout_man_7.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_8': const SuitPresetInfo(label: 'អាវបុរសទី 8', assetPath: 'assets/suits/cutout_man_8.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_9': const SuitPresetInfo(label: 'អាវបុរសទី 9', assetPath: 'assets/suits/cutout_man_9.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_10': const SuitPresetInfo(label: 'អាវបុរសទី 10', assetPath: 'assets/suits/cutout_man_10.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_11': const SuitPresetInfo(label: 'អាវបុរសទី 11', assetPath: 'assets/suits/cutout_man_11.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_12': const SuitPresetInfo(label: 'អាវបុរសទី 12', assetPath: 'assets/suits/cutout_man_12.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_13': const SuitPresetInfo(label: 'អាវបុរសទី 13', assetPath: 'assets/suits/cutout_man_13.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_14': const SuitPresetInfo(label: 'អាវបុរសទី 14', assetPath: 'assets/suits/cutout_man_14.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_15': const SuitPresetInfo(label: 'អាវបុរសទី 15', assetPath: 'assets/suits/cutout_man_15.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_16': const SuitPresetInfo(label: 'អាវបុរសទី 16', assetPath: 'assets/suits/cutout_man_16.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_17': const SuitPresetInfo(label: 'អាវបុរសទី 17', assetPath: 'assets/suits/cutout_man_17.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_18': const SuitPresetInfo(label: 'អាវបុរសទី 18', assetPath: 'assets/suits/cutout_man_18.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_19': const SuitPresetInfo(label: 'អាវបុរសទី 19', assetPath: 'assets/suits/cutout_man_19.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_20': const SuitPresetInfo(label: 'អាវបុរសទី 20', assetPath: 'assets/suits/cutout_man_20.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_21': const SuitPresetInfo(label: 'អាវបុរសទី 21', assetPath: 'assets/suits/cutout_man_21.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_22': const SuitPresetInfo(label: 'អាវបុរសទី 22', assetPath: 'assets/suits/cutout_man_22.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_23': const SuitPresetInfo(label: 'អាវបុរសទី 23', assetPath: 'assets/suits/cutout_man_23.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_24': const SuitPresetInfo(label: 'អាវបុរសទី 24', assetPath: 'assets/suits/cutout_man_24.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_25': const SuitPresetInfo(label: 'អាវបុរសទី 25', assetPath: 'assets/suits/cutout_man_25.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_26': const SuitPresetInfo(label: 'អាវបុរសទី 26', assetPath: 'assets/suits/cutout_man_26.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_27': const SuitPresetInfo(label: 'អាវបុរសទី 27', assetPath: 'assets/suits/cutout_man_27.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_28': const SuitPresetInfo(label: 'អាវបុរសទី 28', assetPath: 'assets/suits/cutout_man_28.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_woman_1': const SuitPresetInfo(label: 'អាវនារីទី 1', assetPath: 'assets/suits/cutout_woman_1.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_2': const SuitPresetInfo(label: 'អាវនារីទី 2', assetPath: 'assets/suits/cutout_woman_2.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_3': const SuitPresetInfo(label: 'អាវនារីទី 3', assetPath: 'assets/suits/cutout_woman_3.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_4': const SuitPresetInfo(label: 'អាវនារីទី 4', assetPath: 'assets/suits/cutout_woman_4.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_5': const SuitPresetInfo(label: 'អាវនារីទី 5', assetPath: 'assets/suits/cutout_woman_5.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_6': const SuitPresetInfo(label: 'អាវនារីទី 6', assetPath: 'assets/suits/cutout_woman_6.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_7': const SuitPresetInfo(label: 'អាវនារីទី 7', assetPath: 'assets/suits/cutout_woman_7.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_8': const SuitPresetInfo(label: 'អាវនារីទី 8', assetPath: 'assets/suits/cutout_woman_8.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_9': const SuitPresetInfo(label: 'អាវនារីទី 9', assetPath: 'assets/suits/cutout_woman_9.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_10': const SuitPresetInfo(label: 'អាវនារីទី 10', assetPath: 'assets/suits/cutout_woman_10.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_11': const SuitPresetInfo(label: 'អាវនារីទី 11', assetPath: 'assets/suits/cutout_woman_11.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_12': const SuitPresetInfo(label: 'អាវនារីទី 12', assetPath: 'assets/suits/cutout_woman_12.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_13': const SuitPresetInfo(label: 'អាវនារីទី 13', assetPath: 'assets/suits/cutout_woman_13.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_14': const SuitPresetInfo(label: 'អាវនារីទី 14', assetPath: 'assets/suits/cutout_woman_14.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_15': const SuitPresetInfo(label: 'អាវនារីទី 15', assetPath: 'assets/suits/cutout_woman_15.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_16': const SuitPresetInfo(label: 'អាវនារីទី 16', assetPath: 'assets/suits/cutout_woman_16.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_17': const SuitPresetInfo(label: 'អាវនារីទី 17', assetPath: 'assets/suits/cutout_woman_17.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_18': const SuitPresetInfo(label: 'អាវនារីទី 18', assetPath: 'assets/suits/cutout_woman_18.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_child_1': const SuitPresetInfo(label: 'អាវកុមារទី 1', assetPath: 'assets/suits/cutout_child_1.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_2': const SuitPresetInfo(label: 'អាវកុមារទី 2', assetPath: 'assets/suits/cutout_child_2.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_3': const SuitPresetInfo(label: 'អាវកុមារទី 3', assetPath: 'assets/suits/cutout_child_3.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_4': const SuitPresetInfo(label: 'អាវកុមារទី 4', assetPath: 'assets/suits/cutout_child_4.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_5': const SuitPresetInfo(label: 'អាវកុមារទី 5', assetPath: 'assets/suits/cutout_child_5.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_6': const SuitPresetInfo(label: 'អាវកុមារទី 6', assetPath: 'assets/suits/cutout_child_6.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_7': const SuitPresetInfo(label: 'អាវកុមារទី 7', assetPath: 'assets/suits/cutout_child_7.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_8': const SuitPresetInfo(label: 'អាវកុមារទី 8', assetPath: 'assets/suits/cutout_child_8.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_9': const SuitPresetInfo(label: 'អាវកុមារទី 9', assetPath: 'assets/suits/cutout_child_9.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_10': const SuitPresetInfo(label: 'អាវកុមារទី 10', assetPath: 'assets/suits/cutout_child_10.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_11': const SuitPresetInfo(label: 'អាវកុមារទី 11', assetPath: 'assets/suits/cutout_child_11.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_12': const SuitPresetInfo(label: 'អាវកុមារទី 12', assetPath: 'assets/suits/cutout_child_12.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_13': const SuitPresetInfo(label: 'អាវកុមារទី 13', assetPath: 'assets/suits/cutout_child_13.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_14': const SuitPresetInfo(label: 'អាវកុមារទី 14', assetPath: 'assets/suits/cutout_child_14.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_15': const SuitPresetInfo(label: 'អាវកុមារទី 15', assetPath: 'assets/suits/cutout_child_15.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_16': const SuitPresetInfo(label: 'អាវកុមារទី 16', assetPath: 'assets/suits/cutout_child_16.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
  };

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
      _processAiCloudRemoveBgCutout(showToast: false);
    }
  }

  @override
  void dispose() {
    _debounceTimer?.cancel();
    _segmentationService.clearCache();
    _segmentationService.dispose();
    super.dispose();
  }

  Future<void> _detectFaceAndAutoFitSuit() async {
    if (_imagePath == null) return;
    try {
      final inputImage = InputImage.fromFilePath(_imagePath!);
      final options = FaceDetectorOptions(
        performanceMode: FaceDetectorMode.accurate,
        enableLandmarks: true,
        enableContours: true,
      );
      final faceDetector = FaceDetector(options: options);
      final faces = await faceDetector.processImage(inputImage);
      faceDetector.close();

      if (faces.isNotEmpty) {
        final face = faces.first;
        final box = face.boundingBox;
        
        final imageBytes = await File(_imagePath!).readAsBytes();
        final decoded = img.decodeImage(imageBytes);
        if (decoded != null) {
          // 1. Precise chin point from Face Contour if available
          double chinY = box.bottom;
          double chinX = box.left + (box.width / 2.0);

          final faceContour = face.contours[FaceContourType.face]?.points;
          if (faceContour != null && faceContour.isNotEmpty) {
            double maxContourY = -1;
            int chinIndex = -1;
            for (int i = 0; i < faceContour.length; i++) {
              if (faceContour[i].y.toDouble() > maxContourY) {
                maxContourY = faceContour[i].y.toDouble();
                chinIndex = i;
              }
            }
            if (chinIndex != -1) {
              chinY = maxContourY;
              chinX = faceContour[chinIndex].x.toDouble();
            }
          }

          // 2. Head width & shoulder ratio calculation (Cutout.pro standard: ~2.38x face width)
          final double faceWidth = box.width;
          final double targetShoulderW = faceWidth * 2.38;
          final double suitCanvasTargetW = decoded.width * 0.92;
          _suitScale = (targetShoulderW / suitCanvasTargetW).clamp(0.70, 1.85);

          // 3. Horizontal centering directly beneath the chin
          final double imageCenterX = decoded.width / 2.0;
          _suitOffsetX = ((chinX - imageCenterX) / (decoded.width * 0.025)).clamp(-12.0, 12.0);

          // 4. Vertical neckline placement (Collar sits right below chin)
          final double suitHeight = decoded.width * 0.92 * _suitScale * 1.12;
          final double targetCollarTopY = chinY + (box.height * 0.03);
          final double defaultSuitTopY = decoded.height - suitHeight;
          _suitOffsetY = ((targetCollarTopY - defaultSuitTopY) / (decoded.height * 0.025)).clamp(-20.0, 20.0);
          
          _hasAutoFittedSuit = true;
        }
      }
    } catch (e) {
      debugPrint('Face detection auto-fit error: $e');
    }
  }

  Future<void> _pickImage(ImageSource source) async {
    try {
      final XFile? picked = await _picker.pickImage(source: source);
      if (picked != null) {
        _segmentationService.clearCache();
        setState(() {
          _imagePath = picked.path;
          _processedImagePath = null;
          _cutoutForegroundBytes = null;
          _isFlipped = (source == ImageSource.camera); // Auto flip selfie camera photos
          _hasAutoFittedSuit = false;
        });
        await _processAiCloudRemoveBgCutout(showToast: true);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('មិនអាចជ្រើសរើសរូបភាពបានទេ៖ $e', style: GoogleFonts.kantumruyPro())),
        );
      }
    }
  }

  /// Composite the transparent Remove.bg cutout foreground onto the selected background & suit
  Future<void> _renderCompositeFromCutout() async {
    if (_imagePath == null) return;
    if (_cutoutForegroundBytes == null) {
      await _processAiCloudRemoveBgCutout(showToast: false);
      return;
    }

    setState(() {
      _isProcessing = true;
      _statusText = 'កំពុងរៀបចំ និងផ្លាស់ប្តូរ Background...';
    });

    try {
      if (_selectedSuitKey != null && !_hasAutoFittedSuit) {
        await _detectFaceAndAutoFitSuit();
      }

      Uint8List? suitBytes;
      if (_selectedSuitKey != null && _suitPresets.containsKey(_selectedSuitKey)) {
        try {
          final assetPath = _suitPresets[_selectedSuitKey]!.assetPath;
          final ByteData data = await rootBundle.load(assetPath);
          suitBytes = data.buffer.asUint8List();
        } catch (e) {
          debugPrint('Error loading suit asset: $e');
        }
      }

      final outFile = await _segmentationService.createPassportBackground(
        imagePath: _imagePath!,
        backgroundColor: _selectedBgColor,
        foregroundBytes: _cutoutForegroundBytes,
        flipHorizontal: _isFlipped,
        suitKey: _selectedSuitKey,
        suitBytes: suitBytes,
        suitScale: _suitScale,
        suitOffsetX: _suitOffsetX,
        suitOffsetY: _suitOffsetY,
      );

      final croppedFile = await _cropToPresetRatio(outFile.path, _selectedPreset);

      if (mounted) {
        setState(() {
          _processedImagePath = croppedFile.path;
          _isProcessing = false;
          _statusText = null;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isProcessing = false;
          _statusText = null;
        });
      }
      debugPrint('Error rendering composite: $e');
    }
  }

  /// Cutout foreground with Multi-Engine Fallback: Remove.bg -> Cutout.pro -> ML Kit On-Device
  Future<void> _processAiCloudRemoveBgCutout({bool showToast = false}) async {
    if (_imagePath == null) return;

    setState(() {
      _isProcessing = true;
      _statusText = 'កំពុងកាត់ Background ដោយ AI (Remove.bg / Cutout.pro)...';
    });

    try {
      final imageFile = File(_imagePath!);
      final imageBytes = await imageFile.readAsBytes();
      Uint8List? resultBytes;
      String engineUsed = 'Remove.bg';

      // 1. Try Remove.bg Pool
      try {
        final rmbgService = RemoveBgService();
        resultBytes = await rmbgService.removeBackgroundBytes(imageBytes, size: 'preview');
      } catch (e) {
        debugPrint('Remove.bg error in studio: $e');
      }

      // 2. Fallback to Cutout.pro Pool
      if (resultBytes == null || resultBytes.isEmpty) {
        try {
          setState(() {
            _statusText = 'កំពុងប្តូរទៅប្រើ AI Cutout.pro...';
          });
          final cutoutService = CutoutProService();
          resultBytes = await cutoutService.removeBackgroundBytes(imageBytes);
          if (resultBytes != null && resultBytes.isNotEmpty) {
            engineUsed = 'Cutout.pro';
          }
        } catch (e) {
          debugPrint('Cutout.pro fallback error in studio: $e');
        }
      }

      // 3. Fallback to On-Device Google ML Kit Segmentation
      if (resultBytes == null || resultBytes.isEmpty) {
        try {
          setState(() {
            _statusText = 'កំពុងកាត់ Background ដោយ ML Kit On-Device...';
          });
          final segResult = await _segmentationService.segmentSubject(_imagePath!);
          if (segResult != null && segResult.foregroundBitmap != null) {
            resultBytes = segResult.foregroundBitmap;
            engineUsed = 'ML Kit (Offline)';
          }
        } catch (e) {
          debugPrint('ML Kit fallback error in studio: $e');
        }
      }

      if (resultBytes != null && resultBytes.isNotEmpty && mounted) {
        _cutoutForegroundBytes = resultBytes;
        _segmentationService.clearCache();
        await _renderCompositeFromCutout();

        if (showToast && mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Row(
                children: [
                  const Icon(Icons.check_circle_rounded, color: Colors.white, size: 20),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'បានកាត់ Background ដោយ AI $engineUsed ជោគជ័យ!',
                      style: GoogleFonts.kantumruyPro(fontSize: 13, fontWeight: FontWeight.bold),
                    ),
                  ),
                ],
              ),
              backgroundColor: const Color(0xFF10B981),
              behavior: SnackBarBehavior.floating,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            ),
          );
        }
      } else {
        if (mounted) {
          setState(() {
            _isProcessing = false;
            _statusText = null;
          });
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('មិនអាចកាត់ Background បានទេ សូមពិនិត្យ Internet ឬ API Keys', style: GoogleFonts.kantumruyPro()),
              backgroundColor: Colors.orange,
            ),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isProcessing = false;
          _statusText = null;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('កំហុស៖ $e', style: GoogleFonts.kantumruyPro()), backgroundColor: Colors.red),
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

  /// Enhance photo resolution using Cutout.pro AI Enhancer
  Future<void> _enhancePhotoWithCutoutPro() async {
    if (_processedImagePath == null && _imagePath == null) return;

    setState(() {
      _isProcessing = true;
      _statusText = 'កំពុងទាញរូបថតឱ្យច្បាស់ HD ដោយ AI Cutout.pro...';
    });

    try {
      final targetPath = _processedImagePath ?? _imagePath!;
      final imageBytes = await File(targetPath).readAsBytes();
      final enhancedBytes = await CutoutProService().enhancePhotoHD(imageBytes);

      if (enhancedBytes != null && enhancedBytes.isNotEmpty) {
        final tempDir = await getTemporaryDirectory();
        final outPath = '${tempDir.path}/enhanced_hd_${DateTime.now().millisecondsSinceEpoch}.jpg';
        final outFile = File(outPath);
        await outFile.writeAsBytes(enhancedBytes);

        if (!mounted) return;

        setState(() {
          _processedImagePath = outFile.path;
          _isProcessing = false;
          _statusText = null;
        });

        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                const Icon(Icons.auto_awesome, color: Colors.white, size: 20),
                const SizedBox(width: 8),
                Text(
                  'រូបថតត្រូវបានទាញឱ្យច្បាស់ HD ជោគជ័យ!',
                  style: GoogleFonts.kantumruyPro(fontSize: 13, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            backgroundColor: const Color(0xFF8B5CF6),
            behavior: SnackBarBehavior.floating,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          ),
        );
      } else {
        if (!mounted) return;
        setState(() {
          _isProcessing = false;
          _statusText = null;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('មិនអាចទាញរូបឱ្យច្បាស់បានទេ សូមពិនិត្យ Cutout.pro API Key', style: GoogleFonts.kantumruyPro()),
            backgroundColor: Colors.orange,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isProcessing = false;
          _statusText = null;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('កំហុស៖ $e', style: GoogleFonts.kantumruyPro()), backgroundColor: Colors.red),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final displayPath = _processedImagePath ?? _imagePath;

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: VvcAppBar(
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
          if (_imagePath != null) ...[
            IconButton(
              icon: const Icon(Icons.auto_awesome_rounded, color: Color(0xFFA855F7)),
              tooltip: 'ទាញរូបថតឱ្យច្បាស់ HD (Cutout.pro)',
              onPressed: _enhancePhotoWithCutoutPro,
            ),
            IconButton(
              icon: Icon(
                Icons.flip_rounded,
                color: _isFlipped ? Colors.tealAccent : Colors.white70,
              ),
              tooltip: 'បង្វិលរូបភាពបញ្ជ្រាស',
              onPressed: () {
                setState(() {
                  _isFlipped = !_isFlipped;
                });
                _renderCompositeFromCutout();
              },
            ),
          ],
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
                              _renderCompositeFromCutout();
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

                    // Background Color Selection & AI Remove.bg
                    Row(
                      children: [
                        Text(
                          'ផ្ទៃខាងក្រោយ (Background)៖',
                          style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.w600),
                        ),
                        const Spacer(),
                        // AI Cloud Remove.bg Button
                        Material(
                          color: Colors.transparent,
                          child: InkWell(
                            onTap: () => _processAiCloudRemoveBgCutout(showToast: true),
                            borderRadius: BorderRadius.circular(8),
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                              decoration: BoxDecoration(
                                gradient: const LinearGradient(
                                  colors: [Color(0xFF6366F1), Color(0xFF8B5CF6)],
                                ),
                                borderRadius: BorderRadius.circular(8),
                                boxShadow: [
                                  BoxShadow(
                                    color: const Color(0xFF6366F1).withValues(alpha: 0.4),
                                    blurRadius: 6,
                                  ),
                                ],
                              ),
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  const Icon(Icons.auto_awesome, color: Colors.white, size: 13),
                                  const SizedBox(width: 4),
                                  Text(
                                    '✨ AI Remove.bg',
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.white,
                                      fontSize: 10.5,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 6),
                        InkWell(
                          onTap: () {
                            setState(() {
                              _isFlipped = !_isFlipped;
                            });
                            _renderCompositeFromCutout();
                          },
                          borderRadius: BorderRadius.circular(6),
                          child: Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.flip_rounded,
                                  color: _isFlipped ? Colors.tealAccent : Colors.white60,
                                  size: 16,
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  _isFlipped ? 'បញ្ជ្រាស' : 'ត្រឡប់រូប',
                                  style: GoogleFonts.kantumruyPro(
                                    color: _isFlipped ? Colors.tealAccent : Colors.white60,
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(width: 4),
                        IconButton(
                          icon: const Icon(Icons.refresh_rounded, color: Colors.white54, size: 18),
                          onPressed: () => _pickImage(ImageSource.gallery),
                          tooltip: 'ប្តូរប្លង់ថតថ្មី',
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceAround,
                      children: _presetColors.map((color) {
                        final isSelected = _selectedBgColor == color;
                        return GestureDetector(
                          onTap: () {
                            setState(() {
                              _selectedBgColor = color;
                            });
                            _renderCompositeFromCutout();
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

                    const SizedBox(height: 14),

                    // Virtual Suit Selection Header & Clear
                    Row(
                      children: [
                        Text(
                          'បំពាក់អាវផ្លូវការ (Virtual Suit)៖',
                          style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.w600),
                        ),
                        const Spacer(),
                        if (_selectedSuitKey != null)
                          GestureDetector(
                            onTap: () {
                              setState(() {
                                _selectedSuitKey = null;
                                _suitScale = 1.0;
                                _suitOffsetX = 0.0;
                                _suitOffsetY = 0.0;
                              });
                              _renderCompositeFromCutout();
                            },
                            child: Text(
                              'ដោះអាវចេញ',
                              style: GoogleFonts.kantumruyPro(color: Colors.redAccent, fontSize: 11, fontWeight: FontWeight.bold),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 6),

                    // Suit Category Tabs (Cutout.pro style)
                    SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      physics: const BouncingScrollPhysics(),
                      child: Row(
                        children: [
                          _buildCategoryTab(SuitCategory.all, 'ទាំងអស់'),
                          _buildCategoryTab(SuitCategory.male, 'អាវបុរស'),
                          _buildCategoryTab(SuitCategory.female, 'អាវនារី'),
                          _buildCategoryTab(SuitCategory.student, 'អាវសិស្ស'),
                        ],
                      ),
                    ),
                    const SizedBox(height: 8),

                    // Filtered Suit Options Chips
                    SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      physics: const BouncingScrollPhysics(),
                      child: Row(
                        children: [
                          // None Option
                          GestureDetector(
                            onTap: () {
                              setState(() {
                                _selectedSuitKey = null;
                              });
                              _renderCompositeFromCutout();
                            },
                            child: Container(
                              margin: const EdgeInsets.only(right: 6),
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
                              decoration: BoxDecoration(
                                color: _selectedSuitKey == null ? const Color(0xFF0D9488) : Colors.white.withValues(alpha: 0.08),
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(
                                  color: _selectedSuitKey == null ? const Color(0xFF0D9488) : Colors.white12,
                                ),
                              ),
                              child: Text(
                                'គ្មានអាវ',
                                style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 11),
                              ),
                            ),
                          ),
                          ..._getFilteredSuitEntries().map((entry) {
                            final isSel = _selectedSuitKey == entry.key;
                            return GestureDetector(
                              onTap: () {
                                setState(() {
                                  _selectedSuitKey = entry.key;
                                });
                                _renderCompositeFromCutout();
                              },
                              child: Container(
                                margin: const EdgeInsets.only(right: 6),
                                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
                                decoration: BoxDecoration(
                                  color: isSel ? const Color(0xFF0D9488) : Colors.white.withValues(alpha: 0.08),
                                  borderRadius: BorderRadius.circular(8),
                                  border: Border.all(
                                    color: isSel ? const Color(0xFF0D9488) : Colors.white12,
                                  ),
                                ),
                                child: Row(
                                  children: [
                                    Icon(entry.value.icon, size: 14, color: isSel ? Colors.white : Colors.tealAccent),
                                    const SizedBox(width: 4),
                                    Text(
                                      entry.value.label,
                                      style: GoogleFonts.kantumruyPro(
                                        color: Colors.white,
                                        fontSize: 11,
                                        fontWeight: isSel ? FontWeight.bold : FontWeight.normal,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            );
                          }),
                        ],
                      ),
                    ),

                    // Suit Adjustments (Scale, Move X, Move Y, Reset)
                    if (_selectedSuitKey != null) ...[
                      const SizedBox(height: 10),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.04),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: Colors.white10),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Text(
                              'តម្រឹម៖',
                              style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 11),
                            ),
                            // Size -
                            IconButton(
                              icon: const Icon(Icons.remove_circle_outline, color: Colors.tealAccent, size: 18),
                              onPressed: () {
                                setState(() => _suitScale = (_suitScale - 0.05).clamp(0.5, 2.0));
                                _debouncedRenderComposite();
                              },
                              tooltip: 'បង្រួមអាវ',
                            ),
                            Text(
                              '${(_suitScale * 100).round()}%',
                              style: GoogleFonts.inter(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold),
                            ),
                            // Size +
                            IconButton(
                              icon: const Icon(Icons.add_circle_outline, color: Colors.tealAccent, size: 18),
                              onPressed: () {
                                setState(() => _suitScale = (_suitScale + 0.05).clamp(0.5, 2.0));
                                _debouncedRenderComposite();
                              },
                              tooltip: 'ពង្រីកអាវ',
                            ),
                            const SizedBox(width: 2),
                            // Move Left
                            IconButton(
                              icon: const Icon(Icons.arrow_back_rounded, color: Colors.white70, size: 16),
                              onPressed: () {
                                setState(() => _suitOffsetX -= 1.0);
                                _debouncedRenderComposite();
                              },
                              tooltip: 'រំកិលទៅឆ្វេង',
                            ),
                            // Move Right
                            IconButton(
                              icon: const Icon(Icons.arrow_forward_rounded, color: Colors.white70, size: 16),
                              onPressed: () {
                                setState(() => _suitOffsetX += 1.0);
                                _debouncedRenderComposite();
                              },
                              tooltip: 'រំកិលទៅស្តាំ',
                            ),
                            // Move Up
                            IconButton(
                              icon: const Icon(Icons.arrow_upward_rounded, color: Colors.white70, size: 16),
                              onPressed: () {
                                setState(() => _suitOffsetY -= 1.0);
                                _debouncedRenderComposite();
                              },
                              tooltip: 'លើកអាវឡើងលើ',
                            ),
                            // Move Down
                            IconButton(
                              icon: const Icon(Icons.arrow_downward_rounded, color: Colors.white70, size: 16),
                              onPressed: () {
                                setState(() => _suitOffsetY += 1.0);
                                _debouncedRenderComposite();
                              },
                              tooltip: 'ទម្លាក់អាវចុះក្រោម',
                            ),
                            // Reset Position
                            IconButton(
                              icon: const Icon(Icons.restart_alt_rounded, color: Colors.orangeAccent, size: 18),
                              onPressed: () {
                                setState(() {
                                  _suitScale = 1.0;
                                  _suitOffsetX = 0.0;
                                  _suitOffsetY = 0.0;
                                });
                                _debouncedRenderComposite();
                              },
                              tooltip: 'កំណត់ទីតាំងឡើងវិញ',
                            ),
                          ],
                        ),
                      ),
                    ],

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

  Widget _buildCategoryTab(SuitCategory cat, String label) {
    final isSelected = _selectedSuitCategory == cat;
    return GestureDetector(
      onTap: () {
        setState(() {
          _selectedSuitCategory = cat;
        });
      },
      child: Container(
        margin: const EdgeInsets.only(right: 6),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
        decoration: BoxDecoration(
          color: isSelected ? Colors.teal.shade700 : Colors.white10,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: isSelected ? Colors.tealAccent : Colors.transparent,
            width: 1,
          ),
        ),
        child: Text(
          label,
          style: GoogleFonts.kantumruyPro(
            color: isSelected ? Colors.white : Colors.white60,
            fontSize: 11,
            fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
          ),
        ),
      ),
    );
  }

  List<MapEntry<String, SuitPresetInfo>> _getFilteredSuitEntries() {
    if (_selectedSuitCategory == SuitCategory.all) {
      return _suitPresets.entries.toList();
    }
    return _suitPresets.entries.where((e) => e.value.category == _selectedSuitCategory).toList();
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
