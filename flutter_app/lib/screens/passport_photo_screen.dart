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
  final String shortLabel;
  final String assetPath;
  final IconData icon;
  final SuitCategory category;

  const SuitPresetInfo({
    required this.label,
    required this.shortLabel,
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

class _PassportPhotoScreenState extends State<PassportPhotoScreen> with SingleTickerProviderStateMixin {
  final SubjectSegmentationService _segmentationService = SubjectSegmentationService();
  final ImagePicker _picker = ImagePicker();

  String? _imagePath;
  String? _processedImagePath;
  bool _isProcessing = false;
  String? _statusText;
  Uint8List? _cutoutForegroundBytes; // Cached transparent PNG from Remove.bg

  bool _isFlipped = false;
  Timer? _debounceTimer;

  // Active Control Deck Tab: 0 = Suit, 1 = Background, 2 = Size Preset
  int _activeDeckTab = 0;

  // Virtual Suit Overlay State
  SuitCategory _selectedSuitCategory = SuitCategory.all;
  String? _selectedSuitKey;
  double _suitScale = 1.0;
  double _suitOffsetY = 0.0;
  double _suitOffsetX = 0.0;
  bool _hasAutoFittedSuit = false;

  // Track gesture scale baseline
  double _baseScale = 1.0;

  final Map<String, SuitPresetInfo> _suitPresets = {
    // Men's Suits & Formal Shirts
    'cutout_man_1': const SuitPresetInfo(label: 'អាវបុរសទី ១', shortLabel: 'បុរស ១', assetPath: 'assets/suits/cutout_man_1.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_2': const SuitPresetInfo(label: 'អាវបុរសទី ២', shortLabel: 'បុរស ២', assetPath: 'assets/suits/cutout_man_2.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_3': const SuitPresetInfo(label: 'អាវបុរសទី ៣', shortLabel: 'បុរស ៣', assetPath: 'assets/suits/cutout_man_3.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_4': const SuitPresetInfo(label: 'អាវបុរសទី ៤', shortLabel: 'បុរស ៤', assetPath: 'assets/suits/cutout_man_4.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_5': const SuitPresetInfo(label: 'អាវបុរសទី ៥', shortLabel: 'បុរស ៥', assetPath: 'assets/suits/cutout_man_5.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_6': const SuitPresetInfo(label: 'អាវបុរសទី ៦', shortLabel: 'បុរស ៦', assetPath: 'assets/suits/cutout_man_6.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_7': const SuitPresetInfo(label: 'អាវបុរសទី ៧', shortLabel: 'បុរស ៧', assetPath: 'assets/suits/cutout_man_7.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_8': const SuitPresetInfo(label: 'អាវបុរសទី ៨', shortLabel: 'បុរស ៨', assetPath: 'assets/suits/cutout_man_8.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_9': const SuitPresetInfo(label: 'អាវបុរសទី ៩', shortLabel: 'បុរស ៩', assetPath: 'assets/suits/cutout_man_9.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_10': const SuitPresetInfo(label: 'អាវបុរសទី ១០', shortLabel: 'បុរស ១០', assetPath: 'assets/suits/cutout_man_10.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_11': const SuitPresetInfo(label: 'អាវបុរសទី ១១', shortLabel: 'បុរស ១១', assetPath: 'assets/suits/cutout_man_11.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_12': const SuitPresetInfo(label: 'អាវបុរសទី ១២', shortLabel: 'បុរស ១២', assetPath: 'assets/suits/cutout_man_12.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_13': const SuitPresetInfo(label: 'អាវបុរសទី ១៣', shortLabel: 'បុរស ១៣', assetPath: 'assets/suits/cutout_man_13.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_14': const SuitPresetInfo(label: 'អាវបុរសទី ១៤', shortLabel: 'បុរស ១៤', assetPath: 'assets/suits/cutout_man_14.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_15': const SuitPresetInfo(label: 'អាវបុរសទី ១៥', shortLabel: 'បុរស ១៥', assetPath: 'assets/suits/cutout_man_15.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_16': const SuitPresetInfo(label: 'អាវបុរសទី ១៦', shortLabel: 'បុរស ១៦', assetPath: 'assets/suits/cutout_man_16.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_17': const SuitPresetInfo(label: 'អាវបុរសទី ១៧', shortLabel: 'បុរស ១៧', assetPath: 'assets/suits/cutout_man_17.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_18': const SuitPresetInfo(label: 'អាវបុរសទី ១៨', shortLabel: 'បុរស ១៨', assetPath: 'assets/suits/cutout_man_18.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_19': const SuitPresetInfo(label: 'អាវបុរសទី ១៩', shortLabel: 'បុរស ១៩', assetPath: 'assets/suits/cutout_man_19.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_20': const SuitPresetInfo(label: 'អាវបុរសទី ២០', shortLabel: 'បុរស ២០', assetPath: 'assets/suits/cutout_man_20.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_21': const SuitPresetInfo(label: 'អាវបុរសទី ២១', shortLabel: 'បុរស ២១', assetPath: 'assets/suits/cutout_man_21.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_22': const SuitPresetInfo(label: 'អាវបុរសទី ២២', shortLabel: 'បុរស ២២', assetPath: 'assets/suits/cutout_man_22.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_23': const SuitPresetInfo(label: 'អាវបុរសទី ២៣', shortLabel: 'បុរស ២៣', assetPath: 'assets/suits/cutout_man_23.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_24': const SuitPresetInfo(label: 'អាវបុរសទី ២៤', shortLabel: 'បុរស ២៤', assetPath: 'assets/suits/cutout_man_24.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_25': const SuitPresetInfo(label: 'អាវបុរសទី ២៥', shortLabel: 'បុរស ២៥', assetPath: 'assets/suits/cutout_man_25.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_26': const SuitPresetInfo(label: 'អាវបុរសទី ២៦', shortLabel: 'បុរស ២៦', assetPath: 'assets/suits/cutout_man_26.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_27': const SuitPresetInfo(label: 'អាវបុរសទី ២៧', shortLabel: 'បុរស ២៧', assetPath: 'assets/suits/cutout_man_27.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'cutout_man_28': const SuitPresetInfo(label: 'អាវបុរសទី ២៨', shortLabel: 'បុរស ២៨', assetPath: 'assets/suits/cutout_man_28.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'suit_male_black': const SuitPresetInfo(label: 'អាវធំខ្មៅបុរស', shortLabel: 'ធំខ្មៅ', assetPath: 'assets/suits/suit_male_black.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'suit_male_navy': const SuitPresetInfo(label: 'អាវធំប៊្លូហ្សីន', shortLabel: 'ធំប៊្លូ', assetPath: 'assets/suits/suit_male_navy.png', icon: Icons.business_center_rounded, category: SuitCategory.male),
    'suit_shirt_tie': const SuitPresetInfo(label: 'អាវស + ក្រវាត់ក', shortLabel: 'ស ក្រវាត់ក', assetPath: 'assets/suits/suit_shirt_tie.png', icon: Icons.business_center_rounded, category: SuitCategory.male),

    // Women's Suits & Blouses
    'cutout_woman_1': const SuitPresetInfo(label: 'អាវនារីទី ១', shortLabel: 'នារី ១', assetPath: 'assets/suits/cutout_woman_1.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_2': const SuitPresetInfo(label: 'អាវនារីទី ២', shortLabel: 'នារី ២', assetPath: 'assets/suits/cutout_woman_2.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_3': const SuitPresetInfo(label: 'អាវនារីទី ៣', shortLabel: 'នារី ៣', assetPath: 'assets/suits/cutout_woman_3.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_4': const SuitPresetInfo(label: 'អាវនារីទី ៤', shortLabel: 'នារី ៤', assetPath: 'assets/suits/cutout_woman_4.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_5': const SuitPresetInfo(label: 'អាវនារីទី ៥', shortLabel: 'នារី ៥', assetPath: 'assets/suits/cutout_woman_5.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_6': const SuitPresetInfo(label: 'អាវនារីទី ៦', shortLabel: 'នារី ៦', assetPath: 'assets/suits/cutout_woman_6.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_7': const SuitPresetInfo(label: 'អាវនារីទី ៧', shortLabel: 'នារី ៧', assetPath: 'assets/suits/cutout_woman_7.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_8': const SuitPresetInfo(label: 'អាវនារីទី ៨', shortLabel: 'នារី ៨', assetPath: 'assets/suits/cutout_woman_8.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_9': const SuitPresetInfo(label: 'អាវនារីទី ៩', shortLabel: 'នារី ៩', assetPath: 'assets/suits/cutout_woman_9.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_10': const SuitPresetInfo(label: 'អាវនារីទី ១០', shortLabel: 'នារី ១០', assetPath: 'assets/suits/cutout_woman_10.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_11': const SuitPresetInfo(label: 'អាវនារីទី ១១', shortLabel: 'នារី ១១', assetPath: 'assets/suits/cutout_woman_11.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_12': const SuitPresetInfo(label: 'អាវនារីទី ១២', shortLabel: 'នារី ១២', assetPath: 'assets/suits/cutout_woman_12.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_13': const SuitPresetInfo(label: 'អាវនារីទី ១៣', shortLabel: 'នារី ១៣', assetPath: 'assets/suits/cutout_woman_13.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_14': const SuitPresetInfo(label: 'អាវនារីទី ១៤', shortLabel: 'នារី ១៤', assetPath: 'assets/suits/cutout_woman_14.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_15': const SuitPresetInfo(label: 'អាវនារីទី ១៥', shortLabel: 'នារី ១៥', assetPath: 'assets/suits/cutout_woman_15.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_16': const SuitPresetInfo(label: 'អាវនារីទី ១៦', shortLabel: 'នារី ១៦', assetPath: 'assets/suits/cutout_woman_16.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_17': const SuitPresetInfo(label: 'អាវនារីទី ១៧', shortLabel: 'នារី ១៧', assetPath: 'assets/suits/cutout_woman_17.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'cutout_woman_18': const SuitPresetInfo(label: 'អាវនារីទី ១៨', shortLabel: 'នារី ១៨', assetPath: 'assets/suits/cutout_woman_18.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'suit_female_black': const SuitPresetInfo(label: 'អាវធំខ្មៅនារី', shortLabel: 'ធំខ្មៅ', assetPath: 'assets/suits/suit_female_black.png', icon: Icons.woman_rounded, category: SuitCategory.female),
    'suit_female_blue': const SuitPresetInfo(label: 'អាវធំប៊្លូនារី', shortLabel: 'ធំប៊្លូ', assetPath: 'assets/suits/suit_female_blue.png', icon: Icons.woman_rounded, category: SuitCategory.female),

    // Student & Children's Uniforms
    'cutout_child_1': const SuitPresetInfo(label: 'អាវកុមារទី ១', shortLabel: 'សិស្ស ១', assetPath: 'assets/suits/cutout_child_1.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_2': const SuitPresetInfo(label: 'អាវកុមារទី ២', shortLabel: 'សិស្ស ២', assetPath: 'assets/suits/cutout_child_2.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_3': const SuitPresetInfo(label: 'អាវកុមារទី ៣', shortLabel: 'សិស្ស ៣', assetPath: 'assets/suits/cutout_child_3.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_4': const SuitPresetInfo(label: 'អាវកុមារទី ៤', shortLabel: 'សិស្ស ៤', assetPath: 'assets/suits/cutout_child_4.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_5': const SuitPresetInfo(label: 'អាវកុមារទី ៥', shortLabel: 'សិស្ស ៥', assetPath: 'assets/suits/cutout_child_5.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_6': const SuitPresetInfo(label: 'អាវកុមារទី ៦', shortLabel: 'សិស្ស ៦', assetPath: 'assets/suits/cutout_child_6.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_7': const SuitPresetInfo(label: 'អាវកុមារទី ៧', shortLabel: 'សិស្ស ៧', assetPath: 'assets/suits/cutout_child_7.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_8': const SuitPresetInfo(label: 'អាវកុមារទី ៨', shortLabel: 'សិស្ស ៨', assetPath: 'assets/suits/cutout_child_8.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_9': const SuitPresetInfo(label: 'អាវកុមារទី ៩', shortLabel: 'សិស្ស ៩', assetPath: 'assets/suits/cutout_child_9.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_10': const SuitPresetInfo(label: 'អាវកុមារទី ១០', shortLabel: 'សិស្ស ១០', assetPath: 'assets/suits/cutout_child_10.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_11': const SuitPresetInfo(label: 'អាវកុមារទី ១១', shortLabel: 'សិស្ស ១១', assetPath: 'assets/suits/cutout_child_11.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_12': const SuitPresetInfo(label: 'អាវកុមារទី ១២', shortLabel: 'សិស្ស ១២', assetPath: 'assets/suits/cutout_child_12.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_13': const SuitPresetInfo(label: 'អាវកុមារទី ១៣', shortLabel: 'សិស្ស ១៣', assetPath: 'assets/suits/cutout_child_13.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_14': const SuitPresetInfo(label: 'អាវកុមារទី ១៤', shortLabel: 'សិស្ស ១៤', assetPath: 'assets/suits/cutout_child_14.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_15': const SuitPresetInfo(label: 'អាវកុមារទី ១៥', shortLabel: 'សិស្ស ១៥', assetPath: 'assets/suits/cutout_child_15.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
    'cutout_child_16': const SuitPresetInfo(label: 'អាវកុមារទី ១៦', shortLabel: 'សិស្ស ១៦', assetPath: 'assets/suits/cutout_child_16.png', icon: Icons.face_4_rounded, category: SuitCategory.student),
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
    const Color(0xFFE2E8F0), // Light Grey
    const Color(0xFF1E293B), // Dark Slate
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

  void _debouncedRenderComposite() {
    _debounceTimer?.cancel();
    _debounceTimer = Timer(const Duration(milliseconds: 60), () {
      _renderCompositeFromCutout();
    });
  }

  /// Accurate face detection & natural neckline auto-alignment
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

          // 1. Natural shoulder width calculation (~2.25x face width)
          final double faceWidth = box.width;
          final double targetShoulderW = faceWidth * 2.25;
          final double suitCanvasTargetW = decoded.width * 0.92;
          _suitScale = (targetShoulderW / suitCanvasTargetW).clamp(0.65, 1.85);

          // 2. Horizontal centering directly beneath chin
          final double imageCenterX = decoded.width / 2.0;
          _suitOffsetX = ((chinX - imageCenterX) / (decoded.width * 0.025)).clamp(-18.0, 18.0);

          // 3. Vertical neckline placement (Collar sits at natural base of neck: chin + ~18% face height)
          final double suitHeight = decoded.width * 0.92 * _suitScale;
          final double defaultSuitTopY = decoded.height - suitHeight + (decoded.height * 0.05);
          final double targetCollarTopY = chinY + (box.height * 0.18);
          _suitOffsetY = ((targetCollarTopY - defaultSuitTopY) / (decoded.height * 0.025)).clamp(-25.0, 25.0);

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
          _isFlipped = (source == ImageSource.camera);
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

  /// Composite transparent cutout foreground onto selected background & virtual suit
  Future<void> _renderCompositeFromCutout() async {
    if (_imagePath == null) return;
    if (_cutoutForegroundBytes == null) {
      await _processAiCloudRemoveBgCutout(showToast: false);
      return;
    }

    setState(() {
      _isProcessing = true;
      _statusText = 'កំពុងតម្រឹម និងរៀបចំរូបថត...';
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

  /// Multi-Engine Background Cutout: Remove.bg -> Cutout.pro -> On-Device ML Kit
  Future<void> _processAiCloudRemoveBgCutout({bool showToast = false}) async {
    if (_imagePath == null) return;

    setState(() {
      _isProcessing = true;
      _statusText = 'កំពុងកាត់ Background ដោយ AI Studio...';
    });

    try {
      final imageFile = File(_imagePath!);
      final imageBytes = await imageFile.readAsBytes();
      Uint8List? resultBytes;
      String engineUsed = 'Remove.bg';

      // 1. Remove.bg
      try {
        final rmbgService = RemoveBgService();
        resultBytes = await rmbgService.removeBackgroundBytes(imageBytes, size: 'preview');
      } catch (e) {
        debugPrint('Remove.bg error: $e');
      }

      // 2. Cutout.pro Fallback
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
          debugPrint('Cutout.pro fallback error: $e');
        }
      }

      // 3. On-Device ML Kit Fallback
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
          debugPrint('ML Kit fallback error: $e');
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

      // Create printable A4 page with passport photos
      pdf.addPage(
        pw.Page(
          pageFormat: PdfPageFormat.a4,
          build: (pw.Context ctx) {
            return pw.Center(
              child: pw.Wrap(
                spacing: 14,
                runSpacing: 14,
                children: List.generate(8, (index) {
                  return pw.Container(
                    width: _selectedPreset == PassportPreset.size4x6 ? 113.38 : 85.03,
                    height: _selectedPreset == PassportPreset.size4x6 ? 170.07 : 113.38,
                    decoration: pw.BoxDecoration(
                      border: pw.Border.all(color: const PdfColor(0.75, 0.75, 0.75), width: 0.5),
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

  /// AI Cutout.pro Photo Enhancer HD
  Future<void> _enhancePhotoWithCutoutPro() async {
    if (_processedImagePath == null && _imagePath == null) return;

    setState(() {
      _isProcessing = true;
      _statusText = 'កំពុងទាញរូបថតឱ្យច្បាស់ HD ដោយ AI...';
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
      backgroundColor: const Color(0xFF0A0F1D),
      appBar: VvcAppBar(
        backgroundColor: const Color(0xFF0F172A),
        elevation: 0,
        centerTitle: true,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 20),
          onPressed: () => Navigator.pop(context, _processedImagePath),
        ),
        title: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'រូបថត 4x6 / 3x4 Studio',
              style: GoogleFonts.kantumruyPro(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
            ),
            const SizedBox(width: 6),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                gradient: const LinearGradient(colors: [Color(0xFF0D9488), Color(0xFF14B8A6)]),
                borderRadius: BorderRadius.circular(6),
              ),
              child: const Text(
                'PRO',
                style: TextStyle(color: Colors.white, fontSize: 9, fontWeight: FontWeight.w900),
              ),
            ),
          ],
        ),
        actions: [
          if (_imagePath != null) ...[
            IconButton(
              icon: const Icon(Icons.auto_awesome_rounded, color: Color(0xFFA855F7), size: 22),
              tooltip: 'ទាញរូបថតឱ្យច្បាស់ HD (AI Enhancer)',
              onPressed: _enhancePhotoWithCutoutPro,
            ),
            IconButton(
              icon: Icon(
                Icons.flip_rounded,
                color: _isFlipped ? const Color(0xFF14B8A6) : Colors.white70,
                size: 22,
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
              icon: const Icon(Icons.print_rounded, color: Color(0xFF14B8A6), size: 22),
              tooltip: 'ព្រីនសន្លឹក 4x6 / 3x4',
              onPressed: _exportPrintSheet,
            ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            // Interactive Photo Studio Canvas (Main Center Stage)
            Expanded(
              child: Container(
                margin: const EdgeInsets.fromLTRB(14, 10, 14, 8),
                decoration: BoxDecoration(
                  color: const Color(0xFF060913),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: Colors.white.withValues(alpha: 0.08), width: 1.5),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: 0.5),
                      blurRadius: 16,
                      offset: const Offset(0, 4),
                    ),
                  ],
                ),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(19),
                  child: Stack(
                    alignment: Alignment.center,
                    children: [
                      if (displayPath != null)
                        GestureDetector(
                          onScaleStart: (details) {
                            _baseScale = _suitScale;
                          },
                          onScaleUpdate: (details) {
                            if (_selectedSuitKey == null) return;
                            setState(() {
                              // Direct on-screen touch dragging of suit
                              _suitOffsetX += (details.focalPointDelta.dx * 0.08);
                              _suitOffsetY += (details.focalPointDelta.dy * 0.08);

                              // Direct pinch-to-zoom scaling
                              if (details.scale != 1.0) {
                                _suitScale = (_baseScale * details.scale).clamp(0.55, 1.95);
                              }
                            });
                          },
                          onScaleEnd: (details) {
                            if (_selectedSuitKey != null) {
                              _debouncedRenderComposite();
                            }
                          },
                          child: Container(
                            color: Colors.transparent,
                            child: Center(
                              child: AspectRatio(
                                aspectRatio: _selectedPreset.ratio,
                                child: Image.file(
                                  File(displayPath),
                                  fit: BoxFit.cover,
                                ),
                              ),
                            ),
                          ),
                        )
                      else
                        Center(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Container(
                                width: 80,
                                height: 80,
                                decoration: BoxDecoration(
                                  color: Colors.white.withValues(alpha: 0.05),
                                  shape: BoxShape.circle,
                                ),
                                child: const Icon(Icons.portrait_rounded, size: 48, color: Colors.white24),
                              ),
                              const SizedBox(height: 14),
                              Text(
                                'ជ្រើសរើសរូបថតដើម្បីកាត់ Background & ពាក់អាវ',
                                style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 13),
                              ),
                              const SizedBox(height: 18),
                              Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  ElevatedButton.icon(
                                    onPressed: () => _pickImage(ImageSource.camera),
                                    icon: const Icon(Icons.camera_alt_rounded, size: 18),
                                    label: Text('ថតរូប', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
                                    style: ElevatedButton.styleFrom(
                                      backgroundColor: const Color(0xFF0D9488),
                                      foregroundColor: Colors.white,
                                      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                                    ),
                                  ),
                                  const SizedBox(width: 12),
                                  OutlinedButton.icon(
                                    onPressed: () => _pickImage(ImageSource.gallery),
                                    icon: const Icon(Icons.photo_library_rounded, size: 18),
                                    label: Text('វិចិត្រសាល', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
                                    style: OutlinedButton.styleFrom(
                                      foregroundColor: const Color(0xFF14B8A6),
                                      side: const BorderSide(color: Color(0xFF14B8A6)),
                                      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                                    ),
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ),

                      // Interactive Touch Drag Hint when suit is active
                      if (_selectedSuitKey != null && !_isProcessing)
                        Positioned(
                          top: 12,
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
                            decoration: BoxDecoration(
                              color: Colors.black.withValues(alpha: 0.65),
                              borderRadius: BorderRadius.circular(20),
                              border: Border.all(color: const Color(0xFF14B8A6).withValues(alpha: 0.4)),
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const Icon(Icons.touch_app_rounded, color: Color(0xFF14B8A6), size: 14),
                                const SizedBox(width: 5),
                                Text(
                                  'ប៉ះអូសលើរូប ឬពង្រីកដើម្បីតម្រឹមអាវ',
                                  style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 11),
                                ),
                              ],
                            ),
                          ),
                        ),

                      // Processing Spinner Overlay
                      if (_isProcessing)
                        Container(
                          color: Colors.black87,
                          child: Center(
                            child: Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const SizedBox(
                                  width: 44,
                                  height: 44,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 3,
                                    valueColor: AlwaysStoppedAnimation<Color>(Color(0xFF14B8A6)),
                                  ),
                                ),
                                const SizedBox(height: 16),
                                Text(
                                  _statusText ?? 'កំពុងដំណើរការ...',
                                  style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w500),
                                ),
                              ],
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
              ),
            ),

            // Studio Control Deck (Bottom Section)
            if (_imagePath != null)
              Container(
                decoration: const BoxDecoration(
                  color: Color(0xFF0F172A),
                  borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
                  boxShadow: [
                    BoxShadow(color: Colors.black54, blurRadius: 20, offset: Offset(0, -4)),
                  ],
                ),
                padding: EdgeInsets.only(
                  left: 14,
                  right: 14,
                  top: 12,
                  bottom: MediaQuery.of(context).padding.bottom + 10,
                ),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Deck Mode Navigation Tabs (Virtual Suit | Background | Size)
                    Container(
                      padding: const EdgeInsets.all(4),
                      decoration: BoxDecoration(
                        color: const Color(0xFF1E293B),
                        borderRadius: BorderRadius.circular(14),
                        border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
                      ),
                      child: Row(
                        children: [
                          _buildDeckTabItem(
                            index: 0,
                            icon: Icons.checkroom_rounded,
                            label: 'ម៉ូដអាវ (Suit)',
                            hasBadge: _selectedSuitKey != null,
                          ),
                          _buildDeckTabItem(
                            index: 1,
                            icon: Icons.palette_rounded,
                            label: 'ផ្ទៃខាងក្រោយ',
                          ),
                          _buildDeckTabItem(
                            index: 2,
                            icon: Icons.aspect_ratio_rounded,
                            label: 'ទំហំរូបថត',
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 10),

                    // Active Deck Content
                    if (_activeDeckTab == 0) _buildVirtualSuitDeckContent(),
                    if (_activeDeckTab == 1) _buildBackgroundDeckContent(),
                    if (_activeDeckTab == 2) _buildSizePresetDeckContent(),

                    const SizedBox(height: 10),

                    // Master Action Button
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _exportPrintSheet,
                        icon: const Icon(Icons.print_rounded, size: 19),
                        label: Text(
                          'ទាញយកសន្លឹកព្រីនរូបថត (Print Sheet 8x)',
                          style: GoogleFonts.kantumruyPro(fontSize: 13.5, fontWeight: FontWeight.bold),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF0D9488),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 12),
                          elevation: 2,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
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

  // Segmented Mode Switcher Item
  Widget _buildDeckTabItem({
    required int index,
    required IconData icon,
    required String label,
    bool hasBadge = false,
  }) {
    final isSelected = _activeDeckTab == index;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _activeDeckTab = index),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 200),
          padding: const EdgeInsets.symmetric(vertical: 8),
          decoration: BoxDecoration(
            color: isSelected ? const Color(0xFF0D9488) : Colors.transparent,
            borderRadius: BorderRadius.circular(10),
            boxShadow: isSelected
                ? [BoxShadow(color: const Color(0xFF0D9488).withValues(alpha: 0.35), blurRadius: 8, offset: const Offset(0, 2))]
                : null,
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, size: 16, color: isSelected ? Colors.white : Colors.white60),
              const SizedBox(width: 5),
              Text(
                label,
                style: GoogleFonts.kantumruyPro(
                  color: isSelected ? Colors.white : Colors.white70,
                  fontSize: 11.5,
                  fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                ),
              ),
              if (hasBadge) ...[
                const SizedBox(width: 4),
                Container(
                  width: 6,
                  height: 6,
                  decoration: const BoxDecoration(
                    color: Color(0xFF38BDF8),
                    shape: BoxShape.circle,
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  /// -------------------------------------------------------------
  /// TAB 0: VIRTUAL SUIT STUDIO DECK (VISUAL PREVIEWS + FINE TUNING)
  /// -------------------------------------------------------------
  Widget _buildVirtualSuitDeckContent() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Category Pills & Remove Suit Action
        Row(
          children: [
            Expanded(
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                physics: const BouncingScrollPhysics(),
                child: Row(
                  children: [
                    _buildCategoryFilterChip(SuitCategory.all, 'ទាំងអស់ (${_suitPresets.length})'),
                    _buildCategoryFilterChip(SuitCategory.male, '👔 បុរស (${_suitPresets.values.where((s) => s.category == SuitCategory.male).length})'),
                    _buildCategoryFilterChip(SuitCategory.female, '👗 នារី (${_suitPresets.values.where((s) => s.category == SuitCategory.female).length})'),
                    _buildCategoryFilterChip(SuitCategory.student, '🎓 សិស្ស (${_suitPresets.values.where((s) => s.category == SuitCategory.student).length})'),
                  ],
                ),
              ),
            ),
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
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: Colors.redAccent.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.redAccent.withValues(alpha: 0.3)),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.close_rounded, size: 12, color: Colors.redAccent),
                      const SizedBox(width: 3),
                      Text(
                        'ដោះអាវចេញ',
                        style: GoogleFonts.kantumruyPro(color: Colors.redAccent, fontSize: 10.5, fontWeight: FontWeight.bold),
                      ),
                    ],
                  ),
                ),
              ),
          ],
        ),
        const SizedBox(height: 8),

        // Visual Suit Gallery (Horizontal Cards with Real PNG Previews)
        SizedBox(
          height: 96,
          child: ListView(
            scrollDirection: Axis.horizontal,
            physics: const BouncingScrollPhysics(),
            children: [
              // No Suit Card
              _buildNoSuitCard(),
              // Filtered Suit Cards
              ..._getFilteredSuitEntries().map((entry) => _buildVisualSuitCard(entry.key, entry.value)),
            ],
          ),
        ),

        // Fine-Tuning Control Pod (Visible when suit is chosen)
        if (_selectedSuitKey != null) ...[
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: const Color(0xFF1E293B),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
            ),
            child: Row(
              children: [
                // Auto-Fit AI Button
                InkWell(
                  onTap: () async {
                    _hasAutoFittedSuit = false;
                    await _detectFaceAndAutoFitSuit();
                    _renderCompositeFromCutout();
                  },
                  borderRadius: BorderRadius.circular(8),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(colors: [Color(0xFF6366F1), Color(0xFF8B5CF6)]),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.auto_awesome, color: Colors.white, size: 13),
                        const SizedBox(width: 4),
                        Text(
                          'តម្រឹម AI',
                          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(width: 8),

                // Scale Slider & Steppers
                IconButton(
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                  icon: const Icon(Icons.remove_circle_outline_rounded, color: Color(0xFF14B8A6), size: 18),
                  onPressed: () {
                    setState(() => _suitScale = (_suitScale - 0.05).clamp(0.55, 1.95));
                    _debouncedRenderComposite();
                  },
                  tooltip: 'បង្រួមអាវ',
                ),
                Expanded(
                  child: SliderTheme(
                    data: SliderTheme.of(context).copyWith(
                      trackHeight: 3,
                      thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 6),
                      overlayShape: const RoundSliderOverlayShape(overlayRadius: 12),
                      activeTrackColor: const Color(0xFF14B8A6),
                      inactiveTrackColor: Colors.white12,
                      thumbColor: Colors.white,
                    ),
                    child: Slider(
                      value: _suitScale.clamp(0.55, 1.95),
                      min: 0.55,
                      max: 1.95,
                      onChanged: (val) {
                        setState(() => _suitScale = val);
                        _debouncedRenderComposite();
                      },
                    ),
                  ),
                ),
                IconButton(
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                  icon: const Icon(Icons.add_circle_outline_rounded, color: Color(0xFF14B8A6), size: 18),
                  onPressed: () {
                    setState(() => _suitScale = (_suitScale + 0.05).clamp(0.55, 1.95));
                    _debouncedRenderComposite();
                  },
                  tooltip: 'ពង្រីកអាវ',
                ),

                const SizedBox(width: 4),
                Text(
                  '${(_suitScale * 100).round()}%',
                  style: GoogleFonts.inter(color: Colors.white70, fontSize: 11, fontWeight: FontWeight.bold),
                ),

                const SizedBox(width: 6),
                // Precision Micro-Adjust D-Pad Trigger
                _buildMicroAdjustButtons(),
              ],
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildCategoryFilterChip(SuitCategory cat, String label) {
    final isSelected = _selectedSuitCategory == cat;
    return GestureDetector(
      onTap: () => setState(() => _selectedSuitCategory = cat),
      child: Container(
        margin: const EdgeInsets.only(right: 6),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(
          color: isSelected ? const Color(0xFF0D9488) : const Color(0xFF1E293B),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: isSelected ? const Color(0xFF14B8A6) : Colors.white.withValues(alpha: 0.08),
          ),
        ),
        child: Text(
          label,
          style: GoogleFonts.kantumruyPro(
            color: isSelected ? Colors.white : Colors.white70,
            fontSize: 11,
            fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
          ),
        ),
      ),
    );
  }

  Widget _buildNoSuitCard() {
    final isSelected = _selectedSuitKey == null;
    return GestureDetector(
      onTap: () {
        setState(() {
          _selectedSuitKey = null;
        });
        _renderCompositeFromCutout();
      },
      child: Container(
        width: 72,
        margin: const EdgeInsets.only(right: 8),
        decoration: BoxDecoration(
          color: isSelected ? const Color(0xFF0D9488).withValues(alpha: 0.25) : const Color(0xFF1E293B),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: isSelected ? const Color(0xFF14B8A6) : Colors.white.withValues(alpha: 0.08),
            width: isSelected ? 2 : 1,
          ),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.block_rounded, color: isSelected ? const Color(0xFF14B8A6) : Colors.white38, size: 28),
            const SizedBox(height: 6),
            Text(
              'គ្មានអាវ',
              style: GoogleFonts.kantumruyPro(
                color: isSelected ? Colors.white : Colors.white60,
                fontSize: 11,
                fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildVisualSuitCard(String key, SuitPresetInfo info) {
    final isSelected = _selectedSuitKey == key;
    return GestureDetector(
      onTap: () {
        setState(() {
          _selectedSuitKey = key;
        });
        _renderCompositeFromCutout();
      },
      child: Container(
        width: 76,
        margin: const EdgeInsets.only(right: 8),
        decoration: BoxDecoration(
          color: isSelected ? const Color(0xFF0D9488).withValues(alpha: 0.25) : const Color(0xFF1E293B),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: isSelected ? const Color(0xFF14B8A6) : Colors.white.withValues(alpha: 0.08),
            width: isSelected ? 2 : 1,
          ),
          boxShadow: isSelected
              ? [BoxShadow(color: const Color(0xFF14B8A6).withValues(alpha: 0.3), blurRadius: 8)]
              : null,
        ),
        child: Stack(
          children: [
            Column(
              children: [
                Expanded(
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(6, 6, 6, 2),
                    child: Image.asset(
                      info.assetPath,
                      fit: BoxFit.contain,
                      errorBuilder: (_, __, ___) => Icon(info.icon, color: Colors.white38, size: 28),
                    ),
                  ),
                ),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(vertical: 3),
                  decoration: BoxDecoration(
                    color: isSelected ? const Color(0xFF0D9488) : Colors.black26,
                    borderRadius: const BorderRadius.vertical(bottom: Radius.circular(12)),
                  ),
                  child: Text(
                    info.shortLabel,
                    textAlign: TextAlign.center,
                    style: GoogleFonts.kantumruyPro(
                      color: isSelected ? Colors.white : Colors.white70,
                      fontSize: 10,
                      fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                    ),
                  ),
                ),
              ],
            ),
            if (isSelected)
              Positioned(
                top: 4,
                right: 4,
                child: Container(
                  padding: const EdgeInsets.all(2),
                  decoration: const BoxDecoration(
                    color: Color(0xFF14B8A6),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(Icons.check, size: 10, color: Colors.white),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildMicroAdjustButtons() {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        IconButton(
          padding: EdgeInsets.zero,
          constraints: const BoxConstraints(minWidth: 26, minHeight: 26),
          icon: const Icon(Icons.arrow_back_rounded, color: Colors.white70, size: 15),
          onPressed: () {
            setState(() => _suitOffsetX -= 1.0);
            _debouncedRenderComposite();
          },
          tooltip: 'រំកិលឆ្វេង',
        ),
        IconButton(
          padding: EdgeInsets.zero,
          constraints: const BoxConstraints(minWidth: 26, minHeight: 26),
          icon: const Icon(Icons.arrow_forward_rounded, color: Colors.white70, size: 15),
          onPressed: () {
            setState(() => _suitOffsetX += 1.0);
            _debouncedRenderComposite();
          },
          tooltip: 'រំកិលស្តាំ',
        ),
        IconButton(
          padding: EdgeInsets.zero,
          constraints: const BoxConstraints(minWidth: 26, minHeight: 26),
          icon: const Icon(Icons.arrow_upward_rounded, color: Colors.white70, size: 15),
          onPressed: () {
            setState(() => _suitOffsetY -= 1.0);
            _debouncedRenderComposite();
          },
          tooltip: 'លើកឡើងលើ',
        ),
        IconButton(
          padding: EdgeInsets.zero,
          constraints: const BoxConstraints(minWidth: 26, minHeight: 26),
          icon: const Icon(Icons.arrow_downward_rounded, color: Colors.white70, size: 15),
          onPressed: () {
            setState(() => _suitOffsetY += 1.0);
            _debouncedRenderComposite();
          },
          tooltip: 'ទម្លាក់ចុះក្រោម',
        ),
      ],
    );
  }

  /// -------------------------------------------------------------
  /// TAB 1: BACKGROUND COLOR & AI CUTOUT DECK
  /// -------------------------------------------------------------
  Widget _buildBackgroundDeckContent() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // AI Cloud Cutout Banner Button
        Material(
          color: Colors.transparent,
          child: InkWell(
            onTap: () => _processAiCloudRemoveBgCutout(showToast: true),
            borderRadius: BorderRadius.circular(12),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                gradient: const LinearGradient(colors: [Color(0xFF4F46E5), Color(0xFF7C3AED)]),
                borderRadius: BorderRadius.circular(12),
                boxShadow: [
                  BoxShadow(color: const Color(0xFF6366F1).withValues(alpha: 0.35), blurRadius: 8),
                ],
              ),
              child: Row(
                children: [
                  const Icon(Icons.auto_awesome, color: Colors.white, size: 18),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '✨ កាត់ Background ដោយ AI (Remove.bg / Cutout.pro)',
                          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 11.5, fontWeight: FontWeight.bold),
                        ),
                        Text(
                          'កាត់រូបស្អាត គ្មានស្នាមកកិត គុណភាពខ្ពស់',
                          style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 10),
                        ),
                      ],
                    ),
                  ),
                  const Icon(Icons.arrow_forward_ios_rounded, color: Colors.white70, size: 12),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: 10),

        // Color Palettes Selection
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: _presetColors.map((color) {
            final isSelected = _selectedBgColor == color;
            return GestureDetector(
              onTap: () {
                setState(() => _selectedBgColor = color);
                _renderCompositeFromCutout();
              },
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 150),
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  color: color,
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: isSelected ? const Color(0xFF14B8A6) : Colors.white24,
                    width: isSelected ? 3 : 1,
                  ),
                  boxShadow: isSelected
                      ? [BoxShadow(color: const Color(0xFF14B8A6).withValues(alpha: 0.5), blurRadius: 10)]
                      : null,
                ),
                child: isSelected
                    ? Icon(
                        Icons.check_rounded,
                        size: 22,
                        color: color == Colors.white ? Colors.black87 : Colors.white,
                      )
                    : null,
              ),
            );
          }).toList(),
        ),
      ],
    );
  }

  /// -------------------------------------------------------------
  /// TAB 2: PASSPORT SIZE RATIO SELECTION DECK
  /// -------------------------------------------------------------
  Widget _buildSizePresetDeckContent() {
    return Row(
      children: PassportPreset.values.map((preset) {
        final isSelected = _selectedPreset == preset;
        return Expanded(
          child: GestureDetector(
            onTap: () {
              setState(() => _selectedPreset = preset);
              _renderCompositeFromCutout();
            },
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 150),
              margin: const EdgeInsets.symmetric(horizontal: 3),
              padding: const EdgeInsets.symmetric(vertical: 10),
              decoration: BoxDecoration(
                color: isSelected ? const Color(0xFF0D9488) : const Color(0xFF1E293B),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: isSelected ? const Color(0xFF14B8A6) : Colors.white.withValues(alpha: 0.08),
                  width: isSelected ? 1.5 : 1,
                ),
                boxShadow: isSelected
                    ? [BoxShadow(color: const Color(0xFF0D9488).withValues(alpha: 0.35), blurRadius: 8)]
                    : null,
              ),
              child: Column(
                children: [
                  Text(
                    preset.label,
                    textAlign: TextAlign.center,
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 12,
                      fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    preset.description,
                    textAlign: TextAlign.center,
                    style: GoogleFonts.kantumruyPro(
                      color: isSelected ? Colors.white.withValues(alpha: 0.85) : Colors.white38,
                      fontSize: 9.5,
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      }).toList(),
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

  String get description {
    switch (this) {
      case PassportPreset.size4x6:
        return 'លិខិតឆ្លងដែន';
      case PassportPreset.size3x4:
        return 'កាតបុគ្គលិក';
      case PassportPreset.size2x3:
        return 'ទំហំតូច';
      case PassportPreset.size5x5:
        return 'ទិដ្ឋាការ 2x2';
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
