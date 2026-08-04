import 'dart:io';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:google_mlkit_subject_segmentation/google_mlkit_subject_segmentation.dart';
import 'package:image/image.dart' as img;
import 'package:path_provider/path_provider.dart';

/// Service for Subject Segmentation and Background Replacement (Passport Photo Studio)
class SubjectSegmentationService {
  late final SubjectSegmenter _segmenter;

  SubjectSegmentationService() {
    _segmenter = SubjectSegmenter(
      options: SubjectSegmenterOptions(
        enableForegroundBitmap: true,
        enableForegroundConfidenceMask: true,
        enableMultipleSubjects: SubjectResultOptions(
          enableConfidenceMask: true,
          enableSubjectBitmap: true,
        ),
      ),
    );
  }

  /// Process input image and return SubjectSegmentationResult containing mask / foreground
  Future<SubjectSegmentationResult?> segmentSubject(String imagePath) async {
    try {
      final inputImage = InputImage.fromFilePath(imagePath);
      final result = await _segmenter.processImage(inputImage);
      return result;
    } catch (e) {
      debugPrint('Subject Segmentation error: $e');
      return null;
    }
  }

  /// Composite foreground subject onto a solid color or custom background image
  Future<File> createPassportBackground({
    required String imagePath,
    required Color backgroundColor,
    String? customBgImagePath,
    List<double>? confidenceMask,
    int? maskW,
    int? maskH,
    bool flipHorizontal = false,
  }) async {
    final bytes = await File(imagePath).readAsBytes();
    img.Image? original = img.decodeImage(bytes);
    if (original == null) return File(imagePath);

    if (flipHorizontal) {
      original = img.flipHorizontal(original);
    }

    final int imgW = original.width;
    final int imgH = original.height;

    // Create background canvas
    img.Image bgCanvas;
    if (customBgImagePath != null && File(customBgImagePath).existsSync()) {
      final bgBytes = await File(customBgImagePath).readAsBytes();
      img.Image? decodedBg = img.decodeImage(bgBytes);
      if (decodedBg != null) {
        bgCanvas = img.copyResize(decodedBg, width: imgW, height: imgH);
      } else {
        bgCanvas = img.Image(width: imgW, height: imgH);
        _fillColor(bgCanvas, backgroundColor);
      }
    } else {
      bgCanvas = img.Image(width: imgW, height: imgH);
      _fillColor(bgCanvas, backgroundColor);
    }

    if (confidenceMask != null && confidenceMask.isNotEmpty) {
      int effectiveMaskW = maskW ?? 0;
      int effectiveMaskH = maskH ?? 0;

      // Auto-detect mask dimensions if passed dimensions do not match mask array length
      if (effectiveMaskW <= 0 || effectiveMaskH <= 0 || (effectiveMaskW * effectiveMaskH != confidenceMask.length)) {
        double aspect = imgW / imgH;
        effectiveMaskH = (sqrt(confidenceMask.length / aspect)).round();
        if (effectiveMaskH <= 0) effectiveMaskH = 1;
        effectiveMaskW = (confidenceMask.length / effectiveMaskH).floor();
        if (effectiveMaskW <= 0) effectiveMaskW = 1;
      }

      for (int y = 0; y < imgH; y++) {
        for (int x = 0; x < imgW; x++) {
          final int maskX = ((x / imgW) * effectiveMaskW).floor().clamp(0, effectiveMaskW - 1);
          final int maskY = ((y / imgH) * effectiveMaskH).floor().clamp(0, effectiveMaskH - 1);
          final floatIndex = maskY * effectiveMaskW + maskX;

          double rawAlpha = 0.0;
          if (floatIndex < confidenceMask.length) {
            rawAlpha = confidenceMask[floatIndex].toDouble().clamp(0.0, 1.0);
          }

          // Smooth alpha threshold with feathering for soft clean edges around hair and shoulders
          double alpha = 0.0;
          if (rawAlpha > 0.06) {
            alpha = ((rawAlpha - 0.06) / 0.65).clamp(0.0, 1.0);
          }

          if (alpha > 0.0) {
            final fgPixel = original.getPixel(x, y);
            final bgPixel = bgCanvas.getPixel(x, y);

            final r = (fgPixel.r * alpha + bgPixel.r * (1.0 - alpha)).round().clamp(0, 255);
            final g = (fgPixel.g * alpha + bgPixel.g * (1.0 - alpha)).round().clamp(0, 255);
            final b = (fgPixel.b * alpha + bgPixel.b * (1.0 - alpha)).round().clamp(0, 255);

            bgCanvas.setPixelRgb(x, y, r, g, b);
          }
        }
      }
    } else {
      // Enhanced multi-point background color sample keying fallback
      final pTL = original.getPixel(0, 0);
      final pTR = original.getPixel(imgW - 1, 0);
      final pTC = original.getPixel((imgW / 2).floor(), 0);

      for (int y = 0; y < imgH; y++) {
        for (int x = 0; x < imgW; x++) {
          final px = original.getPixel(x, y);
          final dTL = (px.r - pTL.r).abs() + (px.g - pTL.g).abs() + (px.b - pTL.b).abs();
          final dTR = (px.r - pTR.r).abs() + (px.g - pTR.g).abs() + (px.b - pTR.b).abs();
          final dTC = (px.r - pTC.r).abs() + (px.g - pTC.g).abs() + (px.b - pTC.b).abs();
          final minDiff = [dTL, dTR, dTC].reduce((a, b) => a < b ? a : b);

          if (minDiff > 35) {
            bgCanvas.setPixelRgb(x, y, px.r, px.g, px.b);
          }
        }
      }
    }

    final tempDir = await getTemporaryDirectory();
    final outPath = '${tempDir.path}/passport_${DateTime.now().millisecondsSinceEpoch}.jpg';
    final jpgData = img.encodeJpg(bgCanvas, quality: 95);
    final outFile = File(outPath);
    await outFile.writeAsBytes(jpgData);
    return outFile;
  }

  void _fillColor(img.Image image, Color color) {
    final r = (color.r * 255).round().clamp(0, 255);
    final g = (color.g * 255).round().clamp(0, 255);
    final b = (color.b * 255).round().clamp(0, 255);
    for (int y = 0; y < image.height; y++) {
      for (int x = 0; x < image.width; x++) {
        image.setPixelRgb(x, y, r, g, b);
      }
    }
  }

  void dispose() {
    try {
      _segmenter.close();
    } catch (_) {}
  }
}
