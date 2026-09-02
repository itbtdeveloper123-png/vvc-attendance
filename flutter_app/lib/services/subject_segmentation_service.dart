import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:google_mlkit_subject_segmentation/google_mlkit_subject_segmentation.dart';
import 'package:image/image.dart' as img;
import 'package:path_provider/path_provider.dart';

/// Service for Subject Segmentation and Background Replacement (Passport Photo Studio)
class SubjectSegmentationService {
  late final SubjectSegmenter _segmenter;

  // In-memory performance caches
  String? _cachedImagePath;
  bool? _cachedFlipHorizontal;
  img.Image? _cachedOriginal;
  img.Image? _cachedFgImg;
  final Map<String, img.Image> _cachedSuits = {};

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

  void clearCache() {
    _cachedImagePath = null;
    _cachedFlipHorizontal = null;
    _cachedOriginal = null;
    _cachedFgImg = null;
    _cachedSuits.clear();
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
    Uint8List? foregroundBytes,
    List<double>? confidenceMask,
    int? maskW,
    int? maskH,
    bool flipHorizontal = false,
    String? suitKey,
    Uint8List? suitBytes,
    double suitScale = 1.0,
    double suitOffsetY = 0.0,
    double suitOffsetX = 0.0,
  }) async {
    // 1. Check or load pre-decoded downsampled original image
    if (_cachedImagePath != imagePath || _cachedFlipHorizontal != flipHorizontal || _cachedOriginal == null) {
      final bytes = await File(imagePath).readAsBytes();
      img.Image? original = img.decodeImage(bytes);
      if (original == null) return File(imagePath);

      if (flipHorizontal) {
        original = img.flipHorizontal(original);
      }

      // Downsample to max 1080px for lightning-fast studio preview & editing
      if (original.width > 1080) {
        original = img.copyResize(original, width: 1080);
      }

      _cachedImagePath = imagePath;
      _cachedFlipHorizontal = flipHorizontal;
      _cachedOriginal = original;
      _cachedFgImg = null;
    }

    final img.Image original = _cachedOriginal!;
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

    bool fgRendered = false;

    // 2. Direct ML Kit Foreground Bitmap Compositing (cached)
    if (foregroundBytes != null && foregroundBytes.isNotEmpty) {
      try {
        if (_cachedFgImg == null) {
          img.Image? fgImg = img.decodeImage(foregroundBytes);
          if (fgImg != null) {
            if (flipHorizontal) {
              fgImg = img.flipHorizontal(fgImg);
            }
            if (fgImg.width != imgW || fgImg.height != imgH) {
              fgImg = img.copyResize(fgImg, width: imgW, height: imgH);
            }
            _cachedFgImg = fgImg;
          }
        }

        if (_cachedFgImg != null) {
          final fgImg = _cachedFgImg!;
          for (int y = 0; y < imgH; y++) {
            for (int x = 0; x < imgW; x++) {
              final px = fgImg.getPixel(x, y);
              final alpha = (px.a / 255.0);
              if (alpha > 0.05) {
                final bgPx = bgCanvas.getPixel(x, y);
                final r = (px.r * alpha + bgPx.r * (1.0 - alpha)).round().clamp(0, 255);
                final g = (px.g * alpha + bgPx.g * (1.0 - alpha)).round().clamp(0, 255);
                final b = (px.b * alpha + bgPx.b * (1.0 - alpha)).round().clamp(0, 255);
                bgCanvas.setPixelRgb(x, y, r, g, b);
              }
            }
          }
          fgRendered = true;
        }
      } catch (e) {
        debugPrint('Foreground bitmap rendering error: $e');
      }
    }

    // 3. Confidence Mask Compositing if bitmap not rendered
    if (!fgRendered && confidenceMask != null && confidenceMask.isNotEmpty) {
      int effectiveMaskW = maskW ?? 0;
      int effectiveMaskH = maskH ?? 0;

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
      fgRendered = true;
    }

    // 4. Smart Edge-Sample Background Keying Fallback
    if (!fgRendered) {
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

          if (minDiff > 45) {
            bgCanvas.setPixelRgb(x, y, px.r, px.g, px.b);
          }
        }
      }
    }

    // 5. Composite Virtual Suit Overlay onto shoulders (cached suit)
    if (suitBytes != null && suitBytes.isNotEmpty) {
      final String sKey = suitKey ?? suitBytes.length.toString();
      if (!_cachedSuits.containsKey(sKey)) {
        img.Image? decodedSuit = img.decodeImage(suitBytes);
        if (decodedSuit != null) {
          _cachedSuits[sKey] = decodedSuit;
        }
      }

      final suitImg = _cachedSuits[sKey];
      if (suitImg != null) {
        _compositeSuit(
          bgCanvas,
          suitImg,
          suitScale: suitScale,
          suitOffsetX: suitOffsetX,
          suitOffsetY: suitOffsetY,
          backgroundColor: backgroundColor,
        );
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

  void _compositeSuit(
    img.Image bgCanvas,
    img.Image suitImg, {
    required double suitScale,
    required double suitOffsetX,
    required double suitOffsetY,
    Color? backgroundColor,
  }) {
    final int imgW = bgCanvas.width;
    final int imgH = bgCanvas.height;

    final double targetW = (imgW * 0.95 * suitScale).clamp(40.0, imgW * 3.0);
    final double scaleFactor = targetW / suitImg.width;
    final int targetH = (suitImg.height * scaleFactor).round();
    final int tw = targetW.round();

    final resizedSuit = img.copyResize(suitImg, width: tw, height: targetH);

    // Normalized calculation matching Flutter Stack Positioned coordinates
    final int posX = (((imgW - tw) / 2.0) + (imgW * (suitOffsetX / 100.0))).round();
    final int posY = ((imgH - targetH) - (imgH * (suitOffsetY / 100.0))).round();

    final Color bgColor = backgroundColor ?? Colors.white;
    final int bgR = (bgColor.r * 255).round().clamp(0, 255);
    final int bgG = (bgColor.g * 255).round().clamp(0, 255);
    final int bgB = (bgColor.b * 255).round().clamp(0, 255);

    // 1. Clean erase old clothes sticking out beyond suit shoulders (only below shoulder line)
    final int shoulderStartY = posY + (targetH * 0.22).round();
    for (int y = shoulderStartY; y < imgH; y++) {
      for (int x = 0; x < imgW; x++) {
        if (x < posX || x >= posX + tw) {
          bgCanvas.setPixelRgb(x, y, bgR, bgG, bgB);
        }
      }
    }

    // 2. Composite suit overlay cleanly onto the canvas
    for (int sy = 0; sy < resizedSuit.height; sy++) {
      final int canvasY = posY + sy;
      if (canvasY < 0 || canvasY >= imgH) continue;

      for (int sx = 0; sx < resizedSuit.width; sx++) {
        final int canvasX = posX + sx;
        if (canvasX < 0 || canvasX >= imgW) continue;

        final px = resizedSuit.getPixel(sx, sy);
        final alpha = (px.a / 255.0);

        if (alpha > 0.05) {
          final bgPx = bgCanvas.getPixel(canvasX, canvasY);
          final r = (px.r * alpha + bgPx.r * (1.0 - alpha)).round().clamp(0, 255);
          final g = (px.g * alpha + bgPx.g * (1.0 - alpha)).round().clamp(0, 255);
          final b = (px.b * alpha + bgPx.b * (1.0 - alpha)).round().clamp(0, 255);
          bgCanvas.setPixelRgb(canvasX, canvasY, r, g, b);
        }
      }
    }
  }

  void dispose() {
    try {
      _segmenter.close();
    } catch (_) {}
  }
}
