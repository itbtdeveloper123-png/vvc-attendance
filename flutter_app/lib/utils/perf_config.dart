import 'dart:io' show Platform;

import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter/foundation.dart' show kIsWeb, debugPrint;
import 'package:flutter/painting.dart' show PaintingBinding;

/// ═══════════════════════════════════════════════════════════════════════════
/// PerfConfig — រកមើលកម្លាំងទូរស័ព្ទ ហើយកែតម្រូវ Effect ឱ្យសមស្រប
/// ═══════════════════════════════════════════════════════════════════════════
///
/// ទូរស័ព្ទខ្សោយ (Low-end) = Android API < 29 (Android 9 ចុះក្រោម)
/// ឬ RAM < 3.5GB ឬ Android សម្គាល់ថា Low-RAM device។
///
/// នៅលើទូរស័ព្ទខ្សោយ៖
/// - បិទ BackdropFilter (Blur) → ប្រើពណ៌ Solid ជំនួស (GPU ស្រាលខ្លាំង)
/// - កាត់បន្ថយ Image cache ដើម្បីការពារ Out-Of-Memory crash
/// - កាត់បន្ថយ Animation ដែលដើររហូត (ambient orbs)
class PerfConfig {
  PerfConfig._();

  static bool _isLowEnd = false;
  static bool _initialized = false;

  /// `true` ពេលទូរស័ព្ទខ្សោយ
  static bool get isLowEnd => _isLowEnd;
  static bool get isLowEndDevice => _isLowEnd;

  /// អនុញ្ញាត Blur (Glass effect) ឬទេ
  static bool get enableBlur => !_isLowEnd;
  static bool shouldEnableBlur([dynamic context]) => enableBlur;

  /// អនុញ្ញាត Animation តុបតែងដែលដើររហូត (orbs, shimmer loops)
  static bool get enableAmbientAnimations => !_isLowEnd;

  /// កម្រិត Blur ដែលត្រូវប្រើ (0 = បិទ)
  static double blur(double sigma) => enableBlur ? sigma : 0.0;

  /// ហៅម្តងក្នុង `main()` មុន `runApp` (ចំណាយពេលប្រហែល 10–30ms)
  static Future<void> init() async {
    if (_initialized) return;
    _initialized = true;

    if (kIsWeb || !Platform.isAndroid) {
      _applyImageCacheLimits();
      return;
    }

    try {
      final info = await DeviceInfoPlugin().androidInfo;
      final sdk = info.version.sdkInt;
      final ramMb = info.physicalRamSize;
      _isLowEnd = sdk < 29 ||
          info.isLowRamDevice ||
          (ramMb > 0 && ramMb < 3500);
      debugPrint(
        '⚙️ PerfConfig: sdk=$sdk ram=${ramMb}MB lowRam=${info.isLowRamDevice} → lowEnd=$_isLowEnd',
      );
    } catch (e) {
      debugPrint('⚙️ PerfConfig detection failed: $e');
    }

    _applyImageCacheLimits();
  }

  static void _applyImageCacheLimits() {
    final cache = PaintingBinding.instance.imageCache;
    if (_isLowEnd) {
      cache.maximumSize = 60; // ចំនួនរូប
      cache.maximumSizeBytes = 40 << 20; // 40MB
    } else {
      cache.maximumSize = 200;
      cache.maximumSizeBytes = 100 << 20; // 100MB
    }
  }
}
