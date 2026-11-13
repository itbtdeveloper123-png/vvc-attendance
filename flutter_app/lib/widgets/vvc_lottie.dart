import 'package:flutter/material.dart';
import 'package:lottie/lottie.dart';

/// ═══════════════════════════════════════════════════════════════════════════════
/// VVC LOTTIE VECTOR ANIMATION HELPER
/// ═══════════════════════════════════════════════════════════════════════════════
/// គ្រប់គ្រងចលនា Lottie Vector Animations ក្នុងកម្មវិធី VVC Attendance
/// ជាមួយ Fallback Gracefully ប្រសិនបើមានបញ្ហា។
class VvcLottie extends StatelessWidget {
  final String assetPath;
  final double? width;
  final double? height;
  final bool repeat;
  final bool animate;
  final BoxFit fit;
  final Widget? fallback;

  const VvcLottie({
    super.key,
    required this.assetPath,
    this.width,
    this.height,
    this.repeat = true,
    this.animate = true,
    this.fit = BoxFit.contain,
    this.fallback,
  });

  /// ចលនាជោគជ័យ (Checkmark Animation ពេល Check-in, ស្កេនជោគជ័យ, ឬ Copy Code)
  factory VvcLottie.success({
    double size = 90.0,
    bool repeat = false,
    Widget? fallback,
  }) {
    return VvcLottie(
      assetPath: 'assets/lottie/success.json',
      width: size,
      height: size,
      repeat: repeat,
      fallback: fallback ??
          Icon(Icons.check_circle_rounded, size: size * 0.7, color: const Color(0xFF10B981)),
    );
  }

  /// ចលនាស្កេន QR (Active Laser Viewfinder)
  factory VvcLottie.scanning({
    double size = 120.0,
    bool repeat = true,
    Widget? fallback,
  }) {
    return VvcLottie(
      assetPath: 'assets/lottie/scanning.json',
      width: size,
      height: size,
      repeat: repeat,
      fallback: fallback ??
          Icon(Icons.qr_code_scanner_rounded, size: size * 0.7, color: const Color(0xFF38BDF8)),
    );
  }

  /// ចលនាទទេស្អាត (Empty State Floating Box / Document)
  factory VvcLottie.empty({
    double size = 110.0,
    bool repeat = true,
    Widget? fallback,
  }) {
    return VvcLottie(
      assetPath: 'assets/lottie/empty.json',
      width: size,
      height: size,
      repeat: repeat,
      fallback: fallback ??
          Icon(Icons.inbox_rounded, size: size * 0.6, color: const Color(0xFF94A3B8)),
    );
  }

  /// ចលនាជួងរោទ៍ (Notification Bell Ringing)
  factory VvcLottie.bell({
    double size = 70.0,
    bool repeat = true,
    Widget? fallback,
  }) {
    return VvcLottie(
      assetPath: 'assets/lottie/bell_notify.json',
      width: size,
      height: size,
      repeat: repeat,
      fallback: fallback ??
          Icon(Icons.notifications_active_rounded, size: size * 0.7, color: const Color(0xFFF3D010)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: width,
      height: height,
      child: Lottie.asset(
        assetPath,
        width: width,
        height: height,
        repeat: repeat,
        animate: animate,
        fit: fit,
        errorBuilder: (context, error, stackTrace) {
          return fallback ??
              Center(
                child: Icon(
                  Icons.auto_awesome_rounded,
                  color: Theme.of(context).brightness == Brightness.dark
                      ? Colors.white54
                      : Colors.black45,
                  size: (width != null ? width! * 0.5 : 32.0),
                ),
              );
        },
      ),
    );
  }
}
