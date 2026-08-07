import 'dart:async';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

enum VvcAlertType { success, error, info, warning }

/// Ultra-Premium Glassmorphic Global Alert & Toast System for VVC App
class VvcAlert {
  /// Show a floating modern glassmorphic Toast notification at the top of screen
  static void showToast(
    BuildContext context, {
    required String title,
    String? message,
    VvcAlertType type = VvcAlertType.info,
    Duration duration = const Duration(seconds: 3),
  }) {
    final overlayState = Overlay.of(context);
    late OverlayEntry overlayEntry;

    overlayEntry = OverlayEntry(
      builder: (ctx) => _VvcToastWidget(
        title: title,
        message: message,
        type: type,
        duration: duration,
        onDismiss: () => overlayEntry.remove(),
      ),
    );

    overlayState.insert(overlayEntry);
  }

  /// Helper: Show Success Toast
  static void showSuccess(BuildContext context, {required String title, String? message}) {
    showToast(context, title: title, message: message, type: VvcAlertType.success);
  }

  /// Helper: Show Error Toast
  static void showError(BuildContext context, {required String title, String? message}) {
    showToast(context, title: title, message: message, type: VvcAlertType.error);
  }

  /// Helper: Show Info Toast
  static void showInfo(BuildContext context, {required String title, String? message}) {
    showToast(context, title: title, message: message, type: VvcAlertType.info);
  }

  /// Helper: Show Warning Toast
  static void showWarning(BuildContext context, {required String title, String? message}) {
    showToast(context, title: title, message: message, type: VvcAlertType.warning);
  }

  /// Show a Modern Glassmorphic Confirmation Dialog Modal
  static Future<bool?> showConfirmDialog(
    BuildContext context, {
    required String title,
    required String message,
    String confirmText = 'យល់ព្រម',
    String cancelText = 'បោះបង់',
    bool isDestructive = false,
    IconData? icon,
  }) {
    return showDialog<bool>(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.7),
      barrierDismissible: true,
      builder: (ctx) => _VvcConfirmDialog(
        title: title,
        message: message,
        confirmText: confirmText,
        cancelText: cancelText,
        isDestructive: isDestructive,
        customIcon: icon,
      ),
    );
  }
}

// Internal Toast Overlay Widget with Animations
class _VvcToastWidget extends StatefulWidget {
  final String title;
  final String? message;
  final VvcAlertType type;
  final Duration duration;
  final VoidCallback onDismiss;

  const _VvcToastWidget({
    required this.title,
    this.message,
    required this.type,
    required this.duration,
    required this.onDismiss,
  });

  @override
  State<_VvcToastWidget> createState() => _VvcToastWidgetState();
}

class _VvcToastWidgetState extends State<_VvcToastWidget> with SingleTickerProviderStateMixin {
  late AnimationController _ctrl;
  late Animation<double> _fadeAnim;
  late Animation<Offset> _slideAnim;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 380),
    );

    _fadeAnim = CurvedAnimation(parent: _ctrl, curve: Curves.easeOutCubic);
    _slideAnim = Tween<Offset>(
      begin: const Offset(0, -0.35),
      end: Offset.zero,
    ).animate(CurvedAnimation(parent: _ctrl, curve: Curves.easeOutBack));

    _ctrl.forward();

    _timer = Timer(widget.duration, _dismiss);
  }

  void _dismiss() async {
    _timer?.cancel();
    if (mounted) {
      await _ctrl.reverse();
      widget.onDismiss();
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    _ctrl.dispose();
    super.dispose();
  }

  Color get _primaryColor {
    switch (widget.type) {
      case VvcAlertType.success:
        return const Color(0xFF10B981);
      case VvcAlertType.error:
        return const Color(0xFFEF4444);
      case VvcAlertType.info:
        return const Color(0xFF007AFF);
      case VvcAlertType.warning:
        return const Color(0xFFF59E0B);
    }
  }

  List<Color> get _gradientColors {
    switch (widget.type) {
      case VvcAlertType.success:
        return [const Color(0xFF059669), const Color(0xFF10B981)];
      case VvcAlertType.error:
        return [const Color(0xFFDC2626), const Color(0xFFEF4444)];
      case VvcAlertType.info:
        return [const Color(0xFF0284C7), const Color(0xFF007AFF)];
      case VvcAlertType.warning:
        return [const Color(0xFFD97706), const Color(0xFFF59E0B)];
    }
  }

  IconData get _icon {
    switch (widget.type) {
      case VvcAlertType.success:
        return Icons.check_circle_rounded;
      case VvcAlertType.error:
        return Icons.error_rounded;
      case VvcAlertType.info:
        return Icons.info_rounded;
      case VvcAlertType.warning:
        return Icons.warning_amber_rounded;
    }
  }

  @override
  Widget build(BuildContext context) {
    final topPadding = MediaQuery.of(context).padding.top + 12.0;

    return Positioned(
      top: topPadding,
      left: 16.0,
      right: 16.0,
      child: Material(
        color: Colors.transparent,
        child: SlideTransition(
          position: _slideAnim,
          child: FadeTransition(
            opacity: _fadeAnim,
            child: GestureDetector(
              onTap: _dismiss,
              onVerticalDragUpdate: (details) {
                if (details.primaryDelta! < -4) _dismiss();
              },
              child: ClipRRect(
                borderRadius: BorderRadius.circular(20.0),
                child: BackdropFilter(
                  filter: ImageFilter.blur(sigmaX: 18.0, sigmaY: 18.0),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 13.0),
                    decoration: BoxDecoration(
                      color: const Color(0xFF1E2738).withValues(alpha: 0.88),
                      borderRadius: BorderRadius.circular(20.0),
                      border: Border.all(
                        color: _primaryColor.withValues(alpha: 0.35),
                        width: 1.2,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.45),
                          blurRadius: 20.0,
                          offset: const Offset(0, 8),
                        ),
                        BoxShadow(
                          color: _primaryColor.withValues(alpha: 0.15),
                          blurRadius: 16.0,
                          offset: const Offset(0, 2),
                        ),
                      ],
                    ),
                    child: Row(
                      children: [
                        // Left Glowing Icon
                        Container(
                          width: 40.0,
                          height: 40.0,
                          decoration: BoxDecoration(
                            gradient: LinearGradient(
                              colors: _gradientColors,
                              begin: Alignment.topLeft,
                              end: Alignment.bottomRight,
                            ),
                            shape: BoxShape.circle,
                            boxShadow: [
                              BoxShadow(
                                color: _primaryColor.withValues(alpha: 0.4),
                                blurRadius: 10,
                                offset: const Offset(0, 3),
                              ),
                            ],
                          ),
                          child: Icon(_icon, color: Colors.white, size: 22.0),
                        ),
                        const SizedBox(width: 14.0),

                        // Title & Optional Message
                        Expanded(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                widget.title,
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white,
                                  fontSize: 14.5,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                              if (widget.message != null && widget.message!.isNotEmpty) ...[
                                const SizedBox(height: 2.0),
                                Text(
                                  widget.message!,
                                  style: GoogleFonts.kantumruyPro(
                                    color: Colors.white70,
                                    fontSize: 12.5,
                                  ),
                                  maxLines: 2,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ],
                            ],
                          ),
                        ),
                        const SizedBox(width: 8.0),

                        // Close icon
                        Icon(
                          Icons.close_rounded,
                          color: Colors.white.withValues(alpha: 0.5),
                          size: 18.0,
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// Internal Glassmorphic Confirmation Modal Dialog
class _VvcConfirmDialog extends StatelessWidget {
  final String title;
  final String message;
  final String confirmText;
  final String cancelText;
  final bool isDestructive;
  final IconData? customIcon;

  const _VvcConfirmDialog({
    required this.title,
    required this.message,
    required this.confirmText,
    required this.cancelText,
    required this.isDestructive,
    this.customIcon,
  });

  @override
  Widget build(BuildContext context) {
    final Color mainColor = isDestructive ? const Color(0xFFEF4444) : const Color(0xFF007AFF);
    final List<Color> gradient = isDestructive
        ? [const Color(0xFFDC2626), const Color(0xFFEF4444)]
        : [const Color(0xFF0284C7), const Color(0xFF007AFF)];

    final IconData icon = customIcon ?? (isDestructive ? Icons.delete_outline_rounded : Icons.check_circle_outline_rounded);

    return Dialog(
      backgroundColor: Colors.transparent,
      insetPadding: const EdgeInsets.symmetric(horizontal: 24.0, vertical: 24.0),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(24.0),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 20.0, sigmaY: 20.0),
          child: Container(
            padding: const EdgeInsets.all(22.0),
            decoration: BoxDecoration(
              color: const Color(0xFF1E2738).withValues(alpha: 0.92),
              borderRadius: BorderRadius.circular(24.0),
              border: Border.all(
                color: Colors.white.withValues(alpha: 0.12),
                width: 1.0,
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.5),
                  blurRadius: 28.0,
                  offset: const Offset(0, 10),
                ),
              ],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // Top Icon Badge
                Container(
                  width: 58.0,
                  height: 58.0,
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: gradient,
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: mainColor.withValues(alpha: 0.4),
                        blurRadius: 14.0,
                        offset: const Offset(0, 4),
                      ),
                    ],
                  ),
                  child: Icon(icon, color: Colors.white, size: 30.0),
                ),
                const SizedBox(height: 16.0),

                // Title
                Text(
                  title,
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontSize: 17.5,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8.0),

                // Message Body
                Text(
                  message,
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white70,
                    fontSize: 13.5,
                    height: 1.4,
                  ),
                ),
                const SizedBox(height: 22.0),

                // Action Buttons
                Row(
                  children: [
                    // Cancel Button
                    Expanded(
                      child: SizedBox(
                        height: 46.0,
                        child: OutlinedButton(
                          onPressed: () => Navigator.pop(context, false),
                          style: OutlinedButton.styleFrom(
                            side: BorderSide(color: Colors.white.withValues(alpha: 0.15)),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(16.0),
                            ),
                          ),
                          child: Text(
                            cancelText,
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white70,
                              fontSize: 14.5,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(width: 12.0),

                    // Confirm Button
                    Expanded(
                      child: SizedBox(
                        height: 46.0,
                        child: Container(
                          decoration: BoxDecoration(
                            gradient: LinearGradient(
                              colors: gradient,
                              begin: Alignment.topLeft,
                              end: Alignment.bottomRight,
                            ),
                            borderRadius: BorderRadius.circular(16.0),
                            boxShadow: [
                              BoxShadow(
                                color: mainColor.withValues(alpha: 0.35),
                                blurRadius: 10.0,
                                offset: const Offset(0, 3),
                              ),
                            ],
                          ),
                          child: ElevatedButton(
                            onPressed: () => Navigator.pop(context, true),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.transparent,
                              shadowColor: Colors.transparent,
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(16.0),
                              ),
                            ),
                            child: Text(
                              confirmText,
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white,
                                fontSize: 14.5,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
