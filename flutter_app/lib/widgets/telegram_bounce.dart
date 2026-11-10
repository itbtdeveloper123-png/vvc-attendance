import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// ═══════════════════════════════════════════════════════════════════════════
/// TelegramBounce (Telegram-style Tactile Micro-Interaction Press Effect)
/// ═══════════════════════════════════════════════════════════════════════════
/// Provides tactile spring scaling and haptic vibration feedback on tap/press,
/// giving buttons, cards, and tiles the signature modern bounce of Telegram.
class TelegramBounce extends StatefulWidget {
  final Widget child;
  final VoidCallback? onTap;
  final VoidCallback? onLongPress;
  final VoidCallback? onDoubleTap;
  final double scaleFactor;
  final Duration duration;
  final bool enableHaptic;
  final HitTestBehavior behavior;

  const TelegramBounce({
    super.key,
    required this.child,
    this.onTap,
    this.onLongPress,
    this.onDoubleTap,
    this.scaleFactor = 0.955,
    this.duration = const Duration(milliseconds: 110),
    this.enableHaptic = true,
    this.behavior = HitTestBehavior.opaque,
  });

  @override
  State<TelegramBounce> createState() => _TelegramBounceState();
}

class _TelegramBounceState extends State<TelegramBounce>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _scaleAnimation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: widget.duration,
      reverseDuration: const Duration(milliseconds: 180),
    );
    _scaleAnimation = Tween<double>(
      begin: 1.0,
      end: widget.scaleFactor,
    ).animate(
      CurvedAnimation(
        parent: _controller,
        curve: Curves.easeOutQuad,
        reverseCurve: Curves.easeOutBack,
      ),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onTapDown(TapDownDetails details) {
    if (widget.onTap != null || widget.onLongPress != null || widget.onDoubleTap != null) {
      if (widget.enableHaptic) {
        HapticFeedback.lightImpact();
      }
      _controller.forward();
    }
  }

  void _onTapUp(TapUpDetails details) {
    if (widget.onTap != null || widget.onLongPress != null || widget.onDoubleTap != null) {
      _controller.reverse();
    }
  }

  void _onTapCancel() {
    if (widget.onTap != null || widget.onLongPress != null || widget.onDoubleTap != null) {
      _controller.reverse();
    }
  }

  @override
  Widget build(BuildContext context) {
    final bool isClickable =
        widget.onTap != null || widget.onLongPress != null || widget.onDoubleTap != null;

    if (!isClickable) {
      return widget.child;
    }

    return MouseRegion(
      cursor: SystemMouseCursors.click,
      child: GestureDetector(
        behavior: widget.behavior,
        onTapDown: _onTapDown,
        onTapUp: _onTapUp,
        onTapCancel: _onTapCancel,
        onTap: widget.onTap,
        onDoubleTap: widget.onDoubleTap,
        onLongPress: widget.onLongPress != null
            ? () {
                if (widget.enableHaptic) {
                  HapticFeedback.mediumImpact();
                }
                widget.onLongPress!();
              }
            : null,
        child: ScaleTransition(
          scale: _scaleAnimation,
          child: widget.child,
        ),
      ),
    );
  }
}

/// ═══════════════════════════════════════════════════════════════════════════
/// TelegramPageRoute (Liquid Parallax Slide & Edge-Swipe Navigation)
/// ═══════════════════════════════════════════════════════════════════════════
class TelegramPageRoute<T> extends PageRouteBuilder<T> {
  final Widget page;

  TelegramPageRoute({
    required this.page,
    super.settings,
  }) : super(
          pageBuilder: (context, animation, secondaryAnimation) => page,
          transitionDuration: const Duration(milliseconds: 320),
          reverseTransitionDuration: const Duration(milliseconds: 280),
          transitionsBuilder: (context, animation, secondaryAnimation, child) {
            // Forward entering slide from right
            final primarySlide = Tween<Offset>(
              begin: const Offset(1.0, 0.0),
              end: Offset.zero,
            ).animate(
              CurvedAnimation(
                parent: animation,
                curve: Curves.fastEaseInToSlowEaseOut,
                reverseCurve: Curves.easeInCubic,
              ),
            );

            // Previous page parallax depth (translates slightly left when pushed)
            final secondarySlide = Tween<Offset>(
              begin: Offset.zero,
              end: const Offset(-0.25, 0.0),
            ).animate(
              CurvedAnimation(
                parent: secondaryAnimation,
                curve: Curves.fastEaseInToSlowEaseOut,
                reverseCurve: Curves.easeInCubic,
              ),
            );

            // Previous page subtle dimming overlay
            final secondaryDim = Tween<double>(
              begin: 0.0,
              end: 0.25,
            ).animate(
              CurvedAnimation(
                parent: secondaryAnimation,
                curve: Curves.linear,
              ),
            );

            return SlideTransition(
              position: secondarySlide,
              child: AnimatedBuilder(
                animation: secondaryDim,
                builder: (context, childWidget) {
                  return ColorFiltered(
                    colorFilter: ColorFilter.mode(
                      Colors.black.withValues(alpha: secondaryDim.value),
                      BlendMode.srcOver,
                    ),
                    child: childWidget,
                  );
                },
                child: SlideTransition(
                  position: primarySlide,
                  child: DecoratedBox(
                    decoration: BoxDecoration(
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.12),
                          blurRadius: 18,
                          offset: const Offset(-4, 0),
                        ),
                      ],
                    ),
                    child: child,
                  ),
                ),
              ),
            );
          },
        );
}
