import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/physics.dart';
import 'package:flutter/services.dart';

/// ═══════════════════════════════════════════════════════════════════════════
/// TelegramBounce — Telegram/iOS-grade Spring Micro-Interaction
/// ═══════════════════════════════════════════════════════════════════════════
/// Spring physics ពិតៗ: press → shrink → release → overshoot → settle at 1.0
/// ដូច iOS Haptic ។  scaleFactor = minimum scale ពេល press (default 0.955)
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
    this.duration = const Duration(milliseconds: 100),
    this.enableHaptic = true,
    this.behavior = HitTestBehavior.opaque,
  });

  @override
  State<TelegramBounce> createState() => _TelegramBounceState();
}

class _TelegramBounceState extends State<TelegramBounce>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  // ── Spring config (Telegram-tuned): stiffness 400, damping 18 ─────────────
  static const SpringDescription _spring = SpringDescription(
    mass: 1.0,
    stiffness: 400.0,
    damping: 18.0,
  );

  bool _isPressed = false;

  @override
  void initState() {
    super.initState();
    // upperBound > 1.0 to allow overshoot above 1.0 during release
    _controller = AnimationController.unbounded(vsync: this)..value = 1.0;
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _press() {
    if (!_isPressed) {
      _isPressed = true;
      if (widget.enableHaptic) HapticFeedback.lightImpact();
      // Spring to scaleFactor (compressed)
      final sim = SpringSimulation(_spring, _controller.value, widget.scaleFactor, 0.0);
      _controller.animateWith(sim);
    }
  }

  void _release() {
    if (_isPressed) {
      _isPressed = false;
      // Spring back to 1.0 (with natural overshoot = Telegram bounce)
      final sim = SpringSimulation(_spring, _controller.value, 1.0, 0.0);
      _controller.animateWith(sim);
    }
  }

  void _onTapDown(TapDownDetails _) {
    final bool clickable =
        widget.onTap != null || widget.onLongPress != null || widget.onDoubleTap != null;
    if (clickable) _press();
  }

  void _onTapUp(TapUpDetails _) => _release();
  void _onTapCancel() => _release();

  @override
  Widget build(BuildContext context) {
    final bool isClickable =
        widget.onTap != null || widget.onLongPress != null || widget.onDoubleTap != null;

    if (!isClickable) return widget.child;

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
                if (widget.enableHaptic) HapticFeedback.mediumImpact();
                widget.onLongPress!();
              }
            : null,
        child: AnimatedBuilder(
          animation: _controller,
          builder: (context, child) => Transform.scale(
            scale: _controller.value.clamp(0.80, 1.08),
            child: child,
          ),
          child: widget.child,
        ),
      ),
    );
  }
}

/// ═══════════════════════════════════════════════════════════════════════════
/// TelegramPageRoute (Liquid Parallax Slide & Edge-Swipe Navigation)
/// ═══════════════════════════════════════════════════════════════════════════
/// Native iOS & Telegram-grade edge-swipe interactive pop gesture,
/// responsive spring curve, and depth parallax on all platforms.
class TelegramPageRoute<T> extends CupertinoPageRoute<T> {
  final Widget page;

  TelegramPageRoute({
    required this.page,
    super.settings,
    super.maintainState = true,
    super.fullscreenDialog = false,
    super.allowSnapshotting = true,
    super.barrierDismissible = false,
  }) : super(builder: (_) => page);
}

/// Quick helper to create a Telegram-style page route
Route<T> telegramRoute<T>(Widget page, {RouteSettings? settings, bool fullscreenDialog = false}) =>
    TelegramPageRoute<T>(
      page: page,
      settings: settings,
      fullscreenDialog: fullscreenDialog,
    );

/// Global PageTransitionsBuilder for Telegram-grade slide & swipe transitions
class TelegramPageTransitionsBuilder extends PageTransitionsBuilder {
  const TelegramPageTransitionsBuilder();

  @override
  Widget buildTransitions<T>(
    PageRoute<T> route,
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) {
    return const CupertinoPageTransitionsBuilder().buildTransitions(
      route,
      context,
      animation,
      secondaryAnimation,
      child,
    );
  }
}

