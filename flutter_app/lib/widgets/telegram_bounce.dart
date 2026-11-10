import 'package:flutter/cupertino.dart';
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

