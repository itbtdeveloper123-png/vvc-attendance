import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../utils/app_theme.dart';

// ═══════════════════════════════════════════════════════════════════════════════
// 1. LIQUID GLASS BOTTOM BAR ITEM MODEL
// ═══════════════════════════════════════════════════════════════════════════════

class LiquidGlassItem {
  final IconData icon;
  final IconData? selectedIcon;
  final String? label;
  final String? badgeText;
  final bool isCenter;

  const LiquidGlassItem({
    required this.icon,
    this.selectedIcon,
    this.label,
    this.badgeText,
    this.isCenter = false,
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. LIQUID GLASS FLOATING BOTTOM NAVIGATION BAR (Telegram iOS 1:1 Dynamic Dock)
// ═══════════════════════════════════════════════════════════════════════════════

class VvcLiquidGlassBottomBar extends StatelessWidget {
  final int currentIndex;
  final ValueChanged<int> onTap;
  final List<LiquidGlassItem> items;
  final Color? backgroundColor;
  final Color? accentColor;
  final Color? borderColor;
  final Color? unselectedItemColor;
  final double blurSigma;
  final double transitionHeight;
  final double bottomInset;
  final ScrollController? scrollController;
  final Widget? trailingAction;
  final VoidCallback? onTrailingActionTap;
  final bool isScrolled;

  const VvcLiquidGlassBottomBar({
    super.key,
    required this.currentIndex,
    required this.onTap,
    required this.items,
    this.backgroundColor,
    this.accentColor,
    this.borderColor,
    this.unselectedItemColor,
    this.blurSigma = 25.0,
    this.transitionHeight = 145.0,
    this.bottomInset = 0.0,
    this.scrollController,
    this.trailingAction,
    this.onTrailingActionTap,
    this.isScrolled = false,
  });

  VvcLiquidGlassBottomBar copyWith({
    int? currentIndex,
    ValueChanged<int>? onTap,
    List<LiquidGlassItem>? items,
    Color? backgroundColor,
    Color? accentColor,
    Color? borderColor,
    Color? unselectedItemColor,
    double? blurSigma,
    double? transitionHeight,
    double? bottomInset,
    ScrollController? scrollController,
    Widget? trailingAction,
    VoidCallback? onTrailingActionTap,
    bool? isScrolled,
  }) {
    return VvcLiquidGlassBottomBar(
      currentIndex: currentIndex ?? this.currentIndex,
      onTap: onTap ?? this.onTap,
      items: items ?? this.items,
      backgroundColor: backgroundColor ?? this.backgroundColor,
      accentColor: accentColor ?? this.accentColor,
      borderColor: borderColor ?? this.borderColor,
      unselectedItemColor: unselectedItemColor ?? this.unselectedItemColor,
      blurSigma: blurSigma ?? this.blurSigma,
      transitionHeight: transitionHeight ?? this.transitionHeight,
      bottomInset: bottomInset ?? this.bottomInset,
      scrollController: scrollController ?? this.scrollController,
      trailingAction: trailingAction ?? this.trailingAction,
      onTrailingActionTap: onTrailingActionTap ?? this.onTrailingActionTap,
      isScrolled: isScrolled ?? this.isScrolled,
    );
  }

  void _triggerHaptic() {
    HapticFeedback.lightImpact();
  }

  /// 1. Localized Bottom Edge Transition Zone (Clear at rest -> Animated Fade Mask on scroll)
  Widget buildTransitionZone({
    required BuildContext context,
    Color? maskColor,
  }) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final effectiveMask = maskColor ??
        (isDark ? const Color(0xFF0F1115) : const Color(0xFFF8FAFC));
    final double totalHeight = transitionHeight + bottomInset;

    return Positioned(
      left: 0,
      right: 0,
      bottom: 0,
      height: totalHeight,
      child: IgnorePointer(
        child: AnimatedOpacity(
          duration: const Duration(milliseconds: 240),
          curve: Curves.easeInOutCubic,
          opacity: isScrolled ? 0.92 : 0.0,
          child: Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topCenter,
                end: Alignment.bottomCenter,
                colors: [
                  effectiveMask.withValues(alpha: 0.0),
                  effectiveMask.withValues(alpha: 0.35),
                  effectiveMask.withValues(alpha: 0.75),
                  effectiveMask.withValues(alpha: 0.95),
                ],
                stops: const [0.0, 0.40, 0.80, 1.0],
              ),
            ),
          ),
        ),
      ),
    );
  }

  /// Top Edge Ambient Transition Zone (Smooth Apple iOS Top Ambient Fade)
  Widget buildTopTransitionZone({
    required BuildContext context,
    Color? maskColor,
    double height = 48.0,
  }) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final effectiveMask = maskColor ??
        (isDark ? const Color(0xFF0F1115) : const Color(0xFFF8FAFC));
    final double topInset = MediaQuery.paddingOf(context).top;

    return Positioned(
      left: 0,
      right: 0,
      top: 0,
      height: topInset + height,
      child: IgnorePointer(
        child: AnimatedOpacity(
          duration: const Duration(milliseconds: 240),
          curve: Curves.easeInOutCubic,
          opacity: isScrolled ? 0.92 : 0.0,
          child: Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topCenter,
                end: Alignment.bottomCenter,
                colors: [
                  effectiveMask.withValues(alpha: 0.40),
                  effectiveMask.withValues(alpha: 0.15),
                  effectiveMask.withValues(alpha: 0.0),
                ],
                stops: const [0.0, 0.55, 1.0],
              ),
            ),
          ),
        ),
      ),
    );
  }

  /// 2. Floating Liquid Glass Dual-Island Dock (Navigation Island Capsule + Standalone Action Pod)
  Widget buildFloatingDock({required BuildContext context}) {
    final double bottomMargin = bottomInset > 0 ? bottomInset + 4.0 : 14.0;
    final effectiveAccent = accentColor ?? const Color(0xFF0A84FF); // Apple Blue
    final isDark = Theme.of(context).brightness == Brightness.dark;
    const double dockHeight = 64.0;

    final targetBorder = borderColor ??
        (isDark
            ? const Color(0x38545458)
            : const Color(0xFFE2E8F0));

    final targetBg = backgroundColor ??
        (isDark
            ? const Color(0xFF1C1C1E).withValues(alpha: 0.82)
            : const Color(0xFFF1F3F6).withValues(alpha: 0.82));

    final effectiveBorder = isScrolled ? targetBorder : Colors.transparent;
    final effectiveBg = isScrolled ? targetBg : Colors.transparent;
    final effectiveShadow = isScrolled
        ? [
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.08),
              blurRadius: 18.0,
              offset: const Offset(0, 4),
            ),
          ]
        : <BoxShadow>[];

    return Container(
      margin: EdgeInsets.fromLTRB(16.0, 0, 16.0, bottomMargin),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          // 1. LEFT MAIN NAVIGATION DOCK CAPSULE
          Expanded(
            child: TweenAnimationBuilder<double>(
              tween: Tween<double>(begin: 0.0, end: isScrolled ? blurSigma : 0.0),
              duration: const Duration(milliseconds: 240),
              curve: Curves.easeInOutCubic,
              builder: (context, blur, child) {
                if (blur <= 0.05) {
                  return child!;
                }
                return ClipRRect(
                  borderRadius: BorderRadius.circular(36.0),
                  child: BackdropFilter(
                    filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
                    child: child,
                  ),
                );
              },
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 240),
                curve: Curves.easeInOutCubic,
                height: dockHeight,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(36.0),
                  boxShadow: effectiveShadow,
                ),
                child: Container(
                  height: dockHeight,
                  padding: const EdgeInsets.symmetric(horizontal: 6.0, vertical: 6.0),
                  decoration: BoxDecoration(
                    color: effectiveBg,
                    borderRadius: BorderRadius.circular(36.0),
                    border: Border.all(
                      color: effectiveBorder,
                      width: 1.2,
                    ),
                  ),
                  child: Row(
                    children: List.generate(items.length, (index) {
                      final item = items[index];
                      final isSelected = index == currentIndex;
                      return Expanded(
                        child: _buildDockItem(
                          context: context,
                          item: item,
                          isSelected: isSelected,
                          activeColor: effectiveAccent,
                          onItemTap: () {
                            _triggerHaptic();
                            onTap(index);
                          },
                        ),
                      );
                    }),
                  ),
                ),
              ),
            ),
          ),

          // 2. RIGHT STANDALONE CIRCULAR ACTION POD (Quick Scan QR / Face)
          if (trailingAction != null) ...[
            const SizedBox(width: 10.0),
            GestureDetector(
              onTap: () {
                _triggerHaptic();
                onTrailingActionTap?.call();
              },
              behavior: HitTestBehavior.opaque,
              child: TweenAnimationBuilder<double>(
                tween: Tween<double>(begin: 0.0, end: isScrolled ? blurSigma : 0.0),
                duration: const Duration(milliseconds: 240),
                curve: Curves.easeInOutCubic,
                builder: (context, blur, child) {
                  if (blur <= 0.05) {
                    return child!;
                  }
                  return ClipOval(
                    child: BackdropFilter(
                      filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
                      child: child,
                    ),
                  );
                },
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 240),
                  curve: Curves.easeInOutCubic,
                  width: dockHeight,
                  height: dockHeight,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: effectiveBg,
                    border: Border.all(
                      color: effectiveBorder,
                      width: 1.2,
                    ),
                    boxShadow: effectiveShadow,
                  ),
                  child: Center(child: trailingAction!),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildDockItem({
    required BuildContext context,
    required LiquidGlassItem item,
    required bool isSelected,
    required Color activeColor,
    required VoidCallback onItemTap,
  }) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final iconData = (isSelected && item.selectedIcon != null)
        ? item.selectedIcon!
        : item.icon;
    final hasLabel = item.label != null && item.label!.isNotEmpty;

    // Active pill indicator wrapping both icon and label
    final activePillBg = isDark
        ? Colors.white.withValues(alpha: 0.12)
        : Colors.black.withValues(alpha: 0.06);

    return GestureDetector(
      onTap: onItemTap,
      behavior: HitTestBehavior.opaque,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 220),
        curve: Curves.easeOutCubic,
        margin: const EdgeInsets.symmetric(horizontal: 2.0),
        padding: const EdgeInsets.symmetric(horizontal: 6.0, vertical: 4.0),
        decoration: BoxDecoration(
          color: isSelected ? activePillBg : Colors.transparent,
          borderRadius: BorderRadius.circular(26.0),
        ),
        child: Stack(
          clipBehavior: Clip.none,
          alignment: Alignment.center,
          children: [
            Column(
              mainAxisSize: MainAxisSize.min,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(
                  iconData,
                  color: isSelected
                      ? activeColor
                      : (isDark ? Colors.white : const Color(0xFF0F172A)),
                  size: 22.0,
                ),
                if (hasLabel) ...[
                  const SizedBox(height: 3.0),
                  Text(
                    item.label!,
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 11.0,
                      fontWeight: isSelected ? FontWeight.w700 : FontWeight.w500,
                      color: isSelected
                          ? activeColor
                          : (isDark ? Colors.white : const Color(0xFF0F172A)),
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ],
            ),
            if (item.badgeText != null && item.badgeText!.isNotEmpty)
              Positioned(
                top: -2.0,
                right: 4.0,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 4.5, vertical: 1.2),
                  decoration: BoxDecoration(
                    color: const Color(0xFFDC2626),
                    borderRadius: BorderRadius.circular(10.0),
                    border: Border.all(color: Colors.white, width: 1.2),
                  ),
                  child: Text(
                    item.badgeText!,
                    style: GoogleFonts.inter(
                      color: Colors.white,
                      fontSize: 8.5,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      clipBehavior: Clip.none,
      children: [
        buildTransitionZone(context: context),
        buildFloatingDock(context: context),
      ],
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. GLOBAL LIQUID GLASS CIRCLE BUTTON (Cupertino Action Button)
// ═══════════════════════════════════════════════════════════════════════════════

class VvcLiquidGlassCircleButton extends StatelessWidget {
  final VoidCallback? onTap;
  final Widget child;
  final double size;
  final Color? borderColor;
  final bool isScrolled;

  const VvcLiquidGlassCircleButton({
    super.key,
    required this.onTap,
    required this.child,
    this.size = 38.0,
    this.borderColor,
    this.isScrolled = false,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return GestureDetector(
      onTap: () {
        if (onTap != null) {
          HapticFeedback.lightImpact();
          onTap!();
        }
      },
      behavior: HitTestBehavior.opaque,
      child: TweenAnimationBuilder<double>(
        tween: Tween<double>(begin: 0.0, end: isScrolled ? 16.0 : 0.0),
        duration: const Duration(milliseconds: 240),
        curve: Curves.easeInOutCubic,
        builder: (context, blur, innerChild) {
          if (blur <= 0.05) return innerChild!;
          return ClipOval(
            child: BackdropFilter(
              filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
              child: innerChild,
            ),
          );
        },
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 240),
          curve: Curves.easeInOutCubic,
          width: size,
          height: size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: isScrolled
                ? (isDark ? const Color(0xFF222630) : const Color(0xFFF1F3F6))
                : Colors.transparent,
            border: Border.all(
              color: isScrolled
                  ? (borderColor ??
                      (isDark
                          ? Colors.white.withValues(alpha: 0.12)
                          : const Color(0xFFE2E8F0)))
                  : Colors.transparent,
              width: 1.2,
            ),
            boxShadow: isScrolled
                ? [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.06),
                      blurRadius: 10.0,
                      offset: const Offset(0, 3),
                    ),
                  ]
                : null,
          ),
          child: Center(child: child),
        ),
      ),
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. GLOBAL LIQUID GLASS PINNED HEADER (Cupertino / Telegram Pinned Top Header)
// ═══════════════════════════════════════════════════════════════════════════════

class VvcLiquidGlassPinnedHeader extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry? padding;
  final double borderRadius;
  final bool isScrolled;
  final Color? borderColor;
  final double blurSigma;
  final bool alwaysShowGlass;

  const VvcLiquidGlassPinnedHeader({
    super.key,
    required this.child,
    this.padding,
    this.borderRadius = 28.0,
    this.isScrolled = false,
    this.borderColor,
    this.blurSigma = 25.0,
    this.alwaysShowGlass = false,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final hasGlass = isScrolled || alwaysShowGlass;

    final effectiveBorder = hasGlass
        ? (borderColor ??
            (isDark
                ? Colors.white.withValues(alpha: 0.12)
                : const Color(0xFFE2E8F0)))
        : Colors.transparent;

    final headerBgColor = hasGlass
        ? (isDark
            ? const Color(0xFF222630).withValues(alpha: 0.85)
            : const Color(0xFFF1F3F6).withValues(alpha: 0.85))
        : Colors.transparent;

    return TweenAnimationBuilder<double>(
      tween: Tween<double>(begin: 0.0, end: hasGlass ? blurSigma : 0.0),
      duration: const Duration(milliseconds: 240),
      curve: Curves.easeInOutCubic,
      builder: (context, blur, innerChild) {
        if (blur <= 0.05) return innerChild!;
        return ClipRRect(
          borderRadius: BorderRadius.vertical(bottom: Radius.circular(borderRadius)),
          child: BackdropFilter(
            filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
            child: innerChild,
          ),
        );
      },
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 240),
        curve: Curves.easeInOutCubic,
        padding: padding,
        decoration: BoxDecoration(
          color: headerBgColor,
          borderRadius: BorderRadius.vertical(bottom: Radius.circular(borderRadius)),
          border: Border.all(
            color: effectiveBorder,
            width: 1.2,
          ),
          boxShadow: hasGlass
              ? [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.06),
                    blurRadius: 16.0,
                    offset: const Offset(0, 4),
                  ),
                ]
              : null,
        ),
        child: child,
      ),
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. GLOBAL FLOATING HEADER PODS (Segmented Three-Islands Apple Glass Header)
// ═══════════════════════════════════════════════════════════════════════════════

class VvcFloatingHeaderPods extends StatelessWidget {
  final String? title;
  final Widget? titleWidget;
  final Widget? leading;
  final List<Widget>? actions;
  final VoidCallback? onLeadingTap;
  final Color? backgroundColor;
  final Color? borderColor;
  final double height;
  final bool isScrolled;
  final bool alwaysShowTitle;
  final bool alwaysShowGlass;
  final double blurSigma;

  const VvcFloatingHeaderPods({
    super.key,
    this.title,
    this.titleWidget,
    this.leading,
    this.actions,
    this.onLeadingTap,
    this.backgroundColor,
    this.borderColor,
    this.height = 48.0,
    this.isScrolled = false,
    this.alwaysShowTitle = false,
    this.alwaysShowGlass = false,
    this.blurSigma = 20.0,
  });

  Widget _buildLeftPod(
    BuildContext context,
    bool isDark,
    Color targetBg,
    Color targetBorder,
  ) {
    final canPop = ModalRoute.of(context)?.canPop ?? false;
    if (leading == null && !canPop) {
      return const SizedBox.shrink();
    }

    Widget content;
    VoidCallback? tapHandler;

    if (leading != null) {
      if (leading is IconButton) {
        final btn = leading as IconButton;
        tapHandler = btn.onPressed;
        content = IconTheme(
          data: IconThemeData(
            size: 20.0,
            color: isDark ? Colors.white : const Color(0xFF0F172A),
          ),
          child: btn.icon,
        );
      } else {
        content = leading!;
      }
    } else {
      tapHandler = () => Navigator.maybePop(context);
      content = Icon(
        CupertinoIcons.chevron_back,
        size: 20.0,
        color: isDark ? Colors.white : const Color(0xFF0F172A),
      );
    }

    final hasGlass = isScrolled || alwaysShowGlass;
    final effectiveBg = hasGlass ? targetBg : Colors.transparent;
    final effectiveBorder = hasGlass ? targetBorder : Colors.transparent;
    final effectiveShadow = hasGlass
        ? [
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.08),
              blurRadius: 14.0,
              offset: const Offset(0, 4),
            ),
          ]
        : <BoxShadow>[];

    return GestureDetector(
      onTap: () {
        HapticFeedback.lightImpact();
        if (tapHandler != null) {
          tapHandler();
        } else if (onLeadingTap != null) {
          onLeadingTap!();
        } else {
          Navigator.maybePop(context);
        }
      },
      behavior: HitTestBehavior.opaque,
      child: TweenAnimationBuilder<double>(
        tween: Tween<double>(begin: 0.0, end: hasGlass ? blurSigma : 0.0),
        duration: const Duration(milliseconds: 240),
        curve: Curves.easeInOutCubic,
        builder: (context, blur, child) {
          if (blur <= 0.05) return child!;
          return ClipOval(
            child: BackdropFilter(
              filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
              child: child,
            ),
          );
        },
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 240),
          curve: Curves.easeInOutCubic,
          width: height,
          height: height,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: effectiveBg,
            border: Border.all(color: effectiveBorder, width: 1.2),
            boxShadow: effectiveShadow,
          ),
          child: Center(child: content),
        ),
      ),
    );
  }

  Widget _buildCenterPod(
    BuildContext context,
    bool isDark,
    Color targetBg,
    Color targetBorder,
  ) {
    Widget titleContent;
    if (titleWidget != null) {
      titleContent = DefaultTextStyle.merge(
        style: GoogleFonts.kantumruyPro(
          fontWeight: FontWeight.bold,
          fontSize: 16.0,
          color: isDark ? Colors.white : const Color(0xFF0F172A),
        ),
        child: titleWidget!,
      );
    } else {
      titleContent = Text(
        title ?? '',
        style: GoogleFonts.kantumruyPro(
          fontWeight: FontWeight.bold,
          fontSize: 16.0,
          color: isDark ? Colors.white : const Color(0xFF0F172A),
        ),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      );
    }

    final hasGlass = isScrolled || alwaysShowGlass;
    final showTitle = hasGlass || alwaysShowTitle;
    final effectiveBg = hasGlass ? targetBg : Colors.transparent;
    final effectiveBorder = hasGlass ? targetBorder : Colors.transparent;
    final effectiveShadow = hasGlass
        ? [
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.08),
              blurRadius: 14.0,
              offset: const Offset(0, 4),
            ),
          ]
        : <BoxShadow>[];

    return TweenAnimationBuilder<double>(
      tween: Tween<double>(begin: 0.0, end: hasGlass ? blurSigma : 0.0),
      duration: const Duration(milliseconds: 240),
      curve: Curves.easeInOutCubic,
      builder: (context, blur, child) {
        if (blur <= 0.05) return child!;
        return ClipRRect(
          borderRadius: BorderRadius.circular(height / 2),
          child: BackdropFilter(
            filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
            child: child,
          ),
        );
      },
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 240),
        curve: Curves.easeInOutCubic,
        height: height,
        padding: const EdgeInsets.symmetric(horizontal: 16.0),
        decoration: BoxDecoration(
          color: effectiveBg,
          borderRadius: BorderRadius.circular(height / 2),
          border: Border.all(color: effectiveBorder, width: 1.2),
          boxShadow: effectiveShadow,
        ),
        child: Center(
          child: AnimatedOpacity(
            duration: const Duration(milliseconds: 220),
            curve: Curves.easeInOutCubic,
            opacity: showTitle ? 1.0 : 0.0,
            child: titleContent,
          ),
        ),
      ),
    );
  }

  Widget _buildRightPod(
    BuildContext context,
    bool isDark,
    Color targetBg,
    Color targetBorder,
    bool hasLeftPod,
  ) {
    if (actions == null || actions!.isEmpty) {
      if (hasLeftPod) {
        return SizedBox(width: height);
      }
      return const SizedBox.shrink();
    }

    final hasGlass = isScrolled || alwaysShowGlass;
    final effectiveBg = hasGlass ? targetBg : Colors.transparent;
    final effectiveBorder = hasGlass ? targetBorder : Colors.transparent;
    final effectiveShadow = hasGlass
        ? [
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.08),
              blurRadius: 14.0,
              offset: const Offset(0, 4),
            ),
          ]
        : <BoxShadow>[];

    if (actions!.length == 1) {
      final act = actions!.first;
      Widget actChild = act;
      if (act is IconButton) {
        actChild = GestureDetector(
          onTap: () {
            HapticFeedback.lightImpact();
            act.onPressed?.call();
          },
          behavior: HitTestBehavior.opaque,
          child: Center(
            child: IconTheme(
              data: IconThemeData(
                size: 20.0,
                color: isDark ? Colors.white : const Color(0xFF0F172A),
              ),
              child: act.icon,
            ),
          ),
        );
      }

      return TweenAnimationBuilder<double>(
        tween: Tween<double>(begin: 0.0, end: hasGlass ? blurSigma : 0.0),
        duration: const Duration(milliseconds: 240),
        curve: Curves.easeInOutCubic,
        builder: (context, blur, child) {
          if (blur <= 0.05) return child!;
          return ClipOval(
            child: BackdropFilter(
              filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
              child: child,
            ),
          );
        },
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 240),
          curve: Curves.easeInOutCubic,
          width: height,
          height: height,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: effectiveBg,
            border: Border.all(color: effectiveBorder, width: 1.2),
            boxShadow: effectiveShadow,
          ),
          child: Center(child: actChild),
        ),
      );
    }

    // Multiple actions -> Capsule Pod
    final actionItems = actions!.map<Widget>((act) {
      if (act is IconButton) {
        return SizedBox(
          width: 38.0,
          height: 38.0,
          child: IconButton(
            padding: EdgeInsets.zero,
            iconSize: 20.0,
            icon: IconTheme(
              data: IconThemeData(
                size: 20.0,
                color: isDark ? Colors.white : const Color(0xFF0F172A),
              ),
              child: act.icon,
            ),
            onPressed: () {
              HapticFeedback.lightImpact();
              act.onPressed?.call();
            },
            tooltip: act.tooltip,
          ),
        );
      }
      return act;
    }).toList();

    return TweenAnimationBuilder<double>(
      tween: Tween<double>(begin: 0.0, end: hasGlass ? blurSigma : 0.0),
      duration: const Duration(milliseconds: 240),
      curve: Curves.easeInOutCubic,
      builder: (context, blur, child) {
        if (blur <= 0.05) return child!;
        return ClipRRect(
          borderRadius: BorderRadius.circular(height / 2),
          child: BackdropFilter(
            filter: ui.ImageFilter.blur(sigmaX: blur, sigmaY: blur),
            child: child,
          ),
        );
      },
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 240),
        curve: Curves.easeInOutCubic,
        height: height,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(height / 2),
          boxShadow: effectiveShadow,
        ),
        child: Container(
          height: height,
          padding: const EdgeInsets.symmetric(horizontal: 4.0),
          decoration: BoxDecoration(
            color: effectiveBg,
            borderRadius: BorderRadius.circular(height / 2),
            border: Border.all(color: effectiveBorder, width: 1.2),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: actionItems,
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final canPop = ModalRoute.of(context)?.canPop ?? false;
    final hasLeft = leading != null || canPop;

    final targetBg = backgroundColor ??
        (isDark
            ? const Color(0xFF1C1C1E).withValues(alpha: 0.82)
            : const Color(0xFFF1F3F6).withValues(alpha: 0.82));

    final targetBorder = borderColor ??
        (isDark ? const Color(0x38545458) : const Color(0xFFE2E8F0));

    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        if (hasLeft) ...[
          _buildLeftPod(context, isDark, targetBg, targetBorder),
          const SizedBox(width: 8.0),
        ],
        Expanded(
          child: _buildCenterPod(context, isDark, targetBg, targetBorder),
        ),
        if (hasLeft || (actions != null && actions!.isNotEmpty)) ...[
          const SizedBox(width: 8.0),
          _buildRightPod(
            context,
            isDark,
            targetBg,
            targetBorder,
            hasLeft,
          ),
        ],
      ],
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. GLOBAL LIQUID GLASS SCAFFOLD (Telegram iOS 1:1 Master Shell for all Screens)
// ═══════════════════════════════════════════════════════════════════════════════

class VvcLiquidGlassScaffold extends StatefulWidget {
  final String? title;
  final Widget? titleWidget;
  final Widget? leading;
  final List<Widget>? actions;
  final Widget? customHeader;
  final Widget Function(BuildContext context, bool isScrolled)? customHeaderBuilder;
  final bool showHeader;
  final bool alwaysShowTitle;
  final bool alwaysShowGlass;

  final Widget body;

  final Widget? bottomNavigationBar;
  final Widget Function(BuildContext context, bool isScrolled)? bottomNavigationBarBuilder;
  final bool showTopTransitionZone;
  final bool showBottomTransitionZone;
  final Color? backgroundColor;
  final Color? transitionMaskColor;
  final ValueChanged<bool>? onScrollChanged;

  const VvcLiquidGlassScaffold({
    super.key,
    this.title,
    this.titleWidget,
    this.leading,
    this.actions,
    this.customHeader,
    this.customHeaderBuilder,
    this.showHeader = true,
    this.alwaysShowTitle = false,
    this.alwaysShowGlass = false,
    required this.body,
    this.bottomNavigationBar,
    this.bottomNavigationBarBuilder,
    this.showTopTransitionZone = true,
    this.showBottomTransitionZone = true,
    this.backgroundColor,
    this.transitionMaskColor,
    this.onScrollChanged,
  });

  @override
  State<VvcLiquidGlassScaffold> createState() => _VvcLiquidGlassScaffoldState();
}

class _VvcLiquidGlassScaffoldState extends State<VvcLiquidGlassScaffold> {
  bool _isScrolled = false;

  Widget _buildTopTransitionZone(BuildContext context, bool isDark) {
    final topInset = MediaQuery.paddingOf(context).top;
    final maskColor = widget.transitionMaskColor ??
        (isDark ? const Color(0xFF0F1115) : const Color(0xFFF8FAFC));
    final double zoneHeight = topInset + 72.0;

    return Positioned(
      left: 0,
      right: 0,
      top: 0,
      height: zoneHeight,
      child: IgnorePointer(
        child: AnimatedOpacity(
          duration: const Duration(milliseconds: 240),
          curve: Curves.easeInOutCubic,
          opacity: _isScrolled ? 0.92 : 0.0,
          child: Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topCenter,
                end: Alignment.bottomCenter,
                colors: [
                  maskColor.withValues(alpha: 0.98),
                  maskColor.withValues(alpha: 0.75),
                  maskColor.withValues(alpha: 0.30),
                  maskColor.withValues(alpha: 0.0),
                ],
                stops: const [0.0, 0.40, 0.75, 1.0],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildBottomTransitionZone(BuildContext context, bool isDark) {
    final bottomInset = MediaQuery.paddingOf(context).bottom;
    final maskColor = widget.transitionMaskColor ??
        (isDark ? const Color(0xFF0F1115) : const Color(0xFFF8FAFC));

    return Positioned(
      left: 0,
      right: 0,
      bottom: 0,
      height: 140.0 + bottomInset,
      child: IgnorePointer(
        child: AnimatedOpacity(
          duration: const Duration(milliseconds: 240),
          curve: Curves.easeInOutCubic,
          opacity: _isScrolled ? 0.92 : 0.0,
          child: Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topCenter,
                end: Alignment.bottomCenter,
                colors: [
                  maskColor.withValues(alpha: 0.0),
                  maskColor.withValues(alpha: 0.35),
                  maskColor.withValues(alpha: 0.75),
                  maskColor.withValues(alpha: 0.95),
                ],
                stops: const [0.0, 0.40, 0.80, 1.0],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildFloatingGlassHeader(BuildContext context, bool isDark) {
    final topInset = MediaQuery.paddingOf(context).top;

    return Positioned(
      top: topInset + 6.0,
      left: 14.0,
      right: 14.0,
      child: VvcFloatingHeaderPods(
        title: widget.title,
        titleWidget: widget.titleWidget,
        leading: widget.leading,
        actions: widget.actions,
        isScrolled: _isScrolled,
        alwaysShowTitle: widget.alwaysShowTitle,
        alwaysShowGlass: widget.alwaysShowGlass,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final bg = widget.backgroundColor ?? AppTheme.bgDark;

    // Resolve bottom nav with dynamic scroll state
    Widget? effectiveBottomNav;
    if (widget.bottomNavigationBarBuilder != null) {
      effectiveBottomNav = widget.bottomNavigationBarBuilder!(context, _isScrolled);
    } else if (widget.bottomNavigationBar != null) {
      if (widget.bottomNavigationBar is VvcLiquidGlassBottomBar) {
        effectiveBottomNav = (widget.bottomNavigationBar as VvcLiquidGlassBottomBar)
            .copyWith(isScrolled: _isScrolled);
      } else {
        effectiveBottomNav = widget.bottomNavigationBar;
      }
    }

    return AnnotatedRegion<SystemUiOverlayStyle>(
      value: SystemUiOverlayStyle(
        statusBarColor: Colors.transparent,
        statusBarBrightness: isDark ? Brightness.dark : Brightness.light,
        statusBarIconBrightness: isDark ? Brightness.light : Brightness.dark,
        systemNavigationBarColor: isDark ? const Color(0xFF000000) : Colors.white,
        systemNavigationBarIconBrightness: isDark ? Brightness.light : Brightness.dark,
      ),
      child: Scaffold(
        backgroundColor: bg,
        extendBodyBehindAppBar: true,
        extendBody: true,
        bottomNavigationBar: effectiveBottomNav,
        body: NotificationListener<ScrollNotification>(
          onNotification: (notification) {
            if (notification.metrics.axis == Axis.vertical) {
              final pixels = notification.metrics.pixels;
              // Strict positive pixel threshold prevents erratic flickering during iOS overscroll/bounce
              final scrolled = pixels > 6.0;
              if (scrolled != _isScrolled) {
                setState(() => _isScrolled = scrolled);
                widget.onScrollChanged?.call(scrolled);
              }
            }
            return false;
          },
          child: Stack(
            children: [
              // 1. Content Body
              widget.body,

              // 2. Localized Top Transition Zone (Animated Fade)
              if (widget.showTopTransitionZone && widget.showHeader)
                _buildTopTransitionZone(context, isDark),

              // 3. Floating Liquid Glass Header Dock (Telegram 1:1 Pods)
              if (widget.showHeader && widget.customHeader == null && widget.customHeaderBuilder == null)
                _buildFloatingGlassHeader(context, isDark),

              if (widget.customHeaderBuilder != null)
                widget.customHeaderBuilder!(context, _isScrolled),

              if (widget.customHeader != null)
                widget.customHeader!,

              // 4. Localized Bottom Transition Zone (Animated Fade)
              if (widget.showBottomTransitionZone && effectiveBottomNav != null)
                _buildBottomTransitionZone(context, isDark),
            ],
          ),
        ),
      ),
    );
  }
}
