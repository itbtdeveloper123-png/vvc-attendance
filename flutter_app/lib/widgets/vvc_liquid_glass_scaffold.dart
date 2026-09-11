import 'dart:ui' as ui;

import 'package:flutter/material.dart';
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
// 2. LIQUID GLASS FLOATING BOTTOM NAVIGATION BAR (Apple iOS Liquid Glass UI)
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
  });

  void _triggerHaptic() {
    HapticFeedback.lightImpact();
  }

  /// 1. Localized Bottom Edge Transition Zone (Clear -> Soft Fade -> Deep Fade Mask)
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
    );
  }

  /// 2. Floating Liquid Glass Dock Container (Apple iOS Liquid Glass Refraction & Caustics)
  Widget buildFloatingDock({required BuildContext context}) {
    final double bottomMargin = bottomInset > 0 ? bottomInset + 4.0 : 14.0;
    const primaryGold = Color(0xFFF3D010);
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final effectiveBorder = borderColor ??
        (isDark
            ? const Color(0xFF475569).withValues(alpha: 0.50)
            : const Color(0xFFCBD5E1).withValues(alpha: 0.65));

    return Container(
      margin: EdgeInsets.fromLTRB(16.0, 0, 16.0, bottomMargin),
      height: 64.0,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(36.0),
        boxShadow: [
          // A. Ambient Caustic Under-Glow (Liquid gold refraction)
          BoxShadow(
            color: primaryGold.withValues(alpha: isDark ? 0.16 : 0.10),
            blurRadius: 26.0,
            spreadRadius: -2.0,
            offset: const Offset(0, 6),
          ),
          // B. Deep Ambient Glass Drop Shadow
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.45 : 0.07),
            blurRadius: 20.0,
            offset: const Offset(0, 5),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(36.0),
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: blurSigma, sigmaY: blurSigma),
          child: Container(
            height: 64.0,
            padding: const EdgeInsets.symmetric(horizontal: 14.0),
            decoration: BoxDecoration(
              // Specular Top-Rim Light (Liquid Glass Highlight)
              gradient: LinearGradient(
                begin: const Alignment(-0.5, -1.0),
                end: const Alignment(0.5, 1.0),
                colors: isDark
                    ? [
                        Colors.white.withValues(alpha: 0.22),
                        const Color(0xFF1E293B).withValues(alpha: 0.82),
                        const Color(0xFF0F172A).withValues(alpha: 0.88),
                      ]
                    : [
                        Colors.white.withValues(alpha: 0.95),
                        const Color(0xFFF8FAFC).withValues(alpha: 0.88),
                        const Color(0xFFF1F5F9).withValues(alpha: 0.80),
                      ],
                stops: const [0.0, 0.25, 1.0],
              ),
              borderRadius: BorderRadius.circular(36.0),
              border: Border.all(
                color: effectiveBorder,
                width: 1.2,
              ),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceAround,
              children: List.generate(items.length, (index) {
                final item = items[index];
                final isSelected = index == currentIndex;
                return _buildDockItem(
                  context: context,
                  item: item,
                  isSelected: isSelected,
                  primaryGold: primaryGold,
                  onItemTap: () {
                    _triggerHaptic();
                    onTap(index);
                  },
                );
              }),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildDockItem({
    required BuildContext context,
    required LiquidGlassItem item,
    required bool isSelected,
    required Color primaryGold,
    required VoidCallback onItemTap,
  }) {
    final unselectedColor = unselectedItemColor ?? const Color(0xFF64748B);
    final iconData = (isSelected && item.selectedIcon != null)
        ? item.selectedIcon!
        : item.icon;

    // Center Item: Elevated Liquid Golden Droplet
    if (item.isCenter) {
      return GestureDetector(
        onTap: onItemTap,
        behavior: HitTestBehavior.opaque,
        child: Stack(
          clipBehavior: Clip.none,
          alignment: Alignment.center,
          children: [
            AnimatedContainer(
              duration: const Duration(milliseconds: 240),
              curve: Curves.easeOutBack,
              width: isSelected ? 48.0 : 42.0,
              height: isSelected ? 48.0 : 42.0,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: isSelected
                      ? const [Color(0xFFFDE047), Color(0xFFF3D010), Color(0xFFCA8A04)]
                      : [
                          primaryGold.withValues(alpha: 0.22),
                          primaryGold.withValues(alpha: 0.12),
                        ],
                  begin: const Alignment(-0.6, -1.0),
                  end: const Alignment(0.6, 1.0),
                ),
                shape: BoxShape.circle,
                border: Border.all(
                  color: isSelected
                      ? Colors.white.withValues(alpha: 0.90)
                      : primaryGold.withValues(alpha: 0.45),
                  width: 1.4,
                ),
                boxShadow: isSelected
                    ? [
                        BoxShadow(
                          color: primaryGold.withValues(alpha: 0.45),
                          blurRadius: 12.0,
                          offset: const Offset(0, 3),
                        ),
                      ]
                    : null,
              ),
              child: Center(
                child: Icon(
                  iconData,
                  color: isSelected ? Colors.white : const Color(0xFFB45309),
                  size: 24.0,
                ),
              ),
            ),
            if (item.badgeText != null && item.badgeText!.isNotEmpty)
              Positioned(
                top: -2.0,
                right: -4.0,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 5.0, vertical: 1.5),
                  decoration: BoxDecoration(
                    color: const Color(0xFFDC2626),
                    borderRadius: BorderRadius.circular(10.0),
                    border: Border.all(color: Colors.white, width: 1.2),
                  ),
                  child: Text(
                    item.badgeText!,
                    style: GoogleFonts.inter(
                      color: Colors.white,
                      fontSize: 9.0,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ),
          ],
        ),
      );
    }

    // Standard Tab Item: Liquid Spring Capsule
    return GestureDetector(
      onTap: onItemTap,
      behavior: HitTestBehavior.opaque,
      child: Stack(
        clipBehavior: Clip.none,
        alignment: Alignment.center,
        children: [
          AnimatedContainer(
            duration: const Duration(milliseconds: 240),
            curve: Curves.easeOutBack,
            width: isSelected ? 46.0 : 38.0,
            height: isSelected ? 46.0 : 38.0,
            decoration: BoxDecoration(
              gradient: isSelected
                  ? const LinearGradient(
                      colors: [Color(0xFFFDE047), Color(0xFFF3D010)],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    )
                  : null,
              shape: BoxShape.circle,
              border: isSelected
                  ? Border.all(color: Colors.white.withValues(alpha: 0.85), width: 1.2)
                  : null,
              boxShadow: isSelected
                  ? [
                      BoxShadow(
                        color: primaryGold.withValues(alpha: 0.38),
                        blurRadius: 10.0,
                        offset: const Offset(0, 2),
                      ),
                    ]
                  : null,
            ),
            child: Center(
              child: Icon(
                iconData,
                color: isSelected ? Colors.white : unselectedColor,
                size: 22.0,
              ),
            ),
          ),
          if (item.badgeText != null && item.badgeText!.isNotEmpty)
            Positioned(
              top: -3.0,
              right: -6.0,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 5.0, vertical: 1.5),
                decoration: BoxDecoration(
                  color: const Color(0xFFDC2626),
                  borderRadius: BorderRadius.circular(10.0),
                  border: Border.all(color: Colors.white, width: 1.2),
                ),
                child: Text(
                  item.badgeText!,
                  style: GoogleFonts.inter(
                    color: Colors.white,
                    fontSize: 9.0,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ),
        ],
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
// 3. GLOBAL LIQUID GLASS SCAFFOLD (Reusable Master Shell for all Screens)
// ═══════════════════════════════════════════════════════════════════════════════

class VvcLiquidGlassScaffold extends StatefulWidget {
  final String? title;
  final Widget? titleWidget;
  final Widget? leading;
  final List<Widget>? actions;
  final Widget? customHeader;
  final bool showHeader;

  final Widget body;

  final Widget? bottomNavigationBar;
  final bool showTopTransitionZone;
  final bool showBottomTransitionZone;
  final Color? backgroundColor;
  final Color? transitionMaskColor;

  const VvcLiquidGlassScaffold({
    super.key,
    this.title,
    this.titleWidget,
    this.leading,
    this.actions,
    this.customHeader,
    this.showHeader = true,
    required this.body,
    this.bottomNavigationBar,
    this.showTopTransitionZone = true,
    this.showBottomTransitionZone = true,
    this.backgroundColor,
    this.transitionMaskColor,
  });

  @override
  State<VvcLiquidGlassScaffold> createState() => _VvcLiquidGlassScaffoldState();
}

class _VvcLiquidGlassScaffoldState extends State<VvcLiquidGlassScaffold> {
  bool _isScrolled = false;

  Widget _buildGlassCircleButton({
    required VoidCallback? onTap,
    required Widget child,
    required bool isDark,
  }) {
    return GestureDetector(
      onTap: onTap,
      behavior: HitTestBehavior.opaque,
      child: Container(
        width: 38.0,
        height: 38.0,
        decoration: BoxDecoration(
          color: isDark
              ? const Color(0xFF1E293B).withValues(alpha: 0.85)
              : const Color(0xFFF8FAFC).withValues(alpha: 0.90),
          shape: BoxShape.circle,
          border: Border.all(
            color: isDark
                ? const Color(0xFF475569).withValues(alpha: 0.50)
                : const Color(0xFFCBD5E1).withValues(alpha: 0.60),
            width: 1.1,
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.25 : 0.04),
              blurRadius: 6.0,
              offset: const Offset(0, 1),
            ),
          ],
        ),
        child: Center(child: child),
      ),
    );
  }

  Widget _buildLeading(BuildContext context, bool isDark) {
    if (widget.leading != null) {
      if (widget.leading is IconButton) {
        final btn = widget.leading as IconButton;
        return _buildGlassCircleButton(
          onTap: btn.onPressed,
          child: btn.icon,
          isDark: isDark,
        );
      }
      return widget.leading!;
    }
    final canPop = ModalRoute.of(context)?.canPop ?? false;
    if (!canPop) return const SizedBox(width: 38.0);

    return _buildGlassCircleButton(
      onTap: () => Navigator.maybePop(context),
      child: Icon(
        Icons.arrow_back_ios_new_rounded,
        size: 15.0,
        color: AppTheme.textPrimary,
      ),
      isDark: isDark,
    );
  }

  Widget _buildTopTransitionZone(BuildContext context, bool isDark) {
    final topInset = MediaQuery.paddingOf(context).top;
    final maskColor = widget.transitionMaskColor ??
        (isDark ? const Color(0xFF0F1115) : const Color(0xFFF8FAFC));

    return Positioned(
      left: 0,
      right: 0,
      top: 0,
      height: topInset + 75.0,
      child: IgnorePointer(
        child: Container(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [
                maskColor.withValues(alpha: 0.95),
                maskColor.withValues(alpha: 0.70),
                maskColor.withValues(alpha: 0.25),
                maskColor.withValues(alpha: 0.0),
              ],
              stops: const [0.0, 0.45, 0.80, 1.0],
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
    );
  }

  Widget _buildFloatingGlassHeader(BuildContext context, bool isDark) {
    final topInset = MediaQuery.paddingOf(context).top;
    const primaryGold = Color(0xFFF3D010);

    final effectiveBorder = isDark
        ? (_isScrolled
            ? primaryGold.withValues(alpha: 0.50)
            : const Color(0xFF475569).withValues(alpha: 0.50))
        : (_isScrolled
            ? primaryGold.withValues(alpha: 0.65)
            : const Color(0xFFCBD5E1).withValues(alpha: 0.70));

    return Positioned(
      top: topInset + 6.0,
      left: 16.0,
      right: 16.0,
      child: Container(
        height: 58.0,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(32.0),
          boxShadow: [
            BoxShadow(
              color: primaryGold.withValues(alpha: _isScrolled ? 0.16 : 0.06),
              blurRadius: 18.0,
              spreadRadius: -2.0,
              offset: const Offset(0, 4),
            ),
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.40 : (_isScrolled ? 0.07 : 0.03)),
              blurRadius: 16.0,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(32.0),
          child: BackdropFilter(
            filter: ui.ImageFilter.blur(sigmaX: 25.0, sigmaY: 25.0),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 220),
              curve: Curves.easeOutCubic,
              height: 58.0,
              padding: const EdgeInsets.symmetric(horizontal: 10.0),
              decoration: BoxDecoration(
                // Liquid Glass Specular Rim Highlight
                gradient: LinearGradient(
                  begin: const Alignment(-0.5, -1.0),
                  end: const Alignment(0.5, 1.0),
                  colors: isDark
                      ? [
                          Colors.white.withValues(alpha: 0.20),
                          const Color(0xFF1E293B).withValues(alpha: _isScrolled ? 0.88 : 0.78),
                          const Color(0xFF0F172A).withValues(alpha: _isScrolled ? 0.85 : 0.75),
                        ]
                      : [
                          Colors.white.withValues(alpha: 0.95),
                          const Color(0xFFF8FAFC).withValues(alpha: _isScrolled ? 0.92 : 0.82),
                          const Color(0xFFF1F5F9).withValues(alpha: _isScrolled ? 0.86 : 0.76),
                        ],
                  stops: const [0.0, 0.30, 1.0],
                ),
                borderRadius: BorderRadius.circular(32.0),
                border: Border.all(
                  color: effectiveBorder,
                  width: 1.2,
                ),
              ),
              child: Row(
                children: [
                  _buildLeading(context, isDark),
                  Expanded(
                    child: Center(
                      child: widget.titleWidget ??
                          Text(
                            widget.title ?? '',
                            style: GoogleFonts.kantumruyPro(
                              fontWeight: FontWeight.bold,
                              fontSize: 16.5,
                              color: AppTheme.textPrimary,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                    ),
                  ),
                  if (widget.actions != null && widget.actions!.isNotEmpty)
                    Row(mainAxisSize: MainAxisSize.min, children: widget.actions!)
                  else
                    const SizedBox(width: 38.0),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final bg = widget.backgroundColor ?? AppTheme.bgDark;

    return AnnotatedRegion<SystemUiOverlayStyle>(
      value: SystemUiOverlayStyle(
        statusBarColor: Colors.transparent,
        statusBarBrightness: isDark ? Brightness.dark : Brightness.light,
        statusBarIconBrightness: isDark ? Brightness.light : Brightness.dark,
        systemNavigationBarColor: isDark ? const Color(0xFF0F1115) : Colors.white,
        systemNavigationBarIconBrightness: isDark ? Brightness.light : Brightness.dark,
      ),
      child: Scaffold(
        backgroundColor: bg,
        extendBodyBehindAppBar: true,
        extendBody: true,
        bottomNavigationBar: widget.bottomNavigationBar,
        body: NotificationListener<ScrollNotification>(
          onNotification: (notification) {
            if (notification.metrics.axis == Axis.vertical) {
              final scrolled = notification.metrics.pixels > 6.0;
              if (scrolled != _isScrolled) {
                setState(() => _isScrolled = scrolled);
              }
            }
            return false;
          },
          child: Stack(
            children: [
              // 1. Content Body
              widget.body,

              // 2. Localized Top Transition Zone
              if (widget.showTopTransitionZone && widget.showHeader)
                _buildTopTransitionZone(context, isDark),

              // 3. Floating Liquid Glass Header Dock
              if (widget.showHeader && widget.customHeader == null)
                _buildFloatingGlassHeader(context, isDark),

              if (widget.customHeader != null)
                widget.customHeader!,

              // 4. Localized Bottom Transition Zone
              if (widget.showBottomTransitionZone && widget.bottomNavigationBar != null)
                _buildBottomTransitionZone(context, isDark),
            ],
          ),
        ),
      ),
    );
  }
}
