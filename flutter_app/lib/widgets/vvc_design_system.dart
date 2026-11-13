import 'dart:ui' as ui;
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'telegram_bounce.dart';
import 'vvc_lottie.dart';
export 'vvc_lottie.dart';

/// ═══════════════════════════════════════════════════════════════════════════════
/// VVC UNIFIED DESIGN SYSTEM (DESIGN TOKENS & ATOMIC COMPONENTS)
/// ═══════════════════════════════════════════════════════════════════════════════
/// ស្តង់ដារួមតែមួយគត់សម្រាប់កម្មវិធី VVC Attendance ទាំងមូល។
/// កម្ចាត់ចោលបញ្ហា UI Fragmentation, ប៊ូតុងត្រប៉ែត (oval stretch), និងខុសរង្វង់។
/// ផ្តល់ជូននូវ Telegram Spring Physics, Apple Cupertino Glassmorphism,
/// និង Atomic Components ដែលមានភាពស៊ីមេទ្រី 100% គ្រប់ Screen ទាំងអស់។

// ─────────────────────────────────────────────────────────────────────────────
// 1. DESIGN TOKENS
// ─────────────────────────────────────────────────────────────────────────────
class AppTokens {
  // --- Corner Radii ---
  /// Capsule / Stadium (Buttons, Search Bars, Filter Chips, Badges)
  static const double radiusPill = 999.0;

  /// Bento Cards, BottomSheets, Large Panels, Dialogs
  static const double radiusCard = 22.0;

  /// Sub-cards, List Tiles, Inner Sections
  static const double radiusInner = 14.0;

  /// Small Badges, Counter Tags, Indicators
  static const double radiusSmall = 10.0;

  // --- Heights ---
  /// Check-in, Submit, Hero CTA
  static const double heightHeroBtn = 52.0;

  /// Dialog buttons, Action CTAs, Header pods
  static const double heightStandardBtn = 44.0;

  /// Scan Login, Copy Code, Secondary actions
  static const double heightCompactBtn = 38.0;

  /// Mini tags, table actions
  static const double heightMiniBtn = 30.0;

  /// Universal Search Bar height
  static const double heightSearch = 42.0;

  /// Filter / Category Pill height
  static const double heightFilterChip = 36.0;

  /// Header Bar total action height
  static const double heightHeaderAction = 44.0;

  // --- Action Pod Sizes (Circle 1:1) ---
  /// Large Circular Pod (Notification & Telegram standard)
  static const double sizePodLarge = 44.0;

  /// Standard Circular Pod (Authenticator & Compact AppBar standard)
  static const double sizePodStandard = 38.0;

  /// Mini Circular Pod
  static const double sizePodMini = 32.0;

  // --- Signature Colors ---
  static const Color gold = Color(0xFFF3D010);
  static const Color goldDark = Color(0xFFE5BF00);
  static const Color goldSoft = Color(0xFFFFE566);
  static const Color goldGlow = Color(0x59F3D010); // alpha: 0.35

  static const Color accentBlue = Color(0xFF007AFF);
  static const Color accentBlueSky = Color(0xFF38BDFC);
  static const Color accentBlueDeep = Color(0xFF1D4ED8);

  static const Color emeraldGreen = Color(0xFF10B981);
  static const Color destructiveRed = Color(0xFFEF4444);
  static const Color warningOrange = Color(0xFFF59E0B);

  // --- Surfaces & Glass (Dark & Light) ---
  static const Color bgDark = Color(0xFF000000);
  static const Color bgDarkSecondary = Color(0xFF0C0E12);
  static const Color bgLight = Color(0xFFF8FAFC);

  static const Color surfaceDark = Color(0xFF161920);
  static const Color surfaceLight = Colors.white;

  static const Color podBgDark = Color(0xFF1C2028);
  static const Color podBorderDark = Color(0xFF333A48);

  static const Color podBgLight = Colors.white;
  static const Color podBorderLight = Color(0xFFE2E8F0);

  static const Color chipInactiveDark = Color(0xFF1E222B);
  static const Color chipInactiveBorderDark = Color(0xFF333A48);

  // --- Haptic Helpers ---
  static void hapticLight() => HapticFeedback.lightImpact();
  static void hapticMedium() => HapticFeedback.mediumImpact();
  static void hapticSelection() => HapticFeedback.selectionClick();
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. VVC CIRCLE POD (UNIVERSAL 1:1 CIRCULAR ACTION POD)
// ─────────────────────────────────────────────────────────────────────────────
/// ប៊ូតុងរង្វង់មូល 1:1 ពិតប្រាកដ (ទំហំ width == height, shape: BoxShape.circle)
/// ធានាថាមិនត្រប៉ែត ឬ stretch ជាពងក្រពើបញ្ឈរពេលដាក់ក្នុង AppBar។
/// គាំទ្រ Double-ring Style (ចិញ្ចៀនក្រៅ Dark Glass + ចិញ្ចៀនក្នុងពណ៌ Accent ដូចប៊ូតុង +)។
class VvcCirclePod extends StatelessWidget {
  final IconData? icon;
  final Widget? child;
  final double size;
  final VoidCallback? onTap;
  final Color? backgroundColor;
  final Color? borderColor;
  final Color? iconColor;
  final double? iconSize;
  final bool isFrosted;
  final Color? innerAccentColor; // បើកំណត់ នឹងបង្កើតជា Double-ring ដូចប៊ូតុង +
  final int? badgeCount;
  final bool showBadgeDot;
  final String? tooltip;

  const VvcCirclePod({
    super.key,
    this.icon,
    this.child,
    this.size = AppTokens.sizePodStandard,
    this.onTap,
    this.backgroundColor,
    this.borderColor,
    this.iconColor,
    this.iconSize,
    this.isFrosted = false,
    this.innerAccentColor,
    this.badgeCount,
    this.showBadgeDot = false,
    this.tooltip,
  });

  /// Factory សម្រាប់ Back Button ស្តង់ដារ (<)
  factory VvcCirclePod.back(
    BuildContext context, {
    double size = AppTokens.sizePodStandard,
    VoidCallback? onBack,
  }) {
    return VvcCirclePod(
      size: size,
      icon: CupertinoIcons.chevron_back,
      iconSize: size * 0.44,
      onTap: onBack ?? () {
        AppTokens.hapticLight();
        Navigator.maybePop(context);
      },
    );
  }

  /// Factory សម្រាប់ Plus Button (+) ដូច Telegram/iOS
  factory VvcCirclePod.plus({
    double size = AppTokens.sizePodStandard,
    VoidCallback? onTap,
    Color? iconColor,
  }) {
    return VvcCirclePod(
      size: size,
      icon: CupertinoIcons.add,
      iconColor: iconColor,
      iconSize: size * 0.48,
      onTap: onTap,
    );
  }

  /// Factory សម្រាប់ Refresh Button (↻)
  factory VvcCirclePod.refresh({
    double size = AppTokens.sizePodLarge,
    VoidCallback? onRefresh,
  }) {
    return VvcCirclePod(
      size: size,
      icon: CupertinoIcons.arrow_clockwise,
      iconSize: size * 0.44,
      onTap: onRefresh,
    );
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final bg = backgroundColor ??
        (isDark ? AppTokens.podBgDark : AppTokens.podBgLight);
    final border = borderColor ??
        (isDark ? AppTokens.podBorderDark : AppTokens.podBorderLight);
    final iColor = iconColor ??
        (isDark ? Colors.white : const Color(0xFF0F172A));
    final effectiveIconSize = iconSize ?? (size * 0.44);

    Widget coreContent;
    if (innerAccentColor != null) {
      final innerSize = size * 0.63;
      coreContent = Container(
        width: innerSize,
        height: innerSize,
        decoration: BoxDecoration(
          color: innerAccentColor,
          shape: BoxShape.circle,
        ),
        child: Center(
          child: Icon(
            icon,
            color: iconColor ?? Colors.white,
            size: effectiveIconSize,
          ),
        ),
      );
    } else if (child != null) {
      coreContent = child!;
    } else {
      coreContent = Icon(
        icon,
        color: iColor,
        size: effectiveIconSize,
      );
    }

    Widget podBody = Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: bg,
        shape: BoxShape.circle,
        border: Border.all(color: border, width: 1.1),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.30 : 0.05),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Center(child: coreContent),
    );

    if (isFrosted) {
      podBody = ClipOval(
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: 16, sigmaY: 16),
          child: podBody,
        ),
      );
    }

    // Badge indicator if needed
    if ((badgeCount != null && badgeCount! > 0) || showBadgeDot) {
      podBody = Stack(
        clipBehavior: Clip.none,
        children: [
          podBody,
          Positioned(
            top: -2,
            right: -2,
            child: showBadgeDot
                ? Container(
                    width: 10,
                    height: 10,
                    decoration: BoxDecoration(
                      color: AppTokens.destructiveRed,
                      shape: BoxShape.circle,
                      border: Border.all(
                        color: isDark ? Colors.black : Colors.white,
                        width: 1.5,
                      ),
                    ),
                  )
                : Container(
                    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1.5),
                    decoration: BoxDecoration(
                      color: AppTokens.destructiveRed,
                      borderRadius: BorderRadius.circular(AppTokens.radiusPill),
                      border: Border.all(
                        color: isDark ? Colors.black : Colors.white,
                        width: 1.5,
                      ),
                    ),
                    child: Text(
                      badgeCount! > 99 ? '99+' : '$badgeCount',
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 9,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
          ),
        ],
      );
    }

    // Wrapped in Center() so Flex/AppBar does not stretch it into an oval!
    Widget result = Center(
      child: TelegramBounce(
        scaleFactor: 0.90,
        onTap: () {
          if (onTap != null) {
            AppTokens.hapticLight();
            onTap!();
          }
        },
        child: podBody,
      ),
    );

    if (tooltip != null && tooltip!.isNotEmpty) {
      result = Tooltip(message: tooltip!, child: result);
    }

    return result;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. VVC PILL BUTTON (UNIVERSAL FULL CAPSULE BUTTON)
// ─────────────────────────────────────────────────────────────────────────────
enum VvcPillVariant { gold, blue, glass, danger, outline }
enum VvcButtonSize { hero, standard, compact, mini }

/// Universal Capsule Stadium Button
/// មាន spring bounce, smooth gradient/solid, និង radiusPill (100% capsule) ស្វ័យប្រវត្តិ។
class VvcPillButton extends StatelessWidget {
  final String? text;
  final IconData? icon;
  final IconData? trailingIcon;
  final Widget? child;
  final VoidCallback? onTap;
  final VvcPillVariant variant;
  final VvcButtonSize size;
  final bool isLoading;
  final bool isFullWidth;
  final EdgeInsetsGeometry? padding;
  final Color? customColor;
  final Color? customTextColor;

  const VvcPillButton({
    super.key,
    this.text,
    this.icon,
    this.trailingIcon,
    this.child,
    this.onTap,
    this.variant = VvcPillVariant.gold,
    this.size = VvcButtonSize.standard,
    this.isLoading = false,
    this.isFullWidth = false,
    this.padding,
    this.customColor,
    this.customTextColor,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    // Dimensions
    double height;
    double fontSize;
    double iconSize;
    EdgeInsets defaultPadding;

    switch (size) {
      case VvcButtonSize.hero:
        height = AppTokens.heightHeroBtn;
        fontSize = 15.0;
        iconSize = 20.0;
        defaultPadding = const EdgeInsets.symmetric(horizontal: 22);
        break;
      case VvcButtonSize.standard:
        height = AppTokens.heightStandardBtn;
        fontSize = 14.0;
        iconSize = 18.0;
        defaultPadding = const EdgeInsets.symmetric(horizontal: 18);
        break;
      case VvcButtonSize.compact:
        height = AppTokens.heightCompactBtn;
        fontSize = 13.0;
        iconSize = 16.0;
        defaultPadding = const EdgeInsets.symmetric(horizontal: 14);
        break;
      case VvcButtonSize.mini:
        height = AppTokens.heightMiniBtn;
        fontSize = 11.5;
        iconSize = 14.0;
        defaultPadding = const EdgeInsets.symmetric(horizontal: 10);
        break;
    }

    // Styling based on variant
    BoxDecoration decoration;
    Color contentColor;

    switch (variant) {
      case VvcPillVariant.gold:
        contentColor = customTextColor ?? const Color(0xFF0F172A);
        decoration = BoxDecoration(
          gradient: const LinearGradient(
            colors: [AppTokens.gold, AppTokens.goldDark],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.circular(AppTokens.radiusPill),
          boxShadow: [
            BoxShadow(
              color: AppTokens.gold.withValues(alpha: 0.35),
              blurRadius: 10,
              offset: const Offset(0, 3),
            ),
          ],
        );
        break;

      case VvcPillVariant.blue:
        contentColor = customTextColor ?? Colors.white;
        decoration = BoxDecoration(
          gradient: const LinearGradient(
            colors: [Color(0xFF2563EB), Color(0xFF1D4ED8)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.circular(AppTokens.radiusPill),
          boxShadow: [
            BoxShadow(
              color: const Color(0xFF2563EB).withValues(alpha: 0.35),
              blurRadius: 10,
              offset: const Offset(0, 3),
            ),
          ],
        );
        break;

      case VvcPillVariant.glass:
        contentColor = customTextColor ?? (isDark ? Colors.white : const Color(0xFF0F172A));
        decoration = BoxDecoration(
          color: customColor ?? (isDark ? AppTokens.chipInactiveDark : Colors.white),
          borderRadius: BorderRadius.circular(AppTokens.radiusPill),
          border: Border.all(
            color: isDark ? AppTokens.podBorderDark : AppTokens.podBorderLight,
            width: 1.0,
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.25 : 0.04),
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
        );
        break;

      case VvcPillVariant.danger:
        contentColor = customTextColor ?? Colors.white;
        decoration = BoxDecoration(
          gradient: const LinearGradient(
            colors: [Color(0xFFEF4444), Color(0xFFDC2626)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.circular(AppTokens.radiusPill),
          boxShadow: [
            BoxShadow(
              color: AppTokens.destructiveRed.withValues(alpha: 0.35),
              blurRadius: 10,
              offset: const Offset(0, 3),
            ),
          ],
        );
        break;

      case VvcPillVariant.outline:
        contentColor = customTextColor ?? (isDark ? AppTokens.gold : const Color(0xFFB45309));
        decoration = BoxDecoration(
          color: Colors.transparent,
          borderRadius: BorderRadius.circular(AppTokens.radiusPill),
          border: Border.all(
            color: customColor ?? (isDark ? AppTokens.gold : const Color(0xFFB45309)),
            width: 1.2,
          ),
        );
        break;
    }

    Widget inner;
    if (isLoading) {
      inner = SizedBox(
        width: iconSize,
        height: iconSize,
        child: CircularProgressIndicator(
          strokeWidth: 2,
          color: contentColor,
        ),
      );
    } else if (child != null) {
      inner = child!;
    } else {
      inner = Row(
        mainAxisSize: isFullWidth ? MainAxisSize.max : MainAxisSize.min,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          if (icon != null) ...[
            Icon(icon, size: iconSize, color: contentColor),
            if (text != null && text!.isNotEmpty) const SizedBox(width: 7),
          ],
          if (text != null && text!.isNotEmpty)
            Flexible(
              child: Text(
                text!,
                style: GoogleFonts.kantumruyPro(
                  fontSize: fontSize,
                  fontWeight: FontWeight.w700,
                  color: contentColor,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          if (trailingIcon != null) ...[
            if (text != null && text!.isNotEmpty) const SizedBox(width: 7),
            Icon(trailingIcon, size: iconSize, color: contentColor),
          ],
        ],
      );
    }

    return TelegramBounce(
      scaleFactor: 0.95,
      onTap: isLoading ? null : () {
        if (onTap != null) {
          AppTokens.hapticLight();
          onTap!();
        }
      },
      child: Container(
        height: height,
        width: isFullWidth ? double.infinity : null,
        padding: padding ?? defaultPadding,
        decoration: decoration,
        alignment: Alignment.center,
        child: inner,
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. VVC FILTER CHIPS (TELEGRAM-GRADE CATEGORY TABS)
// ─────────────────────────────────────────────────────────────────────────────
class VvcFilterItem {
  final String key;
  final String label;
  final int? count;
  final IconData? icon;

  const VvcFilterItem({
    required this.key,
    required this.label,
    this.count,
    this.icon,
  });
}

/// Telegram-style Category Pills Bar
/// Active: Solid Gold `#F3D010` + Black Text + Subtle Glow
/// Inactive: Dark Glass `#1E222B` + Subtle Border
class VvcFilterChips extends StatelessWidget {
  final List<VvcFilterItem> items;
  final String selectedKey;
  final ValueChanged<String> onSelected;
  final EdgeInsetsGeometry padding;

  const VvcFilterChips({
    super.key,
    required this.items,
    required this.selectedKey,
    required this.onSelected,
    this.padding = const EdgeInsets.symmetric(horizontal: 14),
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      physics: const BouncingScrollPhysics(),
      padding: padding,
      child: Row(
        children: items.map((item) {
          final isSelected = item.key == selectedKey;

          final unselectedBg = isDark
              ? AppTokens.chipInactiveDark
              : Colors.white.withValues(alpha: 0.85);
          final unselectedBorder = isDark
              ? AppTokens.chipInactiveBorderDark
              : AppTokens.podBorderLight;

          return Padding(
            padding: const EdgeInsets.only(right: 8),
            child: TelegramBounce(
              scaleFactor: 0.94,
              onTap: () {
                AppTokens.hapticLight();
                onSelected(item.key);
              },
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                curve: Curves.easeOutCubic,
                height: AppTokens.heightFilterChip,
                padding: const EdgeInsets.symmetric(horizontal: 14),
                decoration: BoxDecoration(
                  color: isSelected ? AppTokens.gold : unselectedBg,
                  borderRadius: BorderRadius.circular(AppTokens.radiusPill),
                  border: Border.all(
                    color: isSelected ? AppTokens.gold : unselectedBorder,
                    width: 1.0,
                  ),
                  boxShadow: isSelected
                      ? [
                          BoxShadow(
                            color: AppTokens.gold.withValues(alpha: 0.35),
                            blurRadius: 10,
                            offset: const Offset(0, 3),
                          ),
                        ]
                      : null,
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    if (item.icon != null) ...[
                      Icon(
                        item.icon,
                        size: 15,
                        color: isSelected
                            ? const Color(0xFF0F172A)
                            : (isDark ? Colors.white70 : const Color(0xFF64748B)),
                      ),
                      const SizedBox(width: 6),
                    ],
                    Text(
                      item.label,
                      style: GoogleFonts.kantumruyPro(
                        color: isSelected
                            ? const Color(0xFF0F172A)
                            : (isDark ? Colors.white.withValues(alpha: 0.75) : const Color(0xFF475569)),
                        fontSize: 13,
                        fontWeight: isSelected ? FontWeight.bold : FontWeight.w600,
                      ),
                    ),
                    if (item.count != null) ...[
                      const SizedBox(width: 6),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: isSelected
                              ? Colors.black.withValues(alpha: 0.12)
                              : (isDark ? Colors.white.withValues(alpha: 0.10) : Colors.black.withValues(alpha: 0.06)),
                          borderRadius: BorderRadius.circular(AppTokens.radiusPill),
                        ),
                        child: Text(
                          '${item.count}',
                          style: GoogleFonts.inter(
                            color: isSelected
                                ? const Color(0xFF0F172A)
                                : (isDark ? Colors.white.withValues(alpha: 0.75) : const Color(0xFF64748B)),
                            fontSize: 11,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          );
        }).toList(),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. VVC HEADER POD BAR (UNIFIED 3-ISLAND HEADER)
// ─────────────────────────────────────────────────────────────────────────────
/// Header Bar ដែលមាន Left Pod, Center Capsule, និង Right Actions Pods
/// ផ្តល់ភាពស្អាតដូចគ្នា ១០០% លើគ្រប់ Screen ទាំងអស់។
class VvcHeaderPodBar extends StatelessWidget implements PreferredSizeWidget {
  final Widget? leading;
  final String? title;
  final Widget? titleWidget;
  final String? subtitle;
  final int? counterBadge;
  final List<Widget>? actions;
  final bool isScrolled;
  final EdgeInsetsGeometry padding;

  const VvcHeaderPodBar({
    super.key,
    this.leading,
    this.title,
    this.titleWidget,
    this.subtitle,
    this.counterBadge,
    this.actions,
    this.isScrolled = false,
    this.padding = const EdgeInsets.symmetric(horizontal: 14),
  });

  @override
  Size get preferredSize => const Size.fromHeight(56.0);

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final podBg = isDark
        ? (isScrolled
            ? const Color(0xFF24272E).withValues(alpha: 0.94)
            : const Color(0xFF1C1C1E).withValues(alpha: 0.70))
        : (isScrolled
            ? Colors.white.withValues(alpha: 0.94)
            : Colors.white.withValues(alpha: 0.85));

    final podBorder = isDark
        ? (isScrolled
            ? Colors.white.withValues(alpha: 0.22)
            : Colors.white.withValues(alpha: 0.10))
        : (isScrolled
            ? Colors.black.withValues(alpha: 0.12)
            : Colors.black.withValues(alpha: 0.06));

    final textPrimary = isDark ? Colors.white : const Color(0xFF0F172A);

    return Padding(
      padding: padding,
      child: Row(
        children: [
          // 1. Left Pod
          leading ?? VvcCirclePod.back(context, size: AppTokens.sizePodLarge),
          const SizedBox(width: 10),

          // 2. Center Capsule
          Expanded(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(AppTokens.radiusPill),
              child: BackdropFilter(
                filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 250),
                  curve: Curves.easeInOutCubic,
                  height: AppTokens.heightHeaderAction,
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  decoration: BoxDecoration(
                    color: podBg,
                    borderRadius: BorderRadius.circular(AppTokens.radiusPill),
                    border: Border.all(color: podBorder, width: 1.0),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(
                          alpha: isScrolled ? (isDark ? 0.55 : 0.08) : (isDark ? 0.15 : 0.03),
                        ),
                        blurRadius: isScrolled ? 16 : 4,
                        offset: Offset(0, isScrolled ? 4 : 2),
                      ),
                    ],
                  ),
                  child: titleWidget ??
                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          if (title != null)
                            Flexible(
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                crossAxisAlignment: subtitle != null
                                    ? CrossAxisAlignment.start
                                    : CrossAxisAlignment.center,
                                children: [
                                  Text(
                                    title!,
                                    style: GoogleFonts.kantumruyPro(
                                      color: textPrimary,
                                      fontSize: 15,
                                      fontWeight: FontWeight.bold,
                                    ),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                  if (subtitle != null)
                                    Text(
                                      subtitle!,
                                      style: GoogleFonts.inter(
                                        color: isDark ? Colors.white54 : const Color(0xFF64748B),
                                        fontSize: 10,
                                        fontWeight: FontWeight.w600,
                                      ),
                                      maxLines: 1,
                                    ),
                                ],
                              ),
                            ),
                          if (counterBadge != null) ...[
                            const SizedBox(width: 8),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2.5),
                              decoration: BoxDecoration(
                                color: counterBadge! > 0
                                    ? AppTokens.gold.withValues(alpha: isDark ? 0.22 : 0.25)
                                    : (isDark
                                        ? Colors.white.withValues(alpha: 0.12)
                                        : Colors.black.withValues(alpha: 0.06)),
                                borderRadius: BorderRadius.circular(AppTokens.radiusPill),
                                border: counterBadge! > 0
                                    ? Border.all(
                                        color: AppTokens.gold.withValues(alpha: 0.5),
                                        width: 0.8,
                                      )
                                    : null,
                              ),
                              child: Text(
                                '$counterBadge',
                                style: GoogleFonts.inter(
                                  color: counterBadge! > 0
                                      ? (isDark ? AppTokens.gold : const Color(0xFFB45309))
                                      : (isDark ? Colors.white70 : const Color(0xFF64748B)),
                                  fontSize: 11,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                          ],
                        ],
                      ),
                ),
              ),
            ),
          ),

          // 3. Right Action Pods
          if (actions != null && actions!.isNotEmpty) ...[
            const SizedBox(width: 10),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: actions!.map((action) {
                return Padding(
                  padding: const EdgeInsets.only(left: 8.0),
                  child: action,
                );
              }).toList(),
            ),
          ],
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. VVC SEARCH BAR (UNIVERSAL FULL CAPSULE SEARCH)
// ─────────────────────────────────────────────────────────────────────────────
class VvcSearchBar extends StatelessWidget {
  final TextEditingController controller;
  final ValueChanged<String>? onChanged;
  final VoidCallback? onClear;
  final String hintText;
  final bool isScrolled;
  final EdgeInsetsGeometry padding;

  const VvcSearchBar({
    super.key,
    required this.controller,
    this.onChanged,
    this.onClear,
    this.hintText = 'ស្វែងរក...',
    this.isScrolled = false,
    this.padding = const EdgeInsets.symmetric(horizontal: 14),
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final searchBg = isDark
        ? (isScrolled
            ? const Color(0xFF24272E).withValues(alpha: 0.92)
            : const Color(0xFF1C1C1E).withValues(alpha: 0.65))
        : (isScrolled
            ? Colors.white.withValues(alpha: 0.94)
            : Colors.white.withValues(alpha: 0.85));

    final searchBorder = isDark
        ? (isScrolled
            ? Colors.white.withValues(alpha: 0.20)
            : Colors.white.withValues(alpha: 0.08))
        : (isScrolled
            ? Colors.black.withValues(alpha: 0.12)
            : Colors.black.withValues(alpha: 0.06));

    final textPrimary = isDark ? Colors.white : const Color(0xFF0F172A);
    final textMuted = isDark ? Colors.white.withValues(alpha: 0.45) : const Color(0xFF94A3B8);

    return Padding(
      padding: padding,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(AppTokens.radiusPill),
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 250),
            curve: Curves.easeInOutCubic,
            height: AppTokens.heightSearch,
            decoration: BoxDecoration(
              color: searchBg,
              borderRadius: BorderRadius.circular(AppTokens.radiusPill),
              border: Border.all(color: searchBorder, width: 1.0),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(
                    alpha: isScrolled ? (isDark ? 0.45 : 0.06) : (isDark ? 0.10 : 0.02),
                  ),
                  blurRadius: isScrolled ? 14 : 4,
                  offset: Offset(0, isScrolled ? 4 : 1),
                ),
              ],
            ),
            child: Row(
              children: [
                const SizedBox(width: 14),
                Icon(CupertinoIcons.search, color: textMuted, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: TextField(
                    controller: controller,
                    onChanged: onChanged,
                    style: GoogleFonts.kantumruyPro(
                      color: textPrimary,
                      fontSize: 13.5,
                    ),
                    cursorColor: AppTokens.gold,
                    decoration: InputDecoration(
                      filled: false,
                      fillColor: Colors.transparent,
                      hintText: hintText,
                      hintStyle: GoogleFonts.kantumruyPro(
                        color: textMuted,
                        fontSize: 13,
                      ),
                      border: InputBorder.none,
                      enabledBorder: InputBorder.none,
                      focusedBorder: InputBorder.none,
                      disabledBorder: InputBorder.none,
                      errorBorder: InputBorder.none,
                      focusedErrorBorder: InputBorder.none,
                      isDense: true,
                      contentPadding: const EdgeInsets.symmetric(vertical: 10),
                    ),
                  ),
                ),
                if (controller.text.isNotEmpty)
                  GestureDetector(
                    onTap: () {
                      AppTokens.hapticLight();
                      controller.clear();
                      if (onClear != null) onClear!();
                    },
                    child: Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 10),
                      child: Icon(
                        CupertinoIcons.clear_circled_solid,
                        color: textMuted,
                        size: 16,
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. VVC EMPTY STATE (STANDARDIZED FROSTED CHAMBER)
// ─────────────────────────────────────────────────────────────────────────────
class VvcEmptyState extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final String? buttonLabel;
  final IconData? buttonIcon;
  final VoidCallback? onButtonTap;
  final double topPadding;
  final bool useLottie;
  final String? lottieAsset;

  const VvcEmptyState({
    super.key,
    this.icon = CupertinoIcons.tray,
    required this.title,
    required this.subtitle,
    this.buttonLabel,
    this.buttonIcon,
    this.onButtonTap,
    this.topPadding = 0,
    this.useLottie = true,
    this.lottieAsset,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return SingleChildScrollView(
      physics: const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics()),
      padding: EdgeInsets.only(
        top: topPadding + 28,
        bottom: 40,
        left: 24,
        right: 24,
      ),
      child: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Animation or Circular Chamber
            if (useLottie)
              VvcLottie(
                assetPath: lottieAsset ?? 'assets/lottie/empty.json',
                width: 120,
                height: 120,
                repeat: true,
                fallback: _buildIconChamber(isDark),
              )
            else
              _buildIconChamber(isDark),
            const SizedBox(height: 20),

            // Title
            Text(
              title,
              style: GoogleFonts.kantumruyPro(
                color: isDark ? Colors.white : const Color(0xFF0F172A),
                fontSize: 16.5,
                fontWeight: FontWeight.bold,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),

            // Subtitle
            Text(
              subtitle,
              style: GoogleFonts.kantumruyPro(
                color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
                fontSize: 13,
                height: 1.4,
              ),
              textAlign: TextAlign.center,
            ),

            // Optional Capsule Action Button
            if (buttonLabel != null && onButtonTap != null) ...[
              const SizedBox(height: 24),
              VvcPillButton(
                text: buttonLabel,
                icon: buttonIcon,
                variant: VvcPillVariant.gold,
                size: VvcButtonSize.standard,
                onTap: onButtonTap,
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildIconChamber(bool isDark) {
    return Container(
      width: 84,
      height: 84,
      decoration: BoxDecoration(
        color: isDark ? AppTokens.chipInactiveDark : const Color(0xFFF1F5F9),
        shape: BoxShape.circle,
        border: Border.all(
          color: isDark ? AppTokens.podBorderDark : AppTokens.podBorderLight,
          width: 1.2,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.05),
            blurRadius: 16,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Center(
        child: Icon(
          icon,
          size: 38,
          color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
        ),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. VVC BENTO CARD (UNIVERSAL SQUIRCLE CARD)
// ─────────────────────────────────────────────────────────────────────────────
class VvcBentoCard extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry padding;
  final EdgeInsetsGeometry? margin;
  final VoidCallback? onTap;
  final Color? backgroundColor;
  final Color? borderColor;
  final double radius;

  const VvcBentoCard({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(16),
    this.margin,
    this.onTap,
    this.backgroundColor,
    this.borderColor,
    this.radius = AppTokens.radiusCard,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final bg = backgroundColor ??
        (isDark ? AppTokens.surfaceDark : AppTokens.surfaceLight);
    final border = borderColor ??
        (isDark ? Colors.white.withValues(alpha: 0.08) : const Color(0xFFE2E8F0));

    Widget card = Container(
      margin: margin,
      padding: padding,
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(radius),
        border: Border.all(color: border, width: 0.9),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.04),
            blurRadius: 14,
            offset: const Offset(0, 3),
          ),
        ],
      ),
      child: child,
    );

    if (onTap != null) {
      card = TelegramBounce(
        scaleFactor: 0.97,
        onTap: () {
          AppTokens.hapticLight();
          onTap!();
        },
        child: card,
      );
    }

    return card;
  }
}

