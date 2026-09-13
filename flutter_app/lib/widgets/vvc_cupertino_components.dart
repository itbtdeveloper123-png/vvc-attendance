import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../utils/app_theme.dart';

/// ═══════════════════════════════════════════════════════════════════════════════
/// APPLE CUPERTINO COLOR TOKENS
/// ═══════════════════════════════════════════════════════════════════════════════
class CupertinoTokens {
  static const Color appleBlue = Color(0xFF0A84FF);
  static const Color appleBlueLight = Color(0xFF007AFF);
  static const Color appleDestructiveRed = Color(0xFFFF453A);
  
  // Neutral Track Fills
  static const Color trackLight = Color(0xFFEBEBF0);
  static const Color trackDark = Color(0xFF2C2C2E);
  static const Color trackDarkSubtle = Color(0x38545458);

  // Surface Card Fills
  static const Color cardLight = Colors.white;
  static const Color cardDark = Color(0xFF1C1C1E);
  static const Color cardDarkSecondary = Color(0xFF2C2C2E);

  // Hairline Dividers
  static const Color dividerLight = Color(0x1F000000);
  static const Color dividerDark = Color(0x28FFFFFF);

  // Text Colors
  static const Color textPrimaryLight = Color(0xFF000000);
  static const Color textPrimaryDark = Colors.white;
  static const Color textSecondaryLight = Color(0xFF6E6E73);
  static const Color textSecondaryDark = Color(0xFF8E8E93);
}

/// ═══════════════════════════════════════════════════════════════════════════════
/// 1. VVC POPUP MENU BUTTON (Apple Context Menu & 3-Dots Pod)
/// ═══════════════════════════════════════════════════════════════════════════════
/// តំណាងឱ្យរូបភាពទី ១៖ ប៊ូតុងរង្វង់ 3-Dots អណ្តែត ពេលចុចចេញ Popup Menu រាងមូលស្អាត
/// មាន SF Symbol Icons, Divider កាត់ខណ្ឌ និង Destructive Style។

class VvcPopupMenuItem<T> {
  final T value;
  final String title;
  final IconData? icon;
  final bool isDestructive;
  final bool isDividerAfter;
  final VoidCallback? onTap;

  const VvcPopupMenuItem({
    required this.value,
    required this.title,
    this.icon,
    this.isDestructive = false,
    this.isDividerAfter = false,
    this.onTap,
  });
}

class VvcPopupMenuButton<T> extends StatefulWidget {
  final List<VvcPopupMenuItem<T>> items;
  final ValueChanged<T>? onSelected;
  final Widget? customTrigger;
  final double size;
  final Color? triggerColor;
  final Color? triggerIconColor;
  final String? tooltip;

  const VvcPopupMenuButton({
    super.key,
    required this.items,
    this.onSelected,
    this.customTrigger,
    this.size = 44.0,
    this.triggerColor,
    this.triggerIconColor,
    this.tooltip,
  });

  @override
  State<VvcPopupMenuButton<T>> createState() => _VvcPopupMenuButtonState<T>();
}

class _VvcPopupMenuButtonState<T> extends State<VvcPopupMenuButton<T>> {
  bool _isPressed = false;

  void _showCupertinoMenu() async {
    HapticFeedback.lightImpact();
    final RenderBox renderBox = context.findRenderObject() as RenderBox;
    final offset = renderBox.localToGlobal(Offset.zero);
    final size = renderBox.size;
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;

    final selected = await showGeneralDialog<T>(
      context: context,
      barrierDismissible: true,
      barrierLabel: 'Dismiss',
      barrierColor: Colors.black.withValues(alpha: 0.18),
      transitionDuration: const Duration(milliseconds: 200),
      pageBuilder: (ctx, anim1, anim2) {
        return _VvcCupertinoPopupOverlay<T>(
          items: widget.items,
          triggerRect: Rect.fromLTWH(offset.dx, offset.dy, size.width, size.height),
          isDark: isDark,
        );
      },
      transitionBuilder: (ctx, anim, secondaryAnim, child) {
        final curveAnim = CurvedAnimation(parent: anim, curve: Curves.easeOutCubic);
        return ScaleTransition(
          scale: Tween<double>(begin: 0.92, end: 1.0).animate(curveAnim),
          alignment: Alignment.topRight,
          child: FadeTransition(opacity: curveAnim, child: child),
        );
      },
    );

    if (selected != null && widget.onSelected != null) {
      widget.onSelected!(selected);
    }
  }

  @override
  Widget build(BuildContext context) {
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;

    if (widget.customTrigger != null) {
      return GestureDetector(
        onTap: _showCupertinoMenu,
        child: widget.customTrigger!,
      );
    }

    final podBg = widget.triggerColor ??
        (isDark ? const Color(0xFF1C1C1E) : Colors.white);
    final iconColor = widget.triggerIconColor ??
        (isDark ? Colors.white : const Color(0xFF1C1C1E));

    return AnimatedScale(
      scale: _isPressed ? 0.92 : 1.0,
      duration: const Duration(milliseconds: 120),
      child: GestureDetector(
        onTapDown: (_) => setState(() => _isPressed = true),
        onTapUp: (_) => setState(() => _isPressed = false),
        onTapCancel: () => setState(() => _isPressed = false),
        onTap: _showCupertinoMenu,
        child: Container(
          width: widget.size,
          height: widget.size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: podBg,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.08),
                blurRadius: 16,
                offset: const Offset(0, 4),
              ),
              if (isDark)
                BoxShadow(
                  color: Colors.white.withValues(alpha: 0.06),
                  blurRadius: 1,
                  offset: const Offset(0, -0.5),
                ),
            ],
            border: Border.all(
              color: isDark
                  ? Colors.white.withValues(alpha: 0.12)
                  : Colors.black.withValues(alpha: 0.04),
              width: 0.8,
            ),
          ),
          child: Center(
            child: Icon(
              CupertinoIcons.ellipsis,
              size: 20,
              color: iconColor,
            ),
          ),
        ),
      ),
    );
  }
}

class _VvcCupertinoPopupOverlay<T> extends StatelessWidget {
  final List<VvcPopupMenuItem<T>> items;
  final Rect triggerRect;
  final bool isDark;

  const _VvcCupertinoPopupOverlay({
    required this.items,
    required this.triggerRect,
    required this.isDark,
  });

  @override
  Widget build(BuildContext context) {
    final screenSize = MediaQuery.of(context).size;
    const menuWidth = 240.0;

    // Calculate left/top position relative to trigger
    double left = triggerRect.right - menuWidth;
    if (left < 16) left = 16;
    if (left + menuWidth > screenSize.width - 16) {
      left = screenSize.width - menuWidth - 16;
    }

    double top = triggerRect.bottom + 8;
    if (top + (items.length * 48) > screenSize.height - 40) {
      top = triggerRect.top - (items.length * 48) - 16;
    }

    final cardBg = isDark
        ? const Color(0xFF1C1C1E).withValues(alpha: 0.92)
        : Colors.white.withValues(alpha: 0.95);

    return Stack(
      children: [
        Positioned(
          left: left,
          top: top,
          child: Material(
            color: Colors.transparent,
            child: Container(
              width: menuWidth,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(20),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: isDark ? 0.5 : 0.12),
                    blurRadius: 30,
                    offset: const Offset(0, 12),
                  ),
                ],
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(20),
                child: BackdropFilter(
                  filter: ui.ImageFilter.blur(sigmaX: 25, sigmaY: 25),
                  child: Container(
                    decoration: BoxDecoration(
                      color: cardBg,
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(
                        color: isDark
                            ? Colors.white.withValues(alpha: 0.12)
                            : Colors.black.withValues(alpha: 0.05),
                        width: 0.8,
                      ),
                    ),
                    padding: const EdgeInsets.symmetric(vertical: 6),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: items.map((item) {
                        return _buildMenuItem(context, item);
                      }).toList(),
                    ),
                  ),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildMenuItem(BuildContext context, VvcPopupMenuItem<T> item) {
    final itemColor = item.isDestructive
        ? (isDark ? CupertinoTokens.appleDestructiveRed : const Color(0xFF6E6E73))
        : (isDark ? Colors.white : const Color(0xFF1C1C1E));

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        InkWell(
          onTap: () {
            HapticFeedback.lightImpact();
            Navigator.of(context).pop(item.value);
            if (item.onTap != null) item.onTap!();
          },
          highlightColor: isDark
              ? Colors.white.withValues(alpha: 0.08)
              : Colors.black.withValues(alpha: 0.04),
          splashColor: Colors.transparent,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            child: Row(
              children: [
                if (item.icon != null) ...[
                  Icon(
                    item.icon,
                    size: 20,
                    color: itemColor,
                  ),
                  const SizedBox(width: 14),
                ],
                Expanded(
                  child: Text(
                    item.title,
                    style: GoogleFonts.kantumruyPro(
                      color: itemColor,
                      fontSize: 15,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
        if (item.isDividerAfter)
          Divider(
            height: 1,
            thickness: 0.6,
            color: isDark ? CupertinoTokens.dividerDark : CupertinoTokens.dividerLight,
            indent: 14,
            endIndent: 14,
          ),
      ],
    );
  }
}

/// ═══════════════════════════════════════════════════════════════════════════════
/// 2. VVC SEGMENTED CONTROL (Apple Sliding Capsule Pill)
/// ═══════════════════════════════════════════════════════════════════════════════
/// តំណាងឱ្យរូបភាពទី ២៖ Capsule Segmented Control មាន Track ប្រផេះស្រាល និង Sliding Pill
/// រាងពងក្រពើសសុទ្ធ ជាមួយ Ambient Shadow រត់រអិលដោយ Smooth Animation។

class VvcSegmentedControl<T> extends StatelessWidget {
  final List<T> items;
  final T selectedValue;
  final ValueChanged<T> onValueChanged;
  final String Function(T) itemTitle;
  final IconData Function(T)? itemIcon;
  final double height;
  final EdgeInsetsGeometry margin;

  const VvcSegmentedControl({
    super.key,
    required this.items,
    required this.selectedValue,
    required this.onValueChanged,
    required this.itemTitle,
    this.itemIcon,
    this.height = 42.0,
    this.margin = EdgeInsets.zero,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;
    final selectedIndex = items.indexOf(selectedValue);

    final trackBg = isDark
        ? const Color(0xFF1C1C1E)
        : const Color(0xFFEBEBF0);

    return Container(
      height: height,
      margin: margin,
      padding: const EdgeInsets.all(3.0),
      decoration: BoxDecoration(
        color: trackBg,
        borderRadius: BorderRadius.circular(height / 2),
        border: Border.all(
          color: isDark
              ? Colors.white.withValues(alpha: 0.08)
              : Colors.black.withValues(alpha: 0.03),
          width: 0.8,
        ),
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final tabWidth = constraints.maxWidth / items.length;

          return Stack(
            children: [
              // Smooth Sliding Active White/Dark Pill Indicator
              AnimatedPositioned(
                duration: const Duration(milliseconds: 240),
                curve: Curves.easeInOutCubic,
                left: (selectedIndex >= 0 ? selectedIndex : 0) * tabWidth,
                top: 0,
                bottom: 0,
                width: tabWidth,
                child: Container(
                  decoration: BoxDecoration(
                    color: isDark ? const Color(0xFF3A3A3C) : Colors.white,
                    borderRadius: BorderRadius.circular((height - 6) / 2),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.08),
                        blurRadius: 5,
                        offset: const Offset(0, 2),
                      ),
                      if (!isDark)
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.04),
                          blurRadius: 1,
                          offset: const Offset(0, 1),
                        ),
                    ],
                  ),
                ),
              ),

              // Segment Items Row
              Row(
                children: items.map((item) {
                  final isSelected = item == selectedValue;
                  final title = itemTitle(item);
                  final icon = itemIcon != null ? itemIcon!(item) : null;

                  final textColor = isSelected
                      ? (isDark ? Colors.white : CupertinoTokens.textPrimaryLight)
                      : (isDark
                          ? CupertinoTokens.textSecondaryDark
                          : CupertinoTokens.textSecondaryLight);

                  return Expanded(
                    child: GestureDetector(
                      behavior: HitTestBehavior.opaque,
                      onTap: () {
                        if (!isSelected) {
                          HapticFeedback.selectionClick();
                          onValueChanged(item);
                        }
                      },
                      child: Center(
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            if (icon != null) ...[
                              Icon(icon, size: 16, color: textColor),
                              const SizedBox(width: 6),
                            ],
                            Text(
                              title,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: GoogleFonts.kantumruyPro(
                                fontSize: 14,
                                fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
                                color: textColor,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  );
                }).toList(),
              ),
            ],
          );
        },
      ),
    );
  }
}

/// ═══════════════════════════════════════════════════════════════════════════════
/// 3. VVC SWITCH & VVC SWITCH TILE (Apple Cupertino Switch)
/// ═══════════════════════════════════════════════════════════════════════════════
/// តំណាងឱ្យរូបភាពទី ៣៖ Cupertino Switch ពណ៌ Apple Blue #0A84FF ពេល ON,
/// ពណ៌ប្រផេះពេល OFF, ជាមួយ Knob មូលសសុទ្ធរលោង និង Row Tile ដូច "Basic ON"។

class VvcSwitch extends StatelessWidget {
  final bool value;
  final ValueChanged<bool>? onChanged;
  final Color? activeColor;
  final Color? trackColor;

  const VvcSwitch({
    super.key,
    required this.value,
    required this.onChanged,
    this.activeColor,
    this.trackColor,
  });

  @override
  Widget build(BuildContext context) {
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;
    final onColor = activeColor ?? CupertinoTokens.appleBlue;
    final offColor = trackColor ??
        (isDark ? const Color(0xFF39393D) : const Color(0xFFE9E9EA));

    const width = 51.0;
    const height = 31.0;
    const thumbSize = 27.0;

    return GestureDetector(
      onTap: onChanged != null
          ? () {
              HapticFeedback.lightImpact();
              onChanged!(!value);
            }
          : null,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        curve: Curves.easeInOut,
        width: width,
        height: height,
        padding: const EdgeInsets.all(2.0),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(height / 2),
          color: value ? onColor : offColor,
        ),
        child: AnimatedAlign(
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeInOut,
          alignment: value ? Alignment.centerRight : Alignment.centerLeft,
          child: Container(
            width: thumbSize,
            height: thumbSize,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: Colors.white,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.18),
                  blurRadius: 4,
                  offset: const Offset(0, 2),
                ),
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.06),
                  blurRadius: 1,
                  offset: const Offset(0, 1),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// A clean list tile matching Image 3 (e.g. "Basic ON" with trailing Cupertino switch)
class VvcSwitchTile extends StatelessWidget {
  final String title;
  final String? subtitle;
  final Widget? leading;
  final bool value;
  final ValueChanged<bool>? onChanged;
  final Color? activeColor;
  final EdgeInsetsGeometry padding;

  const VvcSwitchTile({
    super.key,
    required this.title,
    this.subtitle,
    this.leading,
    required this.value,
    required this.onChanged,
    this.activeColor,
    this.padding = const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
  });

  @override
  Widget build(BuildContext context) {
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;

    return Padding(
      padding: padding,
      child: Row(
        children: [
          if (leading != null) ...[
            leading!,
            const SizedBox(width: 14),
          ],
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  title,
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 16,
                    fontWeight: FontWeight.w500,
                    color: isDark ? Colors.white : CupertinoTokens.textPrimaryLight,
                  ),
                ),
                if (subtitle != null) ...[
                  const SizedBox(height: 2),
                  Text(
                    subtitle!,
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 13,
                      color: isDark
                          ? CupertinoTokens.textSecondaryDark
                          : CupertinoTokens.textSecondaryLight,
                    ),
                  ),
                ],
              ],
            ),
          ),
          VvcSwitch(
            value: value,
            onChanged: onChanged,
            activeColor: activeColor,
          ),
        ],
      ),
    );
  }
}

/// ═══════════════════════════════════════════════════════════════════════════════
/// 4. VVC SLIDER (Apple Cupertino Slider)
/// ═══════════════════════════════════════════════════════════════════════════════
/// តំណាងឱ្យរូបភាពទី ៤៖ Cupertino Slider Track ស្ដើងប្រណិត (Height 4.5px)
/// ផ្នែក Active ពណ៌ Apple Blue #0A84FF, Thumb សរលោង (28px) ជាមួយ Ambient Drop Shadow។

class VvcSlider extends StatefulWidget {
  final double value;
  final ValueChanged<double>? onChanged;
  final ValueChanged<double>? onChangeEnd;
  final double min;
  final double max;
  final int? divisions;
  final Color? activeColor;
  final Color? inactiveColor;

  const VvcSlider({
    super.key,
    required this.value,
    required this.onChanged,
    this.onChangeEnd,
    this.min = 0.0,
    this.max = 1.0,
    this.divisions,
    this.activeColor,
    this.inactiveColor,
  });

  @override
  State<VvcSlider> createState() => _VvcSliderState();
}

class _VvcSliderState extends State<VvcSlider> {
  double? _dragValue;

  double get _currentValue => _dragValue ?? widget.value;

  void _handleDragUpdate(double localDx, double trackWidth) {
    if (widget.onChanged == null) return;
    final clampedDx = localDx.clamp(0.0, trackWidth);
    final ratio = clampedDx / trackWidth;
    var newValue = widget.min + ratio * (widget.max - widget.min);

    if (widget.divisions != null && widget.divisions! > 0) {
      final step = (widget.max - widget.min) / widget.divisions!;
      newValue = (newValue / step).round() * step;
    }

    newValue = newValue.clamp(widget.min, widget.max);
    if (_dragValue != newValue) {
      HapticFeedback.selectionClick();
      setState(() => _dragValue = newValue);
      widget.onChanged!(newValue);
    }
  }

  @override
  Widget build(BuildContext context) {
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;
    final activeCol = widget.activeColor ?? CupertinoTokens.appleBlue;
    final inactiveCol = widget.inactiveColor ??
        (isDark ? const Color(0xFF38383A) : const Color(0xFFE5E5EA));

    const thumbSize = 28.0;
    const trackHeight = 4.5;

    return LayoutBuilder(
      builder: (context, constraints) {
        final availableWidth = constraints.maxWidth;
        final trackWidth = availableWidth - thumbSize;
        final progress = ((_currentValue - widget.min) / (widget.max - widget.min))
            .clamp(0.0, 1.0);

        return GestureDetector(
          behavior: HitTestBehavior.opaque,
          onHorizontalDragStart: (details) {
            _handleDragUpdate(details.localPosition.dx - (thumbSize / 2), trackWidth);
          },
          onHorizontalDragUpdate: (details) {
            _handleDragUpdate(details.localPosition.dx - (thumbSize / 2), trackWidth);
          },
          onHorizontalDragEnd: (details) {
            if (_dragValue != null && widget.onChangeEnd != null) {
              widget.onChangeEnd!(_dragValue!);
            }
            setState(() => _dragValue = null);
          },
          onTapDown: (details) {
            _handleDragUpdate(details.localPosition.dx - (thumbSize / 2), trackWidth);
            if (widget.onChangeEnd != null) {
              widget.onChangeEnd!(_currentValue);
            }
          },
          child: SizedBox(
            height: 44, // Generous touch target
            width: availableWidth,
            child: Stack(
              alignment: Alignment.centerLeft,
              children: [
                // Inactive Background Track
                Container(
                  margin: const EdgeInsets.symmetric(horizontal: thumbSize / 2),
                  height: trackHeight,
                  width: trackWidth,
                  decoration: BoxDecoration(
                    color: inactiveCol,
                    borderRadius: BorderRadius.circular(trackHeight / 2),
                  ),
                ),

                // Active Vibrant Blue Track
                Container(
                  margin: const EdgeInsets.only(left: thumbSize / 2),
                  height: trackHeight,
                  width: (trackWidth * progress).clamp(0.0, trackWidth),
                  decoration: BoxDecoration(
                    color: activeCol,
                    borderRadius: BorderRadius.circular(trackHeight / 2),
                  ),
                ),

                // Apple Cupertino Thumb
                Positioned(
                  left: trackWidth * progress,
                  child: Container(
                    width: thumbSize,
                    height: thumbSize,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: Colors.white,
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.16),
                          blurRadius: 8,
                          offset: const Offset(0, 3),
                        ),
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.08),
                          blurRadius: 2,
                          offset: const Offset(0, 1),
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}

/// ═══════════════════════════════════════════════════════════════════════════════
/// 5. VVC BUTTON & ICON BUTTON SUITE (Apple iOS 15+ Button Styles)
/// ═══════════════════════════════════════════════════════════════════════════════
/// តំណាងឱ្យរូបភាពទី ៥៖ Button Styles គ្រប់ជម្រើស៖
/// [Plain, Gray, Tinted, Bordered, BorderedProminent, Filled, Glass, ProminentGlass, Disabled]
/// ព្រមទាំង VvcIconButton (Circular Icon Buttons) ដូចរូបបេះដូង។

enum VvcButtonVariant {
  plain,
  gray,
  tinted,
  bordered,
  borderedProminent,
  filled,
  glass,
  prominentGlass,
  disabled,
}

class VvcButton extends StatefulWidget {
  final VoidCallback? onPressed;
  final String? label;
  final IconData? icon;
  final Widget? child;
  final VvcButtonVariant variant;
  final Color? customColor;
  final double height;
  final EdgeInsetsGeometry? padding;
  final bool isLoading;

  const VvcButton({
    super.key,
    required this.onPressed,
    this.label,
    this.icon,
    this.child,
    this.variant = VvcButtonVariant.filled,
    this.customColor,
    this.height = 40.0,
    this.padding,
    this.isLoading = false,
  });

  @override
  State<VvcButton> createState() => _VvcButtonState();
}

class _VvcButtonState extends State<VvcButton> {
  bool _isPressed = false;

  @override
  Widget build(BuildContext context) {
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;
    final blueColor = widget.customColor ?? CupertinoTokens.appleBlue;
    final isDisabled = widget.variant == VvcButtonVariant.disabled || widget.onPressed == null;

    Color bgColor = Colors.transparent;
    Color fgColor = blueColor;
    Border? border;
    List<BoxShadow>? shadows;
    bool isGlass = false;

    switch (widget.variant) {
      case VvcButtonVariant.plain:
        bgColor = Colors.transparent;
        fgColor = blueColor;
        break;

      case VvcButtonVariant.gray:
        bgColor = isDark ? const Color(0x33767680) : const Color(0xFFE5E5EA);
        fgColor = blueColor;
        break;

      case VvcButtonVariant.tinted:
        bgColor = blueColor.withValues(alpha: isDark ? 0.22 : 0.14);
        fgColor = blueColor;
        break;

      case VvcButtonVariant.bordered:
        bgColor = isDark ? const Color(0x1F767680) : const Color(0xFFF2F2F7);
        fgColor = blueColor;
        border = Border.all(
          color: isDark ? Colors.white.withValues(alpha: 0.15) : Colors.black.withValues(alpha: 0.08),
          width: 0.9,
        );
        break;

      case VvcButtonVariant.borderedProminent:
        bgColor = blueColor;
        fgColor = Colors.white;
        border = Border.all(
          color: Colors.white.withValues(alpha: 0.35),
          width: 1.2,
        );
        shadows = [
          BoxShadow(
            color: blueColor.withValues(alpha: 0.35),
            blurRadius: 10,
            offset: const Offset(0, 3),
          ),
        ];
        break;

      case VvcButtonVariant.filled:
        bgColor = blueColor;
        fgColor = Colors.white;
        shadows = [
          BoxShadow(
            color: blueColor.withValues(alpha: 0.32),
            blurRadius: 8,
            offset: const Offset(0, 3),
          ),
        ];
        break;

      case VvcButtonVariant.glass:
        isGlass = true;
        bgColor = isDark
            ? Colors.white.withValues(alpha: 0.10)
            : Colors.white.withValues(alpha: 0.85);
        fgColor = blueColor;
        border = Border.all(
          color: isDark
              ? Colors.white.withValues(alpha: 0.16)
              : Colors.black.withValues(alpha: 0.06),
          width: 0.8,
        );
        shadows = [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.06),
            blurRadius: 12,
            offset: const Offset(0, 3),
          ),
        ];
        break;

      case VvcButtonVariant.prominentGlass:
        isGlass = true;
        bgColor = blueColor.withValues(alpha: 0.38);
        fgColor = Colors.white;
        border = Border.all(
          color: Colors.white.withValues(alpha: 0.4),
          width: 1.0,
        );
        shadows = [
          BoxShadow(
            color: blueColor.withValues(alpha: 0.35),
            blurRadius: 14,
            offset: const Offset(0, 4),
          ),
        ];
        break;

      case VvcButtonVariant.disabled:
        bgColor = isDark ? const Color(0x18767680) : const Color(0xFFF2F2F7);
        fgColor = isDark ? const Color(0xFF636366) : const Color(0xFFA0A0A5);
        break;
    }

    Widget content = widget.isLoading
        ? SizedBox(
            width: 18,
            height: 18,
            child: CircularProgressIndicator(
              strokeWidth: 2.2,
              valueColor: AlwaysStoppedAnimation<Color>(fgColor),
            ),
          )
        : widget.child ??
            Row(
              mainAxisSize: MainAxisSize.min,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                if (widget.icon != null) ...[
                  Icon(widget.icon, size: 17, color: fgColor),
                  const SizedBox(width: 7),
                ],
                if (widget.label != null)
                  Text(
                    widget.label!,
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                      color: fgColor,
                    ),
                  ),
              ],
            );

    Widget buttonBox = Container(
      height: widget.height,
      padding: widget.padding ?? const EdgeInsets.symmetric(horizontal: 16),
      decoration: BoxDecoration(
        color: bgColor,
        borderRadius: BorderRadius.circular(widget.height / 2),
        border: border,
        boxShadow: shadows,
      ),
      child: Center(child: content),
    );

    if (isGlass) {
      buttonBox = ClipRRect(
        borderRadius: BorderRadius.circular(widget.height / 2),
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: 12, sigmaY: 12),
          child: buttonBox,
        ),
      );
    }

    return AnimatedScale(
      scale: _isPressed && !isDisabled ? 0.95 : 1.0,
      duration: const Duration(milliseconds: 110),
      curve: Curves.easeOutCubic,
      child: GestureDetector(
        onTapDown: (_) {
          if (!isDisabled && !widget.isLoading) {
            setState(() => _isPressed = true);
          }
        },
        onTapUp: (_) {
          if (_isPressed) setState(() => _isPressed = false);
        },
        onTapCancel: () {
          if (_isPressed) setState(() => _isPressed = false);
        },
        onTap: () {
          if (!isDisabled && !widget.isLoading && widget.onPressed != null) {
            HapticFeedback.lightImpact();
            widget.onPressed!();
          }
        },
        child: buttonBox,
      ),
    );
  }
}

/// Circular Icon Button matching the Heart buttons in Image 5
class VvcIconButton extends StatefulWidget {
  final VoidCallback? onPressed;
  final IconData icon;
  final VvcButtonVariant variant;
  final Color? customColor;
  final Color? iconColor;
  final double size;
  final String? tooltip;

  const VvcIconButton({
    super.key,
    required this.onPressed,
    required this.icon,
    this.variant = VvcButtonVariant.filled,
    this.customColor,
    this.iconColor,
    this.size = 44.0,
    this.tooltip,
  });

  @override
  State<VvcIconButton> createState() => _VvcIconButtonState();
}

class _VvcIconButtonState extends State<VvcIconButton> {
  bool _isPressed = false;

  @override
  Widget build(BuildContext context) {
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;
    final blueColor = widget.customColor ?? CupertinoTokens.appleBlue;
    final isDisabled = widget.variant == VvcButtonVariant.disabled || widget.onPressed == null;

    Color bgColor = Colors.transparent;
    Color fgColor = widget.iconColor ?? blueColor;
    Border? border;
    List<BoxShadow>? shadows;
    bool isGlass = false;

    switch (widget.variant) {
      case VvcButtonVariant.plain:
        bgColor = Colors.transparent;
        fgColor = widget.iconColor ?? blueColor;
        break;

      case VvcButtonVariant.gray:
        bgColor = isDark ? const Color(0x33767680) : const Color(0xFFE5E5EA);
        fgColor = widget.iconColor ?? blueColor;
        break;

      case VvcButtonVariant.tinted:
        bgColor = blueColor.withValues(alpha: isDark ? 0.24 : 0.16);
        fgColor = widget.iconColor ?? blueColor;
        break;

      case VvcButtonVariant.bordered:
        bgColor = isDark ? const Color(0x1F767680) : const Color(0xFFF2F2F7);
        fgColor = widget.iconColor ?? blueColor;
        border = Border.all(
          color: isDark ? Colors.white.withValues(alpha: 0.16) : Colors.black.withValues(alpha: 0.08),
          width: 0.9,
        );
        break;

      case VvcButtonVariant.borderedProminent:
      case VvcButtonVariant.filled:
        bgColor = blueColor;
        fgColor = widget.iconColor ?? Colors.white;
        shadows = [
          BoxShadow(
            color: blueColor.withValues(alpha: 0.32),
            blurRadius: 8,
            offset: const Offset(0, 3),
          ),
        ];
        break;

      case VvcButtonVariant.glass:
        isGlass = true;
        bgColor = isDark
            ? Colors.white.withValues(alpha: 0.10)
            : Colors.white.withValues(alpha: 0.85);
        fgColor = widget.iconColor ?? blueColor;
        border = Border.all(
          color: isDark
              ? Colors.white.withValues(alpha: 0.16)
              : Colors.black.withValues(alpha: 0.08),
          width: 0.8,
        );
        shadows = [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.06),
            blurRadius: 10,
            offset: const Offset(0, 2),
          ),
        ];
        break;

      case VvcButtonVariant.prominentGlass:
        isGlass = true;
        bgColor = blueColor.withValues(alpha: 0.40);
        fgColor = widget.iconColor ?? Colors.white;
        border = Border.all(
          color: Colors.white.withValues(alpha: 0.4),
          width: 1.0,
        );
        shadows = [
          BoxShadow(
            color: blueColor.withValues(alpha: 0.38),
            blurRadius: 12,
            offset: const Offset(0, 3),
          ),
        ];
        break;

      case VvcButtonVariant.disabled:
        bgColor = isDark ? const Color(0x18767680) : const Color(0xFFF2F2F7);
        fgColor = isDark ? const Color(0xFF636366) : const Color(0xFFA0A0A5);
        break;
    }

    Widget buttonBox = Container(
      width: widget.size,
      height: widget.size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: bgColor,
        border: border,
        boxShadow: shadows,
      ),
      child: Center(
        child: Icon(
          widget.icon,
          size: widget.size * 0.45,
          color: fgColor,
        ),
      ),
    );

    if (isGlass) {
      buttonBox = ClipOval(
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: 12, sigmaY: 12),
          child: buttonBox,
        ),
      );
    }

    return AnimatedScale(
      scale: _isPressed && !isDisabled ? 0.92 : 1.0,
      duration: const Duration(milliseconds: 110),
      curve: Curves.easeOutCubic,
      child: GestureDetector(
        onTapDown: (_) {
          if (!isDisabled) setState(() => _isPressed = true);
        },
        onTapUp: (_) {
          if (_isPressed) setState(() => _isPressed = false);
        },
        onTapCancel: () {
          if (_isPressed) setState(() => _isPressed = false);
        },
        onTap: () {
          if (!isDisabled && widget.onPressed != null) {
            HapticFeedback.lightImpact();
            widget.onPressed!();
          }
        },
        child: widget.tooltip != null
            ? Tooltip(message: widget.tooltip!, child: buttonBox)
            : buttonBox,
      ),
    );
  }
}
