import 'package:flutter/material.dart';

/// ═══════════════════════════════════════════════════════════════════════════
/// AppPalette — ប្រភពពណ៌តែមួយគត់ (Single Source of Truth) សម្រាប់ Light/Dark
/// ═══════════════════════════════════════════════════════════════════════════
///
/// ច្បាប់៖
/// - Background / Surface / Text / Border → ប្រើតែ Token ខាងក្រោម (កុំ hardcode)
/// - ពណ៌ Brand (Gold, SK Amber, Success, Danger...) → រក្សាដដែល មិនប្តូរតាម Mode
///
/// ប្រើ៖ `context.palette.surface`, `context.isDark`
@immutable
class AppPalette extends ThemeExtension<AppPalette> {
  final Color bg;
  final Color surface;
  final Color surfaceAlt;
  final Color surfaceElevated;
  final Color border;
  final Color divider;
  final Color text;
  final Color textSecondary;
  final Color textMuted;
  final Color overlay;
  final Color shadow;
  final bool isDark;

  const AppPalette({
    required this.bg,
    required this.surface,
    required this.surfaceAlt,
    required this.surfaceElevated,
    required this.border,
    required this.divider,
    required this.text,
    required this.textSecondary,
    required this.textMuted,
    required this.overlay,
    required this.shadow,
    required this.isDark,
  });

  // Aliases for compatibility
  Color get background => bg;
  Color get card => surface;
  Color get cardSurface => surfaceAlt;
  Color get cardBorder => border;
  Color get textPrimary => text;

  // ── LIGHT (Clean White) ───────────────────────────────────────────────────
  static const AppPalette light = AppPalette(
    bg: Color(0xFFF8FAFC),
    surface: Color(0xFFFFFFFF),
    surfaceAlt: Color(0xFFF1F5F9),
    surfaceElevated: Color(0xFFFFFFFF),
    border: Color(0xFFE2E8F0),
    divider: Color(0xFFEEF2F6),
    text: Color(0xFF0F172A),
    textSecondary: Color(0xFF475569),
    textMuted: Color(0xFF64748B),
    overlay: Color(0x66000000),
    shadow: Color(0x140F172A),
    isDark: false,
  );

  // ── LIGHT SK (Warm Gold Tint) ─────────────────────────────────────────────
  static const AppPalette lightSk = AppPalette(
    bg: Color(0xFFF7F1E4),
    surface: Color(0xFFFFFDF8),
    surfaceAlt: Color(0xFFF3EBDA),
    surfaceElevated: Color(0xFFFFFFFF),
    border: Color(0xFFE8DCC2),
    divider: Color(0xFFEFE6D3),
    text: Color(0xFF292524),
    textSecondary: Color(0xFF57534E),
    textMuted: Color(0xFF78716C),
    overlay: Color(0x66000000),
    shadow: Color(0x14292524),
    isDark: false,
  );

  // ── DARK (Apple iOS Native — Pure Black OLED) ─────────────────────────────
  static const AppPalette dark = AppPalette(
    bg: Color(0xFF000000),
    surface: Color(0xFF1C1C1E),
    surfaceAlt: Color(0xFF2C2C2E),
    surfaceElevated: Color(0xFF2C2C2E),
    border: Color(0xFF38383A),
    divider: Color(0xFF2C2C2E),
    text: Color(0xFFFFFFFF),
    textSecondary: Color(0xFFAEAEB2),
    textMuted: Color(0xFF8E8E93),
    overlay: Color(0x99000000),
    shadow: Color(0x66000000),
    isDark: true,
  );

  @override
  AppPalette copyWith({
    Color? bg,
    Color? surface,
    Color? surfaceAlt,
    Color? surfaceElevated,
    Color? border,
    Color? divider,
    Color? text,
    Color? textSecondary,
    Color? textMuted,
    Color? overlay,
    Color? shadow,
    bool? isDark,
  }) {
    return AppPalette(
      bg: bg ?? this.bg,
      surface: surface ?? this.surface,
      surfaceAlt: surfaceAlt ?? this.surfaceAlt,
      surfaceElevated: surfaceElevated ?? this.surfaceElevated,
      border: border ?? this.border,
      divider: divider ?? this.divider,
      text: text ?? this.text,
      textSecondary: textSecondary ?? this.textSecondary,
      textMuted: textMuted ?? this.textMuted,
      overlay: overlay ?? this.overlay,
      shadow: shadow ?? this.shadow,
      isDark: isDark ?? this.isDark,
    );
  }

  @override
  AppPalette lerp(ThemeExtension<AppPalette>? other, double t) {
    if (other is! AppPalette) return this;
    return AppPalette(
      bg: Color.lerp(bg, other.bg, t)!,
      surface: Color.lerp(surface, other.surface, t)!,
      surfaceAlt: Color.lerp(surfaceAlt, other.surfaceAlt, t)!,
      surfaceElevated: Color.lerp(surfaceElevated, other.surfaceElevated, t)!,
      border: Color.lerp(border, other.border, t)!,
      divider: Color.lerp(divider, other.divider, t)!,
      text: Color.lerp(text, other.text, t)!,
      textSecondary: Color.lerp(textSecondary, other.textSecondary, t)!,
      textMuted: Color.lerp(textMuted, other.textMuted, t)!,
      overlay: Color.lerp(overlay, other.overlay, t)!,
      shadow: Color.lerp(shadow, other.shadow, t)!,
      isDark: t < 0.5 ? isDark : other.isDark,
    );
  }
}

extension AppPaletteContext on BuildContext {
  /// Palette បច្ចុប្បន្នតាម Theme (Light/Dark) — Widget នឹង rebuild ពេលប្តូរ Mode
  AppPalette get palette {
    final theme = Theme.of(this);
    return theme.extension<AppPalette>() ??
        (theme.brightness == Brightness.dark ? AppPalette.dark : AppPalette.light);
  }

  /// តើកំពុងនៅ Dark Mode ឬទេ (ប្រភពតែមួយ)
  bool get isDark => Theme.of(this).brightness == Brightness.dark;
}
