import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class AppTheme {
  static bool isDarkMode = true;

  // === FLAT SOLID COLOR PALETTE ===
  static Color primary = const Color(0xFF0E7490); // Teal
  static Color primaryDark = const Color(0xFF155E75);
  static Color primaryLight = const Color(0xFF22D3EE);
  static Color secondary = const Color(0xFF2563EB); // Blue
  static Color accent = const Color(0xFFF59E0B); // Amber
  static Color success = const Color(0xFF16A34A); // Green
  static Color warning = const Color(0xFFD97706); // Orange
  static Color error = const Color(0xFFDC2626);
  static Color danger = const Color(0xFFDC2626);
  static Color info = const Color(0xFF3B82F6);

  // Flat dark layers
  static Color bgDark = const Color(0xFF111827);
  static Color bgCard = const Color(0xFF1F2937);
  static Color bgCardLight = const Color(0xFF374151);
  static Color bgSurface = const Color(0xFF0B1120);

  static Color textPrimary = Colors.white;
  static Color textSecondary = const Color(0xFFCBD5E1);
  static Color textMuted = const Color(0xFF94A3B8);
  static Color borderColor = const Color(0xFF475569);

  static const double radiusSm = 12;
  static const double radiusMd = 16;
  static const double radiusLg = 20;
  static const double radiusXl = 24;

  static Color get labelColor => textPrimary.withValues(alpha: 0.82);
  static Color get helperTextColor => textSecondary.withValues(alpha: 0.78);
  static Color get fieldFill => textPrimary.withValues(alpha: 0.075);
  static Color get fieldBorder => textPrimary.withValues(alpha: 0.14);
  static Color get fieldIconColor => textSecondary.withValues(alpha: 0.9);
  static Color get fieldHintColor => textSecondary.withValues(alpha: 0.72);
  static Color get cardBorder => textPrimary.withValues(alpha: 0.10);

  // === SHADOWS ===
  static List<BoxShadow> get primaryShadow => [
    BoxShadow(
      color: primary.withValues(alpha: 0.3),
      blurRadius: 20,
      offset: const Offset(0, 8),
    ),
  ];

  static List<BoxShadow> get cardShadow => [
    BoxShadow(
      color: Colors.black.withValues(alpha: 0.24),
      blurRadius: 18,
      offset: const Offset(0, 8),
    ),
  ];

  // === COMMON DECORATIONS ===
  static BoxDecoration cardDecoration({
    Color? color,
    double radius = radiusXl,
    Color? borderColor,
    List<BoxShadow>? shadows,
  }) {
    return BoxDecoration(
      color: color ?? bgCard,
      borderRadius: BorderRadius.circular(radius),
      border: Border.all(color: borderColor ?? cardBorder),
      boxShadow: shadows ?? cardShadow,
    );
  }

  static ButtonStyle filledButtonStyle({
    Color? backgroundColor,
    Color? foregroundColor,
    double radius = radiusMd,
  }) {
    final bg = backgroundColor ?? primary;
    return ElevatedButton.styleFrom(
      backgroundColor: bg,
      foregroundColor: foregroundColor ?? textPrimary,
      elevation: 8,
      shadowColor: bg.withValues(alpha: 0.35),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(radius),
      ),
      textStyle: GoogleFonts.kantumruyPro(
        fontWeight: FontWeight.bold,
        fontSize: 16,
      ),
    );
  }

  static InputDecoration inputDecoration(String hint, IconData icon) {
    return InputDecoration(
      hintText: hint,
      hintStyle: GoogleFonts.kantumruyPro(color: fieldHintColor, fontSize: 13),
      prefixIcon: Icon(icon, color: fieldIconColor, size: 20),
      filled: true,
      fillColor: fieldFill,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: BorderSide.none,
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: BorderSide(color: fieldBorder),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: BorderSide(color: primaryLight, width: 1.5),
      ),
      errorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: BorderSide(color: danger.withValues(alpha: 0.75)),
      ),
      focusedErrorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: BorderSide(color: danger, width: 1.5),
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
    );
  }

  // === THEME DATA ===
  static ThemeData get darkTheme => ThemeData(
    brightness: Brightness.dark,
    scaffoldBackgroundColor: bgDark,
    colorScheme: ColorScheme.dark(
      primary: primary,
      secondary: secondary,
      surface: bgCard,
      error: error,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: fieldFill,
      hintStyle: GoogleFonts.kantumruyPro(color: fieldHintColor),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: BorderSide(color: fieldBorder),
      ),
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(style: filledButtonStyle()),
    textTheme: GoogleFonts.kantumruyProTextTheme(ThemeData.dark().textTheme)
        .copyWith(
          bodyLarge: GoogleFonts.kantumruyPro(color: Colors.white),
          bodyMedium: GoogleFonts.kantumruyPro(color: textSecondary),
          titleLarge: GoogleFonts.kantumruyPro(
            color: Colors.white,
            fontWeight: FontWeight.bold,
          ),
        ),
  );

  static ThemeData get lightTheme =>
      darkTheme; // Fallback for simple implementation
}
