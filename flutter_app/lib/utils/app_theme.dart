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
  static Color textSecondary = const Color(0xFF94A3B8);
  static Color textMuted = const Color(0xFF64748B);
  static Color borderColor = const Color(0xFF374151);

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
      color: Colors.black.withValues(alpha: 0.2),
      blurRadius: 15,
      offset: const Offset(0, 5),
    ),
  ];

  // === COMMON DECORATIONS ===
  static InputDecoration inputDecoration(String hint, IconData icon) {
    return InputDecoration(
      hintText: hint,
      prefixIcon: Icon(icon, color: primaryLight),
      filled: true,
      fillColor: bgCard.withValues(alpha: 0.5),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide.none,
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide(color: primary.withValues(alpha: 0.1)),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide(color: primary.withValues(alpha: 0.4)),
      ),
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
