import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'company_theme.dart';

class AppTheme {
  static bool isDarkMode = false;

  /// កំណត់ពណ៌ Theme ទៅតាម CompanyBrand (Vvc ឬ SK) និង Dark Mode Status
  static void applyCompanyTheme(CompanyTheme companyTheme) {
    isDarkMode = companyTheme.isDarkTheme;
    primary = companyTheme.cardPrimary;
    primaryDark = companyTheme.cardSecondary;
    primaryLight = companyTheme.isDarkTheme
        ? companyTheme.cardPrimary.withValues(alpha: 0.35)
        : (companyTheme.brand == CompanyBrand.sk
            ? const Color(0xFFFDE68A)
            : const Color(0xFFFEF08A));
    bgDark = companyTheme.backgroundColor;
    bgCard = companyTheme.cardBackground;
    bgSurface = companyTheme.backgroundColor;
    cardDark = companyTheme.cardBackground;
    textPrimary = companyTheme.textPrimary;
    textSecondary = companyTheme.textSecondary;
    textMuted = companyTheme.textMuted;
    borderColor = companyTheme.cardBorder;
    borderDark = companyTheme.cardBorder;
  }

  // === BRAND COLOR PALETTE (Vibrant Gold #F3D010 matching HomeScreen) ===
  static Color primary = const Color(0xFFF3D010); // Vibrant Gold
  static Color primaryDark = const Color(0xFFE5BF00);
  static Color primaryLight = const Color(0xFFFEF08A);
  static Color secondary = const Color(0xFF2563EB); // Blue
  static Color accent = const Color(0xFFF59E0B); // Amber
  static Color success = const Color(0xFF16A34A); // Green
  static Color warning = const Color(0xFFD97706); // Orange
  static Color error = const Color(0xFFDC2626);
  static Color danger = const Color(0xFFDC2626);
  static Color info = const Color(0xFF3B82F6);

  // iOS Glassmorphism Canvas & Card Layers
  static Color bgDark = const Color(0xFFF8FAFC); // Clean Canvas Slate-50
  static Color bgCard = Colors.white; // Pure white glass cards
  static Color bgCardLight = const Color(0xFFF1F5F9);
  static Color bgSurface = const Color(0xFFF8FAFC);
  static Color cardDark = Colors.white;
  static Color borderDark = const Color(0xFFE2E8F0);
  
  // Additional theme colors for compatibility
  static Color get cardBg => bgCard;
  static Color get borderLight => borderDark;
  static Color get border => borderColor;

  static Color textPrimary = const Color(0xFF0F172A); // High contrast dark slate (visible on white glass)
  static Color textSecondary = const Color(0xFF475569); // Slate-600
  static Color textMuted = const Color(0xFF64748B); // Slate-500
  static Color borderColor = const Color(0xFFE2E8F0);

  static const double radiusSm = 12;
  static const double radiusMd = 16;
  static const double radiusLg = 20;
  static const double radiusXl = 24;

  static Color get labelColor =>
      isDarkMode ? Colors.white : const Color(0xFF1E293B);
  static Color get helperTextColor =>
      isDarkMode ? const Color(0xFF94A3B8) : const Color(0xFF64748B);
  static Color get fieldFill => isDarkMode
      ? const Color(0xFF1E222B)
      : Colors.white.withValues(alpha: 0.90);
  static Color get fieldBorder => isDarkMode
      ? const Color(0x2EFFFFFF)
      : const Color(0xFFE2E8F0);
  static Color get fieldIconColor =>
      isDarkMode ? const Color(0xFF94A3B8) : const Color(0xFF64748B);
  static Color get fieldHintColor =>
      isDarkMode ? const Color(0xFF64748B) : const Color(0xFF94A3B8);
  static Color get cardBorder =>
      isDarkMode ? const Color(0x1FFFFFFF) : Colors.white;

  // === SHADOWS ===
  static List<BoxShadow> get primaryShadow => [
    BoxShadow(
      color: primary.withValues(alpha: isDarkMode ? 0.35 : 0.28),
      blurRadius: 16,
      offset: const Offset(0, 6),
    ),
  ];

  static List<BoxShadow> get cardShadow => isDarkMode
      ? [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.45),
            blurRadius: 18,
            offset: const Offset(0, 6),
          ),
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.22),
            blurRadius: 4,
            offset: const Offset(0, 1),
          ),
        ]
      : [
          BoxShadow(
            color: const Color(0xFF0F172A).withValues(alpha: 0.065),
            blurRadius: 18,
            offset: const Offset(0, 6),
          ),
          BoxShadow(
            color: const Color(0xFF0F172A).withValues(alpha: 0.025),
            blurRadius: 4,
            offset: const Offset(0, 1),
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
      color: color ??
          (isDarkMode ? bgCard : Colors.white.withValues(alpha: 0.94)),
      borderRadius: BorderRadius.circular(radius),
      border: Border.all(
        color: borderColor ??
            (isDarkMode ? const Color(0x1FFFFFFF) : Colors.white),
        width: 1.5,
      ),
      boxShadow: shadows ?? cardShadow,
    );
  }

  // === GLASSMORPHISM DECORATIONS ===
  static BoxDecoration glassDecoration({
    Color? color,
    double radius = radiusXl,
    Color? borderColor,
    bool glow = false,
    Gradient? gradient,
  }) {
    final baseColor =
        color ?? (isDarkMode ? const Color(0xFF191B22) : Colors.white);
    return BoxDecoration(
      gradient: gradient ??
          LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: isDarkMode
                ? [
                    const Color(0xFF1E222B).withValues(alpha: 0.85),
                    const Color(0xFF14161E).withValues(alpha: 0.92),
                  ]
                : [
                    baseColor.withValues(alpha: 0.96),
                    baseColor.withValues(alpha: 0.90),
                    baseColor.withValues(alpha: 0.92),
                  ],
          ),
      borderRadius: BorderRadius.circular(radius),
      border: Border.all(
        color: borderColor ??
            (isDarkMode ? const Color(0x26FFFFFF) : Colors.white),
        width: 1.5,
      ),
      boxShadow: [
        ...cardShadow,
        if (glow)
          BoxShadow(
            color: primary.withValues(alpha: isDarkMode ? 0.25 : 0.20),
            blurRadius: 22,
            spreadRadius: -2,
          ),
      ],
    );
  }

  static Widget glassBox({
    required Widget child,
    Color? color,
    double radius = radiusXl,
    Color? borderColor,
    bool glow = false,
    double blur = 20.0,
    EdgeInsetsGeometry? padding,
    EdgeInsetsGeometry? margin,
    Gradient? gradient,
  }) {
    return Container(
      margin: margin,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(radius),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: blur, sigmaY: blur),
          child: Container(
            padding: padding,
            decoration: glassDecoration(
              color: color,
              radius: radius,
              borderColor: borderColor,
              glow: glow,
              gradient: gradient,
            ),
            child: child,
          ),
        ),
      ),
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
      foregroundColor: foregroundColor ?? Colors.white,
      elevation: 2,
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
        borderSide: BorderSide(color: primary, width: 1.5),
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
  static ThemeData get lightTheme => ThemeData(
    brightness: Brightness.light,
    scaffoldBackgroundColor: bgDark,
    appBarTheme: AppBarTheme(
      backgroundColor: Colors.transparent,
      elevation: 0,
      centerTitle: true,
      systemOverlayStyle: const SystemUiOverlayStyle(
        statusBarColor: Colors.transparent,
        statusBarBrightness: Brightness.light,
        statusBarIconBrightness: Brightness.dark,
      ),
      titleTextStyle: GoogleFonts.kantumruyPro(
        color: textPrimary,
        fontWeight: FontWeight.bold,
        fontSize: 18,
      ),
      iconTheme: IconThemeData(color: textPrimary),
    ),
    colorScheme: ColorScheme.light(
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
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: BorderSide(color: fieldBorder),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: BorderSide(color: primary, width: 1.5),
      ),
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(style: filledButtonStyle()),
    textTheme: GoogleFonts.kantumruyProTextTheme(ThemeData.light().textTheme)
        .copyWith(
          bodyLarge: GoogleFonts.kantumruyPro(color: textPrimary),
          bodyMedium: GoogleFonts.kantumruyPro(color: textSecondary),
          titleLarge: GoogleFonts.kantumruyPro(
            color: textPrimary,
            fontWeight: FontWeight.bold,
          ),
        ),
  );

  static ThemeData get darkTheme => ThemeData(
    brightness: Brightness.dark,
    scaffoldBackgroundColor: const Color(0xFF0F1115),
    cardColor: const Color(0xFF191B22),
    dividerColor: const Color(0x1FFFFFFF),
    appBarTheme: AppBarTheme(
      backgroundColor: Colors.transparent,
      elevation: 0,
      centerTitle: true,
      systemOverlayStyle: const SystemUiOverlayStyle(
        statusBarColor: Colors.transparent,
        statusBarBrightness: Brightness.dark,
        statusBarIconBrightness: Brightness.light,
      ),
      titleTextStyle: GoogleFonts.kantumruyPro(
        color: Colors.white,
        fontWeight: FontWeight.bold,
        fontSize: 18,
      ),
      iconTheme: const IconThemeData(color: Colors.white),
    ),
    colorScheme: ColorScheme.dark(
      primary: primary,
      secondary: secondary,
      surface: const Color(0xFF191B22),
      onSurface: Colors.white,
      onPrimary: Colors.black,
      error: error,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: const Color(0xFF1E222B),
      hintStyle: GoogleFonts.kantumruyPro(color: const Color(0xFF64748B)),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: const BorderSide(color: Color(0x2EFFFFFF)),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: const BorderSide(color: Color(0x2EFFFFFF)),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radiusMd),
        borderSide: BorderSide(color: primary, width: 1.5),
      ),
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(style: filledButtonStyle()),
    textTheme: GoogleFonts.kantumruyProTextTheme(ThemeData.dark().textTheme)
        .copyWith(
          bodyLarge: GoogleFonts.kantumruyPro(color: Colors.white),
          bodyMedium: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8)),
          titleLarge: GoogleFonts.kantumruyPro(
            color: Colors.white,
            fontWeight: FontWeight.bold,
          ),
        ),
  );
}
