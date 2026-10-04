import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'app_palette.dart';
import 'company_theme.dart';
import 'perf_config.dart';

class AppTheme {
  static bool isDarkMode = false;

  /// Palette Light បច្ចុប្បន្ន (ប្តូរតាម Brand: VVC ឬ SK)
  static AppPalette _lightPalette = AppPalette.light;

  /// Palette បច្ចុប្បន្នតាម Mode (សម្រាប់កន្លែងដែលគ្មាន BuildContext)
  static AppPalette get palette => isDarkMode ? AppPalette.dark : _lightPalette;

  /// កំណត់ពណ៌ Theme ទៅតាម CompanyBrand (Vvc ឬ SK) និង Dark Mode Status
  static void applyCompanyTheme(CompanyTheme companyTheme) {
    isDarkMode = companyTheme.isDarkTheme;
    _lightPalette = companyTheme.brand == CompanyBrand.sk
        ? AppPalette.lightSk
        : AppPalette.light;
    primary = companyTheme.cardPrimary;
    primaryDark = companyTheme.cardSecondary;
    primaryLight = companyTheme.isDarkTheme
        ? companyTheme.cardPrimary.withValues(alpha: 0.35)
        : (companyTheme.brand == CompanyBrand.sk
            ? const Color(0xFFFDE68A)
            : const Color(0xFFFEF08A));
    _bgDark = companyTheme.backgroundColor;
    _bgCard = companyTheme.cardBackground;
    _bgSurface = companyTheme.backgroundColor;
    _cardDark = companyTheme.cardBackground;
    _textPrimary = companyTheme.textPrimary;
    _textSecondary = companyTheme.textSecondary;
    _textMuted = companyTheme.textMuted;
    _borderColor = companyTheme.cardBorder;
    _borderDark = companyTheme.cardBorder;
  }

  // === BRAND COLOR PALETTE (Vibrant Gold #F3D010 matching HomeScreen) ===
  // ⚠️ ពណ៌ Brand មិនប្តូរតាម Light/Dark ទេ
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

  // Private storage fields (Light mode values, set by company theme)
  static Color _bgDark = const Color(0xFFF8FAFC);
  static Color _bgCard = Colors.white;
  static Color _bgSurface = const Color(0xFFF8FAFC);
  static Color _cardDark = Colors.white;
  static Color _borderDark = const Color(0xFFE2E8F0);
  static Color _borderColor = const Color(0xFFE2E8F0);
  static Color _textPrimary = const Color(0xFF0F172A);
  static Color _textSecondary = const Color(0xFF475569);
  static Color _textMuted = const Color(0xFF64748B);

  static const AppPalette _dark = AppPalette.dark;

  // Apple Cupertino Native Dark Mode dynamic getters
  static Color get bgDark => isDarkMode ? _dark.bg : _bgDark;
  static set bgDark(Color v) => _bgDark = v;

  static Color get bgCard => isDarkMode ? _dark.surface : _bgCard;
  static set bgCard(Color v) => _bgCard = v;

  static Color get bgCardLight =>
      isDarkMode ? _dark.surfaceAlt : _lightPalette.surfaceAlt;
  static set bgCardLight(Color _) {}

  static Color get bgSurface => isDarkMode ? _dark.bg : _bgSurface;
  static set bgSurface(Color v) => _bgSurface = v;

  static Color get cardDark => isDarkMode ? _dark.surface : _cardDark;
  static set cardDark(Color v) => _cardDark = v;

  static Color get borderDark => isDarkMode ? _dark.border : _borderDark;
  static set borderDark(Color v) => _borderDark = v;

  static Color get borderColor => isDarkMode ? _dark.border : _borderColor;
  static set borderColor(Color v) => _borderColor = v;

  static Color get textPrimary => isDarkMode ? _dark.text : _textPrimary;
  static set textPrimary(Color v) => _textPrimary = v;

  static Color get textSecondary =>
      isDarkMode ? _dark.textSecondary : _textSecondary;
  static set textSecondary(Color v) => _textSecondary = v;

  static Color get textMuted => isDarkMode ? _dark.textMuted : _textMuted;
  static set textMuted(Color v) => _textMuted = v;

  // Additional theme colors for compatibility
  static Color get cardBg => bgCard;
  static Color get borderLight => borderDark;
  static Color get border => borderColor;

  static const double radiusSm = 12;
  static const double radiusMd = 16;
  static const double radiusLg = 20;
  static const double radiusXl = 24;

  static Color get labelColor => palette.text;
  static Color get helperTextColor => palette.textMuted;
  static Color get fieldFill => isDarkMode ? _dark.surfaceAlt : Colors.white;
  static Color get fieldBorder => palette.border;
  static Color get fieldIconColor => palette.textMuted;
  static Color get fieldHintColor =>
      isDarkMode ? _dark.textMuted : const Color(0xFF94A3B8);
  static Color get cardBorder => palette.border;

  // === SHADOWS ===
  static List<BoxShadow> get primaryShadow => [
    BoxShadow(
      color: primary.withValues(alpha: isDarkMode ? 0.30 : 0.25),
      blurRadius: 14,
      offset: const Offset(0, 5),
    ),
  ];

  /// Shadow ស្រាល មួយស្រទាប់ (ស្រាលលើ GPU ជាងពីរស្រទាប់)
  static List<BoxShadow> get cardShadow => isDarkMode
      ? const [] // Dark Mode៖ ប្រើ Border ជំនួស Shadow (ដូច iOS) — ស្អាត និងលឿន
      : [
          BoxShadow(
            color: const Color(0xFF0F172A).withValues(alpha: 0.06),
            blurRadius: 14,
            offset: const Offset(0, 4),
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
      color: color ?? palette.surface,
      borderRadius: BorderRadius.circular(radius),
      border: Border.all(
        color: borderColor ?? palette.border,
        width: 1,
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
    return BoxDecoration(
      color: gradient == null ? (color ?? palette.surface) : null,
      gradient: gradient,
      borderRadius: BorderRadius.circular(radius),
      border: Border.all(
        color: borderColor ?? palette.border,
        width: 1,
      ),
      boxShadow: [
        ...cardShadow,
        if (glow)
          BoxShadow(
            color: primary.withValues(alpha: isDarkMode ? 0.22 : 0.18),
            blurRadius: 20,
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
    final content = Container(
      padding: padding,
      decoration: glassDecoration(
        color: color,
        radius: radius,
        borderColor: borderColor,
        glow: glow,
        gradient: gradient,
      ),
      child: child,
    );

    // ផ្ទៃ Card ជាពណ៌ Solid រួចហើយ ដូច្នេះ Blur មើលមិនឃើញ → រំលង (លឿនជាង)
    final effectiveBlur = PerfConfig.blur(blur);
    final hasTranslucentFill = (color?.a ?? 1.0) < 0.98 || gradient != null;
    if (effectiveBlur <= 0 || !hasTranslucentFill) {
      return Container(margin: margin, child: content);
    }

    return Container(
      margin: margin,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(radius),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: effectiveBlur, sigmaY: effectiveBlur),
          child: content,
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
      foregroundColor: foregroundColor ??
          (bg.computeLuminance() > 0.55 ? const Color(0xFF1C1917) : Colors.white),
      elevation: 0,
      shadowColor: Colors.transparent,
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
  static ThemeData get lightTheme => _buildTheme(_lightPalette);
  static ThemeData get darkTheme => _buildTheme(_dark);

  /// បង្កើត ThemeData ពេញលេញពី Palette — Widget ណាដែលមិនបានដាក់ពណ៌ផ្ទាល់
  /// (Dialog, BottomSheet, ListTile, Card, SnackBar...) នឹងត្រូវពណ៌ដោយស្វ័យប្រវត្តិ
  static ThemeData _buildTheme(AppPalette p) {
    final brightness = p.isDark ? Brightness.dark : Brightness.light;
    final onPrimary =
        primary.computeLuminance() > 0.55 ? const Color(0xFF1C1917) : Colors.white;

    final baseText = GoogleFonts.kantumruyProTextTheme(
      p.isDark ? ThemeData.dark().textTheme : ThemeData.light().textTheme,
    ).apply(bodyColor: p.text, displayColor: p.text);

    final textTheme = baseText.copyWith(
      bodyMedium: baseText.bodyMedium?.copyWith(color: p.textSecondary),
      bodySmall: baseText.bodySmall?.copyWith(color: p.textMuted),
      labelSmall: baseText.labelSmall?.copyWith(color: p.textMuted),
      titleLarge: baseText.titleLarge?.copyWith(fontWeight: FontWeight.bold),
    );

    final colorScheme = ColorScheme(
      brightness: brightness,
      primary: primary,
      onPrimary: onPrimary,
      secondary: secondary,
      onSecondary: Colors.white,
      error: error,
      onError: Colors.white,
      surface: p.surface,
      onSurface: p.text,
      onSurfaceVariant: p.textSecondary,
      surfaceContainerLowest: p.bg,
      surfaceContainerLow: p.surface,
      surfaceContainer: p.surface,
      surfaceContainerHigh: p.surfaceAlt,
      surfaceContainerHighest: p.surfaceAlt,
      outline: p.border,
      outlineVariant: p.divider,
      shadow: Colors.black,
      scrim: Colors.black,
      inverseSurface: p.isDark ? Colors.white : const Color(0xFF1C1C1E),
      onInverseSurface: p.isDark ? const Color(0xFF0F172A) : Colors.white,
    );

    final shape16 = RoundedRectangleBorder(borderRadius: BorderRadius.circular(radiusMd));

    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: colorScheme,
      extensions: [p],
      scaffoldBackgroundColor: p.bg,
      canvasColor: p.bg,
      cardColor: p.surface,
      dividerColor: p.divider,
      hintColor: fieldHintColorFor(p),
      splashFactory: InkRipple.splashFactory, // ស្រាលជាង InkSparkle លើ GPU ចាស់
      textTheme: textTheme,
      primaryTextTheme: textTheme,
      iconTheme: IconThemeData(color: p.text),
      appBarTheme: AppBarTheme(
        backgroundColor: Colors.transparent,
        surfaceTintColor: Colors.transparent,
        foregroundColor: p.text,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: true,
        systemOverlayStyle: p.isDark
            ? const SystemUiOverlayStyle(
                statusBarColor: Colors.transparent,
                statusBarBrightness: Brightness.dark,
                statusBarIconBrightness: Brightness.light,
              )
            : const SystemUiOverlayStyle(
                statusBarColor: Colors.transparent,
                statusBarBrightness: Brightness.light,
                statusBarIconBrightness: Brightness.dark,
              ),
        titleTextStyle: GoogleFonts.kantumruyPro(
          color: p.text,
          fontWeight: FontWeight.bold,
          fontSize: 18,
        ),
        iconTheme: IconThemeData(color: p.text),
        actionsIconTheme: IconThemeData(color: p.text),
      ),
      cardTheme: CardThemeData(
        color: p.surface,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(radiusLg),
          side: BorderSide(color: p.border),
        ),
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: p.surfaceElevated,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(radiusXl)),
        titleTextStyle: GoogleFonts.kantumruyPro(
          color: p.text,
          fontSize: 18,
          fontWeight: FontWeight.bold,
        ),
        contentTextStyle: GoogleFonts.kantumruyPro(
          color: p.textSecondary,
          fontSize: 14,
        ),
      ),
      bottomSheetTheme: BottomSheetThemeData(
        backgroundColor: p.surfaceElevated,
        modalBackgroundColor: p.surfaceElevated,
        surfaceTintColor: Colors.transparent,
        dragHandleColor: p.border,
        shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(radiusXl)),
        ),
      ),
      popupMenuTheme: PopupMenuThemeData(
        color: p.surfaceElevated,
        surfaceTintColor: Colors.transparent,
        shape: shape16,
        textStyle: GoogleFonts.kantumruyPro(color: p.text, fontSize: 14),
      ),
      listTileTheme: ListTileThemeData(
        iconColor: p.textSecondary,
        textColor: p.text,
        tileColor: Colors.transparent,
      ),
      dividerTheme: DividerThemeData(color: p.divider, thickness: 1, space: 1),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        backgroundColor: p.isDark ? p.surfaceAlt : const Color(0xFF1C1C1E),
        contentTextStyle: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14),
        shape: shape16,
      ),
      chipTheme: ChipThemeData(
        backgroundColor: p.surfaceAlt,
        side: BorderSide(color: p.border),
        labelStyle: GoogleFonts.kantumruyPro(color: p.text, fontSize: 13),
      ),
      switchTheme: SwitchThemeData(
        thumbColor: WidgetStateProperty.resolveWith(
          (s) => s.contains(WidgetState.selected) ? Colors.white : p.textMuted,
        ),
        trackColor: WidgetStateProperty.resolveWith(
          (s) => s.contains(WidgetState.selected) ? const Color(0xFF34C759) : p.surfaceAlt,
        ),
        trackOutlineColor: WidgetStateProperty.resolveWith(
          (s) => s.contains(WidgetState.selected) ? Colors.transparent : p.border,
        ),
      ),
      progressIndicatorTheme: ProgressIndicatorThemeData(
        color: primary,
        linearTrackColor: p.surfaceAlt,
        circularTrackColor: Colors.transparent,
      ),
      tabBarTheme: TabBarThemeData(
        labelColor: p.text,
        unselectedLabelColor: p.textMuted,
        indicatorColor: primary,
        dividerColor: p.divider,
      ),
      datePickerTheme: DatePickerThemeData(
        backgroundColor: p.surfaceElevated,
        surfaceTintColor: Colors.transparent,
      ),
      timePickerTheme: TimePickerThemeData(
        backgroundColor: p.surfaceElevated,
      ),
      drawerTheme: DrawerThemeData(
        backgroundColor: p.surface,
        surfaceTintColor: Colors.transparent,
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: p.surface,
        surfaceTintColor: Colors.transparent,
      ),
      textSelectionTheme: TextSelectionThemeData(
        cursorColor: primary,
        selectionHandleColor: primary,
        selectionColor: primary.withValues(alpha: 0.30),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: p.isDark ? p.surfaceAlt : Colors.white,
        hintStyle: GoogleFonts.kantumruyPro(color: fieldHintColorFor(p)),
        labelStyle: GoogleFonts.kantumruyPro(color: p.textSecondary),
        prefixIconColor: p.textMuted,
        suffixIconColor: p.textMuted,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(radiusMd),
          borderSide: BorderSide(color: p.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(radiusMd),
          borderSide: BorderSide(color: p.border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(radiusMd),
          borderSide: BorderSide(color: primary, width: 1.5),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(style: filledButtonStyle()),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: p.isDark ? primary : const Color(0xFFB45309),
          textStyle: GoogleFonts.kantumruyPro(fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: p.text,
          side: BorderSide(color: p.border),
          shape: shape16,
        ),
      ),
    );
  }

  static Color fieldHintColorFor(AppPalette p) =>
      p.isDark ? p.textMuted : const Color(0xFF94A3B8);
}
