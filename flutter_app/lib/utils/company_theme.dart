import 'package:flutter/material.dart';

/// ក្រុមហ៊ុនទាំងពីរ (Vvc និង SK)
enum CompanyBrand {
  vvc,
  sk,
}

/// Helper សម្រាប់សម្គាល់ និងបង្កើត Theme សម្រាប់ក្រុមហ៊ុននីមួយៗ
class CompanyTheme {
  final CompanyBrand brand;
  final String name;
  final String brandLabel;
  final String passTitle;

  // Colors
  final Color backgroundColor;
  final Color cardPrimary;
  final Color cardSecondary;
  final Color cardBackground;
  final Color cardBorder;
  final Color passCardColor;
  final Color passCardTextColor;
  final Color textPrimary;
  final Color textSecondary;
  final Color textMuted;
  final Color glowColor;
  final Color orbPrimary;
  final Color orbSecondary;
  final Color orbAccent;
  final bool isDarkTheme;

  const CompanyTheme({
    required this.brand,
    required this.name,
    required this.brandLabel,
    required this.passTitle,
    required this.backgroundColor,
    required this.cardPrimary,
    required this.cardSecondary,
    required this.cardBackground,
    required this.cardBorder,
    required this.passCardColor,
    required this.passCardTextColor,
    required this.textPrimary,
    required this.textSecondary,
    required this.textMuted,
    required this.glowColor,
    required this.orbPrimary,
    required this.orbSecondary,
    required this.orbAccent,
    this.isDarkTheme = false,
  });

  /// ក្រុមហ៊ុនទី ១៖ Vvc
  /// - Card Primary Rich Amber/Gold: #D97706
  /// - Background: White (#FFFFFF / #F8FAFC)
  static const CompanyTheme vvc = CompanyTheme(
    brand: CompanyBrand.vvc,
    name: 'Vvc',
    brandLabel: 'Vvc HRM',
    passTitle: 'Vvc HRM EMPLOYEE PASS',
    backgroundColor: Color(0xFFF8FAFC),
    cardPrimary: Color(0xFFD97706),
    cardSecondary: Color(0xFFB45309),
    cardBackground: Colors.white,
    cardBorder: Color(0xFFE2E8F0),
    passCardColor: Color(0xFFD97706),
    passCardTextColor: Colors.white,
    textPrimary: Color(0xFF0F172A),
    textSecondary: Color(0xFF475569),
    textMuted: Color(0xFF64748B),
    glowColor: Color(0xFFD97706),
    orbPrimary: Color(0xFFD97706),
    orbSecondary: Color(0xFF38BDF8),
    orbAccent: Color(0xFFA855F7),
    isDarkTheme: false,
  );

  /// ក្រុមហ៊ុនទី ២៖ SK
  /// - Background: Light gold tint #F7F1E4
  /// - Card Color: #C08207 (Deep Amber Gold)
  static const CompanyTheme sk = CompanyTheme(
    brand: CompanyBrand.sk,
    name: 'SK',
    brandLabel: 'SK HRM',
    passTitle: 'SK HRM EMPLOYEE PASS',
    backgroundColor: Color(0xFFF7F1E4),
    cardPrimary: Color(0xFFC08207),
    cardSecondary: Color(0xFFA16207),
    cardBackground: Color(0xFFFFFDF8),
    cardBorder: Color(0xFFE8DCC2),
    passCardColor: Color(0xFFC08207),
    passCardTextColor: Colors.white,
    textPrimary: Color(0xFF292524),
    textSecondary: Color(0xFF78716C),
    textMuted: Color(0xFFA8A29E),
    glowColor: Color(0xFFC08207),
    orbPrimary: Color(0xFFC08207),
    orbSecondary: Color(0xFFD97706),
    orbAccent: Color(0xFFB45309),
    isDarkTheme: false,
  );

  /// ក្រុមហ៊ុនទី ៣៖ Vvc Dark Luxury Obsidian & Gold (Telegram Style)
  static const CompanyTheme vvcDark = CompanyTheme(
    brand: CompanyBrand.vvc,
    name: 'Vvc Obsidian Gold',
    brandLabel: 'Vvc HRM',
    passTitle: 'Vvc HRM EMPLOYEE PASS',
    backgroundColor: Color(0xFF0F1115),
    cardPrimary: Color(0xFFF59E0B),
    cardSecondary: Color(0xFFD97706),
    cardBackground: Color(0xFF191B22),
    cardBorder: Color(0x1FFFFFFF),
    passCardColor: Color(0xFF191B22),
    passCardTextColor: Color(0xFFF59E0B),
    textPrimary: Colors.white,
    textSecondary: Color(0xFF94A3B8),
    textMuted: Color(0xFF64748B),
    glowColor: Color(0xFFF59E0B),
    orbPrimary: Color(0xFFF59E0B),
    orbSecondary: Color(0xFFD97706),
    orbAccent: Color(0xFFB45309),
    isDarkTheme: true,
  );

  /// ជ្រើសរើស Theme តាម CompanyBrand
  static CompanyTheme forBrand(CompanyBrand brand, {bool isDark = true}) {
    switch (brand) {
      case CompanyBrand.sk:
        return sk;
      case CompanyBrand.vvc:
        return isDark ? vvcDark : vvc;
    }
  }
}

/// Helper សម្រាប់ Detect រក CompanyBrand តាមមុខតំណែងបុគ្គលិក (Position)
class CompanyBrandHelper {
  /// ពិនិត្យលើ Position របស់ User (រួមទាំង Department ឬ Branch)
  /// ប្រសិនបើមានអក្សរ SK NR3, KS2, NR3, SK KS2 នោះវានឹងលោតទៅ SK
  /// ក្រៅពីនេះគឺ Vvc
  static CompanyBrand fromPosition(
    String? position, {
    String? department,
    String? branch,
  }) {
    final pos = (position ?? '').trim().toUpperCase();
    final dept = (department ?? '').trim().toUpperCase();
    final br = (branch ?? '').trim().toUpperCase();

    // បញ្ជី Keywords សម្គាល់ SK តាមការស្នើសុំ៖ SK NR3, KS2, NR3, SK KS2
    bool matchPos = pos.contains('SK NR3') ||
        pos.contains('SK KS2') ||
        pos.contains('SK') ||
        pos.contains('NR3') ||
        pos.contains('KS2');

    bool matchDept = dept.contains('SK') ||
        dept.contains('NR3') ||
        dept.contains('KS2');

    bool matchBranch = br.contains('SK') ||
        br.contains('NR3') ||
        br.contains('KS2');

    if (matchPos || matchDept || matchBranch) {
      return CompanyBrand.sk;
    }

    return CompanyBrand.vvc;
  }
}
