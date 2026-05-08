import 'package:flutter/material.dart';
import '../../utils/app_theme.dart';
import 'app_theme_season.dart';

class SeasonalThemeProvider extends ChangeNotifier {
  AppThemeSeason _currentSeason = AppThemeSeason.defaultHRM;
  bool _isAutoMode = true;

  AppThemeSeason get currentSeason => _currentSeason;
  bool get isAutoMode => _isAutoMode;

  ThemeData get themeData => AppTheme.isDarkMode ? AppTheme.darkTheme : AppTheme.lightTheme;

  void setTheme(AppThemeSeason season, {bool save = true}) {
    _currentSeason = season;
    if (save) _isAutoMode = false;
    _updateColors(season);
    notifyListeners();
  }

  void setAutoMode() {
    _isAutoMode = true;
    _currentSeason = AppThemeSeason.defaultHRM;
    _updateColors(AppThemeSeason.defaultHRM);
    notifyListeners();
  }

  void updateFromBackend(String themeStr) {
    if (themeStr == 'auto' || themeStr.isEmpty) {
      if (!_isAutoMode) {
        setAutoMode();
      }
    } else {
      final season = AppThemeSeasonExtension.fromString(themeStr);
      if (_currentSeason != season || _isAutoMode) {
        setTheme(season, save: false);
      }
    }
  }

  void _updateColors(AppThemeSeason season) {
    switch (season) {
      case AppThemeSeason.khmerNewYear:
        AppTheme.primary = const Color(0xFFEAB308); // Gold
        AppTheme.primaryDark = const Color(0xFFCA8A04);
        AppTheme.primaryLight = const Color(0xFFFEF08A);
        break;
      case AppThemeSeason.chineseNewYear:
        AppTheme.primary = const Color(0xFFDC2626); // Red
        AppTheme.primaryDark = const Color(0xFF991B1B);
        AppTheme.primaryLight = const Color(0xFFFCA5A5);
        break;
      case AppThemeSeason.pchumBen:
        AppTheme.primary = const Color(0xFF9333EA); // Purple
        AppTheme.primaryDark = const Color(0xFF7E22CE);
        AppTheme.primaryLight = const Color(0xFFD8B4FE);
        break;
      case AppThemeSeason.waterFestival:
        AppTheme.primary = const Color(0xFF0284C7); // Blue
        AppTheme.primaryDark = const Color(0xFF0369A1);
        AppTheme.primaryLight = const Color(0xFF7DD3FC);
        break;
      case AppThemeSeason.bayonSpirit:
        AppTheme.primary = const Color(0xFF1F4B99); // Bayon Blue
        AppTheme.primaryDark = const Color(0xFF15346A);
        AppTheme.primaryLight = const Color(0xFF6391E2);
        break;
      case AppThemeSeason.angkorEmpire:
        AppTheme.primary = const Color(0xFFD4AF37); // Royal Gold
        AppTheme.primaryDark = const Color(0xFFA6892C);
        AppTheme.primaryLight = const Color(0xFFFDE68A);
        break;
      case AppThemeSeason.romduolBloom:
        AppTheme.primary = const Color(0xFFDB2777); // Romduol Pink
        AppTheme.primaryDark = const Color(0xFF9D174D);
        AppTheme.primaryLight = const Color(0xFFF9A8D4);
        break;
      case AppThemeSeason.silverPagoda:
        AppTheme.primary = const Color(0xFF94A3B8); // Silver/Slate
        AppTheme.primaryDark = const Color(0xFF475569);
        AppTheme.primaryLight = const Color(0xFFE2E8F0);
        break;
      case AppThemeSeason.defaultHRM:
        AppTheme.primary = const Color(0xFF6366F1); // Indigo
        AppTheme.primaryDark = const Color(0xFF4F46E5);
        AppTheme.primaryLight = const Color(0xFF818CF8);
        break;
    }
  }
}
