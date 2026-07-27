import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'api_service.dart';

class AppTheme {
  final String themeId;
  final String themeName;
  final String? themeNameKh;
  final String themeCategory;
  final String themeType;
  final bool isActive;
  final bool isPremium;
  final int displayOrder;
  
  // Colors
  final Color primaryColor;
  final Color secondaryColor;
  final Color accentColor;
  final Color backgroundColor;
  final Color cardColor;
  final Color textPrimaryColor;
  final Color textSecondaryColor;
  
  // Assets
  final String? backgroundImage;
  final String? appIcon;
  final String? splashImage;
  
  // Festival settings
  final DateTime? festivalDateStart;
  final DateTime? festivalDateEnd;
  final bool autoActivate;
  
  final String? description;
  final String? previewImage;

  AppTheme({
    required this.themeId,
    required this.themeName,
    this.themeNameKh,
    required this.themeCategory,
    required this.themeType,
    required this.isActive,
    required this.isPremium,
    required this.displayOrder,
    required this.primaryColor,
    required this.secondaryColor,
    required this.accentColor,
    required this.backgroundColor,
    required this.cardColor,
    required this.textPrimaryColor,
    required this.textSecondaryColor,
    this.backgroundImage,
    this.appIcon,
    this.splashImage,
    this.festivalDateStart,
    this.festivalDateEnd,
    required this.autoActivate,
    this.description,
    this.previewImage,
  });

  factory AppTheme.fromJson(Map<String, dynamic> json) {
    return AppTheme(
      themeId: json['theme_id'] ?? 'default',
      themeName: json['theme_name'] ?? 'Default Theme',
      themeNameKh: json['theme_name_kh'],
      themeCategory: json['theme_category'] ?? 'modern',
      themeType: json['theme_type'] ?? 'modern',
      isActive: (json['is_active'] ?? 0) == 1,
      isPremium: (json['is_premium'] ?? 0) == 1,
      displayOrder: json['display_order'] ?? 0,
      primaryColor: _parseColor(json['primary_color'] ?? '#0E7490'),
      secondaryColor: _parseColor(json['secondary_color'] ?? '#2563EB'),
      accentColor: _parseColor(json['accent_color'] ?? '#F59E0B'),
      backgroundColor: _parseColor(json['background_color'] ?? '#111827'),
      cardColor: _parseColor(json['card_color'] ?? '#1F2937'),
      textPrimaryColor: _parseColor(json['text_primary_color'] ?? '#FFFFFF'),
      textSecondaryColor: _parseColor(json['text_secondary_color'] ?? '#CBD5E1'),
      backgroundImage: json['background_image'],
      appIcon: json['app_icon'],
      splashImage: json['splash_image'],
      festivalDateStart: _parseDate(json['festival_date_start']),
      festivalDateEnd: _parseDate(json['festival_date_end']),
      autoActivate: (json['auto_activate'] ?? 0) == 1,
      description: json['description'],
      previewImage: json['preview_image'],
    );
  }

  static Color _parseColor(String colorString) {
    try {
      return Color(int.parse(colorString.replaceAll('#', '0xFF')));
    } catch (e) {
      return const Color(0xFF0E7490); // Default primary color
    }
  }

  static DateTime? _parseDate(String? dateString) {
    if (dateString == null || dateString.isEmpty) return null;
    try {
      return DateTime.parse(dateString);
    } catch (e) {
      return null;
    }
  }

  Map<String, dynamic> toJson() {
    return {
      'theme_id': themeId,
      'theme_name': themeName,
      'theme_name_kh': themeNameKh,
      'theme_category': themeCategory,
      'theme_type': themeType,
      'is_active': isActive ? 1 : 0,
      'is_premium': isPremium ? 1 : 0,
      'display_order': displayOrder,
      'primary_color': '#${primaryColor.value.toRadixString(16).substring(2)}',
      'secondary_color': '#${secondaryColor.value.toRadixString(16).substring(2)}',
      'accent_color': '#${accentColor.value.toRadixString(16).substring(2)}',
      'background_color': '#${backgroundColor.value.toRadixString(16).substring(2)}',
      'card_color': '#${cardColor.value.toRadixString(16).substring(2)}',
      'text_primary_color': '#${textPrimaryColor.value.toRadixString(16).substring(2)}',
      'text_secondary_color': '#${textSecondaryColor.value.toRadixString(16).substring(2)}',
      'background_image': backgroundImage,
      'app_icon': appIcon,
      'splash_image': splashImage,
      'festival_date_start': festivalDateStart?.toIso8601String(),
      'festival_date_end': festivalDateEnd?.toIso8601String(),
      'auto_activate': autoActivate ? 1 : 0,
      'description': description,
      'preview_image': previewImage,
    };
  }

  // Check if this theme should be auto-active based on current date
  bool shouldAutoActivate() {
    if (!autoActivate || festivalDateStart == null || festivalDateEnd == null) {
      return false;
    }
    
    final now = DateTime.now();
    return now.isAfter(festivalDateStart!) && now.isBefore(festivalDateEnd!);
  }

  // Create ThemeData from this theme
  ThemeData toThemeData() {
    return ThemeData(
      brightness: Brightness.dark,
      primaryColor: primaryColor,
      scaffoldBackgroundColor: backgroundColor,
      cardColor: cardColor,
      colorScheme: ColorScheme.dark(
        primary: primaryColor,
        secondary: secondaryColor,
        surface: cardColor,
        error: Colors.red,
      ),
      textTheme: TextTheme(
        bodyLarge: TextStyle(color: textPrimaryColor),
        bodyMedium: TextStyle(color: textSecondaryColor),
        titleLarge: TextStyle(
          color: textPrimaryColor,
          fontWeight: FontWeight.bold,
        ),
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: primaryColor,
        foregroundColor: textPrimaryColor,
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: primaryColor,
          foregroundColor: textPrimaryColor,
        ),
      ),
    );
  }
}

class ThemeService {
  static final ThemeService _instance = ThemeService._internal();
  factory ThemeService() => _instance;
  ThemeService._internal();

  final ApiService _api = ApiService();
  AppTheme? _currentTheme;
  List<AppTheme> _availableThemes = [];
  
  static const String _cachedThemeKey = 'cached_app_theme';

  AppTheme? get currentTheme => _currentTheme;
  List<AppTheme> get availableThemes => _availableThemes;

  // Initialize theme service
  Future<void> initialize() async {
    await _loadCachedTheme();
    await _fetchActiveTheme();
  }

  // Load cached theme from local storage
  Future<void> _loadCachedTheme() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final cachedThemeJson = prefs.getString(_cachedThemeKey);
      if (cachedThemeJson != null) {
        final themeJson = jsonDecode(cachedThemeJson);
        _currentTheme = AppTheme.fromJson(themeJson);
      }
    } catch (e) {
      // If cache fails, will fetch from server
      debugPrint('Failed to load cached theme: $e');
    }
  }

  // Cache theme locally
  Future<void> _cacheTheme(AppTheme theme) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_cachedThemeKey, jsonEncode(theme.toJson()));
    } catch (e) {
      debugPrint('Failed to cache theme: $e');
    }
  }

  // Fetch active theme from server
  Future<void> _fetchActiveTheme() async {
    try {
      final response = await _api.getActiveTheme();
      if (response['success'] == true && response['theme'] != null) {
        _currentTheme = AppTheme.fromJson(response['theme']);
        await _cacheTheme(_currentTheme!);
      }
    } catch (e) {
      debugPrint('Failed to fetch active theme: $e');
      // Keep cached theme if fetch fails
    }
  }

  // Fetch all available themes
  Future<List<AppTheme>> fetchThemes() async {
    try {
      final response = await _api.getThemes();
      if (response['success'] == true && response['themes'] != null) {
        _availableThemes = (response['themes'] as List)
            .map((json) => AppTheme.fromJson(json))
            .toList();
        return _availableThemes;
      }
    } catch (e) {
      debugPrint('Failed to fetch themes: $e');
    }
    return [];
  }

  // Get auto-active theme based on current date
  Future<AppTheme?> getAutoTheme() async {
    try {
      final response = await _api.getAutoTheme();
      if (response['success'] == true && response['theme'] != null) {
        return AppTheme.fromJson(response['theme']);
      }
    } catch (e) {
      debugPrint('Failed to get auto theme: $e');
    }
    return null;
  }

  // Set active theme (Admin only)
  Future<bool> setActiveTheme(String themeId) async {
    try {
      final response = await _api.setActiveTheme(themeId);
      if (response['success'] == true) {
        await _fetchActiveTheme(); // Refresh current theme
        return true;
      }
    } catch (e) {
      debugPrint('Failed to set active theme: $e');
    }
    return false;
  }

  // Save theme (Admin only)
  Future<bool> saveTheme(AppTheme theme) async {
    try {
      final response = await _api.saveTheme(theme.toJson());
      if (response['success'] == true) {
        await fetchThemes(); // Refresh themes list
        return true;
      }
    } catch (e) {
      debugPrint('Failed to save theme: $e');
    }
    return false;
  }

  // Delete theme (Admin only)
  Future<bool> deleteTheme(String themeId) async {
    try {
      final response = await _api.deleteTheme(themeId);
      if (response['success'] == true) {
        await fetchThemes(); // Refresh themes list
        if (_currentTheme?.themeId == themeId) {
          await _fetchActiveTheme(); // Refresh if deleted theme was active
        }
        return true;
      }
    } catch (e) {
      debugPrint('Failed to delete theme: $e');
    }
    return false;
  }

  // Check and apply auto-active theme
  Future<void> checkAutoTheme() async {
    final autoTheme = await getAutoTheme();
    if (autoTheme != null && autoTheme.themeId != _currentTheme?.themeId) {
      _currentTheme = autoTheme;
      await _cacheTheme(_currentTheme!);
    }
  }

  // Schedule periodic auto-theme checks (every hour)
  Timer? _autoThemeCheckTimer;
  
  void scheduleAutoThemeCheck() {
    _autoThemeCheckTimer?.cancel();
    // Check for auto-active themes every hour
    _autoThemeCheckTimer = Timer.periodic(const Duration(hours: 1), (_) async {
      await checkAutoTheme();
    });
  }
  
  void cancelAutoThemeCheck() {
    _autoThemeCheckTimer?.cancel();
    _autoThemeCheckTimer = null;
  }
}