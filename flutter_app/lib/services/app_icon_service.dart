import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:io';

/// Service for managing dynamic app icons based on themes
/// Similar to Acleda Bank's seasonal icon system
class AppIconService {
  static final AppIconService _instance = AppIconService._internal();
  factory AppIconService() => _instance;
  AppIconService._internal();

  static const String _currentIconKey = 'current_app_icon';
  static const String _iconDirectory = 'assets/icons/themes/';

  // Icon file names for each theme
  static const Map<String, String> _themeIcons = {
    'default': 'default_icon.png',
    'khmer_new_year': 'khmer_new_year_icon.png',
    'pchum_ben': 'pchum_ben_icon.png',
    'water_festival': 'water_festival_icon.png',
    'christmas': 'christmas_icon.png',
    'valentine': 'valentine_icon.png',
    'smart_glass': 'smart_glass_icon.png',
    'lunar': 'lunar_icon.png',
    'bayon_spirit': 'bayon_spirit_icon.png',
  };

  String? _currentIcon;

  String? get currentIcon => _currentIcon;

  /// Initialize the icon service
  Future<void> initialize() async {
    await _loadCurrentIcon();
  }

  /// Load the current icon from local storage
  Future<void> _loadCurrentIcon() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      _currentIcon = prefs.getString(_currentIconKey);
    } catch (e) {
      debugPrint('Failed to load current icon: $e');
    }
  }

  /// Save the current icon to local storage
  Future<void> _saveCurrentIcon(String iconPath) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_currentIconKey, iconPath);
      _currentIcon = iconPath;
    } catch (e) {
      debugPrint('Failed to save current icon: $e');
    }
  }

  /// Get the icon path for a specific theme
  String getIconPathForTheme(String themeId) {
    final iconFile = _themeIcons[themeId] ?? _themeIcons['default'];
    return '$_iconDirectory$iconFile';
  }

  /// Set the current icon for a theme
  Future<bool> setIconForTheme(String themeId) async {
    try {
      final iconPath = getIconPathForTheme(themeId);
      await _saveCurrentIcon(iconPath);
      
      // Note: Runtime icon changing requires native platform implementation
      // For now, this service manages the state and provides preview functionality
      // Native implementation would be needed for actual icon switching
      
      debugPrint('Icon set to: $iconPath');
      return true;
    } catch (e) {
      debugPrint('Failed to set icon: $e');
      return false;
    }
  }

  /// Get all available theme icons
  Map<String, String> getAvailableIcons() {
    return Map.from(_themeIcons);
  }

  /// Check if an icon file exists
  Future<bool> iconExists(String iconPath) async {
    try {
      // Check if the icon exists in assets
      // For production, this would check actual file existence
      return true; // Placeholder - implement actual check
    } catch (e) {
      return false;
    }
  }

  /// Reset to default icon
  Future<bool> resetToDefault() async {
    return await setIconForTheme('default');
  }

  /// Get current icon image as AssetImage
  ImageProvider getCurrentIconImage() {
    final iconPath = _currentIcon ?? getIconPathForTheme('default');
    return AssetImage(iconPath);
  }

  /// Preview icon for a specific theme
  Widget previewIcon(String themeId, {double size = 64}) {
    final iconPath = getIconPathForTheme(themeId);
    return Image.asset(
      iconPath,
      width: size,
      height: size,
      errorBuilder: (context, error, stackTrace) {
        return Icon(
          Icons.apps,
          size: size,
          color: Colors.grey,
        );
      },
    );
  }

  /// Get icon preview for admin panel
  Widget buildIconPreview({
    required String themeId,
    required String themeName,
    double size = 80,
    VoidCallback? onTap,
  }) {
    return Card(
      elevation: 2,
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: size,
                height: size,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: Colors.grey.shade300),
                ),
                child: previewIcon(themeId, size: size - 8),
              ),
              const SizedBox(height: 8),
              Text(
                themeName,
                style: const TextStyle(fontSize: 12),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Extension for theme-related icon operations
extension AppIconThemeExtension on String {
  /// Get icon path for this theme ID
  String get iconPath => AppIconService().getIconPathForTheme(this);
  
  /// Get icon preview widget for this theme ID
  Widget iconPreview({double size = 64}) {
    return AppIconService().previewIcon(this, size: size);
  }
}