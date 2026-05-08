import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter_background_service/flutter_background_service.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import '../services/api_service.dart';

/// តួនាទីក្នុងប្រព័ន្ធ HRM
enum SystemRole { employee, worker, skills, it, admin, hrm, accounting }

extension SystemRoleExt on SystemRole {
  String get value {
    switch (this) {
      case SystemRole.employee:
        return 'Employee';
      case SystemRole.worker:
        return 'Worker';
      case SystemRole.skills:
        return 'Skills';
      case SystemRole.it:
        return 'IT';
      case SystemRole.admin:
        return 'Admin';
      case SystemRole.hrm:
        return 'HRM';
      case SystemRole.accounting:
        return 'Accounting';
    }
  }

  String get label {
    switch (this) {
      case SystemRole.employee:
        return 'បុគ្គលិក (Employee)';
      case SystemRole.worker:
        return 'កម្មករ (Worker)';
      case SystemRole.skills:
        return 'ជំនាញ (Skills)';
      case SystemRole.it:
        return 'IT';
      case SystemRole.admin:
        return 'អ្នកគ្រប់គ្រង (Admin)';
      case SystemRole.hrm:
        return 'ធនធានមនុស្ស (HRM)';
      case SystemRole.accounting:
        return 'គណនេយ្យ (Accounting)';
    }
  }

  String get labelEn {
    switch (this) {
      case SystemRole.employee:
        return 'Employee';
      case SystemRole.worker:
        return 'Worker';
      case SystemRole.skills:
        return 'Skills';
      case SystemRole.it:
        return 'IT';
      case SystemRole.admin:
        return 'Admin';
      case SystemRole.hrm:
        return 'HRM';
      case SystemRole.accounting:
        return 'Accounting';
    }
  }

  bool get canManageUsers => this == SystemRole.admin || this == SystemRole.hrm;
  bool get canViewPayroll =>
      this == SystemRole.admin ||
      this == SystemRole.accounting ||
      this == SystemRole.hrm;
  bool get canSendNotify => this == SystemRole.admin || this == SystemRole.hrm;
  bool get isAdminLevel => this == SystemRole.admin;
  bool get isHrmLevel => this == SystemRole.hrm || this == SystemRole.admin;
  bool get isAccountingLevel => this == SystemRole.accounting;
  bool get isITLevel => this == SystemRole.it || this == SystemRole.admin;
}

SystemRole systemRoleFromString(String? s) {
  switch ((s ?? '').toLowerCase()) {
    case 'worker':
      return SystemRole.worker;
    case 'skills':
      return SystemRole.skills;
    case 'it':
      return SystemRole.it;
    case 'admin':
      return SystemRole.admin;
    case 'hrm':
      return SystemRole.hrm;
    case 'accounting':
      return SystemRole.accounting;
    default:
      return SystemRole.employee;
  }
}

class UserProvider with ChangeNotifier {
  String? _employeeId;
  String? _name;
  String? _avatar;
  String? _token;
  String? _userType; // scan_user_type (legacy: 'admin','worker','skill')
  String?
  _systemRoleStr; // system_role from DB: 'Employee','Worker','Skills','IT','Admin','HRM','Accounting'
  String? _systemRoleLabel; // display label
  String? _position; // user position/department from profile
  String? _phone;
  String? _email;
  bool _isLoggedIn = false;
  bool _isVerified = false;
  int _attendanceStreak = 0;
  Map<String, dynamic> _settings = {};

  String? get employeeId => _employeeId;
  String? get name => _name;
  String? get avatar => _avatar;
  String? get token => _token;
  String? get userType => _userType;
  String? get position => _position;
  String? get phone => _phone;
  String? get email => _email;
  bool get isVerified => _isVerified;
  int get attendanceStreak => _attendanceStreak;
  Map<String, dynamic> get settings => _settings;

  /// Full URL for avatar image (handles relative path from server)
  String? get avatarUrl {
    final full = ApiService.getFullImageUrl(_avatar);
    return full.isNotEmpty ? full : null;
  }

  bool get isLoggedIn => _isLoggedIn;

  /// Check if a specific feature should be shown based on server settings
  bool canShow(String key, {bool defaultValue = true}) {
    if (!_settings.containsKey(key)) return defaultValue;
    final val = _settings[key];
    if (val == null) return defaultValue;
    // Database stores as string '1' or '0'
    return val.toString() == '1' || val.toString().toLowerCase() == 'true';
  }

  /// Get a configuration value as a string
  String getConfig(String key, {String defaultValue = ''}) {
    if (!_settings.containsKey(key)) return defaultValue;
    return _settings[key]?.toString() ?? defaultValue;
  }

  /// New: Check if the user is explicitly assigned to see employee reports via ID lists
  bool canViewEmployeeReport() {
    final String myId = (employeeId ?? '').trim();
    if (myId.isEmpty) return false;

    // Check across all branch assignment lists
    final id318 = (_settings['employee_report_ids_318'] ?? '').toString();
    final idKS2 = (_settings['employee_report_ids_ks2'] ?? '').toString();
    final idNR3 = (_settings['employee_report_ids_nr3'] ?? '').toString();

    final in318 = id318.split(',').map((e) => e.trim()).contains(myId);
    final inKS2 = idKS2.split(',').map((e) => e.trim()).contains(myId);
    final inNR3 = idNR3.split(',').map((e) => e.trim()).contains(myId);

    return in318 || inKS2 || inNR3;
  }

  /// Get list of material request locations from server settings
  List<String> get materialLocations {
    final String raw = (_settings['material_request_locations'] ?? '').toString();
    if (raw.trim().isEmpty) {
      return ['Main Office (318)', 'Factory 1 (NR3)', 'Factory 2 (KS2)'];
    }
    return raw.split(',').map((e) => e.trim()).where((e) => e.isNotEmpty).toList();
  }

  /// Raw DB system_role string
  String get systemRoleStr => _systemRoleStr ?? 'Employee';

  /// Parsed enum
  SystemRole get systemRole => systemRoleFromString(_systemRoleStr);

  /// Label for display (ខ្មែរ + English)
  String get systemRoleLabel => _systemRoleLabel ?? systemRole.label;

  bool get isAdmin => systemRole.isAdminLevel;
  bool get isHRM => systemRole.isHrmLevel;
  bool get isAccounting => systemRole.isAccountingLevel;
  bool get isIT => systemRole.isITLevel;

  final ApiService _apiService = ApiService();

  Future<void> loadSavedUser() async {
    final prefs = await SharedPreferences.getInstance();
    _token = prefs.getString('auth_token');
    _employeeId = prefs.getString('employee_id');
    _name = prefs.getString('user_name');
    _avatar = prefs.getString('avatar');
    _userType = prefs.getString('scan_user_type');
    _systemRoleStr = prefs.getString('system_role') ?? 'Employee';
    _systemRoleLabel = prefs.getString('system_role_label') ?? '';
    _position = prefs.getString('user_position');
    _phone = prefs.getString('user_phone');
    _email = prefs.getString('user_email');
    _isVerified = prefs.getBool('is_verified') ?? false;
    _attendanceStreak = prefs.getInt('attendance_streak') ?? 0;

    final savedSettings = prefs.getString('app_settings');
    if (savedSettings != null) {
      try {
        _settings = Map<String, dynamic>.from(json.decode(savedSettings));
      } catch (_) {}
    }

    if (_token != null && _employeeId != null) {
      _isLoggedIn = true;

      // Refresh FCM Token in background (non-blocking — works offline)
      _refreshFcmTokenSilently();
    }
    notifyListeners();
  }

  /// Refresh FCM token silently in the background (fire-and-forget).
  /// Safe to call at startup even when offline — errors are ignored.
  Future<String?> _resolveCurrentFcmToken() async {
    if (Firebase.apps.isEmpty) {
      return null;
    }

    final messaging = FirebaseMessaging.instance;
    if (kIsWeb) {
      return messaging.getToken(
        vapidKey:
            'BGhJeVu8tlN10zR-k09ReR2Ln8dFvfCIn3AThEAYqn2uo094ewqlKjag5CACOfbTlhom2wMSgCPMP6nL5uW0Fvw',
      );
    }
    return messaging.getToken();
  }

  void _refreshFcmTokenSilently() {
    Future.microtask(() async {
      try {
        // Wait for Firebase to be initialized (retry for 10 seconds)
        int retryCount = 0;
        while (Firebase.apps.isEmpty && retryCount < 10) {
          await Future.delayed(const Duration(seconds: 1));
          retryCount++;
        }

        if (Firebase.apps.isEmpty) {
          debugPrint("FCM: Firebase not initialized, skipping token refresh.");
          return;
        }

        final fcmToken = await _resolveCurrentFcmToken();
        if (fcmToken != null) {
          final platformName = kIsWeb
              ? 'Web'
              : (defaultTargetPlatform == TargetPlatform.android ? 'Android' : 'iOS');

          debugPrint("🔔 FCM REGISTRATION TOKEN ($platformName):");
          debugPrint(fcmToken);
          debugPrint("------------------------------------------");
          
          await _apiService.updateFcmToken(fcmToken, platform: platformName);
        }
      } catch (e) {
        debugPrint("FCM background refresh error (ignored): $e");
      }
    });
  }

  Future<Map<String, dynamic>> login(String employeeId, String userType) async {
    final result = await _apiService.login(employeeId, userType);

    if (result['success'] == true) {
      _token = result['token'];
      _employeeId = result['user']['id']?.toString();
      _name = result['user']['name'] as String?;
      _avatar = result['user']['avatar'] as String?;
      _position = result['user']['position'] as String?;
      _phone = result['user']['phone']?.toString();
      _email = result['user']['email'] as String?;
      _userType = userType;
      // Pull system_role from server response (new fields)
      _systemRoleStr = (result['user']['system_role'] as String?) ?? userType;
      _systemRoleLabel = (result['user']['system_role_label'] as String?) ?? '';
      _isVerified = (result['user']['is_verified'] ?? 0).toString() == '1';
      _attendanceStreak = int.tryParse(result['user']['attendance_streak']?.toString() ?? '0') ?? 0;
      _isLoggedIn = true;

      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('auth_token', _token!);
      await prefs.setString('employee_id', _employeeId!);
      await prefs.setString('user_name', _name!);
      if (_avatar != null) {
        await prefs.setString('avatar', _avatar!);
      } else {
        await prefs.remove('avatar');
      }
      if (_position != null && _position!.isNotEmpty) {
        await prefs.setString('user_position', _position!);
      } else {
        await prefs.remove('user_position');
      }
      if (_phone != null) await prefs.setString('user_phone', _phone!);
      if (_email != null) await prefs.setString('user_email', _email!);
      await prefs.setString('scan_user_type', _userType!);
      await prefs.setString('system_role', _systemRoleStr!);
      await prefs.setString('system_role_label', _systemRoleLabel!);
      await prefs.setBool('is_verified', _isVerified);
      await prefs.setInt('attendance_streak', _attendanceStreak);

      // ទាញយកការកំណត់ (Settings) ភ្លាមៗក្រោយពេល Login ជោគជ័យ
      await refreshConfig();
      await refreshProfile();

      notifyListeners();

      // FCM Token Registration (background — non-blocking)
      _refreshFcmTokenSilently();
    }
    return result;
  }

  Future<void> refreshProfile() async {
    if (_token == null) return;
    refreshConfig(); // Background refresh configuration as well
    final result = await _apiService.fetchProfile();
    if (result['success'] == true && result['user'] != null) {
      final user = result['user'] as Map<String, dynamic>;
      _employeeId = (user['id'] ?? user['employee_id'])?.toString();
      _name = user['name'] as String?;
      _avatar = user['avatar'] as String?;
      _position = user['position'] as String?;
      _phone = user['phone']?.toString();
      _email = user['email'] as String?;
      _systemRoleStr =
          (user['system_role'] as String?) ?? _systemRoleStr ?? 'Employee';
      _systemRoleLabel =
          (user['system_role_label'] as String?) ?? _systemRoleLabel ?? '';
      _isVerified = (user['is_verified'] ?? 0).toString() == '1';
      _attendanceStreak = int.tryParse(user['attendance_streak']?.toString() ?? '0') ?? 0;

      final prefs = await SharedPreferences.getInstance();
      if (_employeeId != null) {
        await prefs.setString('employee_id', _employeeId!);
      }
      if (_name != null) {
        await prefs.setString('user_name', _name!);
      }
      if (_avatar != null && _avatar!.isNotEmpty) {
        await prefs.setString('avatar', _avatar!);
      } else {
        await prefs.remove('avatar');
      }
      if (_position != null && _position!.isNotEmpty) {
        await prefs.setString('user_position', _position!);
      } else {
        await prefs.remove('user_position');
      }
      if (_phone != null) await prefs.setString('user_phone', _phone!);
      if (_email != null) await prefs.setString('user_email', _email!);
      if (_systemRoleStr != null) {
        await prefs.setString('system_role', _systemRoleStr!);
      }
      if (_systemRoleLabel != null) {
        await prefs.setString('system_role_label', _systemRoleLabel!);
      }
      await prefs.setBool('is_verified', _isVerified);
      await prefs.setInt('attendance_streak', _attendanceStreak);
      notifyListeners();
    }
  }

  Future<void> refreshConfig() async {
    if (_token == null) return;
    try {
      final result = await _apiService.fetchAppConfig();
      if (result['success'] == true && result['settings'] != null) {
        final newSettings = Map<String, dynamic>.from(result['settings']);
        
        // Only trigger update if settings have changed
        if (json.encode(newSettings) != json.encode(_settings)) {
          _settings = newSettings;
          
          // Cache it for instant loading next time
          final prefs = await SharedPreferences.getInstance();
          await prefs.setString('app_settings', json.encode(_settings));
          notifyListeners();
        }
      }
    } catch (_) {}
  }

  Future<bool> updateAvatar(String base64String) async {
    if (_token == null) return false;
    final result = await _apiService.updateAvatarBase64(base64String);
    if (result['success'] == true && result['avatar'] != null) {
      _avatar = result['avatar'] as String;
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('avatar', _avatar!);
      notifyListeners();
      return true;
    }
    return false;
  }

  Future<void> logout() async {
    final prefs = await SharedPreferences.getInstance();
    // គ្រាន់តែលុប Token ដើម្បីឱ្យឈប់ចូលឆែកទិន្នន័យបាន (Security)
    if (_token != null && _token!.isNotEmpty) {
      try {
        final fcmToken = await _resolveCurrentFcmToken();
        await _apiService.logout(fcmToken: fcmToken);
      } catch (e) {
        debugPrint("Logout revoke failed (ignored locally): $e");
      }
    }

    try {
      FlutterBackgroundService().invoke("stopService");
    } catch (e) {
      debugPrint("Background service stop failed (ignored): $e");
    }

    await prefs.remove('auth_token');
    await prefs.remove('employee_id');
    await prefs.remove('user_name');
    await prefs.remove('avatar');
    await prefs.remove('user_position');
    await prefs.remove('user_phone');
    await prefs.remove('user_email');
    await prefs.remove('scan_user_type');
    await prefs.remove('system_role');
    await prefs.remove('system_role_label');
    await prefs.remove('is_verified');
    await prefs.remove('attendance_streak');
    await prefs.remove('current_active_trip_id');
    await prefs.remove('last_checkin_time');
    await prefs.remove('streak_last_date');
    
    _token = null;
    _employeeId = null;
    _name = null;
    _avatar = null;
    _userType = null;
    _systemRoleStr = null;
    _systemRoleLabel = null;
    _position = null;
    _phone = null;
    _email = null;
    _isLoggedIn = false;
    _isVerified = false;
    _attendanceStreak = 0;
    
    // ចំណាំ៖ យើងមិនលុប _name, _avatar, _employeeId និង _settings ចោលទេ 
    // ដើម្បីឱ្យ Header ខាងលើ និងប៊ូតុង Quick Actions នៅបង្ហាញដដែល (Smooth UI)
    
    notifyListeners();
  }
}
