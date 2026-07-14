import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter_background_service/flutter_background_service.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import '../services/api_service.dart';

/// តួនាទីក្នុងប្រព័ន្ធ HRM
enum SystemRole { employee, worker, skills, it, admin, hrm, accounting }

const List<String> appSystemRoleValues = [
  'Employee',
  'Worker',
  'Skills',
  'IT',
  'HRM',
  'Accounting',
  'Admin',
  'Store318Head',
  'StoreSKKS2Head',
  'StoreNR3Head',
  'StoreSKKS2Deputy',
  'StoreNR3Deputy',
  'WarehousePSPHead',
  'WarehousePRVHead',
  'WarehousePSPAssistant',
  'WarehousePRVAssistant',
  'StockGeneralHead',
  'GeneralManagerSK',
  'GeneralManagerVVC',
  'DirectorGeneral',
];

const Map<String, String> appSystemRoleLabels = {
  'Employee': 'បុគ្គលិក (Employee)',
  'Worker': 'កម្មករ (Worker)',
  'Skills': 'ជំនាញ (Skills)',
  'IT': 'IT',
  'HRM': 'ធនធានមនុស្ស (HRM)',
  'Accounting': 'គណនេយ្យ (Accounting)',
  'Admin': 'Admin',
  'Store318Head': 'ប្រធានហាងទំនិញ 318',
  'StoreSKKS2Head': 'ប្រធានហាង SKKS2',
  'StoreNR3Head': 'ប្រធានហាង NR3',
  'StoreSKKS2Deputy': 'អនុប្រធានហាង SKKS2',
  'StoreNR3Deputy': 'អនុប្រធានហាង NR3',
  'WarehousePSPHead': 'ប្រធានឃ្លាំង PSP',
  'WarehousePRVHead': 'ប្រធានឃ្លាំង PRV',
  'WarehousePSPAssistant': 'ជំនួយការប្រធានឃ្លាំង PSP',
  'WarehousePRVAssistant': 'ជំនួយការប្រធានឃ្លាំង PRV',
  'StockGeneralHead': 'ប្រធានគ្រប់គ្រងស្តុកទំនិញទូទៅ',
  'GeneralManagerSK': 'ប្រធានគ្រប់គ្រងទូទៅ (SK)',
  'GeneralManagerVVC': 'ប្រធានគ្រប់គ្រងទូទៅ (VVC)',
  'DirectorGeneral': 'អគ្គនាយក',
};

const Map<String, String> appRoleVisibilitySuffixes = {
  'employee': '__skill',
  'worker': '__worker',
  'skills': '__skill',
  'it': '__skill',
  'hrm': '__hrm',
  'accounting': '__skill',
  'admin': '__admin',
  'store318head': '__store318_head',
  'storeskks2head': '__store_skks2_head',
  'storenr3head': '__store_nr3_head',
  'storeskks2deputy': '__store_skks2_deputy',
  'storenr3deputy': '__store_nr3_deputy',
  'warehousepsphead': '__warehouse_psp_head',
  'warehouseprvhead': '__warehouse_prv_head',
  'warehousepspassistant': '__warehouse_psp_assistant',
  'warehouseprvassistant': '__warehouse_prv_assistant',
  'stockgeneralhead': '__stock_general_head',
  'generalmanagersk': '__general_manager_sk',
  'generalmanagervvc': '__general_manager_vvc',
  'directorgeneral': '__director_general',
};

String appSystemRoleDisplayLabel(String? roleValue) {
  final value = (roleValue ?? '').trim();
  if (value.isEmpty) return 'Employee';
  return appSystemRoleLabels[value] ?? value;
}

String appVisibilitySuffixForRole(String? roleValue) {
  final key = (roleValue ?? '').trim().toLowerCase();
  return appRoleVisibilitySuffixes[key] ?? '__skill';
}

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
  _legacyUserRole; // user_role from older accounts: Admin, Worker, Employee
  String?
  _systemRoleStr; // system_role from DB, including custom app role values.
  String? _systemRoleLabel; // display label
  String? _department;
  String? _position;
  String? _phone;
  String? _email;
  bool _isLoggedIn = false;
  bool _isVerified = false;
  int _attendanceStreak = 0;
  Map<String, dynamic> _settings = {};

  static const String _recentAccountsKey = 'recent_accounts';

  String? get employeeId => _employeeId;
  String? get name => _name;
  String? get avatar => _avatar;
  String? get token => _token;
  String? get userType => _userType;
  String? get department => _department;
  String? get position => _position;
  String? get phone => _phone;
  String? get email => _email;
  bool get isVerified => _isVerified;
  int get attendanceStreak => _attendanceStreak;
  Map<String, dynamic> get settings => _settings;

  Future<List<Map<String, dynamic>>> getRecentAccounts() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_recentAccountsKey) ?? '[]';
    try {
      final data = json.decode(raw) as List<dynamic>;
      return data
          .whereType<Map<String, dynamic>>()
          .map((item) => Map<String, dynamic>.from(item))
          .toList();
    } catch (_) {
      return [];
    }
  }

  Future<void> addRecentAccount({
    required String employeeId,
    required String name,
    String? avatar,
    String? userType,
  }) async {
    final prefs = await SharedPreferences.getInstance();
    final accounts = await getRecentAccounts();
    final normalizedId = employeeId.trim();
    final existingIndex = accounts.indexWhere(
      (item) => item['employeeId']?.toString().trim() == normalizedId,
    );
    if (existingIndex != -1) {
      accounts.removeAt(existingIndex);
    }

    accounts.insert(
      0,
      {
        'employeeId': normalizedId,
        'name': name.trim(),
        'avatar': avatar ?? '',
        'userType': userType ?? 'Employee',
      },
    );

    if (accounts.length > 6) {
      accounts.removeRange(6, accounts.length);
    }

    await prefs.setString(_recentAccountsKey, json.encode(accounts));
  }

  Future<void> removeRecentAccount(String employeeId) async {
    final prefs = await SharedPreferences.getInstance();
    final accounts = await getRecentAccounts();
    final normalizedId = employeeId.trim();
    final remaining = accounts
        .where((item) => item['employeeId']?.toString().trim() != normalizedId)
        .toList();
    await prefs.setString(_recentAccountsKey, json.encode(remaining));
  }

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
    final String raw = (_settings['material_request_locations'] ?? '')
        .toString();
    if (raw.trim().isEmpty) {
      return ['Main Office (318)', 'Factory 1 (NR3)', 'Factory 2 (KS2)'];
    }
    return raw
        .split(',')
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();
  }

  /// Raw DB system_role string
  String get systemRoleStr => _systemRoleStr ?? 'Employee';

  /// Parsed enum
  SystemRole get systemRole => systemRoleFromString(_effectiveSystemRoleString);

  /// Label for display (ខ្មែរ + English)
  String get systemRoleLabel {
    final customLabel = (_systemRoleLabel ?? '').trim();
    if (customLabel.isNotEmpty) return customLabel;
    return appSystemRoleDisplayLabel(_effectiveSystemRoleString);
  }

  String get roleVisibilitySuffix =>
      appVisibilitySuffixForRole(_effectiveSystemRoleString);

  bool get isAdmin => systemRole.isAdminLevel;
  bool get isHRM => systemRole.isHrmLevel;
  bool get isAccounting => systemRole.isAccountingLevel;
  bool get isIT => systemRole.isITLevel;

  final ApiService _apiService = ApiService();

  String get _effectiveSystemRoleString {
    final systemRole = (_systemRoleStr ?? '').trim();
    final legacyRole = (_legacyUserRole ?? '').trim();

    if (systemRole.isNotEmpty && systemRole.toLowerCase() != 'employee') {
      return systemRole;
    }
    if (legacyRole.toLowerCase() == 'worker') {
      return 'Worker';
    }
    if (legacyRole.toLowerCase() == 'admin') {
      return 'Admin';
    }
    return systemRole.isNotEmpty ? systemRole : 'Employee';
  }

  String _resolveSystemRoleString(dynamic systemRole, dynamic legacyRole) {
    final systemRoleText = (systemRole ?? '').toString().trim();
    final legacyRoleText = (legacyRole ?? '').toString().trim();
    if (systemRoleText.isNotEmpty &&
        systemRoleText.toLowerCase() != 'employee') {
      return systemRoleText;
    }
    if (legacyRoleText.toLowerCase() == 'worker') return 'Worker';
    if (legacyRoleText.toLowerCase() == 'admin') return 'Admin';
    return systemRoleText.isNotEmpty ? systemRoleText : 'Employee';
  }

  Future<void> loadSavedUser() async {
    final prefs = await SharedPreferences.getInstance();
    _token = prefs.getString('auth_token');
    _employeeId = prefs.getString('employee_id');
    _name = prefs.getString('user_name');
    _avatar = prefs.getString('avatar');
    _userType = prefs.getString('scan_user_type');
    _legacyUserRole = prefs.getString('user_role');
    _systemRoleStr = prefs.getString('system_role') ?? 'Employee';
    _systemRoleLabel = prefs.getString('system_role_label') ?? '';
    _department = prefs.getString('user_department');
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
              : (defaultTargetPlatform == TargetPlatform.android
                    ? 'Android'
                    : 'iOS');

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
      _department = result['user']['department'] as String?;
      _position = result['user']['position'] as String?;
      _phone = result['user']['phone']?.toString();
      _email = result['user']['email'] as String?;
      _userType = userType;
      _legacyUserRole = result['user']['role']?.toString();
      // Pull system_role from server response (new fields)
      _systemRoleStr = _resolveSystemRoleString(
        result['user']['system_role'],
        result['user']['role'],
      );
      _systemRoleLabel = (result['user']['system_role_label'] as String?) ?? '';
      _isVerified = (result['user']['is_verified'] ?? 0).toString() == '1';
      _attendanceStreak =
          int.tryParse(
            result['user']['attendance_streak']?.toString() ?? '0',
          ) ??
          0;
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
      if (_department != null && _department!.isNotEmpty) {
        await prefs.setString('user_department', _department!);
      } else {
        await prefs.remove('user_department');
      }
      if (_phone != null) await prefs.setString('user_phone', _phone!);
      if (_email != null) await prefs.setString('user_email', _email!);
      await prefs.setString('scan_user_type', _userType!);
      if (_legacyUserRole != null && _legacyUserRole!.isNotEmpty) {
        await prefs.setString('user_role', _legacyUserRole!);
      } else {
        await prefs.remove('user_role');
      }
      await prefs.setString('system_role', _systemRoleStr!);
      await prefs.setString('system_role_label', _systemRoleLabel!);
      await prefs.setBool('is_verified', _isVerified);
      await prefs.setInt('attendance_streak', _attendanceStreak);
      await addRecentAccount(
        employeeId: _employeeId!,
        name: _name ?? _employeeId!,
        avatar: _avatar,
        userType: _userType ?? 'Employee',
      );

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
      _department = user['department'] as String?;
      _legacyUserRole = user['role']?.toString() ?? _legacyUserRole;
      _systemRoleStr = _resolveSystemRoleString(
        user['system_role'],
        user['role'],
      );
      _systemRoleLabel =
          (user['system_role_label'] as String?) ?? _systemRoleLabel ?? '';
      _isVerified = (user['is_verified'] ?? 0).toString() == '1';
      _attendanceStreak =
          int.tryParse(user['attendance_streak']?.toString() ?? '0') ?? 0;

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
      if (_department != null && _department!.isNotEmpty) {
        await prefs.setString('user_department', _department!);
      } else {
        await prefs.remove('user_department');
      }
      if (_phone != null) await prefs.setString('user_phone', _phone!);
      if (_email != null) await prefs.setString('user_email', _email!);
      if (_legacyUserRole != null && _legacyUserRole!.isNotEmpty) {
        await prefs.setString('user_role', _legacyUserRole!);
      }
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
    await prefs.remove('user_department');
    await prefs.remove('user_phone');
    await prefs.remove('user_email');
    await prefs.remove('scan_user_type');
    await prefs.remove('user_role');
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
    _legacyUserRole = null;
    _systemRoleStr = null;
    _systemRoleLabel = null;
    _department = null;
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
