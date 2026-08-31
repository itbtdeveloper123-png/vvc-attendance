import 'dart:async';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'api_service.dart';

class AuthenticatorAccount {
  final String id;
  final String name;
  final String issuer;
  final String secret;
  final DateTime createdAt;

  AuthenticatorAccount({
    required this.id,
    required this.name,
    required this.issuer,
    required this.secret,
    required this.createdAt,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'issuer': issuer,
        'secret': secret,
        'created_at': createdAt.toIso8601String(),
      };

  factory AuthenticatorAccount.fromJson(Map<String, dynamic> json) =>
      AuthenticatorAccount(
        id: json['id']?.toString() ?? DateTime.now().millisecondsSinceEpoch.toString(),
        name: json['name']?.toString() ?? 'VVC Admin',
        issuer: json['issuer']?.toString() ?? 'VVC Attendance',
        secret: json['secret']?.toString().toUpperCase().replaceAll(' ', '') ?? '',
        createdAt: json['created_at'] != null
            ? DateTime.tryParse(json['created_at']) ?? DateTime.now()
            : DateTime.now(),
      );
}

class TotpHelper {
  static const String _base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  static Uint8List base32Decode(String input) {
    String sanitized = input.replaceAll('=', '').replaceAll(' ', '').toUpperCase();
    List<int> bytes = [];
    int buffer = 0;
    int bitsLeft = 0;

    for (int i = 0; i < sanitized.length; i++) {
      int val = _base32Chars.indexOf(sanitized[i]);
      if (val < 0) continue;
      buffer = (buffer << 5) | val;
      bitsLeft += 5;
      if (bitsLeft >= 8) {
        bitsLeft -= 8;
        bytes.add((buffer >> bitsLeft) & 0xFF);
      }
    }
    return Uint8List.fromList(bytes);
  }

  /// Calculates 6-digit TOTP code for the given Base32 secret
  static String generateTotp(String secret, {int? timeSlice}) {
    try {
      final currentSlice = timeSlice ?? (DateTime.now().toUtc().millisecondsSinceEpoch ~/ 30000);
      final keyBytes = base32Decode(secret);
      if (keyBytes.isEmpty) return '000000';

      // 8-byte big-endian representation of timeSlice
      final timeBytes = Uint8List(8);
      final byteData = ByteData.view(timeBytes.buffer);
      byteData.setInt64(0, currentSlice, Endian.big);

      final hmac = Hmac(sha1, keyBytes);
      final digest = hmac.convert(timeBytes);
      final hmacBytes = digest.bytes;

      final offset = hmacBytes[hmacBytes.length - 1] & 0x0F;
      final binaryCode = ((hmacBytes[offset] & 0x7F) << 24) |
          ((hmacBytes[offset + 1] & 0xFF) << 16) |
          ((hmacBytes[offset + 2] & 0xFF) << 8) |
          (hmacBytes[offset + 3] & 0xFF);

      final otp = binaryCode % 1000000;
      return otp.toString().padLeft(6, '0');
    } catch (e) {
      debugPrint('Error generating TOTP: $e');
      return '000000';
    }
  }

  /// Seconds remaining in current 30s window (1 to 30)
  static int getRemainingSeconds() {
    final nowSeconds = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
    final remaining = 30 - (nowSeconds % 30);
    return remaining == 0 ? 30 : remaining;
  }

  /// Progress from 0.0 to 1.0
  static double getRemainingProgress() {
    return getRemainingSeconds() / 30.0;
  }

  /// Parses otpauth://totp/Issuer:Account?secret=XXX or plain secret text
  static Map<String, String>? parseOtpAuthUri(String rawData) {
    try {
      final text = rawData.trim();
      if (text.startsWith('otpauth://')) {
        final uri = Uri.parse(text);
        if (uri.host == 'totp' || uri.path.contains('totp')) {
          String path = Uri.decodeComponent(uri.path).replaceFirst('/', '');
          if (path.startsWith('totp/')) {
            path = path.replaceFirst('totp/', '');
          }
          String account = path;
          String issuer = uri.queryParameters['issuer'] ?? 'VVC Attendance';

          if (path.contains(':')) {
            final parts = path.split(':');
            issuer = parts[0].trim();
            account = parts.sublist(1).join(':').trim();
          }

          final secret = uri.queryParameters['secret'] ?? '';
          if (secret.isNotEmpty) {
            return {
              'account': account.isNotEmpty ? account : 'Admin',
              'issuer': issuer.isNotEmpty ? issuer : 'VVC Attendance',
              'secret': secret.toUpperCase().replaceAll(' ', ''),
            };
          }
        }
      }

      // If raw secret or URL with secret= param
      if (text.contains('secret=')) {
        final uri = Uri.tryParse(text);
        final secret = uri?.queryParameters['secret'] ?? '';
        if (secret.isNotEmpty) {
          return {
            'account': 'VVC Account',
            'issuer': 'VVC Attendance',
            'secret': secret.toUpperCase().replaceAll(' ', ''),
          };
        }
      }

      // If alphanumeric base32 key directly
      final clean = text.replaceAll(' ', '').toUpperCase();
      if (clean.length >= 8 && RegExp(r'^[A-Z2-7]+$').hasMatch(clean)) {
        return {
          'account': 'VVC Admin',
          'issuer': 'VVC Attendance',
          'secret': clean,
        };
      }

      return null;
    } catch (e) {
      debugPrint('Failed to parse OTP URI: $e');
      return null;
    }
  }
}

class AuthenticatorService {
  static const String _prefsKey = 'vvc_authenticator_accounts_v1';
  static const String _twoFaEnabledKey = 'vvc_2fa_enabled_local';

  static final AuthenticatorService _instance = AuthenticatorService._internal();
  factory AuthenticatorService() => _instance;
  AuthenticatorService._internal();

  /// Load saved accounts
  Future<List<AuthenticatorAccount>> getAccounts() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final jsonStr = prefs.getString(_prefsKey);
      if (jsonStr != null && jsonStr.isNotEmpty) {
        final List list = jsonDecode(jsonStr);
        return list.map((e) => AuthenticatorAccount.fromJson(e)).toList();
      }
    } catch (e) {
      debugPrint('Failed to load accounts: $e');
    }

    // Default Seed Account for VVC Attendance Admin
    final defaultAcc = AuthenticatorAccount(
      id: 'default_vvc_admin',
      name: 'Super Administrator',
      issuer: 'VVC Attendance',
      secret: 'VVCATTENDANCE2FAKEY2026',
      createdAt: DateTime.now(),
    );
    await saveAccount(defaultAcc);
    return [defaultAcc];
  }

  /// Save / Add an account
  Future<void> saveAccount(AuthenticatorAccount account) async {
    try {
      final accounts = await getAccounts();
      accounts.removeWhere((a) => a.id == account.id || a.secret == account.secret);
      accounts.insert(0, account);

      final prefs = await SharedPreferences.getInstance();
      final list = accounts.map((a) => a.toJson()).toList();
      await prefs.setString(_prefsKey, jsonEncode(list));
    } catch (e) {
      debugPrint('Failed to save account: $e');
    }
  }

  /// Delete an account
  Future<void> deleteAccount(String id) async {
    try {
      final accounts = await getAccounts();
      accounts.removeWhere((a) => a.id == id);
      final prefs = await SharedPreferences.getInstance();
      final list = accounts.map((a) => a.toJson()).toList();
      await prefs.setString(_prefsKey, jsonEncode(list));
    } catch (e) {
      debugPrint('Failed to delete account: $e');
    }
  }

  /// Get 2FA Enabled status from Backend
  Future<bool> get2FaStatus(String employeeId) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final localVal = prefs.getBool('${_twoFaEnabledKey}_$employeeId');

      final url = Uri.parse(ApiService.baseUrl.replaceAll('api.php', 'admin_api.php'));
      final res = await http.post(url, body: {
        'action': 'get_2fa_status',
        'employee_id': employeeId,
      }).timeout(const Duration(seconds: 8));

      if (res.statusCode == 200) {
        final data = jsonDecode(res.body);
        if (data['success'] == true && data['is_enabled'] != null) {
          final isEnabled = data['is_enabled'] == 1 || data['is_enabled'] == true;
          await prefs.setBool('${_twoFaEnabledKey}_$employeeId', isEnabled);
          return isEnabled;
        }
      }
      return localVal ?? true;
    } catch (e) {
      debugPrint('Failed to fetch 2FA status from server: $e');
      final prefs = await SharedPreferences.getInstance();
      return prefs.getBool('${_twoFaEnabledKey}_$employeeId') ?? true;
    }
  }

  /// Toggle / Set 2FA Enabled status on Backend (Also disables/enables it on Admin Panel!)
  Future<bool> toggle2FaStatus(String employeeId, bool isEnabled) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool('${_twoFaEnabledKey}_$employeeId', isEnabled);

      final url = Uri.parse(ApiService.baseUrl.replaceAll('api.php', 'admin_api.php'));
      final res = await http.post(url, body: {
        'action': 'toggle_2fa_status',
        'employee_id': employeeId,
        'is_enabled': isEnabled ? '1' : '0',
      }).timeout(const Duration(seconds: 10));

      if (res.statusCode == 200) {
        final data = jsonDecode(res.body);
        return data['success'] == true;
      }
      return true;
    } catch (e) {
      debugPrint('Failed to toggle 2FA status: $e');
      return true; // Saved locally
    }
  }
}
