import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:dio/dio.dart' as dio;
import 'package:dio/io.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'local_db_service.dart';
import 'secure_storage_service.dart';

class ApiService {
  static const bool _isLocalMode = false;

  static const String _primaryBaseUrl = 'https://app.vvc.asia/flutter/api.php';
  static const String _fallbackV4BaseUrl =
      'https://104.21.2.219/flutter/api.php';

  static String get baseUrl {
    if (_isLocalMode) {
      const String localIp = '10.0.2.2';
      return 'http://$localIp/Vvc-Attendace/api.php';
    } else {
      return _primaryBaseUrl;
    }
  }

  static bool _preferIPv4 = false;

  static String get effectiveBaseUrl {
    if (_isLocalMode) return baseUrl;
    return _preferIPv4 ? _fallbackV4BaseUrl : _primaryBaseUrl;
  }

  static http.Client _buildHttpClient({bool forceIPv4 = false}) {
    if (kIsWeb) return http.Client();
    final ioClient = HttpClient();
    
    // Enable modern TLS protocols
    ioClient.badCertificateCallback =
        (X509Certificate cert, String host, int port) {
      // Allow certificates for specific domains
      if (host == '104.21.2.219' ||
          host == '172.67.129.187' ||
          host == 'app.vvc.asia' ||
          host == 'vvc.asia') {
        // Check if certificate is from trusted issuer
        if (cert.issuer.contains('Cloudflare') || 
            cert.issuer.contains('Let\'s Encrypt') ||
            cert.subject.contains('vvc.asia')) {
          return true;
        }
      }
      return false;
    };
    
    // Set connection timeout
    if (forceIPv4 || _preferIPv4) {
      ioClient.connectionTimeout = const Duration(seconds: 12);
    } else {
      ioClient.connectionTimeout = const Duration(seconds: 15);
    }
    
    return IOClient(ioClient);
  }

  static bool _isSocketBindError(Object e) {
    final s = e.toString();
    return s.contains('Can\'t assign requested address') ||
        s.contains('Cannot assign requested address') ||
        s.contains('EADDRNOTAVAIL') ||
        s.contains('SocketException: Failed host lookup') ||
        (e is SocketException &&
            (e.osError?.errorCode == 99 ||
                e.osError?.errorCode == 10049 ||
                e.toString().contains('address')));
  }

  static String _friendlyError(Object e) {
    final s = e.toString();
    if (_isSocketBindError(e)) {
      return 'មិនអាចភ្ជាប់បាន៖ Network មិនគាំទ្រ IPv6។ កំពុងប្តូរទៅ IPv4...';
    }
    if (s.contains('Connection refused') || s.contains('connection failed')) {
      return 'មិនអាចភ្ជាប់ទៅ Server បាន។ សូមពិនិត្យអ៊ីនធឺណិត';
    }
    if (s.contains('Connection timed out') || s.contains('TimeoutException')) {
      return 'Server ឆ្លើយតបយឺតពេក។ សូមព្យាយាមម្តងទៀត';
    }
    if (s.contains('SSLV3_ALERT_HANDSHAKE_FAILURE') || s.contains('HANDSHAKE_FAILURE')) {
      return 'កំហុស SSL Handshake៖ កំពុងព្យាយាមភ្ជាប់ឡើងវិញ...';
    }
    if (s.contains('certificate') || s.contains('CERTIFICATE_VERIFY_FAILED')) {
      return 'កំហុស SSL Certificate៖ កាលបរិច្ឆេទទូរស័ព្ទមិនត្រឹមត្រូវ';
    }
    return 'កំហុសការភ្ជាប់៖ $s';
  }

  static Future<T> _withRetry<T>(
    Future<T> Function({required bool forceIPv4}) fn, {
    int maxAttempts = 3,
  }) async {
    Object? lastError;
    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        final tryForceIPv4 = _preferIPv4 || attempt >= 2;
        return await fn(forceIPv4: tryForceIPv4);
      } catch (e) {
        lastError = e;
        final bindFail = _isSocketBindError(e);
        final sslFail = e.toString().contains('SSLV3_ALERT_HANDSHAKE_FAILURE') || 
                       e.toString().contains('HANDSHAKE_FAILURE');
        
        if (bindFail) {
          _preferIPv4 = true;
          debugPrint(
              'Detected IPv6 bind failure — switched to IPv4 mode. Attempt $attempt/$maxAttempts');
        }
        
        if (sslFail) {
          debugPrint('SSL Handshake failure — retrying with different configuration. Attempt $attempt/$maxAttempts');
          // Force IPv4 on SSL failures as well
          _preferIPv4 = true;
        }
        
        if (attempt < maxAttempts) {
          final delayMs = (bindFail || sslFail) ? 500 : 400 * attempt;
          await Future<void>.delayed(Duration(milliseconds: delayMs));
          continue;
        }
      }
    }
    if (lastError != null) throw lastError;
    throw StateError('Retry failed');
  }

  static String getFullImageUrl(String? relativePath) {
    if (relativePath == null || relativePath.isEmpty) return '';
    if (relativePath.startsWith('http')) return relativePath;
    if (relativePath.startsWith('/') ||
        relativePath.startsWith('C:') ||
        relativePath.contains('/data/user/') ||
        relativePath.contains('/storage/')) {
      return relativePath;
    }
    String path = relativePath;
    if (path.startsWith('/')) path = path.substring(1);
    final apiUri = Uri.parse(baseUrl);
    final baseDir = apiUri.toString().replaceAll('api.php', '');
    return '$baseDir$path';
  }

  static const String publicReportUrl =
      'https://app.vvc.asia/flutter/public_report.php';
  static const String publicReportFallbackV4 =
      'https://104.21.2.219/flutter/public_report.php';

  static String get effectivePublicReportUrl =>
      _preferIPv4 ? publicReportFallbackV4 : publicReportUrl;

  Future<http.Response> postPublicReport(Map<String, String> body) async {
    return _withRetry<http.Response>(
        ({required bool forceIPv4}) async {
      final client = _buildHttpClient(forceIPv4: forceIPv4);
      try {
        final hdrs = <String, String>{
          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
          if (forceIPv4 || _preferIPv4) 'Host': 'app.vvc.asia',
        };
        return await client
            .post(Uri.parse(effectivePublicReportUrl),
                headers: hdrs, body: body)
            .timeout(const Duration(seconds: 20));
      } finally {
        client.close();
      }
    });
  }

  Future<Map<String, String>> _authHeaders() async {
    String? token;
    try {
      final secureStorage = SecureStorageService();
      token = await secureStorage.read('auth_token');
    } catch (_) {}

    if (token == null || token.isEmpty) {
      final prefs = await SharedPreferences.getInstance();
      token = prefs.getString('auth_token') ?? '';
    }
    return {'Authorization': 'Bearer $token', 'Accept': 'application/json'};
  }

  /// Public method to get auth headers (used by OCR service)
  Future<Map<String, String>> getAuthHeaders() async {
    return _authHeaders();
  }

  Future<Map<String, dynamic>> _processRequest(
    String action, {
    Map<String, String>? body,
    Map<String, String>? headers,
    Duration timeout = const Duration(seconds: 30),
  }) async {
    try {
      return await _withRetry<Map<String, dynamic>>(
          ({required bool forceIPv4}) async {
        final client = _buildHttpClient(forceIPv4: forceIPv4);
        try {
          final finalBody = body != null
              ? Map<String, String>.from(body)
              : <String, String>{};
          finalBody['action'] = action;

          final requestHeaders = headers != null
              ? Map<String, String>.from(headers)
              : <String, String>{};
          requestHeaders['Content-Type'] =
              'application/x-www-form-urlencoded; charset=UTF-8';
          if (forceIPv4 || _preferIPv4) {
            requestHeaders['Host'] = 'app.vvc.asia';
          }

          final uri = Uri.parse(effectiveBaseUrl);
          final response = await client
              .post(uri, headers: requestHeaders, body: finalBody)
              .timeout(timeout);

          return await _handleResponse(response);
        } finally {
          client.close();
        }
      });
    } catch (e) {
      return {
        'success': false,
        'status': 'error',
        'message': _friendlyError(e),
      };
    }
  }

  static dynamic _parseJsonPayload(String payload) {
    return json.decode(payload);
  }

  Future<Map<String, dynamic>> _handleResponse(http.Response response) async {
    debugPrint('API Response Status: ${response.statusCode}');
    debugPrint('API Response Body Length: ${response.body.length}');
    
    if (response.body.isEmpty) {
      debugPrint('Error: Empty response from server');
      return {
        'success': false,
        'status': 'error',
        'message':
            'Server returns empty response (Status: ${response.statusCode})',
      };
    }
    
    debugPrint('API Response Preview: ${response.body.length > 100 ? response.body.substring(0, 100) : response.body}...');
    
    try {
      final decoded = await compute(_parseJsonPayload, response.body);
      if (decoded is Map<String, dynamic>) {
        debugPrint('API Response Success: ${decoded['success']}');
        return decoded;
      }
      debugPrint('Error: Invalid JSON format - not a Map');
      return {
        'success': false,
        'status': 'error',
        'message': 'Invalid JSON format from server',
      };
    } catch (e) {
      debugPrint('JSON Parse Error: $e');
      String preview = response.body.length > 100
          ? '${response.body.substring(0, 100)}...'
          : response.body;
      return {
        'success': false,
        'status': 'error',
        'message': 'JSON Format Error: $e\nResponse: $preview',
      };
    }
  }

  Future<Map<String, dynamic>> login(String employeeId, String userType) async {
    return _processRequest(
      'api_login',
      body: {'employee_id': employeeId, 'scan_user_type': userType},
    );
  }

  // Test method to check API connectivity
  Future<Map<String, dynamic>> testApi() async {
    return _processRequest('test');
  }

  // Generic GET method for compatibility
  Future<Map<String, dynamic>> get(String action) async {
    return _processRequest(action);
  }

  // Generic POST method for compatibility
  Future<Map<String, dynamic>> post(String action, Map<String, dynamic> body) async {
    return _processRequest(
      action,
      body: body.map((key, value) => MapEntry(key, value.toString())),
    );
  }

  Future<Map<String, dynamic>> reverseGeocode(
    double latitude,
    double longitude,
  ) async {
    final headers = await _authHeaders();
    return _processRequest(
      'reverse_geocode',
      headers: headers,
      body: {
        'latitude': latitude.toString(),
        'longitude': longitude.toString(),
      },
    );
  }

  Future<Map<String, dynamic>> fetchDashboardStats() async {
    final headers = await _authHeaders();
    return _processRequest('get_dashboard_stats', headers: headers);
  }

  Future<Map<String, dynamic>> fetchProfile({String? employeeId}) async {
    final headers = await _authHeaders();
    final body = employeeId != null ? {'employee_id': employeeId} : null;
    return _processRequest('get_profile', headers: headers, body: body);
  }

  Future<Map<String, dynamic>> updateAvatarBase64(String base64String) async {
    final headers = await _authHeaders();
    return _processRequest(
      'update_avatar',
      headers: headers,
      body: {'avatar_base64': base64String},
    );
  }

  Future<Map<String, dynamic>> checkAppVersion(
    String version,
    int buildNumber,
  ) async {
    final headers = await _authHeaders();
    return _processRequest(
      'check_update',
      headers: headers,
      body: {'version': version, 'build_number': buildNumber.toString()},
    );
  }

  Future<Map<String, dynamic>> fetchAppConfig() async {
    final headers = await _authHeaders();
    return _processRequest('get_app_config', headers: headers);
  }

  Future<Map<String, dynamic>> createAiChatSession({String? title}) async {
    final headers = await _authHeaders();
    final body = <String, String>{};
    if (title != null && title.trim().isNotEmpty) {
      body['title'] = title.trim();
    }
    return _processRequest(
      'create_ai_chat_session',
      headers: headers,
      body: body,
    );
  }

  Future<Map<String, dynamic>> getAiChatSessions({int limit = 20}) async {
    final headers = await _authHeaders();
    return _processRequest(
      'get_ai_chat_sessions',
      headers: headers,
      body: {'limit': limit.toString()},
    );
  }

  Future<Map<String, dynamic>> getAiChatHistory(int sessionId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'get_ai_chat_history',
      headers: headers,
      body: {'session_id': sessionId.toString()},
    );
  }

  Future<Map<String, dynamic>> deleteAiChatSession(int sessionId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'delete_ai_chat_session',
      headers: headers,
      body: {'session_id': sessionId.toString()},
    );
  }

  Future<Map<String, dynamic>> deleteAllAiChatSessions() async {
    final headers = await _authHeaders();
    return _processRequest('delete_all_ai_chat_sessions', headers: headers);
  }

  Future<Map<String, dynamic>> sendAiChatMessage(
    String message, {
    int? sessionId,
  }) async {
    final headers = await _authHeaders();
    final body = <String, String>{'message': message};
    if (sessionId != null && sessionId > 0) {
      body['session_id'] = sessionId.toString();
    }
    return _processRequest(
      'send_ai_chat_message',
      headers: headers,
      body: body,
    );
  }

  Future<Map<String, dynamic>> removeAiChatImageBackground(
    String imageBase64, {
    int? sessionId,
  }) async {
    final headers = await _authHeaders();
    final body = <String, String>{'image_base64': imageBase64};
    if (sessionId != null && sessionId > 0) {
      body['session_id'] = sessionId.toString();
    }
    return _processRequest(
      'remove_ai_chat_image_background',
      headers: headers,
      body: body,
      timeout: const Duration(minutes: 3),
    );
  }

  /// Analyze a product image using AI Vision.
  /// [imageBase64] — full base64 string (may include data: prefix)
  /// [barcode]     — optional barcode/QR text already scanned
  Future<Map<String, dynamic>> analyzeProductImage({
    String imageBase64 = '',
    String barcode = '',
  }) async {
    final headers = await _authHeaders();
    final body = <String, String>{};
    if (imageBase64.isNotEmpty) body['image_base64'] = imageBase64;
    if (barcode.isNotEmpty) body['barcode'] = barcode;
    return _processRequest(
      'analyze_product_image',
      headers: headers,
      body: body,
      timeout: const Duration(minutes: 15),
    );
  }

  Future<Map<String, dynamic>> regenerateAiChatReply(int sessionId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'regenerate_ai_chat_reply',
      headers: headers,
      body: {'session_id': sessionId.toString()},
    );
  }

  Future<Map<String, dynamic>> fetchTrainingQuestions() async {
    final headers = await _authHeaders();
    return _processRequest('get_training_questions', headers: headers);
  }

  Future<Map<String, dynamic>> fetchActivePolls() async {
    final headers = await _authHeaders();
    return _processRequest('get_active_polls', headers: headers);
  }

  Future<Map<String, dynamic>> castVote(int pollId, String candidateEmployeeId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'cast_vote',
      headers: headers,
      body: {
        'poll_id': pollId.toString(),
        'candidate_employee_id': candidateEmployeeId,
      },
    );
  }

  Future<Map<String, dynamic>> savePoll({
    int? id,
    required String title,
    required String quarter,
    required String location,
    required String startDate,
    required String endDate,
    required String passcode,
    required List<String> excludedCandidates,
    required List<Map<String, dynamic>> candidates,
  }) async {
    final headers = await _authHeaders();
    final body = <String, String>{
      'title': title,
      'quarter': quarter,
      'location': location,
      'start_date': startDate,
      'end_date': endDate,
      'access_code': passcode,
      'passcode': passcode,
      'excluded_candidates': jsonEncode(excludedCandidates),
      'candidates': jsonEncode(candidates),
    };
    if (id != null && id > 0) {
      body['id'] = id.toString();
    }
    return _processRequest('save_poll', headers: headers, body: body);
  }

  Future<Map<String, dynamic>> createPoll({
    required String title,
    required String quarter,
    required String location,
    required String startDate,
    required String endDate,
    required String passcode,
    required List<String> excludedCandidates,
    required List<Map<String, dynamic>> candidates,
  }) async {
    return savePoll(
      title: title,
      quarter: quarter,
      location: location,
      startDate: startDate,
      endDate: endDate,
      passcode: passcode,
      excludedCandidates: excludedCandidates,
      candidates: candidates,
    );
  }

  Future<Map<String, dynamic>> deletePoll(int pollId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'delete_poll',
      headers: headers,
      body: {
        'id': pollId.toString(),
      },
    );
  }

  // ========== ATTENDANCE & SYNC ==========
  Future<Map<String, dynamic>> submitAttendance({
    required String action,
    required String employeeId,
    required String workplace,
    required String branch,
    required String locationRaw,
    required String qrSecret,
    required int qrLocationId,
    String? lateReason,
    double? manualDistance,
    String? manualLocationName,
    String? photoBase64,
    bool biometricVerified = false,
  }) async {
    final headers = await _authHeaders();
    final body = <String, String>{
      'action': action,
      'workplace': workplace,
      'branch': branch,
      'user_location_raw': locationRaw,
      'qr_secret': qrSecret,
      'qr_location_id': qrLocationId.toString(),
      'biometric_verified': biometricVerified ? '1' : '0',
    };
    if (lateReason != null) body['late_reason'] = lateReason;
    if (manualDistance != null) {
      body['manual_distance'] = manualDistance.toString();
    }
    if (manualLocationName != null) {
      body['manual_location_name'] = manualLocationName;
    }
    if (photoBase64 != null) body['photo_base64'] = photoBase64;

    try {
      return await _withRetry<Map<String, dynamic>>(
          ({required bool forceIPv4}) async {
        final client = _buildHttpClient(forceIPv4: forceIPv4);
        try {
          final requestHeaders = Map<String, String>.from(headers);
          requestHeaders['Content-Type'] =
              'application/x-www-form-urlencoded; charset=UTF-8';
          if (forceIPv4 || _preferIPv4) {
            requestHeaders['Host'] = 'app.vvc.asia';
          }

          final uri = Uri.parse(effectiveBaseUrl);
          final response = await client
              .post(uri, headers: requestHeaders, body: body)
              .timeout(const Duration(seconds: 15));

          if (response.statusCode == 200) return json.decode(response.body);
          return {
            'success': false,
            'message': 'Server error: ${response.statusCode}',
          };
        } finally {
          client.close();
        }
      });
    } catch (e) {
      if (kIsWeb) {
        return {
          'success': false,
          'status': 'error',
          'message': 'កំហុសការភ្ជាប់ (Web): ${_friendlyError(e)}',
        };
      }
      final dbService = LocalDbService();
      await dbService.insertPunch({
        'action': action,
        'employee_id': employeeId,
        'workplace': workplace,
        'branch': branch,
        'location_raw': locationRaw,
        'qr_secret': qrSecret,
        'qr_location_id': qrLocationId,
        'late_reason': lateReason ?? '',
        'manual_distance': manualDistance ?? 0.0,
        'manual_location_name': manualLocationName ?? '',
        'timestamp': DateTime.now().toIso8601String(),
        'synced': 0,
      });
      return {
        'success': true,
        'status': 'offline',
        'message':
            'រក្សាទុកសម្រាប់ Offline! វានឹង Sync ទៅ Server ពេលមានអ៊ីនធឺណិតវិញ។',
      };
    }
  }

  // ========== FACE REGISTRATION ==========

  /// ចុះឈ្មោះ Face ថ្មី (ផ្ញើ photos base64 ៣ ដង)
  Future<Map<String, dynamic>> registerFace(List<String> photosBase64) async {
    final headers = await _authHeaders();
    final requestHeaders = Map<String, String>.from(headers);
    requestHeaders['Content-Type'] =
        'application/x-www-form-urlencoded; charset=UTF-8';

    final body = <String, String>{
      'action': 'register_face',
      'photos_json': json.encode(photosBase64),
    };

    try {
      return await _withRetry<Map<String, dynamic>>(
          ({required bool forceIPv4}) async {
        final client = _buildHttpClient(forceIPv4: forceIPv4);
        try {
          final hdrs = Map<String, String>.from(requestHeaders);
          if (forceIPv4 || _preferIPv4) hdrs['Host'] = 'app.vvc.asia';
          final uri = Uri.parse(effectiveBaseUrl);
          final response = await client
              .post(uri, headers: hdrs, body: body)
              .timeout(const Duration(seconds: 30));
          if (response.statusCode == 200) return json.decode(response.body);
          return {
            'success': false,
            'message': 'Server error: ${response.statusCode}',
          };
        } finally {
          client.close();
        }
      });
    } catch (e) {
      return {'success': false, 'message': _friendlyError(e)};
    }
  }

  /// ពិនិត្យថាតើ Face ត្រូវបានចុះឈ្មោះ ឬ យ៉ាង
  Future<Map<String, dynamic>> getFaceStatus() async {
    final headers = await _authHeaders();
    return _processRequest('get_face_status', headers: headers);
  }

  /// លុបការចុះឈ្មោះ Face (admin ឬ ខ្លួនឯង)
  Future<Map<String, dynamic>> deleteFaceRegistration({
    String? employeeId,
  }) async {
    final headers = await _authHeaders();
    final body = <String, String>{};
    if (employeeId != null) body['target_employee_id'] = employeeId;
    return _processRequest('delete_face', body: body, headers: headers);
  }

  /// ផ្ទៀងផ្ទាត់ Face ក្នុងពេល Attendance (ប្រៀបធៀបជាមួយ reference)
  Future<Map<String, dynamic>> verifyFace(String photoBase64) async {
    final headers = await _authHeaders();
    final requestHeaders = Map<String, String>.from(headers);
    requestHeaders['Content-Type'] =
        'application/x-www-form-urlencoded; charset=UTF-8';
    final body = <String, String>{
      'action': 'verify_face',
      'photo_base64': photoBase64,
    };
    try {
      return await _withRetry<Map<String, dynamic>>(
          ({required bool forceIPv4}) async {
        final client = _buildHttpClient(forceIPv4: forceIPv4);
        try {
          final hdrs = Map<String, String>.from(requestHeaders);
          if (forceIPv4 || _preferIPv4) hdrs['Host'] = 'app.vvc.asia';
          final uri = Uri.parse(effectiveBaseUrl);
          final response = await client
              .post(uri, headers: hdrs, body: body)
              .timeout(const Duration(seconds: 20));
          if (response.statusCode == 200) return json.decode(response.body);
          return {
            'success': false,
            'message': 'Server error: ${response.statusCode}',
          };
        } finally {
          client.close();
        }
      });
    } catch (e) {
      return {'success': false, 'message': _friendlyError(e)};
    }
  }

  /// ទទួលបញ្ជីអ្នកចុះឈ្មោះ Face (admin only)
  Future<Map<String, dynamic>> getFaceRegistrations() async {
    final headers = await _authHeaders();
    return _processRequest('get_face_registrations', headers: headers);
  }

  Future<void> syncOfflineAttendance() async {
    if (kIsWeb) return;
    final dbService = LocalDbService();
    final unsynced = await dbService.getUnsyncedPunches();

    if (unsynced.isEmpty) return;
    debugPrint('Syncing ${unsynced.length} offline records...');
    final headers = await _authHeaders();
    for (var punch in unsynced) {
      try {
        final body = <String, String>{
          'action': punch['action'],
          'workplace': punch['workplace'] ?? '',
          'branch': punch['branch'] ?? '',
          'user_location_raw': punch['location_raw'] ?? '',
          'qr_secret': punch['qr_secret'] ?? '',
          'qr_location_id': punch['qr_location_id'].toString(),
          'late_reason': punch['late_reason'] ?? '',
          'manual_distance': punch['manual_distance'].toString(),
          'manual_location_name': punch['manual_location_name'] ?? '',
          'offline_timestamp': punch['timestamp'] ?? '',
        };
        final response = await _withRetry<http.Response>(
            ({required bool forceIPv4}) async {
          final client = _buildHttpClient(forceIPv4: forceIPv4);
          try {
            final hdrs = Map<String, String>.from(headers);
            hdrs['Content-Type'] =
                'application/x-www-form-urlencoded; charset=UTF-8';
            if (forceIPv4 || _preferIPv4) hdrs['Host'] = 'app.vvc.asia';
            final uri = Uri.parse(effectiveBaseUrl);
            return await client
                .post(uri, headers: hdrs, body: body)
                .timeout(const Duration(seconds: 15));
          } finally {
            client.close();
          }
        });
        if (response.statusCode == 200) {
          final res = json.decode(response.body);
          if (res['success'] == true) await dbService.markAsSynced(punch['id']);
        }
      } catch (e) {
        debugPrint('Sync item ${punch['id']} failed: ${_friendlyError(e)}');
        break;
      }
    }
  }

  Future<Map<String, dynamic>> fetchLastAction() async {
    final headers = await _authHeaders();
    return _processRequest('fetch_last_action', headers: headers);
  }

  Future<Map<String, dynamic>> submitRequest(
    String requestType,
    Map<String, dynamic> formData,
  ) async {
    final headers = await _authHeaders();
    return _processRequest(
      'submit_request',
      headers: headers,
      body: {'requestType': requestType, 'formDataJson': json.encode(formData)},
    );
  }

  Future<Map<String, dynamic>> fetchRequests({int limit = 100, bool trash = false}) async {
    final headers = await _authHeaders();
    return _processRequest(
      'fetch_requests',
      headers: headers,
      body: {'limit': limit.toString(), 'trash': trash.toString()},
    );
  }

  Future<Map<String, dynamic>> fetchRequestSignatures(int requestId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'get_request_signatures',
      headers: headers,
      body: {'request_id': requestId.toString()},
    );
  }

  Future<Map<String, dynamic>> deleteRequest(int requestId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'delete_request',
      headers: headers,
      body: {'request_id': requestId.toString()},
    );
  }

  Future<Map<String, dynamic>> restoreRequest(int requestId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'restore_request',
      headers: headers,
      body: {'request_id': requestId.toString()},
    );
  }

  Future<Map<String, dynamic>> permanentDeleteRequest(int requestId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'permanent_delete_request',
      headers: headers,
      body: {'request_id': requestId.toString()},
    );
  }

  Future<Map<String, dynamic>> approveRequest({
    required int requestId,
    required String status,
    String? adminComment,
  }) async {
    final headers = await _authHeaders();
    return _processRequest(
      'approve_request',
      headers: headers,
      body: {
        'id': requestId.toString(),
        'status': status,
        'admin_comment': adminComment ?? '',
      },
    );
  }

  Future<Map<String, dynamic>> updateRequest(
    int requestId,
    Map<String, dynamic> formData,
  ) async {
    final headers = await _authHeaders();
    return _processRequest(
      'update_request',
      headers: headers,
      body: {'id': requestId.toString(), 'formDataJson': json.encode(formData)},
    );
  }

  Future<Map<String, dynamic>> updateRequestStatus(
    int requestId,
    String status,
  ) async {
    final headers = await _authHeaders();
    return _processRequest(
      'update_request_status',
      headers: headers,
      body: {'id': requestId.toString(), 'status': status},
    );
  }

  Future<Map<String, dynamic>> updateFcmToken(
    String fcmToken, {
    String? platform,
  }) async {
    final headers = await _authHeaders();
    return _processRequest(
      'update_fcm_token',
      headers: headers,
      body: {'token': fcmToken, 'platform': platform ?? ''},
    );
  }

  Future<Map<String, dynamic>> logout({String? fcmToken}) async {
    final headers = await _authHeaders();
    return _processRequest(
      'logout',
      headers: headers,
      body: {
        if (fcmToken != null && fcmToken.isNotEmpty) 'fcm_token': fcmToken,
      },
    );
  }

  Future<Map<String, dynamic>> getNotifications() async {
    final headers = await _authHeaders();
    return _processRequest('get_user_notifications', headers: headers);
  }

  Future<Map<String, dynamic>> markNotificationAsRead(
    int notificationId,
  ) async {
    final headers = await _authHeaders();
    return _processRequest(
      'mark_notification_read',
      headers: headers,
      body: {'notification_id': notificationId.toString()},
    );
  }

  Future<Map<String, dynamic>> sendNotification(
    Map<String, dynamic> data,
  ) async {
    final headers = await _authHeaders();
    final Map<String, String> body = {
      'recipient_type': data['recipient_type']?.toString() ?? 'all',
      'notification_title': data['notification_title']?.toString() ?? '',
      'notification_message': data['notification_message']?.toString() ?? '',
      if (data['expiry_date'] != null)
        'expiry_date': data['expiry_date'].toString(),
      if (data['target_roles'] != null)
        'target_roles': data['target_roles'].toString(),
      if (data['target_users'] != null)
        'target_users': data['target_users'].toString(),
    };
    return _processRequest(
      'send_app_notification',
      headers: headers,
      body: body,
    );
  }

  Future<Map<String, dynamic>> fetchPayrollHistory() async {
    final headers = await _authHeaders();
    return _processRequest('get_payroll_history', headers: headers);
  }

  Future<Map<String, dynamic>> recordPayrollBiometricVerification({
    required String platform,
    String authMethod = 'device_biometric_or_passcode',
  }) async {
    final headers = await _authHeaders();
    return _processRequest(
      'record_payroll_biometric_verification',
      headers: headers,
      body: {'platform': platform, 'auth_method': authMethod},
    );
  }

  Future<Map<String, dynamic>> fetchAnnouncements() async {
    final headers = await _authHeaders();
    return _processRequest('get_announcements', headers: headers);
  }

  Future<Map<String, dynamic>> fetchMeetings() async {
    final headers = await _authHeaders();
    return _processRequest('get_meetings', headers: headers);
  }

  Future<Map<String, dynamic>> fetchChecklist() async {
    final headers = await _authHeaders();
    return _processRequest('get_checklist', headers: headers);
  }

  Future<Map<String, dynamic>> addChecklistItem(
    String task, {
    String? startDate,
    String? startTime,
    String? endDate,
    String? endTime,
    String? imageBase64,
    String category = 'General',
  }) async {
    final headers = await _authHeaders();
    final Map<String, String> requestBody = {
      'task': task,
      'category': category,
    };
    if (startDate != null) {
      requestBody['start_date'] = startDate;
    }
    if (startTime != null) {
      requestBody['start_time'] = startTime;
    }
    if (endDate != null) {
      requestBody['end_date'] = endDate;
    }
    if (endTime != null) {
      requestBody['end_time'] = endTime;
    }
    if (imageBase64 != null) {
      requestBody['image_base64'] = imageBase64;
    }
    return _processRequest(
      'add_checklist_item',
      headers: headers,
      body: requestBody,
    );
  }

  Future<Map<String, dynamic>> toggleChecklistStatus(
    int taskId,
    String status,
  ) async {
    final headers = await _authHeaders();
    return _processRequest(
      'toggle_checklist_status',
      headers: headers,
      body: {'task_id': taskId.toString(), 'status': status},
    );
  }

  Future<Map<String, dynamic>> deleteChecklistItem(int taskId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'delete_checklist_item',
      headers: headers,
      body: {'task_id': taskId.toString()},
    );
  }

  Future<Map<String, dynamic>> editChecklistItem(
    int taskId,
    String task, {
    String category = 'General',
    String? startDate,
    String? startTime,
    String? endDate,
    String? endTime,
    String? imageBase64,
  }) async {
    final headers = await _authHeaders();
    final Map<String, String> requestBody = {
      'task_id': taskId.toString(),
      'task': task,
      'category': category,
    };
    if (startDate != null) {
      requestBody['start_date'] = startDate;
    }
    if (startTime != null) {
      requestBody['start_time'] = startTime;
    }
    if (endDate != null) {
      requestBody['end_date'] = endDate;
    }
    if (endTime != null) {
      requestBody['end_time'] = endTime;
    }
    if (imageBase64 != null) {
      requestBody['image_base64'] = imageBase64;
    }
    return _processRequest(
      'edit_checklist_item',
      headers: headers,
      body: requestBody,
    );
  }

  Future<Map<String, dynamic>> submitDailyReport(
    String content, {
    String? position,
    String? threadId,
    String? chatId,
  }) async {
    final Map<String, String> body = {'content': content};
    if (position != null) body['position'] = position;
    if (threadId != null) body['thread_id'] = threadId;
    if (chatId != null) body['chat_id'] = chatId;
    final headers = await _authHeaders();
    return _processRequest('submit_daily_report', headers: headers, body: body);
  }

  Future<Map<String, dynamic>> fetchAllDailyReports() async {
    final headers = await _authHeaders();
    return _processRequest('get_all_daily_reports', headers: headers);
  }

  Future<Map<String, dynamic>> fetchMyDailyReports() async {
    final headers = await _authHeaders();
    return _processRequest('get_my_daily_reports', headers: headers);
  }

  Future<Map<String, dynamic>> fetchReportPositions() async {
    final headers = await _authHeaders();
    return _processRequest('get_report_positions', headers: headers);
  }

  Future<Map<String, dynamic>> submitMissionLetter({
    required String location,
    required String purpose,
    required String startDate,
    required String startTime,
    required String endDate,
    required String endTime,
    required String transport,
    String? materials,
    String? dateKhmerPart1,
    String? dateKhmerPart2,
    String? startLunarDate,
    String? endLunarDate,
    List<Map<String, String>>? personnel,
  }) async {
    final headers = await _authHeaders();
    final body = <String, String>{
      'location': location,
      'purpose': purpose,
      'start_date': startDate,
      'start_time': startTime,
      'end_date': endDate,
      'end_time': endTime,
      'transport': transport,
      'materials': materials ?? '',
      'date_khmer_part1': dateKhmerPart1 ?? '',
      'date_khmer_part2': dateKhmerPart2 ?? '',
      'start_lunar_date': startLunarDate ?? '',
      'end_lunar_date': endLunarDate ?? '',
    };
    if (personnel != null) {
      for (var i = 0; i < personnel.length && i < 10; i++) {
        final name = (personnel[i]['name'] ?? '').trim();
        final role = (personnel[i]['role'] ?? '').trim();
        if (name.isEmpty) continue;
        body['person${i + 1}'] = name;
        body['role${i + 1}'] = role;
      }
      body['personnel_json'] = json.encode(personnel);
    }
    return _processRequest(
      'submit_mission_letter',
      headers: headers,
      body: body,
    );
  }

  Future<Map<String, dynamic>> fetchMissionLetters() async {
    final headers = await _authHeaders();
    return _processRequest('get_my_mission_letters', headers: headers);
  }

  Future<Map<String, dynamic>> saveMeeting({
    required String topic,
    String? department,
    required String date,
    String? description,
    String? externalUrl,
    String? audioPath,
    Uint8List? audioBytes,
    String? audioFilename,
    List<String>? photoPaths,
  }) async {
    final headers = await _authHeaders();

    Future<Map<String, dynamic>> doPost({required bool forceIPv4}) async {
      final dioInstance = dio.Dio();
      if (!kIsWeb) {
        dioInstance.httpClientAdapter = IOHttpClientAdapter(
          createHttpClient: () {
            final client = HttpClient();
            client.badCertificateCallback =
                (X509Certificate cert, String host, int port) {
              if (forceIPv4 || _preferIPv4) {
                return host == '104.21.2.219' ||
                    host == '172.67.129.187' ||
                    cert.subject.contains('vvc.asia') ||
                    cert.issuer.contains('Cloudflare') ||
                    cert.issuer.contains('Let\'s Encrypt');
              }
              return false;
            };
            return client;
          },
        );
      }
      final formData = dio.FormData.fromMap({
        'action': 'save_meeting',
        'topic': topic,
        'department': department ?? '',
        'date': date,
        'description': description ?? '',
        'external_url': externalUrl ?? '',
        'audio_original_name': audioFilename ?? '',
      });
      if (audioBytes != null && audioBytes.isNotEmpty) {
        formData.files.add(
          MapEntry(
            'audio_file',
            dio.MultipartFile.fromBytes(
              audioBytes,
              filename: audioFilename ?? 'meeting_audio.m4a',
            ),
          ),
        );
      } else if (audioPath != null) {
        if (kIsWeb) {
          final resp = await http.get(Uri.parse(audioPath));
          formData.files.add(
            MapEntry(
              'audio_file',
              dio.MultipartFile.fromBytes(
                resp.bodyBytes,
                filename: audioFilename ?? 'audio.m4a',
              ),
            ),
          );
        } else {
          formData.files.add(
            MapEntry(
              'audio_file',
              await dio.MultipartFile.fromFile(
                audioPath,
                filename: audioFilename,
              ),
            ),
          );
        }
      }
      if (photoPaths != null) {
        for (var i = 0; i < photoPaths.length; i++) {
          var p = photoPaths[i];
          if (kIsWeb) {
            final resp = await http.get(Uri.parse(p));
            formData.files.add(
              MapEntry(
                'related_photos[]',
                dio.MultipartFile.fromBytes(
                  resp.bodyBytes,
                  filename: 'photo_$i.jpg',
                ),
              ),
            );
          } else {
            formData.files.add(MapEntry(
                'related_photos[]', await dio.MultipartFile.fromFile(p)));
          }
        }
      }
      final postHeaders = Map<String, String>.from(headers);
      if (forceIPv4 || _preferIPv4) postHeaders['Host'] = 'app.vvc.asia';
      final response = await dioInstance.post(
        effectiveBaseUrl,
        data: formData,
        options: dio.Options(
          headers: postHeaders,
          receiveTimeout: const Duration(seconds: 60),
          sendTimeout: const Duration(seconds: 120),
        ),
      );
      return response.data is String
          ? json.decode(response.data)
          : (response.data as Map<String, dynamic>);
    }

    try {
      return await _withRetry<Map<String, dynamic>>(doPost);
    } catch (e) {
      return {'success': false, 'message': _friendlyError(e)};
    }
  }

  Future<Map<String, dynamic>> fetchDeptHeads() async {
    final headers = await _authHeaders();
    return _processRequest('get_dept_heads', headers: headers);
  }

  Future<Map<String, dynamic>> saveDeptHead({
    int? id,
    required String fullName,
    String? signature,
  }) async {
    final headers = await _authHeaders();
    final body = {
      'full_name': fullName,
      if (id != null) 'id': id.toString(),
      'signature': signature ?? '',
    };
    return _processRequest('save_dept_head', headers: headers, body: body);
  }

  Future<Map<String, dynamic>> fetchUsers() async {
    final headers = await _authHeaders();
    return _processRequest('get_users', headers: headers);
  }

  Future<Map<String, dynamic>> saveUser({
    required String targetEid,
    required String name,
    String? password,
    String? systemRole,
    String? systemRoleLabel,
    String? department,
    String? position,
    String? branch,
    String? latinName,
    String? username,
    String? email,
    String? address,
    String? joinedAt,
    String? maritalStatus,
    double? baseSalary,
    String? nssfId,
  }) async {
    final headers = await _authHeaders();
    return _processRequest(
      'save_user',
      headers: headers,
      body: {
        'target_employee_id': targetEid,
        'name': name,
        'password': password ?? '',
        'system_role': systemRole ?? '',
        'system_role_label': systemRoleLabel ?? '',
        'department': department ?? '',
        'position': position ?? '',
        'branch': branch ?? '',
        'latin_name': latinName ?? '',
        'username': username ?? '',
        'email': email ?? '',
        'current_address': address ?? '',
        'joined_at': joinedAt ?? '',
        'marital_status': maritalStatus ?? 'Single',
        'base_salary': (baseSalary ?? 0.0).toString(),
        'nssf_id': nssfId ?? '',
      },
    );
  }

  Future<Map<String, dynamic>> fetchAllAttendanceLogs({
    int limit = 20,
    int offset = 0,
    String? startDate,
    String? endDate,
  }) async {
    final headers = await _authHeaders();
    final body = <String, String>{
      'limit': limit.toString(),
      'offset': offset.toString(),
    };
    if (startDate != null) body['start_date'] = startDate;
    if (endDate != null) body['end_date'] = endDate;
    return _processRequest(
      'get_all_attendance_logs',
      headers: headers,
      body: body,
    );
  }

  Future<Map<String, dynamic>> fetchLogTree({
    int? year,
    int? month,
    int? day,
  }) async {
    final headers = await _authHeaders();
    final body = <String, String>{};
    if (year != null) body['year'] = year.toString();
    if (month != null) body['month'] = month.toString();
    if (day != null) body['day'] = day.toString();
    return _processRequest(
      'get_attendance_log_tree',
      headers: headers,
      body: body,
    );
  }

  Future<Map<String, dynamic>> fetchAllPayroll() async {
    final headers = await _authHeaders();
    return _processRequest('get_all_payroll', headers: headers);
  }

  Future<Map<String, dynamic>> fetchAllTrips() async {
    final headers = await _authHeaders();
    return _processRequest('get_all_trips', headers: headers);
  }

  Future<Map<String, dynamic>> getTripDetails(int tripId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'get_trip_details',
      headers: headers,
      body: {'trip_id': tripId.toString()},
    );
  }

  // ========== MATERIAL REQUESTS ==========
  Future<Map<String, dynamic>> fetchMaterialItems() async {
    final headers = await _authHeaders();
    return _processRequest('get_material_items', headers: headers);
  }

  Future<Map<String, dynamic>> submitMaterialRequest(
    Map<String, dynamic> data,
  ) async {
    final headers = await _authHeaders();
    final rawTitle = (data['title'] ?? '').toString().trim();
    final rawRemarks = (data['remarks'] ?? '').toString().trim();
    final title = rawTitle.isNotEmpty
        ? rawTitle
        : (rawRemarks.isNotEmpty ? rawRemarks : 'Material Request');
    final itemsJson = json.encode(data['items'] ?? []);
    final body = <String, String>{
      'location': data['location']?.toString() ?? '',
      'title': title,
      'remarks': rawRemarks,
      'items': itemsJson,
      'items_json': itemsJson,
    };
    return _processRequest(
      'submit_material_request',
      headers: headers,
      body: body,
    );
  }

  // ========== DEPT HEAD ==========
  Future<Map<String, dynamic>> deleteDeptHead(int id) async {
    final headers = await _authHeaders();
    return _processRequest(
      'delete_dept_head',
      headers: headers,
      body: {'id': id.toString()},
    );
  }

  // ========== USER MANAGEMENT ==========
  Future<Map<String, dynamic>> deleteUser(String employeeId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'delete_user',
      headers: headers,
      body: {'target_employee_id': employeeId},
    );
  }

  // ========== MEETINGS AI ==========
  Future<Map<String, dynamic>> summarizeMeeting(
    int meetingId, {
    bool force = false,
  }) async {
    final headers = await _authHeaders();
    return _processRequest(
      'summarize_meeting',
      headers: headers,
      timeout: const Duration(seconds: 45),
      body: {'meeting_id': meetingId.toString(), if (force) 'force': '1'},
    );
  }

  Future<Map<String, dynamic>> getMeetingSummaryStatus(int meetingId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'get_meeting_summary_status',
      headers: headers,
      timeout: const Duration(seconds: 30),
      body: {'meeting_id': meetingId.toString()},
    );
  }

  /// Process meeting audio with AI (Whisper + Gemini/GPT)
  /// This calls the new PHP endpoint for Khmer meeting summarization
  Future<Map<String, dynamic>> processMeetingAudio({
    required String audioPath,
    String? meetingId,
    String? meetingTitle,
    String? department,
  }) async {
    final headers = await _authHeaders();
    
    // Add Authorization header with API key from SharedPreferences
    final prefs = await SharedPreferences.getInstance();
    final apiKey = prefs.getString('meeting_api_key') ?? '';
    
    if (apiKey.isEmpty) {
      throw Exception('Meeting API key not configured. Please set it in settings.');
    }
    
    headers['Authorization'] = 'Bearer $apiKey';
    
    // Use Dio for multipart file upload
    final dioInstance = dio.Dio();
    dioInstance.options.baseUrl = baseUrl;
    dioInstance.options.headers.addAll(headers);
    dioInstance.options.connectTimeout = const Duration(minutes: 5);
    dioInstance.options.receiveTimeout = const Duration(minutes: 5);
    
    try {
      final formData = dio.FormData.fromMap({
        'audio_file': await dio.MultipartFile.fromFile(audioPath),
        if (meetingId != null) 'meeting_id': meetingId,
        if (meetingTitle != null) 'meeting_title': meetingTitle,
        if (department != null) 'department': department,
      });
      
      final response = await dioInstance.post(
        '/process-meeting.php',
        data: formData,
      );
      
      if (response.statusCode == 200) {
        return response.data as Map<String, dynamic>;
      } else {
        throw Exception('HTTP ${response.statusCode}: ${response.data}');
      }
    } catch (e) {
      if (kDebugMode) print('Error processing meeting audio: $e');
      throw Exception('Failed to process meeting audio: $e');
    }
  }

  // ========== TRIP / TRACKING ==========
  Future<Map<String, dynamic>> getTrackingCustomers() async {
    final headers = await _authHeaders();
    return _processRequest('get_tracking_customers', headers: headers);
  }

  Future<Map<String, dynamic>> getActiveTrip() async {
    final headers = await _authHeaders();
    return _processRequest('get_active_trip', headers: headers);
  }

  Future<Map<String, dynamic>> startTrip({
    required int customerId,
    required String customerName,
    required double latitude,
    required double longitude,
    String notes = '',
  }) async {
    final headers = await _authHeaders();
    return _processRequest(
      'start_trip',
      headers: headers,
      body: {
        'customer_id': customerId.toString(),
        'customer_name': customerName,
        'latitude': latitude.toString(),
        'longitude': longitude.toString(),
        'notes': notes,
      },
    );
  }

  Future<Map<String, dynamic>> updateTripLocation({
    required int tripId,
    required double latitude,
    required double longitude,
    double speed = 0,
    double accuracy = 0,
  }) async {
    final headers = await _authHeaders();
    return _processRequest(
      'update_trip_location',
      headers: headers,
      body: {
        'trip_id': tripId.toString(),
        'latitude': latitude.toString(),
        'longitude': longitude.toString(),
        'speed': speed.toString(),
        'accuracy': accuracy.toString(),
      },
    );
  }

  Future<Map<String, dynamic>> endTrip(int tripId, {String notes = ''}) async {
    final headers = await _authHeaders();
    return _processRequest(
      'end_trip',
      headers: headers,
      body: {'trip_id': tripId.toString(), 'notes': notes},
    );
  }

  Future<Map<String, dynamic>?> httpGet(String url) async {
    try {
      final response = await http
          .get(Uri.parse(url))
          .timeout(const Duration(seconds: 8));
      if (response.statusCode == 200) {
        final decoded = jsonDecode(response.body);
        if (decoded is Map<String, dynamic>) return decoded;
      }
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Auto-save customer lat/lng after a trip ends (only if customer has no location yet)
  Future<Map<String, dynamic>> updateCustomerLocation({
    required int customerId,
    required double latitude,
    required double longitude,
  }) async {
    final headers = await _authHeaders();
    return _processRequest(
      'update_customer_location',
      headers: headers,
      body: {
        'customer_id': customerId.toString(),
        'latitude': latitude.toString(),
        'longitude': longitude.toString(),
      },
    );
  }

  /// Fetch a road-following route from OSRM between two points.
  /// Returns a list of LatLng-like maps [{lat, lng}] on success, or null on failure.
  static Future<List<Map<String, double>>?> getOsrmRoute({
    required double startLat,
    required double startLng,
    required double endLat,
    required double endLng,
  }) async {
    try {
      final url =
          'https://router.project-osrm.org/route/v1/driving/'
          '$startLng,$startLat;$endLng,$endLat'
          '?overview=full&geometries=geojson';
      final response = await http
          .get(Uri.parse(url))
          .timeout(const Duration(seconds: 10));
      if (response.statusCode != 200) return null;
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      if (data['code'] != 'Ok') return null;
      final routes = data['routes'] as List?;
      if (routes == null || routes.isEmpty) return null;
      final geometry = routes[0]['geometry'] as Map<String, dynamic>?;
      if (geometry == null) return null;
      final coordinates = geometry['coordinates'] as List?;
      if (coordinates == null) return null;
      return coordinates.map<Map<String, double>>((c) {
        final list = c as List;
        return {
          'lat': (list[1] as num).toDouble(),
          'lng': (list[0] as num).toDouble(),
        };
      }).toList();
    } catch (e) {
      debugPrint('OSRM route error: $e');
      return null;
    }
  }

  // Theme Management API Methods

  /// Get all available themes
  Future<Map<String, dynamic>> getThemes() async {
    final headers = await _authHeaders();
    return _processRequest('get_themes', headers: headers);
  }

  /// Get currently active theme
  Future<Map<String, dynamic>> getActiveTheme() async {
    final headers = await _authHeaders();
    return _processRequest('get_active_theme', headers: headers);
  }

  /// Get auto-active theme based on current date
  Future<Map<String, dynamic>> getAutoTheme() async {
    final headers = await _authHeaders();
    return _processRequest('get_auto_theme', headers: headers);
  }

  /// Set active theme (Admin only)
  Future<Map<String, dynamic>> setActiveTheme(String themeId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'set_active_theme',
      headers: headers,
      body: {'theme_id': themeId},
    );
  }

  /// Save theme (Admin only)
  Future<Map<String, dynamic>> saveTheme(Map<String, dynamic> themeData) async {
    final headers = await _authHeaders();
    // Convert dynamic map to string map for _processRequest
    final stringBody = <String, String>{};
    themeData.forEach((key, value) {
      stringBody[key] = value?.toString() ?? '';
    });
    return _processRequest(
      'save_theme',
      headers: headers,
      body: stringBody,
    );
  }

  /// Delete theme (Admin only)
  Future<Map<String, dynamic>> deleteTheme(String themeId) async {
    final headers = await _authHeaders();
    return _processRequest(
      'delete_theme',
      headers: headers,
      body: {'theme_id': themeId},
    );
  }
}
