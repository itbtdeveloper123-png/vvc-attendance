import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:ui';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_background_service/flutter_background_service.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:geolocator/geolocator.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import 'api_service.dart';
import 'local_db_service.dart';

class BackgroundLocationService {
  static bool _isSuccessfulSyncResponse(http.Response response) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      return false;
    }
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) {
        return decoded['success'] == true || decoded['status'] == 'success';
      }
    } catch (_) {}
    return false;
  }

  static Future<void> initializeService() async {
    final service = FlutterBackgroundService();

    const channel = AndroidNotificationChannel(
      'background_location_channel',
      'Location Tracking',
      description: 'Tracks active employee trips in the background.',
      importance: Importance.low,
    );

    final notifications = FlutterLocalNotificationsPlugin();

    if (defaultTargetPlatform == TargetPlatform.android) {
      await notifications
          .resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin
          >()
          ?.createNotificationChannel(channel);
    }

    await service.configure(
      androidConfiguration: AndroidConfiguration(
        onStart: onStart,
        autoStart: false,
        autoStartOnBoot: false,
        isForegroundMode: true,
        notificationChannelId: 'background_location_channel',
        initialNotificationTitle: 'VVC Attendance Service',
        initialNotificationContent: 'Trip tracking is ready',
        foregroundServiceNotificationId: 888,
      ),
      iosConfiguration: IosConfiguration(
        autoStart: false,
        onForeground: onStart,
        onBackground: onIosBackground,
      ),
    );
  }

  @pragma('vm:entry-point')
  static Future<bool> onIosBackground(ServiceInstance service) async {
    WidgetsFlutterBinding.ensureInitialized();
    DartPluginRegistrant.ensureInitialized();
    return true;
  }

  static Future<void> startTracking() async {
    final service = FlutterBackgroundService();
    if (!(await service.isRunning())) {
      await service.startService();
    }
  }

  static void stopTracking() {
    FlutterBackgroundService().invoke('stopService');
  }

  static LocationSettings _locationSettings() {
    if (Platform.isAndroid) {
      return AndroidSettings(
        accuracy: LocationAccuracy.bestForNavigation,
        distanceFilter: 5,
        intervalDuration: const Duration(seconds: 10),
        forceLocationManager: false,
      );
    }

    if (Platform.isIOS) {
      return AppleSettings(
        accuracy: LocationAccuracy.bestForNavigation,
        activityType: ActivityType.automotiveNavigation,
        distanceFilter: 5,
        pauseLocationUpdatesAutomatically: false,
        showBackgroundLocationIndicator: true,
      );
    }

    return const LocationSettings(
      accuracy: LocationAccuracy.bestForNavigation,
      distanceFilter: 5,
    );
  }

  @pragma('vm:entry-point')
  static void onStart(ServiceInstance service) async {
    WidgetsFlutterBinding.ensureInitialized();
    DartPluginRegistrant.ensureInitialized();

    final prefs = await SharedPreferences.getInstance();
    final localDb = LocalDbService();
    StreamSubscription<Position>? positionSubscription;

    positionSubscription =
        Geolocator.getPositionStream(
          locationSettings: _locationSettings(),
        ).listen(
          (Position position) async {
            try {
              await prefs.reload();

              final currentTripId = prefs.getString('current_active_trip_id');
              final token = prefs.getString('auth_token');

              if (currentTripId == null || token == null || token.isEmpty) {
                return;
              }

              final tripIdInt = int.tryParse(currentTripId);

              // ─── Try to send to server ───────────────────────────────────────────
              bool synced = false;
              try {
                final response = await http
                    .post(
                      Uri.parse(ApiService.baseUrl),
                      body: {
                        'action': 'update_trip_location',
                        'trip_id': currentTripId,
                        'latitude': position.latitude.toString(),
                        'longitude': position.longitude.toString(),
                        'speed': (position.speed * 3.6).toString(),
                        'accuracy': position.accuracy.toString(),
                      },
                      headers: {'Authorization': 'Bearer $token'},
                    )
                    .timeout(const Duration(seconds: 8));

                synced = _isSuccessfulSyncResponse(response);
              } catch (e) {
                // No internet or timeout — will queue locally
                synced = false;
                debugPrint(
                  'Background GPS send failed (will queue offline): $e',
                );
              }

              // ─── Queue locally if server sync failed ─────────────────────────────
              if (!synced && tripIdInt != null) {
                await localDb.insertTripPoint(
                  tripId: tripIdInt,
                  latitude: position.latitude,
                  longitude: position.longitude,
                  speed: position.speed * 3.6,
                  accuracy: position.accuracy,
                );
                debugPrint('GPS point queued offline for trip #$tripIdInt');
              }

              // ─── Update foreground notification ──────────────────────────────────
              if (service is AndroidServiceInstance) {
                final status = synced ? '✅ Online' : '📴 Offline (cached)';
                service.setForegroundNotificationInfo(
                  title: 'VVC Trip Tracking — $status',
                  content:
                      'GPS ${position.latitude.toStringAsFixed(4)}, ${position.longitude.toStringAsFixed(4)}',
                );
              }
            } catch (e) {
              debugPrint('Background Stream Error: $e');
            }
          },
          onError: (dynamic error) {
            debugPrint('Background location stream error: $error');
          },
        );

    service.on('stopService').listen((event) {
      positionSubscription?.cancel();
      service.stopSelf();
    });
  }
}
