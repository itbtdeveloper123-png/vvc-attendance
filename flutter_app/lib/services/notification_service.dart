import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:timezone/data/latest_all.dart' as tz;
import 'package:timezone/timezone.dart' as tz;
import 'package:flutter_timezone/flutter_timezone.dart';

class NotificationService {
  static final NotificationService _instance = NotificationService._internal();

  factory NotificationService() {
    return _instance;
  }

  NotificationService._internal();

  final FlutterLocalNotificationsPlugin flutterLocalNotificationsPlugin =
      FlutterLocalNotificationsPlugin();

  bool _isInitialized = false;
  Future<void>? _initializing;

  Future<void> init() async {
    // Web doesn't support these plugins/permissions.
    if (kIsWeb) return;
    if (_isInitialized) return;
    if (_initializing != null) {
      await _initializing;
      return;
    }

    _initializing = _initInternal();
    await _initializing;
  }

  Future<void> _initInternal() async {
    // Initialize Timezones
    tz.initializeTimeZones();
    final String timeZoneName = await FlutterTimezone.getLocalTimezone();
    tz.setLocalLocation(tz.getLocation(timeZoneName));

    // ស្នើសុំសិទ្ធិសម្រាប់ Android 13+ (POST_NOTIFICATIONS)
    try {
      await Permission.notification.request();
    } catch (_) {
      // Avoid crashing app startup if OEM/OS blocks permission prompt.
    }

    const AndroidInitializationSettings initializationSettingsAndroid =
        AndroidInitializationSettings('@mipmap/ic_launcher');

    const DarwinInitializationSettings initializationSettingsIOS =
        DarwinInitializationSettings(
          requestAlertPermission: true,
          requestBadgePermission: true,
          requestSoundPermission: true,
        );

    const InitializationSettings initializationSettings =
        InitializationSettings(
          android: initializationSettingsAndroid,
          iOS: initializationSettingsIOS,
        );

    await flutterLocalNotificationsPlugin.initialize(
      initializationSettings,
      onDidReceiveNotificationResponse: (NotificationResponse response) async {
        debugPrint('Notification clicked with payload: ${response.payload}');
      },
      onDidReceiveBackgroundNotificationResponse: notificationTapBackground,
    );

    // Create Channel for Checklist
    final androidPlugin = flutterLocalNotificationsPlugin
        .resolvePlatformSpecificImplementation<
          AndroidFlutterLocalNotificationsPlugin
        >();
    if (androidPlugin != null) {
      await androidPlugin.createNotificationChannel(
        const AndroidNotificationChannel(
          'vvc_hrm_checklist',
          'Checklist Reminders',
          description: 'ការជូនដំណឹងរំលឹកកិច្ចការងារ',
          importance: Importance.max,
          playSound: true,
        ),
      );
    }
    _isInitialized = true;
  }

  Future<void> showNotification({
    required int id,
    required String title,
    required String body,
    String? payload,
    String? channelId,
  }) async {
    if (!kIsWeb && !_isInitialized) {
      await init();
    }

    final AndroidNotificationDetails androidNotificationDetails =
        AndroidNotificationDetails(
          channelId ?? 'vvc_hrm_channel',
          'VVC HRM Notifications',
          channelDescription: 'ការជូនដំណឹងពីប្រព័ន្ធ VVC HRM',
          importance: Importance.max,
          priority: Priority.high,
          ticker: 'ticker',
          icon: '@mipmap/ic_launcher',
          playSound: true,
        );

    const DarwinNotificationDetails iosNotificationDetails =
        DarwinNotificationDetails(
          presentAlert: true,
          presentBadge: true,
          presentSound: true,
        );

    final NotificationDetails notificationDetails = NotificationDetails(
      android: androidNotificationDetails,
      iOS: iosNotificationDetails,
    );

    await flutterLocalNotificationsPlugin.show(
      id,
      title,
      body,
      notificationDetails,
      payload: payload,
    );
  }

  Future<void> scheduleNotification({
    required int id,
    required String title,
    required String body,
    required DateTime scheduledDate,
    String? payload,
  }) async {
    if (kIsWeb) return;

    // Check if the date is in the future
    if (scheduledDate.isBefore(DateTime.now())) return;

    try {
      await _scheduleWithMode(
        id: id,
        title: title,
        body: body,
        scheduledDate: scheduledDate,
        payload: payload,
        androidScheduleMode: AndroidScheduleMode.exactAllowWhileIdle,
      );
    } on PlatformException catch (e) {
      if (e.code != 'exact_alarms_not_permitted') rethrow;
      await _scheduleWithMode(
        id: id,
        title: title,
        body: body,
        scheduledDate: scheduledDate,
        payload: payload,
        androidScheduleMode: AndroidScheduleMode.inexactAllowWhileIdle,
      );
    }
  }

  /// Schedule a notification on a specific notification channel.
  /// Used by [KhmerCalendarNotificationService] for holiday/sila alerts.
  Future<void> scheduleNotificationOnChannel({
    required int id,
    required String title,
    required String body,
    required DateTime scheduledDate,
    required String channelId,
    required String channelName,
    String? payload,
  }) async {
    if (kIsWeb) return;
    if (scheduledDate.isBefore(DateTime.now())) return;

    Future<void> doSchedule(AndroidScheduleMode mode) {
      return flutterLocalNotificationsPlugin.zonedSchedule(
        id,
        title,
        body,
        tz.TZDateTime.from(scheduledDate, tz.local),
        NotificationDetails(
          android: AndroidNotificationDetails(
            channelId,
            channelName,
            importance: Importance.max,
            priority: Priority.high,
            icon: '@mipmap/ic_launcher',
            playSound: true,
          ),
          iOS: const DarwinNotificationDetails(
            presentAlert: true,
            presentBadge: true,
            presentSound: true,
          ),
        ),
        androidScheduleMode: mode,
        uiLocalNotificationDateInterpretation:
            UILocalNotificationDateInterpretation.absoluteTime,
        payload: payload,
      );
    }

    try {
      await doSchedule(AndroidScheduleMode.exactAllowWhileIdle);
    } on PlatformException catch (e) {
      if (e.code != 'exact_alarms_not_permitted') rethrow;
      await doSchedule(AndroidScheduleMode.inexactAllowWhileIdle);
    }
  }


  Future<void> _scheduleWithMode({
    required int id,
    required String title,
    required String body,
    required DateTime scheduledDate,
    required AndroidScheduleMode androidScheduleMode,
    String? payload,
  }) {
    return flutterLocalNotificationsPlugin.zonedSchedule(
      id,
      title,
      body,
      tz.TZDateTime.from(scheduledDate, tz.local),
      const NotificationDetails(
        android: AndroidNotificationDetails(
          'vvc_hrm_checklist',
          'Checklist Reminders',
          channelDescription: 'ការជូនដំណឹងរំលឹកកិច្ចការងារ',
          importance: Importance.max,
          priority: Priority.high,
          icon: '@mipmap/ic_launcher',
          playSound: true,
        ),
        iOS: DarwinNotificationDetails(
          presentAlert: true,
          presentBadge: true,
          presentSound: true,
        ),
      ),
      androidScheduleMode: androidScheduleMode,
      uiLocalNotificationDateInterpretation:
          UILocalNotificationDateInterpretation.absoluteTime,
      payload: payload,
    );
  }

  Future<void> cancelNotification(int id) async {
    await flutterLocalNotificationsPlugin.cancel(id);
  }
}

@pragma('vm:entry-point')
void notificationTapBackground(NotificationResponse notificationResponse) {
  debugPrint(
    'notification(${notificationResponse.id}) action tapped: '
    '${notificationResponse.actionId} with'
    ' payload: ${notificationResponse.payload}',
  );
  if (notificationResponse.input?.isNotEmpty ?? false) {
    debugPrint(
      'notification action tapped with input: ${notificationResponse.input}',
    );
  }
}
