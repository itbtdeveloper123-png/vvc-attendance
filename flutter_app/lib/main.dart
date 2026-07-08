import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:provider/provider.dart';

import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

import 'package:vvc_hrm/providers/user_provider.dart';
import 'package:vvc_hrm/core/theme/theme_provider.dart';
import 'package:intl/date_symbol_data_local.dart';

// Screens
import 'package:vvc_hrm/screens/home_screen.dart';
import 'package:vvc_hrm/screens/login_screen.dart';
import 'package:vvc_hrm/firebase_options.dart';

// Services
import 'package:vvc_hrm/services/notification_service.dart';
import 'package:vvc_hrm/services/background_location_service.dart';

@pragma('vm:entry-point')
Future<void> _firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  await Firebase.initializeApp();
  debugPrint("Handling a background message: ${message.messageId}");
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await initializeDateFormatting();
  if (!kIsWeb) {
    try {
      await BackgroundLocationService.initializeService();
    } catch (e) {
      debugPrint("BackgroundLocationService init error: $e");
    }
  }

  // ---- STEP 1: Load saved user FIRST (local, no network needed) ----
  final userProvider = UserProvider();
  await userProvider.loadSavedUser();

  // ---- STEP 2: Run the app immediately (works offline!) ----
  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider<UserProvider>(create: (_) => userProvider),
        ChangeNotifierProvider<SeasonalThemeProvider>(
          create: (_) => SeasonalThemeProvider(),
        ),
      ],
      child: const VvcHrmApp(),
    ),
  );

  // ---- STEP 3: Initialize Firebase & notifications in background (non-blocking) ----
  _initFirebaseInBackground();
}

/// Initialize Firebase and push notifications in the background.
/// This runs AFTER the app is shown so offline users are never blocked.
Future<void> _initFirebaseInBackground() async {
  try {
    await Firebase.initializeApp(
      options: DefaultFirebaseOptions.currentPlatform,
    );
  } catch (e) {
    debugPrint("Firebase init failed (offline?): $e");
    return; // Stop here — no point setting up FCM if Firebase failed
  }

  try {
    // Request Firebase permission (Android 13+ & iOS)
    FirebaseMessaging messaging = FirebaseMessaging.instance;
    await messaging.requestPermission(alert: true, badge: true, sound: true);
    try {
      await NotificationService().init();
    } catch (e) {
      debugPrint("NotificationService init error: $e");
    }

    // Subscribe to Global Topic — NOT supported on web
    if (!kIsWeb) {
      await messaging
          .subscribeToTopic('all_users')
          .catchError((e) => debugPrint("FCM subscribeToTopic error: $e"));
      FirebaseMessaging.onBackgroundMessage(
        _firebaseMessagingBackgroundHandler,
      );
    }

    // Define Android notification channels
    if (!kIsWeb) {
      const AndroidNotificationChannel channel = AndroidNotificationChannel(
        'vvc_hrm_channel',
        'VVC HRM Notifications',
        description: 'ការជូនដំណឹងទូទៅពីប្រព័ន្ធ VVC HRM',
        importance: Importance.max,
        playSound: true,
      );

      const AndroidNotificationChannel callChannel = AndroidNotificationChannel(
        'vvc_attendance_call',
        'ការរំលឹកស្កេនវត្តមាន (Reminders)',
        description: 'ការរំលឹកស្កេនវត្តមាន (សម្លេងដូចគេខល)',
        importance: Importance.max,
        playSound: true,
      );
      await NotificationService().flutterLocalNotificationsPlugin
          .resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin
          >()
          ?.createNotificationChannel(channel);

      await NotificationService().flutterLocalNotificationsPlugin
          .resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin
          >()
          ?.createNotificationChannel(callChannel);

      FirebaseMessaging.onMessage.listen((RemoteMessage message) async {
        debugPrint('Got a message whilst in the foreground!');
        RemoteNotification? notification = message.notification;
        final isVersionUpdate = message.data['type'] == 'version_update';

        if (isVersionUpdate) {
          HomeScreenState? homeState = HomeScreen.homeKey.currentState;
          if (homeState == null) {
            await Future<void>.delayed(const Duration(milliseconds: 700));
            homeState = HomeScreen.homeKey.currentState;
          }

          final didShowUpdate =
              await homeState?.triggerUpdateCheck(pushData: message.data) ??
              false;
          if (didShowUpdate) {
            return;
          }
        }

        if (notification != null) {
          String activeChannel = message.data['channel_id'] ?? channel.id;

          if (kIsWeb) {
            debugPrint(
              "Web Notif Title: ${notification.title}, Body: ${notification.body}",
            );
          } else {
            await NotificationService().showNotification(
              id: notification.hashCode,
              title: notification.title ?? 'VVC HRM',
              body: notification.body ?? '',
              channelId: activeChannel,
            );
          }
        }
      });
    }

    // Web foreground messages
    if (kIsWeb) {
      FirebaseMessaging.onMessage.listen((RemoteMessage message) {
        debugPrint('Got a foreground message on Web!');
      });
    }
  } catch (e) {
    debugPrint("Firebase messaging setup error: $e");
  }

  // NotificationService is initialized before Firebase listeners above.
}

class VvcHrmApp extends StatelessWidget {
  const VvcHrmApp({super.key});

  @override
  Widget build(BuildContext context) {
    return Consumer2<UserProvider, SeasonalThemeProvider>(
      builder: (context, userProvider, seasonalTheme, child) {
        return MaterialApp(
          title: 'VVC Attendance',
          debugShowCheckedModeBanner: false,
          theme: seasonalTheme.themeData,
          home: userProvider.isLoggedIn
              ? HomeScreen(key: HomeScreen.homeKey)
              : const LoginScreen(),
        );
      },
    );
  }
}
