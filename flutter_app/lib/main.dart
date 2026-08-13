import 'dart:io' show Platform;
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:provider/provider.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

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
import 'package:vvc_hrm/services/offline_sync_service.dart';
import 'package:vvc_hrm/services/khmer_calendar_notification_service.dart';
import 'package:vvc_hrm/widgets/app_widgets.dart';
import 'package:vvc_hrm/widgets/global_call_observer.dart';

@pragma('vm:entry-point')
Future<void> _firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  await Firebase.initializeApp();
  debugPrint("Handling a background message: ${message.messageId}");
}

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  initializeDateFormatting();

  // Instant local providers
  final userProvider = UserProvider();
  final themeProvider = SeasonalThemeProvider();

  // STEP 1: Run the app immediately! First frame paints in <30ms without native launch screen freeze
  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider<UserProvider>.value(value: userProvider),
        ChangeNotifierProvider<SeasonalThemeProvider>.value(value: themeProvider),
      ],
      child: const VvcHrmApp(),
    ),
  );

  // STEP 2: Asynchronous background bootstrapping
  _runBackgroundBootstrap(userProvider);
}

/// Asynchronously initialize all background services without blocking UI rendering
Future<void> _runBackgroundBootstrap(UserProvider userProvider) async {
  // 1. Fast load saved user
  await userProvider.loadSavedUser();

  // 2. Start offline sync
  OfflineSyncService().startListening();

  // 3. Background location (non-blocking)
  if (!kIsWeb) {
    try {
      await BackgroundLocationService.initializeService();
    } catch (e) {
      debugPrint("BackgroundLocationService init error: $e");
    }
  }

  // 4. Initialize Firebase & push notifications in background
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

  final bool isMobile = !kIsWeb && (Platform.isAndroid || Platform.isIOS);
  if (isMobile) {
    try {
      FirebaseMessaging messaging = FirebaseMessaging.instance;
      await messaging.requestPermission(alert: true, badge: true, sound: true);
      try {
        await NotificationService().init();
      } catch (e) {
        debugPrint("NotificationService init error: $e");
      }

      // Schedule Khmer calendar holiday & sila notifications for the year
      try {
        await KhmerCalendarNotificationService().scheduleForYear();
      } catch (e) {
        debugPrint("KhmerCalendarNotif scheduleForYear error: $e");
      }

      // Subscribe to Global Topic
      await messaging
          .subscribeToTopic('all_users')
          .catchError((e) => debugPrint("FCM subscribeToTopic error: $e"));
      FirebaseMessaging.onBackgroundMessage(
        _firebaseMessagingBackgroundHandler,
      );

      // Define Android notification channels
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

      const AndroidNotificationChannel calendarChannel = AndroidNotificationChannel(
        'vvc_khmer_calendar',
        'ការជូនដំណឹងប្រតិទិនខ្មែរ',
        description: 'ជូនដំណឹងថ្ងៃបុណ្យ និង ថ្ងៃសីល',
        importance: Importance.max,
        playSound: true,
      );

      final androidPlugin = NotificationService().flutterLocalNotificationsPlugin
          .resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin
          >();
      await androidPlugin?.createNotificationChannel(channel);
      await androidPlugin?.createNotificationChannel(callChannel);
      await androidPlugin?.createNotificationChannel(calendarChannel);

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
          await NotificationService().showNotification(
            id: notification.hashCode,
            title: notification.title ?? 'VVC HRM',
            body: notification.body ?? '',
            channelId: activeChannel,
          );
        }
      });
    } catch (e) {
      debugPrint("Mobile Notification setup error: $e");
    }
  }

  // Web foreground messages
  if (kIsWeb) {
    FirebaseMessaging.onMessage.listen((RemoteMessage message) {
      debugPrint('Got a foreground message on Web!');
    });
  }
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
          home: GlobalCallObserver(
            child: !userProvider.isInitialized
                ? const VvcAppSplashScreen()
                : (userProvider.isLoggedIn
                    ? HomeScreen(key: HomeScreen.homeKey)
                    : const LoginScreen()),
          ),
          localizationsDelegates: const [
            GlobalMaterialLocalizations.delegate,
            GlobalWidgetsLocalizations.delegate,
            GlobalCupertinoLocalizations.delegate,
          ],
          supportedLocales: const [
            Locale('en', 'US'),
            Locale('km', 'KH'),
          ],
        );
      },
    );
  }
}
