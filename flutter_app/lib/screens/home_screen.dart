import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:animate_do/animate_do.dart';
import 'package:intl/intl.dart';
import 'package:google_nav_bar/google_nav_bar.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../providers/user_provider.dart';
import '../services/background_location_service.dart';
import '../core/theme/theme_provider.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import '../widgets/app_update_dialog.dart';
import '../services/api_service.dart';
import '../services/notification_service.dart';
import 'login_screen.dart';
import 'attendance_screen.dart';
import 'scan_history_screen.dart';
import 'outside_attendance_screen.dart';
import 'requests_screen.dart';
import 'material_request_screen.dart';
import 'profile_screen.dart';
import 'notification_screen.dart';
import 'send_notification_screen.dart';
import 'announcements_screen.dart';
import 'meetings_screen.dart';
import 'checklist_screen.dart';
import 'daily_report_screen.dart';
import 'mission_screen.dart';
import 'request_list_screen.dart';
import 'user_management_screen.dart';
import 'attendance_report_screen.dart';
import 'employee_report_screen.dart';
import 'trip_screen.dart';
import 'trip_report_screen.dart';
import 'payroll_admin_screen.dart';
import 'payroll_screen.dart';
import 'chat_list_screen.dart';
import 'outside_report_screen.dart';
import 'training_quiz_screen.dart';
import 'ai_chat_screen.dart';

// ========== SLIDE PAGE ROUTE (Feature #9) ==========
PageRouteBuilder _slideRoute(Widget page) {
  return PageRouteBuilder(
    transitionDuration: const Duration(milliseconds: 380),
    reverseTransitionDuration: const Duration(milliseconds: 300),
    pageBuilder: (context, animation, secondaryAnimation) => page,
    transitionsBuilder: (context, animation, secondaryAnimation, child) {
      final tween = Tween<Offset>(
        begin: const Offset(1.0, 0.0),
        end: Offset.zero,
      ).chain(CurveTween(curve: Curves.easeInOutCubic));
      final fadeTween = Tween<double>(
        begin: 0.0,
        end: 1.0,
      ).chain(CurveTween(curve: Curves.easeIn));
      return SlideTransition(
        position: animation.drive(tween),
        child: FadeTransition(
          opacity: animation.drive(fadeTween),
          child: child,
        ),
      );
    },
  );
}

// Feature #10: Haptic helpers
void _hapticLight() => HapticFeedback.lightImpact();
void _hapticMedium() => HapticFeedback.mediumImpact();
void _hapticSuccess() {
  HapticFeedback.heavyImpact();
  Future.delayed(
    const Duration(milliseconds: 120),
    () => HapticFeedback.lightImpact(),
  );
}

class HomeScreen extends StatefulWidget {
  static final GlobalKey<HomeScreenState> homeKey =
      GlobalKey<HomeScreenState>();
  const HomeScreen({super.key});

  @override
  HomeScreenState createState() => HomeScreenState();
}

class HomeScreenState extends State<HomeScreen> {
  int _currentIndex = 0;
  bool _isUpdateDialogVisible = false;

  List<Widget> _getScreens(UserProvider user) {
    return [
      HomeContent(onProfileTap: () => setState(() => _currentIndex = 2)),
      (user.isHRM) ? const RequestListScreen() : const RequestsScreen(),
      const ProfileScreen(),
    ];
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      if (mounted) {
        _checkForUpdates();

        // Ensure background location service is running if an active trip exists.
        // Sometimes the user returns to Home and the foreground map was the only
        // place that kept the location active; any active trip should keep the
        // background tracker running so location continues.
        try {
          final prefs = await SharedPreferences.getInstance();
          final currentTrip = prefs.getString('current_active_trip_id');
          if (currentTrip != null && currentTrip.isNotEmpty) {
            await BackgroundLocationService.startTracking();
          }
        } catch (e) {
          debugPrint('Failed to start background tracking from HomeScreen: $e');
        }
      }
    });
  }

  /// Public method to trigger update check (e.g. from push notification)
  Future<bool> triggerUpdateCheck({Map<String, dynamic>? pushData}) async {
    if (!mounted) return false;
    return _checkForUpdates(pushData: pushData);
  }

  Future<bool> _checkForUpdates({Map<String, dynamic>? pushData}) async {
    try {
      final packageInfo = await PackageInfo.fromPlatform();
      final version = packageInfo.version;
      final buildNumberStr = packageInfo.buildNumber;
      final buildNumber = int.tryParse(buildNumberStr) ?? 1;

      final result = await ApiService().checkAppVersion(version, buildNumber);
      if (result['success'] == true &&
          result['has_update'] == true &&
          mounted) {
        await _showUpdateDialog(
          result['latest_version'],
          result['message'],
          result['apk_url'],
          result['force_update'] == true,
        );
        return true;
      }

      final pushUpdate = _parsePushUpdatePayload(pushData);
      if (pushUpdate != null &&
          _isRemoteUpdateNewer(
            currentVersion: version,
            currentBuild: buildNumber,
            remoteVersion: pushUpdate.version,
            remoteBuild: pushUpdate.build,
          )) {
        await _showUpdateDialog(
          pushUpdate.version,
          pushUpdate.message,
          pushUpdate.apkUrl,
          pushUpdate.forceUpdate,
        );
        return true;
      }
    } catch (e) {
      debugPrint('Update check failed: $e');
    }
    return false;
  }

  _PushUpdatePayload? _parsePushUpdatePayload(Map<String, dynamic>? pushData) {
    if (pushData == null || pushData.isEmpty) return null;

    final version = '${pushData['latest_version'] ?? pushData['version'] ?? ''}'
        .trim();
    final build =
        int.tryParse(
          '${pushData['latest_build'] ?? pushData['build_number'] ?? '0'}',
        ) ??
        0;
    final apkUrl = '${pushData['apk_url'] ?? ''}'.trim();
    final message = '${pushData['message'] ?? pushData['update_message'] ?? ''}'
        .trim();
    final forceRaw = '${pushData['force_update'] ?? '0'}'.trim();
    final forceUpdate = forceRaw == '1' || forceRaw.toLowerCase() == 'true';

    if (version.isEmpty || apkUrl.isEmpty) {
      return null;
    }

    return _PushUpdatePayload(
      version: version,
      build: build,
      apkUrl: apkUrl,
      message: message.isNotEmpty
          ? message
          : 'កម្មវិធីមានជំនាន់ថ្មី។ សូមធ្វើការអាប់ដេត។',
      forceUpdate: forceUpdate,
    );
  }

  bool _isRemoteUpdateNewer({
    required String currentVersion,
    required int currentBuild,
    required String remoteVersion,
    required int remoteBuild,
  }) {
    if (remoteBuild > currentBuild) return true;
    return _compareSemanticVersion(remoteVersion, currentVersion) > 0;
  }

  int _compareSemanticVersion(String a, String b) {
    final aParts = a.split('.').map((e) => int.tryParse(e) ?? 0).toList();
    final bParts = b.split('.').map((e) => int.tryParse(e) ?? 0).toList();
    final maxLength = aParts.length > bParts.length
        ? aParts.length
        : bParts.length;

    for (var i = 0; i < maxLength; i++) {
      final aValue = i < aParts.length ? aParts[i] : 0;
      final bValue = i < bParts.length ? bParts[i] : 0;
      if (aValue != bValue) {
        return aValue.compareTo(bValue);
      }
    }
    return 0;
  }

  Future<void> _showUpdateDialog(
    String version,
    String msg,
    String apkUrl,
    bool forceUpdate,
  ) async {
    if (!mounted || _isUpdateDialogVisible) return;
    _isUpdateDialogVisible = true;

    try {
      await Future<void>.delayed(Duration.zero);
      if (!mounted) return;
      await showAppUpdateDialog(
        context: context,
        version: version,
        message: msg,
        apkUrl: apkUrl,
        forceUpdate: forceUpdate,
      );
    } finally {
      _isUpdateDialogVisible = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    final userProvider = Provider.of<UserProvider>(context);
    if (!userProvider.isLoggedIn) return const LoginScreen();

    final screens = _getScreens(userProvider);

    return Scaffold(
      extendBody: true,
      backgroundColor: AppTheme.bgDark,
      body: IndexedStack(index: _currentIndex, children: screens),
      bottomNavigationBar: _buildBottomNav(userProvider),
      floatingActionButton: _currentIndex == 0
          ? Transform.translate(
              offset: const Offset(0, 6),
              child: SizedBox(
                width: 48, // ទំហំប៊ូតុងតូចជាងមុន
                height: 48,
                child: FloatingActionButton(
                  backgroundColor: AppTheme.primary,
                  elevation: 6,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14),
                  ),
                  onPressed: () {
                    _hapticLight();
                    Navigator.push(context, _slideRoute(const AiChatScreen()));
                  },
                  child: const Icon(
                    Icons.smart_toy_rounded,
                    color: Colors.white,
                    size: 24, // ទំហំ Icon តូចជាងមុន
                  ),
                ),
              ),
            )
          : null,
    );
  }

  Widget _buildBottomNav(UserProvider user) {
    final hPad = AppResponsive.horizontalPadding(context);
    final bottomInset = MediaQuery.paddingOf(context).bottom;
    return Container(
      margin: EdgeInsets.fromLTRB(hPad, 0, hPad, bottomInset + 14),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(30),
        border: Border.all(
          color: AppTheme.textPrimary.withValues(alpha: 0.08),
          width: 1,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.4),
            blurRadius: 25,
            offset: const Offset(0, 10),
          ),
        ],
      ),
      child: Padding(
        padding: EdgeInsets.symmetric(
          horizontal: AppResponsive.isCompact(context) ? 8 : 15,
          vertical: 8,
        ),
        child: GNav(
          rippleColor: AppTheme.primary.withValues(alpha: 0.3),
          hoverColor: AppTheme.primary.withValues(alpha: 0.1),
          gap: 8,
          activeColor: AppTheme.primary,
          iconSize: 24,
          padding: EdgeInsets.symmetric(
            horizontal: AppResponsive.isCompact(context) ? 14 : 20,
            vertical: 12,
          ),
          duration: const Duration(milliseconds: 400),
          tabBackgroundColor: AppTheme.primary.withValues(alpha: 0.1),
          color: AppTheme.textMuted,
          tabs: [
            GButton(
              icon: Icons.dashboard_rounded,
              text: 'ទំព័រដើម',
              textStyle: GoogleFonts.kantumruyPro(
                color: AppTheme.primary,
                fontWeight: FontWeight.bold,
                fontSize: 13,
              ),
            ),
            GButton(
              icon: user.isHRM ? Icons.list_alt_rounded : Icons.layers_rounded,
              text: user.isHRM ? "បញ្ជីសំណើ" : "សំណើ",
              textStyle: GoogleFonts.kantumruyPro(
                color: AppTheme.primary,
                fontWeight: FontWeight.bold,
                fontSize: 13,
              ),
            ),
            GButton(
              icon: Icons.person_rounded,
              text: 'គណនី',
              textStyle: GoogleFonts.kantumruyPro(
                color: AppTheme.primary,
                fontWeight: FontWeight.bold,
                fontSize: 13,
              ),
            ),
          ],
          selectedIndex: _currentIndex,
          onTabChange: (index) {
            setState(() {
              _currentIndex = index;
            });
          },
        ),
      ),
    );
  }
}

class _PushUpdatePayload {
  final String version;
  final int build;
  final String apkUrl;
  final String message;
  final bool forceUpdate;

  const _PushUpdatePayload({
    required this.version,
    required this.build,
    required this.apkUrl,
    required this.message,
    required this.forceUpdate,
  });
}

// ========== HOME CONTENT ==========
class HomeContent extends StatefulWidget {
  final VoidCallback? onProfileTap;
  const HomeContent({super.key, this.onProfileTap});

  @override
  State<HomeContent> createState() => _HomeContentState();
}

class _HomeContentState extends State<HomeContent> {
  final ApiService _api = ApiService();
  Map<String, dynamic> _stats = {
    'today_work': 0,
    'requests_count': 0,
    'announcements_count': 0,
    'unread_notifications': 0,
    'annual_leave_remaining': 0,
  };
  bool _isLoadingStats = true;
  int? _lastUnreadNotificationCount;
  String _nextAction = 'Check-In'; // auto-detected from last action
  bool _isLoadingNextAction = true;
  Timer? _pollingTimer;
  final PageController _statsController = PageController(
    viewportFraction: 0.92,
  );
  int _currentStatPage = 0;
  Timer? _statsAutoTimer;

  // Banner Slider
  final PageController _bannerController = PageController();
  int _currentBannerPage = 0;
  Timer? _bannerAutoTimer;
  List<dynamic> _banners = [];

  // ===== Feature #1: Live Work Timer =====
  DateTime? _checkInTime;
  Timer? _liveTimerTick;
  String _liveWorkDuration = '';

  // ===== Feature #5: Attendance Streak =====
  int _attendanceStreak = 0;

  // ===== Feature #8: Weather =====
  String _weatherText = '';
  String _weatherIcon = '☀️';

  void _safeSetState(VoidCallback fn) {
    if (!mounted) return;
    setState(fn);
  }

  @override
  void initState() {
    super.initState();
    _loadStats();
    _loadNextAction();
    _loadStreak();
    _loadCheckInTime();
    _loadWeather();
    _pollingTimer = Timer.periodic(const Duration(seconds: 6), (timer) {
      if (mounted) {
        _refreshStatsSilently();
        _loadNextAction();
        _api.syncOfflineAttendance();
        Provider.of<UserProvider>(context, listen: false).refreshProfile();
      }
    });

    _loadBanners();
    _startStatsAutoSlide();
    _startBannerAutoSlide();

    Future.microtask(() async {
      if (!mounted) return;
      final userProvider = Provider.of<UserProvider>(context, listen: false);
      final themeProvider = Provider.of<SeasonalThemeProvider>(
        context,
        listen: false,
      );

      await userProvider.refreshConfig();
      final themeSeason = userProvider.getConfig('app_theme_season');
      if (themeSeason.isNotEmpty) {
        themeProvider.updateFromBackend(themeSeason);
      }
      if (mounted) userProvider.refreshProfile();
    });
  }

  // ===== Feature #1: Live Work Timer =====
  Future<void> _loadCheckInTime() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final ts = prefs.getString('last_checkin_time');
      if (ts != null) {
        final t = DateTime.tryParse(ts);
        if (t != null && DateTime.now().difference(t).inHours < 16) {
          _safeSetState(() => _checkInTime = t);
          _startLiveTimer();
        }
      }
    } catch (_) {}
  }

  void _startLiveTimer() {
    _liveTimerTick?.cancel();
    _liveTimerTick = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted || _checkInTime == null) return;
      final diff = DateTime.now().difference(_checkInTime!);
      final h = diff.inHours;
      final m = diff.inMinutes % 60;
      final s = diff.inSeconds % 60;
      _safeSetState(() {
        _liveWorkDuration =
            '${h.toString().padLeft(2, '0')}:${m.toString().padLeft(2, '0')}:${s.toString().padLeft(2, '0')}';
      });
    });
  }

  Future<void> _saveCheckInTime() async {
    final prefs = await SharedPreferences.getInstance();
    final now = DateTime.now();
    await prefs.setString('last_checkin_time', now.toIso8601String());
    _safeSetState(() => _checkInTime = now);
    _startLiveTimer();
  }

  Future<void> _clearCheckInTime() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('last_checkin_time');
    _liveTimerTick?.cancel();
    _safeSetState(() {
      _checkInTime = null;
      _liveWorkDuration = '';
    });
  }

  // ===== Feature #5: Attendance Streak =====
  Future<void> _loadStreak() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final streak = prefs.getInt('attendance_streak') ?? 0;
      final lastDateStr = prefs.getString('streak_last_date') ?? '';
      final today = DateFormat('yyyy-MM-dd').format(DateTime.now());
      final yesterday = DateFormat(
        'yyyy-MM-dd',
      ).format(DateTime.now().subtract(const Duration(days: 1)));

      if (lastDateStr == today) {
        _safeSetState(() => _attendanceStreak = streak);
      } else if (lastDateStr == yesterday) {
        // Streak still valid from yesterday, keep it until today's check-in
        _safeSetState(() => _attendanceStreak = streak);
      } else {
        // Streak broken
        await prefs.setInt('attendance_streak', 0);
        _safeSetState(() => _attendanceStreak = 0);
      }
    } catch (_) {}
  }

  Future<void> _incrementStreak() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final today = DateFormat('yyyy-MM-dd').format(DateTime.now());
      final lastDate = prefs.getString('streak_last_date') ?? '';
      if (lastDate != today) {
        final streak = (prefs.getInt('attendance_streak') ?? 0) + 1;
        await prefs.setInt('attendance_streak', streak);
        await prefs.setString('streak_last_date', today);
        _safeSetState(() => _attendanceStreak = streak);
      }
    } catch (_) {}
  }

  Future<void> _loadWeather() async {
    try {
      // OpenMeteo free API - Phnom Penh coordinates (11.5564, 104.9282)
      final uri = Uri.parse(
        'https://api.open-meteo.com/v1/forecast?latitude=11.5564&longitude=104.9282&current=temperature_2m,weathercode&timezone=Asia%2FPhnom_Penh',
      );
      final response = await _api.httpGet(uri.toString());
      if (!mounted) return;
      if (response != null && response['current'] != null) {
        final temp = response['current']['temperature_2m']?.round() ?? 0;
        final code = response['current']['weathercode'] ?? 0;
        String icon = '☀️';
        if (code >= 61 && code <= 67) {
          icon = '🌧️';
        } else if (code >= 51 && code <= 57) {
          icon = '🌦️';
        } else if (code >= 71 && code <= 77) {
          icon = '❄️';
        } else if (code >= 80 && code <= 82) {
          icon = '⛈️';
        } else if (code >= 1 && code <= 3) {
          icon = '⛅';
        } else if (code == 45 || code == 48) {
          icon = '🌫️';
        }
        _safeSetState(() {
          _weatherText = '$temp°C';
          _weatherIcon = icon;
        });
      }
    } catch (_) {}
  }

  Future<void> _loadNextAction() async {
    try {
      final result = await _api.fetchLastAction();
      if (result['success'] == true) {
        final last = result['last_action'] ?? 'Check-Out';
        _safeSetState(() {
          _nextAction = (last == 'Check-In') ? 'Check-Out' : 'Check-In';
          _isLoadingNextAction = false;
        });
      } else {
        _safeSetState(() => _isLoadingNextAction = false);
      }
    } catch (_) {
      _safeSetState(() => _isLoadingNextAction = false);
    }
  }

  void _goScan(String action) {
    _hapticMedium();
    Navigator.push(
      context,
      _slideRoute(AttendanceScreen(presetAction: action)),
    ).then((result) {
      _safeSetState(() => _isLoadingNextAction = true);
      _loadNextAction();
      // Feature #1 & #5: track check-in time and streak
      if (result == 'checked_in') {
        _saveCheckInTime();
        _incrementStreak();
        _showMoodDialog(); // Feature #2
      } else if (result == 'checked_out') {
        _clearCheckInTime();
        _hapticSuccess();
      }
    });
  }

  // ===== Feature #2: Mood Check-In Dialog =====
  void _showMoodDialog() {
    Future.delayed(const Duration(milliseconds: 600), () {
      if (!mounted) return;
      showDialog(
        context: context,
        builder: (ctx) => Dialog(
          backgroundColor: Colors.transparent,
          child: Container(
            padding: const EdgeInsets.all(28),
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(28),
              border: Border.all(
                color: AppTheme.primary.withValues(alpha: 0.2),
              ),
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.sentiment_satisfied_alt_rounded,
                  color: AppTheme.primaryLight,
                  size: 36,
                ),
                const SizedBox(height: 12),
                Text(
                  'ថ្ងៃនេះ Feeling ដូចម្ដេច?',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 20),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    _buildMoodBtn(ctx, '😴', 'ងងុយ'),
                    _buildMoodBtn(ctx, '😊', 'ល្អ'),
                    _buildMoodBtn(ctx, '🔥', 'Productive'),
                    _buildMoodBtn(ctx, '😤', 'ហត់'),
                  ],
                ),
                const SizedBox(height: 12),
                TextButton(
                  onPressed: () => Navigator.pop(ctx),
                  child: Text(
                    'រំលង',
                    style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted),
                  ),
                ),
              ],
            ),
          ),
        ),
      );
    });
  }

  Widget _buildMoodBtn(BuildContext ctx, String emoji, String label) {
    return GestureDetector(
      onTap: () {
        _hapticSuccess();
        Navigator.pop(ctx);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              '$emoji ថ្ងៃល្អ! $label — ទៅ 💪',
              style: GoogleFonts.kantumruyPro(
                fontSize: 14,
                color: Colors.white,
              ),
            ),
            backgroundColor: AppTheme.primary,
            behavior: SnackBarBehavior.floating,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(14),
            ),
            duration: const Duration(seconds: 2),
          ),
        );
      },
      child: Column(
        children: [
          Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              shape: BoxShape.circle,
              border: Border.all(
                color: AppTheme.primary.withValues(alpha: 0.2),
              ),
            ),
            child: Center(
              child: Text(emoji, style: const TextStyle(fontSize: 26)),
            ),
          ),
          const SizedBox(height: 6),
          Text(
            label,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textSecondary,
              fontSize: 11,
            ),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    _statsAutoTimer?.cancel();
    _bannerAutoTimer?.cancel();
    _liveTimerTick?.cancel();
    _statsController.dispose();
    _bannerController.dispose();
    super.dispose();
  }

  void _startStatsAutoSlide() {
    _statsAutoTimer?.cancel();
    _statsAutoTimer = Timer.periodic(const Duration(seconds: 4), (timer) {
      if (!mounted || !_statsController.hasClients) return;

      final int count = _getStatsCount();
      if (count <= 1) return;

      int next = _currentStatPage + 1;
      if (next >= count) next = 0;

      _statsController.animateToPage(
        next,
        duration: const Duration(milliseconds: 600),
        curve: Curves.easeInOutCubic,
      );
    });
  }

  void _startBannerAutoSlide() {
    _bannerAutoTimer?.cancel();
    _bannerAutoTimer = Timer.periodic(const Duration(seconds: 6), (timer) {
      if (!mounted || !_bannerController.hasClients) return;

      final int count = _banners.length + 1; // +1 for Employee Pass
      if (count <= 1) return;

      int next = _currentBannerPage + 1;
      if (next >= count) next = 0;

      _bannerController.animateToPage(
        next,
        duration: const Duration(milliseconds: 800),
        curve: Curves.fastOutSlowIn,
      );
    });
  }

  Future<void> _loadBanners() async {
    try {
      final result = await _api.fetchAnnouncements();
      if (mounted && result['success'] == true) {
        setState(() {
          _banners = result['data'] ?? [];
        });
      }
    } catch (e) {
      // ignore error, banners will just remain empty
    }
  }

  int _getStatsCount() {
    final role = Provider.of<UserProvider>(context, listen: false).systemRole;
    int count = 3; // default: tasks, announcements, leave
    if (role == SystemRole.admin || role == SystemRole.hrm) {
      count = 4; // adds pending requests
    }
    return count;
  }

  Future<void> _loadStats() async {
    try {
      final result = await _api.fetchDashboardStats();
      if (result['success'] == true) {
        final nextStats = _normalizeStats(result['stats']);
        _safeSetState(() {
          _stats = nextStats;
          _lastUnreadNotificationCount = _readUnreadCount(nextStats);
          _isLoadingStats = false;
        });
      } else {
        _safeSetState(() => _isLoadingStats = false);
      }
    } catch (_) {
      _safeSetState(() => _isLoadingStats = false);
    }
  }

  Future<void> _refreshStatsSilently() async {
    try {
      // Note: We avoid calling userProvider.refreshConfig() here because it triggers
      // notifyListeners() which causes a full MaterialApp rebuild (flicker) every 10s.
      // Dashboard stats are updated via local state which is much more efficient.
      final result = await _api.fetchDashboardStats();
      if (result['success'] == true) {
        final nextStats = _normalizeStats(result['stats']);
        final nextUnread = _readUnreadCount(nextStats);
        final previousUnread = _lastUnreadNotificationCount;
        _safeSetState(() {
          _stats = nextStats;
          _lastUnreadNotificationCount = nextUnread;
        });
        if (previousUnread != null && nextUnread > previousUnread) {
          await _showNewNotificationAlert(nextUnread - previousUnread);
        }
      }
    } catch (_) {}
  }

  Map<String, dynamic> _normalizeStats(dynamic stats) {
    if (stats is Map<String, dynamic>) return stats;
    if (stats is Map) return Map<String, dynamic>.from(stats);
    return _stats;
  }

  int _readUnreadCount(Map<String, dynamic> stats) {
    final v = stats['unread_notifications'];
    if (v == null) return 0;
    if (v is int) return v;
    if (v is num) return v.toInt();
    if (v is String) return int.tryParse(v) ?? 0;
    return 0;
  }

  Future<void> _showNewNotificationAlert(int count) async {
    if (!mounted || count <= 0) return;
    try {
      await NotificationService().showNotification(
        id: DateTime.now().millisecondsSinceEpoch.remainder(2147483647),
        title: 'ការជូនដំណឹងថ្មី',
        body: count == 1
            ? 'មានការជូនដំណឹងថ្មីមួយសម្រាប់អ្នក'
            : 'មានការជូនដំណឹងថ្មី $count សម្រាប់អ្នក',
        payload: 'notifications',
      );
    } catch (_) {}
  }

  int get _unreadNotifications {
    return _readUnreadCount(_stats);
  }

  // ===== Feature #7: Smart Greeting =====
  String get _greeting {
    final h = DateTime.now().hour;
    final now = DateTime.now();
    // Birthday check (if user has DOB - fallback to time-based)
    if (h < 6) return "ព្រឹកស្ងាត់ — ហ្នឹងសម្រាន្តទៀតបន្ដិចណា 😴";
    if (h < 10) return "អរុណសួស្ដី — Ready ហើយ? 💪";
    if (h < 12) {
      return "ម៉ោង$h:${now.minute.toString().padLeft(2, '0')} — Keep Going! 🔥";
    }
    if (h < 14) return "ថ្ងៃត្រង់ — Lunch Break ហើយ 🍜";
    if (h < 17) return "ទិវាសួស្ដី — ៣ ម៉ោងទៀតចប់ 🎯";
    if (h < 20) return "សាយណ្ហសួស្ដី — Good Job ថ្ងៃនេះ! ✅";
    return "យប់ — សម្រាន្ដ ដើម្បីថ្ងៃស្អែក 🌙";
  }

  String get _todayDate => DateFormat('dd/MM/yyyy').format(DateTime.now());

  @override
  Widget build(BuildContext context) {
    final user = Provider.of<UserProvider>(context);

    return Container(
      decoration: BoxDecoration(color: AppTheme.bgSurface),
      child: Stack(
        children: [
          Positioned(
            top: -120,
            right: -100,
            child: IgnorePointer(
              child: Container(
                width: 380,
                height: 380,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: AppTheme.primary.withValues(alpha: 0.08),
                ),
              ),
            ),
          ),
          Positioned(
            top: 300,
            left: -120,
            child: IgnorePointer(
              child: Container(
                width: 320,
                height: 320,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: AppTheme.secondary.withValues(alpha: 0.06),
                ),
              ),
            ),
          ),
          Positioned(
            bottom: 100,
            right: -150,
            child: IgnorePointer(
              child: Container(
                width: 450,
                height: 450,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: AppTheme.primary.withValues(alpha: 0.05),
                ),
              ),
            ),
          ),

          RefreshIndicator(
            onRefresh: () async {
              final seasonalThemeProvider = Provider.of<SeasonalThemeProvider>(
                context,
                listen: false,
              );
              await user.refreshConfig();
              final themeSeason = user.getConfig('app_theme_season');
              if (themeSeason.isNotEmpty && mounted) {
                seasonalThemeProvider.updateFromBackend(themeSeason);
              }
              await _loadStats();
              await _loadWeather();
              _loadNextAction();
              if (mounted) user.refreshProfile();
            },
            color: AppTheme.primary,
            backgroundColor: AppTheme.bgDark,
            child: CustomScrollView(
              physics: const AlwaysScrollableScrollPhysics(
                parent: BouncingScrollPhysics(),
              ),
              slivers: [
                SliverToBoxAdapter(
                  child: SafeArea(
                    bottom: false,
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          _buildTopBar(user),
                          const SizedBox(height: 12),
                          _buildWeatherAndQuoteRow(),
                          const SizedBox(height: 14),
                          _buildWelcomeBanner(user),
                          const SizedBox(height: 24),
                          _buildRoleBasedActions(user),
                          SizedBox(
                            height: AppResponsive.bottomPadding(
                              context,
                              hasBottomNav: true,
                              extra: 18,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ===== Feature #1 + #5 + #8: Weather, Streak & Live Timer Row =====
  Widget _buildWeatherAndQuoteRow() {
    return FadeInDown(
      delay: const Duration(milliseconds: 100),
      duration: const Duration(milliseconds: 400),
      child: Row(
        children: [
          // Feature #8: Weather pill
          if (_weatherText.isNotEmpty)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: AppTheme.primary.withValues(alpha: 0.2),
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(_weatherIcon, style: const TextStyle(fontSize: 14)),
                  const SizedBox(width: 6),
                  Text(
                    'ភ្នំពេញ $_weatherText',
                    style: GoogleFonts.inter(
                      color: AppTheme.textSecondary,
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          if (_weatherText.isNotEmpty) const SizedBox(width: 8),
          // Feature #5: Streak pill
          if (_attendanceStreak > 0)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: Colors.orange.withValues(alpha: 0.18),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: Colors.orange.withValues(alpha: 0.4)),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text('🔥', style: TextStyle(fontSize: 13)),
                  const SizedBox(width: 4),
                  Text(
                    '$_attendanceStreak ថ្ងៃ',
                    style: GoogleFonts.inter(
                      color: Colors.orange,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          const Spacer(),
          // Feature #1: Live work timer
          if (_liveWorkDuration.isNotEmpty)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              decoration: BoxDecoration(
                color: Colors.green.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: Colors.greenAccent.withValues(alpha: 0.3),
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(
                    Icons.timer_outlined,
                    color: Colors.greenAccent,
                    size: 13,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    _liveWorkDuration,
                    style: GoogleFonts.inter(
                      color: Colors.greenAccent,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                      fontFeatures: [const FontFeature.tabularFigures()],
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildTopBar(UserProvider user) {
    return FadeInDown(
      duration: const Duration(milliseconds: 400),
      child: Row(
        children: [
          // User Avatar & Greeting
          Expanded(
            child: GestureDetector(
              onTap: widget.onProfileTap,
              behavior: HitTestBehavior.opaque,
              child: Row(
                children: [
                  Stack(
                    clipBehavior: Clip.none,
                    children: [
                      Container(
                        width: 42,
                        height: 42,
                        decoration: BoxDecoration(
                          color: AppTheme.primary,
                          shape: BoxShape.circle,
                          boxShadow: AppTheme.primaryShadow,
                        ),
                        child: ClipOval(
                          child:
                              user.avatarUrl != null &&
                                  user.avatarUrl!.isNotEmpty
                              ? Image.network(
                                  user.avatarUrl!,
                                  fit: BoxFit.cover,
                                  errorBuilder: (context, error, stackTrace) =>
                                      _buildInitialsAvatar(user),
                                )
                              : _buildInitialsAvatar(user),
                        ),
                      ),
                      if (user.isVerified)
                        Positioned(
                          bottom: -2,
                          right: -2,
                          child: Container(
                            decoration: const BoxDecoration(
                              color: Colors.white,
                              shape: BoxShape.circle,
                            ),
                            child: const Icon(
                              Icons.verified,
                              color: Colors.blueAccent,
                              size: 14,
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          _greeting,
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white.withValues(alpha: 0.7),
                            fontSize: 11,
                            fontWeight: FontWeight.w500,
                            letterSpacing: 0.3,
                            height: 1.4,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        Text(
                          user.name ?? 'បុគ្គលិក',
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textPrimary,
                            fontWeight: FontWeight.bold,
                            fontSize: 15,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(width: 2),
          // Action Icons Group
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              _buildTopIcon(
                Icons.psychology_rounded,
                () => Navigator.push(
                  context,
                  _slideRoute(const TrainingQuizScreen()),
                ),
              ),
              _buildTopIcon(
                Icons.forum_rounded,
                () => Navigator.push(
                  context,
                  _slideRoute(const ChatListScreen()),
                ),
              ),
              _buildTopIcon(
                Icons.notifications_rounded,
                () => Navigator.push(
                  context,
                  _slideRoute(const NotificationScreen()),
                ),
                badge: _unreadNotifications > 0,
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildTopIcon(
    IconData icon,
    VoidCallback onTap, {
    Color? color,
    bool badge = false,
  }) {
    return GestureDetector(
      onTap: () {
        _hapticLight();
        onTap();
      },
      child: Container(
        margin: const EdgeInsets.only(left: 2),
        width: 38,
        height: 38,
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          shape: BoxShape.circle,
          border: Border.all(
            color: Colors.white.withValues(alpha: 0.2),
            width: 1.2,
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.15),
              blurRadius: 10,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Stack(
          alignment: Alignment.center,
          children: [
            Icon(icon, color: color ?? Colors.white, size: 24),
            if (badge)
              Positioned(
                top: 10,
                right: 10,
                child: Container(
                  width: 9,
                  height: 9,
                  decoration: BoxDecoration(
                    color: Colors.redAccent,
                    shape: BoxShape.circle,
                    border: Border.all(color: AppTheme.bgCard, width: 1.5),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildInitialsAvatar(UserProvider user) {
    return Center(
      child: Text(
        (user.name ?? 'U').isNotEmpty
            ? user.name!.substring(0, 1).toUpperCase()
            : 'U',
        style: GoogleFonts.inter(
          color: AppTheme.textPrimary,
          fontWeight: FontWeight.bold,
          fontSize: 18,
        ),
      ),
    );
  }

  Widget _buildStatsSlider(UserProvider user) {
    final role = user.systemRole;
    final List<Widget> stats = [];

    stats.add(
      AppStatCard(
        label: "កិច្ចការថ្ងៃនេះ",
        value: '${_stats['today_work']}',
        icon: Icons.task_alt_rounded,
        color: AppTheme.primary,
        isLoading: _isLoadingStats,
      ),
    );
    stats.add(
      AppStatCard(
        label: "ការជូនដំណឹង",
        value: '${_stats['announcements_count']}',
        icon: Icons.campaign_rounded,
        color: AppTheme.warning,
        isLoading: _isLoadingStats,
      ),
    );
    stats.add(
      AppStatCard(
        label: "ច្បាប់នៅសល់",
        value: '${_stats['annual_leave_remaining']}',
        icon: Icons.beach_access_rounded,
        color: AppTheme.success,
        isLoading: _isLoadingStats,
      ),
    );

    if (role == SystemRole.admin || role == SystemRole.hrm) {
      stats.add(
        AppStatCard(
          label: "សំណើរ Pending",
          value: '${_stats['requests_count']}',
          icon: Icons.pending_actions_rounded,
          color: AppTheme.secondary,
          isLoading: _isLoadingStats,
        ),
      );
    }

    return Column(
      children: [
        const Padding(
          padding: EdgeInsets.symmetric(horizontal: 20),
          child: SectionHeader(title: "ស្ថិតិប្រចាំថ្ងៃ"),
        ),
        const SizedBox(height: 14),
        SizedBox(
          height: 150,
          child: PageView.builder(
            controller: _statsController,
            onPageChanged: (idx) => _safeSetState(() => _currentStatPage = idx),
            physics: const BouncingScrollPhysics(),
            itemCount: stats.length,
            itemBuilder: (context, index) => Padding(
              padding: const EdgeInsets.symmetric(horizontal: 6),
              child: FadeIn(child: stats[index]),
            ),
          ),
        ),
        const SizedBox(height: 12),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: List.generate(
            stats.length,
            (index) => _buildStatDot(index),
          ),
        ),
      ],
    );
  }

  Widget _buildStatDot(int index) {
    bool isActive = _currentStatPage == index;
    return AnimatedContainer(
      duration: const Duration(milliseconds: 300),
      margin: const EdgeInsets.symmetric(horizontal: 4),
      height: 6,
      width: isActive ? 24 : 6,
      decoration: BoxDecoration(
        color: isActive
            ? AppTheme.primary
            : AppTheme.textPrimary.withValues(alpha: 0.2),
        borderRadius: BorderRadius.circular(3),
      ),
    );
  }

  Widget _buildWelcomeBanner(UserProvider user) {
    int count = 1 + _banners.length; // +1 for Employee Pass

    return Column(
      children: [
        SizedBox(
          height: 195, // Slightly increased height for zoom scale overhead
          child: PageView.builder(
            controller: _bannerController,
            onPageChanged: (idx) =>
                _safeSetState(() => _currentBannerPage = idx),
            itemCount: count,
            physics: const BouncingScrollPhysics(),
            itemBuilder: (context, index) {
              final String heroTag = 'banner_hero_$index';
              final Widget card = index == 0
                  ? _buildEmployeePassCard(user)
                  : _buildEventPassCard(_banners[index - 1]);

              return Hero(
                tag: heroTag,
                child: GestureDetector(
                  onLongPress: () {
                    Navigator.push(
                      context,
                      PageRouteBuilder(
                        opaque: false,
                        barrierDismissible: true,
                        pageBuilder: (context, _, _) =>
                            BannerDetailView(heroTag: heroTag, child: card),
                      ),
                    );
                  },
                  child: AnimatedBuilder(
                    animation: _bannerController,
                    builder: (context, child) {
                      double value = 1.0;
                      if (_bannerController.position.haveDimensions) {
                        value = _bannerController.page! - index;
                        value = (1 - (value.abs() * 0.12)).clamp(0.88, 1.0);
                      } else {
                        value = (index == _currentBannerPage) ? 1.0 : 0.88;
                      }

                      return Transform.scale(
                        scale: value,
                        child: AnimatedOpacity(
                          duration: const Duration(milliseconds: 200),
                          opacity: value.clamp(0.7, 1.0),
                          child: child,
                        ),
                      );
                    },
                    child: card,
                  ),
                ),
              );
            },
          ),
        ),
        if (count > 1) ...[
          const SizedBox(height: 10),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: List.generate(count, (index) => _buildBannerDot(index)),
          ),
        ],
      ],
    );
  }

  Widget _buildBannerDot(int index) {
    bool isActive = _currentBannerPage == index;
    return AnimatedContainer(
      duration: const Duration(milliseconds: 300),
      margin: const EdgeInsets.symmetric(horizontal: 3),
      height: 4,
      width: isActive ? 16 : 4,
      decoration: BoxDecoration(
        color: isActive
            ? AppTheme.primary
            : AppTheme.textPrimary.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(2),
      ),
    );
  }

  Widget _buildEmployeePassCard(UserProvider user) {
    return FadeIn(
      child: AppShimmer(
        enabled: _isLoadingStats,
        child: Container(
          width: double.infinity,
          margin: const EdgeInsets.symmetric(horizontal: 0),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(20)),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(20),
            child: Stack(
              children: [
                // Solid background
                Container(decoration: BoxDecoration(color: AppTheme.primary)),
                // Decorative Circle
                Positioned(
                  top: -40,
                  right: -40,
                  child: Container(
                    width: 150,
                    height: 150,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: Colors.white.withValues(alpha: 0.05),
                    ),
                  ),
                ),
                // Content
                Padding(
                  padding: const EdgeInsets.all(22),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Icon(
                            Icons.nfc_rounded,
                            color: Colors.white.withValues(alpha: 0.8),
                            size: 28,
                          ),
                          _buildRoleBadge(user.systemRoleStr),
                        ],
                      ),
                      const Spacer(),
                      Text(
                        "${user.getConfig('app_display_name', defaultValue: 'VVC')} EMPLOYEE PASS",
                        style: GoogleFonts.inter(
                          color: Colors.white.withValues(alpha: 0.7),
                          fontSize: 11,
                          fontWeight: FontWeight.w900,
                          letterSpacing: 1.5,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        user.name ?? 'បុគ្គលិក',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 22,
                          fontWeight: FontWeight.bold,
                          height: 1.1,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            "ID: ${user.employeeId ?? '---'}",
                            style: GoogleFonts.inter(
                              color: Colors.white.withValues(alpha: 0.8),
                              fontSize: 13,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                          _buildDateBadge(),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildEventPassCard(dynamic banner) {
    bool hasImage =
        banner['image_url'] != null &&
        banner['image_url'].toString().isNotEmpty;

    return FadeIn(
      child: Container(
        width: double.infinity,
        decoration: BoxDecoration(borderRadius: BorderRadius.circular(20)),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(20),
          child: Stack(
            children: [
              // Background (image or solid fallback)
              if (hasImage)
                Image.network(
                  ApiService.getFullImageUrl(banner['image_url']),
                  width: double.infinity,
                  height: double.infinity,
                  fit: BoxFit.cover,
                  errorBuilder: (context, error, stackTrace) => Container(
                    color: AppTheme.danger,
                    child: Center(
                      child: Icon(
                        Icons.broken_image_rounded,
                        color: Colors.white,
                        size: 40,
                      ),
                    ),
                  ),
                )
              else
                Container(color: AppTheme.danger),
              // Overlay for readability if image exists
              if (hasImage)
                Container(color: Colors.black.withValues(alpha: 0.38)),
              // Decorative Badge
              Positioned(
                top: 15,
                right: 15,
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 10,
                    vertical: 4,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.2),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                      color: Colors.white.withValues(alpha: 0.2),
                    ),
                  ),
                  child: Text(
                    "EVENT",
                    style: GoogleFonts.inter(
                      color: Colors.white,
                      fontSize: 10,
                      fontWeight: FontWeight.w900,
                    ),
                  ),
                ),
              ),
              // Content
              Padding(
                padding: const EdgeInsets.all(22),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    Text(
                      banner['title'] ?? 'NEWS',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontSize: 20,
                        fontWeight: FontWeight.bold,
                        height: 1.2,
                      ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 6),
                    Text(
                      banner['text'] ?? '',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white.withValues(alpha: 0.8),
                        fontSize: 12,
                        height: 1.3,
                      ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildRoleBadge(String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Text(
        label.toUpperCase(),
        style: GoogleFonts.inter(
          color: Colors.white,
          fontSize: 10,
          fontWeight: FontWeight.bold,
          letterSpacing: 1,
        ),
      ),
    );
  }

  Widget _buildDateBadge() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.calendar_today_rounded,
            color: Colors.white.withValues(alpha: 0.7),
            size: 12,
          ),
          const SizedBox(width: 6),
          Text(
            _todayDate,
            style: GoogleFonts.inter(
              color: Colors.white.withValues(alpha: 0.7),
              fontSize: 11,
            ),
          ),
        ],
      ),
    );
  }

  // ---- ROLE-BASED QUICK ACTIONS ----
  Widget _buildRoleBasedActions(UserProvider user) {
    final role = user.systemRole;
    switch (role) {
      case SystemRole.admin:
        return _buildAdminActions(user);
      case SystemRole.hrm:
        return _buildHrmActions(user);
      case SystemRole.accounting:
        return _buildAccountingActions(user);
      case SystemRole.it:
        return _buildItActions(user);
      case SystemRole.skills:
        return _buildSkillsActions(user);
      case SystemRole.worker:
        return _buildWorkerActions(user);
      default:
        final suffix = user.roleVisibilitySuffix;
        return suffix == '__skill'
            ? _buildEmployeeActions(user)
            : _buildDynamicActions(user, suffix);
    }
  }

  // ===== EMPLOYEE (Default) =====
  Widget _buildEmployeeActions(UserProvider user) {
    return _buildDynamicActions(user, '__skill');
  }

  // ===== WORKER =====
  Widget _buildWorkerActions(UserProvider user) {
    return _buildDynamicActions(user, '__worker');
  }

  // ===== SKILLS =====
  Widget _buildSkillsActions(UserProvider user) {
    return _buildDynamicActions(user, '__skill');
  }

  // ===== IT =====
  Widget _buildItActions(UserProvider user) {
    return _buildDynamicActions(user, '__skill');
  }

  // ===== ACCOUNTING =====
  Widget _buildAccountingActions(UserProvider user) {
    return _buildDynamicActions(user, '__skill');
  }

  // ===== DYNAMIC ROLE-BASED ACTIONS =====

  Widget _buildDynamicActions(UserProvider user, String suffix) {
    final layoutType = user.getConfig(
      'home_layout_type$suffix',
      defaultValue: 'grid',
    );
    final orderStr = user.getConfig(
      'home_card_order$suffix',
      defaultValue:
          'stats_slider,attendance,outside_attendance,training_quiz,announcements,meetings,checklist,daily_report,mission,trip,user_management,request_form,reports,material_request,notification,payroll',
    );

    final keys = orderStr
        .split(',')
        .map((e) => e.trim())
        .where((e) => e.isNotEmpty)
        .toList();

    // Mapping of available actions
    final Map<String, Widget Function(bool isList)> actionBuilders = {
      'attendance': (isList) =>
          _canShowRoleAction(user, 'show_attendance_card$suffix', suffix)
          ? Padding(
              padding: EdgeInsets.only(bottom: isList ? 10 : 0),
              child: AttendanceScanCard(
                nextAction: _nextAction,
                isLoading: _isLoadingNextAction,
                checkInTime: _checkInTime,
                liveWorkDuration: _liveWorkDuration,
                onCheckIn: () => _goScan('Check-In'),
                onCheckOut: () => _goScan('Check-Out'),
                onHistoryTap: () => Navigator.push(
                  context,
                  _slideRoute(const ScanHistoryScreen()),
                ),
                onTap: () => _goScan(_nextAction),
              ),
            )
          : const SizedBox.shrink(),

      'outside_attendance': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_outside_attendance_card$suffix',
        user: user,
        label: "Check-In ខាងក្រៅ",
        subtitle: "Check-in ទីតាំងអតិថិជន",
        icon: Icons.location_on_rounded,
        color: Colors.redAccent,
        onTap: () {
          _hapticLight();
          if (user.isHRM || user.isAdmin) {
            Navigator.push(context, _slideRoute(const OutsideReportScreen()));
          } else {
            Navigator.push(
              context,
              _slideRoute(const OutsideAttendanceScreen()),
            );
          }
        },
      ),

      'training_quiz': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_training_quiz_card$suffix',
        user: user,
        label: "វគ្គបណ្ដុះបណ្ដាល",
        subtitle: "ឆ្លើយសំណួរដើម្បីទទួលបានមេដាយ",
        icon: Icons.psychology_rounded,
        color: Colors.orangeAccent,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const TrainingQuizScreen()),
        ),
      ),

      'announcements': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_announcements_card$suffix',
        user: user,
        label: "ការជូនដំណឹង",
        subtitle: "គ្រប់គ្រង និងប្រកាសព័ត៌មានទូទៅ",
        icon: Icons.campaign_rounded,
        color: Colors.deepPurpleAccent,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const AnnouncementsScreen()),
        ),
      ),

      'meetings': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_meetings_card$suffix',
        user: user,
        label: "កិច្ចប្រជុំ",
        subtitle: "រៀបចំ និងកំណត់កាលវិភាគប្រជុំ",
        icon: Icons.groups_rounded,
        color: Colors.indigoAccent,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const MeetingsScreen()),
        ),
      ),

      'checklist': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_checklist_card$suffix',
        user: user,
        label: "បញ្ជីការងារ",
        subtitle: "តាមដានកិច្ចការងារប្រចាំថ្ងៃ",
        icon: Icons.checklist_rounded,
        color: Colors.tealAccent,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const ChecklistScreen()),
        ),
      ),

      'daily_report': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_daily_report_card$suffix',
        user: user,
        label: "របាយការណ៍ប្រចាំថ្ងៃ",
        subtitle: "បញ្ជូនរបាយការណ៍ការងារប្រចាំថ្ងៃ",
        icon: Icons.summarize_rounded,
        color: Colors.lightGreenAccent,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const DailyReportScreen()),
        ),
      ),

      'mission': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_mission_card$suffix',
        user: user,
        label: "លិខិតបេសកកម្ម",
        subtitle: "ស្នើសុំចេញបេសកកម្មខាងក្រៅ",
        icon: Icons.map_rounded,
        color: Colors.blueAccent,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const MissionScreen()),
        ),
      ),

      'user_management': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_user_management_card$suffix',
        user: user,
        label: "គ្រប់គ្រងបុគ្គលិក",
        subtitle: "បន្ថែម កែប្រែ និងពិនិត្យទិន្នន័យបុគ្គលិក",
        icon: Icons.people_alt_rounded,
        color: const Color(0xFF8B5CF6),
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const UserManagementScreen()),
        ),
      ),

      'request_form': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_request_form_card$suffix',
        user: user,
        label: "បញ្ជីសំណើ",
        subtitle: "គ្រប់គ្រងសំណើច្បាប់ឈប់សម្រាក",
        icon: Icons.list_alt_rounded,
        color: const Color(0xFFF59E0B),
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(
            builder: (_) => (user.isHRM || user.isAdmin)
                ? const RequestListScreen()
                : const RequestsScreen(),
          ),
        ),
      ),

      'reports': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_reports_card$suffix',
        user: user,
        label: "របាយការណ៍វត្តមាន",
        subtitle: "ពិនិត្យរបាយការណ៍វត្តមាន និងអវត្តមាន",
        icon: Icons.insert_chart_rounded,
        color: const Color(0xFF10B981),
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const AttendanceReportScreen()),
        ),
      ),

      'material_request': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_material_request_card$suffix',
        user: user,
        label: "ស្នើសុំសម្ភារៈ",
        subtitle: "ស្នើសុំសម្ភារៈប្រើប្រាស់ក្នុងស្តុក",
        icon: Icons.inventory_2_rounded,
        color: Colors.cyanAccent,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const MaterialRequestScreen()),
        ),
      ),

      'notification': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_notification_card$suffix',
        user: user,
        label: "ផ្ញើការជូនដំណឹង",
        subtitle: "Push notification ទៅបុគ្គលិក",
        icon: Icons.send_rounded,
        color: Colors.orangeAccent,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const SendNotificationScreen()),
        ),
      ),

      'notification_history': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_notification_history_card$suffix',
        user: user,
        label: "ប្រវត្តិជូនដំណឹង",
        subtitle: "ពិនិត្យប្រវត្តិទទួលបានដំណឹង",
        icon: Icons.notifications_rounded,
        color: Colors.orangeAccent,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const NotificationScreen()),
        ),
      ),

      'employee_report': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_employee_report_card$suffix',
        user: user,
        label: "របាយការណ៍វត្តមាន",
        subtitle: "ពិនិត្យរបាយការណ៍វត្តមានប្រចាំសាខា",
        icon: Icons.recent_actors_rounded,
        color: Colors.pinkAccent,
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const EmployeeReportScreen()),
        ),
      ),

      'trip': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_trip_card$suffix',
        user: user,
        label: "ការធ្វើដំណើរ",
        subtitle: "តាមដាន និងកត់ត្រាការចុះជួបអតិថិជន",
        icon: Icons.directions_car_rounded,
        color: const Color(0xFF10B981),
        onTap: () {
          if (user.isHRM || user.isAdmin) {
            Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const TripReportScreen()),
            );
          } else {
            Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const TripScreen()),
            );
          }
        },
      ),

      'payroll': (isList) => _buildActionItem(
        isList: isList,
        key: 'show_payroll_card$suffix',
        user: user,
        label: "ប្រាក់បៀវត្ស",
        subtitle: "ពិនិត្យមើលប្រវត្តិបើកប្រាក់ខែ",
        icon: Icons.payments_rounded,
        color: Colors.greenAccent.shade700,
        onTap: () {
          _hapticLight();
          if (user.isHRM || user.isAdmin || user.isAccounting) {
            Navigator.push(context, _slideRoute(const PayrollAdminScreen()));
          } else {
            Navigator.push(context, _slideRoute(const PayrollScreen()));
          }
        },
      ),

      'stats_slider': (isList) =>
          _canShowRoleAction(user, 'show_stats_slider$suffix', suffix)
          ? Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: _buildStatsSlider(user),
            )
          : const SizedBox.shrink(),
    };

    final isListLayout = layoutType == 'list';
    List<Widget> gridBatch = [];
    List<Widget> finalWidgets = [];

    for (var key in keys) {
      if (actionBuilders.containsKey(key)) {
        final widget = actionBuilders[key]!(isListLayout);
        if (widget is SizedBox && widget.width == 0) continue;

        if (isListLayout) {
          finalWidgets.add(widget);
        } else {
          if (key == 'attendance' || key == 'stats_slider') {
            if (gridBatch.isNotEmpty) {
              finalWidgets.add(_buildGridWrapper(gridBatch));
              gridBatch = [];
            }
            finalWidgets.add(widget);
            finalWidgets.add(const SizedBox(height: 18));
          } else {
            gridBatch.add(widget);
            if (gridBatch.length == 3) {
              finalWidgets.add(_buildGridWrapper(gridBatch));
              gridBatch = [];
            }
          }
        }
      }
    }

    if (gridBatch.isNotEmpty) finalWidgets.add(_buildGridWrapper(gridBatch));

    if (finalWidgets.isEmpty) {
      return _buildEmptyActionsState();
    }

    return Column(children: finalWidgets);
  }

  bool _canShowRoleAction(UserProvider user, String configKey, String suffix) {
    return user.canShow(
      configKey,
      defaultValue: _defaultRoleActionVisibility(configKey, suffix),
    );
  }

  bool _defaultRoleActionVisibility(String configKey, String suffix) {
    if (suffix == '__worker') {
      return configKey == 'show_attendance_card__worker';
    }
    return true;
  }

  Widget _buildActionItem({
    required bool isList,
    required String key,
    required UserProvider user,
    required String label,
    required String subtitle,
    required IconData icon,
    required Color color,
    required VoidCallback onTap,
  }) {
    if (!_canShowRoleAction(user, key, _suffixFromConfigKey(key))) {
      return const SizedBox.shrink();
    }
    // Wrap onTap with haptic
    void wrappedTap() {
      _hapticLight();
      onTap();
    }

    if (isList) {
      return Padding(
        padding: const EdgeInsets.only(bottom: 10),
        child: AppActionButton(
          title: label,
          subtitle: subtitle,
          icon: icon,
          iconColor: color,
          onTap: wrappedTap,
        ),
      );
    } else {
      return AppGridAction(
        label: label.replaceAll(' ', '\n'),
        icon: icon,
        color: color,
        onTap: wrappedTap,
      );
    }
  }

  String _suffixFromConfigKey(String key) {
    final suffixIndex = key.lastIndexOf('__');
    if (suffixIndex >= 0) return key.substring(suffixIndex);
    return '';
  }

  Widget _buildGridWrapper(List<Widget> items) {
    return Column(
      children: [
        GridView.count(
          crossAxisCount: 3,
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          padding: const EdgeInsets.symmetric(horizontal: 2),
          crossAxisSpacing: 14,
          mainAxisSpacing: 14,
          childAspectRatio: 0.98,
          children: items,
        ),
        const SizedBox(height: 12),
      ],
    );
  }

  Widget _buildEmptyActionsState() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 22),
      decoration: AppTheme.cardDecoration(
        radius: AppTheme.radiusLg,
        borderColor: AppTheme.primary.withValues(alpha: 0.18),
      ),
      child: Column(
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: AppTheme.primary.withValues(alpha: 0.12),
              shape: BoxShape.circle,
              border: Border.all(
                color: AppTheme.primary.withValues(alpha: 0.2),
              ),
            ),
            child: Icon(
              Icons.visibility_off_rounded,
              color: AppTheme.primaryLight,
              size: 24,
            ),
          ),
          const SizedBox(height: 12),
          Text(
            "មិនមានមុខងារបង្ហាញ",
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary,
              fontWeight: FontWeight.bold,
              fontSize: 15,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            "សូមពិនិត្យការកំណត់បង្ហាញតាម Role នៅផ្នែក Admin",
            textAlign: TextAlign.center,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.helperTextColor,
              fontSize: 12,
            ),
          ),
        ],
      ),
    );
  }

  // ===== HRM =====
  Widget _buildHrmActions(UserProvider user) {
    return FadeInUp(
      duration: const Duration(milliseconds: 450),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeader(title: "👥 HRM — ការគ្រប់គ្រងធនធានមនុស្ស"),
          const SizedBox(height: 14),
          _buildDynamicActions(user, '__hrm'),
          _buildInfoBox(
            icon: Icons.security_rounded,
            color: const Color(0xFF6366F1),
            message:
                "អ្នកមានសិទ្ធិគ្រប់គ្រងបុគ្គលិក និងពិនិត្យសំណើទាំងអស់ក្នុងប្រព័ន្ធ។",
          ),
        ],
      ),
    );
  }

  // ===== ADMIN =====
  Widget _buildAdminActions(UserProvider user) {
    return FadeInUp(
      duration: const Duration(milliseconds: 500),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeader(title: "🔴 Admin — ការគ្រប់គ្រងទូទៅ"),
          const SizedBox(height: 14),
          _buildDynamicActions(user, '__admin'),
          _buildInfoBox(
            icon: Icons.admin_panel_settings_rounded,
            color: const Color(0xFFEF4444),
            message:
                "Admin Panel ពេញ: សូម login លើ Web Browser ដើម្បីប្រើមុខងារគ្រប់គ្រង",
          ),
        ],
      ),
    );
  }

  // ---- INFO BOX ----
  Widget _buildInfoBox({
    required IconData icon,
    required Color color,
    required String message,
  }) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Row(
        children: [
          Icon(icon, color: color, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              message,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.70),
                fontSize: 12,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// Full-screen Preview View
class BannerDetailView extends StatelessWidget {
  final Widget child;
  final String heroTag;

  const BannerDetailView({
    super.key,
    required this.child,
    required this.heroTag,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () => Navigator.pop(context),
      child: Scaffold(
        backgroundColor: Colors.black.withValues(alpha: 0.9),
        body: Center(
          child: Hero(
            tag: heroTag,
            child: InteractiveViewer(
              panEnabled: true,
              boundaryMargin: const EdgeInsets.all(20),
              minScale: 0.5,
              maxScale: 4,
              child: child,
            ),
          ),
        ),
      ),
    );
  }
}
