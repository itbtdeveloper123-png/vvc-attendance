import 'dart:async';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/cupertino.dart' show CupertinoIcons;
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:animate_do/animate_do.dart';
import 'package:intl/intl.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../providers/user_provider.dart';
import '../services/background_location_service.dart';
import '../core/theme/theme_provider.dart';
import '../utils/app_theme.dart';
import '../utils/company_theme.dart';
import '../widgets/app_widgets.dart';
import '../widgets/app_update_dialog.dart';
import '../services/api_service.dart';
import '../services/notification_service.dart';
import 'login_screen.dart';
import 'attendance_screen.dart';
import 'scan_history_screen.dart';
import 'outside_attendance_screen.dart';
import 'requests_screen.dart';
import 'leave_request_screen.dart';
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
import 'product_analyzer_screen.dart';
import 'poll_voting_screen.dart';
import 'hrm_poll_management_screen.dart';
import 'document_scanner_screen.dart';
import 'app_settings_screen.dart';
import 'kpi_performance_screen.dart';
import 'certificate_editor_screen.dart';
import '../widgets/responsive_layout.dart';
import '../widgets/desktop_navigation_shell.dart';
import '../widgets/desktop_dashboard_view.dart';

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

    final version =
        '${pushData['latest_version'] ?? pushData['version'] ?? ''}'.trim();
    final build =
        int.tryParse(
          '${pushData['latest_build'] ?? pushData['build_number'] ?? '0'}',
        ) ??
        0;
    final apkUrl = '${pushData['apk_url'] ?? ''}'.trim();
    final message =
        '${pushData['message'] ?? pushData['update_message'] ?? ''}'.trim();
    final forceRaw = '${pushData['force_update'] ?? '0'}'.trim();
    final forceUpdate = forceRaw == '1' || forceRaw.toLowerCase() == 'true';

    if (version.isEmpty || apkUrl.isEmpty) {
      return null;
    }

    return _PushUpdatePayload(
      version: version,
      build: build,
      apkUrl: apkUrl,
      message:
          message.isNotEmpty
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
    final maxLength =
        aParts.length > bParts.length ? aParts.length : bParts.length;

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

    if (Responsive.isDesktop(context) || Responsive.isTablet(context)) {
      return DesktopNavigationShell(
        items: [
          const DesktopNavigationItem(
            title: 'ផ្ទាំងគ្រប់គ្រងទូទៅ (Dashboard)',
            icon: Icons.dashboard_outlined,
            selectedIcon: Icons.dashboard_rounded,
            screen: DesktopDashboardView(),
          ),
          const DesktopNavigationItem(
            title: 'ស្ទូឌីយោលិខិតសរសើរ A4',
            icon: Icons.workspace_premium_outlined,
            selectedIcon: Icons.workspace_premium_rounded,
            screen: CertificateEditorScreen(),
            badge: 'Pro Studio',
          ),
          const DesktopNavigationItem(
            title: 'បោះឆ្នោតបុគ្គលិកឆ្នើម',
            icon: Icons.how_to_vote_outlined,
            selectedIcon: Icons.how_to_vote_rounded,
            screen: PollVotingScreen(),
          ),
          DesktopNavigationItem(
            title: userProvider.isHRM ? 'សំណើសុំច្បាប់ & អនុម័ត' : 'ស្នើសុំច្បាប់ (Requests)',
            icon: Icons.assignment_outlined,
            selectedIcon: Icons.assignment_rounded,
            screen: userProvider.isHRM ? const RequestListScreen() : const RequestsScreen(),
          ),
          const DesktopNavigationItem(
            title: 'របាយការណ៍វត្តមាន & ស្ថិតិ',
            icon: Icons.assessment_outlined,
            selectedIcon: Icons.assessment_rounded,
            screen: AttendanceReportScreen(),
          ),
          const DesktopNavigationItem(
            title: 'ជំនួយការ AI Chat HR',
            icon: Icons.smart_toy_outlined,
            selectedIcon: Icons.smart_toy_rounded,
            screen: AiChatScreen(),
            badge: 'AI Gen',
          ),
          const DesktopNavigationItem(
            title: 'ស្កេនឯកសារ & Passport',
            icon: Icons.document_scanner_outlined,
            selectedIcon: Icons.document_scanner_rounded,
            screen: DocumentScannerScreen(),
          ),
          const DesktopNavigationItem(
            title: 'កត់ត្រាកិច្ចប្រជុំ & សំឡេង',
            icon: Icons.mic_none_outlined,
            selectedIcon: Icons.mic_rounded,
            screen: MeetingsScreen(),
          ),
          if (userProvider.isHRM) ...[
            const DesktopNavigationItem(
              title: 'គ្រប់គ្រងបុគ្គលិក (HRM)',
              icon: Icons.people_alt_outlined,
              selectedIcon: Icons.people_alt_rounded,
              screen: UserManagementScreen(),
            ),
            const DesktopNavigationItem(
              title: 'បើកប្រាក់បៀវត្ស (Payroll)',
              icon: Icons.payments_outlined,
              selectedIcon: Icons.payments_rounded,
              screen: PayrollAdminScreen(),
            ),
          ],
          const DesktopNavigationItem(
            title: 'គណនីរបស់ខ្ញុំ (My Profile)',
            icon: Icons.person_outline_rounded,
            selectedIcon: Icons.person_rounded,
            screen: ProfileScreen(),
          ),
        ],
      );
    }

    final screens = _getScreens(userProvider);
    final theme = userProvider.companyTheme;
    final isDark = theme.isDarkTheme;
    final bottomInset = MediaQuery.paddingOf(context).bottom;

    final scrollAwareNavBar = VvcLiquidGlassBottomBar(
      currentIndex: _currentIndex,
      onTap: (index) => setState(() => _currentIndex = index),
      bottomInset: bottomInset,
      backgroundColor: isDark ? const Color(0xFF181A20) : const Color(0xFFE2E8F0),
      accentColor: const Color(0xFFF3D010),
      items: [
        // 1. Home / Dashboard (Left)
        const LiquidGlassItem(
          icon: CupertinoIcons.square_grid_2x2_fill,
          label: 'ទំព័រដើម',
        ),
        // 2. សំណើ / Requests (Center Item - Elevated Liquid Droplet)
        LiquidGlassItem(
          icon: userProvider.isHRM
              ? CupertinoIcons.doc_text_fill
              : CupertinoIcons.layers_alt_fill,
          label: 'សំណើ',
          isCenter: true,
        ),
        // 3. Profile / គណនី (Right)
        const LiquidGlassItem(
          icon: CupertinoIcons.person_fill,
          label: 'គណនី',
        ),
      ],
    );

    return AnnotatedRegion<SystemUiOverlayStyle>(
      value: SystemUiOverlayStyle(
        statusBarColor: Colors.transparent,
        statusBarIconBrightness: isDark ? Brightness.light : Brightness.dark,
        statusBarBrightness: isDark ? Brightness.dark : Brightness.light,
        systemNavigationBarColor: isDark ? const Color(0xFF0F1115) : Colors.white,
        systemNavigationBarIconBrightness: isDark ? Brightness.light : Brightness.dark,
      ),
      child: Scaffold(
        extendBody: true,
        backgroundColor: theme.backgroundColor,
        body: Stack(
          children: [
            // 1. Content Screens
            IndexedStack(index: _currentIndex, children: screens),

            // 2. Scroll-Aware Localized Fade & Blur Transition Zone (Requirements 3-7)
            scrollAwareNavBar.buildTransitionZone(
              context: context,
              maskColor: theme.backgroundColor,
            ),

            // 3. Floating Quick Action Bubbles (AI Assistant & Chat)
            _buildFloatingActionBubbles(bottomInset),
          ],
        ),
        bottomNavigationBar: scrollAwareNavBar.buildFloatingDock(context: context),
      ),
    );
  }

  /// Floating Quick Action Bubbles (AI Assistant & Chat) at bottom-right above the Dock
  Widget _buildFloatingActionBubbles(double bottomInset) {
    final double bottomMargin =
        (bottomInset > 0 ? bottomInset + 4.0 : 14.0) + 64.0 + 12.0;

    return Positioned(
      right: 18,
      bottom: bottomMargin,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          // 1. AI Assistant Floating Bubble
          GestureDetector(
            onTap: () {
              _hapticLight();
              Navigator.push(
                context,
                _slideRoute(const AiChatScreen()),
              );
            },
            behavior: HitTestBehavior.opaque,
            child: Stack(
              clipBehavior: Clip.none,
              children: [
                Container(
                  width: 46,
                  height: 46,
                  decoration: BoxDecoration(
                    color: const Color(0xFFF3D010),
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFFF3D010).withValues(alpha: 0.45),
                        blurRadius: 10,
                        spreadRadius: 1,
                        offset: const Offset(0, 3),
                      ),
                      BoxShadow(
                        color: Colors.black.withValues(alpha: 0.14),
                        blurRadius: 8,
                        offset: const Offset(0, 2),
                      ),
                    ],
                  ),
                  child: const Center(
                    child: Icon(
                      Icons.smart_toy_rounded,
                      color: Colors.white,
                      size: 23,
                    ),
                  ),
                ),
                Positioned(
                  top: -4,
                  right: -4,
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                    decoration: BoxDecoration(
                      color: const Color(0xFFEF4444),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: Colors.white, width: 1.5),
                      boxShadow: [
                        BoxShadow(
                          color: const Color(0xFFEF4444).withValues(alpha: 0.4),
                          blurRadius: 4,
                          offset: const Offset(0, 1),
                        ),
                      ],
                    ),
                    child: Text(
                      'AI',
                      style: GoogleFonts.inter(
                        color: Colors.white,
                        fontSize: 9,
                        fontWeight: FontWeight.w900,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          // 2. Chat Floating Bubble (with 3.9K Badge)
          GestureDetector(
            onTap: () {
              _hapticLight();
              Navigator.push(
                context,
                _slideRoute(const ChatListScreen()),
              );
            },
            behavior: HitTestBehavior.opaque,
            child: Stack(
              clipBehavior: Clip.none,
              children: [
                Container(
                  width: 46,
                  height: 46,
                  decoration: BoxDecoration(
                    color: const Color(0xFFF3D010),
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFFF3D010).withValues(alpha: 0.45),
                        blurRadius: 10,
                        spreadRadius: 1,
                        offset: const Offset(0, 3),
                      ),
                      BoxShadow(
                        color: Colors.black.withValues(alpha: 0.14),
                        blurRadius: 8,
                        offset: const Offset(0, 2),
                      ),
                    ],
                  ),
                  child: const Center(
                    child: Icon(
                      Icons.chat_bubble_rounded,
                      color: Colors.white,
                      size: 22,
                    ),
                  ),
                ),
                Positioned(
                  top: -4,
                  right: -6,
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                    decoration: BoxDecoration(
                      color: const Color(0xFFEF4444),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: Colors.white, width: 1.5),
                      boxShadow: [
                        BoxShadow(
                          color: const Color(0xFFEF4444).withValues(alpha: 0.4),
                          blurRadius: 4,
                          offset: const Offset(0, 1),
                        ),
                      ],
                    ),
                    child: Text(
                      '3.9K',
                      style: GoogleFonts.inter(
                        color: Colors.white,
                        fontSize: 8.5,
                        fontWeight: FontWeight.w900,
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

  // ===== Apple iOS Scroll Frosted Glass Header Tracking =====
  late final ScrollController _homeScrollController;
  bool _isHeaderScrolled = false;

  // ===== Feature #1: Live Work Timer =====
  DateTime? _checkInTime;
  Timer? _liveTimerTick;
  String _liveWorkDuration = '';

  // ===== Feature #5: Attendance Streak =====
  int _attendanceStreak = 0;

  // ===== Feature #8: Weather =====
  String _weatherText = '';
  String _weatherIcon = '☀️';

  // ===== Category Filter Tabs =====
  String _selectedCategory = 'All';
  final List<String> _categories = [
    'All',
    'ការងារ',
    'វត្តមាន',
    'របាយការណ៍',
    'សំណើ',
    'សម្ភារៈ',
  ];

  void _safeSetState(VoidCallback fn) {
    if (!mounted) return;
    setState(fn);
  }

  void _onHomeScroll() {
    if (!_homeScrollController.hasClients) return;
    final scrolled = _homeScrollController.offset > 4.0;
    if (scrolled != _isHeaderScrolled) {
      _safeSetState(() {
        _isHeaderScrolled = scrolled;
      });
    }
  }

  @override
  void initState() {
    super.initState();
    _homeScrollController = ScrollController();
    _homeScrollController.addListener(_onHomeScroll);
    _loadStats();
    _loadNextAction();
    _loadStreak();
    _loadCheckInTime();
    _loadWeather();
    _pollingTimer = Timer.periodic(const Duration(seconds: 30), (timer) {
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
        builder:
            (ctx) => Dialog(
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
                      color: AppTheme.primary,
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
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textMuted,
                        ),
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
    _homeScrollController.removeListener(_onHomeScroll);
    _homeScrollController.dispose();
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
        body:
            count == 1
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
    final theme = user.companyTheme;

    return GlassOrbBackground(
      baseColor: theme.backgroundColor,
      primaryOrbColor: theme.orbPrimary,
      secondaryOrbColor: theme.orbSecondary,
      accentOrbColor: theme.orbAccent,
      child: Stack(
        children: [
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
            color: theme.cardPrimary,
            backgroundColor: theme.backgroundColor,
            child: CustomScrollView(
              controller: _homeScrollController,
              physics: const AlwaysScrollableScrollPhysics(
                parent: BouncingScrollPhysics(),
              ),
              slivers: [
                SliverPersistentHeader(
                  pinned: true,
                  delegate: _HomeHeaderDelegate(
                    user: user,
                    theme: theme,
                    greeting: _greeting,
                    unreadNotifications: _unreadNotifications,
                    onProfileTap: widget.onProfileTap,
                    topPadding: MediaQuery.paddingOf(context).top,
                    isScrolled: _isHeaderScrolled,
                  ),
                ),
                SliverToBoxAdapter(
                  child: SafeArea(
                    top: false,
                    bottom: false,
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          _buildWeatherAndQuoteRow(theme),
                          const SizedBox(height: 12),
                          _buildCategoryFilterTabs(theme),
                          const SizedBox(height: 16),
                          if (_selectedCategory == 'All') ...[
                            _buildWelcomeBanner(user),
                            const SizedBox(height: 16),
                            _buildBentoDashboard(user),
                            const SizedBox(height: 20),
                          ] else if (_selectedCategory == 'វត្តមាន') ...[
                            _buildBentoHeroAttendanceCard(user),
                            const SizedBox(height: 20),
                          ],
                          _buildRoleBasedActions(user),
                          SizedBox(
                            height: AppResponsive.bottomPadding(
                              context,
                              hasBottomNav: true,
                              extra: 80,
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

  // ===== Category Filter Tabs =====
  Widget _buildCategoryFilterTabs(CompanyTheme theme) {
    return SizedBox(
      height: 38,
      child: ListView.separated(
        scrollDirection: Axis.horizontal,
        physics: const BouncingScrollPhysics(),
        itemCount: _categories.length,
        separatorBuilder: (_, __) => const SizedBox(width: 8),
        itemBuilder: (context, index) {
          final cat = _categories[index];
          final isSelected = cat == _selectedCategory;
          return GestureDetector(
            onTap: () {
              _hapticLight();
              setState(() {
                _selectedCategory = cat;
              });
            },
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 220),
              curve: Curves.easeOutCubic,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                color: isSelected
                    ? const Color(0xFFF3D010)
                    : (theme.isDarkTheme
                        ? const Color(0xFF191B22)
                        : Colors.white),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: isSelected
                      ? const Color(0xFFF3D010)
                      : (theme.isDarkTheme
                          ? Colors.white.withValues(alpha: 0.10)
                          : const Color(0xFFE2E8F0)),
                  width: 1,
                ),
                boxShadow: isSelected
                    ? [
                        BoxShadow(
                          color: const Color(0xFFF3D010).withValues(alpha: 0.3),
                          blurRadius: 8,
                          offset: const Offset(0, 2),
                        ),
                      ]
                    : [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.03),
                          blurRadius: 4,
                          offset: const Offset(0, 1),
                        ),
                      ],
              ),
              child: Center(
                child: Text(
                  cat,
                  style: GoogleFonts.kantumruyPro(
                    color: isSelected
                        ? Colors.white
                        : (theme.isDarkTheme
                            ? const Color(0xFF94A3B8)
                            : const Color(0xFF64748B)),
                    fontWeight: isSelected ? FontWeight.w800 : FontWeight.w600,
                    fontSize: 12.5,
                  ),
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  bool _matchesCategory(String key, String category) {
    if (category == 'All') return true;
    switch (category) {
      case 'ការងារ':
        return [
          'checklist',
          'meetings',
          'mission',
          'trip',
          'kpi',
          'training_quiz',
          'poll_voting',
          'announcements',
          'product_analyzer',
          'document_scanner',
          'app_settings',
          'user_management',
        ].contains(key);
      case 'វត្តមាន':
        return [
          'attendance',
          'outside_attendance',
          'reports',
          'employee_report',
          'trip',
        ].contains(key);
      case 'របាយការណ៍':
        return [
          'daily_report',
          'reports',
          'employee_report',
          'trip',
          'kpi',
          'payroll',
        ].contains(key);
      case 'សំណើ':
        return [
          'request_form',
          'material_request',
          'mission',
        ].contains(key);
      case 'សម្ភារៈ':
        return [
          'material_request',
          'product_analyzer',
          'document_scanner',
        ].contains(key);
      default:
        return true;
    }
  }

  // ===== Feature #1 + #5 + #8: Weather, Streak & Live Timer Row =====
  Widget _buildWeatherAndQuoteRow(CompanyTheme theme) {
    return FadeInDown(
      delay: const Duration(milliseconds: 100),
      duration: const Duration(milliseconds: 400),
      child: Row(
        children: [
          // Feature #8: Weather pill
          if (_weatherText.isNotEmpty)
            ClipRRect(
              borderRadius: BorderRadius.circular(20),
              child: BackdropFilter(
                filter: ui.ImageFilter.blur(sigmaX: 16, sigmaY: 16),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  decoration: BoxDecoration(
                    color: theme.isDarkTheme
                        ? const Color(0xFF191B22)
                        : Colors.white.withValues(alpha: 0.85),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(
                      color: theme.isDarkTheme
                          ? Colors.white.withValues(alpha: 0.10)
                          : Colors.white.withValues(alpha: 0.95),
                      width: 1.2,
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: theme.isDarkTheme ? 0.2 : 0.035),
                        blurRadius: 8,
                        offset: const Offset(0, 2),
                      ),
                    ],
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(_weatherIcon, style: const TextStyle(fontSize: 14)),
                      const SizedBox(width: 6),
                      Text(
                        'ភ្នំពេញ $_weatherText',
                        style: GoogleFonts.kantumruyPro(
                          color: theme.isDarkTheme ? Colors.white : const Color(0xFF0F172A),
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          if (_weatherText.isNotEmpty) const SizedBox(width: 8),
          // Feature #5: Streak pill
          if (_attendanceStreak > 0)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: Colors.orange.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: Colors.orange.withValues(alpha: 0.35),
                  width: 1,
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text('🔥', style: TextStyle(fontSize: 13)),
                  const SizedBox(width: 5),
                  Text(
                    '$_attendanceStreak ថ្ងៃ',
                    style: GoogleFonts.inter(
                      color: Colors.deepOrange,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          const Spacer(),
        ],
      ),
    );
  }





  // ═════════════════════════════════════════════════════════════════════════════
  // ─── BENTO GRID DASHBOARD (Apple / Linear Style) ────────────────────────────
  // ═════════════════════════════════════════════════════════════════════════════

  Widget _buildBentoDashboard(UserProvider user) {
    return FadeInUp(
      duration: const Duration(milliseconds: 450),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 1. HERO BENTO CARD (Attendance & Live Work Timer)
          _buildBentoHeroAttendanceCard(user),
          const SizedBox(height: 12),

          // 2. DUAL MEDIUM BENTO CARDS (Leave Balance & Daily Report)
          _buildBentoMediumRow(user),
          const SizedBox(height: 12),

          // 3. MINI BENTO TRIO (Checklist, Meetings, Announcements)
          _buildBentoMiniTrio(user),
        ],
      ),
    );
  }

  // ─── 1. HERO BENTO CARD (Full Width) ──────────────────────────────────────
  Widget _buildBentoHeroAttendanceCard(UserProvider user) {
    final theme = user.companyTheme;
    final isDark = theme.isDarkTheme;
    final bool isCheckedIn = _checkInTime != null;
    final bool isNextCheckIn = _nextAction == 'Check-In';

    return ClipRRect(
      borderRadius: BorderRadius.circular(24),
      child: BackdropFilter(
        filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
        child: Container(
          decoration: BoxDecoration(
            gradient: isDark
                ? const LinearGradient(
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                    colors: [
                      Color(0xFF1E222B),
                      Color(0xFF16181F),
                    ],
                  )
                : LinearGradient(
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                    colors: [
                      (theme.brand == CompanyBrand.vvc ? Colors.white : theme.cardBackground).withValues(alpha: 0.94),
                      (theme.brand == CompanyBrand.vvc ? Colors.white : theme.cardBackground).withValues(alpha: 0.85),
                      (theme.brand == CompanyBrand.vvc ? Colors.white : theme.cardBackground).withValues(alpha: 0.90),
                    ],
                    stops: const [0.0, 0.55, 1.0],
                  ),
            borderRadius: BorderRadius.circular(24),
            border: Border.all(
              color: isDark ? Colors.white.withValues(alpha: 0.08) : Colors.white,
              width: 1.5,
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.065),
                blurRadius: 18,
                spreadRadius: 0,
                offset: const Offset(0, 6),
              ),
            ],
          ),
          padding: const EdgeInsets.all(18),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Top Row: Status Chip + Streak Chip + Scan History Icon
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  // Status Badge (Frosted Pill)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: isCheckedIn
                          ? const Color(0xFF10B981).withValues(alpha: 0.15)
                          : (isDark ? const Color(0xFF232733) : Colors.white.withValues(alpha: 0.85)),
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(
                        color: isCheckedIn
                            ? const Color(0xFF10B981).withValues(alpha: 0.35)
                            : (isDark ? Colors.white.withValues(alpha: 0.12) : Colors.white),
                        width: 1.2,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: const Color(0xFF0F172A).withValues(alpha: 0.03),
                          blurRadius: 4,
                          offset: const Offset(0, 1),
                        ),
                      ],
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          width: 8,
                          height: 8,
                          decoration: BoxDecoration(
                            color: isCheckedIn
                                ? const Color(0xFF10B981)
                                : const Color(0xFF64748B),
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 7),
                        Text(
                          isCheckedIn
                              ? 'ចូលធ្វើការ ${DateFormat('hh:mm a').format(_checkInTime!)}'
                              : 'មិនទាន់ Check-In',
                          style: GoogleFonts.kantumruyPro(
                            color: isCheckedIn
                                ? const Color(0xFF10B981)
                                : (isDark ? Colors.white : const Color(0xFF1E293B)),
                            fontSize: 12,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ],
                    ),
                  ),
                  // Right Controls: Streak + History
                  Row(
                    children: [
                      if (_attendanceStreak > 0) ...[
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                          decoration: BoxDecoration(
                            color: Colors.orange.withValues(alpha: 0.12),
                            borderRadius: BorderRadius.circular(16),
                            border: Border.all(
                              color: Colors.orange.withValues(alpha: 0.30),
                            ),
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const Text('🔥', style: TextStyle(fontSize: 12)),
                              const SizedBox(width: 4),
                              Text(
                                '$_attendanceStreak ថ្ងៃ',
                                style: GoogleFonts.inter(
                                  color: Colors.deepOrange,
                                  fontSize: 11.5,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ],
                          ),
                        ),
                        const SizedBox(width: 8),
                      ],
                      GestureDetector(
                        onTap: () {
                          _hapticLight();
                          Navigator.push(
                            context,
                            _slideRoute(const ScanHistoryScreen()),
                          );
                        },
                        child: Container(
                          padding: const EdgeInsets.all(7),
                          decoration: BoxDecoration(
                            color: isDark ? const Color(0xFF232733) : Colors.white.withValues(alpha: 0.85),
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: isDark ? Colors.white.withValues(alpha: 0.12) : Colors.white,
                              width: 1.2,
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: const Color(0xFF0F172A).withValues(alpha: 0.03),
                                blurRadius: 4,
                                offset: const Offset(0, 1),
                              ),
                            ],
                          ),
                          child: Icon(
                            Icons.history_rounded,
                            color: isDark ? Colors.white70 : const Color(0xFF1E293B),
                            size: 18,
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 16),

              // Bottom Action Buttons
              Row(
                children: [
                  // Main Scan Action Button (Core Branding Color Highlight)
                  Expanded(
                    flex: 3,
                    child: GestureDetector(
                      onTap: () {
                        _hapticMedium();
                        _goScan(_nextAction);
                      },
                      child: Container(
                        height: 48,
                        decoration: BoxDecoration(
                          gradient: isNextCheckIn
                              ? const LinearGradient(
                                  colors: [Color(0xFFF3D010), Color(0xFFE5BF00)],
                                )
                              : const LinearGradient(
                                  colors: [Color(0xFFEF4444), Color(0xFFDC2626)],
                                ),
                          borderRadius: BorderRadius.circular(14),
                          boxShadow: [
                            BoxShadow(
                              color: (isNextCheckIn
                                      ? const Color(0xFFF3D010)
                                      : const Color(0xFFEF4444))
                                  .withValues(alpha: 0.35),
                              blurRadius: 10,
                              offset: const Offset(0, 4),
                            ),
                          ],
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              isNextCheckIn
                                  ? Icons.qr_code_scanner_rounded
                                  : Icons.logout_rounded,
                              color: Colors.white,
                              size: 20,
                            ),
                            const SizedBox(width: 8),
                            Text(
                              isNextCheckIn ? 'ស្កេនចូល (Check-In)' : 'ស្កេនចេញ (Check-Out)',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white,
                                fontSize: 13.5,
                                fontWeight: FontWeight.w800,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  // Outside Attendance Shortcut (Frosted Glass Button)
                  Expanded(
                    flex: 2,
                    child: GestureDetector(
                      onTap: () {
                        _hapticLight();
                        if (user.isHRM || user.isAdmin) {
                          Navigator.push(
                            context,
                            _slideRoute(const OutsideReportScreen()),
                          );
                        } else {
                          Navigator.push(
                            context,
                            _slideRoute(const OutsideAttendanceScreen()),
                          );
                        }
                      },
                      child: Container(
                        height: 48,
                        decoration: BoxDecoration(
                          color: isDark ? const Color(0xFF232733) : Colors.white.withValues(alpha: 0.75),
                          borderRadius: BorderRadius.circular(14),
                          border: Border.all(
                            color: isDark ? Colors.white.withValues(alpha: 0.12) : Colors.white.withValues(alpha: 0.95),
                            width: 1.2,
                          ),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.location_on_rounded,
                              color: theme.brand == CompanyBrand.vvc
                                  ? const Color(0xFF0284C7)
                                  : theme.cardPrimary,
                              size: 19,
                            ),
                            const SizedBox(width: 6),
                            Text(
                              'ក្រៅទីតាំង',
                              style: GoogleFonts.kantumruyPro(
                                color: isDark ? Colors.white : const Color(0xFF0F172A),
                                fontSize: 12.5,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  // ─── 2. DUAL MEDIUM BENTO CARDS (50% / 50% Row) ───────────────────────────
  Widget _buildBentoMediumRow(UserProvider user) {
    // Dynamic Annual Leave (AL) Live Balance from database/stats
    final dynamic rawAl = _stats['annual_leave_remaining'] ?? _stats['leave_remaining'] ?? 0;
    final num alNum = (rawAl is num) ? rawAl : (num.tryParse(rawAl.toString()) ?? 0);
    final String leaveBalanceStr = (alNum % 1 == 0) ? alNum.toInt().toString() : alNum.toStringAsFixed(1);
    final theme = user.companyTheme;

    return Row(
      children: [
        // Left: Leave Balance Card (AL Live Balance)
        Expanded(
          child: _buildBentoMediumCard(
            theme: theme,
            icon: Icons.beach_access_rounded,
            iconColor: theme.cardPrimary,
            title: 'AL នៅសល់',
            value: '$leaveBalanceStr ថ្ងៃ',
            subtitle: 'ក្នុងឆ្នាំ (Live Balance)',
            actionText: '+ សុំច្បាប់',
            onTap: () {
              _hapticLight();
              Navigator.push(
                context,
                _slideRoute(const LeaveRequestScreen()),
              );
            },
          ),
        ),
        const SizedBox(width: 12),
        // Right: Daily Report Card (ធ្វើរបាយការណ៍ប្រចាំថ្ងៃ)
        Expanded(
          child: _buildBentoMediumCard(
            theme: theme,
            icon: Icons.assignment_turned_in_rounded,
            iconColor: theme.cardPrimary,
            title: 'ផ្ញើទៅ Telegram',
            value: 'ធ្វើរបាយការណ៍',
            subtitle: 'ប្រចាំថ្ងៃ',
            actionText: '+ បញ្ជូន',
            onTap: () {
              _hapticLight();
              Navigator.push(
                context,
                _slideRoute(const DailyReportScreen()),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildBentoMediumCard({
    required CompanyTheme theme,
    required IconData icon,
    required Color iconColor,
    required String title,
    required String value,
    required String subtitle,
    required String actionText,
    required VoidCallback onTap,
  }) {
    const brandAccent = Color(0xFFD4AF37);
    final isDark = theme.isDarkTheme;

    return GestureDetector(
      onTap: onTap,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(20),
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: 18, sigmaY: 18),
          child: Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              gradient: isDark
                  ? const LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [
                        Color(0xFF1C1E26),
                        Color(0xFF16181F),
                      ],
                    )
                  : LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [
                        (theme.brand == CompanyBrand.vvc ? Colors.white : theme.cardBackground).withValues(alpha: 0.94),
                        (theme.brand == CompanyBrand.vvc ? Colors.white : theme.cardBackground).withValues(alpha: 0.85),
                      ],
                    ),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(
                color: isDark ? Colors.white.withValues(alpha: 0.08) : Colors.white,
                width: 1.2,
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.065),
                  blurRadius: 16,
                  offset: const Offset(0, 5),
                ),
              ],
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Container(
                      width: 38,
                      height: 38,
                      decoration: BoxDecoration(
                        color: isDark ? const Color(0xFF232733) : const Color(0xFFFFFBEB),
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: const Color(0xFFD4AF37),
                          width: 1.2,
                        ),
                      ),
                      child: Icon(icon, color: brandAccent, size: 20),
                    ),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4.5),
                      decoration: BoxDecoration(
                        color: const Color(0xFFF3D010),
                        borderRadius: BorderRadius.circular(12),
                        boxShadow: [
                          BoxShadow(
                            color: const Color(0xFFF3D010).withValues(alpha: 0.35),
                            blurRadius: 6,
                            offset: const Offset(0, 2),
                          ),
                        ],
                      ),
                      child: Text(
                        actionText,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 11,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 14),
                Text(
                  value,
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? Colors.white : const Color(0xFF0F172A),
                    fontSize: 16.5,
                    fontWeight: FontWeight.w800,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 2),
                Text(
                  subtitle,
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF475569),
                    fontSize: 11.5,
                    fontWeight: FontWeight.w600,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 10),
                // Gold underline highlight bar (as seen in screenshot)
                Container(
                  height: 2.5,
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: [
                        const Color(0xFFD4AF37),
                        const Color(0xFFF59E0B).withValues(alpha: 0.1),
                      ],
                    ),
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ─── 3. MINI BENTO TRIO (3-Column Row) ────────────────────────────────────
  Widget _buildBentoMiniTrio(UserProvider user) {
    final announcementsCount = _stats['announcements_count'] ?? 0;
    final theme = user.companyTheme;

    return Row(
      children: [
        // 1. Checklist
        Expanded(
          child: _buildBentoMiniCard(
            theme: theme,
            icon: Icons.checklist_rtl_rounded,
            color: theme.cardPrimary,
            title: 'Checklist',
            subtitle: 'ការងារថ្ងៃនេះ',
            onTap: () {
              _hapticLight();
              Navigator.push(
                context,
                _slideRoute(const ChecklistScreen()),
              );
            },
          ),
        ),
        const SizedBox(width: 10),
        // 2. Meetings
        Expanded(
          child: _buildBentoMiniCard(
            theme: theme,
            icon: Icons.groups_rounded,
            color: theme.cardPrimary,
            title: 'ការប្រជុំ',
            subtitle: 'កំណត់ត្រា AI',
            onTap: () {
              _hapticLight();
              Navigator.push(
                context,
                _slideRoute(const MeetingsScreen()),
              );
            },
          ),
        ),
        const SizedBox(width: 10),
        // 3. Announcements
        Expanded(
          child: _buildBentoMiniCard(
            theme: theme,
            icon: Icons.campaign_rounded,
            color: theme.cardPrimary,
            title: 'ដំណឹងថ្មី',
            subtitle: '$announcementsCount ដំណឹង',
            onTap: () {
              _hapticLight();
              Navigator.push(
                context,
                _slideRoute(const AnnouncementsScreen()),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildBentoMiniCard({
    required CompanyTheme theme,
    required IconData icon,
    required Color color,
    required String title,
    required String subtitle,
    required VoidCallback onTap,
  }) {
    const brandAccent = Color(0xFFD4AF37);
    final isDark = theme.isDarkTheme;

    return GestureDetector(
      onTap: onTap,
      child: ClipRRect(
        borderRadius: BorderRadius.circular(18),
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: 16, sigmaY: 16),
          child: Container(
            padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 8),
            decoration: BoxDecoration(
              gradient: isDark
                  ? const LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [
                        Color(0xFF1C1E26),
                        Color(0xFF16181F),
                      ],
                    )
                  : LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: [
                        (theme.brand == CompanyBrand.vvc ? Colors.white : theme.cardBackground).withValues(alpha: 0.94),
                        (theme.brand == CompanyBrand.vvc ? Colors.white : theme.cardBackground).withValues(alpha: 0.85),
                      ],
                    ),
              borderRadius: BorderRadius.circular(18),
              border: Border.all(
                color: isDark ? Colors.white.withValues(alpha: 0.08) : Colors.white,
                width: 1.2,
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: isDark ? 0.3 : 0.06),
                  blurRadius: 14,
                  offset: const Offset(0, 4),
                ),
              ],
            ),
            child: Column(
              children: [
                Container(
                  width: 38,
                  height: 38,
                  decoration: BoxDecoration(
                    color: isDark ? const Color(0xFF232733) : const Color(0xFFFFFBEB),
                    shape: BoxShape.circle,
                    border: Border.all(
                      color: const Color(0xFFD4AF37),
                      width: 1.4,
                    ),
                  ),
                  child: Icon(icon, color: brandAccent, size: 20),
                ),
                const SizedBox(height: 8),
                Text(
                  title,
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? Colors.white : const Color(0xFF0F172A),
                    fontSize: 12.5,
                    fontWeight: FontWeight.w700,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 2),
                Text(
                  subtitle,
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
                    fontSize: 10.5,
                    fontWeight: FontWeight.w500,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildStatsSlider(UserProvider user) {
    final role = user.systemRole;
    final theme = user.companyTheme;
    final List<Widget> stats = [];

    stats.add(
      AppStatCard(
        label: "កិច្ចការថ្ងៃនេះ",
        value: '${_stats['today_work']}',
        icon: Icons.task_alt_rounded,
        color: AppTheme.primary,
        isLoading: _isLoadingStats,
        cardColor: theme.cardBackground,
        borderColor: theme.cardBorder,
      ),
    );
    stats.add(
      AppStatCard(
        label: "ការជូនដំណឹង",
        value: '${_stats['announcements_count']}',
        icon: Icons.campaign_rounded,
        color: AppTheme.warning,
        isLoading: _isLoadingStats,
        cardColor: theme.cardBackground,
        borderColor: theme.cardBorder,
      ),
    );
    stats.add(
      AppStatCard(
        label: "ច្បាប់នៅសល់",
        value: '${_stats['annual_leave_remaining']}',
        icon: Icons.beach_access_rounded,
        color: AppTheme.success,
        isLoading: _isLoadingStats,
        cardColor: theme.cardBackground,
        borderColor: theme.cardBorder,
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
          cardColor: theme.cardBackground,
          borderColor: theme.cardBorder,
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
            itemBuilder:
                (context, index) => Padding(
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
        color:
            isActive
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
            onPageChanged:
                (idx) => _safeSetState(() => _currentBannerPage = idx),
            itemCount: count,
            physics: const BouncingScrollPhysics(),
            itemBuilder: (context, index) {
              final String heroTag = 'banner_hero_$index';
              final Widget card =
                  index == 0
                      ? _buildEmployeePassCard(user)
                      : _buildEventPassCard(_banners[index - 1]);

              return Hero(
                tag: heroTag,
                child: GestureDetector(
                  behavior: HitTestBehavior.opaque,
                  onTap: () {
                    Navigator.push(
                      context,
                      PageRouteBuilder(
                        opaque: false,
                        barrierDismissible: true,
                        pageBuilder:
                            (context, _, _) =>
                                BannerDetailView(heroTag: heroTag, child: card),
                      ),
                    );
                  },
                  onLongPress: () {
                    Navigator.push(
                      context,
                      PageRouteBuilder(
                        opaque: false,
                        barrierDismissible: true,
                        pageBuilder:
                            (context, _, _) =>
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
            children: List.generate(count, (index) => _buildBannerDot(index, user.companyTheme)),
          ),
        ],
      ],
    );
  }

  Widget _buildBannerDot(int index, CompanyTheme theme) {
    bool isActive = _currentBannerPage == index;
    return AnimatedContainer(
      duration: const Duration(milliseconds: 300),
      margin: const EdgeInsets.symmetric(horizontal: 3),
      height: 4,
      width: isActive ? 16 : 4,
      decoration: BoxDecoration(
        color:
            isActive
                ? theme.cardPrimary
                : theme.textMuted.withValues(alpha: 0.25),
        borderRadius: BorderRadius.circular(2),
      ),
    );
  }

  Widget _buildEmployeePassCard(UserProvider user) {
    final theme = user.companyTheme;
    return FadeIn(
      child: AppShimmer(
        enabled: _isLoadingStats,
        child: Container(
          width: double.infinity,
          margin: const EdgeInsets.symmetric(horizontal: 0),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(20),
            boxShadow: [
              BoxShadow(
                color: theme.cardPrimary.withValues(alpha: 0.35),
                blurRadius: 18,
                offset: const Offset(0, 6),
              ),
            ],
          ),
          child: ClipRRect(
            borderRadius: BorderRadius.circular(20),
            child: Stack(
              children: [
                // Rich Warm Gold or Bronze Card with depth
                Container(
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                      colors: theme.brand == CompanyBrand.vvc
                          ? const [
                              Color(0xFFEAB308), // Rich Warm Gold
                              Color(0xFFD97706), // Deep Amber Gold
                            ]
                          : [
                              theme.cardPrimary,
                              theme.cardSecondary,
                            ],
                    ),
                  ),
                ),
                // Decorative Circle
                Positioned(
                  top: -40,
                  right: -40,
                  child: Container(
                    width: 150,
                    height: 150,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: Colors.white.withValues(alpha: 0.12),
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
                          const Icon(
                            Icons.nfc_rounded,
                            color: Colors.white,
                            size: 28,
                          ),
                          _buildRoleBadge(
                            user.systemRoleStr,
                            textColor: Colors.white,
                            bgColor: Colors.white.withValues(alpha: 0.22),
                          ),
                        ],
                      ),
                      const Spacer(),
                      Text(
                        theme.passTitle,
                        style: GoogleFonts.inter(
                          color: Colors.white.withValues(alpha: 0.90),
                          fontSize: 11,
                          fontWeight: FontWeight.w900,
                          letterSpacing: 1.5,
                          shadows: [
                            Shadow(
                              color: Colors.black.withValues(alpha: 0.18),
                              blurRadius: 3,
                              offset: const Offset(0, 1),
                            ),
                          ],
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
                          shadows: [
                            Shadow(
                              color: Colors.black.withValues(alpha: 0.18),
                              blurRadius: 4,
                              offset: const Offset(0, 1),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 6),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            "ID: ${user.employeeId ?? '---'}",
                            style: GoogleFonts.inter(
                              color: Colors.white.withValues(alpha: 0.95),
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                              shadows: [
                                Shadow(
                                  color: Colors.black.withValues(alpha: 0.15),
                                  blurRadius: 3,
                                  offset: const Offset(0, 1),
                                ),
                              ],
                            ),
                          ),
                          _buildDateBadge(
                            textColor: Colors.white,
                            bgColor: Colors.white.withValues(alpha: 0.22),
                          ),
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
                  errorBuilder:
                      (context, error, stackTrace) => Container(
                        color: AppTheme.danger,
                        child: const Center(
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

  Widget _buildRoleBadge(String label, {Color? textColor, Color? bgColor}) {
    final c = textColor ?? Colors.white;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: bgColor ?? c.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Text(
        label.toUpperCase(),
        style: GoogleFonts.inter(
          color: c,
          fontSize: 10,
          fontWeight: FontWeight.bold,
          letterSpacing: 1,
        ),
      ),
    );
  }

  Widget _buildDateBadge({Color? textColor, Color? bgColor}) {
    final c = textColor ?? Colors.white;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: bgColor ?? c.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.calendar_today_rounded,
            color: c.withValues(alpha: 0.8),
            size: 12,
          ),
          const SizedBox(width: 6),
          Text(
            _todayDate,
            style: GoogleFonts.inter(
              color: c.withValues(alpha: 0.8),
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
    final theme = user.companyTheme;
    final layoutType = user.getConfig(
      'home_layout_type$suffix',
      defaultValue: 'grid',
    );
    final orderStr = user.getConfig(
      'home_card_order$suffix',
      defaultValue:
          'stats_slider,attendance,outside_attendance,kpi,product_analyzer,training_quiz,poll_voting,announcements,meetings,checklist,daily_report,mission,trip,user_management,request_form,reports,material_request,notification,payroll,document_scanner,app_settings',
    );

    final keys =
        orderStr
            .split(',')
            .map((e) => e.trim())
            .where((e) => e.isNotEmpty)
            .toList();

    // Mapping of available actions
    final Map<String, Widget Function(bool isList)> actionBuilders = {
      'attendance':
          (isList) =>
              _canShowRoleAction(user, 'show_attendance_card$suffix', suffix)
                  ? Padding(
                    padding: EdgeInsets.only(bottom: isList ? 10 : 0),
                    child: AttendanceScanCard(
                      nextAction: _nextAction,
                      isLoading: _isLoadingNextAction,
                      checkInTime: _checkInTime,
                      liveWorkDuration: _liveWorkDuration,
                      cardColor: theme.cardBackground,
                      borderColor: theme.cardBorder,
                      onCheckIn: () => _goScan('Check-In'),
                      onCheckOut: () => _goScan('Check-Out'),
                      onHistoryTap:
                          () => Navigator.push(
                            context,
                            _slideRoute(const ScanHistoryScreen()),
                          ),
                      onTap: () => _goScan(_nextAction),
                    ),
                  )
                  : const SizedBox.shrink(),

      'outside_attendance':
          (isList) => _buildActionItem(
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
                Navigator.push(
                  context,
                  _slideRoute(const OutsideReportScreen()),
                );
              } else {
                Navigator.push(
                  context,
                  _slideRoute(const OutsideAttendanceScreen()),
                );
              }
            },
          ),

      'training_quiz':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_training_quiz_card$suffix',
            user: user,
            label: "វគ្គបណ្ដុះបណ្ដាល",
            subtitle: "ឆ្លើយសំណួរដើម្បីទទួលបានមេដាយ",
            icon: Icons.psychology_rounded,
            color: Colors.orangeAccent,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const TrainingQuizScreen()),
                ),
          ),

      'product_analyzer':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_product_analyzer_card$suffix',
            user: user,
            label: "វិភាគផលិតផល",
            subtitle: "ថតរូប ឬ Scan Barcode ដើម្បីឱ្យ AI វិភាគ",
            icon: Icons.document_scanner_rounded,
            color: AppTheme.primary,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const ProductAnalyzerScreen(),
                  ),
                ),
          ),

      'poll_voting':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_poll_voting_card$suffix',
            user: user,
            label: (user.isHRM || user.isAdmin) ? "គ្រប់គ្រងការបោះឆ្នោត" : "បោះឆ្នោតបុគ្គលិក",
            subtitle: (user.isHRM || user.isAdmin) ? "គ្រប់គ្រង និងមើលលទ្ធផលបោះឆ្នោត" : "ចូលរួមបោះឆ្នោតបុគ្គលិកល្អ",
            icon: Icons.how_to_vote_rounded,
            color: AppTheme.primary,
            onTap: () {
              _hapticLight();
              if (user.isHRM || user.isAdmin) {
                Navigator.push(
                  context,
                  _slideRoute(const HrmPollManagementScreen()),
                );
              } else {
                Navigator.push(
                  context,
                  _slideRoute(const PollVotingScreen()),
                );
              }
            },
          ),

      'announcements':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_announcements_card$suffix',
            user: user,
            label: "ការជូនដំណឹង",
            subtitle: "គ្រប់គ្រង និងប្រកាសព័ត៌មានទូទៅ",
            icon: Icons.campaign_rounded,
            color: Colors.deepPurpleAccent,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const AnnouncementsScreen(),
                  ),
                ),
          ),

      'meetings':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_meetings_card$suffix',
            user: user,
            label: "កិច្ចប្រជុំ",
            subtitle: "រៀបចំ និងកំណត់កាលវិភាគប្រជុំ",
            icon: Icons.groups_rounded,
            color: Colors.indigoAccent,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const MeetingsScreen()),
                ),
          ),

      'checklist':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_checklist_card$suffix',
            user: user,
            label: "បញ្ជីការងារ",
            subtitle: "តាមដានកិច្ចការងារប្រចាំថ្ងៃ",
            icon: Icons.checklist_rounded,
            color: Colors.tealAccent,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const ChecklistScreen()),
                ),
          ),

      'daily_report':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_daily_report_card$suffix',
            user: user,
            label: "របាយការណ៍ប្រចាំថ្ងៃ",
            subtitle: "បញ្ជូនរបាយការណ៍ការងារប្រចាំថ្ងៃ",
            icon: Icons.summarize_rounded,
            color: Colors.lightGreenAccent,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const DailyReportScreen()),
                ),
          ),

      'mission':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_mission_card$suffix',
            user: user,
            label: "លិខិតបេសកកម្ម",
            subtitle: "ស្នើសុំចេញបេសកកម្មខាងក្រៅ",
            icon: Icons.map_rounded,
            color: Colors.blueAccent,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const MissionScreen()),
                ),
          ),

      'user_management':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_user_management_card$suffix',
            user: user,
            label: "គ្រប់គ្រងបុគ្គលិក",
            subtitle: "បន្ថែម កែប្រែ និងពិនិត្យទិន្នន័យបុគ្គលិក",
            icon: Icons.people_alt_rounded,
            color: AppTheme.primary,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const UserManagementScreen(),
                  ),
                ),
          ),

      'request_form':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_request_form_card$suffix',
            user: user,
            label: "បញ្ជីសំណើ",
            subtitle: "គ្រប់គ្រងសំណើច្បាប់ឈប់សម្រាក",
            icon: Icons.list_alt_rounded,
            color: AppTheme.primary,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder:
                        (_) =>
                            (user.isHRM || user.isAdmin)
                                ? const RequestListScreen()
                                : const RequestsScreen(),
                  ),
                ),
          ),

      'reports':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_reports_card$suffix',
            user: user,
            label: "របាយការណ៍វត្តមាន",
            subtitle: "ពិនិត្យរបាយការណ៍វត្តមាន និងអវត្តមាន",
            icon: Icons.insert_chart_rounded,
            color: AppTheme.primary,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const AttendanceReportScreen(),
                  ),
                ),
          ),

      'material_request':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_material_request_card$suffix',
            user: user,
            label: "ស្នើសុំសម្ភារៈ",
            subtitle: "ស្នើសុំសម្ភារៈប្រើប្រាស់ក្នុងស្តុក",
            icon: Icons.inventory_2_rounded,
            color: Colors.cyanAccent,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const MaterialRequestScreen(),
                  ),
                ),
          ),

      'notification':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_notification_card$suffix',
            user: user,
            label: "ផ្ញើការជូនដំណឹង",
            subtitle: "Push notification ទៅបុគ្គលិក",
            icon: Icons.send_rounded,
            color: Colors.orangeAccent,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const SendNotificationScreen(),
                  ),
                ),
          ),

      'notification_history':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_notification_history_card$suffix',
            user: user,
            label: "ប្រវត្តិជូនដំណឹង",
            subtitle: "ពិនិត្យប្រវត្តិទទួលបានដំណឹង",
            icon: Icons.notifications_rounded,
            color: Colors.orangeAccent,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const NotificationScreen()),
                ),
          ),

      'employee_report':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_employee_report_card$suffix',
            user: user,
            label: "របាយការណ៍វត្តមាន",
            subtitle: "ពិនិត្យរបាយការណ៍វត្តមានប្រចាំសាខា",
            icon: Icons.recent_actors_rounded,
            color: Colors.pinkAccent,
            onTap:
                () => Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const EmployeeReportScreen(),
                  ),
                ),
          ),

      'trip':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_trip_card$suffix',
            user: user,
            label: "ការធ្វើដំណើរ",
            subtitle: "តាមដាន និងកត់ត្រាការចុះជួបអតិថិជន",
            icon: Icons.directions_car_rounded,
            color: AppTheme.primary,
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

      'payroll':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_payroll_card$suffix',
            user: user,
            label: "ប្រាក់បៀវត្ស",
            subtitle: "ពិនិត្យមើលប្រវត្តិបើកប្រាក់ខែ",
            icon: Icons.payments_rounded,
            color: AppTheme.primaryDark,
            onTap: () {
              _hapticLight();
              if (user.isHRM || user.isAdmin || user.isAccounting) {
                Navigator.push(
                  context,
                  _slideRoute(const PayrollAdminScreen()),
                );
              } else {
                Navigator.push(context, _slideRoute(const PayrollScreen()));
              }
            },
          ),

      'kpi':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_kpi_card$suffix',
            user: user,
            label: "ការវាយតម្លៃ KPI/OKR",
            subtitle: "តាមដាន និងវាយតម្លៃការងារ",
            icon: Icons.auto_graph_rounded,
            color: AppTheme.primary,
            onTap: () {
              _hapticLight();
              Navigator.push(
                context,
                _slideRoute(const KpiPerformanceScreen()),
              );
            },
          ),

      'document_scanner':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_document_scanner_card$suffix',
            user: user,
            label: "ស្កេនឯកសារ",
            subtitle: "ស្កេនឯកសារអាជីព",
            icon: Icons.document_scanner_outlined,
            color: Colors.orange,
            onTap: () {
              _hapticLight();
              Navigator.push(
                context,
                _slideRoute(const DocumentScannerScreen()),
              );
            },
          ),

      'app_settings':
          (isList) => _buildActionItem(
            isList: isList,
            key: 'show_app_settings$suffix',
            user: user,
            label: "ការកំណត់កម្មវិធី",
            subtitle: "គ្រប់គ្រងការបង្ហាញមុខងារ",
            icon: Icons.settings_rounded,
            color: Colors.grey.shade700,
            onTap: () {
              _hapticLight();
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const AppSettingsScreen()),
              );
            },
          ),

      'stats_slider':
          (isList) =>
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

    const Set<String> bentoDuplicates = {
      'attendance',
      'stats_slider',
      'outside_attendance',
    };

    for (var key in keys) {
      if (bentoDuplicates.contains(key)) continue;
      if (!actionBuilders.containsKey(key)) continue;
      if (!_matchesCategory(key, _selectedCategory)) continue;

      // Pre-check visibility: skip hidden items (SizedBox.shrink has null width)
      final bool isFullWidth = key == 'attendance' || key == 'stats_slider';

      // Check visibility before building the actual widget
      final bool isVisible =
          actionBuilders.containsKey(key) &&
          _canShowRoleAction(
            user,
            _visibilityKeyForAction(key, suffix),
            suffix,
          );
      if (!isVisible) continue;

      final widget = actionBuilders[key]!(isListLayout);

      if (isListLayout) {
        finalWidgets.add(widget);
      } else {
        if (isFullWidth) {
          // Flush any pending grid items first
          if (gridBatch.isNotEmpty) {
            finalWidgets.add(_buildGridWrapper(gridBatch));
            gridBatch = [];
          }
          finalWidgets.add(widget);
          finalWidgets.add(const SizedBox(height: 18));
        } else {
          gridBatch.add(widget);
        }
      }
    }

    // Flush remaining grid items into a single GridView
    if (gridBatch.isNotEmpty) finalWidgets.add(_buildGridWrapper(gridBatch));

    if (finalWidgets.isEmpty) {
      return _buildEmptyActionsState();
    }

    finalWidgets.insert(
      0,
      Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: SectionHeader(
          title: "⚡ សេវាកម្ម និងមុខងារ",
          textColor: theme.isDarkTheme ? Colors.white : theme.textPrimary,
        ),
      ),
    );

    return Column(children: finalWidgets);
  }

  /// Returns the config visibility key for a given action key.
  String _visibilityKeyForAction(String key, String suffix) {
    switch (key) {
      case 'attendance':
        return 'show_attendance_card$suffix';
      case 'stats_slider':
        return 'show_stats_slider$suffix';
      case 'outside_attendance':
        return 'show_outside_attendance_card$suffix';
      case 'training_quiz':
        return 'show_training_quiz_card$suffix';
      case 'product_analyzer':
        return 'show_product_analyzer_card$suffix';
      case 'poll_voting':
        return 'show_poll_voting_card$suffix';
      case 'announcements':
        return 'show_announcements_card$suffix';
      case 'meetings':
        return 'show_meetings_card$suffix';
      case 'checklist':
        return 'show_checklist_card$suffix';
      case 'daily_report':
        return 'show_daily_report_card$suffix';
      case 'mission':
        return 'show_mission_card$suffix';
      case 'user_management':
        return 'show_user_management_card$suffix';
      case 'request_form':
        return 'show_request_form_card$suffix';
      case 'reports':
        return 'show_reports_card$suffix';
      case 'material_request':
        return 'show_material_request_card$suffix';
      case 'notification':
        return 'show_notification_card$suffix';
      case 'notification_history':
        return 'show_notification_history_card$suffix';
      case 'employee_report':
        return 'show_employee_report_card$suffix';
      case 'trip':
        return 'show_trip_card$suffix';
      case 'payroll':
        return 'show_payroll_card$suffix';
      case 'document_scanner':
        return 'show_document_scanner_card$suffix';
      case 'app_settings':
        return 'show_app_settings$suffix';
      default:
        return 'show_${key}_card$suffix';
    }
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
    // Document scanner is disabled by default for workers
    if (configKey.contains('document_scanner') && suffix == '__worker') {
      return false;
    }
    // App settings only for HRM and Admin
    if (configKey.contains('app_settings') &&
        suffix != '__hrm' &&
        suffix != '__admin') {
      return false;
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

    final theme = user.companyTheme;
    // Unified core branding color for clean Glassmorphism (no messy multi-colors)
    final brandAccentColor = theme.brand == CompanyBrand.vvc
        ? const Color(0xFFD97706)
        : theme.cardPrimary;

    if (isList) {
      return Padding(
        padding: const EdgeInsets.only(bottom: 10),
        child: AppActionButton(
          title: label,
          subtitle: subtitle,
          icon: icon,
          iconColor: brandAccentColor,
          onTap: wrappedTap,
          textColor: theme.textPrimary,
          subtitleColor: theme.textSecondary,
          cardColor: theme.cardBackground,
          borderColor: theme.cardBorder,
        ),
      );
    } else {
      return AppGridAction(
        label: label.replaceAll(' ', '\n'),
        icon: icon,
        color: brandAccentColor,
        onTap: wrappedTap,
        textColor: theme.textPrimary,
        cardColor: theme.cardBackground,
        borderColor: theme.cardBorder,
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
        GridView.builder(
          shrinkWrap: true,
          physics: const BouncingScrollPhysics(),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 3,
            crossAxisSpacing: 12.0,
            mainAxisSpacing: 12.0,
            childAspectRatio: 1.0,
          ),
          itemCount: items.length,
          itemBuilder: (context, index) {
            return items[index];
          },
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
              color: AppTheme.primary,
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

// ═════════════════════════════════════════════════════════════════════════════
// ─── DYNAMIC COLLAPSIBLE HEADER (Apple / Telegram Luxury 1:1) ─────────────────
// ═════════════════════════════════════════════════════════════════════════════

class _HomeHeaderDelegate extends SliverPersistentHeaderDelegate {
  final UserProvider user;
  final CompanyTheme theme;
  final String greeting;
  final int unreadNotifications;
  final VoidCallback? onProfileTap;
  final double topPadding;
  final bool isScrolled;

  _HomeHeaderDelegate({
    required this.user,
    required this.theme,
    required this.greeting,
    required this.unreadNotifications,
    this.onProfileTap,
    required this.topPadding,
    this.isScrolled = false,
  });

  @override
  double get minExtent => topPadding + 68.0;

  @override
  double get maxExtent => topPadding + 68.0;

  @override
  Widget build(
    BuildContext context,
    double shrinkOffset,
    bool overlapsContent,
  ) {
    final effectiveScrolled = isScrolled || overlapsContent || shrinkOffset > 2.0;
    final isDark = theme.isDarkTheme;
    const primaryGold = Color(0xFFF3D010);

    final headerBgColor = isDark
        ? const Color(0xFF1E293B).withValues(alpha: effectiveScrolled ? 0.65 : 0.50)
        : const Color(0xFFE2E8F0).withValues(alpha: effectiveScrolled ? 0.45 : 0.35);

    final effectiveBorder = isDark
        ? (effectiveScrolled
            ? Colors.white.withValues(alpha: 0.35)
            : Colors.white.withValues(alpha: 0.18))
        : (effectiveScrolled
            ? Colors.white.withValues(alpha: 0.85)
            : Colors.white.withValues(alpha: 0.65));

    return AnnotatedRegion<SystemUiOverlayStyle>(
      value: SystemUiOverlayStyle(
        statusBarColor: Colors.transparent,
        statusBarIconBrightness: isDark ? Brightness.light : Brightness.dark,
        statusBarBrightness: isDark ? Brightness.dark : Brightness.light,
      ),
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          // ── 1. Authentic Apple iOS Frosted Glass Header Bar (Status Bar + Navigation Bar) ──
          Positioned(
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            child: TweenAnimationBuilder<double>(
              duration: const Duration(milliseconds: 220),
              curve: Curves.easeOutCubic,
              tween: Tween<double>(begin: 0.0, end: effectiveScrolled ? 1.0 : 0.0),
              builder: (context, animValue, _) {
                if (animValue <= 0.01) {
                  return const SizedBox.shrink();
                }
                return ClipRect(
                  child: BackdropFilter(
                    filter: ui.ImageFilter.blur(
                      sigmaX: 25.0 * animValue,
                      sigmaY: 25.0 * animValue,
                    ),
                    child: Container(
                      decoration: BoxDecoration(
                        color: isDark
                            ? const Color(0xFF0F1115).withValues(alpha: 0.78 * animValue)
                            : Colors.white.withValues(alpha: 0.82 * animValue),
                        border: Border(
                          bottom: BorderSide(
                            color: isDark
                                ? Colors.white.withValues(alpha: 0.12 * animValue)
                                : const Color(0xFFCBD5E1).withValues(alpha: 0.70 * animValue),
                            width: 0.8,
                          ),
                        ),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withValues(alpha: (isDark ? 0.35 : 0.05) * animValue),
                            blurRadius: 16.0,
                            offset: const Offset(0, 4),
                          ),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ),

          // ── 2. Top Ambient Transition Zone below Header (Matches Bottom Transition Zone) ──
          Positioned(
            top: topPadding + 68.0,
            left: 0,
            right: 0,
            height: 24.0,
            child: TweenAnimationBuilder<double>(
              duration: const Duration(milliseconds: 220),
              curve: Curves.easeOutCubic,
              tween: Tween<double>(begin: 0.0, end: effectiveScrolled ? 1.0 : 0.0),
              builder: (context, animValue, _) {
                if (animValue <= 0.01) {
                  return const SizedBox.shrink();
                }
                final fadeColor = isDark ? const Color(0xFF0F1115) : Colors.white;
                return IgnorePointer(
                  child: Container(
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        begin: Alignment.topCenter,
                        end: Alignment.bottomCenter,
                        colors: [
                          fadeColor.withValues(alpha: 0.28 * animValue),
                          fadeColor.withValues(alpha: 0.0),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ),

          // ── 3. Three Standalone Floating Glass Pods (Left Island, Center Capsule, Right Island) ──
          Positioned(
            top: topPadding + 6.0,
            left: 14.0,
            right: 14.0,
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                // [POD 1] Left Standalone Circular Glass Pod: Quick Add / Leave Request & Others (+)
                _buildCircularGlassPod(
                  size: 48.0,
                  isDark: isDark,
                  isScrolled: effectiveScrolled,
                  headerBgColor: headerBgColor,
                  effectiveBorder: effectiveBorder,
                  primaryGold: primaryGold,
                  onTap: () => _showQuickRequestSheet(context, isDark, primaryGold),
                  child: const Center(
                    child: Icon(
                      Icons.add_rounded,
                      color: primaryGold,
                      size: 24.0,
                    ),
                  ),
                ),

                const SizedBox(width: 8.0),

                // [POD 2] Center Standalone Capsule Glass Pod: Profile Avatar + Name + VVC Tag + Greeting
                Expanded(
                  child: _buildProfileCapsulePod(
                    context: context,
                    isDark: isDark,
                    isScrolled: effectiveScrolled,
                    headerBgColor: headerBgColor,
                    effectiveBorder: effectiveBorder,
                    primaryGold: primaryGold,
                  ),
                ),

                const SizedBox(width: 8.0),

                // [POD 3] Right Standalone Circular Glass Pod: Notifications Bell
                _buildCircularGlassPod(
                  size: 48.0,
                  isDark: isDark,
                  isScrolled: effectiveScrolled,
                  headerBgColor: headerBgColor,
                  effectiveBorder: effectiveBorder,
                  primaryGold: primaryGold,
                  onTap: () {
                    HapticFeedback.lightImpact();
                    Navigator.push(
                      context,
                      _slideRoute(const NotificationScreen()),
                    );
                  },
                  child: Stack(
                    clipBehavior: Clip.none,
                    alignment: Alignment.center,
                    children: [
                      const Center(
                        child: Icon(
                          Icons.notifications_rounded,
                          color: primaryGold,
                          size: 22.0,
                        ),
                      ),
                      if (unreadNotifications > 0)
                        Positioned(
                          top: 4,
                          right: 4,
                          child: Container(
                            width: 8.5,
                            height: 8.5,
                            decoration: BoxDecoration(
                              color: const Color(0xFFEF4444),
                              shape: BoxShape.circle,
                              border: Border.all(
                                color: isDark ? const Color(0xFF0F1115) : Colors.white,
                                width: 1.4,
                              ),
                              boxShadow: [
                                BoxShadow(
                                  color: const Color(0xFFEF4444).withValues(alpha: 0.6),
                                  blurRadius: 4,
                                ),
                              ],
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showQuickRequestSheet(BuildContext context, bool isDark, Color primaryGold) {
    HapticFeedback.lightImpact();
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (ctx) {
        return Container(
          padding: const EdgeInsets.fromLTRB(20, 12, 20, 32),
          decoration: BoxDecoration(
            color: isDark ? const Color(0xFF181A20) : Colors.white,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
            border: Border(
              top: BorderSide(
                color: primaryGold.withValues(alpha: 0.45),
                width: 1.5,
              ),
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: isDark ? 0.5 : 0.15),
                blurRadius: 30,
                offset: const Offset(0, -6),
              ),
            ],
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Center(
                child: Container(
                  width: 38,
                  height: 4.5,
                  margin: const EdgeInsets.only(bottom: 18),
                  decoration: BoxDecoration(
                    color: isDark ? Colors.white24 : Colors.black12,
                    borderRadius: BorderRadius.circular(3),
                  ),
                ),
              ),
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: primaryGold.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Icon(Icons.post_add_rounded, color: primaryGold, size: 22),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'ស្នើសុំ & បន្ថែមសំណើ',
                          style: GoogleFonts.kantumruyPro(
                            color: isDark ? Colors.white : const Color(0xFF0F172A),
                            fontWeight: FontWeight.w700,
                            fontSize: 16.5,
                          ),
                        ),
                        Text(
                          'ជ្រើសរើសប្រភេទសំណើដែលលោកអ្នកចង់ស្នើសុំ',
                          style: GoogleFonts.kantumruyPro(
                            color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
                            fontSize: 11.5,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 18),
              _buildRequestTile(
                ctx: ctx,
                title: 'ស្នើសុំច្បាប់ឈប់សម្រាក (Leave Request)',
                subtitle: 'ច្បាប់ឈប់សម្រាកប្រចាំឆ្នាំ ឬ ឈឺ',
                icon: Icons.beach_access_rounded,
                iconColor: primaryGold,
                isDark: isDark,
                isPrimary: true,
                primaryGold: primaryGold,
                onTap: () {
                  Navigator.pop(ctx);
                  Navigator.push(context, _slideRoute(const LeaveRequestScreen()));
                },
              ),
              const SizedBox(height: 8),
              _buildRequestTile(
                ctx: ctx,
                title: 'ស្នើសុំសម្ភារៈការិយាល័យ (Material Request)',
                subtitle: 'សម្ភារៈ និងបរិក្ខារប្រើប្រាស់',
                icon: Icons.inventory_2_rounded,
                iconColor: const Color(0xFF38BDF8),
                isDark: isDark,
                onTap: () {
                  Navigator.pop(ctx);
                  Navigator.push(context, _slideRoute(const MaterialRequestScreen()));
                },
              ),
              const SizedBox(height: 8),
              _buildRequestTile(
                ctx: ctx,
                title: 'ស្នើសុំបេសកកម្មការងារ (Mission)',
                subtitle: 'ចុះបំពេញបេសកកម្មការងារក្រៅ',
                icon: Icons.flight_takeoff_rounded,
                iconColor: const Color(0xFF34D399),
                isDark: isDark,
                onTap: () {
                  Navigator.pop(ctx);
                  Navigator.push(context, _slideRoute(const MissionScreen()));
                },
              ),
              const SizedBox(height: 8),
              _buildRequestTile(
                ctx: ctx,
                title: 'សំណើផ្សេងៗទាំងអស់ (All Requests)',
                subtitle: 'ពិនិត្យប្រវត្តិ និងបញ្ជីសំណើទាំងអស់',
                icon: Icons.assignment_rounded,
                iconColor: const Color(0xFFA78BFA),
                isDark: isDark,
                onTap: () {
                  Navigator.pop(ctx);
                  Navigator.push(
                    context,
                    _slideRoute(user.isHRM ? const RequestListScreen() : const RequestsScreen()),
                  );
                },
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildRequestTile({
    required BuildContext ctx,
    required String title,
    required String subtitle,
    required IconData icon,
    required Color iconColor,
    required bool isDark,
    bool isPrimary = false,
    Color? primaryGold,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        decoration: BoxDecoration(
          color: isPrimary
              ? (primaryGold ?? const Color(0xFFF3D010)).withValues(alpha: isDark ? 0.16 : 0.10)
              : (isDark ? Colors.white.withValues(alpha: 0.05) : const Color(0xFFF8FAFC)),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: isPrimary
                ? (primaryGold ?? const Color(0xFFF3D010)).withValues(alpha: 0.40)
                : (isDark ? Colors.white.withValues(alpha: 0.08) : const Color(0xFFE2E8F0)),
            width: isPrimary ? 1.4 : 1.0,
          ),
        ),
        child: Row(
          children: [
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                color: iconColor.withValues(alpha: 0.15),
                shape: BoxShape.circle,
              ),
              child: Center(
                child: Icon(icon, color: iconColor, size: 20),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: GoogleFonts.kantumruyPro(
                      color: isDark ? Colors.white : const Color(0xFF0F172A),
                      fontWeight: isPrimary ? FontWeight.w700 : FontWeight.w600,
                      fontSize: 13.5,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    subtitle,
                    style: GoogleFonts.kantumruyPro(
                      color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
                      fontSize: 11.0,
                    ),
                  ),
                ],
              ),
            ),
            Icon(
              Icons.chevron_right_rounded,
              color: isDark ? Colors.white38 : Colors.black38,
              size: 20,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCircularGlassPod({
    required double size,
    required bool isDark,
    required bool isScrolled,
    required Color headerBgColor,
    required Color effectiveBorder,
    required Color primaryGold,
    required VoidCallback onTap,
    required Widget child,
  }) {
    final podContent = Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: LinearGradient(
          begin: const Alignment(-0.5, -1.0),
          end: const Alignment(0.5, 1.0),
          colors: isDark
              ? [
                  Colors.white.withValues(alpha: 0.18),
                  headerBgColor,
                  const Color(0xFF0F172A).withValues(alpha: isScrolled ? 0.65 : 0.50),
                ]
              : [
                  Colors.white.withValues(alpha: 0.75),
                  headerBgColor,
                  const Color(0xFFCBD5E1).withValues(alpha: isScrolled ? 0.40 : 0.30),
                ],
          stops: const [0.0, 0.30, 1.0],
        ),
        border: Border.all(
          color: effectiveBorder,
          width: 1.2,
        ),
      ),
      child: child,
    );

    return GestureDetector(
      onTap: onTap,
      behavior: HitTestBehavior.opaque,
      child: Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          boxShadow: [
            BoxShadow(
              color: primaryGold.withValues(alpha: isScrolled ? 0.14 : 0.05),
              blurRadius: 16,
              spreadRadius: -2,
              offset: const Offset(0, 4),
            ),
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.38 : (isScrolled ? 0.06 : 0.02)),
              blurRadius: 14,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(size / 2),
          child: isScrolled
              ? podContent
              : BackdropFilter(
                  filter: ui.ImageFilter.blur(sigmaX: 25.0, sigmaY: 25.0),
                  child: podContent,
                ),
        ),
      ),
    );
  }

  Widget _buildProfileCapsulePod({
    required BuildContext context,
    required bool isDark,
    required bool isScrolled,
    required Color headerBgColor,
    required Color effectiveBorder,
    required Color primaryGold,
  }) {
    final capsuleContent = GestureDetector(
      onTap: () {
        HapticFeedback.lightImpact();
        onProfileTap?.call();
      },
      behavior: HitTestBehavior.opaque,
      child: Container(
        height: 54.0,
        padding: const EdgeInsets.symmetric(horizontal: 8.0, vertical: 6.0),
        decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(30.0),
                gradient: LinearGradient(
                  begin: const Alignment(-0.5, -1.0),
                  end: const Alignment(0.5, 1.0),
                  colors: isDark
                      ? [
                          Colors.white.withValues(alpha: 0.18),
                          headerBgColor,
                          const Color(0xFF0F172A).withValues(alpha: isScrolled ? 0.65 : 0.50),
                        ]
                      : [
                          Colors.white.withValues(alpha: 0.75),
                          headerBgColor,
                          const Color(0xFFCBD5E1).withValues(alpha: isScrolled ? 0.40 : 0.30),
                        ],
                  stops: const [0.0, 0.30, 1.0],
                ),
                border: Border.all(
                  color: effectiveBorder,
                  width: 1.2,
                ),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  // Profile Photo with Gold rim + check badge
                  Stack(
                    clipBehavior: Clip.none,
                    alignment: Alignment.center,
                    children: [
                      Container(
                        width: 38.0,
                        height: 38.0,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: theme.cardPrimary,
                          border: Border.all(
                            color: const Color(0xFFD4AF37),
                            width: 1.8,
                          ),
                          boxShadow: [
                            BoxShadow(
                              color: const Color(0xFFD4AF37).withValues(alpha: 0.35),
                              blurRadius: 8,
                              offset: const Offset(0, 1),
                            ),
                          ],
                        ),
                        child: ClipOval(
                          child: user.avatarUrl != null && user.avatarUrl!.isNotEmpty
                              ? Image.network(
                                  user.avatarUrl!,
                                  fit: BoxFit.cover,
                                  alignment: const Alignment(0, -0.25),
                                  errorBuilder: (_, __, ___) => _buildInitials(user, theme),
                                )
                              : _buildInitials(user, theme),
                        ),
                      ),
                      Positioned(
                        bottom: -1,
                        right: -1,
                        child: Container(
                          width: 13.5,
                          height: 13.5,
                          decoration: BoxDecoration(
                            color: const Color(0xFF0EA5E9),
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: isDark ? const Color(0xFF0F1115) : Colors.white,
                              width: 1.3,
                            ),
                          ),
                          child: const Center(
                            child: Icon(
                              Icons.check_rounded,
                              color: Colors.white,
                              size: 8.5,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(width: 8.0),

                  // Column: Name + Verified + VVC outlined tag & Greeting
                  Expanded(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Flexible(
                              child: Text(
                                user.name ?? 'បុគ្គលិក',
                                style: GoogleFonts.kantumruyPro(
                                  color: isDark ? Colors.white : const Color(0xFF0F172A),
                                  fontWeight: FontWeight.w700,
                                  fontSize: 12.5,
                                ),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                            const SizedBox(width: 3.5),
                            const Icon(
                              Icons.verified_rounded,
                              color: Color(0xFF0EA5E9),
                              size: 13.5,
                            ),
                            const SizedBox(width: 4.0),
                            Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 4.5,
                                vertical: 1.0,
                              ),
                              decoration: BoxDecoration(
                                color: Colors.transparent,
                                borderRadius: BorderRadius.circular(4.5),
                                border: Border.all(
                                  color: const Color(0xFFD4AF37),
                                  width: 1.1,
                                ),
                              ),
                              child: Text(
                                theme.brand == CompanyBrand.sk ? 'SK' : 'VVC',
                                style: GoogleFonts.inter(
                                  color: const Color(0xFFD4AF37),
                                  fontWeight: FontWeight.w900,
                                  fontSize: 8.5,
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 1.0),
                        Text(
                          greeting,
                          style: GoogleFonts.kantumruyPro(
                            color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
                            fontSize: 9.5,
                            fontWeight: FontWeight.w500,
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
          );

    return Container(
      height: 54.0,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(30.0),
        boxShadow: [
          BoxShadow(
            color: primaryGold.withValues(alpha: isScrolled ? 0.14 : 0.05),
            blurRadius: 18,
            spreadRadius: -2,
            offset: const Offset(0, 4),
          ),
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.38 : (isScrolled ? 0.06 : 0.02)),
            blurRadius: 16,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(30.0),
        child: isScrolled
            ? capsuleContent
            : BackdropFilter(
                filter: ui.ImageFilter.blur(sigmaX: 25.0, sigmaY: 25.0),
                child: capsuleContent,
              ),
      ),
    );
  }

  Widget _buildInitials(UserProvider user, CompanyTheme theme) {
    return Center(
      child: Text(
        (user.name ?? 'U').isNotEmpty
            ? user.name!.substring(0, 1).toUpperCase()
            : 'U',
        style: GoogleFonts.inter(
          color: theme.passCardTextColor,
          fontWeight: FontWeight.bold,
          fontSize: 18,
        ),
      ),
    );
  }

  @override
  bool shouldRebuild(covariant _HomeHeaderDelegate oldDelegate) {
    return oldDelegate.user != user ||
        oldDelegate.theme != theme ||
        oldDelegate.greeting != greeting ||
        oldDelegate.unreadNotifications != unreadNotifications ||
        oldDelegate.topPadding != topPadding ||
        oldDelegate.isScrolled != isScrolled;
  }
}
