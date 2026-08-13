import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../screens/attendance_screen.dart';
import '../screens/certificate_editor_screen.dart';
import '../screens/poll_voting_screen.dart';
import '../screens/requests_screen.dart';
import '../screens/request_list_screen.dart';
import '../screens/attendance_report_screen.dart';
import '../screens/ai_chat_screen.dart';
import '../screens/document_scanner_screen.dart';
import '../screens/meetings_screen.dart';
import '../screens/user_management_screen.dart';
import '../screens/announcements_screen.dart';
import '../screens/notification_screen.dart';

class DesktopDashboardView extends StatefulWidget {
  final Function(int navIndex)? onNavigateToTab;

  const DesktopDashboardView({
    super.key,
    this.onNavigateToTab,
  });

  @override
  State<DesktopDashboardView> createState() => _DesktopDashboardViewState();
}

class _DesktopDashboardViewState extends State<DesktopDashboardView> {
  final ApiService _api = ApiService();

  Map<String, dynamic> _stats = {
    'today_work': 0,
    'requests_count': 0,
    'announcements_count': 0,
    'unread_notifications': 0,
    'annual_leave_remaining': 0,
  };
  bool _isLoadingStats = true;
  String _nextAction = 'Check-In';
  bool _isLoadingNextAction = true;
  List<dynamic> _banners = [];

  // Live Timer
  DateTime? _checkInTime;
  Timer? _liveTimerTick;
  String _liveWorkDuration = '00:00:00';

  // Digital Clock
  Timer? _clockTimer;
  DateTime _currentTime = DateTime.now();

  @override
  void initState() {
    super.initState();
    _loadStats();
    _loadNextAction();
    _loadCheckInTime();
    _loadBanners();

    // Update real-time clock every second
    _clockTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) {
        setState(() {
          _currentTime = DateTime.now();
        });
      }
    });
  }

  @override
  void dispose() {
    _clockTimer?.cancel();
    _liveTimerTick?.cancel();
    super.dispose();
  }

  Future<void> _loadStats() async {
    try {
      final result = await _api.fetchDashboardStats();
      if (mounted && result['success'] == true) {
        setState(() {
          if (result['stats'] is Map) {
            _stats = Map<String, dynamic>.from(result['stats']);
          }
          _isLoadingStats = false;
        });
      } else {
        if (mounted) setState(() => _isLoadingStats = false);
      }
    } catch (_) {
      if (mounted) setState(() => _isLoadingStats = false);
    }
  }

  Future<void> _loadNextAction() async {
    try {
      final result = await _api.fetchLastAction();
      if (!mounted) return;
      if (result['success'] == true) {
        final last = result['last_action'] ?? 'Check-Out';
        setState(() {
          _nextAction = (last == 'Check-In') ? 'Check-Out' : 'Check-In';
          _isLoadingNextAction = false;
        });
      } else {
        setState(() => _isLoadingNextAction = false);
      }
    } catch (_) {
      if (mounted) setState(() => _isLoadingNextAction = false);
    }
  }

  Future<void> _loadCheckInTime() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final ts = prefs.getString('last_checkin_time');
      if (ts != null) {
        final t = DateTime.tryParse(ts);
        if (t != null && DateTime.now().difference(t).inHours < 16) {
          setState(() => _checkInTime = t);
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
      setState(() {
        _liveWorkDuration =
            '${h.toString().padLeft(2, '0')}:${m.toString().padLeft(2, '0')}:${s.toString().padLeft(2, '0')}';
      });
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
    } catch (_) {}
  }

  void _handleScanAction(String action) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => AttendanceScreen(presetAction: action),
      ),
    ).then((result) {
      _loadStats();
      _loadNextAction();
      if (result == 'checked_in') {
        final now = DateTime.now();
        SharedPreferences.getInstance().then((p) => p.setString('last_checkin_time', now.toIso8601String()));
        setState(() => _checkInTime = now);
        _startLiveTimer();
      } else if (result == 'checked_out') {
        SharedPreferences.getInstance().then((p) => p.remove('last_checkin_time'));
        _liveTimerTick?.cancel();
        setState(() {
          _checkInTime = null;
          _liveWorkDuration = '00:00:00';
        });
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final user = Provider.of<UserProvider>(context);
    final userName = user.name?.isNotEmpty == true ? user.name! : 'អ្នកប្រើប្រាស់';
    final userRole = user.systemRoleLabel.isNotEmpty ? user.systemRoleLabel : 'បុគ្គលិក';

    return SelectionArea(
      child: Container(
        color: const Color(0xFF0B1120),
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Top Hero Welcome & Stopwatch Banner
              _buildTopHeroBanner(userName, userRole, user),
              const SizedBox(height: 24),

              // Row of 4 KPI Metric Cards
              _buildKpiMetricsGrid(user),
              const SizedBox(height: 28),

              // Main Two-Column Layout (Operations Canvas 68% + Smart Sidebar 32%)
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Left Workspace (Operations + Announcements)
                  Expanded(
                    flex: 68,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        _buildSectionHeader(
                          title: 'មជ្ឈមណ្ឌលប្រតិបត្តិការ & ឧបករណ៍ (Operations Hub)',
                          subtitle: 'ជ្រើសរើសមុខងាររហ័សសម្រាប់បំពេញការងារប្រចាំថ្ងៃ',
                          icon: Icons.grid_view_rounded,
                        ),
                        const SizedBox(height: 16),
                        _buildQuickActionGrid(user),
                        const SizedBox(height: 32),

                        _buildSectionHeader(
                          title: 'សេចក្តីជូនដំណឹង & ព័ត៌មានក្រុមហ៊ុន (Announcements)',
                          subtitle: 'ព័ត៌មានផ្លូវការ និងការជូនដំណឹងពីថ្នាក់ដឹកនាំ',
                          icon: Icons.campaign_rounded,
                        ),
                        const SizedBox(height: 16),
                        _buildAnnouncementsSection(),
                      ],
                    ),
                  ),
                  const SizedBox(width: 24),

                  // Right Smart Sidebar (Clock, Calendar, AI Prompt)
                  Expanded(
                    flex: 32,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        _buildDigitalClockKhmerCalendarCard(),
                        const SizedBox(height: 20),
                        _buildOfficeGpsStatusCard(),
                        const SizedBox(height: 20),
                        _buildAiAssistantQuickCard(),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 40),
            ],
          ),
        ),
      ),
    );
  }

  // ===== 1. Top Hero Welcome & Stopwatch Banner =====
  Widget _buildTopHeroBanner(String userName, String userRole, UserProvider user) {
    final bool isCheckedIn = _checkInTime != null;
    final String timeGreeting = _currentTime.hour < 12
        ? 'អរុណសួស្តី (Good Morning)'
        : (_currentTime.hour < 17 ? 'ទិវាសួស្តី (Good Afternoon)' : 'សាយណ្ហសួស្តី (Good Evening)');

    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [
            Color(0xFF1E293B),
            Color(0xFF0F172A),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: Colors.white.withValues(alpha: 0.08),
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.3),
            blurRadius: 16,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          // Left Greeting Details
          Row(
            children: [
              Container(
                width: 60,
                height: 60,
                decoration: BoxDecoration(
                  gradient: const LinearGradient(
                    colors: [Color(0xFF2563EB), Color(0xFF1D4ED8)],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                  borderRadius: BorderRadius.circular(16),
                  boxShadow: [
                    BoxShadow(
                      color: const Color(0xFF2563EB).withValues(alpha: 0.4),
                      blurRadius: 12,
                      offset: const Offset(0, 4),
                    ),
                  ],
                ),
                child: const Center(
                  child: Icon(
                    Icons.badge_rounded,
                    color: Colors.white,
                    size: 30,
                  ),
                ),
              ),
              const SizedBox(width: 18),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        '$timeGreeting, ',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white70,
                          fontSize: 14,
                        ),
                      ),
                      Text(
                        userName,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
                        decoration: BoxDecoration(
                          color: const Color(0xFF2563EB).withValues(alpha: 0.25),
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(
                            color: const Color(0xFF2563EB).withValues(alpha: 0.5),
                          ),
                        ),
                        child: Text(
                          userRole,
                          style: GoogleFonts.kantumruyPro(
                            color: const Color(0xFF93C5FD),
                            fontSize: 11.5,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Text(
                        'ប្រព័ន្ធគ្រប់គ្រងវត្តមាន & ធនធានមនុស្ស VVC Group',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white54,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ],
          ),

          // Right Live Stopwatch & Primary Check-In/Out Action
          Row(
            children: [
              // Live Stopwatch Card
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
                decoration: BoxDecoration(
                  color: const Color(0xFF0F172A),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(
                    color: isCheckedIn
                        ? const Color(0xFF10B981).withValues(alpha: 0.4)
                        : Colors.white.withValues(alpha: 0.1),
                  ),
                ),
                child: Row(
                  children: [
                    Container(
                      width: 10,
                      height: 10,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: isCheckedIn ? const Color(0xFF10B981) : Colors.white30,
                        boxShadow: isCheckedIn
                            ? [
                                BoxShadow(
                                  color: const Color(0xFF10B981).withValues(alpha: 0.6),
                                  blurRadius: 6,
                                  spreadRadius: 2,
                                )
                              ]
                            : null,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          isCheckedIn ? 'ម៉ោងធ្វើការបច្ចុប្បន្ន' : 'ស្ថានភាពវត្តមាន',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white54,
                            fontSize: 10.5,
                          ),
                        ),
                        Text(
                          isCheckedIn ? _liveWorkDuration : 'មិនទាន់ Check-In',
                          style: GoogleFonts.outfit(
                            color: isCheckedIn ? const Color(0xFF10B981) : Colors.white70,
                            fontSize: 16,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 1.1,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 14),

              // Action Button
              ElevatedButton.icon(
                onPressed: () => _handleScanAction(_nextAction),
                icon: Icon(
                  _nextAction == 'Check-In' ? Icons.login_rounded : Icons.logout_rounded,
                  color: Colors.white,
                  size: 20,
                ),
                label: Text(
                  _nextAction == 'Check-In' ? 'ស្កេន Check-In' : 'ស្កេន Check-Out',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 13.5,
                  ),
                ),
                style: ElevatedButton.styleFrom(
                  backgroundColor: _nextAction == 'Check-In'
                      ? const Color(0xFF16A34A)
                      : const Color(0xFFDC2626),
                  padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 18),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14),
                  ),
                  elevation: 4,
                  shadowColor: (_nextAction == 'Check-In'
                          ? const Color(0xFF16A34A)
                          : const Color(0xFFDC2626))
                      .withValues(alpha: 0.4),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // ===== 2. KPI Metrics Grid (4 Cards) =====
  Widget _buildKpiMetricsGrid(UserProvider user) {
    final int todayWork = _stats['today_work'] is int ? _stats['today_work'] : 0;
    final int pendingRequests = _stats['requests_count'] is int ? _stats['requests_count'] : 0;
    final dynamic annualLeave = _stats['annual_leave_remaining'] ?? 0;
    final int unreadNotifs = _stats['unread_notifications'] is int ? _stats['unread_notifications'] : 0;

    return Row(
      children: [
        Expanded(
          child: _buildMetricCard(
            title: 'វត្តមានថ្ងៃនេះ',
            value: todayWork > 0 ? 'បានកត់ត្រា' : 'រង់ចាំស្កេន',
            subtitle: 'កំណត់ត្រាវត្តមានផ្លូវការ',
            icon: Icons.access_time_filled_rounded,
            accentColor: const Color(0xFF10B981),
            badge: todayWork > 0 ? 'Checked' : 'Pending',
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const AttendanceReportScreen()),
            ),
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _buildMetricCard(
            title: 'សំណើដែលរង់ចាំ',
            value: '$pendingRequests សំណើ',
            subtitle: 'ច្បាប់ឈប់សម្រាក & បេសកកម្ម',
            icon: Icons.pending_actions_rounded,
            accentColor: const Color(0xFFF59E0B),
            badge: pendingRequests > 0 ? 'ត្រូវការអនុម័ត' : 'ស្អាតល្អ',
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => user.isHRM ? const RequestListScreen() : const RequestsScreen(),
              ),
            ),
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _buildMetricCard(
            title: 'ច្បាប់នៅសល់ (AL)',
            value: '$annualLeave ថ្ងៃ',
            subtitle: 'សិទ្ធិឈប់សម្រាកប្រចាំឆ្នាំ',
            icon: Icons.beach_access_rounded,
            accentColor: const Color(0xFF3B82F6),
            badge: 'ប្រចាំឆ្នាំ',
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const RequestsScreen()),
            ),
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _buildMetricCard(
            title: 'ការជូនដំណឹងថ្មី',
            value: '$unreadNotifs សារ',
            subtitle: 'ព័ត៌មានពីក្រុមហ៊ុន & HR',
            icon: Icons.notifications_active_rounded,
            accentColor: const Color(0xFF8B5CF6),
            badge: unreadNotifs > 0 ? 'New' : 'Update',
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const NotificationScreen()),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildMetricCard({
    required String title,
    required String value,
    required String subtitle,
    required IconData icon,
    required Color accentColor,
    required String badge,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      hoverColor: Colors.white.withValues(alpha: 0.03),
      child: Container(
        padding: const EdgeInsets.all(18),
        decoration: BoxDecoration(
          color: const Color(0xFF1E293B),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: Colors.white.withValues(alpha: 0.07),
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.15),
              blurRadius: 10,
              offset: const Offset(0, 3),
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
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: accentColor.withValues(alpha: 0.18),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(icon, color: accentColor, size: 22),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.06),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Text(
                    badge,
                    style: GoogleFonts.outfit(
                      color: Colors.white70,
                      fontSize: 10,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 14),
            Text(
              value,
              style: GoogleFonts.outfit(
                color: Colors.white,
                fontSize: 20,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              title,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white70,
                fontSize: 12.5,
                fontWeight: FontWeight.w600,
              ),
            ),
            Text(
              subtitle,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white38,
                fontSize: 11,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ===== 3. Section Header Helper =====
  Widget _buildSectionHeader({
    required String title,
    required String subtitle,
    required IconData icon,
  }) {
    return Row(
      children: [
        Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: const Color(0xFF2563EB).withValues(alpha: 0.2),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, color: const Color(0xFF60A5FA), size: 20),
        ),
        const SizedBox(width: 12),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 15,
                fontWeight: FontWeight.bold,
              ),
            ),
            Text(
              subtitle,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white54,
                fontSize: 11.5,
              ),
            ),
          ],
        ),
      ],
    );
  }

  // ===== 4. Quick Action Grid (8 Cards) =====
  Widget _buildQuickActionGrid(UserProvider user) {
    final actions = [
      _ActionItem(
        title: 'ស្កេនវត្តមានប្រចាំថ្ងៃ',
        desc: 'កត់ត្រាម៉ោងចូល & ចេញពីការងារ',
        icon: Icons.qr_code_scanner_rounded,
        gradient: const [Color(0xFF059669), Color(0xFF10B981)],
        onTap: () => _handleScanAction(_nextAction),
      ),
      _ActionItem(
        title: 'ស្ទូឌីយោលិខិតសរសើរ A4',
        desc: 'បង្កើត និង Export លិខិតសរសើរ PDF',
        icon: Icons.workspace_premium_rounded,
        gradient: const [Color(0xFFD97706), Color(0xFFF59E0B)],
        badge: 'Studio',
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const CertificateEditorScreen()),
        ),
      ),
      _ActionItem(
        title: 'ស្នើសុំច្បាប់ & បេសកកម្ម',
        desc: 'ដាក់ពាក្យសុំច្បាប់ ឬចេញបំពេញការងារ',
        icon: Icons.assignment_rounded,
        gradient: const [Color(0xFF2563EB), Color(0xFF3B82F6)],
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(
            builder: (_) => user.isHRM ? const RequestListScreen() : const RequestsScreen(),
          ),
        ),
      ),
      _ActionItem(
        title: 'របាយការណ៍វត្តមាន & ស្ថិតិ',
        desc: 'ពិនិត្យតារាងវត្តមានប្រចាំខែ & PDF',
        icon: Icons.assessment_rounded,
        gradient: const [Color(0xFF7C3AED), Color(0xFF8B5CF6)],
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const AttendanceReportScreen()),
        ),
      ),
      _ActionItem(
        title: 'បោះឆ្នោតបុគ្គលិកឆ្នើម',
        desc: 'ចូលរួមបោះឆ្នោតបុគ្គលិកប្រចាំខែ',
        icon: Icons.how_to_vote_rounded,
        gradient: const [Color(0xFFE11D48), Color(0xFFF43F5E)],
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const PollVotingScreen()),
        ),
      ),
      _ActionItem(
        title: 'ជំនួយការ AI Chat Assistant',
        desc: 'សួរសំណួរ HR ច្បាប់ការងារ និងក្រុមហ៊ុន',
        icon: Icons.smart_toy_rounded,
        gradient: const [Color(0xFF0284C7), Color(0xFF0EA5E9)],
        badge: 'AI Gen',
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const AiChatScreen()),
        ),
      ),
      _ActionItem(
        title: 'ស្កេនឯកសារ & Passport',
        desc: 'OCR ស្កេនឯកសារ និងថតរូបកាត់ត',
        icon: Icons.document_scanner_rounded,
        gradient: const [Color(0xFF4F46E5), Color(0xFF6366F1)],
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const DocumentScannerScreen()),
        ),
      ),
      _ActionItem(
        title: user.isHRM ? 'គ្រប់គ្រងបុគ្គលិក (HRM)' : 'កត់ត្រាកិច្ចប្រជុំ & សំឡេង',
        desc: user.isHRM ? 'គ្រប់គ្រងបញ្ជីបុគ្គលិក និងប្រាក់ខែ' : 'កត់ត្រា និង Transcribe សំឡេងប្រជុំ',
        icon: user.isHRM ? Icons.people_alt_rounded : Icons.mic_rounded,
        gradient: user.isHRM
            ? const [Color(0xFF0D9488), Color(0xFF14B8A6)]
            : const [Color(0xFF64748B), Color(0xFF475569)],
        onTap: () => Navigator.push(
          context,
          MaterialPageRoute(
            builder: (_) => user.isHRM ? const UserManagementScreen() : const MeetingsScreen(),
          ),
        ),
      ),
    ];

    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 4,
        crossAxisSpacing: 16,
        mainAxisSpacing: 16,
        childAspectRatio: 1.45,
      ),
      itemCount: actions.length,
      itemBuilder: (context, idx) {
        final item = actions[idx];
        return InkWell(
          onTap: item.onTap,
          borderRadius: BorderRadius.circular(16),
          hoverColor: Colors.white.withValues(alpha: 0.05),
          child: Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF1E293B),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: Colors.white.withValues(alpha: 0.08),
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.2),
                  blurRadius: 10,
                  offset: const Offset(0, 4),
                ),
              ],
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Container(
                      width: 44,
                      height: 44,
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          colors: item.gradient,
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        ),
                        borderRadius: BorderRadius.circular(12),
                        boxShadow: [
                          BoxShadow(
                            color: item.gradient[0].withValues(alpha: 0.4),
                            blurRadius: 8,
                            offset: const Offset(0, 3),
                          ),
                        ],
                      ),
                      child: Center(
                        child: Icon(item.icon, color: Colors.white, size: 22),
                      ),
                    ),
                    if (item.badge != null)
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: const Color(0xFFD4AF37),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(
                          item.badge!,
                          style: GoogleFonts.outfit(
                            color: Colors.black,
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                  ],
                ),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      item.title,
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontSize: 13,
                        fontWeight: FontWeight.bold,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 2),
                    Text(
                      item.desc,
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white54,
                        fontSize: 10.5,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  // ===== 5. Announcements Wide Section =====
  Widget _buildAnnouncementsSection() {
    if (_banners.isEmpty) {
      return Container(
        width: double.infinity,
        padding: const EdgeInsets.all(24),
        decoration: BoxDecoration(
          color: const Color(0xFF1E293B),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
        ),
        child: Center(
          child: Text(
            'មិនមានសេចក្តីជូនដំណឹងថ្មីនៅឡើយទេ 📋',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white54,
              fontSize: 13,
            ),
          ),
        ),
      );
    }

    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: const Color(0xFF1E293B),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
      ),
      child: ListView.separated(
        shrinkWrap: true,
        physics: const NeverScrollableScrollPhysics(),
        itemCount: _banners.length > 3 ? 3 : _banners.length,
        separatorBuilder: (_, __) => Divider(
          color: Colors.white.withValues(alpha: 0.06),
          height: 1,
        ),
        itemBuilder: (context, idx) {
          final banner = _banners[idx];
          final title = banner['title'] ?? 'សេចក្តីជូនដំណឹង';
          final date = banner['created_at'] ?? '';

          return ListTile(
            contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
            leading: Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: const Color(0xFF2563EB).withValues(alpha: 0.2),
                shape: BoxShape.circle,
              ),
              child: const Icon(
                Icons.notifications_rounded,
                color: Color(0xFF60A5FA),
                size: 20,
              ),
            ),
            title: Text(
              title,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 13.5,
                fontWeight: FontWeight.w600,
              ),
            ),
            subtitle: date.isNotEmpty
                ? Text(
                    date,
                    style: GoogleFonts.outfit(
                      color: Colors.white38,
                      fontSize: 11,
                    ),
                  )
                : null,
            trailing: TextButton(
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const AnnouncementsScreen()),
              ),
              child: Text(
                'មើលលម្អិត',
                style: GoogleFonts.kantumruyPro(
                  color: const Color(0xFF60A5FA),
                  fontSize: 12,
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  // ===== 6. Digital Clock & Khmer Calendar Card =====
  Widget _buildDigitalClockKhmerCalendarCard() {
    final String timeStr = DateFormat('HH:mm:ss').format(_currentTime);
    final String dateStr = DateFormat('EEEE, d MMMM yyyy').format(_currentTime);

    return Container(
      padding: const EdgeInsets.all(22),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF1E293B), Color(0xFF0F172A)],
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
        ),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.2),
            blurRadius: 12,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'កាលបរិច្ឆេទ & ពេលវេលា',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white70,
                  fontSize: 12.5,
                  fontWeight: FontWeight.w600,
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: const Color(0xFF10B981).withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.public, color: Color(0xFF10B981), size: 12),
                    const SizedBox(width: 4),
                    Text(
                      'GMT+7',
                      style: GoogleFonts.outfit(
                        color: const Color(0xFF10B981),
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),

          // Digital Big Clock
          Text(
            timeStr,
            style: GoogleFonts.outfit(
              color: Colors.white,
              fontSize: 32,
              fontWeight: FontWeight.w800,
              letterSpacing: 2,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            dateStr,
            style: GoogleFonts.kantumruyPro(
              color: const Color(0xFF93C5FD),
              fontSize: 12.5,
            ),
          ),
          const SizedBox(height: 14),
          Divider(color: Colors.white.withValues(alpha: 0.08)),
          const SizedBox(height: 10),

          // Khmer Buddhist Era Note
          Row(
            children: [
              const Icon(Icons.wb_sunny_rounded, color: Colors.amberAccent, size: 16),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'ពុទ្ធសករាជ ២៥៦៩ — ព្រះរាជាណាចក្រកម្ពុជា',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white60,
                    fontSize: 11,
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // ===== 7. Office GPS & Location Status =====
  Widget _buildOfficeGpsStatusCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF1E293B),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: const Color(0xFF059669).withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(
                  Icons.location_city_rounded,
                  color: Color(0xFF34D399),
                  size: 18,
                ),
              ),
              const SizedBox(width: 10),
              Text(
                'សាខាក្រុមហ៊ុន & ទីតាំងធ្វើការ',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 13,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Text(
            'VVC GROUP HEADQUARTERS',
            style: GoogleFonts.outfit(
              color: Colors.white,
              fontSize: 14,
              fontWeight: FontWeight.bold,
              letterSpacing: 0.8,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            'រាជធានីភ្នំពេញ, ព្រះរាជាណាចក្រកម្ពុជា',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white54,
              fontSize: 11,
            ),
          ),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: const Color(0xFF10B981).withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.check_circle_rounded, color: Color(0xFF10B981), size: 14),
                const SizedBox(width: 6),
                Text(
                  'ប្រព័ន្ធភ្ជាប់ទៅ Server ដំណើរការល្អ',
                  style: GoogleFonts.kantumruyPro(
                    color: const Color(0xFF6EE7B7),
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ===== 8. AI Assistant Quick Query Card =====
  Widget _buildAiAssistantQuickCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF1E1B4B), Color(0xFF0F172A)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: const Color(0xFF6366F1).withValues(alpha: 0.3),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: const Color(0xFF6366F1).withValues(alpha: 0.3),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(
                  Icons.auto_awesome,
                  color: Color(0xFFA5B4FC),
                  size: 18,
                ),
              ),
              const SizedBox(width: 10),
              Text(
                'ជំនួយការឆ្លាតវៃ (AI Assistant)',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 13,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            'សួរព័ត៌មានអំពីច្បាប់ឈប់សម្រាក បទបញ្ជាផ្ទៃក្នុង ឬជំនួយការងារទូទៅ។',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white70,
              fontSize: 11,
              height: 1.4,
            ),
          ),
          const SizedBox(height: 14),
          ElevatedButton.icon(
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const AiChatScreen()),
            ),
            icon: const Icon(Icons.chat_bubble_outline_rounded, size: 16, color: Colors.white),
            label: Text(
              'សន្ទនាជាមួយ AI ឥឡូវនេះ',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 11.5,
                fontWeight: FontWeight.bold,
              ),
            ),
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF4F46E5),
              minimumSize: const Size(double.infinity, 38),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(10),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ActionItem {
  final String title;
  final String desc;
  final IconData icon;
  final List<Color> gradient;
  final String? badge;
  final VoidCallback onTap;

  _ActionItem({
    required this.title,
    required this.desc,
    required this.icon,
    required this.gradient,
    this.badge,
    required this.onTap,
  });
}
