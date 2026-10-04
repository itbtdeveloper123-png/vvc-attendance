import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/cupertino.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:image_picker/image_picker.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import 'badge_holders_screen.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../providers/user_provider.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import '../widgets/responsive_layout.dart';
import '../services/api_service.dart';
import 'home_screen.dart';
import 'login_screen.dart';
import 'face_setup_screen.dart';
import 'package:package_info_plus/package_info_plus.dart';
import '../services/face_recognizer_service.dart';
import '../services/cutout_pro_service.dart';
import '../services/remove_bg_service.dart';

import '../widgets/khmer_lunar_calendar_card.dart';
import 'package:flutter_khmer_chankitec/flutter_khmer_chankitec.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../services/khmer_calendar_notification_service.dart';
import 'authenticator_screen.dart';

class ProfileScreen extends StatefulWidget {
  final String? targetEmployeeId;
  const ProfileScreen({super.key, this.targetEmployeeId});

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  Map<String, dynamic>? _targetUserData;
  bool _isLoading = false;
  final bool _isSwitchingAccount = false;
  Timer? _pollingTimer;
  bool _khmerCalNotificationsEnabled = true;

  @override
  void initState() {
    super.initState();
    _fetchTargetUser();
    _pollingTimer = Timer.periodic(const Duration(seconds: 15), (_) {
      if (mounted) _fetchTargetUserSilently();
    });
    _loadNotificationPreference();
  }

  void _loadNotificationPreference() async {
    final prefs = await SharedPreferences.getInstance();
    if (mounted) {
      setState(() {
        _khmerCalNotificationsEnabled =
            prefs.getBool('khmer_cal_notifications_enabled') ?? true;
      });
    }
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    super.dispose();
  }

  Future<void> _fetchTargetUserSilently() async {
    try {
      final api = ApiService();
      final res = await api.fetchProfile(employeeId: widget.targetEmployeeId);
      if (res['success'] == true && res['user'] != null && mounted) {
        setState(() {
          _targetUserData = res['user'];
        });

        final currentUser = Provider.of<UserProvider>(context, listen: false);
        final bool isMe = widget.targetEmployeeId == null ||
            widget.targetEmployeeId == currentUser.employeeId;
        if (isMe) {
          final serverFaceReg = (res['user']['face_registered'] ?? 0).toString() == '1' ||
              res['user']['face_registered'] == true;
          final localFaceReg = await FaceRecognizerService().isFaceRegistered(currentUser.employeeId ?? '');
          currentUser.setFaceRegistered(serverFaceReg || localFaceReg);
        }
      }
    } catch (_) {}
  }

  Future<void> _fetchTargetUser() async {
    setState(() => _isLoading = true);
    final api = ApiService();
    final res = await api.fetchProfile(employeeId: widget.targetEmployeeId);
    if (res['success'] == true && res['user'] != null) {
      if (mounted) {
        setState(() {
          _targetUserData = res['user'];
          _isLoading = false;
        });

        final currentUser = Provider.of<UserProvider>(context, listen: false);
        final bool isMe = widget.targetEmployeeId == null ||
            widget.targetEmployeeId == currentUser.employeeId;
        if (isMe) {
          final serverFaceReg = (res['user']['face_registered'] ?? 0).toString() == '1' ||
              res['user']['face_registered'] == true;
          final localFaceReg = await FaceRecognizerService().isFaceRegistered(currentUser.employeeId ?? '');
          currentUser.setFaceRegistered(serverFaceReg || localFaceReg);
        }
      }
    } else {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final currentUser = Provider.of<UserProvider>(context);
    final bool isMe =
        widget.targetEmployeeId == null ||
        widget.targetEmployeeId == currentUser.employeeId;

    // Use current user provider if it's me
    final String? displayName = isMe
        ? currentUser.name
        : _targetUserData?['name'];
    final String? displayId = isMe
        ? currentUser.employeeId
        : _targetUserData?['id'];
    final String? displayAvatar = isMe
        ? currentUser.avatarUrl
        : (ApiService.getFullImageUrl(_targetUserData?['avatar']));
    final String? displayType = isMe
        ? currentUser.userType
        : _targetUserData?['role'];
    final String? displayDept = isMe
        ? currentUser.position
        : _targetUserData?['department'];
    final String? displayPos = isMe
        ? currentUser.position
        : _targetUserData?['position'];

    if (_isLoading) {
      return Scaffold(
        backgroundColor: AppTheme.bgSurface,
        body: Center(child: CircularProgressIndicator(color: AppTheme.primary)),
      );
    }

    final bool isDesktopOrTablet =
        Responsive.isDesktop(context) || Responsive.isTablet(context);
    final bool canPop = Navigator.canPop(context);

    if (isDesktopOrTablet) {
      return AppBackgroundShell(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
          physics: const BouncingScrollPhysics(),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (canPop) ...[
                Padding(
                  padding: const EdgeInsets.only(bottom: 16),
                  child: Row(
                    children: [
                      IconButton(
                        icon: Icon(
                          Icons.arrow_back_ios_new_rounded,
                          color: AppTheme.textPrimary,
                        ),
                        onPressed: () => Navigator.pop(context),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        isMe ? "ប្រវត្តិរូបសង្ខេប" : "ព័ត៌មានបុគ្គលិក",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Left Column (380px)
                  SizedBox(
                    width: 380,
                    child: Column(
                      children: [
                        _buildAvatarSection(
                          context,
                          displayName,
                          displayAvatar,
                          displayType,
                          isMe,
                          currentUser,
                        ),
                        const SizedBox(height: 24),
                        _buildInfoCard(
                          displayId,
                          displayName,
                          displayType,
                          displayDept,
                          displayPos,
                        ),
                        const SizedBox(height: 20),
                        _buildBadgeSection(displayId),
                      ],
                    ),
                  ),
                  const SizedBox(width: 24),
                  // Right Column (Expanded)
                  Expanded(
                    child: Column(
                      children: [
                        if (isMe) _buildMenuSection(context, currentUser),
                      ],
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      );
    }

    return DynamicAppBarWrapper(
      title: isMe ? "ប្រវត្តិរូបសង្ខេប" : "ព័ត៌មានបុគ្គលិក",
      leading: canPop
          ? IconButton(
              icon: const Icon(CupertinoIcons.chevron_back),
              onPressed: () => Navigator.pop(context),
            )
          : null,
      body: AppBackgroundShell(
        child: CustomScrollView(
          physics: const BouncingScrollPhysics(),
          slivers: [
            SliverToBoxAdapter(
              child: Padding(
                padding: EdgeInsets.only(
                  top: MediaQuery.paddingOf(context).top + kToolbarHeight + 12,
                  left: 20,
                  right: 20,
                  bottom: 100,
                ),
                child: AnimationLimiter(
                  child: Column(
                    children: AnimationConfiguration.toStaggeredList(
                      duration: const Duration(milliseconds: 600),
                      childAnimationBuilder: (widget) => SlideAnimation(
                        verticalOffset: 50.0,
                        child: FadeInAnimation(child: widget),
                      ),
                      children: [
                        _buildAvatarSection(
                          context,
                          displayName,
                          displayAvatar,
                          displayType,
                          isMe,
                          currentUser,
                        ),
                        const SizedBox(height: 28),
                        _buildInfoCard(
                          displayId,
                          displayName,
                          displayType,
                          displayDept,
                          displayPos,
                        ),
                        const SizedBox(height: 20),
                        _buildBadgeSection(displayId),
                        const SizedBox(height: 20),
                        if (isMe) _buildMenuSection(context, currentUser),
                        const SizedBox(height: 100),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAvatarSection(
    BuildContext context,
    String? name,
    String? avatarUrl,
    String? role,
    bool isMe,
    UserProvider user,
  ) {
    const double frameSize = 118;

    return Column(
      children: [
        // Avatar
        GestureDetector(
          onTap: isMe ? () => _pickImage(context, user) : null,
          child: Stack(
            clipBehavior: Clip.none,
            children: [
              Container(
                width: frameSize,
                height: frameSize,
                padding: const EdgeInsets.all(6),
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: SweepGradient(
                    colors: [
                      Colors.white,
                      AppTheme.primary,
                      AppTheme.primaryLight,
                      AppTheme.accent,
                      Colors.white,
                    ],
                  ),
                  border: Border.all(
                    color: Colors.white.withValues(alpha: 0.8),
                    width: 2,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: AppTheme.primary.withValues(alpha: 0.38),
                      blurRadius: 28,
                      spreadRadius: 3,
                      offset: const Offset(0, 8),
                    ),
                    BoxShadow(
                      color: Colors.black.withValues(alpha: 0.35),
                      blurRadius: 18,
                      offset: const Offset(0, 8),
                    ),
                  ],
                ),
                child: Container(
                  padding: const EdgeInsets.all(3),
                  decoration: BoxDecoration(
                    color: AppTheme.bgDark,
                    shape: BoxShape.circle,
                    border: Border.all(
                      color: AppTheme.primary.withValues(alpha: 0.88),
                      width: 2,
                    ),
                  ),
                  child: ClipOval(
                    child: avatarUrl != null && avatarUrl.isNotEmpty
                        ? Image.network(
                            avatarUrl,
                            fit: BoxFit.cover,
                            errorBuilder: (context, error, stackTrace) =>
                                _buildInitialsAvatar(name),
                          )
                        : _buildInitialsAvatar(name),
                  ),
                ),
              ),
              if (isMe
                  ? user.isVerified
                  : (_targetUserData?['is_verified']?.toString() == '1'))
                Positioned(
                  bottom: 4,
                  right: 4,
                  child: Container(
                    padding: const EdgeInsets.all(3),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      shape: BoxShape.circle,
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.25),
                          blurRadius: 8,
                          offset: const Offset(0, 3),
                        ),
                      ],
                    ),
                    child: const Icon(
                      Icons.verified,
                      color: Colors.blueAccent,
                      size: 22,
                    ),
                  ),
                ),
              if (isMe)
                Positioned(
                  top: 4,
                  right: 4,
                  child: Container(
                    padding: const EdgeInsets.all(7),
                    decoration: BoxDecoration(
                      color: AppTheme.accent,
                      shape: BoxShape.circle,
                      border: Border.all(color: AppTheme.bgDark, width: 3),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.28),
                          blurRadius: 10,
                          offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    child: const Icon(
                      Icons.camera_alt_rounded,
                      color: Colors.white,
                      size: 15,
                    ),
                  ),
                ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              name ?? 'បុគ្គលិក',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 22,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        const SizedBox(height: 14),
        _buildKhmerCalendarMiniCard(context),
      ],
    );
  }

  Widget _buildKhmerCalendarMiniCard(BuildContext context) {
    final user = Provider.of<UserProvider>(context, listen: false);
    final isDark = Theme.of(context).brightness == Brightness.dark || user.isDarkMode;
    final cardBg = isDark ? const Color(0xFF1C1C1E) : Colors.white;
    final cardBorder = isDark ? Colors.white.withValues(alpha: 0.08) : Colors.black.withValues(alpha: 0.06);
    final textPrimary = isDark ? Colors.white : const Color(0xFF1D1D1F);
    final textMuted = isDark ? const Color(0xFF8E8E93) : const Color(0xFF6C6C70);

    return GestureDetector(
      onTap: () => _showKhmerCalendar(context),
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 10),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: cardBg,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: cardBorder, width: 1.0),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.3 : 0.03),
              blurRadius: 10,
              offset: const Offset(0, 3),
            ),
          ],
        ),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: AppTheme.primary.withValues(alpha: isDark ? 0.18 : 0.10),
                shape: BoxShape.circle,
              ),
              child: Icon(
                Icons.calendar_month_rounded,
                color: AppTheme.primary,
                size: 20,
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    "ប្រតិទិនចន្ទគតិខ្មែរ",
                    style: GoogleFonts.kantumruyPro(
                      color: textPrimary,
                      fontWeight: FontWeight.w700,
                      fontSize: 15,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    Chhankitek.now().toString(),
                    style: GoogleFonts.kantumruyPro(
                      color: textMuted,
                      fontSize: 11.5,
                      fontWeight: FontWeight.w400,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            Icon(
              Icons.chevron_right_rounded,
              color: textMuted,
              size: 20,
            ),
          ],
        ),
      ),
    );
  }

  void _showKhmerCalendar(BuildContext context) {
    final user = Provider.of<UserProvider>(context, listen: false);
    final isDark = Theme.of(context).brightness == Brightness.dark || user.isDarkMode;
    final modalBg = isDark ? const Color(0xFF1C1C1E) : Colors.white;
    final borderColor = isDark ? Colors.white.withValues(alpha: 0.1) : Colors.black.withValues(alpha: 0.08);
    final textPrimary = isDark ? Colors.white : const Color(0xFF1D1D1F);

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => Container(
        height: MediaQuery.of(context).size.height * 0.78,
        decoration: BoxDecoration(
          color: modalBg,
          borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
          border: Border.all(color: borderColor, width: 1),
        ),
        child: Column(
          children: [
            const SizedBox(height: 12),
            Container(
              width: 44,
              height: 5,
              decoration: BoxDecoration(
                color: isDark ? Colors.white.withValues(alpha: 0.25) : Colors.black.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(5),
              ),
            ),
            const SizedBox(height: 18),
            Text(
              "ប្រតិទិនខ្មែរ",
              style: GoogleFonts.kantumruyPro(
                color: textPrimary,
                fontSize: 19,
                fontWeight: FontWeight.w700,
              ),
            ),
            const Expanded(
              child: SingleChildScrollView(
                physics: BouncingScrollPhysics(),
                padding: EdgeInsets.symmetric(vertical: 16),
                child: KhmerLunarCalendarCard(isModal: true),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInitialsAvatar(String? name) {
    String initials = 'U';
    if (name != null && name.isNotEmpty) {
      initials = name.substring(0, 1).toUpperCase();
    }
    return Center(
      child: Text(
        initials,
        style: GoogleFonts.inter(
          color: AppTheme.textPrimary,
          fontWeight: FontWeight.w900,
          fontSize: 36,
        ),
      ),
    );
  }

  Widget _buildBadgeSection(String? userId) {
    if (userId == null) return const SizedBox.shrink();
    return StreamBuilder<DocumentSnapshot>(
      stream: FirebaseFirestore.instance
          .collection('users')
          .doc(userId)
          .snapshots(),
      builder: (context, snapshot) {
        final data = snapshot.hasData && snapshot.data!.exists
            ? snapshot.data!.data() as Map<String, dynamic>
            : null;
        final List<dynamic> badges = data != null ? (data['badges'] ?? []) : [];

        // Always add default badges if not already there
        final displayBadges = List.from(badges);
        if (!displayBadges.contains('ACTIVE_MEMBER')) {
          displayBadges.insert(0, 'ACTIVE_MEMBER');
        }
        if (!displayBadges.contains('EARLY_BIRD')) {
          displayBadges.add('EARLY_BIRD');
        }

        final currentUser = Provider.of<UserProvider>(context, listen: false);
        final bool isMe =
            widget.targetEmployeeId == null ||
            widget.targetEmployeeId == currentUser.employeeId;

        // Add Attendance Medals based on Streak from API or Provider
        final int streak =
            _targetUserData?['attendance_streak'] ??
            (isMe ? currentUser.attendanceStreak : 0);

        if (streak >= 30) displayBadges.add('GOLD_MEDAL');
        if (streak >= 15) displayBadges.add('BRONZE_MEDAL');
        if (streak >= 7) displayBadges.add('SILVER_MEDAL');

        // Progress Calculation
        int nextTarget = 7;
        String nextMedal = "មេដាយប្រាក់";
        Color progressColor = Colors.grey.shade400;

        if (streak >= 30) {
          nextTarget = 60; // Next goal after gold
          nextMedal = "Platinum (Soon)";
          progressColor = Colors.cyanAccent;
        } else if (streak >= 15) {
          nextTarget = 30;
          nextMedal = "មេដាយមាស";
          progressColor = Colors.amber;
        } else if (streak >= 7) {
          nextTarget = 15;
          nextMedal = "មេដាយសំរឹទ្ធ";
          progressColor = Colors.deepOrange;
        }

        double progress = (streak / nextTarget).clamp(0.0, 1.0);

        final isDark = Theme.of(context).brightness == Brightness.dark || currentUser.isDarkMode;
        final cardBg = isDark ? const Color(0xFF1C1C1E) : Colors.white;
        final cardBorder = isDark ? const Color(0xFF2C2C2E) : const Color(0xFFE2E8F0);
        final textPrimary = isDark ? Colors.white : const Color(0xFF0F172A);
        final textMuted = isDark ? const Color(0xFF8E8E93) : const Color(0xFF64748B);

        return Container(
          width: double.infinity,
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: cardBg,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
              color: cardBorder,
              width: isDark ? 0.9 : 1.1,
            ),
            boxShadow: [
              BoxShadow(
                color: isDark
                    ? Colors.black.withValues(alpha: 0.35)
                    : const Color(0xFF0F172A).withValues(alpha: 0.04),
                blurRadius: 12,
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
                  Text(
                    "មេដាយកិត្តិយស (Badges)",
                    style: GoogleFonts.kantumruyPro(
                      color: textPrimary,
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                    ),
                  ),
                  if (streak > 0)
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 2,
                      ),
                      decoration: BoxDecoration(
                        color: AppTheme.primary.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        "$streak ថ្ងៃជាប់គ្នា",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.primary,
                          fontSize: 10,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                ],
              ),
              const SizedBox(height: 16),

              // Attendance Streak Progress
              if (streak < 30) ...[
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      "វឌ្ឍនភាពមេដាយបន្ទាប់ ($nextMedal)",
                      style: GoogleFonts.kantumruyPro(
                        color: textMuted,
                        fontSize: 11,
                      ),
                    ),
                    Text(
                      "${(progress * 100).toInt()}%",
                      style: GoogleFonts.inter(
                        color: progressColor,
                        fontWeight: FontWeight.bold,
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                ClipRRect(
                  borderRadius: BorderRadius.circular(10),
                  child: LinearProgressIndicator(
                    value: progress,
                    backgroundColor: textPrimary.withValues(alpha: 0.08),
                    color: progressColor,
                    minHeight: 6,
                  ),
                ),
                const SizedBox(height: 20),
              ],

              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: displayBadges
                    .map((b) => _buildBadgeItem(context, b.toString()))
                    .toList(),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildBadgeItem(BuildContext context, String type) {
    String label = type;
    IconData icon = Icons.star_rounded;
    Color color = Colors.amber;

    if (type == 'QUIZ_MASTER') {
      label = "Quiz Master";
      icon = Icons.emoji_events_rounded;
      color = Colors.orangeAccent;
    } else if (type == 'ACTIVE_MEMBER') {
      label = "សមាជិកសកម្ម";
      icon = Icons.verified_rounded;
      color = Colors.blueAccent;
    } else if (type == 'EARLY_BIRD') {
      label = "Early Bird";
      icon = Icons.wb_twilight_rounded; // New beautiful icon for early arrival
      color = Colors.amber;
    } else if (type == 'GOLD_MEDAL') {
      label = "មេដាយមាស (30 ថ្ងៃ)";
      color = Colors.amber;
    } else if (type == 'SILVER_MEDAL') {
      label = "មេដាយប្រាក់ (1 សប្តាហ៍)";
      color = Colors.grey.shade400;
    } else if (type == 'BRONZE_MEDAL') {
      label = "មេដាយសំរឹទ្ធ (15 ថ្ងៃ)";
      color = Colors.deepOrange;
    }

    String? imageUrl;
    if (type == 'GOLD_MEDAL') {
      imageUrl = "https://cdn-icons-png.flaticon.com/512/11167/11167978.png";
    }
    if (type == 'SILVER_MEDAL') {
      imageUrl = "https://cdn-icons-png.flaticon.com/512/7645/7645294.png";
    }
    if (type == 'BRONZE_MEDAL') {
      imageUrl = "https://cdn-icons-png.flaticon.com/512/7645/7645366.png";
    }

    return GestureDetector(
      onTap: () {
        Navigator.push(
          context,
          MaterialPageRoute(
            builder: (_) =>
                BadgeHoldersScreen(badgeType: type, badgeLabel: label),
          ),
        );
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.1),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withValues(alpha: 0.3)),
          boxShadow: [
            BoxShadow(
              color: color.withValues(alpha: 0.05),
              blurRadius: 10,
              spreadRadius: 0,
            ),
          ],
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (imageUrl != null)
              Image.network(imageUrl, width: 20, height: 20)
            else
              Icon(icon, color: color, size: 18),
            const SizedBox(width: 8),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: color,
                fontWeight: FontWeight.bold,
                fontSize: 12,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoCard(
    String? id,
    String? name,
    String? role,
    String? dept,
    String? pos,
  ) {
    final user = Provider.of<UserProvider>(context, listen: false);
    final isDark = Theme.of(context).brightness == Brightness.dark || user.isDarkMode;
    final cardBg = isDark ? const Color(0xFF1C1C1E) : Colors.white;
    final cardBorder = isDark ? const Color(0xFF2C2C2E) : const Color(0xFFE2E8F0);
    final textPrimary = isDark ? Colors.white : const Color(0xFF0F172A);
    final textMuted = isDark ? const Color(0xFF8E8E93) : const Color(0xFF64748B);
    final dividerColor = isDark ? const Color(0xFF2C2C2E) : const Color(0xFFEEF2F6);

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: cardBg,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: cardBorder, width: isDark ? 0.9 : 1.1),
        boxShadow: [
          BoxShadow(
            color: isDark
                ? Colors.black.withValues(alpha: 0.35)
                : const Color(0xFF0F172A).withValues(alpha: 0.04),
            blurRadius: 12,
            offset: const Offset(0, 3),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            "ព័ត៌មានគណនី",
            style: GoogleFonts.kantumruyPro(
              color: textPrimary,
              fontWeight: FontWeight.bold,
              fontSize: 15,
            ),
          ),
          const SizedBox(height: 16),
          _buildInfoRow(Icons.badge_rounded, "អត្តលេខ", id ?? 'N/A', textPrimary: textPrimary, textMuted: textMuted),
          Divider(color: dividerColor, height: 20),
          _buildInfoRow(Icons.person_rounded, "ឈ្មោះ", name ?? 'N/A', textPrimary: textPrimary, textMuted: textMuted),
          if (dept != null && dept != 'N/A') ...[
            Divider(color: dividerColor, height: 20),
            _buildInfoRow(Icons.account_balance_rounded, "ផ្នែក (Dept)", dept, textPrimary: textPrimary, textMuted: textMuted),
          ],
          if (pos != null && pos != 'N/A') ...[
            Divider(color: dividerColor, height: 20),
            _buildInfoRow(Icons.work_history_rounded, "តួនាទី (Pos)", pos, textPrimary: textPrimary, textMuted: textMuted),
          ],
        ],
      ),
    );
  }

  Widget _buildInfoRow(IconData icon, String label, String value, {Color? textPrimary, Color? textMuted}) {
    return Row(
      children: [
        Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: AppTheme.primary.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, color: AppTheme.primary, size: 18),
        ),
        const SizedBox(width: 12),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: textMuted ?? AppTheme.textMuted,
                fontSize: 11,
              ),
            ),
            Text(
              value,
              style: GoogleFonts.kantumruyPro(
                color: textPrimary ?? AppTheme.textPrimary,
                fontSize: 14,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildMenuSection(BuildContext context, UserProvider user) {
    final isDark = Theme.of(context).brightness == Brightness.dark || user.isDarkMode;
    final cardBg = isDark ? const Color(0xFF1C1C1E) : Colors.white;
    final cardBorder = isDark ? const Color(0xFF2C2C2E) : const Color(0xFFE2E8F0);
    final textPrimary = isDark ? Colors.white : const Color(0xFF0F172A);
    final dividerColor = isDark ? const Color(0xFF2C2C2E) : const Color(0xFFEEF2F6);

    return Container(
      decoration: BoxDecoration(
        color: cardBg,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: cardBorder, width: isDark ? 0.9 : 1.1),
        boxShadow: [
          BoxShadow(
            color: isDark
                ? Colors.black.withValues(alpha: 0.35)
                : const Color(0xFF0F172A).withValues(alpha: 0.04),
            blurRadius: 12,
            offset: const Offset(0, 3),
          ),
        ],
      ),
      child: Column(
        children: [
          if (widget.targetEmployeeId == null) ...[
            _buildMenuItem(
              icon: Icons.face_retouching_natural_rounded,
              label: user.faceRegistered
                  ? "កំណត់ Face ID (បានចុះឈ្មោះ)"
                  : "ចុះឈ្មោះផ្ទៃមុខ (Face Scan)",
              color: AppTheme.success,
              textColor: textPrimary,
              trailingWidget: user.faceRegistered
                  ? Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: AppTheme.success.withAlpha(35),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: AppTheme.success.withAlpha(90)),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.check_circle_rounded, size: 13, color: AppTheme.success),
                          const SizedBox(width: 4),
                          Text(
                            'បានចុះឈ្មោះ',
                            style: GoogleFonts.kantumruyPro(
                              fontSize: 11,
                              color: AppTheme.success,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                    )
                  : null,
              onTap: () async {
                final res = await Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const FaceSetupScreen()),
                );
                if (res == true && mounted) {
                  _fetchTargetUserSilently();
                }
              },
            ),
            Divider(
              color: dividerColor,
              height: 1,
              indent: 16,
              endIndent: 16,
            ),
          ],
          _buildMenuItem(
            icon: Icons.shield_rounded,
            label: "កូដផ្ទៀងផ្ទាត់ 2FA (Authenticator)",
            color: const Color(0xFF0284C7),
            textColor: textPrimary,
            trailingWidget: Icon(
              CupertinoIcons.chevron_right,
              size: 14,
              color: isDark ? const Color(0xFF8E8E93) : Colors.grey,
            ),
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const AuthenticatorScreen()),
              );
            },
          ),
          Divider(
            color: dividerColor,
            height: 1,
            indent: 16,
            endIndent: 16,
          ),
          _buildMenuItem(
            icon: Icons.info_outline_rounded,
            label: "អំពីប្រព័ន្ធ",
            color: AppTheme.info,
            textColor: textPrimary,
            onTap: () => _showAboutDialog(context),
          ),
          Divider(
            color: dividerColor,
            height: 1,
            indent: 16,
            endIndent: 16,
          ),

          _buildMenuItem(
            icon: Icons.person_outline_rounded,
            label: "ប្ដូរគណនី",
            color: AppTheme.primary,
            textColor: textPrimary,
            onTap: () => _showAccountSwitchSheet(context, user),
            trailingWidget: Icon(
              CupertinoIcons.chevron_right,
              size: 14,
              color: isDark ? const Color(0xFF8E8E93) : const Color(0xFF94A3B8),
            ),
          ),
          Divider(
            color: dividerColor,
            height: 1,
            indent: 16,
            endIndent: 16,
          ),
          _buildSwitchMenuItem(
            icon: user.isDarkMode ? CupertinoIcons.moon_fill : CupertinoIcons.sun_max_fill,
            label: "ទម្រង់ងងឹត (Dark Mode)",
            color: const Color(0xFFF3D010),
            textColor: textPrimary,
            value: user.isDarkMode,
            onChanged: (val) async {
              await user.setDarkMode(val);
            },
          ),
          Divider(
            color: dividerColor,
            height: 1,
            indent: 16,
            endIndent: 16,
          ),
          _buildSwitchMenuItem(
            icon: Icons.calendar_month_rounded,
            label: "ជូនដំណឹងថ្ងៃបុណ្យ/ថ្ងៃសីល",
            color: Colors.orange,
            textColor: textPrimary,
            value: _khmerCalNotificationsEnabled,
            onChanged: (val) async {
              setState(() {
                _khmerCalNotificationsEnabled = val;
              });
              final prefs = await SharedPreferences.getInstance();
              await prefs.setBool('khmer_cal_notifications_enabled', val);
              if (val) {
                await KhmerCalendarNotificationService().reschedule();
              } else {
                await KhmerCalendarNotificationService().cancelAll();
              }
            },
          ),
          Divider(
            color: dividerColor,
            height: 1,
            indent: 16,
            endIndent: 16,
          ),
          _buildMenuItem(
            icon: Icons.logout_rounded,
            label: "ចេញពីគណនី",
            color: AppTheme.danger,
            textColor: AppTheme.danger,
            isDestructive: true,
            onTap: () => _confirmLogout(context, user),
          ),
        ],
      ),
    );
  }

  Widget _buildSwitchMenuItem({
    required IconData icon,
    required String label,
    required Color color,
    required bool value,
    required ValueChanged<bool> onChanged,
    Color? textColor,
  }) {
    return ListTile(
      leading: Container(
        width: 38,
        height: 38,
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Icon(icon, color: color, size: 20),
      ),
      title: Text(
        label,
        style: GoogleFonts.kantumruyPro(
          color: textColor ?? AppTheme.textPrimary,
          fontSize: 14,
          fontWeight: FontWeight.w500,
        ),
      ),
      trailing: CupertinoSwitch(
        value: value,
        onChanged: onChanged,
        activeTrackColor: const Color(0xFF34C759),
      ),
    );
  }

  Widget _buildMenuItem({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
    bool isDestructive = false,
    Widget? trailingWidget,
    Color? textColor,
  }) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(16),
        splashColor: color.withValues(alpha: 0.1),
        highlightColor: color.withValues(alpha: 0.05),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          child: Row(
            children: [
              Container(
                width: 38,
                height: 38,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      color.withValues(alpha: 0.2),
                      color.withValues(alpha: 0.08),
                    ],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                    color: color.withValues(alpha: 0.25),
                    width: 1,
                  ),
                ),
                child: Icon(icon, color: color, size: 20),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Text(
                  label,
                  style: GoogleFonts.kantumruyPro(
                    color: isDestructive ? AppTheme.danger : (textColor ?? AppTheme.textPrimary),
                    fontSize: 14,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ),
              trailingWidget ??
                  Icon(
                    CupertinoIcons.chevron_right,
                    size: 14,
                    color: textColor?.withValues(alpha: 0.3) ?? AppTheme.textPrimary.withValues(alpha: 0.25),
                  ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _pickImage(BuildContext context, UserProvider user) async {
    final picker = ImagePicker();
    final pickedFile = await picker.pickImage(
      source: ImageSource.gallery,
      maxWidth: 512,
      maxHeight: 512,
      imageQuality: 85,
    );

    if (pickedFile != null && context.mounted) {
      final isDark = Theme.of(context).brightness == Brightness.dark || user.isDarkMode;
      final modalBg = isDark ? const Color(0xFF1C1C1E) : Colors.white;
      final textPri = isDark ? Colors.white : const Color(0xFF1D1D1F);
      final textMut = isDark ? const Color(0xFF8E8E93) : const Color(0xFF6C6C70);
      final borderColor = isDark ? Colors.white.withValues(alpha: 0.1) : Colors.black.withValues(alpha: 0.08);

      final choice = await showModalBottomSheet<String>(
        context: context,
        backgroundColor: Colors.transparent,
        builder: (ctx) => Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: modalBg,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
            border: Border.all(color: borderColor),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: isDark ? Colors.white.withValues(alpha: 0.25) : Colors.black.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'ជម្រើសរូបភាព Profile',
                style: GoogleFonts.kantumruyPro(
                  color: textPri,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 16),
              ListTile(
                leading: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(colors: [Color(0xFF6366F1), Color(0xFF8B5CF6)]),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: const Icon(CupertinoIcons.sparkles, color: Colors.white, size: 20),
                ),
                title: Text('✨ កាត់ Background ដោយ AI (Remove.bg)', style: GoogleFonts.kantumruyPro(color: textPri, fontWeight: FontWeight.bold)),
                subtitle: Text('កាត់ផ្ទៃខាងក្រោយឱ្យថ្លា ស្អាតកម្រិត Studio HD', style: GoogleFonts.kantumruyPro(color: textMut, fontSize: 12)),
                onTap: () => Navigator.pop(ctx, 'ai_remove_bg'),
              ),
              Divider(color: borderColor),
              ListTile(
                leading: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: isDark ? const Color(0xFF2C2C2E) : const Color(0xFFF1F5F9),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Icon(CupertinoIcons.photo, color: textMut, size: 20),
                ),
                title: Text('រក្សារូបភាពដើម (Original Photo)', style: GoogleFonts.kantumruyPro(color: textPri)),
                subtitle: Text('ប្រើរូបភាពដើមទាំងស្រុងដោយមិនកាត់', style: GoogleFonts.kantumruyPro(color: textMut, fontSize: 12)),
                onTap: () => Navigator.pop(ctx, 'original'),
              ),
              const SizedBox(height: 10),
            ],
          ),
        ),
      );

      if (choice == null || !context.mounted) return;

      showDialog(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => Center(
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
            decoration: BoxDecoration(
              color: modalBg,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: borderColor),
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                CircularProgressIndicator(color: AppTheme.primary),
                const SizedBox(height: 14),
                Text(
                  choice == 'ai_remove_bg' ? 'កំពុងកាត់ Background ដោយ AI...' : 'កំពុងរក្សាទុករូបភាព...',
                  style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 13),
                ),
              ],
            ),
          ),
        ),
      );

      try {
        Uint8List bytes = await pickedFile.readAsBytes();

        if (choice == 'ai_remove_bg') {
          Uint8List? cutoutBytes;
          try {
            final rmbgService = RemoveBgService();
            cutoutBytes = await rmbgService.removeBackgroundBytes(bytes, bgColor: 'transparent', size: 'preview');
          } catch (_) {}

          if (cutoutBytes == null || cutoutBytes.isEmpty) {
            try {
              final cutoutService = CutoutProService();
              cutoutBytes = await cutoutService.removeBackgroundBytes(bytes);
            } catch (_) {}
          }

          if (cutoutBytes != null && cutoutBytes.isNotEmpty) {
            bytes = cutoutBytes;
          }
        }

        final base64Image = base64Encode(bytes);
        final success = await user.updateAvatar(base64Image);

        if (context.mounted) {
          Navigator.pop(context); // Close loading dialog
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                success ? "ប្តូររូបភាព Profile ជោគជ័យ!" : "បរាជ័យក្នុងការប្តូររូបភាព",
                style: GoogleFonts.kantumruyPro(),
              ),
              backgroundColor: success ? AppTheme.success : AppTheme.danger,
            ),
          );
        }
      } catch (e) {
        if (context.mounted) {
          Navigator.pop(context); // Close loading dialog
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text("មានបញ្ហា: $e", style: GoogleFonts.kantumruyPro()),
              backgroundColor: AppTheme.danger,
            ),
          );
        }
      }
    }
  }

  Future<void> _showAccountSwitchSheet(
    BuildContext context,
    UserProvider user,
  ) async {
    final accounts = await user.getRecentAccounts();
    if (!context.mounted) return;

    final currentId = user.employeeId?.toString() ?? '';
    final currentName = user.name ?? 'គណនីបច្ចុប្បន្នក្នុងប្រព័ន្ធ';
    final currentAvatar = user.avatarUrl ?? '';
    final otherAccounts = accounts
        .where((account) =>
            account['employeeId']?.toString() != currentId &&
            account['employeeId']?.toString().isNotEmpty == true)
        .toList();

    final isDark = Theme.of(context).brightness == Brightness.dark || user.isDarkMode;
    final sheetBg = isDark ? const Color(0xFF1C1C1E) : Colors.white;
    final sheetBorder = isDark ? Colors.white.withValues(alpha: 0.1) : Colors.black.withValues(alpha: 0.08);

    final itemBg = isDark ? const Color(0xFF2C2C2E) : const Color(0xFFF8FAFC);
    final itemBorder = isDark ? Colors.white.withValues(alpha: 0.08) : Colors.black.withValues(alpha: 0.06);
    final textPri = isDark ? Colors.white : const Color(0xFF1D1D1F);
    final textSec = isDark ? const Color(0xFF8E8E93) : const Color(0xFF64748B);

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: sheetBg,
      shape: RoundedRectangleBorder(
        borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
        side: BorderSide(
          color: sheetBorder,
          width: 1.0,
        ),
      ),
      builder: (ctx) {
        return SafeArea(
          child: SingleChildScrollView(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 20),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Center(
                    child: Container(
                      width: 40,
                      height: 4,
                      decoration: BoxDecoration(
                        color: isDark ? Colors.white.withValues(alpha: 0.25) : Colors.black.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(2),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'ជ្រើសគណនីដើម្បីប្ដូរ',
                    style: GoogleFonts.kantumruyPro(
                      color: textPri,
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 14),
                  Text(
                    'គណនីបច្ចុប្បន្ន',
                    style: GoogleFonts.kantumruyPro(
                      color: textSec,
                      fontSize: 12,
                    ),
                  ),
                  const SizedBox(height: 10),
                  ListTile(
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(18),
                      side: BorderSide(
                        color: AppTheme.primary.withValues(alpha: 0.35),
                        width: 1.2,
                      ),
                    ),
                    tileColor: itemBg,
                    leading: CircleAvatar(
                      radius: 24,
                      backgroundColor: AppTheme.primary.withValues(alpha: 0.15),
                      backgroundImage: currentAvatar.isNotEmpty
                          ? NetworkImage(currentAvatar)
                              as ImageProvider<Object>?
                          : null,
                      child: currentAvatar.isEmpty
                          ? Text(
                              currentName
                                  .trim()
                                  .split(RegExp(r'\s+'))
                                  .where((part) => part.isNotEmpty)
                                  .take(2)
                                  .map((part) => part[0].toUpperCase())
                                  .join(),
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.primary,
                                fontWeight: FontWeight.bold,
                              ),
                            )
                          : null,
                    ),
                    title: Text(
                      currentName,
                      style: GoogleFonts.kantumruyPro(
                        color: textPri,
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    subtitle: Text(
                      currentId.isNotEmpty ? currentId : 'N/A',
                      style: GoogleFonts.kantumruyPro(
                        color: textSec,
                        fontSize: 12,
                      ),
                    ),
                    trailing: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: AppTheme.primary.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Text(
                        'បច្ចុប្បន្ន',
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.primary,
                          fontSize: 11.5,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 18),
                  if (otherAccounts.isNotEmpty) ...[
                    Text(
                      'គណនីចុងក្រោយ',
                      style: GoogleFonts.kantumruyPro(
                        color: textSec,
                        fontSize: 12,
                      ),
                    ),
                    const SizedBox(height: 10),
                    Column(
                      children: otherAccounts.map((account) {
                        final id = account['employeeId']?.toString() ?? '';
                        final name = account['name']?.toString() ?? id;
                        final avatarUrl = account['avatar']?.toString() ?? '';
                        final userType = account['userType']?.toString() ?? 'Employee';

                        return Padding(
                          padding: const EdgeInsets.symmetric(vertical: 6),
                          child: ListTile(
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(18),
                              side: BorderSide(
                                color: itemBorder,
                              ),
                            ),
                            tileColor: itemBg,
                            leading: CircleAvatar(
                              radius: 22,
                              backgroundColor: AppTheme.primary.withValues(alpha: 0.18),
                              backgroundImage: avatarUrl.isNotEmpty
                                  ? NetworkImage(avatarUrl)
                                      as ImageProvider<Object>?
                                  : null,
                              child: avatarUrl.isEmpty
                                  ? Text(
                                      name
                                          .trim()
                                          .split(RegExp(r'\s+'))
                                          .where((part) => part.isNotEmpty)
                                          .take(2)
                                          .map((part) => part[0].toUpperCase())
                                          .join(),
                                      style: GoogleFonts.kantumruyPro(
                                        color: AppTheme.primary,
                                        fontWeight: FontWeight.bold,
                                      ),
                                    )
                                  : null,
                            ),
                            title: Text(
                              name,
                              style: GoogleFonts.kantumruyPro(
                                color: textPri,
                                fontSize: 14,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            subtitle: Text(
                              id,
                              style: GoogleFonts.kantumruyPro(
                                color: textSec,
                                fontSize: 12,
                              ),
                            ),
                            onTap: () async {
                              if (_isSwitchingAccount) return;
                              Navigator.of(ctx).pop();
                              
                              if (context.mounted) {
                                showDialog(
                                  context: context,
                                  barrierDismissible: false,
                                  builder: (_) => Center(
                                    child: CircularProgressIndicator(color: AppTheme.primary),
                                  ),
                                );
                              }

                              final result = await user.login(id, userType);

                              if (context.mounted) {
                                Navigator.of(context, rootNavigator: true).pop();
                              }

                              if (!context.mounted) return;

                              if (result['success'] == true) {
                                Navigator.of(context).pushAndRemoveUntil(
                                  MaterialPageRoute(
                                    builder: (_) => const HomeScreen(),
                                  ),
                                  (_) => false,
                                );
                              } else {
                                ScaffoldMessenger.of(context).showSnackBar(
                                  SnackBar(
                                    content: Text(
                                      result['message'] ?? 'ការប្ដូរការចូលបរាជ័យ',
                                      style: GoogleFonts.kantumruyPro(),
                                    ),
                                    backgroundColor: Colors.redAccent,
                                    behavior: SnackBarBehavior.floating,
                                  ),
                                );
                              }
                            },
                          ),
                        );
                      }).toList(),
                    ),
                  ] else ...[
                    Center(
                      child: Text(
                        'មិនមានគណនីចុងក្រោយផ្សេងទៀតទេ',
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textSecondary,
                          fontSize: 12,
                        ),
                      ),
                    ),
                    const SizedBox(height: 18),
                  ],
                  ElevatedButton(
                    onPressed: () {
                      Navigator.of(ctx).pop();
                      Navigator.of(context).push(
                        MaterialPageRoute(builder: (_) => const LoginScreen()),
                      );
                    },
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppTheme.primary,
                      foregroundColor: Colors.white,
                      minimumSize: const Size.fromHeight(48),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(16),
                      ),
                    ),
                    child: Text(
                      'បន្ថែមគណនីថ្មី',
                      style: GoogleFonts.kantumruyPro(
                        fontSize: 14,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  void _showAboutDialog(BuildContext context) async {
    final PackageInfo packageInfo = await PackageInfo.fromPlatform();
    final String version = packageInfo.version;
    final String buildNumber = packageInfo.buildNumber;
    final currentYear = DateTime.now().year;

    if (!context.mounted) return;

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Text(
          "VVC HRM",
          style: GoogleFonts.inter(
            color: AppTheme.textPrimary,
            fontWeight: FontWeight.bold,
          ),
          textAlign: TextAlign.center,
        ),
        content: Text(
          "កម្មវិធីគ្រប់គ្រងវត្តមានបុគ្គលិក-HRM\nBY IT OF VVC © $currentYear\nVersion $version+$buildNumber",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textSecondary,
            fontSize: 14,
          ),
          textAlign: TextAlign.center,
        ),
        actions: [
          Center(
            child: TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: Text(
                "យល់ព្រម",
                style: GoogleFonts.kantumruyPro(color: AppTheme.primary),
              ),
            ),
          ),
        ],
      ),
    );
  }

  void _confirmLogout(BuildContext context, UserProvider user) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Text(
          "ចេញពីគណនី?",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontWeight: FontWeight.bold,
          ),
        ),
        content: Text(
          "តើអ្នកប្រាកដជាចង់ចេញពីគណនីមែនទេ?",
          style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text(
              "បោះបង់",
              style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted),
            ),
          ),
          ElevatedButton(
            onPressed: () async {
              await user.logout();
              if (context.mounted) {
                Navigator.of(context).pushAndRemoveUntil(
                  MaterialPageRoute(builder: (_) => const LoginScreen()),
                  (_) => false,
                );
              }
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.danger,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: Text(
              "ចេញ",
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
