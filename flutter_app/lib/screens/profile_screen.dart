import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:image_picker/image_picker.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import 'badge_holders_screen.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../providers/user_provider.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import '../services/api_service.dart';
import 'login_screen.dart';
import 'package:package_info_plus/package_info_plus.dart';
import '../widgets/khmer_lunar_calendar_card.dart';
import 'package:flutter_khmer_chankitec/flutter_khmer_chankitec.dart';

class ProfileScreen extends StatefulWidget {
  final String? targetEmployeeId;
  const ProfileScreen({super.key, this.targetEmployeeId});

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  Map<String, dynamic>? _targetUserData;
  bool _isLoading = false;
  Timer? _pollingTimer;

  @override
  void initState() {
    super.initState();
    _fetchTargetUser();
    _pollingTimer = Timer.periodic(const Duration(seconds: 15), (_) {
      if (mounted) _fetchTargetUserSilently();
    });
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
      }
    } catch (_) {}
  }

  Future<void> _fetchTargetUser() async {
    setState(() => _isLoading = true);
    final api = ApiService();
    final res = await api.fetchProfile(employeeId: widget.targetEmployeeId);
    if (res['success'] == true && res['user'] != null) {
      setState(() {
        _targetUserData = res['user'];
        _isLoading = false;
      });
    } else {
      setState(() => _isLoading = false);
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
        backgroundColor: AppTheme.bgDark,
        body: Center(child: CircularProgressIndicator(color: AppTheme.primary)),
      );
    }

    return DynamicAppBarWrapper(
      title: isMe ? "ប្រវត្តិរូបសង្ខេប" : "ព័ត៌មានបុគ្គលិក",
      body: AppBackgroundShell(
        child: CustomScrollView(
          physics: const BouncingScrollPhysics(),
          slivers: [
            SliverToBoxAdapter(
              child: SafeArea(
                bottom: false,
                child: Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 20,
                    vertical: 10,
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
    return GestureDetector(
      onTap: () => _showKhmerCalendar(context),
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 10),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: AppTheme.textPrimary.withValues(alpha: 0.08),
          ),
        ),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: AppTheme.primary.withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: Icon(
                Icons.calendar_month_rounded,
                color: AppTheme.primaryLight,
                size: 20,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    "ប្រតិទិនចន្ទគតិខ្មែរ",
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary,
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                    ),
                  ),
                  Text(
                    Chhankitek.now().toString(),
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textMuted,
                      fontSize: 11,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            Icon(
              Icons.arrow_forward_ios_rounded,
              color: AppTheme.textMuted,
              size: 14,
            ),
          ],
        ),
      ),
    );
  }

  void _showKhmerCalendar(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => Container(
        height: MediaQuery.of(context).size.height * 0.75,
        decoration: BoxDecoration(
          color: AppTheme.bgDark,
          borderRadius: const BorderRadius.vertical(top: Radius.circular(30)),
        ),
        child: Column(
          children: [
            const SizedBox(height: 12),
            Container(
              width: 50,
              height: 5,
              decoration: BoxDecoration(
                color: AppTheme.textMuted.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(5),
              ),
            ),
            const SizedBox(height: 20),
            Text(
              "ប្រតិទិនខ្មែរ",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 20,
                fontWeight: FontWeight.bold,
              ),
            ),
            const Expanded(
              child: SingleChildScrollView(
                padding: EdgeInsets.symmetric(vertical: 20),
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

        return Container(
          width: double.infinity,
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
              color: AppTheme.textPrimary.withValues(alpha: 0.07),
            ),
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
                      color: AppTheme.textPrimary,
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
                          color: AppTheme.primaryLight,
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
                        color: AppTheme.textMuted,
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
                    backgroundColor: AppTheme.textPrimary.withValues(
                      alpha: 0.05,
                    ),
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
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.07)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            "ព័ត៌មានគណនី",
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary,
              fontWeight: FontWeight.bold,
              fontSize: 15,
            ),
          ),
          const SizedBox(height: 16),
          _buildInfoRow(Icons.badge_rounded, "អត្តលេខ", id ?? 'N/A'),
          Divider(
            color: AppTheme.textPrimary.withValues(alpha: 0.12),
            height: 20,
          ),
          _buildInfoRow(Icons.person_rounded, "ឈ្មោះ", name ?? 'N/A'),
          if (dept != null && dept != 'N/A') ...[
            Divider(
              color: AppTheme.textPrimary.withValues(alpha: 0.12),
              height: 20,
            ),
            _buildInfoRow(Icons.account_balance_rounded, "ផ្នែក (Dept)", dept),
          ],
          if (pos != null && pos != 'N/A') ...[
            Divider(
              color: AppTheme.textPrimary.withValues(alpha: 0.12),
              height: 20,
            ),
            _buildInfoRow(Icons.work_history_rounded, "តួនាទី (Pos)", pos),
          ],
        ],
      ),
    );
  }

  Widget _buildInfoRow(IconData icon, String label, String value) {
    return Row(
      children: [
        Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: AppTheme.primary.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, color: AppTheme.primaryLight, size: 18),
        ),
        const SizedBox(width: 12),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textMuted,
                fontSize: 11,
              ),
            ),
            Text(
              value,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
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
    return Container(
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.07)),
      ),
      child: Column(
        children: [
          _buildMenuItem(
            icon: Icons.info_outline_rounded,
            label: "អំពីប្រព័ន្ធ",
            color: AppTheme.info,
            onTap: () => _showAboutDialog(context),
          ),
          Divider(
            color: AppTheme.textPrimary.withValues(alpha: 0.12),
            height: 1,
            indent: 16,
            endIndent: 16,
          ),
          _buildMenuItem(
            icon: Icons.logout_rounded,
            label: "ចេញពីគណនី",
            color: AppTheme.danger,
            isDestructive: true,
            onTap: () => _confirmLogout(context, user),
          ),
        ],
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
  }) {
    return ListTile(
      onTap: onTap,
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
          color: isDestructive ? AppTheme.danger : AppTheme.textPrimary,
          fontSize: 14,
          fontWeight: FontWeight.w500,
        ),
      ),
      trailing:
          trailingWidget ??
          Icon(
            Icons.arrow_forward_ios_rounded,
            size: 14,
            color: AppTheme.textPrimary.withValues(alpha: 0.25),
          ),
    );
  }

  Future<void> _pickImage(BuildContext context, UserProvider user) async {
    final picker = ImagePicker();
    final pickedFile = await picker.pickImage(
      source: ImageSource.gallery,
      maxWidth: 512,
      maxHeight: 512,
      imageQuality: 80,
    );

    if (pickedFile != null) {
      if (!context.mounted) return;

      showDialog(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => Center(
          child: Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(15),
            ),
            child: CircularProgressIndicator(color: AppTheme.primary),
          ),
        ),
      );

      try {
        final bytes = await pickedFile.readAsBytes();
        final base64Image = base64Encode(bytes);
        final success = await user.updateAvatar(base64Image);

        if (context.mounted) {
          Navigator.pop(context); // Close loading dialog
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                success
                    ? "ប្តូររូបភាព Profile ជោគជ័យ"
                    : "បរាជ័យក្នុងការប្តូររូបភាព",
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
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
