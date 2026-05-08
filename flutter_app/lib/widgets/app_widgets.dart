import 'package:flutter/material.dart';
import 'dart:async';
import 'package:google_fonts/google_fonts.dart';
import 'package:shimmer/shimmer.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';

/// A reusable flat background shell for app screens.
class AppBackgroundShell extends StatelessWidget {
  final Widget child;
  final bool showGlows;

  const AppBackgroundShell({
    super.key,
    required this.child,
    this.showGlows = true,
  });

  @override
  Widget build(BuildContext context) {
    return ColoredBox(color: AppTheme.bgSurface, child: child);
  }
}

// ===== SHIMMER HELPER =====
class AppShimmer extends StatelessWidget {
  final Widget child;
  final bool enabled;

  const AppShimmer({super.key, required this.child, this.enabled = true});

  @override
  Widget build(BuildContext context) {
    if (!enabled) return child;
    return Shimmer.fromColors(
      baseColor: AppTheme.bgCard,
      highlightColor: AppTheme.bgCardLight.withValues(alpha: 0.5),
      child: child,
    );
  }
}

class AppShimmerBox extends StatelessWidget {
  final double width;
  final double height;
  final double borderRadius;

  const AppShimmerBox({
    super.key,
    required this.width,
    required this.height,
    this.borderRadius = 8,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: width,
      height: height,
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(borderRadius),
      ),
    );
  }
}

// ===== STATS CARD =====
class AppStatCard extends StatelessWidget {
  final String title;
  final String label;
  final String value;
  final IconData icon;
  final Color color;
  final bool isLoading;

  const AppStatCard({
    super.key,
    this.title = '',
    required this.label,
    required this.value,
    required this.icon,
    this.color = const Color(0xFF6366F1), // Default to primary
    this.isLoading = false,
  });

  @override
  Widget build(BuildContext context) {
    return AppShimmer(
      enabled: isLoading,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(24),
          border: Border.all(color: color.withValues(alpha: 0.2), width: 1.5),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: Icon(icon, color: color, size: 20),
            ),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (isLoading)
                  const AppShimmerBox(width: 60, height: 28)
                else
                  Text(
                    value,
                    style: GoogleFonts.inter(
                      color: AppTheme.textPrimary,
                      fontSize: 28,
                      fontWeight: FontWeight.w900,
                    ),
                  ),
                const SizedBox(height: 4),
                if (isLoading)
                  const AppShimmerBox(width: 80, height: 12)
                else
                  Text(
                    label,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary,
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

// ===== GRID ACTION =====
class AppGridAction extends StatelessWidget {
  final String title;
  final String label;
  final IconData icon;
  final Color color;
  final VoidCallback onTap;

  const AppGridAction({
    super.key,
    this.title = '',
    required this.label,
    required this.icon,
    this.color = const Color(0xFF6366F1), // Default to primary
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 0),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: AppTheme.borderColor.withValues(alpha: 0.6),
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.03),
              blurRadius: 10,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: Icon(icon, color: color, size: 24),
            ),
            const SizedBox(height: 8),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 12,
                fontWeight: FontWeight.w600,
                height: 1.2,
              ),
              textAlign: TextAlign.center,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
      ),
    );
  }
}

// ===== SECTION HEADER =====
class SectionHeader extends StatelessWidget {
  final String title;
  final VoidCallback? onSeeAll;

  const SectionHeader({super.key, required this.title, this.onSeeAll});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          title,
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontSize: 18,
            fontWeight: FontWeight.bold,
          ),
        ),
        if (onSeeAll != null)
          TextButton(
            onPressed: onSeeAll,
            child: Text(
              "មើលទាំងអស់",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.primaryLight,
                fontSize: 13,
              ),
            ),
          ),
      ],
    );
  }
}

// ===== ATTENDANCE SCAN CARD =====
class AttendanceScanCard extends StatelessWidget {
  final String nextAction;
  final VoidCallback onCheckIn;
  final VoidCallback onCheckOut;
  final VoidCallback? onTap;
  final VoidCallback? onHistoryTap;
  final bool isLoading;
  final DateTime? checkInTime; // Feature #1: live timer
  final String liveWorkDuration; // Feature #1: HH:mm:ss string

  const AttendanceScanCard({
    super.key,
    required this.nextAction,
    required this.onCheckIn,
    required this.onCheckOut,
    this.onTap,
    this.onHistoryTap,
    this.isLoading = false,
    this.checkInTime,
    this.liveWorkDuration = '',
  });

  @override
  Widget build(BuildContext context) {
    bool isCheckIn = nextAction == 'Check-In';
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(28),
          border: Border.all(color: AppTheme.borderColor),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.08),
              blurRadius: 20,
              offset: const Offset(0, 10),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: AppTheme.primary.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(
                    Icons.qr_code_scanner_rounded,
                    color: AppTheme.primary,
                    size: 24,
                  ),
                ),
                const SizedBox(width: 15),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        "ស្កេនវត្តមាន",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Text(
                        "បន្ទាប់: $nextAction",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.primaryLight,
                          fontSize: 13,
                        ),
                      ),
                    ],
                  ),
                ),
                if (onHistoryTap != null)
                  InkWell(
                    onTap: onHistoryTap,
                    borderRadius: BorderRadius.circular(12),
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 6,
                      ),
                      decoration: BoxDecoration(
                        color: AppTheme.primary.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                          color: AppTheme.primary.withValues(alpha: 0.2),
                        ),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            Icons.history_rounded,
                            color: AppTheme.primaryLight,
                            size: 16,
                          ),
                          const SizedBox(width: 6),
                          Text(
                            "ប្រវត្តិ",
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.primaryLight,
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
              ],
            ),
            // Feature #1: Live work timer (shown when checked in)
            if (liveWorkDuration.isNotEmpty) ...[
              const SizedBox(height: 10),
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 14,
                  vertical: 8,
                ),
                decoration: BoxDecoration(
                  color: Colors.greenAccent.withValues(alpha: 0.08),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                    color: Colors.greenAccent.withValues(alpha: 0.25),
                  ),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(
                      Icons.timer_outlined,
                      color: Colors.greenAccent,
                      size: 14,
                    ),
                    const SizedBox(width: 6),
                    Text(
                      'ម៉ោងធ្វើការ: $liveWorkDuration',
                      style: GoogleFonts.inter(
                        color: Colors.greenAccent,
                        fontSize: 12,
                        fontWeight: FontWeight.w700,
                        fontFeatures: [const FontFeature.tabularFigures()],
                      ),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 24),
            Row(
              children: [
                Expanded(
                  child: _buildButton(
                    context: context,
                    label: "Check-In",
                    icon: Icons.login_rounded,
                    color: Colors.cyanAccent.shade700,
                    isActive: isCheckIn,
                    onTap: onCheckIn,
                    primaryStyle: true,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: _buildButton(
                    context: context,
                    label: "Check-Out",
                    icon: Icons.logout_rounded,
                    color: Colors.deepOrangeAccent.shade200,
                    isActive: !isCheckIn,
                    onTap: onCheckOut,
                    primaryStyle: false,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildButton({
    required BuildContext context,
    required String label,
    required IconData icon,
    required Color color,
    required bool isActive,
    required VoidCallback onTap,
    required bool primaryStyle,
  }) {
    final Color btnColor = isActive
        ? color
        : AppTheme.textPrimary.withValues(alpha: 0.05);

    return GestureDetector(
      onTap: isLoading ? null : onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 300),
        height: 54,
        decoration: BoxDecoration(
          color: btnColor.withValues(
            alpha: primaryStyle && isActive ? 0.9 : 0.1,
          ),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: isActive
                ? btnColor.withValues(alpha: 0.5)
                : AppTheme.borderColor,
            width: 1.5,
          ),
        ),
        child: Stack(
          alignment: Alignment.center,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(
                  icon,
                  color: isActive
                      ? (primaryStyle ? Colors.white : color)
                      : AppTheme.textMuted,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  label,
                  style: GoogleFonts.kantumruyPro(
                    color: isActive
                        ? (primaryStyle ? Colors.white : color)
                        : AppTheme.textMuted,
                    fontWeight: FontWeight.bold,
                    fontSize: 15,
                  ),
                ),
              ],
            ),
            if (isLoading)
              const SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: Colors.white,
                ),
              ),
          ],
        ),
      ),
    );
  }
}

// ===== QUICK ACTION BUTTON =====
class AppActionButton extends StatelessWidget {
  final String title;
  final String subtitle;
  final IconData icon;
  final Color iconColor;
  final VoidCallback onTap;
  final bool isHighlighted;

  const AppActionButton({
    super.key,
    required this.title,
    required this.subtitle,
    required this.icon,
    required this.iconColor,
    required this.onTap,
    this.isHighlighted = false,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: isHighlighted
              ? iconColor.withValues(alpha: 0.15)
              : AppTheme.bgCard,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(
            color: isHighlighted
                ? iconColor.withValues(alpha: 0.35)
                : AppTheme.borderColor,
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.05),
              blurRadius: 10,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Row(
          children: [
            Container(
              width: 48,
              height: 48,
              decoration: BoxDecoration(
                color: iconColor.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(14),
              ),
              child: Icon(icon, color: iconColor, size: 24),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary,
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    subtitle,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textSecondary,
                      fontSize: 12,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            Icon(
              Icons.arrow_forward_ios_rounded,
              color: AppTheme.textMuted.withValues(alpha: 0.3),
              size: 14,
            ),
          ],
        ),
      ),
    );
  }
}

// ===== DYNAMIC PREMIUM APP BAR =====
class DynamicPremiumAppBar extends StatefulWidget
    implements PreferredSizeWidget {
  final String title;
  final List<Widget>? actions;
  final Widget? leading;
  final bool centerTitle;

  const DynamicPremiumAppBar({
    super.key,
    required this.title,
    this.actions,
    this.leading,
    this.centerTitle = true,
  });

  @override
  State<DynamicPremiumAppBar> createState() => _DynamicPremiumAppBarState();

  @override
  Size get preferredSize => const Size.fromHeight(kToolbarHeight);
}

class _DynamicPremiumAppBarState extends State<DynamicPremiumAppBar> {
  @override
  Widget build(BuildContext context) {
    return AppBar(
      title: Text(
        widget.title,
        style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
      ),
      centerTitle: widget.centerTitle,
      leading: widget.leading,
      actions: widget.actions,
      backgroundColor: AppTheme.bgDark.withValues(alpha: 0.95),
      elevation: 0,
    );
  }
}

// A wrapper for screens to handle the dynamic app bar state
class DynamicAppBarWrapper extends StatefulWidget {
  final String title;
  final List<Widget>? actions;
  final Widget? leading;
  final Widget body;

  const DynamicAppBarWrapper({
    super.key,
    required this.title,
    required this.body,
    this.actions,
    this.leading,
  });

  @override
  State<DynamicAppBarWrapper> createState() => _DynamicAppBarWrapperState();
}

class _DynamicAppBarWrapperState extends State<DynamicAppBarWrapper> {
  bool _isScrolling = false;
  Timer? _scrollTimer;

  @override
  void dispose() {
    _scrollTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        title: Text(
          widget.title,
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        backgroundColor: Colors.transparent,
        elevation: 0,
        centerTitle: true,
        leading: widget.leading,
        actions: widget.actions,
        flexibleSpace: AnimatedContainer(
          duration: const Duration(milliseconds: 250),
          decoration: BoxDecoration(
            color: _isScrolling
                ? AppTheme.bgDark.withValues(alpha: 0.3)
                : AppTheme.bgDark.withValues(alpha: 0.98),
            border: Border(
              bottom: BorderSide(
                color: _isScrolling
                    ? Colors.transparent
                    : AppTheme.textPrimary.withValues(alpha: 0.05),
                width: 1,
              ),
            ),
          ),
        ),
      ),
      body: NotificationListener<ScrollNotification>(
        onNotification: (notification) {
          if (notification is ScrollStartNotification) {
            setState(() => _isScrolling = true);
            _scrollTimer?.cancel();
          } else if (notification is ScrollUpdateNotification) {
            _scrollTimer?.cancel();
            _scrollTimer = Timer(const Duration(milliseconds: 150), () {
              if (mounted) setState(() => _isScrolling = false);
            });
          } else if (notification is ScrollEndNotification) {
            _scrollTimer?.cancel();
            if (mounted) setState(() => _isScrolling = false);
          }
          return false;
        },
        child: widget.body,
      ),
    );
  }
}

class AppWidgets {
  static void showSnackBar(
    BuildContext context,
    String message, {
    bool isError = false,
  }) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          message,
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14),
        ),
        backgroundColor: isError ? Colors.redAccent : AppTheme.success,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        duration: const Duration(seconds: 3),
      ),
    );
  }
}

// ===== GLOBAL USER UI COMPONENTS =====

/// Static cache for Firebase Presence streams so they aren't recreated
class AppPresenceCache {
  static final Map<String, Stream<DocumentSnapshot>> streams = {};
}

class AppUserAvatar extends StatelessWidget {
  final String? url;
  final String name;
  final double size;

  const AppUserAvatar({
    super.key,
    this.url,
    required this.name,
    this.size = 64,
  });

  @override
  Widget build(BuildContext context) {
    final placeholder = Center(
      child: Text(
        name.isNotEmpty ? name[0].toUpperCase() : '?',
        style: TextStyle(
          color: AppTheme.primary,
          fontSize: size * 0.4,
          fontWeight: FontWeight.bold,
        ),
      ),
    );

    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: AppTheme.primary.withValues(alpha: 0.2),
        border: Border.all(
          color: AppTheme.primary.withValues(alpha: 0.3),
          width: 2,
        ),
      ),
      child: url != null && url!.isNotEmpty
          ? ClipOval(
              child: Image.network(
                url!,
                fit: BoxFit.cover,
                errorBuilder: (context, error, stackTrace) => placeholder,
              ),
            )
          : placeholder,
    );
  }
}

class AppOnlineStatusBadge extends StatelessWidget {
  final String employeeId;

  const AppOnlineStatusBadge({super.key, required this.employeeId});

  @override
  Widget build(BuildContext context) {
    if (!AppPresenceCache.streams.containsKey(employeeId)) {
      AppPresenceCache.streams[employeeId] = FirebaseFirestore.instance
          .collection('users')
          .doc(employeeId)
          .snapshots();
    }
    return StreamBuilder<DocumentSnapshot>(
      stream: AppPresenceCache.streams[employeeId],
      builder: (context, snapshot) {
        Widget defaultOffline = Container(
          width: 14,
          height: 14,
          decoration: BoxDecoration(
            color: const Color(0xFF4A4A5A),
            shape: BoxShape.circle,
            border: Border.all(color: AppTheme.bgCard, width: 2),
          ),
        );

        if (!snapshot.hasData || !snapshot.data!.exists) {
          return defaultOffline;
        }

        final data = snapshot.data!.data() as Map<String, dynamic>?;
        if (data == null) return defaultOffline;

        final bool isOnline = data['isOnline'] == true;
        if (isOnline) {
          return Container(
            width: 14,
            height: 14,
            decoration: BoxDecoration(
              color: Colors.greenAccent,
              shape: BoxShape.circle,
              border: Border.all(color: AppTheme.bgCard, width: 2),
            ),
          );
        }

        final Timestamp? lastActive = data['lastActive'];
        if (lastActive == null) return defaultOffline;

        final DateTime lastTime = lastActive.toDate();
        final Duration diff = DateTime.now().difference(lastTime);
        String label = '';
        if (diff.inMinutes < 1) {
          label = '1m';
        } else if (diff.inMinutes < 60) {
          label = '${diff.inMinutes}m';
        } else if (diff.inHours < 24) {
          label = '${diff.inHours}h';
        } else {
          label = '${diff.inDays}d';
        }

        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
          decoration: BoxDecoration(
            color: const Color(0xFF4A4A5A),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: AppTheme.bgCard, width: 2.5),
          ),
          child: Text(
            label,
            style: const TextStyle(
              color: Colors.white,
              fontSize: 9,
              fontWeight: FontWeight.bold,
              height: 1,
            ),
          ),
        );
      },
    );
  }
}

class AppUserBadges extends StatelessWidget {
  final List<dynamic>? badges;

  const AppUserBadges({super.key, this.badges});

  @override
  Widget build(BuildContext context) {
    if (badges == null || badges!.isEmpty) return const SizedBox.shrink();

    return Wrap(
      spacing: 6,
      runSpacing: 6,
      alignment: WrapAlignment.center,
      children: badges!.map((badge) {
        String label = '';
        IconData icon = Icons.star;
        Color color = Colors.amber;

        if (badge == 'QUIZ_MASTER') {
          label = 'Quiz Master';
          icon = Icons.psychology_rounded;
          color = Colors.orangeAccent;
        } else if (badge == 'EARLY_BIRD') {
          label = 'Early Bird';
          icon = Icons.alarm_on_rounded;
          color = Colors.lightBlueAccent;
        } else if (badge == 'ZERO_ABSENCE') {
          label = 'Stellar Attendance';
          icon = Icons.shield_rounded;
          color = Colors.greenAccent;
        } else {
          return const SizedBox.shrink();
        }

        return Tooltip(
          message: label,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: color.withValues(alpha: 0.3), width: 1),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(icon, size: 12, color: color),
                const SizedBox(width: 4),
                Text(
                  label,
                  style: GoogleFonts.inter(
                    color: color,
                    fontSize: 9,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
          ),
        );
      }).toList(),
    );
  }
}

class AppUserListTile extends StatelessWidget {
  final Map<String, dynamic> user;
  final int index;
  final VoidCallback? onTap;
  final Widget? trailingAction;

  const AppUserListTile({
    super.key,
    required this.user,
    required this.index,
    this.onTap,
    this.trailingAction,
  });

  @override
  Widget build(BuildContext context) {
    final roleStr = (user['system_role_label'] ?? user['system_role'] ?? '')
        .toString()
        .trim();
    final rawAvatar = user['avatar'];
    final avatarUrl = ApiService.getFullImageUrl(rawAvatar?.toString() ?? '');
    final finalAvatarUrl = avatarUrl.isNotEmpty ? avatarUrl : null;
    final posStr = (user['position'] ?? '').toString().trim();

    return AnimationConfiguration.staggeredList(
      position: index,
      duration: const Duration(milliseconds: 400),
      child: SlideAnimation(
        verticalOffset: 20.0,
        child: FadeInAnimation(
          child: GestureDetector(
            onTap: onTap,
            child: Container(
              margin: const EdgeInsets.only(bottom: 12),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.08),
                    blurRadius: 8,
                    offset: const Offset(0, 4),
                  ),
                ],
              ),
              child: Row(
                children: [
                  Stack(
                    clipBehavior: Clip.none,
                    alignment: Alignment.center,
                    children: [
                      AppUserAvatar(
                        url: finalAvatarUrl,
                        name: user['name'] ?? '',
                        size: 56,
                      ),
                      Positioned(
                        bottom: -4,
                        right: -4,
                        child: AppOnlineStatusBadge(
                          employeeId: user['employee_id'].toString(),
                        ),
                      ),
                      if (user['is_verified']?.toString() == '1')
                        Positioned(
                          bottom: -4,
                          left: -4,
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
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          user['name'] ?? 'N/A',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: 16,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Row(
                          children: [
                            if (posStr.isNotEmpty)
                              Flexible(
                                child: Text(
                                  posStr,
                                  style: TextStyle(
                                    color: AppTheme.textPrimary.withValues(
                                      alpha: 0.7,
                                    ),
                                    fontSize: 12,
                                    fontWeight: FontWeight.w500,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            if (posStr.isNotEmpty)
                              Padding(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 6,
                                ),
                                child: Icon(
                                  Icons.circle,
                                  size: 4,
                                  color: Colors.white.withValues(alpha: 0.2),
                                ),
                              ),
                            Text(
                              "ID: ${user['employee_id']}",
                              style: TextStyle(
                                color: Colors.white.withValues(alpha: 0.4),
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  if (roleStr.isNotEmpty &&
                      roleStr.toLowerCase() != 'employee') ...[
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 6,
                      ),
                      decoration: BoxDecoration(
                        color: AppTheme.primary.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        roleStr,
                        style: GoogleFonts.inter(
                          color: AppTheme.primaryLight,
                          fontSize: 11,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ],
                  if (user['badges'] != null &&
                      (user['badges'] as List).isNotEmpty) ...[
                    const SizedBox(width: 8),
                    AppUserBadges(badges: user['badges'] as List<dynamic>?),
                  ],
                  ?trailingAction,
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class AppUserCard extends StatelessWidget {
  final Map<String, dynamic> user;
  final int index;
  final VoidCallback? onTap;
  final Widget? trailingAction;

  const AppUserCard({
    super.key,
    required this.user,
    required this.index,
    this.onTap,
    this.trailingAction,
  });

  @override
  Widget build(BuildContext context) {
    final roleStr = (user['system_role_label'] ?? user['system_role'] ?? '')
        .toString()
        .trim();
    final rawAvatar = user['avatar'];
    final avatarUrl = ApiService.getFullImageUrl(rawAvatar?.toString() ?? '');
    final finalAvatarUrl = avatarUrl.isNotEmpty ? avatarUrl : null;
    final posStr = (user['position'] ?? '').toString().trim();

    return AnimationConfiguration.staggeredGrid(
      position: index,
      columnCount: 2,
      duration: const Duration(milliseconds: 500),
      child: SlideAnimation(
        verticalOffset: 50.0,
        child: FadeInAnimation(
          child: GestureDetector(
            onTap: onTap,
            child: Container(
              padding: const EdgeInsets.fromLTRB(10, 16, 10, 16),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: BorderRadius.circular(24),
                border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.1),
                    blurRadius: 10,
                    offset: const Offset(0, 4),
                  ),
                ],
              ),
              child: Stack(
                clipBehavior: Clip.none,
                children: [
                  if (trailingAction != null)
                    Positioned(top: -16, right: -16, child: trailingAction!),
                  SizedBox(
                    width: double.infinity,
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      crossAxisAlignment: CrossAxisAlignment.center,
                      children: [
                        const SizedBox(height: 8),
                        Stack(
                          clipBehavior: Clip.none,
                          alignment: Alignment.center,
                          children: [
                            AppUserAvatar(
                              url: finalAvatarUrl,
                              name: user['name'] ?? '',
                              size: 70,
                            ),
                            Positioned(
                              bottom: -4,
                              child: AppOnlineStatusBadge(
                                employeeId: user['employee_id'].toString(),
                              ),
                            ),
                            if (user['is_verified']?.toString() == '1')
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
                                    size: 16,
                                  ),
                                ),
                              ),
                          ],
                        ),
                        const SizedBox(height: 16),
                        Text(
                          user['name'] ?? 'N/A',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: 15,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          textAlign: TextAlign.center,
                        ),
                        if (posStr.isNotEmpty) ...[
                          const SizedBox(height: 4),
                          Text(
                            posStr.toUpperCase(),
                            style: TextStyle(
                              color: AppTheme.primaryLight.withValues(
                                alpha: 0.8,
                              ),
                              fontSize: 10,
                              letterSpacing: 0.5,
                              fontWeight: FontWeight.w600,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            textAlign: TextAlign.center,
                          ),
                        ],
                        if (roleStr.isNotEmpty &&
                            roleStr.toLowerCase() != 'employee') ...[
                          const SizedBox(height: 10),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 4,
                            ),
                            decoration: BoxDecoration(
                              color: AppTheme.primary.withValues(alpha: 0.15),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              roleStr,
                              style: GoogleFonts.inter(
                                color: AppTheme.primaryLight,
                                fontSize: 10,
                                fontWeight: FontWeight.bold,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              textAlign: TextAlign.center,
                            ),
                          ),
                        ],
                        if (user['badges'] != null &&
                            (user['badges'] as List).isNotEmpty) ...[
                          const SizedBox(height: 10),
                          AppUserBadges(
                            badges: user['badges'] as List<dynamic>?,
                          ),
                        ],
                        const SizedBox(height: 12),
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 10,
                            vertical: 4,
                          ),
                          decoration: BoxDecoration(
                            color: Colors.white.withValues(alpha: 0.05),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: Text(
                            "ID: ${user['employee_id']}",
                            style: TextStyle(
                              color: Colors.white.withValues(alpha: 0.5),
                              fontSize: 12,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
