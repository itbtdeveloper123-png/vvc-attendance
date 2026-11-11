import 'dart:async';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import 'package:intl/intl.dart';
import '../services/api_service.dart';
import '../models/notification_model.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import '../widgets/responsive_layout.dart';
import 'notification_detail_screen.dart';

class NotificationScreen extends StatefulWidget {
  const NotificationScreen({super.key});

  @override
  State<NotificationScreen> createState() => _NotificationScreenState();
}

class _NotificationScreenState extends State<NotificationScreen> {
  final ApiService _apiService = ApiService();
  final _searchController = TextEditingController();
  List<NotificationModel> _notifications = [];
  bool _isLoading = true;
  bool _isScrolled = false;
  String? _error;
  String _filter = 'all'; // 'all', 'unread', 'read'
  Timer? _pollingTimer;

  @override
  void initState() {
    super.initState();
    _fetchNotifications();
    _searchController.addListener(() {
      if (mounted) setState(() {});
    });

    // Auto polling every 30 seconds
    _pollingTimer = Timer.periodic(const Duration(seconds: 30), (timer) {
      if (mounted) {
        _fetchNotificationsSilently();
      }
    });
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    _searchController.dispose();
    super.dispose();
  }

  int get _unreadCount => _notifications.where((n) => !n.isRead).length;

  List<NotificationModel> get _visibleNotifications {
    final q = _searchController.text.trim().toLowerCase();
    return _notifications.where((notification) {
      final matchesFilter = _filter == 'all' ||
          (_filter == 'unread' && !notification.isRead) ||
          (_filter == 'read' && notification.isRead);
      final matchesSearch = q.isEmpty ||
          notification.title.toLowerCase().contains(q) ||
          notification.message.toLowerCase().contains(q) ||
          notification.type.toLowerCase().contains(q);
      return matchesFilter && matchesSearch;
    }).toList();
  }

  Future<void> _fetchNotifications() async {
    if (!mounted) return;
    setState(() {
      _isLoading = true;
      _error = null;
    });

    try {
      final result = await _apiService.getNotifications();
      if (result['success'] == true || result['status'] == 'success') {
        final List<dynamic> data =
            result['data'] ?? result['notifications'] ?? [];
        if (!mounted) return;
        setState(() {
          _notifications =
              data.map((item) => NotificationModel.fromJson(item)).toList();

          // Sort: Unread (isRead == false) first, then by sentAt descending
          _notifications.sort((a, b) {
            if (a.isRead != b.isRead) {
              return a.isRead ? 1 : -1;
            }
            return b.sentAt.compareTo(a.sentAt);
          });

          _isLoading = false;
        });
      } else {
        if (!mounted) return;
        setState(() {
          _error = result['message'] ?? 'Failed to load notifications';
          _isLoading = false;
        });
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = 'Error: $e';
        _isLoading = false;
      });
    }
  }

  Future<void> _fetchNotificationsSilently() async {
    try {
      final result = await _apiService.getNotifications();
      if (result['success'] == true || result['status'] == 'success') {
        final List<dynamic> data =
            result['data'] ?? result['notifications'] ?? [];
        if (!mounted) return;
        setState(() {
          _notifications =
              data.map((item) => NotificationModel.fromJson(item)).toList();

          _notifications.sort((a, b) {
            if (a.isRead != b.isRead) {
              return a.isRead ? 1 : -1;
            }
            return b.sentAt.compareTo(a.sentAt);
          });
        });
      }
    } catch (e) {
      debugPrint("Silent notification refresh failed: $e");
    }
  }

  Future<void> _markAsRead(int notificationId) async {
    try {
      await _apiService.markNotificationAsRead(notificationId);
      setState(() {
        final index = _notifications.indexWhere((n) => n.id == notificationId);
        if (index != -1) {
          _notifications[index] = NotificationModel(
            id: _notifications[index].id,
            title: _notifications[index].title,
            message: _notifications[index].message,
            sentAt: _notifications[index].sentAt,
            isRead: true,
            type: _notifications[index].type,
            targetId: _notifications[index].targetId,
            imageUrl: _notifications[index].imageUrl,
          );

          _notifications.sort((a, b) {
            if (a.isRead != b.isRead) {
              return a.isRead ? 1 : -1;
            }
            return b.sentAt.compareTo(a.sentAt);
          });
        }
      });
    } catch (e) {
      debugPrint("Error marking notification as read: $e");
    }
  }

  String _formatTimestamp(String? raw) {
    if (raw == null || raw.isEmpty) return '';
    try {
      final dt = DateTime.parse(raw).toLocal();
      final now = DateTime.now();
      final diff = now.difference(dt);

      if (diff.inMinutes < 1) {
        return 'ទើបតែឥឡូវ';
      } else if (diff.inMinutes < 60) {
        return '${diff.inMinutes} នាទីមុន';
      } else if (diff.inHours < 24 && dt.day == now.day) {
        return DateFormat('hh:mm a').format(dt);
      } else if (diff.inDays == 1 || (diff.inHours < 48 && dt.day == now.day - 1)) {
        return 'ម្សិលមិញ';
      } else if (diff.inDays < 7) {
        return '${diff.inDays} ថ្ងៃមុន';
      } else {
        return DateFormat('dd/MM/yy').format(dt);
      }
    } catch (_) {
      return raw;
    }
  }

  @override
  Widget build(BuildContext context) {
    final topPadding = MediaQuery.paddingOf(context).top;
    final headerTotalHeight = topPadding + 6 + 44 + 10 + 42 + 8 + 36 + 10;
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return VvcLiquidGlassScaffold(
      showHeader: true,
      showTopTransitionZone: true,
      topTransitionZoneHeight: headerTotalHeight,
      backgroundColor: isDark ? const Color(0xFF000000) : const Color(0xFFF8FAFC),
      onScrollChanged: (scrolled) {
        if (scrolled != _isScrolled) {
          setState(() => _isScrolled = scrolled);
        }
      },
      customHeaderBuilder: (context, isScrolled) => Positioned(
        top: 0,
        left: 0,
        right: 0,
        child: SafeArea(
          bottom: false,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 6),
              _buildHeaderPods(context),
              const SizedBox(height: 10),
              _buildSearchBar(),
              const SizedBox(height: 8),
              _buildSegmentedFilterSlider(),
              const SizedBox(height: 10),
            ],
          ),
        ),
      ),
      body: _isLoading
          ? _buildShimmerList(topPadding: headerTotalHeight)
          : _error != null
              ? _buildErrorState(topPadding: headerTotalHeight)
              : RefreshIndicator(
                  onRefresh: _fetchNotifications,
                  color: const Color(0xFFF3D010),
                  edgeOffset: headerTotalHeight + 8.0,
                  displacement: 28.0,
                  child: _visibleNotifications.isEmpty
                      ? _buildEmptyState(topPadding: headerTotalHeight)
                      : _buildList(_visibleNotifications, topPadding: headerTotalHeight),
                ),
    );
  }

  // ===========================================================================
  // 1. DYNAMIC FROSTED HEADER PODS (UNIFIED DESIGN SYSTEM)
  // ===========================================================================
  Widget _buildHeaderPods(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final textPrimary = isDark ? Colors.white : const Color(0xFF0F172A);

    return VvcHeaderPodBar(
      isScrolled: _isScrolled,
      leading: VvcCirclePod.back(
        context,
        size: AppTokens.sizePodLarge,
        onBack: () => Navigator.maybePop(context),
      ),
      titleWidget: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Flexible(
            child: Text(
              'ការជូនដំណឹង',
              style: GoogleFonts.kantumruyPro(
                color: textPrimary,
                fontSize: 15,
                fontWeight: FontWeight.bold,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2.5),
            decoration: BoxDecoration(
              color: _unreadCount > 0
                  ? AppTokens.gold.withValues(alpha: isDark ? 0.22 : 0.25)
                  : (isDark ? Colors.white.withValues(alpha: 0.12) : Colors.black.withValues(alpha: 0.06)),
              borderRadius: BorderRadius.circular(AppTokens.radiusPill),
              border: _unreadCount > 0
                  ? Border.all(
                      color: AppTokens.gold.withValues(alpha: 0.5),
                      width: 0.8,
                    )
                  : null,
            ),
            child: Text(
              _unreadCount > 0 ? '$_unreadCount ថ្មី' : '${_notifications.length}',
              style: GoogleFonts.inter(
                color: _unreadCount > 0
                    ? (isDark ? AppTokens.gold : const Color(0xFFB45309))
                    : (isDark ? Colors.white70 : const Color(0xFF64748B)),
                fontSize: 10.5,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
      actions: [
        VvcCirclePod.refresh(
          size: AppTokens.sizePodLarge,
          onRefresh: _fetchNotifications,
        ),
      ],
    );
  }

  // ===========================================================================
  // 2. SLEEK FROSTED SEARCH BAR (UNIFIED DESIGN SYSTEM)
  // ===========================================================================
  Widget _buildSearchBar() {
    return VvcSearchBar(
      controller: _searchController,
      hintText: 'ស្វែងរកការជូនដំណឹង...',
      isScrolled: _isScrolled,
      onClear: () {
        if (mounted) setState(() {});
      },
    );
  }

  // ===========================================================================
  // 3. FLUID HORIZONTAL TELEGRAM-STYLE CATEGORY FILTER PILLS
  // ===========================================================================
  Widget _buildSegmentedFilterSlider() {
    return VvcFilterChips(
      selectedKey: _filter,
      onSelected: (key) => setState(() => _filter = key),
      items: [
        VvcFilterItem(key: 'all', label: 'ទាំងអស់', count: _notifications.length),
        VvcFilterItem(key: 'unread', label: 'មិនទាន់អាន', count: _unreadCount),
        VvcFilterItem(key: 'read', label: 'បានអាន', count: _notifications.length - _unreadCount),
      ],
    );
  }

  // ===========================================================================
  // 4. LIST & SHIMMER VIEWS
  // ===========================================================================
  Widget _buildList(List<NotificationModel> notifications, {required double topPadding}) {
    if (Responsive.isDesktop(context) || Responsive.isTablet(context)) {
      return GridView.builder(
        padding: EdgeInsets.fromLTRB(24, topPadding + 6, 24, 24),
        physics: const BouncingScrollPhysics(),
        gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: MediaQuery.of(context).size.width > 1200 ? 3 : 2,
          childAspectRatio: 2.3,
          crossAxisSpacing: 16,
          mainAxisSpacing: 16,
        ),
        itemCount: notifications.length,
        itemBuilder: (context, index) => _buildNotificationCard(notifications[index]),
      );
    }

    final hPad = AppResponsive.horizontalPadding(context);
    return AnimationLimiter(
      child: ListView.builder(
        padding: EdgeInsets.fromLTRB(
          hPad,
          topPadding + 6,
          hPad,
          AppResponsive.bottomPadding(context),
        ),
        physics: const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics()),
        itemCount: notifications.length,
        itemBuilder: (context, index) {
          final notification = notifications[index];
          return AnimationConfiguration.staggeredList(
            position: index,
            duration: const Duration(milliseconds: 400),
            child: SlideAnimation(
              verticalOffset: 30.0,
              child: FadeInAnimation(
                child: AppResponsive.maxWidth(
                  context: context,
                  child: _buildNotificationCard(notification),
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  // ===========================================================================
  // 5. PREMIUM NOTIFICATION CARD COMPONENT
  // ===========================================================================
  Widget _buildNotificationCard(NotificationModel notification) {
    final hasImage = notification.imageUrl != null && notification.imageUrl!.isNotEmpty;
    final isDark = Theme.of(context).brightness == Brightness.dark;

    final cardBg = isDark
        ? (notification.isRead
            ? const Color(0xFF1C1C1E).withValues(alpha: 0.70)
            : const Color(0xFF1C1C1E))
        : (notification.isRead
            ? Colors.white.withValues(alpha: 0.85)
            : Colors.white);

    final cardBorder = isDark
        ? (notification.isRead
            ? Colors.white.withValues(alpha: 0.08)
            : const Color(0xFFFFCC00).withValues(alpha: 0.35))
        : (notification.isRead
            ? const Color(0xFFE2E8F0)
            : const Color(0xFFFFCC00).withValues(alpha: 0.50));

    final titleColor = isDark ? Colors.white : const Color(0xFF0F172A);
    final messageColor = isDark ? Colors.white.withValues(alpha: 0.70) : const Color(0xFF475569);
    final timeColor = isDark ? Colors.white.withValues(alpha: 0.38) : const Color(0xFF94A3B8);

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: cardBg,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: cardBorder,
          width: 0.8,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.25 : 0.04),
            blurRadius: 10,
            offset: const Offset(0, 3),
          ),
          if (!notification.isRead)
            BoxShadow(
              color: const Color(0xFFFFCC00).withValues(alpha: isDark ? 0.08 : 0.12),
              blurRadius: 12,
              offset: const Offset(0, 2),
            ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: () {
            HapticFeedback.lightImpact();
            _markAsRead(notification.id);
            showModalBottomSheet(
              context: context,
              isScrollControlled: true,
              backgroundColor: Colors.transparent,
              enableDrag: true,
              builder: (context) => NotificationDetailSheet(notification: notification),
            );
          },
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header Row: Bell Icon Pod + Title + Timestamp & Unread Dot
              Padding(
                padding: const EdgeInsets.fromLTRB(14, 14, 14, 10),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Bell Icon Pod (36x36)
                    Container(
                      width: 36,
                      height: 36,
                      decoration: BoxDecoration(
                        color: const Color(0xFFFFCC00).withValues(alpha: isDark ? 0.15 : 0.18),
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: const Color(0xFFFFCC00).withValues(alpha: 0.35),
                          width: 0.8,
                        ),
                        boxShadow: [
                          BoxShadow(
                            color: const Color(0xFFFFCC00).withValues(alpha: 0.20),
                            blurRadius: 8,
                          ),
                        ],
                      ),
                      child: const Center(
                        child: Icon(
                          CupertinoIcons.bell_fill,
                          color: Color(0xFFFFCC00),
                          size: 18,
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),

                    // Title and Message
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            crossAxisAlignment: CrossAxisAlignment.center,
                            children: [
                              Expanded(
                                child: Text(
                                  notification.title,
                                  style: GoogleFonts.kantumruyPro(
                                    color: titleColor,
                                    fontSize: 15,
                                    fontWeight: notification.isRead
                                        ? FontWeight.w600
                                        : FontWeight.bold,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              const SizedBox(width: 8),
                              // Subtle Timestamp
                              Text(
                                _formatTimestamp(notification.sentAt),
                                style: GoogleFonts.inter(
                                  color: timeColor,
                                  fontSize: 11,
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                              if (!notification.isRead) ...[
                                const SizedBox(width: 6),
                                Container(
                                  width: 7,
                                  height: 7,
                                  decoration: const BoxDecoration(
                                    color: Color(0xFFFFCC00),
                                    shape: BoxShape.circle,
                                    boxShadow: [
                                      BoxShadow(
                                        color: Color(0xFFFFCC00),
                                        blurRadius: 4,
                                      ),
                                    ],
                                  ),
                                ),
                              ],
                            ],
                          ),
                          const SizedBox(height: 4),
                          Text(
                            notification.message,
                            style: GoogleFonts.kantumruyPro(
                              color: messageColor,
                              fontSize: 13,
                              height: 1.35,
                            ),
                            maxLines: 3,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),

              // Framed Media Attachment (if present)
              if (hasImage)
                Padding(
                  padding: const EdgeInsets.fromLTRB(14, 0, 14, 14),
                  child: GestureDetector(
                    onTap: () {
                      HapticFeedback.lightImpact();
                      _viewFullImage(notification.imageUrl!);
                    },
                    child: Container(
                      constraints: const BoxConstraints(maxHeight: 180),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                          color: Colors.white.withValues(alpha: 0.10),
                          width: 0.8,
                        ),
                      ),
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(12),
                        child: Image.network(
                          notification.imageUrl!,
                          height: 180,
                          width: double.infinity,
                          fit: BoxFit.cover,
                          loadingBuilder: (context, child, loadingProgress) {
                            if (loadingProgress == null) return child;
                            return Container(
                              height: 140,
                              color: const Color(0xFF2C2C2E),
                              child: const Center(
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Color(0xFFFFCC00),
                                ),
                              ),
                            );
                          },
                          errorBuilder: (context, error, stackTrace) => Container(
                            height: 50,
                            width: double.infinity,
                            decoration: BoxDecoration(
                              color: Colors.red.withValues(alpha: 0.08),
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: const Center(
                              child: Icon(CupertinoIcons.photo, color: Colors.grey, size: 20),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildShimmerList({required double topPadding}) {
    final hPad = AppResponsive.horizontalPadding(context);
    return ListView.builder(
      padding: EdgeInsets.fromLTRB(hPad, topPadding + 6, hPad, 24),
      itemCount: 6,
      itemBuilder: (context, index) => Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: AppShimmer(
          child: Container(
            height: 85,
            decoration: BoxDecoration(
              color: const Color(0xFF1C1C1E),
              borderRadius: BorderRadius.circular(16),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildErrorState({required double topPadding}) {
    return SingleChildScrollView(
      physics: const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics()),
      padding: EdgeInsets.only(top: topPadding / 2),
      child: AppStateView(
        icon: Icons.error_outline_rounded,
        title: "មានបញ្ហាក្នុងការទាញទិន្នន័យ",
        message: _error ?? '',
        color: AppTheme.error,
        actionLabel: "ព្យាយាមម្តងទៀត",
        onAction: _fetchNotifications,
      ),
    );
  }

  Widget _buildEmptyState({double topPadding = 0}) {
    final isFiltered = _searchController.text.trim().isNotEmpty || _filter != 'all';

    return VvcEmptyState(
      icon: isFiltered ? CupertinoIcons.search : CupertinoIcons.bell_slash,
      title: isFiltered
          ? (_filter == 'unread'
              ? "គ្មានការជូនដំណឹងមិនទាន់អានទេ"
              : "រកមិនឃើញការជូនដំណឹង")
          : "មិនទាន់មានការជូនដំណឹងទេ",
      subtitle: isFiltered
          ? (_filter == 'unread'
              ? "អ្នកបានអានការជូនដំណឹងទាំងអស់រួចរាល់ហើយ"
              : "សាកល្បងប្តូរពាក្យស្វែងរក ឬ Filter ផ្សេងទៀត")
          : "ការជូនដំណឹងថ្មីៗនឹងបង្ហាញនៅទីនេះ",
      buttonLabel: isFiltered ? 'បង្ហាញការជូនដំណឹងទាំងអស់ (${_notifications.length})' : null,
      buttonIcon: isFiltered ? CupertinoIcons.list_bullet : null,
      onButtonTap: isFiltered
          ? () {
              AppTokens.hapticLight();
              setState(() {
                _filter = 'all';
                _searchController.clear();
              });
            }
          : null,
      topPadding: topPadding,
    );
  }

  void _viewFullImage(String url) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => Scaffold(
          backgroundColor: Colors.black,
          appBar: AppBar(
            backgroundColor: Colors.transparent,
            elevation: 0,
            leading: IconButton(
              icon: const Icon(CupertinoIcons.chevron_back, color: Colors.white),
              onPressed: () => Navigator.pop(context),
            ),
          ),
          body: Center(child: InteractiveViewer(child: Image.network(url))),
        ),
      ),
    );
  }
}
