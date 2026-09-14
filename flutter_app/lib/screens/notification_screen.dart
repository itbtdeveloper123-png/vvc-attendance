import 'dart:async';
import 'dart:ui' as ui;
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
                  color: const Color(0xFFFFCC00),
                  edgeOffset: headerTotalHeight,
                  child: _visibleNotifications.isEmpty
                      ? _buildEmptyState(topPadding: headerTotalHeight)
                      : _buildList(_visibleNotifications, topPadding: headerTotalHeight),
                ),
    );
  }

  // ===========================================================================
  // 1. DYNAMIC FROSTED HEADER PODS (3 ISLANDS)
  // ===========================================================================
  Widget _buildHeaderPods(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 14),
      child: Row(
        children: [
          // Left Pod: 44x44 circular frosted glass back button
          ClipRRect(
            borderRadius: BorderRadius.circular(22),
            child: BackdropFilter(
              filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 250),
                curve: Curves.easeInOutCubic,
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  color: _isScrolled
                      ? const Color(0xFF24272E).withValues(alpha: 0.94)
                      : const Color(0xFF1C1C1E).withValues(alpha: 0.65),
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: _isScrolled
                        ? Colors.white.withValues(alpha: 0.22)
                        : Colors.white.withValues(alpha: 0.10),
                    width: 1.0,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: _isScrolled ? 0.55 : 0.15),
                      blurRadius: _isScrolled ? 16 : 4,
                      offset: Offset(0, _isScrolled ? 4 : 2),
                    ),
                  ],
                ),
                child: Material(
                  color: Colors.transparent,
                  child: InkWell(
                    borderRadius: BorderRadius.circular(22),
                    onTap: () {
                      HapticFeedback.lightImpact();
                      Navigator.maybePop(context);
                    },
                    child: const Center(
                      child: Icon(
                        CupertinoIcons.chevron_back,
                        color: Colors.white,
                        size: 20,
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(width: 10),

          // Center Pod: Title "ការជូនដំណឹង" with counter capsule
          Expanded(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(22),
              child: BackdropFilter(
                filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 250),
                  curve: Curves.easeInOutCubic,
                  height: 44,
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  decoration: BoxDecoration(
                    color: _isScrolled
                        ? const Color(0xFF24272E).withValues(alpha: 0.94)
                        : const Color(0xFF1C1C1E).withValues(alpha: 0.65),
                    borderRadius: BorderRadius.circular(22),
                    border: Border.all(
                      color: _isScrolled
                          ? Colors.white.withValues(alpha: 0.22)
                          : Colors.white.withValues(alpha: 0.10),
                      width: 1.0,
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: _isScrolled ? 0.55 : 0.15),
                        blurRadius: _isScrolled ? 16 : 4,
                        offset: Offset(0, _isScrolled ? 4 : 2),
                      ),
                    ],
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Flexible(
                        child: Text(
                          'ការជូនដំណឹង',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontSize: 15,
                            fontWeight: FontWeight.bold,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                        decoration: BoxDecoration(
                          color: _unreadCount > 0
                              ? const Color(0xFFFFCC00).withValues(alpha: 0.18)
                              : Colors.white.withValues(alpha: 0.12),
                          borderRadius: BorderRadius.circular(10),
                          border: _unreadCount > 0
                              ? Border.all(
                                  color: const Color(0xFFFFCC00).withValues(alpha: 0.4),
                                  width: 0.8,
                                )
                              : null,
                        ),
                        child: Text(
                          _unreadCount > 0 ? '$_unreadCount ថ្មី' : '${_notifications.length}',
                          style: GoogleFonts.inter(
                            color: _unreadCount > 0
                                ? const Color(0xFFFFCC00)
                                : Colors.white.withValues(alpha: 0.75),
                            fontSize: 10.5,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(width: 10),

          // Right Pod: 44x44 Refresh Pod
          ClipRRect(
            borderRadius: BorderRadius.circular(22),
            child: BackdropFilter(
              filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 250),
                curve: Curves.easeInOutCubic,
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  color: _isScrolled
                      ? const Color(0xFF24272E).withValues(alpha: 0.94)
                      : const Color(0xFF1C1C1E).withValues(alpha: 0.65),
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: _isScrolled
                        ? Colors.white.withValues(alpha: 0.22)
                        : Colors.white.withValues(alpha: 0.10),
                    width: 1.0,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: _isScrolled ? 0.55 : 0.15),
                      blurRadius: _isScrolled ? 16 : 4,
                      offset: Offset(0, _isScrolled ? 4 : 2),
                    ),
                  ],
                ),
                child: Material(
                  color: Colors.transparent,
                  child: InkWell(
                    borderRadius: BorderRadius.circular(22),
                    onTap: () {
                      HapticFeedback.lightImpact();
                      _fetchNotifications();
                    },
                    child: const Center(
                      child: Icon(
                        CupertinoIcons.arrow_clockwise,
                        color: Colors.white,
                        size: 19,
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ===========================================================================
  // 2. SLEEK FROSTED SEARCH BAR
  // ===========================================================================
  Widget _buildSearchBar() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 14),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(14),
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 250),
            curve: Curves.easeInOutCubic,
            height: 42,
            decoration: BoxDecoration(
              color: _isScrolled
                  ? const Color(0xFF24272E).withValues(alpha: 0.92)
                  : const Color(0xFF1C1C1E).withValues(alpha: 0.65),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(
                color: _isScrolled
                    ? Colors.white.withValues(alpha: 0.20)
                    : Colors.white.withValues(alpha: 0.08),
                width: 1.0,
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: _isScrolled ? 0.45 : 0.10),
                  blurRadius: _isScrolled ? 14 : 4,
                  offset: Offset(0, _isScrolled ? 4 : 1),
                ),
              ],
            ),
            child: Row(
              children: [
                const SizedBox(width: 12),
                Icon(
                  CupertinoIcons.search,
                  color: Colors.white.withValues(alpha: 0.45),
                  size: 18,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: TextField(
                    controller: _searchController,
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 13.5,
                    ),
                    cursorColor: const Color(0xFFFFCC00),
                    decoration: InputDecoration(
                      filled: false,
                      fillColor: Colors.transparent,
                      hintText: 'ស្វែងរកការជូនដំណឹង...',
                      hintStyle: GoogleFonts.kantumruyPro(
                        color: Colors.white.withValues(alpha: 0.35),
                        fontSize: 13,
                      ),
                      border: InputBorder.none,
                      enabledBorder: InputBorder.none,
                      focusedBorder: InputBorder.none,
                      disabledBorder: InputBorder.none,
                      errorBorder: InputBorder.none,
                      focusedErrorBorder: InputBorder.none,
                      isDense: true,
                      contentPadding: const EdgeInsets.symmetric(vertical: 10),
                    ),
                  ),
                ),
                if (_searchController.text.isNotEmpty)
                  GestureDetector(
                    onTap: () {
                      HapticFeedback.lightImpact();
                      _searchController.clear();
                    },
                    child: Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 10),
                      child: Icon(
                        CupertinoIcons.clear_circled_solid,
                        color: Colors.white.withValues(alpha: 0.45),
                        size: 16,
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ===========================================================================
  // 3. FLUID HORIZONTAL IOS SEGMENTED FILTER SLIDER
  // ===========================================================================
  Widget _buildSegmentedFilterSlider() {
    final chips = [
      {'key': 'all', 'label': 'ទាំងអស់ ${_notifications.length}'},
      {'key': 'unread', 'label': 'មិនទាន់អាន $_unreadCount'},
      {'key': 'read', 'label': 'បានអាន ${_notifications.length - _unreadCount}'},
    ];

    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      physics: const BouncingScrollPhysics(),
      padding: const EdgeInsets.symmetric(horizontal: 14),
      child: Row(
        children: chips.map((chip) {
          final key = chip['key'] as String;
          final label = chip['label'] as String;
          final isSelected = _filter == key;

          return Padding(
            padding: const EdgeInsets.only(right: 8),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(16),
              child: BackdropFilter(
                filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 250),
                  curve: Curves.easeOutCubic,
                  decoration: BoxDecoration(
                    color: isSelected
                        ? const Color(0xFFFFCC00).withValues(alpha: 0.18)
                        : _isScrolled
                            ? const Color(0xFF1C1C1E).withValues(alpha: 0.82)
                            : const Color(0xFF1C1C1E).withValues(alpha: 0.52),
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(
                      color: isSelected
                          ? const Color(0xFFFFCC00).withValues(alpha: 0.65)
                          : _isScrolled
                              ? Colors.white.withValues(alpha: 0.14)
                              : Colors.white.withValues(alpha: 0.07),
                      width: isSelected ? 1.2 : 1.0,
                    ),
                    boxShadow: isSelected
                        ? [
                            BoxShadow(
                              color: const Color(0xFFFFCC00).withValues(alpha: 0.20),
                              blurRadius: 8,
                              offset: const Offset(0, 2),
                            ),
                          ]
                        : null,
                  ),
                  child: Material(
                    color: Colors.transparent,
                    child: InkWell(
                      borderRadius: BorderRadius.circular(16),
                      onTap: () {
                        HapticFeedback.lightImpact();
                        setState(() => _filter = key);
                      },
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7.5),
                        child: Text(
                          label,
                          style: GoogleFonts.kantumruyPro(
                            color: isSelected
                                ? const Color(0xFFFFCC00)
                                : Colors.white.withValues(alpha: 0.65),
                            fontSize: 12,
                            fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ),
          );
        }).toList(),
      ),
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

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: notification.isRead
            ? const Color(0xFF1C1C1E).withValues(alpha: 0.70)
            : const Color(0xFF1C1C1E),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: notification.isRead
              ? Colors.white.withValues(alpha: 0.08)
              : const Color(0xFFFFCC00).withValues(alpha: 0.35),
          width: 0.8,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.25),
            blurRadius: 10,
            offset: const Offset(0, 3),
          ),
          if (!notification.isRead)
            BoxShadow(
              color: const Color(0xFFFFCC00).withValues(alpha: 0.08),
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
                        color: const Color(0xFFFFCC00).withValues(alpha: 0.15),
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
                                    color: Colors.white,
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
                                  color: Colors.white.withValues(alpha: 0.38),
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
                              color: Colors.white.withValues(alpha: 0.70),
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
    return SingleChildScrollView(
      physics: const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics()),
      padding: EdgeInsets.only(top: topPadding / 2),
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                isFiltered ? CupertinoIcons.search : CupertinoIcons.bell_slash,
                size: 64,
                color: Colors.white.withValues(alpha: 0.25),
              ),
              const SizedBox(height: 16),
              Text(
                isFiltered ? "រកមិនឃើញការជូនដំណឹង" : "មិនទាន់មានការជូនដំណឹងទេ",
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              Text(
                isFiltered
                    ? "សាកល្បងប្តូរពាក្យស្វែងរក ឬ filter ផ្សេងទៀត"
                    : "ការជូនដំណឹងថ្មីៗនឹងបង្ហាញនៅទីនេះ",
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white.withValues(alpha: 0.50),
                  fontSize: 13,
                ),
                textAlign: TextAlign.center,
              ),
              if (isFiltered) ...[
                const SizedBox(height: 16),
                TextButton.icon(
                  onPressed: () {
                    HapticFeedback.lightImpact();
                    setState(() {
                      _filter = 'all';
                      _searchController.clear();
                    });
                  },
                  icon: const Icon(CupertinoIcons.clear_circled, size: 16),
                  label: Text('បង្ហាញទាំងអស់',
                      style: GoogleFonts.kantumruyPro(
                          fontSize: 13, fontWeight: FontWeight.bold)),
                  style: TextButton.styleFrom(
                    foregroundColor: const Color(0xFFFFCC00),
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
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
