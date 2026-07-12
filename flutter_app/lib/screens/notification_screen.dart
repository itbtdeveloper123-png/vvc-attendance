import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import '../services/api_service.dart';
import '../models/notification_model.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
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
  String? _error;
  String _filter = 'all';
  Timer? _pollingTimer;

  @override
  void initState() {
    super.initState();
    _fetchNotifications();
    _searchController.addListener(() {
      if (mounted) setState(() {});
    });

    // Auto polling every 6 seconds
    _pollingTimer = Timer.periodic(const Duration(seconds: 6), (timer) {
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
      final matchesFilter =
          _filter == 'all' ||
          (_filter == 'unread' && !notification.isRead) ||
          (_filter == 'read' && notification.isRead);
      final matchesSearch =
          q.isEmpty ||
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
          _notifications = data
              .map((item) => NotificationModel.fromJson(item))
              .toList();

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
          _notifications = data
              .map((item) => NotificationModel.fromJson(item))
              .toList();

          // Sort: Unread (isRead == false) first, then by sentAt descending
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

          // Re-sort to move the newly read notification down if necessary
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

  @override
  Widget build(BuildContext context) {
    return DynamicAppBarWrapper(
      title: "ការជូនដំណឹង",
      leading: IconButton(
        icon: Icon(
          Icons.arrow_back_ios_new_rounded,
          color: AppTheme.textPrimary,
        ),
        onPressed: () => Navigator.pop(context),
      ),
      actions: [
        IconButton(
          icon: Icon(Icons.refresh_rounded, color: AppTheme.textPrimary),
          onPressed: _fetchNotifications,
        ),
      ],
      body: AppBackgroundShell(
        child: _isLoading
            ? _buildShimmerList()
            : _error != null
            ? _buildErrorState()
            : Column(
                children: [
                  SizedBox(height: MediaQuery.paddingOf(context).top + 70),
                  _buildToolbar(),
                  Expanded(
                    child: RefreshIndicator(
                      onRefresh: _fetchNotifications,
                      color: AppTheme.primary,
                      child: _visibleNotifications.isEmpty
                          ? _buildEmptyState()
                          : _buildList(_visibleNotifications),
                    ),
                  ),
                ],
              ),
      ),
    );
  }

  Widget _buildToolbar() {
    final hPad = AppResponsive.horizontalPadding(context);
    return Padding(
      padding: EdgeInsets.fromLTRB(hPad, 0, hPad, 12),
      child: AppResponsive.maxWidth(
        context: context,
        child: Column(
          children: [
            AppSearchField(
              controller: _searchController,
              hintText: 'ស្វែងរកការជូនដំណឹង...',
            ),
            const SizedBox(height: 10),
            SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              physics: const BouncingScrollPhysics(),
              child: Row(
                children: [
                  _buildFilterChip('all', 'ទាំងអស់ ${_notifications.length}'),
                  const SizedBox(width: 8),
                  _buildFilterChip('unread', 'មិនទាន់អាន $_unreadCount'),
                  const SizedBox(width: 8),
                  _buildFilterChip(
                    'read',
                    'បានអាន ${_notifications.length - _unreadCount}',
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFilterChip(String value, String label) {
    final selected = _filter == value;
    return InkWell(
      borderRadius: BorderRadius.circular(999),
      onTap: () => setState(() => _filter = value),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: selected
              ? AppTheme.primary.withValues(alpha: 0.16)
              : AppTheme.bgCard,
          borderRadius: BorderRadius.circular(999),
          border: Border.all(
            color: selected
                ? AppTheme.primary.withValues(alpha: 0.45)
                : AppTheme.cardBorder,
          ),
        ),
        child: Text(
          label,
          style: GoogleFonts.kantumruyPro(
            color: selected ? AppTheme.primaryLight : AppTheme.textSecondary,
            fontSize: 12,
            fontWeight: FontWeight.bold,
          ),
        ),
      ),
    );
  }

  Widget _buildShimmerList() {
    final hPad = AppResponsive.horizontalPadding(context);
    return ListView.builder(
      padding: EdgeInsets.fromLTRB(
        hPad,
        110,
        hPad,
        AppResponsive.bottomPadding(context),
      ),
      itemCount: 10,
      itemBuilder: (context, index) => Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: AppShimmer(
          child: Container(
            height: 70,
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(20),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildErrorState() {
    return AppStateView(
      icon: Icons.error_outline_rounded,
      title: "មានបញ្ហាក្នុងការទាញទិន្នន័យ",
      message: _error ?? '',
      color: AppTheme.error,
      actionLabel: "ព្យាយាមម្តងទៀត",
      onAction: _fetchNotifications,
    );
  }

  Widget _buildEmptyState() {
    final isFiltered =
        _searchController.text.trim().isNotEmpty || _filter != 'all';
    return AppStateView(
      icon: isFiltered
          ? Icons.manage_search_rounded
          : Icons.notifications_none_rounded,
      title: isFiltered ? "រកមិនឃើញការជូនដំណឹង" : "មិនទាន់មានការជូនដំណឹងទេ",
      message: isFiltered
          ? "សាកល្បងប្តូរពាក្យស្វែងរក ឬ filter ផ្សេងទៀត"
          : "ការជូនដំណឹងថ្មីៗនឹងបង្ហាញនៅទីនេះ",
      color: AppTheme.primary,
    );
  }

  Widget _buildList(List<NotificationModel> notifications) {
    final hPad = AppResponsive.horizontalPadding(context);
    return AnimationLimiter(
      child: ListView.builder(
        padding: EdgeInsets.fromLTRB(
          hPad,
          0,
          hPad,
          AppResponsive.bottomPadding(context),
        ),
        physics: const BouncingScrollPhysics(),
        itemCount: notifications.length,
        itemBuilder: (context, index) {
          final notification = notifications[index];
          return AnimationConfiguration.staggeredList(
            position: index,
            duration: const Duration(milliseconds: 500),
            child: SlideAnimation(
              verticalOffset: 50.0,
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

  Widget _buildNotificationCard(NotificationModel notification) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: notification.isRead
            ? AppTheme.bgCard.withValues(alpha: 0.6)
            : AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: notification.isRead
              ? AppTheme.borderColor
              : AppTheme.primary.withValues(alpha: 0.3),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          ListTile(
            onLongPress: () {
              // Option to delete or expand
            },
            onTap: () {
              _markAsRead(notification.id);
              showModalBottomSheet(
                context: context,
                isScrollControlled: true,
                backgroundColor: Colors.transparent,
                enableDrag: true,
                builder: (context) =>
                    NotificationDetailSheet(notification: notification),
              );
            },
            leading: Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color:
                    (notification.type == 'alert'
                            ? AppTheme.error
                            : AppTheme.primary)
                        .withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: Icon(
                notification.type == 'alert'
                    ? Icons.warning_rounded
                    : Icons.notifications_rounded,
                color: notification.type == 'alert'
                    ? AppTheme.error
                    : AppTheme.primary,
                size: 20,
              ),
            ),
            title: Text(
              notification.title,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: notification.isRead
                    ? FontWeight.normal
                    : FontWeight.bold,
              ),
            ),
            subtitle: Text(
              notification.message,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textSecondary,
                fontSize: 13,
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: notification.isRead
                ? null
                : Container(
                    width: 8,
                    height: 8,
                    decoration: BoxDecoration(
                      color: AppTheme.primary,
                      shape: BoxShape.circle,
                    ),
                  ),
          ),
          if (notification.imageUrl != null &&
              notification.imageUrl!.isNotEmpty)
            Container(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
              child: GestureDetector(
                onTap: () => _viewFullImage(notification.imageUrl!),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(15),
                  child: Image.network(
                    notification.imageUrl!,
                    height: 160,
                    width: double.infinity,
                    fit: BoxFit.cover,
                    loadingBuilder: (context, child, loadingProgress) {
                      if (loadingProgress == null) return child;
                      return Container(
                        height: 160,
                        color: Colors.black12,
                        child: const Center(child: CircularProgressIndicator()),
                      );
                    },
                    errorBuilder: (context, error, stackTrace) => Container(
                      height: 50,
                      width: double.infinity,
                      decoration: BoxDecoration(
                        color: Colors.red.withValues(alpha: 0.05),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: const Center(
                        child: Icon(Icons.broken_image, color: Colors.grey),
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

  void _viewFullImage(String url) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => Scaffold(
          backgroundColor: Colors.black,
          appBar: AppBar(backgroundColor: Colors.transparent, elevation: 0),
          body: Center(child: InteractiveViewer(child: Image.network(url))),
        ),
      ),
    );
  }
}
