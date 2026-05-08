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
  List<NotificationModel> _notifications = [];
  bool _isLoading = true;
  String? _error;
  Timer? _pollingTimer;

  @override
  void initState() {
    super.initState();
    _fetchNotifications();
    
    // Auto polling every 20 seconds
    _pollingTimer = Timer.periodic(const Duration(seconds: 20), (timer) {
      if (mounted) {
        _fetchNotificationsSilently();
      }
    });
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    super.dispose();
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
        final List<dynamic> data = result['data'] ?? result['notifications'] ?? [];
        if (!mounted) return;
        setState(() {
          _notifications = data.map((item) => NotificationModel.fromJson(item)).toList();
          
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
        final List<dynamic> data = result['data'] ?? result['notifications'] ?? [];
        if (!mounted) return;
        setState(() {
          _notifications = data.map((item) => NotificationModel.fromJson(item)).toList();
          
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
        icon: Icon(Icons.arrow_back_ios_new_rounded, color: AppTheme.textPrimary),
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
                : RefreshIndicator(
                    onRefresh: _fetchNotifications,
                    color: AppTheme.primary,
                    child: _notifications.isEmpty ? _buildEmptyState() : _buildList(),
                  ),
      ),
    );
  }

  Widget _buildShimmerList() {
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(20, 110, 20, 20),
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
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.error_outline_rounded, color: AppTheme.error, size: 64),
            const SizedBox(height: 16),
            Text(
              _error!,
              style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: _fetchNotifications,
              child: const Text("ព្យាយាមម្តងទៀត"),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.notifications_none_rounded, color: AppTheme.textPrimary.withValues(alpha: 0.1), size: 100),
          const SizedBox(height: 16),
          Text(
            "មិនទាន់មានការជូនដំណឹងទេ",
            style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary, fontSize: 16),
          ),
        ],
      ),
    );
  }

  Widget _buildList() {
    return AnimationLimiter(
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(20, 110, 20, 20),
        physics: const BouncingScrollPhysics(),
        itemCount: _notifications.length,
        itemBuilder: (context, index) {
          final notification = _notifications[index];
          return AnimationConfiguration.staggeredList(
            position: index,
            duration: const Duration(milliseconds: 500),
            child: SlideAnimation(
              verticalOffset: 50.0,
              child: FadeInAnimation(
                child: _buildNotificationCard(notification),
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
        color: notification.isRead ? AppTheme.bgCard.withValues(alpha: 0.6) : AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: notification.isRead ? AppTheme.borderColor : AppTheme.primary.withValues(alpha: 0.3),
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
                builder: (context) => NotificationDetailSheet(notification: notification),
              );
            },
            leading: Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: (notification.type == 'alert' ? AppTheme.error : AppTheme.primary).withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: Icon(
                notification.type == 'alert' ? Icons.warning_rounded : Icons.notifications_rounded,
                color: notification.type == 'alert' ? AppTheme.error : AppTheme.primary,
                size: 20,
              ),
            ),
            title: Text(
              notification.title,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: notification.isRead ? FontWeight.normal : FontWeight.bold,
              ),
            ),
            subtitle: Text(
              notification.message,
              style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary, fontSize: 13),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: notification.isRead 
                ? null 
                : Container(width: 8, height: 8, decoration: BoxDecoration(color: AppTheme.primary, shape: BoxShape.circle)),
          ),
          if (notification.imageUrl != null && notification.imageUrl!.isNotEmpty)
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
                       child: const Center(child: Icon(Icons.broken_image, color: Colors.grey)),
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
     Navigator.push(context, MaterialPageRoute(builder: (context) => Scaffold(
        backgroundColor: Colors.black,
        appBar: AppBar(backgroundColor: Colors.transparent, elevation: 0),
        body: Center(child: InteractiveViewer(child: Image.network(url))),
     )));
  }
}
