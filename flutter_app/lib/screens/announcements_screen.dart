import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

class AnnouncementsScreen extends StatefulWidget {
  const AnnouncementsScreen({super.key});

  @override
  State<AnnouncementsScreen> createState() => _AnnouncementsScreenState();
}

class _AnnouncementsScreenState extends State<AnnouncementsScreen> {
  final ApiService _api = ApiService();
  List<dynamic> _items = [];
  bool _isLoading = true;
  Timer? _pollingTimer;

  @override
  void initState() {
    super.initState();
    _loadData();

    // Auto polling every 30 seconds
    _pollingTimer = Timer.periodic(const Duration(seconds: 30), (timer) {
      if (mounted) {
        _loadDataSilently();
      }
    });
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadData() async {
    try {
      final res = await _api.fetchAnnouncements();
      if (res['success'] == true) {
        if (mounted) {
          setState(() {
            _items = res['data'] ?? [];
            _isLoading = false;
          });
        }
      } else {
        if (mounted) setState(() => _isLoading = false);
      }
    } catch (e) {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _loadDataSilently() async {
    try {
      final res = await _api.fetchAnnouncements();
      if (res['success'] == true && mounted) {
        setState(() {
          _items = res['data'] ?? [];
        });
      }
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return DynamicAppBarWrapper(
      title: "ការជូនដំណឹង",
      leading: IconButton(
        icon: const Icon(Icons.arrow_back_ios_new_rounded),
        onPressed: () => Navigator.pop(context),
      ),
      body: AppBackgroundShell(
        child: _isLoading
            ? _buildShimmerList()
            : RefreshIndicator(
                onRefresh: _loadData,
                color: AppTheme.primary,
                child: _items.isEmpty ? _buildEmptyState() : _buildList(),
              ),
      ),
    );
  }

  Widget _buildShimmerList() {
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(20, 110, 20, 20),
      itemCount: 6,
      itemBuilder: (context, index) => Padding(
        padding: const EdgeInsets.only(bottom: 20),
        child: AppShimmer(
          child: Container(
            height: 140,
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(28),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.campaign_outlined,
            color: AppTheme.textPrimary.withValues(alpha: 0.10),
            size: 80,
          ),
          const SizedBox(height: 16),
          Text(
            "មិនទាន់មានការជូនដំណឹងនៅឡើយ",
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary.withValues(alpha: 0.38),
            ),
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
        itemCount: _items.length,
        itemBuilder: (context, index) {
          final item = _items[index];
          return AnimationConfiguration.staggeredList(
            position: index,
            duration: const Duration(milliseconds: 500),
            child: SlideAnimation(
              verticalOffset: 50.0,
              child: FadeInAnimation(child: _buildAnnouncementCard(item)),
            ),
          );
        },
      ),
    );
  }

  Widget _buildAnnouncementCard(dynamic item) {
    return Container(
      margin: const EdgeInsets.only(bottom: 20),
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(28),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.05)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.2),
            blurRadius: 15,
            offset: const Offset(0, 8),
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
                  shape: BoxShape.circle,
                ),
                child: Icon(
                  Icons.campaign_rounded,
                  color: AppTheme.primaryLight,
                  size: 24,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      item['title'] ?? 'No Title',
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary,
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                    if ((item['created_at'] ?? '').toString().isNotEmpty)
                      Row(
                        children: [
                          Icon(
                            Icons.access_time_rounded,
                            color: AppTheme.textPrimary.withValues(alpha: 0.38),
                            size: 12,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            item['created_at'],
                            style: GoogleFonts.inter(
                              color: AppTheme.textPrimary.withValues(
                                alpha: 0.38,
                              ),
                              fontSize: 11,
                            ),
                          ),
                        ],
                      ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.textPrimary.withValues(alpha: 0.03),
              borderRadius: BorderRadius.circular(16),
            ),
            child: Text(
              item['text'] ?? '',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.70),
                fontSize: 14,
                height: 1.6,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
