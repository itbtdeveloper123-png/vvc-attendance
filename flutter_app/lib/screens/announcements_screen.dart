import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/cupertino.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import '../widgets/responsive_layout.dart';

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
      leading: Navigator.canPop(context)
          ? IconButton(
              icon: const Icon(CupertinoIcons.chevron_back),
              onPressed: () => Navigator.pop(context),
            )
          : null,
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
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;
    final shimmerBg = isDark ? const Color(0xFF1C1C1E) : Colors.white;

    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(20, 110, 20, 20),
      itemCount: 6,
      itemBuilder: (context, index) => Padding(
        padding: const EdgeInsets.only(bottom: 20),
        child: AppShimmer(
          child: Container(
            height: 140,
            decoration: BoxDecoration(
              color: shimmerBg,
              borderRadius: BorderRadius.circular(24),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;
    final textMuted = isDark ? const Color(0xFF8E8E93) : const Color(0xFF64748B);

    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            CupertinoIcons.speaker_2,
            color: textMuted.withValues(alpha: 0.30),
            size: 80,
          ),
          const SizedBox(height: 16),
          Text(
            "មិនទាន់មានការជូនដំណឹងនៅឡើយ",
            style: GoogleFonts.kantumruyPro(
              color: textMuted,
              fontSize: 15,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildList() {
    if (Responsive.isDesktop(context) || Responsive.isTablet(context)) {
      return GridView.builder(
        padding: const EdgeInsets.fromLTRB(24, 110, 24, 24),
        physics: const BouncingScrollPhysics(),
        gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: MediaQuery.of(context).size.width > 1200 ? 3 : 2,
          childAspectRatio: 2.2,
          crossAxisSpacing: 16,
          mainAxisSpacing: 16,
        ),
        itemCount: _items.length,
        itemBuilder: (context, index) => _buildAnnouncementCard(_items[index]),
      );
    }

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
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;
    final cardBg = isDark ? const Color(0xFF1C1C1E) : Colors.white;
    final cardBorder = isDark ? Colors.white.withValues(alpha: 0.08) : Colors.black.withValues(alpha: 0.06);
    final innerBg = isDark ? Colors.white.withValues(alpha: 0.05) : const Color(0xFFF8FAFC);
    final textPrimary = isDark ? Colors.white : const Color(0xFF0F172A);
    final textSecondary = isDark ? const Color(0xFF98989D) : const Color(0xFF64748B);

    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: cardBg,
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: cardBorder, width: 1.0),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.30 : 0.04),
            blurRadius: 12,
            offset: const Offset(0, 3),
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
                  color: AppTheme.primary.withValues(alpha: isDark ? 0.18 : 0.12),
                  shape: BoxShape.circle,
                ),
                child: Icon(
                  CupertinoIcons.speaker_2_fill,
                  color: AppTheme.primary,
                  size: 22,
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
                        color: textPrimary,
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                    if ((item['created_at'] ?? '').toString().isNotEmpty)
                      Row(
                        children: [
                          Icon(
                            CupertinoIcons.clock,
                            color: textSecondary,
                            size: 12,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            item['created_at'],
                            style: GoogleFonts.inter(
                              color: textSecondary,
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
              color: innerBg,
              borderRadius: BorderRadius.circular(16),
            ),
            child: Text(
              item['text'] ?? '',
              style: GoogleFonts.kantumruyPro(
                color: textPrimary.withValues(alpha: 0.85),
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
