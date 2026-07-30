import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import 'leave_request_screen.dart';
import 'ot_request_screen.dart';
import 'forget_scan_screen.dart';
import 'late_request_screen.dart';
import 'change_day_off_screen.dart';
import 'request_list_screen.dart';

class RequestsScreen extends StatelessWidget {
  const RequestsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return AppBackgroundShell(
      child: CustomScrollView(
        physics: const BouncingScrollPhysics(),
        slivers: [
          SliverToBoxAdapter(
            child: SafeArea(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(20, 8, 20, 0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    FadeInDown(
                      duration: const Duration(milliseconds: 400),
                      child: Text(
                        "សំណើផ្សេងៗ",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontSize: 26,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                    FadeInDown(
                      duration: const Duration(milliseconds: 500),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Expanded(
                            child: Text(
                              "ជ្រើសរើសសំណើដែលអ្នកចង់ដាក់",
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textMuted,
                                fontSize: 14,
                              ),
                            ),
                          ),
                          TextButton.icon(
                            onPressed: () => Navigator.push(
                              context,
                              MaterialPageRoute(
                                builder: (_) => const RequestListScreen(),
                              ),
                            ),
                            icon: Icon(
                              Icons.history_rounded,
                              size: 18,
                              color: AppTheme.primaryLight,
                            ),
                            label: Text(
                              "បញ្ជីសំណើ",
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.primaryLight,
                                fontWeight: FontWeight.bold,
                                fontSize: 13,
                              ),
                            ),
                            style: TextButton.styleFrom(
                              backgroundColor: AppTheme.primary.withValues(
                                alpha: 0.1,
                              ),
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                                vertical: 8,
                              ),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(10),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 24),
                    AnimationLimiter(
                      child: Column(
                        children: _buildRequestList(context),
                      ),
                    ),
                    const SizedBox(height: 110),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  List<Widget> _buildRequestList(BuildContext context) {
    final items = [
      _RequestItem(
        title: "ច្បាប់ឈប់សម្រាក",
        subtitle: "ស្នើសំណើច្បាប់ប្រចាំឆ្នាំ, ឈប់ជំងឺ ឬឈប់ផ្ទាល់",
        icon: Icons.beach_access_rounded,
        color: Colors.pinkAccent,
        screen: const LeaveRequestScreen(),
      ),
      _RequestItem(
        title: "ថែមម៉ោង (OT)",
        subtitle: "ស្នើសំណើថែមម៉ោងធ្វើការ",
        icon: Icons.bolt_rounded,
        color: Colors.amberAccent,
        screen: const OtRequestScreen(),
      ),
      _RequestItem(
        title: "ភ្លេចស្កេន",
        subtitle: "ដាក់ពាក្យស្នើ Check-In/Out ដែលភ្លេច",
        icon: Icons.history_rounded,
        color: Colors.purpleAccent,
        screen: const ForgetScanScreen(),
      ),
      _RequestItem(
        title: "មកថ្ងៃត្រូវវែ (Late)",
        subtitle: "ស្នើបញ្ជាក់ហេតុផលមកយឺត",
        icon: Icons.access_time_rounded,
        color: Colors.orangeAccent,
        screen: const LateRequestScreen(),
      ),
      _RequestItem(
        title: "ប្តូរថ្ងៃ OFF",
        subtitle: "ស្នើប្តូរថ្ងៃឈប់សម្រាក",
        icon: Icons.swap_horiz_rounded,
        color: Colors.tealAccent,
        screen: const ChangeDayOffScreen(),
      ),
    ];

    return List.generate(items.length, (i) {
      final item = items[i];
      return AnimationConfiguration.staggeredList(
        position: i,
        duration: const Duration(milliseconds: 500),
        child: SlideAnimation(
          verticalOffset: 50.0,
          child: FadeInAnimation(
            child: Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: AppActionButton(
                title: item.title,
                subtitle: item.subtitle,
                icon: item.icon,
                iconColor: item.color,
                onTap: () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => item.screen),
                ),
              ),
            ),
          ),
        ),
      );
    });
  }
}

class _RequestItem {
  final String title;
  final String subtitle;
  final IconData icon;
  final Color color;
  final Widget screen;

  _RequestItem({
    required this.title,
    required this.subtitle,
    required this.icon,
    required this.color,
    required this.screen,
  });
}
