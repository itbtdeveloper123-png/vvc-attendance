import 'package:flutter/material.dart';
import 'package:flutter/cupertino.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import '../widgets/responsive_layout.dart';
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
                          VvcButton(
                            height: 38,
                            variant: VvcButtonVariant.tinted,
                            icon: CupertinoIcons.list_bullet_below_rectangle,
                            label: "បញ្ជីសំណើ",
                            onPressed: () => Navigator.push(
                              context,
                              MaterialPageRoute(
                                builder: (_) => const RequestListScreen(),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 24),
                    if (Responsive.isDesktop(context) || Responsive.isTablet(context))
                      GridView.builder(
                        shrinkWrap: true,
                        physics: const NeverScrollableScrollPhysics(),
                        gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
                          crossAxisCount: MediaQuery.of(context).size.width > 1200 ? 3 : 2,
                          childAspectRatio: 2.8,
                          crossAxisSpacing: 16,
                          mainAxisSpacing: 16,
                        ),
                        itemCount: _requestItems.length,
                        itemBuilder: (context, i) {
                          final item = _requestItems[i];
                          return AppActionButton(
                            title: item.title,
                            subtitle: item.subtitle,
                            icon: item.icon,
                            iconColor: item.color,
                            onTap: () => Navigator.push(
                              context,
                              MaterialPageRoute(builder: (_) => item.screen),
                            ),
                          );
                        },
                      )
                    else
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

  static final List<_RequestItem> _requestItems = [
    _RequestItem(
      title: "ច្បាប់ឈប់សម្រាក",
      subtitle: "ស្នើសំណើច្បាប់ប្រចាំឆ្នាំ, ឈប់ជំងឺ ឬឈប់ផ្ទាល់",
      icon: CupertinoIcons.calendar_badge_minus,
      color: Colors.pinkAccent,
      screen: const LeaveRequestScreen(),
    ),
    _RequestItem(
      title: "ថែមម៉ោង (OT)",
      subtitle: "ស្នើសំណើថែមម៉ោងធ្វើការ",
      icon: CupertinoIcons.bolt_fill,
      color: Colors.amberAccent,
      screen: const OtRequestScreen(),
    ),
    _RequestItem(
      title: "ភ្លេចស្កេន",
      subtitle: "ដាក់ពាក្យស្នើ Check-In/Out ដែលភ្លេច",
      icon: CupertinoIcons.hand_raised_fill,
      color: Colors.purpleAccent,
      screen: const ForgetScanScreen(),
    ),
    _RequestItem(
      title: "មកថ្ងៃត្រូវវែ (Late)",
      subtitle: "ស្នើបញ្ជាក់ហេតុផលមកយឺត",
      icon: CupertinoIcons.clock_fill,
      color: Colors.orangeAccent,
      screen: const LateRequestScreen(),
    ),
    _RequestItem(
      title: "ប្តូរថ្ងៃ OFF",
      subtitle: "ស្នើប្តូរថ្ងៃឈប់សម្រាក",
      icon: CupertinoIcons.arrow_2_squarepath,
      color: Colors.tealAccent,
      screen: const ChangeDayOffScreen(),
    ),
  ];

  List<Widget> _buildRequestList(BuildContext context) {
    return List.generate(_requestItems.length, (i) {
      final item = _requestItems[i];
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
