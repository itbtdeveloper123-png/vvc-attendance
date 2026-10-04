import 'package:flutter/material.dart';
import 'package:flutter/cupertino.dart';
import 'package:google_fonts/google_fonts.dart';
import '../models/notification_model.dart';
import '../utils/app_theme.dart';
import 'requests_screen.dart';
import 'trip_tracking_screen.dart';
import '../widgets/app_widgets.dart';

class NotificationDetailSheet extends StatelessWidget {
  final NotificationModel notification;

  const NotificationDetailSheet({super.key, required this.notification});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;
    final sheetBg = isDark ? const Color(0xFF1C1C1E) : Colors.white;
    final innerCardBg = isDark ? const Color(0xFF2C2C2E) : const Color(0xFFF8FAFC);
    final borderColor = isDark ? Colors.white.withValues(alpha: 0.10) : Colors.black.withValues(alpha: 0.08);
    final textPri = isDark ? Colors.white : const Color(0xFF0F172A);
    final textSec = isDark ? const Color(0xFF98989D) : const Color(0xFF64748B);

    return Container(
      constraints: BoxConstraints(
        maxHeight: MediaQuery.of(context).size.height * 0.85,
        minWidth: double.infinity,
      ),
      padding: EdgeInsets.only(
        top: 12,
        bottom: MediaQuery.of(context).padding.bottom + 20,
      ),
      decoration: BoxDecoration(
        color: sheetBg,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(32)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.45 : 0.10),
            blurRadius: 20,
            offset: const Offset(0, -4),
          ),
        ],
        border: Border.all(
          color: borderColor,
          width: 1,
        ),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Drag handle for premium feel
          Container(
            width: 44,
            height: 4.5,
            decoration: BoxDecoration(
              color: isDark ? Colors.white.withValues(alpha: 0.25) : Colors.black.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(10),
            ),
          ),
          const SizedBox(height: 15),

          Flexible(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              physics: const BouncingScrollPhysics(),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 1. Image if exists
                  if (notification.imageUrl != null &&
                      notification.imageUrl!.isNotEmpty)
                    Container(
                      margin: const EdgeInsets.symmetric(vertical: 20),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(22),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withValues(alpha: 0.25),
                            blurRadius: 15,
                            offset: const Offset(0, 6),
                          ),
                        ],
                      ),
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(22),
                        child: GestureDetector(
                          onTap: () {
                            Navigator.push(
                              context,
                              MaterialPageRoute(
                                builder:
                                    (context) => Scaffold(
                                      backgroundColor: Colors.black,
                                      appBar: const VvcAppBar(
                                        backgroundColor: Colors.transparent,
                                        elevation: 0,
                                      ),
                                      body: Center(
                                        child: InteractiveViewer(
                                          child: Image.network(
                                            notification.imageUrl!,
                                          ),
                                        ),
                                      ),
                                    ),
                              ),
                            );
                          },
                          child: Image.network(
                            notification.imageUrl!,
                            width: double.infinity,
                            fit: BoxFit.cover,
                            height: 220,
                            loadingBuilder: (context, child, loadingProgress) {
                              if (loadingProgress == null) return child;
                              return Container(
                                height: 220,
                                width: double.infinity,
                                color: innerCardBg,
                                child: const Center(
                                  child: CircularProgressIndicator(),
                                ),
                              );
                            },
                          ),
                        ),
                      ),
                    ),

                  const SizedBox(height: 15),

                  // 2. Title & Message Card
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(22),
                    decoration: BoxDecoration(
                      color: innerCardBg,
                      borderRadius: BorderRadius.circular(24),
                      border: Border.all(color: borderColor),
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
                                CupertinoIcons.bell_fill,
                                color: AppTheme.primary,
                                size: 20,
                              ),
                            ),
                            const SizedBox(width: 14),
                            Expanded(
                              child: Text(
                                notification.title,
                                style: GoogleFonts.kantumruyPro(
                                  color: textPri,
                                  fontSize: 18,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 16),
                        Divider(
                          color: borderColor,
                        ),
                        const SizedBox(height: 16),
                        Text(
                          notification.message,
                          style: GoogleFonts.kantumruyPro(
                            color: textPri.withValues(alpha: 0.90),
                            fontSize: 14.5,
                            height: 1.6,
                          ),
                        ),
                        const SizedBox(height: 20),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.end,
                          children: [
                            Icon(
                              CupertinoIcons.clock,
                              color: textSec,
                              size: 14,
                            ),
                            const SizedBox(width: 6),
                            Text(
                              notification.sentAt,
                              style: GoogleFonts.inter(
                                color: textSec,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),

                  // 3. Action Buttons
                  if (notification.type == 'request') ...[
                    const SizedBox(height: 25),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: () {
                          Navigator.pop(context); // Close sheet
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (context) => const RequestsScreen(),
                            ),
                          );
                        },
                        icon: const Icon(CupertinoIcons.list_bullet_below_rectangle),
                        label: Text(
                          "មើលបញ្ជីសំណើ",
                          style: GoogleFonts.kantumruyPro(
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        style: ElevatedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(vertical: 16),
                          backgroundColor: AppTheme.primary,
                          foregroundColor: Colors.white,
                          elevation: 0,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18),
                          ),
                        ),
                      ),
                    ),
                  ],
                  if (notification.type == 'gps_tracking' &&
                      notification.targetId > 0) ...[
                    const SizedBox(height: 25),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: () {
                          Navigator.pop(context); // Close sheet
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder:
                                  (context) => TripTrackingScreen(
                                    tripId: notification.targetId,
                                  ),
                            ),
                          );
                        },
                        icon: const Icon(CupertinoIcons.map_fill),
                        label: Text(
                          "តាមដានផែនទីដំណើរ",
                          style: GoogleFonts.kantumruyPro(
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        style: ElevatedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(vertical: 16),
                          backgroundColor: const Color(0xFF10b981),
                          foregroundColor: Colors.white,
                          elevation: 0,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(18),
                          ),
                        ),
                      ),
                    ),
                  ],

                  const SizedBox(height: 15),
                  SizedBox(
                    width: double.infinity,
                    child: OutlinedButton(
                      onPressed: () => Navigator.pop(context),
                      style: OutlinedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 16),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(18),
                        ),
                        side: BorderSide(color: AppTheme.borderColor),
                      ),
                      child: Text(
                        "បិទ",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textSecondary,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
