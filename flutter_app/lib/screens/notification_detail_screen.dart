import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../models/notification_model.dart';
import '../utils/app_theme.dart';
import 'requests_screen.dart';

class NotificationDetailSheet extends StatelessWidget {
  final NotificationModel notification;

  const NotificationDetailSheet({super.key, required this.notification});

  @override
  Widget build(BuildContext context) {
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
        color: AppTheme.bgDark,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(35)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.5),
            blurRadius: 30,
            offset: const Offset(0, -10),
          ),
        ],
        border: Border.all(color: AppTheme.borderColor.withValues(alpha: 0.5), width: 1),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Drag handle for premium feel
          Container(
            width: 45,
            height: 4.5,
            decoration: BoxDecoration(
              color: AppTheme.textMuted.withValues(alpha: 0.4),
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
                  if (notification.imageUrl != null && notification.imageUrl!.isNotEmpty)
                    Container(
                      margin: const EdgeInsets.symmetric(vertical: 20),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(25),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withValues(alpha: 0.3),
                            blurRadius: 15,
                            offset: const Offset(0, 8),
                          ),
                        ],
                      ),
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(25),
                        child: GestureDetector(
                          onTap: () {
                            Navigator.push(context, MaterialPageRoute(builder: (context) => Scaffold(
                              backgroundColor: Colors.black,
                              appBar: AppBar(backgroundColor: Colors.transparent, elevation: 0),
                              body: Center(child: InteractiveViewer(child: Image.network(notification.imageUrl!))),
                            )));
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
                                color: AppTheme.bgCard,
                                child: const Center(child: CircularProgressIndicator()),
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
                    padding: const EdgeInsets.all(24),
                    decoration: BoxDecoration(
                      color: AppTheme.bgCard,
                      borderRadius: BorderRadius.circular(28),
                      border: Border.all(color: AppTheme.borderColor),
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
                              child: Icon(Icons.notifications_rounded, color: AppTheme.primary, size: 20),
                            ),
                            const SizedBox(width: 15),
                            Expanded(
                              child: Text(
                                notification.title,
                                style: GoogleFonts.kantumruyPro(
                                  color: AppTheme.textPrimary,
                                  fontSize: 19,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 18),
                        Divider(color: AppTheme.borderColor.withValues(alpha: 0.5)),
                        const SizedBox(height: 18),
                        Text(
                          notification.message,
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textPrimary.withValues(alpha: 0.9),
                            fontSize: 15.5,
                            height: 1.6,
                          ),
                        ),
                        const SizedBox(height: 25),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.end,
                          children: [
                            Icon(Icons.access_time_rounded, color: AppTheme.textSecondary, size: 14),
                            const SizedBox(width: 6),
                            Text(
                              notification.sentAt,
                              style: GoogleFonts.inter(
                                color: AppTheme.textSecondary,
                                fontSize: 12.5,
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
                          Navigator.push(context, MaterialPageRoute(builder: (context) => const RequestsScreen()));
                        },
                        icon: const Icon(Icons.list_alt_rounded),
                        label: Text("មើលបញ្ជីសំណើ", style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
                        style: ElevatedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(vertical: 16),
                          backgroundColor: AppTheme.primary,
                          foregroundColor: Colors.white,
                          elevation: 0,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
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
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
                        side: BorderSide(color: AppTheme.borderColor),
                      ),
                      child: Text("បិទ", style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary)),
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
