import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:animate_do/animate_do.dart';
import '../utils/app_theme.dart';
import 'package:google_fonts/google_fonts.dart';

class CustomerTrackingCard extends StatelessWidget {
  final String profileImageUrl;
  final String customerName;
  final String phoneNumber;
  final double latitude;
  final double longitude;

  const CustomerTrackingCard({
    super.key,
    required this.profileImageUrl,
    required this.customerName,
    required this.phoneNumber,
    required this.latitude,
    required this.longitude,
  });

  Future<void> _makePhoneCall() async {
    final Uri launchUri = Uri(
      scheme: 'tel',
      path: phoneNumber,
    );
    try {
      if (await canLaunchUrl(launchUri)) {
        await launchUrl(launchUri);
      }
    } catch (e) {
      debugPrint('Error launching dialer: $e');
    }
  }

  Future<void> _openMaps() async {
    final String googleMapsUrl = "https://www.google.com/maps/search/?api=1&query=$latitude,$longitude";
    final Uri url = Uri.parse(googleMapsUrl);
    try {
      if (await canLaunchUrl(url)) {
        await launchUrl(url, mode: LaunchMode.externalApplication);
      }
    } catch (e) {
      debugPrint('Error launching maps: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return FadeInUp(
      duration: const Duration(milliseconds: 500),
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: AppTheme.isDarkMode 
                ? Colors.white.withValues(alpha: 0.1) 
                : Colors.black.withValues(alpha: 0.05),
          ),
          boxShadow: AppTheme.cardShadow,
        ),
        child: Row(
          children: [
            // Profile Image Bordered Avatar
            Container(
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  color: AppTheme.primary.withValues(alpha: 0.3),
                  width: 2,
                ),
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(30),
                child: CachedNetworkImage(
                  imageUrl: profileImageUrl,
                  width: 60,
                  height: 60,
                  fit: BoxFit.cover,
                  placeholder: (context, url) => Container(
                    color: AppTheme.bgCardLight,
                    child: const Icon(Icons.person, color: Colors.white54),
                  ),
                  errorWidget: (context, url, error) => Container(
                    color: AppTheme.bgCardLight,
                    child: const Icon(Icons.person, color: Colors.white54),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 16),
            
            // Customer Info Center Section
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    customerName,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary,
                      fontSize: 17,
                      fontWeight: FontWeight.bold,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 6),
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(4),
                        decoration: BoxDecoration(
                          color: AppTheme.primary.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Icon(Icons.phone_outlined, size: 12, color: AppTheme.primary),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        phoneNumber,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textSecondary,
                          fontSize: 14,
                          letterSpacing: 0.5,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),

            // Functional Action Buttons
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                _buildActionButton(
                  icon: Icons.call_rounded,
                  color: AppTheme.success,
                  onTap: _makePhoneCall,
                  tooltip: 'Call Customer',
                ),
                const SizedBox(width: 10),
                _buildActionButton(
                  icon: Icons.near_me_rounded,
                  color: AppTheme.info,
                  onTap: _openMaps,
                  tooltip: 'Get Directions',
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildActionButton({
    required IconData icon,
    required Color color,
    required VoidCallback onTap,
    required String tooltip,
  }) {
    return Tooltip(
      message: tooltip,
      child: Material(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(14),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(14),
          child: Container(
            padding: const EdgeInsets.all(10),
            child: Icon(icon, color: color, size: 22),
          ),
        ),
      ),
    );
  }
}
