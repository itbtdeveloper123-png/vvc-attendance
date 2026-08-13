import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import 'responsive_layout.dart';
import '../screens/notification_screen.dart';
import '../screens/ai_chat_screen.dart';
import '../screens/login_screen.dart';

class DesktopNavigationItem {
  final String title;
  final IconData icon;
  final IconData selectedIcon;
  final Widget screen;
  final String? badge;

  const DesktopNavigationItem({
    required this.title,
    required this.icon,
    required this.selectedIcon,
    required this.screen,
    this.badge,
  });
}

class DesktopNavigationShell extends StatefulWidget {
  final List<DesktopNavigationItem> items;
  final int initialIndex;
  final Widget? mobileDrawer;

  const DesktopNavigationShell({
    super.key,
    required this.items,
    this.initialIndex = 0,
    this.mobileDrawer,
  });

  @override
  State<DesktopNavigationShell> createState() => _DesktopNavigationShellState();
}

class _DesktopNavigationShellState extends State<DesktopNavigationShell> {
  late int _selectedIndex;
  bool _isCollapsed = false;
  DateTime _currentTime = DateTime.now();
  Timer? _clockTimer;

  @override
  void initState() {
    super.initState();
    _selectedIndex = widget.initialIndex;
    _clockTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) {
        setState(() => _currentTime = DateTime.now());
      }
    });
  }

  @override
  void dispose() {
    _clockTimer?.cancel();
    super.dispose();
  }

  void _showLogoutConfirmDialog(BuildContext context, UserProvider userProvider) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
        title: Row(
          children: [
            const Icon(Icons.logout_rounded, color: Color(0xFFEF4444), size: 24),
            const SizedBox(width: 10),
            Text(
              'ចាកចេញពីគណនី',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        content: Text(
          'តើអ្នកប្រាកដជាចង់ចាកចេញពីប្រព័ន្ធ VVC HRM មែនទេ?',
          style: GoogleFonts.kantumruyPro(
            color: Colors.white70,
            fontSize: 13.5,
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text(
              'បោះបង់',
              style: GoogleFonts.kantumruyPro(color: Colors.white60),
            ),
          ),
          ElevatedButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await userProvider.logout();
              if (context.mounted) {
                Navigator.pushAndRemoveUntil(
                  context,
                  MaterialPageRoute(builder: (_) => const LoginScreen()),
                  (route) => false,
                );
              }
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFDC2626),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
            ),
            child: Text(
              'ចាកចេញ (Logout)',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (Responsive.isMobile(context)) {
      return widget.items[_selectedIndex].screen;
    }

    final userProvider = Provider.of<UserProvider>(context);
    final userName = (userProvider.name != null && userProvider.name!.isNotEmpty)
        ? userProvider.name!
        : 'អ្នកប្រើប្រាស់';
    final userRole = userProvider.systemRoleLabel.isNotEmpty
        ? userProvider.systemRoleLabel
        : 'បុគ្គលិក';
    final currentItem = widget.items[_selectedIndex];

    return Scaffold(
      backgroundColor: const Color(0xFF0B1120),
      body: Row(
        children: [
          // 1. Collapsible Left Desktop Sidebar
          AnimatedContainer(
            duration: const Duration(milliseconds: 200),
            width: _isCollapsed ? 80 : 270,
            decoration: BoxDecoration(
              color: const Color(0xFF0F172A),
              border: Border(
                right: BorderSide(
                  color: Colors.white.withValues(alpha: 0.08),
                  width: 1,
                ),
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.3),
                  blurRadius: 16,
                  offset: const Offset(2, 0),
                ),
              ],
            ),
            child: Column(
              children: [
                // Brand Header with Toggle Button
                Container(
                  padding: EdgeInsets.symmetric(
                    horizontal: _isCollapsed ? 12 : 20,
                    vertical: 20,
                  ),
                  decoration: BoxDecoration(
                    border: Border(
                      bottom: BorderSide(
                        color: Colors.white.withValues(alpha: 0.06),
                      ),
                    ),
                  ),
                  child: Row(
                    mainAxisAlignment: _isCollapsed
                        ? MainAxisAlignment.center
                        : MainAxisAlignment.spaceBetween,
                    children: [
                      Row(
                        children: [
                          Container(
                            width: 42,
                            height: 42,
                            decoration: BoxDecoration(
                              gradient: const LinearGradient(
                                colors: [Color(0xFFD4AF37), Color(0xFFB8860B)],
                                begin: Alignment.topLeft,
                                end: Alignment.bottomRight,
                              ),
                              borderRadius: BorderRadius.circular(12),
                              boxShadow: [
                                BoxShadow(
                                  color: const Color(0xFFD4AF37).withValues(alpha: 0.35),
                                  blurRadius: 8,
                                  offset: const Offset(0, 3),
                                ),
                              ],
                            ),
                            child: const Center(
                              child: Icon(
                                Icons.workspace_premium_rounded,
                                color: Colors.black,
                                size: 24,
                              ),
                            ),
                          ),
                          if (!_isCollapsed) ...[
                            const SizedBox(width: 12),
                            Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'VVC GROUP',
                                  style: GoogleFonts.outfit(
                                    color: Colors.white,
                                    fontSize: 16,
                                    fontWeight: FontWeight.w800,
                                    letterSpacing: 1.2,
                                  ),
                                ),
                                Text(
                                  'HRM & Studio Enterprise',
                                  style: GoogleFonts.kantumruyPro(
                                    color: const Color(0xFFD4AF37),
                                    fontSize: 10.5,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ],
                      ),
                      if (!_isCollapsed)
                        IconButton(
                          icon: const Icon(
                            Icons.menu_open_rounded,
                            color: Colors.white60,
                            size: 20,
                          ),
                          onPressed: () => setState(() => _isCollapsed = true),
                          tooltip: 'បង្រួម Sidebar',
                        ),
                    ],
                  ),
                ),

                if (_isCollapsed)
                  IconButton(
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    icon: const Icon(
                      Icons.menu_rounded,
                      color: Colors.white70,
                      size: 22,
                    ),
                    onPressed: () => setState(() => _isCollapsed = false),
                    tooltip: 'ពង្រីក Sidebar',
                  ),

                // Navigation Items List
                Expanded(
                  child: ListView.separated(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 10,
                      vertical: 14,
                    ),
                    itemCount: widget.items.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 4),
                    itemBuilder: (context, idx) {
                      final item = widget.items[idx];
                      final isSelected = _selectedIndex == idx;

                      return InkWell(
                        onTap: () => setState(() => _selectedIndex = idx),
                        borderRadius: BorderRadius.circular(12),
                        hoverColor: Colors.white.withValues(alpha: 0.05),
                        child: AnimatedContainer(
                          duration: const Duration(milliseconds: 150),
                          padding: EdgeInsets.symmetric(
                            horizontal: _isCollapsed ? 12 : 14,
                            vertical: 12,
                          ),
                          decoration: BoxDecoration(
                            color: isSelected
                                ? const Color(0xFF2563EB).withValues(alpha: 0.22)
                                : Colors.transparent,
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(
                              color: isSelected
                                  ? const Color(0xFF3B82F6).withValues(alpha: 0.6)
                                  : Colors.transparent,
                            ),
                          ),
                          child: Row(
                            mainAxisAlignment: _isCollapsed
                                ? MainAxisAlignment.center
                                : MainAxisAlignment.start,
                            children: [
                              Icon(
                                isSelected ? item.selectedIcon : item.icon,
                                color: isSelected
                                    ? const Color(0xFFD4AF37)
                                    : Colors.white70,
                                size: 22,
                              ),
                              if (!_isCollapsed) ...[
                                const SizedBox(width: 14),
                                Expanded(
                                  child: Text(
                                    item.title,
                                    style: GoogleFonts.kantumruyPro(
                                      color: isSelected
                                          ? Colors.white
                                          : Colors.white70,
                                      fontWeight: isSelected
                                          ? FontWeight.bold
                                          : FontWeight.w500,
                                      fontSize: 13,
                                    ),
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ),
                                if (item.badge != null)
                                  Container(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 8,
                                      vertical: 2.5,
                                    ),
                                    decoration: BoxDecoration(
                                      color: const Color(0xFFD4AF37),
                                      borderRadius: BorderRadius.circular(6),
                                    ),
                                    child: Text(
                                      item.badge!,
                                      style: GoogleFonts.outfit(
                                        color: Colors.black,
                                        fontSize: 10,
                                        fontWeight: FontWeight.bold,
                                      ),
                                    ),
                                  ),
                              ],
                            ],
                          ),
                        ),
                      );
                    },
                  ),
                ),

                // Bottom User Profile & Logout Area
                Container(
                  padding: EdgeInsets.all(_isCollapsed ? 10 : 14),
                  decoration: BoxDecoration(
                    color: const Color(0xFF0A101D),
                    border: Border(
                      top: BorderSide(
                        color: Colors.white.withValues(alpha: 0.06),
                      ),
                    ),
                  ),
                  child: Row(
                    mainAxisAlignment: _isCollapsed
                        ? MainAxisAlignment.center
                        : MainAxisAlignment.spaceBetween,
                    children: [
                      Row(
                        children: [
                          Stack(
                            children: [
                              CircleAvatar(
                                radius: 18,
                                backgroundColor: const Color(0xFF2563EB),
                                backgroundImage: (userProvider.avatarUrl != null && userProvider.avatarUrl!.isNotEmpty)
                                    ? NetworkImage(userProvider.avatarUrl!)
                                    : null,
                                child: (userProvider.avatarUrl == null || userProvider.avatarUrl!.isEmpty)
                                    ? Text(
                                        userName.isNotEmpty ? userName.substring(0, 1).toUpperCase() : 'U',
                                        style: const TextStyle(
                                          color: Colors.white,
                                          fontWeight: FontWeight.bold,
                                        ),
                                      )
                                    : null,
                              ),
                              Positioned(
                                right: 0,
                                bottom: 0,
                                child: Container(
                                  width: 10,
                                  height: 10,
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF10B981),
                                    shape: BoxShape.circle,
                                    border: Border.all(color: const Color(0xFF0A101D), width: 1.5),
                                  ),
                                ),
                              ),
                            ],
                          ),
                          if (!_isCollapsed) ...[
                            const SizedBox(width: 10),
                            Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  userName,
                                  style: GoogleFonts.kantumruyPro(
                                    color: Colors.white,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 12.5,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                                Text(
                                  userRole,
                                  style: GoogleFonts.kantumruyPro(
                                    color: Colors.white54,
                                    fontSize: 10.5,
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ],
                      ),
                      if (!_isCollapsed)
                        IconButton(
                          icon: const Icon(
                            Icons.power_settings_new_rounded,
                            color: Color(0xFFEF4444),
                            size: 20,
                          ),
                          onPressed: () => _showLogoutConfirmDialog(context, userProvider),
                          tooltip: 'ចាកចេញពីគណនី (Logout)',
                        ),
                    ],
                  ),
                ),
              ],
            ),
          ),

          // 2. Main Screen Area with Top Windows Navigation Header
          Expanded(
            child: Column(
              children: [
                // Top Windows Command & Header Bar
                _buildTopWindowsHeader(currentItem, userProvider),

                // Main Selected Screen Canvas
                Expanded(
                  child: currentItem.screen,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ===== Top Windows Header & Command Bar =====
  Widget _buildTopWindowsHeader(DesktopNavigationItem currentItem, UserProvider userProvider) {
    final String timeStr = DateFormat('HH:mm:ss').format(_currentTime);
    final String dateStr = DateFormat('dd MMM yyyy').format(_currentTime);

    return Container(
      height: 64,
      padding: const EdgeInsets.symmetric(horizontal: 24),
      decoration: BoxDecoration(
        color: const Color(0xFF0F172A),
        border: Border(
          bottom: BorderSide(
            color: Colors.white.withValues(alpha: 0.08),
            width: 1,
          ),
        ),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          // Left: Current Page Title & Icon
          Row(
            children: [
              Icon(
                currentItem.selectedIcon,
                color: const Color(0xFF60A5FA),
                size: 22,
              ),
              const SizedBox(width: 10),
              Text(
                currentItem.title,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 15,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),

          // Right: Live Clock, AI Quick Button, Notification Bell
          Row(
            children: [
              // Live Digital Clock Pill
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.schedule_rounded, color: Color(0xFF60A5FA), size: 16),
                    const SizedBox(width: 8),
                    Text(
                      timeStr,
                      style: GoogleFonts.outfit(
                        color: Colors.white,
                        fontSize: 13,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 1,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Text(
                      '• $dateStr',
                      style: GoogleFonts.outfit(
                        color: Colors.white54,
                        fontSize: 11.5,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),

              // AI Chat Quick Launcher Button
              IconButton(
                onPressed: () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const AiChatScreen()),
                ),
                icon: const Icon(Icons.auto_awesome, color: Color(0xFFA5B4FC), size: 20),
                tooltip: 'ជំនួយការ AI Chat Assistant',
                style: IconButton.styleFrom(
                  backgroundColor: const Color(0xFF1E293B),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
              ),
              const SizedBox(width: 8),

              // Notification Bell Button
              IconButton(
                onPressed: () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const NotificationScreen()),
                ),
                icon: const Icon(Icons.notifications_outlined, color: Colors.white70, size: 20),
                tooltip: 'ការជូនដំណឹង & សារថ្មី',
                style: IconButton.styleFrom(
                  backgroundColor: const Color(0xFF1E293B),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
