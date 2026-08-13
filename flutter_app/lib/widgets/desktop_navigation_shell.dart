import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../utils/app_theme.dart';
import 'responsive_layout.dart';

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

  @override
  void initState() {
    super.initState();
    _selectedIndex = widget.initialIndex;
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

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: Row(
        children: [
          // Collapsible Left Desktop Sidebar
          AnimatedContainer(
            duration: const Duration(milliseconds: 200),
            width: _isCollapsed ? 80 : 260,
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
                  color: Colors.black.withValues(alpha: 0.25),
                  blurRadius: 10,
                ),
              ],
            ),
            child: Column(
              children: [
                // Top Brand Header
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
                            width: 40,
                            height: 40,
                            decoration: BoxDecoration(
                              gradient: const LinearGradient(
                                colors: [Color(0xFF2563EB), Color(0xFF1D4ED8)],
                                begin: Alignment.topLeft,
                                end: Alignment.bottomRight,
                              ),
                              borderRadius: BorderRadius.circular(10),
                              boxShadow: [
                                BoxShadow(
                                  color: const Color(0xFF2563EB).withValues(alpha: 0.4),
                                  blurRadius: 8,
                                  offset: const Offset(0, 2),
                                ),
                              ],
                            ),
                            child: const Center(
                              child: Icon(
                                Icons.workspace_premium_rounded,
                                color: Colors.white,
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
                                    letterSpacing: 1.1,
                                  ),
                                ),
                                Text(
                                  'HR & Studio Enterprise',
                                  style: GoogleFonts.kantumruyPro(
                                    color: Colors.white54,
                                    fontSize: 11,
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
                                ? const Color(0xFF2563EB).withValues(alpha: 0.2)
                                : Colors.transparent,
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(
                              color: isSelected
                                  ? const Color(0xFF2563EB).withValues(alpha: 0.5)
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
                                    ? Colors.amberAccent
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
                                      fontSize: 13.5,
                                    ),
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ),
                                if (item.badge != null)
                                  Container(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 7,
                                      vertical: 2,
                                    ),
                                    decoration: BoxDecoration(
                                      color: Colors.amberAccent,
                                      borderRadius: BorderRadius.circular(8),
                                    ),
                                    child: Text(
                                      item.badge!,
                                      style: GoogleFonts.outfit(
                                        color: Colors.black,
                                        fontSize: 10.5,
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

                // Bottom Profile Area
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
                        : MainAxisAlignment.start,
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
                      if (!_isCollapsed) ...[
                        const SizedBox(width: 10),
                        Expanded(
                          child: Column(
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
                                  fontSize: 11,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ],
            ),
          ),

          // Main Screen Area with smooth transitions
          Expanded(
            child: widget.items[_selectedIndex].screen,
          ),
        ],
      ),
    );
  }
}
