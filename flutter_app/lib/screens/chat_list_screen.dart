import 'dart:async';
import 'dart:io';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:path_provider/path_provider.dart';
import 'new_message_screen.dart';
import 'chat_detail_screen.dart';
import 'storage_usage_screen.dart';
import 'add_story_screen.dart';
import 'community_channel_screen.dart';
import 'profile_screen.dart';
import '../services/api_service.dart';
import '../providers/user_provider.dart';
import '../utils/app_theme.dart';


// ==========================================
// COLOR TOKENS (DYNAMIC COMPANY THEME)
// ==========================================
class MessengerTheme {
  static Color get bg => AppTheme.bgSurface;
  static Color get cardBg => AppTheme.bgCard;
  static Color get textPrimary => AppTheme.textPrimary;
  static Color get textSecondary => AppTheme.textSecondary;
  static Color get textMuted => AppTheme.textMuted;
  static Color get activeBlue => AppTheme.primary;
  static Color get onlineGreen => const Color(0xFF10B981);
  static Color get actionBtnBg => const Color(0xFFF1F5F9);
  static Color get adBadgeBg => AppTheme.border;
  static Color get unreadDot => AppTheme.primary;
  static Color get border => AppTheme.border;
}

Color _getAvatarBgColor(String name) {
  if (name.isEmpty) return const Color(0xFF0084FF);
  const colors = [
    Color(0xFF0084FF),
    Color(0xFFFFB300),
    Color(0xFFAB47BC),
    Color(0xFF26A69A),
    Color(0xFFFF7043),
    Color(0xFF66BB6A),
    Color(0xFFEC407A),
  ];
  return colors[name.codeUnitAt(0) % colors.length];
}

class ChatListScreen extends StatefulWidget {
  const ChatListScreen({super.key});

  @override
  State<ChatListScreen> createState() => _ChatListScreenState();
}

class _ChatListScreenState extends State<ChatListScreen> with SingleTickerProviderStateMixin {
  final ApiService _api = ApiService();
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  bool isLoading = true;
  List<dynamic> usersList = [];
  List<dynamic> filteredUsers = [];
  String searchQuery = '';
  List<Map<String, dynamic>> customGroups = [];
  StreamSubscription? _groupsSubscription;
  Map<String, Timestamp?> chatActivity = {};
  Map<String, Map<String, dynamic>> activeChatsData = {};
  String currentUserId = '';

  final Map<String, Stream<DocumentSnapshot>> _presenceStreams = {};

  late AnimationController _broomAnimCtrl;
  int _cacheSizeBytes = 0;
  String _cacheSizeText = '';

  final ScrollController _scrollController = ScrollController();
  bool _isScrolled = false;
  String _selectedFolder = 'all'; // 'all', 'direct', 'group', 'unread'

  int get _totalUnreadCount {
    int count = 0;
    for (final entry in activeChatsData.values) {
      if (entry['isRead'] == false && entry['lastSenderId'] != currentUserId) {
        count++;
      }
    }
    return count;
  }

  @override
  void initState() {
    super.initState();
    _broomAnimCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    );

    _scrollController.addListener(() {
      final scrolled = _scrollController.hasClients && _scrollController.offset > 5;
      if (scrolled != _isScrolled) {
        setState(() => _isScrolled = scrolled);
      }
    });

    _loadCurrentUserId().then((_) {
      _fetchUsersList();
      _listenToActiveChats();
      _listenToGroups();
      _checkCacheSize();
    });
  }

  @override
  void dispose() {
    _broomAnimCtrl.dispose();
    _scrollController.dispose();
    _groupsSubscription?.cancel();
    super.dispose();
  }

  Future<void> _checkCacheSize() async {
    // Non-blocking async delay to prevent startup UI thread jank
    await Future.delayed(const Duration(seconds: 2));
    if (!mounted) return;

    try {
      final docDir = await getApplicationDocumentsDirectory();
      final tempDir = await getTemporaryDirectory();
      int total = 0;
      if (docDir.existsSync()) {
        await for (var f in docDir.list(recursive: true, followLinks: false)) {
          if (f is File) {
            total += await f.length();
          }
        }
      }
      if (tempDir.existsSync()) {
        await for (var f in tempDir.list(recursive: true, followLinks: false)) {
          if (f is File) {
            total += await f.length();
          }
        }
      }

      if (mounted) {
        setState(() {
          _cacheSizeBytes = total;
          if (total > 0) {
            final mb = (total / (1024 * 1024)).toStringAsFixed(1);
            _cacheSizeText = '${mb}MB';
          } else {
            _cacheSizeText = '';
          }
        });
        if (total > 15 * 1024 * 1024) {
          _broomAnimCtrl.repeat(reverse: true);
        } else {
          _broomAnimCtrl.stop();
        }
      }
    } catch (_) {}
  }

  Future<void> _loadCurrentUserId() async {
    final prefs = await SharedPreferences.getInstance();
    currentUserId = prefs.getString('employee_id') ?? '';
  }

  void _listenToGroups() {
    if (currentUserId.isEmpty) return;

    _groupsSubscription?.cancel();
    _groupsSubscription = _firestore
        .collection('groups')
        .where('participantIds', arrayContains: currentUserId)
        .snapshots()
        .listen((snapshot) {
          if (mounted) {
            setState(() {
              final groups =
                  snapshot.docs
                      .map((doc) => {'id': doc.id, ...doc.data()})
                      .toList();

              groups.sort((a, b) {
                final timeA =
                    (a['lastTimestamp'] as Timestamp?)?.toDate() ??
                    DateTime(1970);
                final timeB =
                    (b['lastTimestamp'] as Timestamp?)?.toDate() ??
                    DateTime(1970);
                return timeB.compareTo(timeA);
              });

              customGroups = groups;
            });
          }
        });
  }

  void _listenToActiveChats() {
    if (currentUserId.isEmpty) return;
    _firestore
        .collection('chats')
        .where('participants', arrayContains: currentUserId)
        .snapshots()
        .listen((snapshot) {
          final Map<String, Timestamp?> activity = {};
          final Map<String, Map<String, dynamic>> chatsData = {};
          for (var doc in snapshot.docs) {
            final data = doc.data();
            final List<dynamic> p = data['participants'] ?? [];
            final otherId = p.firstWhere(
              (id) => id != currentUserId,
              orElse: () => '',
            );
            if (otherId.isNotEmpty) {
              final rawMsg = (data['lastMessage'] ?? '').toString().trim();
              final ts = data['lastTimestamp'] as Timestamp?;
              if (rawMsg.isNotEmpty && ts != null) {
                activity[otherId] = ts;
                chatsData[otherId] = data;
              }
            }
          }
          if (mounted) {
            setState(() {
              chatActivity = activity;
              activeChatsData = chatsData;
              _sortUsers();
            });
          }
        });
  }

  void _sortUsers() {
    filteredUsers.sort((a, b) {
      final idA = a['employee_id'] ?? '';
      final idB = b['employee_id'] ?? '';
      final timeA = chatActivity[idA]?.toDate() ?? DateTime(1970);
      final timeB = chatActivity[idB]?.toDate() ?? DateTime(1970);
      return timeB.compareTo(timeA);
    });
  }

  Future<void> _fetchUsersList() async {
    try {
      final res = await _api.fetchUsers();
      if (res['success'] == true) {
        final List<dynamic> fetched = res['users'] ?? [];
        if (mounted) {
          final List<dynamic> filtered =
              fetched.where((u) {
                final role = (u['role'] ?? '').toString().toLowerCase();
                final name = (u['name'] ?? '').toString().toLowerCase();
                final eid = (u['employee_id'] ?? '').toString().toLowerCase();

                bool isTechnical =
                    role == 'admin_panel' ||
                    eid == 'admin_panel' ||
                    name.contains('it-by-vvc') ||
                    name.isEmpty;

                return !isTechnical;
              }).toList();

          setState(() {
            usersList = filtered;
            filteredUsers = filtered;
            _sortUsers();
            isLoading = false;
          });
        }
      } else {
        if (mounted) setState(() => isLoading = false);
      }
    } catch (e) {
      debugPrint('Error fetching users: $e');
      if (mounted) setState(() => isLoading = false);
    }
  }

  void _filterUsers(String query) {
    setState(() {
      searchQuery = query;
      if (query.isEmpty) {
        filteredUsers = usersList;
      } else {
        filteredUsers =
            usersList.where((u) {
              final name = (u['name'] ?? '').toString().toLowerCase();
              final eid = (u['employee_id'] ?? '').toString().toLowerCase();
              final dept = (u['department'] ?? '').toString().toLowerCase();
              final q = query.toLowerCase();
              return name.contains(q) || eid.contains(q) || dept.contains(q);
            }).toList();
      }
    });
  }

  String _formatTimestamp(Timestamp timestamp) {
    final date = timestamp.toDate();
    final now = DateTime.now();
    final diff = now.difference(date);
    if (diff.inDays == 0) {
      return DateFormat('h:mm a').format(date);
    } else if (diff.inDays < 7) {
      return DateFormat('E').format(date);
    } else {
      return DateFormat('dd/MM').format(date);
    }
  }

  @override
  Widget build(BuildContext context) {
    final userProvider = Provider.of<UserProvider>(context);
    final double topSafeArea = MediaQuery.of(context).padding.top;
    final double bottomSafeArea = MediaQuery.of(context).padding.bottom;

    // Top frosted header height: safeArea + top row (46) + search (36) + tabs (32) + vertical paddings (26)
    final double topHeaderHeight = topSafeArea + 148.0;
    // Bottom frosted bar height: bottomSafeArea + bar items (52) + vertical padding (14)
    final double bottomBarHeight = (bottomSafeArea > 0 ? bottomSafeArea : 10.0) + 64.0;

    return Scaffold(
      backgroundColor: MessengerTheme.bg,
      body: Stack(
        children: [
          // 1. Full-Bleed Scrollable Content Layer (Glides under top and bottom frosted glass bars)
          Positioned.fill(
            child: isLoading
                ? Center(
                    child: CircularProgressIndicator(
                      color: MessengerTheme.activeBlue,
                    ),
                  )
                : ListView(
                    controller: _scrollController,
                    physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
                    padding: EdgeInsets.fromLTRB(
                      0,
                      topHeaderHeight,
                      0,
                      bottomBarHeight,
                    ),
                    children: [
                      // A. Stories horizontal row (Active team online colleagues)
                      if (searchQuery.isEmpty && (_selectedFolder == 'all' || _selectedFolder == 'direct')) ...[
                        const SizedBox(height: 6.0),
                        _buildStoriesSection(),
                        const SizedBox(height: 10.0),
                      ],

                      // B. Filtered Conversations List
                      ..._buildFilteredChatItems(),
                    ],
                  ),
          ),

          // 2. Top Floating Frosted Glass Header (Dynamically blurs conversations as they scroll underneath)
          Positioned(
            top: 0,
            left: 0,
            right: 0,
            child: _buildTelegramFrostedHeader(userProvider, topSafeArea),
          ),

          // 3. Bottom Floating Frosted Glass Bar (Dynamically blurs conversations as they reach bottom edge)
          Positioned(
            bottom: 0,
            left: 0,
            right: 0,
            child: _buildTelegramFrostedBottomBar(bottomSafeArea),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // TOP FROSTED GLASS HEADER (TELEGRAM STYLE)
  // ==========================================
  Widget _buildTelegramFrostedHeader(UserProvider user, double topSafeArea) {
    return ClipRect(
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 25.0, sigmaY: 25.0),
        child: Container(
          decoration: BoxDecoration(
            color: MessengerTheme.bg.withValues(alpha: 0.85),
            border: Border(
              bottom: BorderSide(
                color: MessengerTheme.border.withValues(alpha: 0.65),
                width: 0.8,
              ),
            ),
            boxShadow: _isScrolled
                ? [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: 0.04),
                      blurRadius: 10,
                      offset: const Offset(0, 2),
                    ),
                  ]
                : null,
          ),
          padding: EdgeInsets.fromLTRB(14.0, topSafeArea + 4.0, 14.0, 8.0),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              _buildTopHeader(user),
              const SizedBox(height: 6.0),
              _buildSearchBar(),
              const SizedBox(height: 8.0),
              _buildFolderTabs(),
            ],
          ),
        ),
      ),
    );
  }

  // ==========================================
  // TELEGRAM FOLDER FILTER TABS (CATEGORIES)
  // ==========================================
  Widget _buildFolderTabs() {
    final int unreadCount = _totalUnreadCount;
    final int directCount = filteredUsers.length;
    final int groupCount = 2 + customGroups.length;

    final tabs = [
      {'id': 'all', 'label': 'ទាំងអស់', 'count': 0},
      {'id': 'direct', 'label': 'ការងារ', 'count': directCount},
      {'id': 'group', 'label': 'ក្រុម', 'count': groupCount},
      if (unreadCount > 0)
        {'id': 'unread', 'label': 'មិនទាន់អាន', 'count': unreadCount},
    ];

    return SizedBox(
      height: 32.0,
      child: ListView.separated(
        scrollDirection: Axis.horizontal,
        physics: const BouncingScrollPhysics(),
        itemCount: tabs.length,
        separatorBuilder: (_, __) => const SizedBox(width: 8.0),
        itemBuilder: (context, index) {
          final tab = tabs[index];
          final String id = tab['id'] as String;
          final String label = tab['label'] as String;
          final int count = tab['count'] as int;
          final bool isSelected = _selectedFolder == id;

          return GestureDetector(
            onTap: () {
              HapticFeedback.selectionClick();
              setState(() => _selectedFolder = id);
            },
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 180),
              padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 5.0),
              decoration: BoxDecoration(
                color: isSelected ? MessengerTheme.activeBlue : MessengerTheme.cardBg,
                borderRadius: BorderRadius.circular(16.0),
                border: Border.all(
                  color: isSelected ? MessengerTheme.activeBlue : MessengerTheme.border,
                  width: 0.8,
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    label,
                    style: GoogleFonts.kantumruyPro(
                      color: isSelected ? Colors.white : MessengerTheme.textPrimary,
                      fontSize: 12.5,
                      fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                    ),
                  ),
                  if (count > 0 && id != 'all') ...[
                    const SizedBox(width: 6.0),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 5.0, vertical: 1.0),
                      decoration: BoxDecoration(
                        color: isSelected
                            ? Colors.white.withValues(alpha: 0.25)
                            : MessengerTheme.activeBlue.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(8.0),
                      ),
                      child: Text(
                        '$count',
                        style: GoogleFonts.inter(
                          color: isSelected ? Colors.white : MessengerTheme.activeBlue,
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
    );
  }

  // ==========================================
  // BOTTOM FROSTED GLASS BAR (TELEGRAM STYLE)
  // ==========================================
  Widget _buildTelegramFrostedBottomBar(double bottomSafeArea) {
    return ClipRect(
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 25.0, sigmaY: 25.0),
        child: Container(
          decoration: BoxDecoration(
            color: MessengerTheme.bg.withValues(alpha: 0.85),
            border: Border(
              top: BorderSide(
                color: MessengerTheme.border.withValues(alpha: 0.65),
                width: 0.8,
              ),
            ),
          ),
          padding: EdgeInsets.fromLTRB(16.0, 8.0, 16.0, bottomSafeArea > 0 ? bottomSafeArea : 10.0),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceAround,
            children: [
              _buildBottomNavItem(
                icon: Icons.people_alt_rounded,
                label: 'បុគ្គលិក',
                onTap: () {
                  HapticFeedback.lightImpact();
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) => NewMessageScreen(
                        allUsers: usersList,
                        currentUserId: currentUserId,
                      ),
                    ),
                  );
                },
              ),
              _buildBottomNavItem(
                icon: Icons.phone_rounded,
                label: 'ការហៅ',
                onTap: () {
                  HapticFeedback.lightImpact();
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('ប្រព័ន្ធទំនាក់ទំនង និងការហៅផ្ទៃក្នុង', style: GoogleFonts.kantumruyPro()),
                      duration: const Duration(seconds: 1),
                    ),
                  );
                },
              ),
              _buildBottomNavItem(
                icon: Icons.chat_bubble_rounded,
                label: 'សារ',
                isActive: true,
                badgeCount: _totalUnreadCount,
                onTap: () {
                  HapticFeedback.lightImpact();
                  if (_scrollController.hasClients) {
                    _scrollController.animateTo(
                      0,
                      duration: const Duration(milliseconds: 300),
                      curve: Curves.easeOut,
                    );
                  }
                },
              ),
              _buildBottomNavItem(
                icon: Icons.cleaning_services_rounded,
                label: 'ទំហំផ្ទុក',
                badgeText: _cacheSizeText.isNotEmpty ? _cacheSizeText : null,
                onTap: () async {
                  HapticFeedback.lightImpact();
                  await Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) => const StorageUsageScreen(),
                    ),
                  );
                  _checkCacheSize();
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildBottomNavItem({
    required IconData icon,
    required String label,
    bool isActive = false,
    int badgeCount = 0,
    String? badgeText,
    required VoidCallback onTap,
  }) {
    final color = isActive ? MessengerTheme.activeBlue : MessengerTheme.textSecondary;

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12.0, vertical: 4.0),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Stack(
              clipBehavior: Clip.none,
              children: [
                Icon(icon, color: color, size: 22),
                if (badgeCount > 0)
                  Positioned(
                    right: -8,
                    top: -4,
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1.5),
                      decoration: BoxDecoration(
                        color: const Color(0xFFFF3B30),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Text(
                        badgeCount > 99 ? '99+' : '$badgeCount',
                        style: GoogleFonts.inter(
                          color: Colors.white,
                          fontSize: 9.5,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  )
                else if (badgeText != null && badgeText.isNotEmpty)
                  Positioned(
                    right: -10,
                    top: -4,
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
                      decoration: BoxDecoration(
                        color: const Color(0xFFFF9500),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        badgeText,
                        style: GoogleFonts.inter(
                          color: Colors.white,
                          fontSize: 8.5,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 3),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: color,
                fontSize: 11.0,
                fontWeight: isActive ? FontWeight.bold : FontWeight.normal,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // FILTERED CONVERSATION LIST ITEMS
  // ==========================================
  List<Widget> _buildFilteredChatItems() {
    final List<Widget> items = [];

    final bool showGroups = _selectedFolder == 'all' || _selectedFolder == 'group';
    final bool showDirect = _selectedFolder == 'all' || _selectedFolder == 'direct';
    final bool isUnreadOnly = _selectedFolder == 'unread';

    if (isUnreadOnly) {
      for (final user in filteredUsers) {
        final targetId = (user['employee_id'] ?? user['id'] ?? '').toString();
        final chatData = activeChatsData[targetId];
        if (chatData != null && chatData['isRead'] == false && chatData['lastSenderId'] != currentUserId) {
          items.add(_buildUserConversationTile(user));
        }
      }
      if (items.isEmpty) {
        return [
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 50.0),
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.mark_chat_read_rounded, color: MessengerTheme.textMuted, size: 48),
                  const SizedBox(height: 12),
                  Text(
                    'គ្មានសារមិនទាន់អានឡើយ',
                    style: GoogleFonts.kantumruyPro(color: MessengerTheme.textMuted, fontSize: 14),
                  ),
                ],
              ),
            ),
          ),
        ];
      }
      return items;
    }

    // Add Groups first if All or Group selected, and no search query active
    if (showGroups && searchQuery.isEmpty) {
      items.add(_buildCommunityChannelTile());
      items.add(_buildTeamGeneralGroupTile());
      for (final group in customGroups) {
        items.add(_buildCustomGroupTile(group));
      }
    }

    // Add Direct chats
    if (showDirect) {
      for (final user in filteredUsers) {
        items.add(_buildUserConversationTile(user));
      }
    }

    if (items.isEmpty) {
      return [
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 50.0),
          child: Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.search_off_rounded, color: MessengerTheme.textMuted, size: 48),
                const SizedBox(height: 12),
                Text(
                  'រកមិនឃើញការសន្ទនាឡើយ',
                  style: GoogleFonts.kantumruyPro(color: MessengerTheme.textMuted, fontSize: 14),
                ),
              ],
            ),
          ),
        ),
      ];
    }

    return items;
  }

  // ==========================================
  // TOP APPMBAR HEADER
  // ==========================================
  Widget _buildTopHeader(UserProvider user) {
    return Row(
      children: [
        // Back arrow navigation icon
        IconButton(
          icon: Icon(
            Icons.arrow_back_ios_new_rounded,
            color: MessengerTheme.textPrimary,
            size: 19,
          ),
          onPressed: () => Navigator.pop(context),
        ),

        // User avatar (Clickable to open profile screen)
        InkWell(
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => const ProfileScreen(),
              ),
            );
          },
          borderRadius: BorderRadius.circular(20),
          child: CircleAvatar(
            radius: 19.0,
            backgroundImage:
                user.avatar != null && user.avatar!.isNotEmpty
                    ? NetworkImage(ApiService.getFullImageUrl(user.avatar!))
                    : null,
            backgroundColor: _getAvatarBgColor(user.name ?? ''),
            child:
                user.avatar == null || user.avatar!.isEmpty
                    ? Text(
                      (user.name ?? 'U').substring(0, 1).toUpperCase(),
                      style: GoogleFonts.inter(
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                        fontSize: 13,
                      ),
                    )
                    : null,
          ),
        ),
        const SizedBox(width: 10.0),

        // Title "Chats" (សារ)
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'សារ (Chats)',
                style: GoogleFonts.kantumruyPro(
                  fontSize: 19.0,
                  fontWeight: FontWeight.bold,
                  color: MessengerTheme.textPrimary,
                ),
              ),
              if (_totalUnreadCount > 0)
                Text(
                  '$_totalUnreadCount សារមិនទាន់អាន',
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 11.0,
                    color: AppTheme.primary,
                    fontWeight: FontWeight.w600,
                  ),
                ),
            ],
          ),
        ),

        // Animated Broom / Clean Storage Action Button
        AnimatedBuilder(
          animation: _broomAnimCtrl,
          builder: (context, child) {
            final scale = 1.0 + (_broomAnimCtrl.value * 0.12);
            return Transform.scale(
              scale: _cacheSizeBytes > 15 * 1024 * 1024 ? scale : 1.0,
              child: Stack(
                clipBehavior: Clip.none,
                children: [
                  _buildActionButton(
                    icon: Icons.cleaning_services_rounded,
                    onTap: () async {
                      await Navigator.push(
                        context,
                        MaterialPageRoute(
                          builder: (_) => const StorageUsageScreen(),
                        ),
                      );
                      _checkCacheSize();
                    },
                  ),
                  if (_cacheSizeText.isNotEmpty)
                    Positioned(
                      right: -4,
                      top: -4,
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                        decoration: BoxDecoration(
                          color: _cacheSizeBytes > 30 * 1024 * 1024
                              ? const Color(0xFFEF4444)
                              : const Color(0xFFFF9500),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: MessengerTheme.bg, width: 1.5),
                        ),
                        child: Text(
                          _cacheSizeText,
                          style: GoogleFonts.inter(
                            color: Colors.white,
                            fontSize: 9,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ),
                ],
              ),
            );
          },
        ),
        const SizedBox(width: 8.0),
        _buildActionButton(
          icon: Icons.edit_rounded,
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder:
                    (_) => NewMessageScreen(
                      allUsers: usersList,
                      currentUserId: currentUserId,
                    ),
              ),
            );
          },
        ),
      ],
    );
  }

  Widget _buildActionButton({
    required IconData icon,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 36.0,
        height: 36.0,
        decoration: BoxDecoration(
          color: MessengerTheme.actionBtnBg,
          shape: BoxShape.circle,
          border: Border.all(color: MessengerTheme.border),
        ),
        child: Icon(icon, size: 18.0, color: MessengerTheme.textPrimary),
      ),
    );
  }

  // ==========================================
  // SEARCH BAR
  // ==========================================
  Widget _buildSearchBar() {
    return SizedBox(
      height: 36.0,
      child: TextField(
        onChanged: _filterUsers,
        cursorColor: MessengerTheme.activeBlue,
        style: GoogleFonts.kantumruyPro(
          color: MessengerTheme.textPrimary,
          fontSize: 13.5,
        ),
        decoration: InputDecoration(
          hintText: 'ស្វែងរកឈ្មោះបុគ្គលិក ឬផ្នែក...',
          hintStyle: GoogleFonts.kantumruyPro(
            color: MessengerTheme.textMuted,
            fontSize: 13.0,
          ),
          prefixIcon: Icon(
            Icons.search_rounded,
            color: MessengerTheme.textMuted,
            size: 18.0,
          ),
          filled: true,
          fillColor: MessengerTheme.cardBg,
          isDense: true,
          contentPadding: const EdgeInsets.symmetric(
            vertical: 6.0,
            horizontal: 12.0,
          ),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(18.0),
            borderSide: BorderSide(color: MessengerTheme.border, width: 0.8),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(18.0),
            borderSide: BorderSide(color: MessengerTheme.border, width: 0.8),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(18.0),
            borderSide: BorderSide(
              color: MessengerTheme.activeBlue,
              width: 1.2,
            ),
          ),
        ),
      ),
    );
  }

  // ==========================================
  // ACTIVE STORIES ROW (Real Data Only)
  // ==========================================
  Widget _buildStoriesSection() {
    return StreamBuilder<QuerySnapshot>(
      stream: _firestore.collection('stories').snapshots(),
      builder: (context, snapshot) {
        List<DocumentSnapshot> realStories = [];
        if (snapshot.hasData) {
          final now = DateTime.now();
          realStories =
              snapshot.data!.docs.where((doc) {
                final data = doc.data() as Map<String, dynamic>?;
                final ts = data?['createdAt'] as Timestamp?;
                if (ts == null) return false;
                return now.difference(ts.toDate()).inHours < 24;
              }).toList();
        }

        return SizedBox(
          height: 106.0,
          child: ListView.builder(
            scrollDirection: Axis.horizontal,
            physics: const BouncingScrollPhysics(),
            padding: const EdgeInsets.symmetric(horizontal: 16.0),
            itemCount: realStories.length + 1,
            itemBuilder: (context, index) {
              if (index == 0) {
                return InkWell(
                  onTap: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(builder: (_) => const AddStoryScreen()),
                    );
                  },
                  borderRadius: BorderRadius.circular(30),
                  child: Container(
                    margin: const EdgeInsets.only(right: 14.0),
                    child: Column(
                      children: [
                        Container(
                          width: 60.0,
                          height: 60.0,
                          decoration: BoxDecoration(
                            color: MessengerTheme.cardBg,
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: MessengerTheme.border,
                              width: 1.0,
                            ),
                          ),
                          child: Icon(
                            Icons.add_rounded,
                            size: 28.0,
                            color: MessengerTheme.activeBlue,
                          ),
                        ),
                        const SizedBox(height: 8.0),
                        SizedBox(
                          width: 60.0,
                          child: Text(
                            'រឿងរបស់អ្នក',
                            textAlign: TextAlign.center,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: GoogleFonts.kantumruyPro(
                              fontSize: 11.5,
                              fontWeight: FontWeight.w400,
                              color: MessengerTheme.textSecondary,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                );
              }

              final storyData =
                  realStories[index - 1].data() as Map<String, dynamic>;
              final String name = storyData['userName'] ?? 'User';
              final String avatar = storyData['userPhoto'] ?? '';

              return Container(
                margin: const EdgeInsets.only(right: 14.0),
                child: Column(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(2.0),
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: MessengerTheme.activeBlue,
                          width: 2.0,
                        ),
                      ),
                      child: CircleAvatar(
                        radius: 28.0,
                        backgroundImage:
                            avatar.isNotEmpty
                                ? NetworkImage(
                                  ApiService.getFullImageUrl(avatar),
                                )
                                : null,
                        backgroundColor: _getAvatarBgColor(name),
                        child:
                            avatar.isEmpty
                                ? Text(
                                  name.isNotEmpty ? name[0].toUpperCase() : 'U',
                                  style: GoogleFonts.inter(
                                    color: Colors.white,
                                    fontWeight: FontWeight.bold,
                                  ),
                                )
                                : null,
                      ),
                    ),
                    const SizedBox(height: 8.0),
                    SizedBox(
                      width: 60.0,
                      child: Text(
                        name,
                        textAlign: TextAlign.center,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: GoogleFonts.kantumruyPro(
                          fontSize: 11.5,
                          color: MessengerTheme.textPrimary,
                        ),
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        );
      },
    );
  }


  // Official VVC Community Channel Tile
  Widget _buildCommunityChannelTile() {
    return InkWell(
      onTap: () {
        Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const CommunityChannelScreen()),
        );
      },
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
        child: Row(
          children: [
            Container(
              width: 60,
              height: 60,
              decoration: const BoxDecoration(
                color: Color(0xFF007AFF),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.hub_rounded, color: Colors.white, size: 30),
            ),
            const SizedBox(width: 14.0),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        'សហគមន៍ VVC (VVC Community)',
                        style: GoogleFonts.kantumruyPro(
                          fontSize: 15.5,
                          fontWeight: FontWeight.bold,
                          color: MessengerTheme.textPrimary,
                        ),
                      ),
                      const SizedBox(width: 4),
                      const Icon(Icons.verified_rounded, color: Color(0xFF007AFF), size: 16),
                    ],
                  ),
                  const SizedBox(height: 4.0),
                  Text(
                    'ការជូនដំណឹង ព័ត៌មានក្រុមហ៊ុន និងការផ្សព្វផ្សាយ...',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 13.0,
                      color: MessengerTheme.textSecondary,
                    ),
                  ),
                ],
              ),
            ),
            Icon(Icons.arrow_forward_ios_rounded, size: 14.0, color: MessengerTheme.textSecondary),
          ],
        ),
      ),
    );
  }

  // Team Chat Group (ALL) Tile
  Widget _buildTeamGeneralGroupTile() {
    const String roomId = 'ALL';
    final stream = _firestore.collection('chats').doc(roomId).snapshots();

    return StreamBuilder<DocumentSnapshot>(
      stream: stream,
      builder: (context, snapshot) {
        String lastMsg = 'ជជែកកម្សាន្តសម្រាប់បុគ្គលិកទាំងអស់';
        String timeStr = '';
        if (snapshot.hasData && snapshot.data!.exists) {
          final data = snapshot.data!.data() as Map<String, dynamic>?;
          if (data != null) {
            final raw = data['lastMessage'] ?? '';
            final Timestamp? ts = data['lastTimestamp'] as Timestamp?;
            if (raw.isNotEmpty) lastMsg = raw;
            if (ts != null) timeStr = _formatTimestamp(ts);
          }
        }

        return InkWell(
          onTap:
              () => _navigateToChat(
                'ALL',
                'Team Chat Group (ក្រុមរួម)',
                '',
                isGroup: true,
              ),
          onLongPress:
              () => _showTelegramChatPeekPreview(
                targetId: 'ALL',
                targetName: 'Team Chat Group',
                avatar: '',
                isGroup: true,
              ),
          child: Padding(
            padding: const EdgeInsets.symmetric(
              horizontal: 16.0,
              vertical: 8.0,
            ),
            child: Row(
              children: [
                CircleAvatar(
                  radius: 30.0,
                  backgroundColor: MessengerTheme.activeBlue,
                  child: const Icon(
                    Icons.groups_rounded,
                    color: Colors.white,
                    size: 30,
                  ),
                ),
                const SizedBox(width: 14.0),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Team Chat Group (ក្រុមរួម)',
                        style: GoogleFonts.kantumruyPro(
                          fontSize: 15.5,
                          fontWeight: FontWeight.w600,
                          color: MessengerTheme.textPrimary,
                        ),
                      ),
                      const SizedBox(height: 4.0),
                      Row(
                        children: [
                          Flexible(
                            child: Text(
                              lastMsg,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: GoogleFonts.kantumruyPro(
                                fontSize: 13.5,
                                color: MessengerTheme.textSecondary,
                              ),
                            ),
                          ),
                          if (timeStr.isNotEmpty) ...[
                            Padding(
                              padding: const EdgeInsets.symmetric(horizontal: 6.0),
                              child: Text(
                                '•',
                                style: TextStyle(
                                  fontSize: 11,
                                  color: MessengerTheme.textSecondary,
                                ),
                              ),
                            ),
                            Text(
                              timeStr,
                              style: GoogleFonts.inter(
                                fontSize: 13.0,
                                color: MessengerTheme.textSecondary,
                              ),
                            ),
                          ],
                        ],
                      ),
                    ],
                  ),
                ),
                Icon(
                  Icons.arrow_forward_ios_rounded,
                  size: 12.0,
                  color: MessengerTheme.textSecondary,
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  // Custom Created Groups Tile
  Widget _buildCustomGroupTile(Map<String, dynamic> group) {
    final String groupId = group['id'];
    final String name = group['name'] ?? 'Group';
    final String lastMsg = group['lastMessage'] ?? '';
    final Timestamp? ts = group['lastTimestamp'] as Timestamp?;
    final String timeStr = ts != null ? _formatTimestamp(ts) : '';

    return InkWell(
      onTap: () => _navigateToChat(groupId, name, '', isGroup: true),
      onLongPress:
          () => _showTelegramChatPeekPreview(
            targetId: groupId,
            targetName: name,
            avatar: '',
            isGroup: true,
          ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
        child: Row(
          children: [
            CircleAvatar(
              radius: 30.0,
              backgroundColor: Colors.indigo.shade400,
              child: const Icon(
                Icons.forum_rounded,
                color: Colors.white,
                size: 28,
              ),
            ),
            const SizedBox(width: 14.0),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    name,
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 15.5,
                      fontWeight: FontWeight.w600,
                      color: MessengerTheme.textPrimary,
                    ),
                  ),
                  const SizedBox(height: 4.0),
                  Row(
                    children: [
                      Flexible(
                        child: Text(
                          lastMsg.isNotEmpty
                              ? lastMsg
                              : 'គ្មានសារកម្សាន្តនៅឡើយទេ',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 13.5,
                            color: MessengerTheme.textSecondary,
                          ),
                        ),
                      ),
                      if (timeStr.isNotEmpty) ...[
                        Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 6.0),
                          child: Text(
                            '•',
                            style: TextStyle(
                              fontSize: 11,
                              color: MessengerTheme.textSecondary,
                            ),
                          ),
                        ),
                        Text(
                          timeStr,
                          style: GoogleFonts.inter(
                            fontSize: 13.0,
                            color: MessengerTheme.textSecondary,
                          ),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            ),
            Icon(
              Icons.arrow_forward_ios_rounded,
              size: 12.0,
              color: MessengerTheme.textSecondary,
            ),
          ],
        ),
      ),
    );
  }

  // Real-time Employee Chat Tile (Firestore Stream-based)
  Widget _buildUserConversationTile(dynamic user) {
    final String title = user['name'] ?? 'Unknown';
    final String targetId = user['employee_id'] ?? '';
    final String avatar = user['avatar'] ?? '';
    final String position = user['position'] ?? 'បុគ្គលិក';

    if (currentUserId.isEmpty || targetId.isEmpty) {
      return const SizedBox.shrink();
    }

    final chatData = activeChatsData[targetId];
    String lastMsg = position;
    String timeStr = '';
    bool isUnread = false;
    bool isLastMessageByMe = false;
    bool isLastMessageRead = false;

    if (chatData != null) {
      final rawLastMsg = (chatData['lastMessage'] ?? '').toString().trim();
      final Timestamp? ts = chatData['lastTimestamp'] as Timestamp?;
      final lastSenderId = (chatData['lastSenderId'] ?? '').toString();
      isLastMessageRead = chatData['isRead'] == true;

      if (rawLastMsg.isNotEmpty && ts != null) {
        String cleanMsg = rawLastMsg;
        if (cleanMsg.startsWith('assets/') || cleanMsg.contains('/sticker/') || cleanMsg.endsWith('.json') || cleanMsg.endsWith('.png')) {
          cleanMsg = '🎨 ស្ទីគ័រ (Sticker)';
        }
        isLastMessageByMe = lastSenderId == currentUserId;
        lastMsg = isLastMessageByMe ? "អ្នក៖ $cleanMsg" : cleanMsg;
        if (!isLastMessageByMe && !isLastMessageRead) {
          isUnread = true;
        }
        timeStr = _formatTimestamp(ts);
      } else {
        lastMsg = position;
      }
    }

    // Presence stream caching
    if (!_presenceStreams.containsKey(targetId)) {
      _presenceStreams[targetId] =
          _firestore.collection('users').doc(targetId).snapshots();
    }

    return StreamBuilder<DocumentSnapshot>(
      stream: _presenceStreams[targetId],
      builder: (context, presenceSnapshot) {
        bool isOnline = false;
        if (presenceSnapshot.hasData && presenceSnapshot.data!.exists) {
          final data = presenceSnapshot.data!.data() as Map<String, dynamic>?;
          isOnline = data?['isOnline'] == true;
        }

        return InkWell(
                  onTap: () => _navigateToChat(targetId, title, avatar),
                  onLongPress:
                      () => _showTelegramChatPeekPreview(
                        targetId: targetId,
                        targetName: title,
                        avatar: avatar,
                        isGroup: false,
                      ),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 16.0,
                      vertical: 8.0,
                    ),
                    child: Row(
                      children: [
                        // Left profile picture with online indicator
                        Stack(
                          children: [
                            CircleAvatar(
                              radius: 26.0,
                              backgroundImage:
                                  avatar.isNotEmpty
                                      ? NetworkImage(
                                        ApiService.getFullImageUrl(avatar),
                                      )
                                      : null,
                              backgroundColor: _getAvatarBgColor(title),
                              child:
                                  avatar.isEmpty
                                      ? Text(
                                        title.isNotEmpty
                                            ? title
                                                .substring(0, 1)
                                                .toUpperCase()
                                            : 'U',
                                        style: GoogleFonts.inter(
                                          fontWeight: FontWeight.bold,
                                          fontSize: 18,
                                          color: Colors.white,
                                        ),
                                      )
                                      : null,
                            ),
                            Positioned(
                              right: 0.0,
                              bottom: 0.0,
                              child: Container(
                                width: 15.0,
                                height: 15.0,
                                decoration: BoxDecoration(
                                  color:
                                      isOnline
                                          ? MessengerTheme.onlineGreen
                                          : const Color(0xFFB0B3B8),
                                  shape: BoxShape.circle,
                                  border: Border.fromBorderSide(
                                    BorderSide(color: MessengerTheme.cardBg, width: 2.5),
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(width: 14.0),

                        // Chat details
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                title,
                                style: GoogleFonts.kantumruyPro(
                                  fontSize: 17.0,
                                  fontWeight: FontWeight.w600,
                                  color: MessengerTheme.textPrimary,
                                ),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                              ),
                              const SizedBox(height: 4.0),
                              Row(
                                children: [
                                  Flexible(
                                    child: Text(
                                      lastMsg,
                                      maxLines: 1,
                                      overflow: TextOverflow.ellipsis,
                                      style: GoogleFonts.kantumruyPro(
                                        fontSize: 14.5,
                                        fontWeight:
                                            isUnread
                                                ? FontWeight.w600
                                                : FontWeight.normal,
                                        color:
                                            isUnread
                                                ? MessengerTheme.textPrimary
                                                : MessengerTheme.textSecondary,
                                      ),
                                    ),
                                  ),
                                  if (timeStr.isNotEmpty) ...[
                                    Padding(
                                      padding: const EdgeInsets.symmetric(
                                        horizontal: 6.0,
                                      ),
                                      child: Text(
                                        '•',
                                        style: TextStyle(
                                          fontSize: 11,
                                          color: MessengerTheme.textSecondary,
                                        ),
                                      ),
                                    ),
                                    Text(
                                      timeStr,
                                      style: GoogleFonts.inter(
                                        fontSize: 13.5,
                                        fontWeight:
                                            isUnread
                                                ? FontWeight.w600
                                                : FontWeight.normal,
                                        color:
                                            isUnread
                                                ? MessengerTheme.textPrimary
                                                : MessengerTheme.textSecondary,
                                      ),
                                    ),
                                  ],
                                ],
                              ),
                            ],
                          ),
                        ),

                        // Unread dot indicator or delivery status
                        _buildConversationStatus(
                          isUnread,
                          isLastMessageByMe,
                          isLastMessageRead,
                          avatar,
                          title,
                        ),
                      ],
                    ),
                  ),
                );
      },
    );
  }

  Widget _buildConversationStatus(
    bool isUnread,
    bool isLastMessageByMe,
    bool isLastMessageRead,
    String avatar,
    String title,
  ) {
    if (isUnread) {
      return Container(
        width: 14.0,
        height: 14.0,
        decoration: BoxDecoration(
          color: MessengerTheme.unreadDot,
          shape: BoxShape.circle,
        ),
      );
    }
    if (isLastMessageByMe) {
      if (isLastMessageRead) {
        return const Icon(
          Icons.done_all_rounded,
          size: 16.0,
          color: Color(0xFF007AFF),
        );
      } else {
        return Icon(
          Icons.done_rounded,
          size: 16.0,
          color: MessengerTheme.textSecondary,
        );
      }
    }
    return const SizedBox.shrink();
  }

  void _navigateToChat(
    String id,
    String name,
    String photo, {
    bool isGroup = false,
  }) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder:
            (_) => ChatDetailScreen(
              targetUserId: id,
              targetUserName: name,
              targetUserPhoto: photo,
              isGroup: isGroup,
            ),
      ),
    );
  }

  // Telegram 3D Touch / Peek & Pop Chat Preview Modal (Matching Attached Image 100%)
  void _showTelegramChatPeekPreview({
    required String targetId,
    required String targetName,
    required String avatar,
    bool isGroup = false,
  }) {
    String roomId = targetId;
    if (!isGroup) {
      final List<String> ids = [currentUserId, targetId]..sort();
      roomId = "PRIVATE_${ids[0]}_${ids[1]}";
    }

    showDialog(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.78),
      builder: (ctx) {
        return Dialog(
          backgroundColor: Colors.transparent,
          insetPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // 1. Scrollable Chat Feed Preview Window
              Container(
                height: MediaQuery.of(context).size.height * 0.54,
                width: double.infinity,
                decoration: BoxDecoration(
                  color: const Color(0xFF17171C),
                  borderRadius: BorderRadius.circular(24),
                  border: Border.all(color: Colors.white.withValues(alpha: 0.12), width: 0.8),
                  boxShadow: const [
                    BoxShadow(color: Colors.black87, blurRadius: 20, offset: Offset(0, 8)),
                  ],
                ),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(24),
                  child: Stack(
                    children: [
                      Column(
                        children: [
                          // Capsule Header Pill inside Preview
                          Container(
                            padding: const EdgeInsets.symmetric(vertical: 10),
                            alignment: Alignment.center,
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 6),
                              decoration: BoxDecoration(
                                color: const Color(0xDD262629),
                                borderRadius: BorderRadius.circular(20),
                                border: Border.all(color: Colors.white12, width: 0.5),
                              ),
                              child: Column(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Text(
                                    targetName,
                                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5, fontWeight: FontWeight.bold),
                                  ),
                                  Text(
                                    isGroup ? 'Group Chat' : 'last seen recently',
                                    style: GoogleFonts.inter(color: const Color(0xFF8E8E93), fontSize: 10.5),
                                  ),
                                ],
                              ),
                            ),
                          ),

                          // Scrollable Message Feed
                          Expanded(
                            child: StreamBuilder<QuerySnapshot>(
                              stream: _firestore
                                  .collection('chats')
                                  .doc(roomId)
                                  .collection('messages')
                                  .orderBy('timestamp', descending: true)
                                  .limit(30)
                                  .snapshots(),
                              builder: (context, snap) {
                                if (snap.connectionState == ConnectionState.waiting && !snap.hasData) {
                                  return const Center(child: CircularProgressIndicator(color: Color(0xFF0A84FF)));
                                }

                                if (!snap.hasData || snap.data!.docs.isEmpty) {
                                  return Center(
                                    child: Text(
                                      'គ្មានសារក្នុងសន្ទនានេះទេ',
                                      style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 13),
                                    ),
                                  );
                                }

                                final docs = snap.data!.docs;

                                return ListView.builder(
                                  reverse: true,
                                  physics: const BouncingScrollPhysics(),
                                  padding: const EdgeInsets.all(12),
                                  itemCount: docs.length,
                                  itemBuilder: (context, idx) {
                                    final data = docs[idx].data() as Map<String, dynamic>;
                                    final String text = data['text'] ?? '';
                                    final String type = data['type'] ?? 'text';
                                    final String senderId = data['senderId'] ?? '';
                                    final bool isMine = senderId == currentUserId;
                                    final Timestamp? ts = data['timestamp'] as Timestamp?;
                                    final String timeStr = ts != null ? DateFormat('h:mm a').format(ts.toDate()) : '';

                                    return Align(
                                      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
                                      child: Container(
                                        margin: const EdgeInsets.symmetric(vertical: 4),
                                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 9),
                                        constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.65),
                                        decoration: BoxDecoration(
                                          color: isMine ? const Color(0xFF0A84FF) : const Color(0xFF2C2C2E),
                                          borderRadius: BorderRadius.circular(16),
                                        ),
                                        child: Column(
                                          crossAxisAlignment: isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                                          children: [
                                            if (type == 'voice')
                                              Row(
                                                mainAxisSize: MainAxisSize.min,
                                                children: [
                                                  const Icon(Icons.play_circle_fill_rounded, color: Colors.white, size: 24),
                                                  const SizedBox(width: 8),
                                                  Text('Voice Message', style: GoogleFonts.inter(color: Colors.white, fontSize: 13)),
                                                ],
                                              )
                                            else if (type == 'image')
                                              Row(
                                                mainAxisSize: MainAxisSize.min,
                                                children: [
                                                  const Icon(Icons.image_rounded, color: Colors.white, size: 18),
                                                  const SizedBox(width: 6),
                                                  Text('Photo', style: GoogleFonts.inter(color: Colors.white, fontSize: 13)),
                                                ],
                                              )
                                            else
                                              Text(
                                                text,
                                                style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                                              ),
                                            const SizedBox(height: 2),
                                            Text(
                                              timeStr,
                                              style: GoogleFonts.inter(color: Colors.white70, fontSize: 10),
                                            ),
                                          ],
                                        ),
                                      ),
                                    );
                                  },
                                );
                              },
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 12),

              // 2. Context Actions Menu Card (Matching Screenshot 100%)
              Align(
                alignment: Alignment.centerRight,
                child: Container(
                  width: 240,
                  decoration: BoxDecoration(
                    color: const Color(0xEE1C1C1E),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(color: Colors.white12, width: 0.5),
                    boxShadow: const [
                      BoxShadow(color: Colors.black54, blurRadius: 16, offset: Offset(0, 4)),
                    ],
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      _buildPeekActionItem(
                        icon: Icons.move_to_inbox_rounded,
                        title: 'Remove from Folder',
                        onTap: () {
                          Navigator.pop(ctx);
                        },
                      ),
                      const Divider(height: 1, color: Color(0xFF334155), indent: 14, endIndent: 14),
                      _buildPeekActionItem(
                        icon: Icons.chat_bubble_outline_rounded,
                        title: 'Mark as Unread',
                        onTap: () {
                          Navigator.pop(ctx);
                        },
                      ),
                      const Divider(height: 1, color: Color(0xFF334155), indent: 14, endIndent: 14),
                      _buildPeekActionItem(
                        icon: Icons.push_pin_outlined,
                        title: 'Pin',
                        onTap: () {
                          Navigator.pop(ctx);
                        },
                      ),
                      const Divider(height: 1, color: Color(0xFF334155), indent: 14, endIndent: 14),
                      _buildPeekActionItem(
                        icon: Icons.notifications_off_outlined,
                        title: 'Mute',
                        onTap: () {
                          Navigator.pop(ctx);
                        },
                      ),
                      const Divider(height: 1, color: Color(0xFF334155), indent: 14, endIndent: 14),
                      _buildPeekActionItem(
                        icon: Icons.delete_outline_rounded,
                        title: 'Delete',
                        isDanger: true,
                        onTap: () async {
                          Navigator.pop(ctx);
                          await _firestore.collection('chats').doc(roomId).delete();
                        },
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildPeekActionItem({
    required IconData icon,
    required String title,
    required VoidCallback onTap,
    bool isDanger = false,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              title,
              style: GoogleFonts.inter(
                color: isDanger ? const Color(0xFFFF3B30) : Colors.white,
                fontSize: 14,
                fontWeight: isDanger ? FontWeight.bold : FontWeight.w500,
              ),
            ),
            Icon(icon, color: isDanger ? const Color(0xFFFF3B30) : Colors.white, size: 20),
          ],
        ),
      ),
    );
  }
}
