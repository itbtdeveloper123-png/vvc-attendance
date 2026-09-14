import 'dart:async';
import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/cupertino.dart';
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
import '../widgets/vvc_liquid_glass_scaffold.dart';
import '../services/api_service.dart';
import '../providers/user_provider.dart';
import '../utils/app_theme.dart';


// ==========================================
// COLOR TOKENS (DYNAMIC COMPANY THEME - HIGH CONTRAST)
// ==========================================
class MessengerTheme {
  static bool _contextDark = false;
  static void update(BuildContext context) {
    _contextDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;
  }
  static bool get isDark => _contextDark || AppTheme.isDarkMode;
  static Color get bg => isDark ? const Color(0xFF0F172A) : AppTheme.bgSurface;
  static Color get cardBg => isDark ? const Color(0xFF1E222B) : AppTheme.bgCard;
  static Color get textPrimary => isDark ? Colors.white : AppTheme.textPrimary;
  static Color get textSecondary => isDark ? const Color(0xFFCBD5E1) : const Color(0xFF475569);
  static Color get textMuted => isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B);
  static Color get activeBlue => const Color(0xFFF3D010);
  static Color get onlineGreen => const Color(0xFF10B981);
  static Color get actionBtnBg => isDark ? const Color(0xFF222630) : const Color(0xFFF1F5F9);
  static Color get adBadgeBg => isDark ? const Color(0xFF334155) : AppTheme.border;
  static Color get unreadDot => const Color(0xFFF3D010);
  static Color get border => isDark ? const Color(0xFF334155) : AppTheme.border;
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
  bool _isSearchExpanded = false;
  final TextEditingController _searchController = TextEditingController();
  final FocusNode _searchFocusNode = FocusNode();

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
    _searchController.dispose();
    _searchFocusNode.dispose();
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
    MessengerTheme.update(context);
    final userProvider = Provider.of<UserProvider>(context);
    final isDark = MessengerTheme.isDark;
    final double topSafeArea = MediaQuery.of(context).padding.top;
    final double bottomSafeArea = MediaQuery.of(context).padding.bottom;

    // Top padding: topSafeArea + 44.0 (Pods) + 8.0
    final double topHeaderHeight = topSafeArea + 52.0;
    // Bottom dock height: (bottomSafeArea + 4.0 or 14.0) + 64.0
    final double bottomBarHeight = (bottomSafeArea > 0 ? bottomSafeArea + 4.0 : 14.0) + 64.0;
    final double listBottomPadding = bottomBarHeight + (_isSearchExpanded ? 64.0 : 12.0);

    final bottomNavBar = _buildTelegramFrostedBottomBar(bottomSafeArea, isDark);

    return Scaffold(
      backgroundColor: MessengerTheme.bg,
      body: NotificationListener<ScrollNotification>(
        onNotification: (notification) {
          if (notification.metrics.axis == Axis.vertical) {
            final scrolled = notification.metrics.pixels > 6.0;
            if (scrolled != _isScrolled) {
              setState(() => _isScrolled = scrolled);
            }
          }
          return false;
        },
        child: Stack(
          children: [
            // 1. Full-Bleed Scrollable Content Layer (Glides under floating header & dock)
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
                        listBottomPadding,
                      ),
                      children: [
                        const SizedBox(height: 6.0),

                        // Centered Folder Filter Tabs (Inside scrollable view, matching HomeScreen!)
                        _buildFolderTabs(),

                        const SizedBox(height: 12.0),

                        // A. Stories horizontal row (Active team online colleagues)
                        if (searchQuery.isEmpty && (_selectedFolder == 'all' || _selectedFolder == 'direct')) ...[
                          _buildStoriesSection(),
                          const SizedBox(height: 10.0),
                        ],

                        // B. Filtered Conversations List
                        ..._buildFilteredChatItems(),
                      ],
                    ),
            ),

            // 2. Scroll-Aware Top Ambient Transition Zone (Fades content smoothly under the 3 pods)
            bottomNavBar.buildTopTransitionZone(
              context: context,
              maskColor: MessengerTheme.bg,
              height: 56.0,
            ),

            // 3. Localized Bottom Edge Transition Zone (Fades content smoothly under the dock)
            bottomNavBar.buildTransitionZone(
              context: context,
              maskColor: MessengerTheme.bg,
            ),

            // 4. Floating Glass Search Bar (Appears smoothly when search button is tapped)
            if (_isSearchExpanded)
              Positioned(
                left: 16.0,
                right: 16.0,
                bottom: bottomBarHeight + 10.0,
                child: _buildFloatingGlassSearchBar(isDark),
              ),

            // 5. Bottom Floating Liquid Glass Dock (with Standalone Search Pod)
            Positioned(
              bottom: 0,
              left: 0,
              right: 0,
              child: bottomNavBar.buildFloatingDock(context: context),
            ),

            // 6. Top Floating 3-Pods Header (Segmented Three-Islands Apple Glass Header)
            Positioned(
              top: topSafeArea + 6.0,
              left: 14.0,
              right: 14.0,
              child: _buildTopPodsHeader(userProvider, isDark),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // TELEGRAM FOLDER FILTER TABS (CENTERED NAVTABS)
  // ==========================================
  Widget _buildFolderTabs() {
    final isDark = Theme.of(context).brightness == Brightness.dark;
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
      height: 34.0,
      child: Center(
        child: SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          physics: const BouncingScrollPhysics(),
          padding: const EdgeInsets.symmetric(horizontal: 14.0),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            mainAxisAlignment: MainAxisAlignment.center,
            children: tabs.map((tab) {
              final String id = tab['id'] as String;
              final String label = tab['label'] as String;
              final int count = tab['count'] as int;
              final bool isSelected = _selectedFolder == id;

              return Padding(
                padding: const EdgeInsets.symmetric(horizontal: 4.0),
                child: GestureDetector(
                  onTap: () {
                    HapticFeedback.selectionClick();
                    setState(() => _selectedFolder = id);
                  },
                  child: AnimatedContainer(
                    duration: const Duration(milliseconds: 180),
                    padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 6.0),
                    decoration: BoxDecoration(
                      gradient: isSelected
                          ? const LinearGradient(
                              colors: [Color(0xFFF3D010), Color(0xFFE5BF00)],
                            )
                          : null,
                      color: isSelected
                          ? null
                          : (isDark
                              ? const Color(0xFF1E222B).withValues(alpha: 0.85)
                              : Colors.white.withValues(alpha: 0.70)),
                      borderRadius: BorderRadius.circular(18.0),
                      border: Border.all(
                        color: isSelected
                            ? const Color(0xFFFDE047)
                            : (isDark
                                ? Colors.white.withValues(alpha: 0.16)
                                : Colors.white.withValues(alpha: 0.80)),
                        width: 1.0,
                      ),
                      boxShadow: isSelected
                          ? [
                              BoxShadow(
                                color: const Color(0xFFF3D010).withValues(alpha: 0.35),
                                blurRadius: 8,
                                offset: const Offset(0, 2),
                              ),
                            ]
                          : [
                              BoxShadow(
                                color: Colors.black.withValues(alpha: isDark ? 0.25 : 0.05),
                                blurRadius: 6,
                                offset: const Offset(0, 2),
                              ),
                            ],
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          label,
                          style: GoogleFonts.kantumruyPro(
                            color: isSelected
                                ? const Color(0xFF0F172A)
                                : (isDark ? Colors.white : const Color(0xFF0F172A)),
                            fontSize: 12.5,
                            fontWeight: isSelected ? FontWeight.bold : FontWeight.w600,
                          ),
                        ),
                        if (count > 0 && id != 'all') ...[
                          const SizedBox(width: 6.0),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 5.5, vertical: 1.5),
                            decoration: BoxDecoration(
                              color: isSelected
                                  ? Colors.black.withValues(alpha: 0.20)
                                  : (isDark
                                      ? const Color(0xFF334155)
                                      : const Color(0xFFFEF3C7)),
                              borderRadius: BorderRadius.circular(8.0),
                            ),
                            child: Text(
                              '$count',
                              style: GoogleFonts.inter(
                                color: isSelected
                                    ? const Color(0xFF0F172A)
                                    : (isDark
                                        ? const Color(0xFFFDE047)
                                        : const Color(0xFFB45309)),
                                fontSize: 10.5,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
              );
            }).toList(),
          ),
        ),
      ),
    );
  }

  // ==========================================
  // BOTTOM FROSTED GLASS BAR (with Standalone Search Pod)
  // ==========================================
  VvcLiquidGlassBottomBar _buildTelegramFrostedBottomBar(double bottomSafeArea, bool isDark) {
    return VvcLiquidGlassBottomBar(
      currentIndex: 2,
      bottomInset: bottomSafeArea,
      isScrolled: _isScrolled,
      accentColor: const Color(0xFFF3D010),
      backgroundColor: isDark
          ? const Color(0xFF181B22).withValues(alpha: 0.90)
          : const Color(0xFFF1F3F6).withValues(alpha: 0.92),
      borderColor: isDark
          ? Colors.white.withValues(alpha: 0.16)
          : const Color(0xFFE2E8F0),
      unselectedItemColor: isDark
          ? const Color(0xFFCBD5E1)
          : const Color(0xFF64748B),
      trailingAction: AnimatedRotation(
        turns: _isSearchExpanded ? 0.25 : 0.0,
        duration: const Duration(milliseconds: 240),
        child: Icon(
          _isSearchExpanded ? CupertinoIcons.xmark : CupertinoIcons.search,
          color: isDark ? const Color(0xFFF3D010) : const Color(0xFF0F172A),
          size: 24.0,
        ),
      ),
      onTrailingActionTap: () {
        HapticFeedback.lightImpact();
        setState(() {
          _isSearchExpanded = !_isSearchExpanded;
          if (!_isSearchExpanded) {
            searchQuery = '';
            filteredUsers = usersList;
            _searchController.clear();
            _searchFocusNode.unfocus();
          } else {
            _searchFocusNode.requestFocus();
          }
        });
      },
      onTap: (index) {
        if (index == 0) {
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
        } else if (index == 1) {
          HapticFeedback.lightImpact();
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('ប្រព័ន្ធទំនាក់ទំនង និងការហៅផ្ទៃក្នុង', style: GoogleFonts.kantumruyPro()),
              duration: const Duration(seconds: 1),
            ),
          );
        } else if (index == 2) {
          HapticFeedback.lightImpact();
          if (_scrollController.hasClients) {
            _scrollController.animateTo(
              0,
              duration: const Duration(milliseconds: 300),
              curve: Curves.easeOut,
            );
          }
        } else if (index == 3) {
          HapticFeedback.lightImpact();
          Navigator.push(
            context,
            MaterialPageRoute(
              builder: (_) => const StorageUsageScreen(),
            ),
          ).then((_) => _checkCacheSize());
        }
      },
      items: [
        const LiquidGlassItem(
          icon: Icons.people_alt_rounded,
          label: 'បុគ្គលិក',
        ),
        const LiquidGlassItem(
          icon: Icons.phone_rounded,
          label: 'ការហៅ',
        ),
        LiquidGlassItem(
          icon: Icons.chat_bubble_rounded,
          label: 'សារ',
          badgeText: _totalUnreadCount > 0
              ? (_totalUnreadCount > 99 ? '99+' : '$_totalUnreadCount')
              : null,
        ),
        LiquidGlassItem(
          icon: Icons.cleaning_services_rounded,
          label: 'ទំហំផ្ទុក',
          badgeText: _cacheSizeText.isNotEmpty ? _cacheSizeText : null,
        ),
      ],
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
  // TOP 3-PODS FLOATING LIQUID GLASS HEADER
  // ==========================================
  Widget _buildTopPodsHeader(UserProvider user, bool isDark) {
    return VvcFloatingHeaderPods(
      height: 42.0,
      isScrolled: _isScrolled,
      alwaysShowGlass: true,
      alwaysShowTitle: true,
      backgroundColor: isDark
          ? const Color(0xFF181B22).withValues(alpha: 0.88)
          : Colors.white.withValues(alpha: 0.86),
      borderColor: isDark
          ? Colors.white.withValues(alpha: 0.16)
          : const Color(0xFFE2E8F0),
      leadingWidth: 80.0,
      leading: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 6.0),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: [
            // Back arrow
            GestureDetector(
              behavior: HitTestBehavior.opaque,
              onTap: () {
                HapticFeedback.lightImpact();
                Navigator.pop(context);
              },
              child: Padding(
                padding: const EdgeInsets.all(4.0),
                child: Icon(
                  Icons.arrow_back_ios_new_rounded,
                  color: isDark ? Colors.white : const Color(0xFF0F172A),
                  size: 16.0,
                ),
              ),
            ),
            // User avatar (Clickable to open profile screen)
            GestureDetector(
              behavior: HitTestBehavior.opaque,
              onTap: () {
                HapticFeedback.lightImpact();
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const ProfileScreen(),
                  ),
                );
              },
              child: CircleAvatar(
                radius: 14.5,
                backgroundImage: user.avatar != null && user.avatar!.isNotEmpty
                    ? NetworkImage(ApiService.getFullImageUrl(user.avatar!))
                    : null,
                backgroundColor: _getAvatarBgColor(user.name ?? ''),
                child: user.avatar == null || user.avatar!.isEmpty
                    ? Text(
                        (user.name ?? 'U').substring(0, 1).toUpperCase(),
                        style: GoogleFonts.inter(
                          fontWeight: FontWeight.bold,
                          color: Colors.white,
                          fontSize: 11.5,
                        ),
                      )
                    : null,
              ),
            ),
          ],
        ),
      ),
      titleWidget: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            'សារ (Chats)',
            style: GoogleFonts.kantumruyPro(
              fontSize: 15.0,
              fontWeight: FontWeight.bold,
              color: isDark ? Colors.white : const Color(0xFF0F172A),
            ),
          ),
          if (_totalUnreadCount > 0)
            Text(
              '$_totalUnreadCount សារមិនទាន់អាន',
              style: GoogleFonts.kantumruyPro(
                fontSize: 9.5,
                color: const Color(0xFFF3D010),
                fontWeight: FontWeight.w600,
              ),
            ),
        ],
      ),
      actions: [
        // Broom cleaner action
        AnimatedBuilder(
          animation: _broomAnimCtrl,
          builder: (context, child) {
            final scale = 1.0 + (_broomAnimCtrl.value * 0.12);
            return Transform.scale(
              scale: _cacheSizeBytes > 15 * 1024 * 1024 ? scale : 1.0,
              child: Stack(
                clipBehavior: Clip.none,
                alignment: Alignment.center,
                children: [
                  IconButton(
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(minWidth: 36.0, minHeight: 36.0),
                    icon: Icon(
                      Icons.cleaning_services_rounded,
                      size: 18.0,
                      color: isDark ? Colors.white : const Color(0xFF0F172A),
                    ),
                    onPressed: () async {
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
                  if (_cacheSizeText.isNotEmpty)
                    Positioned(
                      right: -2,
                      top: 0,
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 4.0, vertical: 1.0),
                        decoration: BoxDecoration(
                          color: _cacheSizeBytes > 30 * 1024 * 1024
                              ? const Color(0xFFEF4444)
                              : const Color(0xFFFF9500),
                          borderRadius: BorderRadius.circular(8.0),
                          border: Border.all(
                            color: isDark ? const Color(0xFF181B22) : Colors.white,
                            width: 1.0,
                          ),
                        ),
                        child: Text(
                          _cacheSizeText,
                          style: GoogleFonts.inter(
                            color: Colors.white,
                            fontSize: 8.0,
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
        // Compose Pen action
        IconButton(
          padding: EdgeInsets.zero,
          constraints: const BoxConstraints(minWidth: 36.0, minHeight: 36.0),
          icon: Icon(
            Icons.edit_rounded,
            size: 18.0,
            color: isDark ? Colors.white : const Color(0xFF0F172A),
          ),
          onPressed: () {
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
      ],
    );
  }

  // ==========================================
  // FLOATING GLASS SEARCH BAR (EXPANDABLE)
  // ==========================================
  Widget _buildFloatingGlassSearchBar(bool isDark) {
    return ClipRRect(
      borderRadius: BorderRadius.circular(23.0),
      child: BackdropFilter(
        filter: ui.ImageFilter.blur(sigmaX: 20.0, sigmaY: 20.0),
        child: Container(
          height: 46.0,
          padding: const EdgeInsets.symmetric(horizontal: 14.0),
          decoration: BoxDecoration(
            color: isDark
                ? const Color(0xFF1E2638).withValues(alpha: 0.95)
                : Colors.white.withValues(alpha: 0.96),
            borderRadius: BorderRadius.circular(23.0),
            border: Border.all(
              color: isDark
                  ? const Color(0xFF334155)
                  : const Color(0xFFCBD5E1),
              width: 1.0,
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.08),
                blurRadius: 16.0,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: Row(
            children: [
              Icon(
                CupertinoIcons.search,
                color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
                size: 19.0,
              ),
              const SizedBox(width: 10.0),
              Expanded(
                child: TextField(
                  controller: _searchController,
                  focusNode: _searchFocusNode,
                  onChanged: _filterUsers,
                  cursorColor: const Color(0xFFF3D010),
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? Colors.white : const Color(0xFF0F172A),
                    fontSize: 13.5,
                  ),
                  decoration: InputDecoration(
                    hintText: 'ស្វែងរកឈ្មោះបុគ្គលិក ផ្នែក ឬសារ...',
                    hintStyle: GoogleFonts.kantumruyPro(
                      color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
                      fontSize: 13.0,
                    ),
                    filled: false,
                    border: InputBorder.none,
                    enabledBorder: InputBorder.none,
                    focusedBorder: InputBorder.none,
                    disabledBorder: InputBorder.none,
                    errorBorder: InputBorder.none,
                    focusedErrorBorder: InputBorder.none,
                    isDense: true,
                    contentPadding: EdgeInsets.zero,
                  ),
                ),
              ),
              if (_searchController.text.isNotEmpty)
                GestureDetector(
                  onTap: () {
                    _searchController.clear();
                    _filterUsers('');
                  },
                  child: Padding(
                    padding: const EdgeInsets.all(4.0),
                    child: Icon(
                      CupertinoIcons.clear_circled_solid,
                      color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
                      size: 18.0,
                    ),
                  ),
                ),
            ],
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
