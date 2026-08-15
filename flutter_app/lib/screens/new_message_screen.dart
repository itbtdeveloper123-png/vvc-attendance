import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../utils/app_theme.dart';
import '../services/api_service.dart';
import 'chat_detail_screen.dart';
import 'chat_create_group_screen.dart';
import 'add_story_screen.dart';
import 'community_channel_screen.dart';
import 'ai_chat_screen.dart';

Color _getAvatarBgColor(String name) {
  if (name.isEmpty) return const Color(0xFFD4AF37);
  const colors = [
    Color(0xFFD4AF37),
    Color(0xFF38BDF8),
    Color(0xFFA855F7),
    Color(0xFF10B981),
    Color(0xFFF59E0B),
    Color(0xFFEC4899),
    Color(0xFF6366F1),
  ];
  return colors[name.codeUnitAt(0) % colors.length];
}

class NewMessageScreen extends StatefulWidget {
  final List<dynamic> allUsers;
  final String currentUserId;

  const NewMessageScreen({
    super.key,
    this.allUsers = const [],
    this.currentUserId = '',
  });

  @override
  State<NewMessageScreen> createState() => _NewMessageScreenState();
}

class _NewMessageScreenState extends State<NewMessageScreen> {
  final TextEditingController _searchController = TextEditingController();
  final ApiService _api = ApiService();
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  String _myId = '';
  List<dynamic> _usersList = [];
  List<dynamic> _filteredUsers = [];
  bool _isLoading = true;
  String _searchQuery = '';

  // Realtime Presence Map: employee_id -> isOnline
  Map<String, bool> _onlineStatusMap = {};

  @override
  void initState() {
    super.initState();
    _myId = widget.currentUserId;
    _initData();
    _searchController.addListener(_onSearchChanged);
    _listenToPresence();
  }

  Future<void> _initData() async {
    if (_myId.isEmpty) {
      final prefs = await SharedPreferences.getInstance();
      _myId = prefs.getString('employee_id') ?? '';
    }

    if (widget.allUsers.isNotEmpty) {
      _processUsers(widget.allUsers);
    } else {
      await _fetchUsersFromApi();
    }
  }

  Future<void> _fetchUsersFromApi() async {
    try {
      final res = await _api.fetchUsers();
      if (res['success'] == true) {
        final List<dynamic> fetched = res['users'] ?? [];
        _processUsers(fetched);
      } else {
        if (mounted) setState(() => _isLoading = false);
      }
    } catch (e) {
      debugPrint('Error fetching users in NewMessageScreen: $e');
      if (mounted) setState(() => _isLoading = false);
    }
  }

  void _processUsers(List<dynamic> rawList) {
    final List<dynamic> filtered = rawList.where((u) {
      final String eid = (u['employee_id'] ?? u['id'] ?? '').toString();
      if (eid == _myId && _myId.isNotEmpty) return false;

      final role = (u['role'] ?? '').toString().toLowerCase();
      final name = (u['name'] ?? '').toString().toLowerCase();

      bool isTechnical =
          role == 'admin_panel' ||
          eid == 'admin_panel' ||
          name.contains('it-by-vvc') ||
          name.isEmpty;

      return !isTechnical;
    }).toList();

    if (mounted) {
      setState(() {
        _usersList = filtered;
        _filteredUsers = filtered;
        _isLoading = false;
      });
    }
  }

  void _listenToPresence() {
    _firestore.collection('users').snapshots().listen((snapshot) {
      final Map<String, bool> statusMap = {};
      for (var doc in snapshot.docs) {
        final data = doc.data();
        final bool isOnline = data['isOnline'] == true;
        // Map both doc.id and employee_id
        statusMap[doc.id] = isOnline;
        if (data['employee_id'] != null) {
          statusMap[data['employee_id'].toString()] = isOnline;
        }
      }
      if (mounted) {
        setState(() {
          _onlineStatusMap = statusMap;
        });
      }
    });
  }

  void _onSearchChanged() {
    final query = _searchController.text.trim().toLowerCase();
    setState(() {
      _searchQuery = query;
      if (query.isEmpty) {
        _filteredUsers = _usersList;
      } else {
        _filteredUsers = _usersList.where((u) {
          final name = (u['name'] ?? '').toString().toLowerCase();
          final eid = (u['employee_id'] ?? u['id'] ?? '').toString().toLowerCase();
          final dept = (u['department'] ?? '').toString().toLowerCase();
          final pos = (u['position'] ?? '').toString().toLowerCase();
          return name.contains(query) ||
              eid.contains(query) ||
              dept.contains(query) ||
              pos.contains(query);
        }).toList();
      }
    });
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _hapticLight() => HapticFeedback.lightImpact();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 1. Top VVC Header
            _buildTopHeader(),

            // 2. Search Box
            _buildSearchRow(),

            const SizedBox(height: 8),

            // 3. Main Body: Actions + Contacts
            Expanded(
              child: _isLoading
                  ? Center(
                      child: CircularProgressIndicator(
                        color: AppTheme.primary,
                      ),
                    )
                  : ListView(
                      physics: const BouncingScrollPhysics(),
                      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
                      children: [
                        // Quick Action Bento Cards (Only shown when not searching)
                        if (_searchQuery.isEmpty) ...[
                          _buildQuickActionsSection(),
                          const SizedBox(height: 16.0),
                        ],

                        // Contacts Section Header
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Text(
                              _searchQuery.isEmpty
                                  ? '👥 បុគ្គលិក និងទំនាក់ទំនង'
                                  : 'លទ្ធផលស្វែងរក (${_filteredUsers.length})',
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textSecondary,
                                fontSize: 13.5,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                              decoration: BoxDecoration(
                                color: Colors.white.withValues(alpha: 0.06),
                                borderRadius: BorderRadius.circular(12),
                              ),
                              child: Text(
                                '${_filteredUsers.length} នាក់',
                                style: GoogleFonts.inter(
                                  color: AppTheme.primary,
                                  fontSize: 11.5,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 10.0),

                        if (_filteredUsers.isEmpty)
                          Padding(
                            padding: const EdgeInsets.all(40.0),
                            child: Center(
                              child: Column(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(
                                    Icons.person_search_rounded,
                                    color: AppTheme.textMuted,
                                    size: 48,
                                  ),
                                  const SizedBox(height: 12),
                                  Text(
                                    'រកមិនឃើញបុគ្គលិកឡើយ',
                                    style: GoogleFonts.kantumruyPro(
                                      color: AppTheme.textMuted,
                                      fontSize: 14,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          )
                        else
                          ..._filteredUsers.map((u) {
                            final String targetId = (u['employee_id'] ?? u['id'] ?? '').toString();
                            final String name = (u['name'] ?? u['username'] ?? 'User').toString();
                            final String avatar = (u['avatar'] ?? u['photoUrl'] ?? u['photo'] ?? '').toString();
                            final String position = (u['position'] ?? u['department'] ?? '').toString();
                            final bool isOnline = _onlineStatusMap[targetId] == true;
                            final bool isVerified = (u['role'] ?? '').toString().toLowerCase() == 'admin' ||
                                (u['system_role'] ?? '').toString().toLowerCase() == 'admin';

                            return _buildContactCard(
                              name: name,
                              avatarUrl: avatar,
                              position: position,
                              isOnline: isOnline,
                              isVerified: isVerified,
                              onTap: () {
                                _hapticLight();
                                Navigator.pushReplacement(
                                  context,
                                  MaterialPageRoute(
                                    builder: (_) => ChatDetailScreen(
                                      targetUserId: targetId,
                                      targetUserName: name,
                                      targetUserPhoto: avatar,
                                    ),
                                  ),
                                );
                              },
                            );
                          }),
                      ],
                    ),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // TOP HEADER (VVC ENTERPRISE STYLE)
  // ==========================================
  Widget _buildTopHeader() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
      child: Row(
        children: [
          // Back Button
          GestureDetector(
            onTap: () {
              _hapticLight();
              Navigator.pop(context);
            },
            child: Container(
              padding: const EdgeInsets.all(9),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                shape: BoxShape.circle,
                border: Border.all(
                  color: Colors.white.withValues(alpha: 0.1),
                ),
              ),
              child: const Icon(
                Icons.arrow_back_ios_new_rounded,
                color: Colors.white,
                size: 17,
              ),
            ),
          ),
          const SizedBox(width: 14),

          // Title & Subtitle
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'ផ្ញើសារថ្មី (New Message)',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontSize: 16.5,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                Text(
                  'ជ្រើសរើសបុគ្គលិក ឬបង្កើតក្រុមការងារ',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textMuted,
                    fontSize: 11.5,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // SEARCH INPUT (GLASSMORPHIC VVC STYLE)
  // ==========================================
  Widget _buildSearchRow() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 6.0),
      child: Container(
        height: 44.0,
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(14.0),
          border: Border.all(
            color: Colors.white.withValues(alpha: 0.08),
          ),
        ),
        child: Row(
          children: [
            const SizedBox(width: 12),
            const Icon(
              Icons.search_rounded,
              color: Color(0xFFD4AF37),
              size: 20,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: TextField(
                controller: _searchController,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontSize: 13.5,
                ),
                cursorColor: AppTheme.primary,
                decoration: InputDecoration(
                  hintText: 'ស្វែងរកឈ្មោះបុគ្គលិក ឬផ្នែក...',
                  hintStyle: GoogleFonts.kantumruyPro(
                    color: AppTheme.textMuted,
                    fontSize: 13.0,
                  ),
                  border: InputBorder.none,
                  isDense: true,
                  contentPadding: const EdgeInsets.symmetric(vertical: 10),
                ),
              ),
            ),
            if (_searchController.text.isNotEmpty)
              GestureDetector(
                onTap: () {
                  _searchController.clear();
                },
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 10),
                  child: Icon(
                    Icons.cancel_rounded,
                    color: AppTheme.textMuted,
                    size: 18,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // QUICK ACTIONS SECTION (BENTO GRID TILES)
  // ==========================================
  Widget _buildQuickActionsSection() {
    return Column(
      children: [
        // 1. Create Group Card
        _buildActionTile(
          icon: Icons.group_add_rounded,
          gradientColors: [const Color(0xFFD4AF37), const Color(0xFFB8860B)],
          title: 'បង្កើតក្រុមការងារ (Team Group)',
          subtitle: 'ជជែក និងចែករំលែកឯកសារជាក្រុម',
          onTap: () {
            _hapticLight();
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => ChatCreateGroupScreen(
                  allUsers: _usersList,
                  currentUserId: _myId,
                ),
              ),
            );
          },
        ),
        const SizedBox(height: 8),

        // 2. Community Channel Card
        _buildActionTile(
          icon: Icons.campaign_rounded,
          gradientColors: [const Color(0xFFA855F7), const Color(0xFF7C3AED)],
          title: 'ប៉ុស្តិ៍សហគមន៍ (Community Channel)',
          subtitle: 'ដំណឹងក្រុមហ៊ុន និងការផ្សព្វផ្សាយផ្លូវការ',
          onTap: () {
            _hapticLight();
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => const CommunityChannelScreen(),
              ),
            );
          },
        ),
        const SizedBox(height: 8),

        // 3. New Story Card
        _buildActionTile(
          icon: Icons.add_photo_alternate_rounded,
          gradientColors: [const Color(0xFF38BDF8), const Color(0xFF0284C7)],
          title: 'ចែករំលែក Story ថ្មី (Post Story)',
          subtitle: 'រូបភាព ឬវីដេអូបច្ចុប្បន្នភាព ២៤ ម៉ោង',
          onTap: () {
            _hapticLight();
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => const AddStoryScreen(),
              ),
            );
          },
        ),
        const SizedBox(height: 8),

        // 4. AI Assistant
        _buildActionTile(
          icon: Icons.smart_toy_rounded,
          gradientColors: [const Color(0xFF10B981), const Color(0xFF059669)],
          title: 'ជំនួយការ VVC AI Assistant',
          subtitle: 'ឆ្លើយសំណួរ គណនា និងវិភាគទិន្នន័យ',
          onTap: () {
            _hapticLight();
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => const AiChatScreen(),
              ),
            );
          },
        ),
      ],
    );
  }

  Widget _buildActionTile({
    required IconData icon,
    required List<Color> gradientColors,
    required String title,
    required String subtitle,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 12.0),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(16.0),
          border: Border.all(
            color: Colors.white.withValues(alpha: 0.07),
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.15),
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Row(
          children: [
            Container(
              width: 42.0,
              height: 42.0,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: gradientColors,
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                borderRadius: BorderRadius.circular(12.0),
                boxShadow: [
                  BoxShadow(
                    color: gradientColors.first.withValues(alpha: 0.3),
                    blurRadius: 8,
                    offset: const Offset(0, 3),
                  ),
                ],
              ),
              child: Icon(icon, color: Colors.white, size: 22.0),
            ),
            const SizedBox(width: 14.0),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary,
                      fontSize: 13.5,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    subtitle,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textMuted,
                      fontSize: 11.0,
                    ),
                  ),
                ],
              ),
            ),
            const Icon(
              Icons.chevron_right_rounded,
              color: Colors.white38,
              size: 20.0,
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // CONTACT CARD (VVC ENTERPRISE STYLE)
  // ==========================================
  Widget _buildContactCard({
    required String name,
    required String avatarUrl,
    required String position,
    required bool isOnline,
    required bool isVerified,
    required VoidCallback onTap,
  }) {
    final fullAvatar = avatarUrl.isNotEmpty ? ApiService.getFullImageUrl(avatarUrl) : '';

    return Padding(
      padding: const EdgeInsets.only(bottom: 8.0),
      child: GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 10.0),
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: BorderRadius.circular(16.0),
            border: Border.all(
              color: Colors.white.withValues(alpha: 0.05),
            ),
          ),
          child: Row(
            children: [
              // Avatar with Online indicator
              Stack(
                children: [
                  Container(
                    width: 46.0,
                    height: 46.0,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(
                        color: isOnline
                            ? const Color(0xFF10B981)
                            : Colors.white.withValues(alpha: 0.15),
                        width: 1.5,
                      ),
                    ),
                    child: ClipOval(
                      child: fullAvatar.isNotEmpty
                          ? Image.network(
                              fullAvatar,
                              fit: BoxFit.cover,
                              errorBuilder: (_, __, ___) => _buildInitials(name),
                            )
                          : _buildInitials(name),
                    ),
                  ),
                  if (isOnline)
                    Positioned(
                      right: 1.0,
                      bottom: 1.0,
                      child: Container(
                        width: 11.0,
                        height: 11.0,
                        decoration: BoxDecoration(
                          color: const Color(0xFF10B981),
                          shape: BoxShape.circle,
                          border: Border.all(color: AppTheme.bgCard, width: 2.0),
                        ),
                      ),
                    ),
                ],
              ),
              const SizedBox(width: 12.0),

              // Name & Position
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Flexible(
                          child: Text(
                            name,
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.textPrimary,
                              fontSize: 14.0,
                              fontWeight: FontWeight.bold,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (isVerified) ...[
                          const SizedBox(width: 4.0),
                          const Icon(
                            Icons.verified_rounded,
                            color: Color(0xFF38BDF8),
                            size: 15.0,
                          ),
                        ],
                      ],
                    ),
                    const SizedBox(height: 3.0),
                    Row(
                      children: [
                        if (position.isNotEmpty) ...[
                          Flexible(
                            child: Text(
                              position,
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textSecondary,
                                fontSize: 11.5,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          const SizedBox(width: 6),
                          Container(
                            width: 3,
                            height: 3,
                            decoration: const BoxDecoration(
                              color: Colors.white24,
                              shape: BoxShape.circle,
                            ),
                          ),
                          const SizedBox(width: 6),
                        ],
                        Text(
                          isOnline ? 'Online' : 'ក្រៅបណ្តាញ',
                          style: GoogleFonts.kantumruyPro(
                            color: isOnline ? const Color(0xFF10B981) : AppTheme.textMuted,
                            fontSize: 11.0,
                            fontWeight: isOnline ? FontWeight.w600 : FontWeight.normal,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),

              // Right Action Icon
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.05),
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.chat_bubble_outline_rounded,
                  color: Color(0xFFD4AF37),
                  size: 18,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildInitials(String name) {
    return Container(
      color: _getAvatarBgColor(name),
      alignment: Alignment.center,
      child: Text(
        name.isNotEmpty ? name[0].toUpperCase() : 'U',
        style: GoogleFonts.inter(
          color: Colors.white,
          fontWeight: FontWeight.bold,
          fontSize: 17.0,
        ),
      ),
    );
  }
}
