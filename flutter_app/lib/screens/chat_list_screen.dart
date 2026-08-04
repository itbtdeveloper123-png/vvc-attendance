import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'new_message_screen.dart';
import 'chat_detail_screen.dart';
import '../services/api_service.dart';
import '../providers/user_provider.dart';
import '../widgets/chat_wallpaper_picker.dart';
import 'team_chat_screen.dart';

// ==========================================
// COLOR TOKENS (MESSENGER THEME)
// ==========================================
class MessengerTheme {
  static const Color bg = Color(0xFFFFFFFF);
  static const Color textPrimary = Color(0xFF000000);
  static const Color textSecondary = Color(0xFF65676B);
  static const Color activeBlue = Color(0xFF0084FF);
  static const Color onlineGreen = Color(0xFF44B700);
  static const Color actionBtnBg = Color(0xFFF0F2F5);
  static const Color adBadgeBg = Color(0xFFE4E6EB);
  static const Color unreadDot = Color(0xFF0084FF);
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

class _ChatListScreenState extends State<ChatListScreen> {
  final ApiService _api = ApiService();
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  bool isLoading = true;
  List<dynamic> usersList = [];
  List<dynamic> filteredUsers = [];
  String searchQuery = '';
  List<Map<String, dynamic>> customGroups = [];
  StreamSubscription? _groupsSubscription;
  Map<String, Timestamp?> chatActivity = {};
  String currentUserId = '';

  final Map<String, Stream<QuerySnapshot>> _unreadStreams = {};
  final Map<String, Stream<DocumentSnapshot>> _presenceStreams = {};
  final Map<String, Stream<DocumentSnapshot>> _lastMessageStreams = {};

  @override
  void initState() {
    super.initState();
    _loadCurrentUserId().then((_) {
      _fetchUsersList();
      _listenToActiveChats();
      _listenToGroups();
    });
  }

  @override
  void dispose() {
    _groupsSubscription?.cancel();
    super.dispose();
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
          final groups = snapshot.docs
              .map((doc) => {'id': doc.id, ...doc.data()})
              .toList();

          groups.sort((a, b) {
            final timeA = (a['lastTimestamp'] as Timestamp?)?.toDate() ?? DateTime(1970);
            final timeB = (b['lastTimestamp'] as Timestamp?)?.toDate() ?? DateTime(1970);
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
      for (var doc in snapshot.docs) {
        final data = doc.data();
        final List<dynamic> p = data['participants'] ?? [];
        final otherId = p.firstWhere(
          (id) => id != currentUserId,
          orElse: () => '',
        );
        if (otherId.isNotEmpty) {
          activity[otherId] = data['lastTimestamp'] as Timestamp?;
        }
      }
      if (mounted) {
        setState(() {
          chatActivity = activity;
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
          final List<dynamic> filtered = fetched.where((u) {
            final role = (u['role'] ?? '').toString().toLowerCase();
            final name = (u['name'] ?? '').toString().toLowerCase();
            final eid = (u['employee_id'] ?? '').toString().toLowerCase();

            bool isTechnical = role.contains('admin') ||
                eid.contains('admin') ||
                name.contains('demo') ||
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
        filteredUsers = usersList.where((u) {
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

    return Scaffold(
      backgroundColor: MessengerTheme.bg,
      body: SafeArea(
        child: Column(
          children: [
            // A. Top Messenger-Style Header Bar
            _buildTopHeader(userProvider),

            // Search Bar Container
            _buildSearchBar(),

            // Conversations & Stories Area
            Expanded(
              child: isLoading
                  ? const Center(
                      child: CircularProgressIndicator(color: MessengerTheme.activeBlue),
                    )
                  : ListView(
                      physics: const BouncingScrollPhysics(),
                      children: [
                        const SizedBox(height: 8),
                        // B. Stories horizontal row (Active team online colleagues)
                        _buildStoriesSection(),
                        const SizedBox(height: 16),

                        // C. Main conversations vertical list
                        _buildChatListSection(),
                      ],
                    ),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // TOP APPMBAR HEADER
  // ==========================================
  Widget _buildTopHeader(UserProvider user) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12.0, vertical: 8.0),
      child: Row(
        children: [
          // Back arrow navigation icon
          IconButton(
            icon: const Icon(Icons.arrow_back_ios_new_rounded, color: MessengerTheme.textPrimary, size: 20),
            onPressed: () => Navigator.pop(context),
          ),

          // User avatar
          CircleAvatar(
            radius: 22.0,
            backgroundImage: user.avatar != null && user.avatar!.isNotEmpty
                ? NetworkImage(ApiService.getFullImageUrl(user.avatar!))
                : null,
            backgroundColor: _getAvatarBgColor(user.name ?? ''),
            child: user.avatar == null || user.avatar!.isEmpty
                ? Text(
                    (user.name ?? 'U').substring(0, 1).toUpperCase(),
                    style: GoogleFonts.inter(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 14),
                  )
                : null,
          ),
          const SizedBox(width: 10.0),

          // Title "Chats" (សារ)
          Expanded(
            child: Text(
              'សារ',
              style: GoogleFonts.kantumruyPro(
                fontSize: 24.0,
                fontWeight: FontWeight.bold,
                color: MessengerTheme.textPrimary,
              ),
            ),
          ),

          // Action rounded buttons
          _buildActionButton(
            icon: Icons.camera_alt_rounded,
            onTap: () {},
          ),
          const SizedBox(width: 10.0),
          _buildActionButton(
            icon: Icons.edit_rounded,
            onTap: () {
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
      ),
    );
  }

  Widget _buildActionButton({required IconData icon, required VoidCallback onTap}) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 36.0,
        height: 36.0,
        decoration: const BoxDecoration(
          color: MessengerTheme.actionBtnBg,
          shape: BoxShape.circle,
        ),
        child: Icon(icon, size: 18.0, color: MessengerTheme.textPrimary),
      ),
    );
  }

  // ==========================================
  // SEARCH BAR
  // ==========================================
  Widget _buildSearchBar() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 6.0),
      child: Container(
        height: 38.0,
        decoration: BoxDecoration(
          color: MessengerTheme.actionBtnBg,
          borderRadius: BorderRadius.circular(10.0),
        ),
        padding: const EdgeInsets.symmetric(horizontal: 12.0),
        child: Row(
          children: [
            const Icon(Icons.search_rounded, color: MessengerTheme.textSecondary, size: 20.0),
            const SizedBox(width: 8.0),
            Expanded(
              child: TextField(
                onChanged: _filterUsers,
                cursorColor: MessengerTheme.activeBlue,
                style: GoogleFonts.kantumruyPro(
                  color: MessengerTheme.textPrimary,
                  fontSize: 14.5,
                ),
                decoration: InputDecoration(
                  hintText: 'ស្វែងរកឈ្មោះបុគ្គលិក ឬផ្នែក...',
                  hintStyle: GoogleFonts.kantumruyPro(
                    color: MessengerTheme.textSecondary,
                    fontSize: 14.0,
                  ),
                  border: InputBorder.none,
                  isDense: true,
                  contentPadding: EdgeInsets.zero,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // ACTIVE STORIES ROW
  // ==========================================
  Widget _buildStoriesSection() {
    // Show top 8 colleagues from usersList as Active Stories
    final storyUsers = usersList.take(8).toList();

    return SizedBox(
      height: 106.0,
      child: ListView.builder(
        scrollDirection: Axis.horizontal,
        physics: const BouncingScrollPhysics(),
        padding: const EdgeInsets.symmetric(horizontal: 16.0),
        itemCount: storyUsers.length + 1, // First item is "Your Story"
        itemBuilder: (context, index) {
          if (index == 0) {
            return Container(
              margin: const EdgeInsets.only(right: 14.0),
              child: Column(
                children: [
                  Container(
                    width: 60.0,
                    height: 60.0,
                    decoration: BoxDecoration(
                      color: MessengerTheme.actionBtnBg,
                      shape: BoxShape.circle,
                      border: Border.all(color: Colors.grey.shade300, width: 0.8),
                    ),
                    child: const Icon(Icons.add_rounded, size: 28.0, color: MessengerTheme.textPrimary),
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
            );
          }

          final user = storyUsers[index - 1];
          final String name = user['name'] ?? 'Colleague';
          final String targetId = user['employee_id'] ?? '';
          final String avatar = user['avatar'] ?? '';
          final String firstName = name.split(' ').last;

          if (!_presenceStreams.containsKey(targetId)) {
            _presenceStreams[targetId] = _firestore.collection('users').doc(targetId).snapshots();
          }

          return StreamBuilder<DocumentSnapshot>(
            stream: _presenceStreams[targetId],
            builder: (context, snapshot) {
              bool isOnline = false;
              if (snapshot.hasData && snapshot.data!.exists) {
                final data = snapshot.data!.data() as Map<String, dynamic>?;
                isOnline = data?['isOnline'] == true;
              }

              return Container(
                margin: const EdgeInsets.only(right: 14.0),
                child: Column(
                  children: [
                    Stack(
                      children: [
                        // Border highlight for story
                        Container(
                          padding: const EdgeInsets.all(2.0),
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: isOnline ? MessengerTheme.activeBlue : Colors.grey.shade300,
                              width: 2.0,
                            ),
                          ),
                          child: CircleAvatar(
                            radius: 28.0,
                            backgroundImage: avatar.isNotEmpty ? NetworkImage(ApiService.getFullImageUrl(avatar)) : null,
                            backgroundColor: _getAvatarBgColor(name),
                            child: avatar.isEmpty
                                ? Text(
                                    name.isNotEmpty ? name.substring(0, 1).toUpperCase() : 'U',
                                    style: GoogleFonts.inter(fontWeight: FontWeight.bold, fontSize: 16, color: Colors.white),
                                  )
                                : null,
                          ),
                        ),
                        // Online status indicator badge
                        if (isOnline)
                          Positioned(
                            right: 2.0,
                            bottom: 2.0,
                            child: Container(
                              width: 12.0,
                              height: 12.0,
                              decoration: BoxDecoration(
                                color: MessengerTheme.onlineGreen,
                                shape: BoxShape.circle,
                                border: Border.all(color: Colors.white, width: 2.0),
                              ),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 8.0),
                    SizedBox(
                      width: 60.0,
                      child: Text(
                        firstName,
                        textAlign: TextAlign.center,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: GoogleFonts.kantumruyPro(
                          fontSize: 11.5,
                          fontWeight: isOnline ? FontWeight.w700 : FontWeight.w500,
                          color: isOnline ? MessengerTheme.textPrimary : MessengerTheme.textSecondary,
                        ),
                      ),
                    ),
                  ],
                ),
              );
            },
          );
        },
      ),
    );
  }

  // ==========================================
  // CONVERSATIONS LIST
  // ==========================================
  Widget _buildChatListSection() {
    const int adIndex = 3; // Inject Sponsored Ad at index 3
    final int listLength = 1 + customGroups.length + filteredUsers.length + 1; // +1 group template +1 Ad

    return ListView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      itemCount: listLength,
      itemBuilder: (context, index) {
        // 1. Team General Group Chat at top (Index 0)
        if (index == 0) {
          return _buildTeamGeneralGroupTile();
        }

        // 2. Custom created Groups
        if (index > 0 && index <= customGroups.length) {
          return _buildCustomGroupTile(customGroups[index - 1]);
        }

        // 3. Sponsored Porsche Ad (Ad Index)
        if (index == adIndex) {
          return _buildPorscheAdTile();
        }

        // 4. Team Members private chats (Index offset adjustments for Ad and Groups)
        final int userIdx = index - 1 - customGroups.length - (index > adIndex ? 1 : 0);
        if (userIdx >= 0 && userIdx < filteredUsers.length) {
          final user = filteredUsers[userIdx];
          return _buildUserConversationTile(user);
        }

        return const SizedBox.shrink();
      },
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
          onTap: () => _navigateToChat('ALL', 'Team Chat Group (ក្រុមរួម)', '', isGroup: true),
          onLongPress: () => showChatWallpaperPicker(
            context,
            targetId: 'ALL',
            targetName: 'Team Chat Group',
            onWallpaperSelected: (_) {},
          ),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
            child: Row(
              children: [
                const CircleAvatar(
                  radius: 30.0,
                  backgroundColor: MessengerTheme.activeBlue,
                  child: Icon(Icons.groups_rounded, color: Colors.white, size: 30),
                ),
                const SizedBox(width: 14.0),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Team Chat Group (ក្រុមរួម)',
                        style: GoogleFonts.kantumruyPro(fontSize: 15.5, fontWeight: FontWeight.w600, color: MessengerTheme.textPrimary),
                      ),
                      const SizedBox(height: 4.0),
                      Row(
                        children: [
                          Flexible(
                            child: Text(
                              lastMsg,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: GoogleFonts.kantumruyPro(fontSize: 13.5, color: MessengerTheme.textSecondary),
                            ),
                          ),
                          if (timeStr.isNotEmpty) ...[
                            const Padding(
                              padding: EdgeInsets.symmetric(horizontal: 6.0),
                              child: Text('•', style: TextStyle(fontSize: 11, color: MessengerTheme.textSecondary)),
                            ),
                            Text(timeStr, style: GoogleFonts.inter(fontSize: 13.0, color: MessengerTheme.textSecondary)),
                          ],
                        ],
                      ),
                    ],
                  ),
                ),
                const Icon(Icons.arrow_forward_ios_rounded, size: 12.0, color: Colors.black26),
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
      onLongPress: () => showChatWallpaperPicker(
        context,
        targetId: groupId,
        targetName: name,
        onWallpaperSelected: (_) {},
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
        child: Row(
          children: [
            CircleAvatar(
              radius: 30.0,
              backgroundColor: Colors.indigo.shade400,
              child: const Icon(Icons.forum_rounded, color: Colors.white, size: 28),
            ),
            const SizedBox(width: 14.0),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    name,
                    style: GoogleFonts.kantumruyPro(fontSize: 15.5, fontWeight: FontWeight.w600, color: MessengerTheme.textPrimary),
                  ),
                  const SizedBox(height: 4.0),
                  Row(
                    children: [
                      Flexible(
                        child: Text(
                          lastMsg.isNotEmpty ? lastMsg : 'គ្មានសារកម្សាន្តនៅឡើយទេ',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: GoogleFonts.kantumruyPro(fontSize: 13.5, color: MessengerTheme.textSecondary),
                        ),
                      ),
                      if (timeStr.isNotEmpty) ...[
                        const Padding(
                          padding: EdgeInsets.symmetric(horizontal: 6.0),
                          child: Text('•', style: TextStyle(fontSize: 11, color: MessengerTheme.textSecondary)),
                        ),
                        Text(timeStr, style: GoogleFonts.inter(fontSize: 13.0, color: MessengerTheme.textSecondary)),
                      ],
                    ],
                  ),
                ],
              ),
            ),
            const Icon(Icons.arrow_forward_ios_rounded, size: 12.0, color: Colors.black26),
          ],
        ),
      ),
    );
  }

  // Sponsored Porsche Ad
  Widget _buildPorscheAdTile() {
    return InkWell(
      onTap: () {},
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
        child: Row(
          children: [
            CircleAvatar(
              radius: 30.0,
              backgroundColor: const Color(0xFFF9FAFB),
              child: ClipOval(
                child: Image.network(
                  'https://images.unsplash.com/photo-1614162692292-7ac56d7f7f1e?w=120&auto=format&fit=crop',
                  width: 60.0,
                  height: 60.0,
                  fit: BoxFit.cover,
                ),
              ),
            ),
            const SizedBox(width: 14.0),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        'Porsche',
                        style: GoogleFonts.inter(fontSize: 15.5, fontWeight: FontWeight.bold, color: MessengerTheme.textPrimary),
                      ),
                      const SizedBox(width: 6.0),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 5.0, vertical: 1.5),
                        decoration: BoxDecoration(
                          color: MessengerTheme.adBadgeBg,
                          borderRadius: BorderRadius.circular(4.0),
                        ),
                        child: Text(
                          'Ad',
                          style: GoogleFonts.inter(fontSize: 9.0, fontWeight: FontWeight.w700, color: MessengerTheme.textSecondary),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4.0),
                  Text(
                    'The new Macan',
                    style: GoogleFonts.kantumruyPro(fontSize: 13.5, color: MessengerTheme.textSecondary),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2.0),
                  Text(
                    'មើលបន្ថែម',
                    style: GoogleFonts.kantumruyPro(fontSize: 13.5, fontWeight: FontWeight.bold, color: MessengerTheme.activeBlue),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8.0),
            ClipRRect(
              borderRadius: BorderRadius.circular(8.0),
              child: Image.network(
                'https://images.unsplash.com/photo-1614162692292-7ac56d7f7f1e?w=150&auto=format&fit=crop',
                width: 50.0,
                height: 50.0,
                fit: BoxFit.cover,
              ),
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

    if (currentUserId.isEmpty || targetId.isEmpty) return const SizedBox.shrink();

    final List<String> ids = [currentUserId, targetId];
    ids.sort();
    final String roomId = "PRIVATE_${ids[0]}_${ids[1]}";

    // 1. Unread stream caching
    if (!_unreadStreams.containsKey(roomId)) {
      _unreadStreams[roomId] = _firestore
          .collection('chats')
          .doc(roomId)
          .collection('messages')
          .where('isRead', isEqualTo: false)
          .snapshots();
    }

    // 2. Presence stream caching
    if (!_presenceStreams.containsKey(targetId)) {
      _presenceStreams[targetId] = _firestore.collection('users').doc(targetId).snapshots();
    }

    // 3. Last Message stream caching
    if (!_lastMessageStreams.containsKey(roomId)) {
      _lastMessageStreams[roomId] = _firestore.collection('chats').doc(roomId).snapshots();
    }

    return StreamBuilder<DocumentSnapshot>(
      stream: _presenceStreams[targetId],
      builder: (context, presenceSnapshot) {
        bool isOnline = false;
        if (presenceSnapshot.hasData && presenceSnapshot.data!.exists) {
          final data = presenceSnapshot.data!.data() as Map<String, dynamic>?;
          isOnline = data?['isOnline'] == true;
        }

        return StreamBuilder<QuerySnapshot>(
          stream: _unreadStreams[roomId],
          builder: (context, unreadSnapshot) {
            int unreadCount = 0;
            if (unreadSnapshot.hasData) {
              unreadCount = unreadSnapshot.data!.docs.where((doc) {
                final data = doc.data() as Map<String, dynamic>;
                return data['senderId'] != currentUserId;
              }).length;
            }
            final bool isUnread = unreadCount > 0;

            return StreamBuilder<DocumentSnapshot>(
              stream: _lastMessageStreams[roomId],
              builder: (context, chatSnapshot) {
                String lastMsg = position;
                String timeStr = '';
                bool isLastMessageByMe = false;

                if (chatSnapshot.hasData && chatSnapshot.data!.exists) {
                  final chatData = chatSnapshot.data!.data() as Map<String, dynamic>?;
                  if (chatData != null) {
                    final rawLastMsg = chatData['lastMessage'] ?? '';
                    final Timestamp? ts = chatData['lastTimestamp'] as Timestamp?;
                    final lastSenderId = chatData['lastSenderId'] ?? '';
                    
                    if (rawLastMsg.isNotEmpty) {
                      isLastMessageByMe = lastSenderId == currentUserId;
                      lastMsg = isLastMessageByMe ? "អ្នក៖ $rawLastMsg" : rawLastMsg;
                    }
                    if (ts != null) {
                      timeStr = _formatTimestamp(ts);
                    }
                  }
                }

                return InkWell(
                  onTap: () => _navigateToChat(targetId, title, avatar),
                  onLongPress: () => showChatWallpaperPicker(
                    context,
                    targetId: targetId,
                    targetName: title,
                    onWallpaperSelected: (_) {},
                  ),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
                    child: Row(
                      children: [
                        // Left profile picture with online indicator
                        Stack(
                          children: [
                            CircleAvatar(
                              radius: 32.0,
                              backgroundImage: avatar.isNotEmpty ? NetworkImage(ApiService.getFullImageUrl(avatar)) : null,
                              backgroundColor: _getAvatarBgColor(title),
                              child: avatar.isEmpty
                                  ? Text(
                                      title.isNotEmpty ? title.substring(0, 1).toUpperCase() : 'U',
                                      style: GoogleFonts.inter(fontWeight: FontWeight.bold, fontSize: 18, color: Colors.white),
                                    )
                                  : null,
                            ),
                            if (isOnline)
                              Positioned(
                                right: 0.0,
                                bottom: 0.0,
                                child: Container(
                                  width: 14.0,
                                  height: 14.0,
                                  decoration: const BoxDecoration(
                                    color: MessengerTheme.onlineGreen,
                                    shape: BoxShape.circle,
                                    border: Border.fromBorderSide(BorderSide(color: Colors.white, width: 2.0)),
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
                                  fontSize: 15.5,
                                  fontWeight: isUnread ? FontWeight.bold : FontWeight.w600,
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
                                        fontSize: 13.5,
                                        fontWeight: isUnread ? FontWeight.w800 : FontWeight.normal,
                                        color: isUnread ? MessengerTheme.textPrimary : MessengerTheme.textSecondary,
                                      ),
                                    ),
                                  ),
                                  if (timeStr.isNotEmpty) ...[
                                    const Padding(
                                      padding: EdgeInsets.symmetric(horizontal: 6.0),
                                      child: Text('•', style: TextStyle(fontSize: 11, color: MessengerTheme.textSecondary)),
                                    ),
                                    Text(
                                      timeStr,
                                      style: GoogleFonts.inter(
                                        fontSize: 13.0,
                                        fontWeight: isUnread ? FontWeight.w700 : FontWeight.normal,
                                        color: isUnread ? MessengerTheme.textPrimary : MessengerTheme.textSecondary,
                                      ),
                                    ),
                                  ],
                                ],
                              ),
                            ],
                          ),
                        ),

                        // Unread dot indicator or delivery status
                        _buildConversationStatus(isUnread, isLastMessageByMe),
                      ],
                    ),
                  ),
                );
              },
            );
          },
        );
      },
    );
  }

  Widget _buildConversationStatus(bool isUnread, bool isLastMessageByMe) {
    if (isUnread) {
      return Container(
        width: 12.0,
        height: 12.0,
        decoration: const BoxDecoration(
          color: MessengerTheme.unreadDot,
          shape: BoxShape.circle,
        ),
      );
    }
    if (isLastMessageByMe) {
      return Container(
        width: 14.0,
        height: 14.0,
        decoration: BoxDecoration(
          color: Colors.grey.shade100,
          shape: BoxShape.circle,
        ),
        child: const Icon(Icons.check_rounded, size: 9.0, color: Colors.black38),
      );
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
        builder: (_) => isGroup
            ? TeamChatScreen(
                targetUserId: id,
                targetUserName: name,
                targetUserPhoto: photo,
                isGroup: true,
              )
            : ChatDetailScreen(
                targetUserId: id,
                targetUserName: name,
                targetUserPhoto: photo,
              ),
      ),
    );
  }
}
