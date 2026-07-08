import 'dart:async';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'chat_create_group_screen.dart';
import '../utils/app_theme.dart';
import '../services/api_service.dart';
import '../widgets/app_widgets.dart';
import 'team_chat_screen.dart';

class ChatListScreen extends StatefulWidget {
  const ChatListScreen({super.key});

  @override
  State<ChatListScreen> createState() => _ChatListScreenState();
}

class _ChatListScreenState extends State<ChatListScreen> {
  final ApiService _api = ApiService();
  bool isLoading = true;
  List<dynamic> usersList = [];
  List<dynamic> filteredUsers = [];
  String searchQuery = '';
  List<Map<String, dynamic>> customGroups = [];
  StreamSubscription? _groupsSubscription;
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  Map<String, Timestamp?> chatActivity = {};
  String currentUserId = '';

  final Map<String, Stream<QuerySnapshot>> _unreadStreams = {};

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

            bool isTechnical =
                role.contains('admin') ||
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      extendBodyBehindAppBar: true,
      floatingActionButton: FloatingActionButton.extended(
        backgroundColor: AppTheme.primary,
        onPressed: () => Navigator.push(
          context,
          MaterialPageRoute(
            builder: (_) => ChatCreateGroupScreen(
              allUsers: usersList,
              currentUserId: currentUserId,
            ),
          ),
        ),
        icon: const Icon(Icons.group_add_rounded, color: Colors.white),
        label: Text(
          'បង្កើតក្រុម',
          style: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.bold,
            color: Colors.white,
          ),
        ),
      ),
      appBar: PreferredSize(
        preferredSize: const Size.fromHeight(80),
        child: ClipRRect(
          child: BackdropFilter(
            filter: ImageFilter.blur(sigmaX: 15, sigmaY: 15),
            child: AppBar(
              backgroundColor: AppTheme.bgDark.withValues(alpha: 0.3),
              elevation: 0,
              toolbarHeight: 80,
              leadingWidth: 46,
              leading: Padding(
                padding: const EdgeInsets.only(left: 12),
                child: IconButton(
                  icon: Icon(
                    Icons.arrow_back_ios_new_rounded,
                    color: AppTheme.textPrimary,
                    size: 20,
                  ),
                  onPressed: () => Navigator.pop(context),
                ),
              ),
              title: Column(
                children: [
                  Text(
                    'សារជជែកកម្សាន្ត',
                    style: GoogleFonts.kantumruyPro(
                      fontWeight: FontWeight.bold,
                      fontSize: 20,
                      color: AppTheme.textPrimary,
                    ),
                  ),
                  Text(
                    'VVC HRM Messaging',
                    style: GoogleFonts.inter(
                      fontSize: 10,
                      color: AppTheme.primaryLight,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 1.2,
                    ),
                  ),
                ],
              ),
              centerTitle: true,
            ),
          ),
        ),
      ),
      body: Stack(
        children: [
          Positioned.fill(
            child: Container(
              decoration: BoxDecoration(color: AppTheme.bgSurface),
            ),
          ),
          SafeArea(
            bottom: false,
            child: Column(
              children: [
                _buildSearchBar(),
                Expanded(
                  child: isLoading
                      ? Center(
                          child: CircularProgressIndicator(
                            color: AppTheme.primary,
                          ),
                        )
                      : ListView.builder(
                          physics: const BouncingScrollPhysics(),
                          padding: const EdgeInsets.fromLTRB(20, 10, 20, 40),
                          itemCount:
                              1 + customGroups.length + filteredUsers.length,
                          itemBuilder: (context, index) {
                            if (index == 0) return _buildTeamChatTile();

                            if (index <= customGroups.length) {
                              return _buildGroupTile(customGroups[index - 1]);
                            }

                            final user =
                                filteredUsers[index - 1 - customGroups.length];
                            return _buildUserTile(user, index);
                          },
                        ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSearchBar() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 10, 20, 20),
      child: FadeInDown(
        duration: const Duration(milliseconds: 400),
        child: AppSearchField(
          hintText: "ស្វែងរកឈ្មោះបុគ្គលិក ឬផ្នែក...",
          onChanged: _filterUsers,
          borderRadius: 20,
          backgroundColor: AppTheme.bgCard.withValues(alpha: 0.4),
          borderColor: AppTheme.textPrimary.withValues(alpha: 0.05),
          iconColor: AppTheme.primaryLight,
          hintColor: AppTheme.textMuted,
        ),
      ),
    );
  }

  Widget _buildTeamChatTile() {
    return FadeInUp(
      duration: const Duration(milliseconds: 400),
      child: GestureDetector(
        onTap: () => _navigateToChat('ALL', 'Team Chat Group (ក្រុមរួម)', ''),
        child: Container(
          margin: const EdgeInsets.only(bottom: 24),
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: BorderRadius.circular(28),
            border: Border.all(
              color: AppTheme.primary.withValues(alpha: 0.3),
              width: 1.5,
            ),
          ),
          child: Row(
            children: [
              Container(
                width: 60,
                height: 60,
                decoration: BoxDecoration(
                  color: AppTheme.primary,
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.groups_rounded,
                  color: Colors.white,
                  size: 32,
                ),
              ),
              const SizedBox(width: 18),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Team Chat Group (ក្រុមរួម)',
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary,
                        fontWeight: FontWeight.bold,
                        fontSize: 17,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'ជជែកកម្សាន្តសម្រាប់បុគ្គលិកទាំងអស់',
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.primaryLight.withValues(alpha: 0.9),
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildGroupTile(Map<String, dynamic> group) {
    final String groupId = group['id'];
    final String name = group['name'] ?? 'Group';
    final String lastMsg = group['lastMessage'] ?? '';
    final Map<String, dynamic> members = Map<String, dynamic>.from(
      group['members'] ?? {},
    );
    final String myStatus = members[currentUserId] ?? 'pending';
    final bool isPending = myStatus == 'pending';

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: FadeInRight(
        child: Container(
          decoration: BoxDecoration(
            color: AppTheme.bgCard.withValues(alpha: 0.2),
            borderRadius: BorderRadius.circular(18),
            border: Border.all(
              color: isPending
                  ? Colors.orangeAccent.withValues(alpha: 0.3)
                  : AppTheme.textPrimary.withValues(alpha: 0.05),
            ),
          ),
          child: ListTile(
            contentPadding: const EdgeInsets.symmetric(
              horizontal: 16,
              vertical: 8,
            ),
            leading: Stack(
              children: [
                Container(
                  width: 50,
                  height: 50,
                  decoration: BoxDecoration(
                    color: AppTheme.primary,
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(
                    Icons.groups_rounded,
                    color: Colors.white,
                    size: 28,
                  ),
                ),
                if (isPending)
                  Positioned(
                    right: 0,
                    top: 0,
                    child: Container(
                      width: 14,
                      height: 14,
                      decoration: const BoxDecoration(
                        color: Colors.orangeAccent,
                        shape: BoxShape.circle,
                      ),
                      child: const Icon(
                        Icons.priority_high_rounded,
                        size: 10,
                        color: Colors.white,
                      ),
                    ),
                  ),
              ],
            ),
            title: Text(
              name,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            subtitle: Text(
              isPending ? '🔔 អ្នកត្រូវបានអញ្ជើញឱ្យចូលរួម' : lastMsg,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: GoogleFonts.kantumruyPro(
                color: isPending ? Colors.orangeAccent : AppTheme.textSecondary,
                fontSize: 12,
              ),
            ),
            trailing: Icon(
              Icons.arrow_forward_ios_rounded,
              size: 14,
              color: AppTheme.textMuted,
            ),
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => TeamChatScreen(
                    targetUserId: groupId,
                    targetUserName: name,
                    isGroup: true,
                  ),
                ),
              );
            },
          ),
        ),
      ),
    );
  }

  Widget _buildUserTile(dynamic user, int index) {
    final String title = user['name'] ?? 'Unknown';
    final String targetId = user['employee_id'] ?? '';
    final String avatar = user['avatar'] ?? '';
    final String subtitle = user['position'] ?? 'Employee';

    return FadeInUp(
      delay: Duration(milliseconds: (index * 50).clamp(0, 500)),
      duration: const Duration(milliseconds: 400),
      child: Container(
        margin: const EdgeInsets.only(bottom: 14),
        decoration: BoxDecoration(
          color: AppTheme.bgCard.withValues(alpha: 0.35),
          borderRadius: BorderRadius.circular(22),
          border: Border.all(
            color: AppTheme.textPrimary.withValues(alpha: 0.06),
            width: 1,
          ),
        ),
        child: InkWell(
          onTap: () => _navigateToChat(targetId, title, avatar),
          borderRadius: BorderRadius.circular(22),
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Row(
              children: [
                Stack(
                  clipBehavior: Clip.none,
                  alignment: Alignment.center,
                  children: [
                    AppUserAvatar(
                      url: ApiService.getFullImageUrl(avatar),
                      name: title,
                      size: 52,
                    ),
                    Positioned(
                      bottom: -2,
                      right: -2,
                      child: AppOnlineStatusBadge(employeeId: targetId),
                    ),
                  ],
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontWeight: FontWeight.bold,
                          fontSize: 15.5,
                        ),
                      ),
                      const SizedBox(height: 5),
                      Text(
                        subtitle,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textSecondary,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),
                _buildUnreadBadge(targetId),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildUnreadBadge(String targetId) {
    if (targetId == 'ALL' || currentUserId.isEmpty) {
      return const SizedBox.shrink();
    }
    List<String> ids = [currentUserId, targetId];
    ids.sort();
    final roomId = "PRIVATE_${ids[0]}_${ids[1]}";

    if (!_unreadStreams.containsKey(roomId)) {
      _unreadStreams[roomId] = _firestore
          .collection('chats')
          .doc(roomId)
          .collection('messages')
          .where('isRead', isEqualTo: false)
          .snapshots();
    }

    return StreamBuilder<QuerySnapshot>(
      stream: _unreadStreams[roomId],
      builder: (context, snapshot) {
        if (!snapshot.hasData || snapshot.data!.docs.isEmpty) {
          return const SizedBox.shrink();
        }

        final unreadCount = snapshot.data!.docs.where((doc) {
          final data = doc.data() as Map<String, dynamic>;
          return data['senderId'] != currentUserId;
        }).length;

        if (unreadCount == 0) return const SizedBox.shrink();

        return Container(
          margin: const EdgeInsets.only(left: 8),
          padding: const EdgeInsets.all(6),
          decoration: const BoxDecoration(
            color: Colors.redAccent,
            shape: BoxShape.circle,
          ),
          child: Text(
            '$unreadCount',
            style: GoogleFonts.inter(
              color: Colors.white,
              fontSize: 10,
              fontWeight: FontWeight.bold,
            ),
          ),
        );
      },
    );
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
        builder: (_) => TeamChatScreen(
          targetUserId: id,
          targetUserName: name,
          targetUserPhoto: photo,
          isGroup: isGroup,
        ),
      ),
    );
  }
}
