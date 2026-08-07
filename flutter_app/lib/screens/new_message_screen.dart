import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../services/api_service.dart';
import 'chat_detail_screen.dart';
import 'chat_create_group_screen.dart';
import 'add_story_screen.dart';

Color _getAvatarBgColor(String name) {
  if (name.isEmpty) return const Color(0xFF3388FF);
  const colors = [
    Color(0xFF3388FF),
    Color(0xFFFFB300),
    Color(0xFFAB47BC),
    Color(0xFF26A69A),
    Color(0xFFFF7043),
    Color(0xFF66BB6A),
    Color(0xFFEC407A),
  ];
  return colors[name.codeUnitAt(0) % colors.length];
}

class _NMDark {
  static const Color bg = Color(0xFF1C1C1E);
  static const Color cardBg = Color(0xFF2C2C2E);
  static const Color textPrimary = Color(0xFFFFFFFF);
  static const Color textMuted = Color(0xFF8E8E93);
  static const Color accent = Color(0xFF3388FF);
  static const Color iconBg = Color(0xFF2C2C2E);
  static const Color divider = Color(0x1AFFFFFF);
  static const Color onlineGreen = Color(0xFF10B981);
}

class _QuickAction {
  final IconData icon;
  final String label;

  const _QuickAction({required this.icon, required this.label});
}

class _QuickActionTile extends StatelessWidget {
  final _QuickAction action;
  final VoidCallback? onTap;

  const _QuickActionTile({required this.action, this.onTap});

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 12.0),
        child: Row(
          children: [
            Container(
              width: 44.0,
              height: 44.0,
              decoration: const BoxDecoration(
                color: _NMDark.iconBg,
                shape: BoxShape.circle,
              ),
              child: Icon(action.icon, color: _NMDark.accent, size: 22.0),
            ),
            const SizedBox(width: 14.0),
            Expanded(
              child: Text(
                action.label,
                style: GoogleFonts.inter(
                  color: _NMDark.textPrimary,
                  fontSize: 15.5,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ),
            const Icon(Icons.chevron_right_rounded, color: _NMDark.textMuted, size: 20.0),
          ],
        ),
      ),
    );
  }
}

class ContactTile extends StatelessWidget {
  final String name;
  final String avatarUrl;
  final String subtitle;
  final bool isOnline;
  final bool isVerified;
  final VoidCallback? onTap;

  const ContactTile({
    super.key,
    required this.name,
    required this.avatarUrl,
    this.subtitle = '',
    this.isOnline = false,
    this.isVerified = false,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final fullAvatar = avatarUrl.isNotEmpty ? ApiService.getFullImageUrl(avatarUrl) : '';

    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 10.0),
        child: Row(
          children: [
            Stack(
              children: [
                CircleAvatar(
                  radius: 24.0,
                  backgroundImage: fullAvatar.isNotEmpty ? NetworkImage(fullAvatar) : null,
                  backgroundColor: _getAvatarBgColor(name),
                  child: fullAvatar.isEmpty
                      ? Text(
                          name.isNotEmpty ? name[0].toUpperCase() : 'U',
                          style: GoogleFonts.inter(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: 16.0,
                          ),
                        )
                      : null,
                ),
                if (isOnline)
                  Positioned(
                    right: 0.0,
                    bottom: 0.0,
                    child: Container(
                      width: 12.0,
                      height: 12.0,
                      decoration: BoxDecoration(
                        color: _NMDark.onlineGreen,
                        shape: BoxShape.circle,
                        border: Border.all(color: _NMDark.bg, width: 2.0),
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(width: 14.0),

            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Flexible(
                        child: Text(
                          name,
                          style: GoogleFonts.inter(
                            color: _NMDark.textPrimary,
                            fontSize: 15.0,
                            fontWeight: FontWeight.w600,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      if (isVerified) ...[
                        const SizedBox(width: 4.0),
                        const Icon(Icons.verified_rounded, color: _NMDark.accent, size: 16.0),
                      ],
                    ],
                  ),
                  const SizedBox(height: 3.0),
                  Text(
                    subtitle.isNotEmpty ? subtitle : (isOnline ? 'online' : 'last seen recently'),
                    style: GoogleFonts.inter(
                      color: isOnline ? _NMDark.accent : _NMDark.textMuted,
                      fontSize: 12.5,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class NewMessageScreen extends StatefulWidget {
  final List<dynamic> allUsers;
  final String currentUserId;

  const NewMessageScreen({
    super.key,
    required this.allUsers,
    required this.currentUserId,
  });

  @override
  State<NewMessageScreen> createState() => _NewMessageScreenState();
}

class _NewMessageScreenState extends State<NewMessageScreen> {
  final TextEditingController _searchController = TextEditingController();
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  String _searchQuery = '';

  final List<_QuickAction> _quickActions = const [
    _QuickAction(icon: Icons.chat_bubble_outline_rounded, label: 'New note'),
    _QuickAction(icon: Icons.face_retouching_natural_rounded, label: 'Send an instant'),
    _QuickAction(icon: Icons.add_to_photos_rounded, label: 'New story'),
    _QuickAction(icon: Icons.people_alt_rounded, label: 'Group chat'),
  ];

  @override
  void initState() {
    super.initState();
    _searchController.addListener(() {
      setState(() {
        _searchQuery = _searchController.text.trim();
      });
    });
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _NMDark.bg,
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(),
            const Divider(height: 1.0, color: _NMDark.divider),
            _buildToSearchRow(),
            const Divider(height: 1.0, color: _NMDark.divider),

            Expanded(
              child: StreamBuilder<QuerySnapshot>(
                stream: _firestore.collection('users').snapshots(),
                builder: (context, snapshot) {
                  if (!snapshot.hasData) {
                    return const Center(
                      child: Padding(
                        padding: EdgeInsets.all(24),
                        child: CircularProgressIndicator(color: _NMDark.accent),
                      ),
                    );
                  }

                  final usersDocs = snapshot.data!.docs.where((doc) {
                    final data = doc.data() as Map<String, dynamic>;
                    final uid = doc.id;
                    if (uid == widget.currentUserId) return false;
                    final role = (data['role'] ?? '').toString().toLowerCase();
                    if (role == 'admin_panel' || data['isAdminPanel'] == true) return false;

                    if (_searchQuery.isNotEmpty) {
                      final name = (data['name'] ?? data['username'] ?? '').toString().toLowerCase();
                      final pos = (data['position'] ?? data['department'] ?? '').toString().toLowerCase();
                      final empId = (data['employee_id'] ?? '').toString().toLowerCase();
                      final q = _searchQuery.toLowerCase();
                      return name.contains(q) || pos.contains(q) || empId.contains(q);
                    }
                    return true;
                  }).toList();

                  return ListView(
                    physics: const BouncingScrollPhysics(),
                    children: [
                      if (_searchQuery.isEmpty) ...[
                        const SizedBox(height: 8.0),
                        ..._quickActions.map(
                          (action) => _QuickActionTile(
                            action: action,
                            onTap: () {
                              if (action.label == 'Group chat') {
                                Navigator.push(
                                  context,
                                  MaterialPageRoute(
                                    builder: (_) => ChatCreateGroupScreen(
                                      allUsers: widget.allUsers,
                                      currentUserId: widget.currentUserId,
                                    ),
                                  ),
                                );
                              } else if (action.label == 'New story') {
                                Navigator.push(
                                  context,
                                  MaterialPageRoute(
                                    builder: (_) => const AddStoryScreen(),
                                  ),
                                );
                              } else {
                                ScaffoldMessenger.of(context).showSnackBar(
                                  SnackBar(
                                    backgroundColor: _NMDark.cardBg,
                                    content: Text(
                                      'មុខងារ "${action.label}" ត្រូវបានជ្រើសរើស',
                                      style: GoogleFonts.kantumruyPro(color: Colors.white),
                                    ),
                                    duration: const Duration(seconds: 2),
                                  ),
                                );
                              }
                            },
                          ),
                        ),
                        const SizedBox(height: 8.0),
                      ],

                      Padding(
                        padding: const EdgeInsets.fromLTRB(16.0, 12.0, 16.0, 6.0),
                        child: Text(
                          _searchQuery.isEmpty ? 'Suggested Contacts' : 'Search Results (${usersDocs.length})',
                          style: GoogleFonts.inter(
                            color: _NMDark.textMuted,
                            fontSize: 13.5,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),

                      if (usersDocs.isEmpty)
                        Padding(
                          padding: const EdgeInsets.all(32.0),
                          child: Center(
                            child: Text(
                              'រកមិនឃើញបុគ្គលិកឡើយ',
                              style: GoogleFonts.kantumruyPro(color: _NMDark.textMuted, fontSize: 14),
                            ),
                          ),
                        )
                      else
                        ...usersDocs.map((doc) {
                          final data = doc.data() as Map<String, dynamic>;
                          final String targetId = doc.id;
                          final String name = (data['name'] ?? data['username'] ?? data['employee_id'] ?? 'User').toString();
                          final String avatar = (data['avatar'] ?? data['photoUrl'] ?? data['photo'] ?? '').toString();
                          final String position = (data['position'] ?? data['department'] ?? data['role'] ?? '').toString();
                          final bool isOnline = data['isOnline'] == true;
                          final bool isVerified = (data['role'] ?? '').toString().toLowerCase() == 'admin';

                          return ContactTile(
                            name: name,
                            avatarUrl: avatar,
                            subtitle: position,
                            isOnline: isOnline,
                            isVerified: isVerified,
                            onTap: () {
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
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8.0, vertical: 12.0),
      child: Stack(
        alignment: Alignment.center,
        children: [
          Align(
            alignment: Alignment.centerLeft,
            child: TextButton(
              onPressed: () => Navigator.pop(context),
              style: TextButton.styleFrom(
                foregroundColor: _NMDark.accent,
                padding: const EdgeInsets.symmetric(horizontal: 8.0),
              ),
              child: Text(
                'Cancel',
                style: GoogleFonts.inter(
                  fontSize: 16.0,
                  fontWeight: FontWeight.w500,
                  color: _NMDark.accent,
                ),
              ),
            ),
          ),
          Text(
            'New message',
            style: GoogleFonts.inter(
              color: _NMDark.textPrimary,
              fontSize: 17.0,
              fontWeight: FontWeight.bold,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildToSearchRow() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
      child: Row(
        children: [
          Text(
            'To:',
            style: GoogleFonts.inter(
              color: _NMDark.textMuted,
              fontSize: 16.0,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(width: 10.0),
          Expanded(
            child: SizedBox(
              height: 40.0,
              child: TextField(
                controller: _searchController,
                autofocus: false,
                cursorColor: _NMDark.accent,
                style: GoogleFonts.inter(color: _NMDark.textPrimary, fontSize: 15.0),
                decoration: InputDecoration(
                  hintText: 'ស្វែងរកឈ្មោះបុគ្គលិក ឬ ផ្នែក...',
                  hintStyle: GoogleFonts.kantumruyPro(color: _NMDark.textMuted, fontSize: 14.0),
                  prefixIcon: const Icon(Icons.search_rounded, color: _NMDark.textMuted, size: 18.0),
                  filled: true,
                  fillColor: _NMDark.cardBg,
                  isDense: true,
                  contentPadding: const EdgeInsets.symmetric(vertical: 8.0, horizontal: 14.0),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(20.0),
                    borderSide: BorderSide.none,
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(20.0),
                    borderSide: BorderSide.none,
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(20.0),
                    borderSide: const BorderSide(color: _NMDark.accent, width: 1.0),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
