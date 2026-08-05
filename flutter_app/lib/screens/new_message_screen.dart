import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../services/api_service.dart';
import 'chat_detail_screen.dart';
import 'chat_create_group_screen.dart';

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

// ==========================================
// DARK THEME TOKENS (Shared with ChatDetailScreen)
// ==========================================
class _NMDark {
  static const Color bg = Color(0xFF1C1C1E);
  static const Color textPrimary = Color(0xFFFFFFFF);
  static const Color textMuted = Color(0xFFB0B3B8);
  static const Color accent = Color(0xFF0084FF);
  static const Color iconBg = Color(0xFF3A3B3C);
  static const Color divider = Color(0xFF38383A);
  static const Color onlineGreen = Color(0xFF44B700);
}

// ==========================================
// DATA MODELS
// ==========================================
class _QuickAction {
  final IconData icon;
  final String label;

  const _QuickAction({required this.icon, required this.label});
}

// ==========================================
// SUB-WIDGETS
// ==========================================

/// Single row in the Quick Actions List (New note, Send an instant, etc.)
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
              child: Icon(action.icon, color: _NMDark.textPrimary, size: 22.0),
            ),
            const SizedBox(width: 14.0),
            Expanded(
              child: Text(
                action.label,
                style: GoogleFonts.kantumruyPro(
                  color: _NMDark.textPrimary,
                  fontSize: 16.0,
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

/// Contact row with avatar + online badge + name + optional verified badge
class ContactTile extends StatelessWidget {
  final String name;
  final String avatarUrl;
  final bool isOnline;
  final bool isVerified;
  final VoidCallback? onTap;

  const ContactTile({
    super.key,
    required this.name,
    required this.avatarUrl,
    this.isOnline = false,
    this.isVerified = false,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 10.0),
        child: Row(
          children: [
            // Avatar + online badge
            Stack(
              children: [
                CircleAvatar(
                  radius: 30.0,
                  backgroundImage: avatarUrl.isNotEmpty ? NetworkImage(avatarUrl) : null,
                  backgroundColor: _getAvatarBgColor(name),
                  child: avatarUrl.isEmpty
                      ? Text(
                          name.isNotEmpty ? name[0].toUpperCase() : 'U',
                          style: GoogleFonts.inter(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: 18.0,
                          ),
                        )
                      : null,
                ),
                if (isOnline)
                  Positioned(
                    right: 0.0,
                    bottom: 0.0,
                    child: Container(
                      width: 15.0,
                      height: 15.0,
                      decoration: const BoxDecoration(
                        color: _NMDark.onlineGreen,
                        shape: BoxShape.circle,
                        border: Border.fromBorderSide(
                          BorderSide(color: _NMDark.bg, width: 2.5),
                        ),
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(width: 14.0),

            // Name area
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
                            color: _NMDark.textPrimary,
                            fontSize: 15.5,
                            fontWeight: FontWeight.w500,
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
                  const Divider(height: 16.0, color: _NMDark.divider),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ==========================================
// MAIN SCREEN: NEW MESSAGE / COMPOSE
// ==========================================
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
  List<dynamic> _filtered = [];

  final List<_QuickAction> _quickActions = const [
    _QuickAction(icon: Icons.chat_bubble_outline_rounded, label: 'New note'),
    _QuickAction(icon: Icons.face_retouching_natural_rounded, label: 'Send an instant'),
    _QuickAction(icon: Icons.add_to_photos_rounded, label: 'New story'),
    _QuickAction(icon: Icons.people_alt_rounded, label: 'Group chat'),
  ];

  @override
  void initState() {
    super.initState();
    _filtered = widget.allUsers;
    _searchController.addListener(() {
      _filterContacts(_searchController.text);
    });
  }

  void _filterContacts(String query) {
    setState(() {
      _searchQuery = query;
      if (query.isEmpty) {
        _filtered = widget.allUsers;
      } else {
        _filtered = widget.allUsers.where((u) {
          final name = (u['name'] ?? '').toString().toLowerCase();
          final eid = (u['employee_id'] ?? '').toString().toLowerCase();
          return name.contains(query.toLowerCase()) || eid.contains(query.toLowerCase());
        }).toList();
      }
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
            // A. Header
            _buildHeader(),

            // Divider
            const Divider(height: 1.0, color: _NMDark.divider),

            // "To:" search row
            _buildToSearchRow(),

            const Divider(height: 1.0, color: _NMDark.divider),

            // B & C: Quick actions + Suggested list
            Expanded(
              child: ListView(
                physics: const BouncingScrollPhysics(),
                children: [
                  // B. Quick Actions (only show when not searching)
                  if (_searchQuery.isEmpty) ...[
                    const SizedBox(height: 8.0),
                    ..._quickActions.map((action) => _QuickActionTile(
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
                            } else {
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(
                                  content: Text('មុខងារ "${action.label}" នឹងមកដល់ឆាប់ៗនេះ!', style: GoogleFonts.kantumruyPro()),
                                  duration: const Duration(seconds: 2),
                                ),
                              );
                            }
                          },
                        )),
                    const SizedBox(height: 8.0),
                  ],

                  // C. Suggested / Search Results
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16.0, 8.0, 16.0, 4.0),
                    child: Text(
                      _searchQuery.isEmpty ? 'Suggested' : 'Results',
                      style: GoogleFonts.inter(
                        color: _NMDark.textMuted,
                        fontSize: 14.0,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ),

                  // Contacts list with real-time presence
                  ..._filtered.map((user) {
                    final String name = user['name'] ?? 'Unknown';
                    final String targetId = user['employee_id'] ?? '';
                    final String avatar = user['avatar'] ?? '';
                    final bool isVerified = (user['role'] ?? '').toString().toLowerCase() == 'admin';

                    return StreamBuilder<DocumentSnapshot>(
                      stream: _firestore.collection('users').doc(targetId).snapshots(),
                      builder: (context, snap) {
                        bool isOnline = false;
                        if (snap.hasData && snap.data!.exists) {
                          final data = snap.data!.data() as Map<String, dynamic>?;
                          isOnline = data?['isOnline'] == true;
                        }
                        return ContactTile(
                          name: name,
                          avatarUrl: avatar.isNotEmpty ? ApiService.getFullImageUrl(avatar) : '',
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
  // A. HEADER
  // ==========================================
  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8.0, vertical: 12.0),
      child: Stack(
        alignment: Alignment.center,
        children: [
          // Cancel button left
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

          // Centered title
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

  // "To:" search row
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
                style: GoogleFonts.kantumruyPro(color: _NMDark.textPrimary, fontSize: 15.0),
                decoration: InputDecoration(
                  hintText: 'ស្វែងរក...',
                  hintStyle: GoogleFonts.kantumruyPro(color: _NMDark.textMuted, fontSize: 14.5),
                  prefixIcon: const Icon(Icons.search_rounded, color: _NMDark.textMuted, size: 18.0),
                  filled: true,
                  fillColor: const Color(0xFF2C2C2E),
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
