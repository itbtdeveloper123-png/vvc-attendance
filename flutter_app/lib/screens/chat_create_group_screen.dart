import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../services/api_service.dart';

// ==========================================
// DARK THEME TOKENS (Matching Messenger)
// ==========================================
class _GPDark {
  static const Color bg = Color(0xFF1C1C1E);
  static const Color card = Color(0xFF2C2C2E);
  static const Color textPrimary = Color(0xFFFFFFFF);
  static const Color textMuted = Color(0xFFB0B3B8);
  static const Color accent = Color(0xFF0084FF);
  static const Color divider = Color(0xFF38383A);
  static const Color onlineGreen = Color(0xFF44B700);
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

class ChatCreateGroupScreen extends StatefulWidget {
  final List<dynamic> allUsers;
  final String currentUserId;

  const ChatCreateGroupScreen({
    super.key,
    required this.allUsers,
    required this.currentUserId,
  });

  @override
  State<ChatCreateGroupScreen> createState() => _ChatCreateGroupScreenState();
}

class _ChatCreateGroupScreenState extends State<ChatCreateGroupScreen> {
  final TextEditingController _groupNameController = TextEditingController();
  final TextEditingController _searchController = TextEditingController();
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  final Set<String> _selectedUserIds = {};
  String _searchQuery = '';
  List<dynamic> _filteredUsers = [];
  bool _isCreating = false;

  @override
  void initState() {
    super.initState();
    _filteredUsers = widget.allUsers;
    _searchController.addListener(() {
      _filterUsers(_searchController.text);
    });
  }

  void _filterUsers(String query) {
    setState(() {
      _searchQuery = query;
      if (query.isEmpty) {
        _filteredUsers = widget.allUsers;
      } else {
        _filteredUsers = widget.allUsers.where((u) {
          final name = (u['name'] ?? '').toString().toLowerCase();
          final position = (u['position'] ?? '').toString().toLowerCase();
          final eid = (u['employee_id'] ?? '').toString().toLowerCase();
          return name.contains(query.toLowerCase()) ||
              position.contains(query.toLowerCase()) ||
              eid.contains(query.toLowerCase());
        }).toList();
      }
    });
  }

  @override
  void dispose() {
    _groupNameController.dispose();
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _createGroup() async {
    final name = _groupNameController.text.trim();
    if (name.isEmpty) {
      _showNameInputDialog();
      return;
    }

    setState(() => _isCreating = true);

    try {
      final Map<String, String> members = {widget.currentUserId: 'accepted'};
      for (var id in _selectedUserIds) {
        members[id] = 'pending';
      }

      await _firestore.collection('groups').add({
        'name': name,
        'members': members,
        'participantIds': [widget.currentUserId, ..._selectedUserIds],
        'createdBy': widget.currentUserId,
        'createdAt': FieldValue.serverTimestamp(),
        'lastMessage': 'ក្រុមត្រូវបានបង្កើត',
        'lastTimestamp': FieldValue.serverTimestamp(),
      });

      if (mounted) {
        Navigator.pop(context, true);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('បានបង្កើតក្រុម "$name" ដោយជោគជ័យ!', style: GoogleFonts.kantumruyPro()),
            backgroundColor: _GPDark.accent,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isCreating = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error: $e', style: GoogleFonts.kantumruyPro()), backgroundColor: Colors.redAccent),
        );
      }
    }
  }

  void _showNameInputDialog() {
    showDialog(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          backgroundColor: const Color(0xFF2C2C2E),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20.0)),
          title: Text(
            'បញ្ចូលឈ្មោះក្រុម (Group Name)',
            style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 17.0, fontWeight: FontWeight.bold),
          ),
          content: TextField(
            controller: _groupNameController,
            autofocus: true,
            style: GoogleFonts.kantumruyPro(color: Colors.white),
            cursorColor: _GPDark.accent,
            decoration: InputDecoration(
              hintText: 'ឧ. ក្រុមការងារ VVC...',
              hintStyle: GoogleFonts.kantumruyPro(color: _GPDark.textMuted),
              enabledBorder: const UnderlineInputBorder(borderSide: BorderSide(color: _GPDark.accent)),
              focusedBorder: const UnderlineInputBorder(borderSide: BorderSide(color: _GPDark.accent, width: 2.0)),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: _GPDark.textMuted)),
            ),
            ElevatedButton(
              onPressed: () {
                Navigator.pop(ctx);
                _createGroup();
              },
              style: ElevatedButton.styleFrom(backgroundColor: _GPDark.accent),
              child: Text('បង្កើត (Create)', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
            ),
          ],
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final bool canCreate = _selectedUserIds.isNotEmpty && !_isCreating;

    return Scaffold(
      backgroundColor: _GPDark.bg,
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // A. Top Bar Header
            _buildTopHeader(canCreate),

            const Divider(height: 1.0, color: _GPDark.divider),

            // B. Group Name + Search Row Input
            _buildSearchAndNameSection(),

            const Divider(height: 1.0, color: _GPDark.divider),

            // C. Suggested Contacts Header
            Padding(
              padding: const EdgeInsets.fromLTRB(16.0, 12.0, 16.0, 6.0),
              child: Row(
                children: [
                  Text(
                    _searchQuery.isEmpty ? 'Suggested' : 'Results',
                    style: GoogleFonts.inter(
                      color: _GPDark.textMuted,
                      fontSize: 14.0,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const Spacer(),
                  if (_selectedUserIds.isNotEmpty)
                    Text(
                      'ជ្រើសរើស ${_selectedUserIds.length} នាក់',
                      style: GoogleFonts.kantumruyPro(
                        color: _GPDark.accent,
                        fontSize: 13.0,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                ],
              ),
            ),

            // D. Contacts List with Radio Checkbox
            Expanded(
              child: ListView.builder(
                physics: const BouncingScrollPhysics(),
                itemCount: _filteredUsers.length,
                itemBuilder: (context, index) {
                  final user = _filteredUsers[index];
                  final String targetId = (user['employee_id'] ?? '').toString();
                  if (targetId == widget.currentUserId) {
                    return const SizedBox.shrink();
                  }

                  final String name = (user['name'] ?? 'Unknown').toString();
                  final String avatar = (user['avatar'] ?? '').toString();
                  final bool isSelected = _selectedUserIds.contains(targetId);
                  final bool isVerified = (user['role'] ?? '').toString().toLowerCase() == 'admin';

                  return StreamBuilder<DocumentSnapshot>(
                    stream: _firestore.collection('users').doc(targetId).snapshots(),
                    builder: (context, snap) {
                      bool isOnline = false;
                      if (snap.hasData && snap.data!.exists) {
                        final data = snap.data!.data() as Map<String, dynamic>?;
                        isOnline = data?['isOnline'] == true;
                      }

                      return InkWell(
                        onTap: () {
                          setState(() {
                            if (isSelected) {
                              _selectedUserIds.remove(targetId);
                            } else {
                              _selectedUserIds.add(targetId);
                            }
                          });
                        },
                        child: Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 10.0),
                          child: Row(
                            children: [
                              // Avatar + Online badge
                              Stack(
                                children: [
                                  CircleAvatar(
                                    radius: 28.0,
                                    backgroundImage: avatar.isNotEmpty ? NetworkImage(ApiService.getFullImageUrl(avatar)) : null,
                                    backgroundColor: _getAvatarBgColor(name),
                                    child: avatar.isEmpty
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
                                        width: 14.0,
                                        height: 14.0,
                                        decoration: const BoxDecoration(
                                          color: _GPDark.onlineGreen,
                                          shape: BoxShape.circle,
                                          border: Border.fromBorderSide(
                                            BorderSide(color: _GPDark.bg, width: 2.0),
                                          ),
                                        ),
                                      ),
                                    ),
                                ],
                              ),
                              const SizedBox(width: 14.0),

                              // Name + verified checkmark
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
                                              color: _GPDark.textPrimary,
                                              fontSize: 16.0,
                                              fontWeight: FontWeight.w500,
                                            ),
                                            maxLines: 1,
                                            overflow: TextOverflow.ellipsis,
                                          ),
                                        ),
                                        if (isVerified) ...[
                                          const SizedBox(width: 4.0),
                                          const Icon(Icons.verified_rounded, color: _GPDark.accent, size: 16.0),
                                        ],
                                      ],
                                    ),
                                    const Divider(height: 16.0, color: _GPDark.divider),
                                  ],
                                ),
                              ),

                              // Radio / Checkbox Circle
                              Icon(
                                isSelected ? Icons.check_circle_rounded : Icons.radio_button_unchecked_rounded,
                                color: isSelected ? _GPDark.accent : const Color(0xFF65676B),
                                size: 24.0,
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
      ),
    );
  }

  // ==========================================
  // TOP BAR HEADER
  // ==========================================
  Widget _buildTopHeader(bool canCreate) {
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
                foregroundColor: _GPDark.accent,
                padding: const EdgeInsets.symmetric(horizontal: 8.0),
              ),
              child: Text(
                'Cancel',
                style: GoogleFonts.inter(
                  fontSize: 16.0,
                  fontWeight: FontWeight.w500,
                  color: _GPDark.accent,
                ),
              ),
            ),
          ),

          // Centered title "New group"
          Text(
            'New group',
            style: GoogleFonts.inter(
              color: _GPDark.textPrimary,
              fontSize: 17.0,
              fontWeight: FontWeight.bold,
            ),
          ),

          // Next / Create button right
          Align(
            alignment: Alignment.centerRight,
            child: TextButton(
              onPressed: canCreate ? _createGroup : null,
              style: TextButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 8.0),
              ),
              child: _isCreating
                  ? const SizedBox(
                      width: 18.0,
                      height: 18.0,
                      child: CircularProgressIndicator(color: _GPDark.accent, strokeWidth: 2.0),
                    )
                  : Text(
                      'Create',
                      style: GoogleFonts.inter(
                        fontSize: 16.0,
                        fontWeight: FontWeight.bold,
                        color: canCreate ? _GPDark.accent : const Color(0xFF65676B),
                      ),
                    ),
            ),
          ),
        ],
      ),
    );
  }

  // Group Name & Search Input Section
  Widget _buildSearchAndNameSection() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 10.0),
      child: Column(
        children: [
          // Group Name Input
          Container(
            height: 44.0,
            decoration: BoxDecoration(
              color: _GPDark.card,
              borderRadius: BorderRadius.circular(12.0),
            ),
            padding: const EdgeInsets.symmetric(horizontal: 12.0),
            child: Row(
              children: [
                const Icon(Icons.group_add_rounded, color: _GPDark.accent, size: 20.0),
                const SizedBox(width: 10.0),
                Expanded(
                  child: TextField(
                    controller: _groupNameController,
                    style: GoogleFonts.kantumruyPro(color: _GPDark.textPrimary, fontSize: 15.0),
                    cursorColor: _GPDark.accent,
                    decoration: InputDecoration(
                      hintText: 'ឈ្មោះក្រុម...',
                      hintStyle: GoogleFonts.kantumruyPro(color: _GPDark.textMuted, fontSize: 14.5),
                      border: InputBorder.none,
                      isDense: true,
                      contentPadding: EdgeInsets.zero,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 8.0),

          // Search Field
          Container(
            height: 40.0,
            decoration: BoxDecoration(
              color: _GPDark.card,
              borderRadius: BorderRadius.circular(12.0),
            ),
            padding: const EdgeInsets.symmetric(horizontal: 12.0),
            child: Row(
              children: [
                const Icon(Icons.search_rounded, color: _GPDark.textMuted, size: 20.0),
                const SizedBox(width: 10.0),
                Expanded(
                  child: TextField(
                    controller: _searchController,
                    style: GoogleFonts.kantumruyPro(color: _GPDark.textPrimary, fontSize: 15.0),
                    cursorColor: _GPDark.accent,
                    decoration: InputDecoration(
                      hintText: 'Search',
                      hintStyle: GoogleFonts.inter(color: _GPDark.textMuted, fontSize: 15.0),
                      border: InputBorder.none,
                      isDense: true,
                      contentPadding: EdgeInsets.zero,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
