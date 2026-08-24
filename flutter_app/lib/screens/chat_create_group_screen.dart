import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../utils/app_theme.dart';
import '../services/api_service.dart';

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
  bool _isCreating = false;

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
    _groupNameController.dispose();
    _searchController.dispose();
    super.dispose();
  }

  void _hapticLight() => HapticFeedback.lightImpact();

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
            content: Text(
              'បានបង្កើតក្រុម "$name" ដោយជោគជ័យ!',
              style: GoogleFonts.kantumruyPro(color: Colors.white),
            ),
            backgroundColor: const Color(0xFF10B981),
          ),
        );
      }
    } on FirebaseException catch (e) {
      if (mounted) {
        setState(() => _isCreating = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'បរាជ័យក្នុងការបង្កើតក្រុម: ${e.message}',
              style: GoogleFonts.kantumruyPro(),
            ),
            backgroundColor: Colors.redAccent,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isCreating = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'កំហុសមិនរំពឹងទុក: $e',
              style: GoogleFonts.kantumruyPro(),
            ),
            backgroundColor: Colors.redAccent,
          ),
        );
      }
    }
  }

  void _showNameInputDialog() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Row(
          children: [
            const Icon(Icons.edit_rounded, color: Color(0xFFD4AF37), size: 22),
            const SizedBox(width: 10),
            Text(
              'បញ្ចូលឈ្មោះក្រុម',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        content: Text(
          'សូមបញ្ចូលឈ្មោះសម្រាប់ក្រុមការងារថ្មីរបស់អ្នកមុននឹងបន្ត។',
          style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text(
              'យល់ព្រម',
              style: GoogleFonts.kantumruyPro(color: const Color(0xFFD4AF37), fontWeight: FontWeight.bold),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final bool canCreate = _selectedUserIds.isNotEmpty && !_isCreating;

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: Column(
          children: [
            // 1. Top Bar Header
            _buildTopHeader(canCreate),

            // 2. Group Name & Search Inputs
            _buildInputsSection(),

            // 3. Selected Users Horizontal Chips (if any)
            if (_selectedUserIds.isNotEmpty) _buildSelectedChipsBar(),

            const SizedBox(height: 8),

            // 4. Users List
            Expanded(
              child: StreamBuilder<QuerySnapshot>(
                stream: _firestore.collection('users').snapshots(),
                builder: (context, snapshot) {
                  if (!snapshot.hasData) {
                    return Center(
                      child: CircularProgressIndicator(color: AppTheme.primary),
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

                  if (usersDocs.isEmpty) {
                    return Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.person_search_rounded, color: AppTheme.textMuted, size: 48),
                          const SizedBox(height: 12),
                          Text(
                            'រកមិនឃើញបុគ្គលិកឡើយ',
                            style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 14),
                          ),
                        ],
                      ),
                    );
                  }

                  return ListView.builder(
                    physics: const BouncingScrollPhysics(),
                    padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 6.0),
                    itemCount: usersDocs.length,
                    itemBuilder: (context, index) {
                      final doc = usersDocs[index];
                      final data = doc.data() as Map<String, dynamic>;
                      final String targetId = doc.id;
                      final String name = (data['name'] ?? data['username'] ?? data['employee_id'] ?? 'User').toString();
                      final String avatar = (data['avatar'] ?? data['photoUrl'] ?? data['photo'] ?? '').toString();
                      final String position = (data['position'] ?? data['department'] ?? data['role'] ?? '').toString();
                      final bool isSelected = _selectedUserIds.contains(targetId);

                      return _buildUserSelectCard(
                        id: targetId,
                        name: name,
                        avatarUrl: avatar,
                        position: position,
                        isSelected: isSelected,
                        onTap: () {
                          _hapticLight();
                          setState(() {
                            if (isSelected) {
                              _selectedUserIds.remove(targetId);
                            } else {
                              _selectedUserIds.add(targetId);
                            }
                          });
                        },
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
                border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
              ),
              child: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 17),
            ),
          ),
          const SizedBox(width: 14),

          // Title
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'បង្កើតក្រុមការងារ (New Group)',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontSize: 16.0,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                Text(
                  'បានជ្រើសរើស ${_selectedUserIds.length} នាក់',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textMuted,
                    fontSize: 11.5,
                  ),
                ),
              ],
            ),
          ),

          // Create CTA Button
          GestureDetector(
            onTap: canCreate ? _createGroup : null,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                gradient: canCreate
                    ? const LinearGradient(
                        colors: [Color(0xFFD4AF37), Color(0xFFB8860B)],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      )
                    : null,
                color: canCreate ? null : Colors.white.withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(12),
                boxShadow: canCreate
                    ? [
                        BoxShadow(
                          color: const Color(0xFFD4AF37).withValues(alpha: 0.35),
                          blurRadius: 10,
                          offset: const Offset(0, 3),
                        ),
                      ]
                    : null,
              ),
              child: _isCreating
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                    )
                  : Text(
                      'បង្កើតក្រុម',
                      style: GoogleFonts.kantumruyPro(
                        color: canCreate ? Colors.white : Colors.white38,
                        fontSize: 12.5,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // INPUTS SECTION (NAME + SEARCH)
  // ==========================================
  Widget _buildInputsSection() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 6.0),
      child: Column(
        children: [
          // Group Name Box
          Container(
            height: 46.0,
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(14.0),
              border: Border.all(color: const Color(0xFFD4AF37).withValues(alpha: 0.3)),
            ),
            child: Row(
              children: [
                const SizedBox(width: 12),
                const Icon(Icons.group_work_rounded, color: Color(0xFFD4AF37), size: 20),
                const SizedBox(width: 10),
                Expanded(
                  child: TextField(
                    controller: _groupNameController,
                    style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 13.5),
                    cursorColor: AppTheme.primary,
                    decoration: InputDecoration(
                      hintText: 'ដាក់ឈ្មោះក្រុមការងារ (ឧ. ក្រុម IT Support)...',
                      hintStyle: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 12.5),
                      border: InputBorder.none,
                      isDense: true,
                      contentPadding: const EdgeInsets.symmetric(vertical: 10),
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 8.0),

          // Search Field
          Container(
            height: 42.0,
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(14.0),
              border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
            ),
            child: Row(
              children: [
                const SizedBox(width: 12),
                const Icon(Icons.search_rounded, color: Colors.white38, size: 18),
                const SizedBox(width: 10),
                Expanded(
                  child: TextField(
                    controller: _searchController,
                    style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 13.0),
                    cursorColor: AppTheme.primary,
                    decoration: InputDecoration(
                      hintText: 'ស្វែងរកបុគ្គលិកដើម្បីបញ្ចូល...',
                      hintStyle: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 12.5),
                      border: InputBorder.none,
                      isDense: true,
                      contentPadding: const EdgeInsets.symmetric(vertical: 10),
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

  // ==========================================
  // SELECTED USERS CAROUSEL
  // ==========================================
  Widget _buildSelectedChipsBar() {
    return Container(
      height: 42.0,
      margin: const EdgeInsets.symmetric(vertical: 6.0),
      child: ListView(
        scrollDirection: Axis.horizontal,
        physics: const BouncingScrollPhysics(),
        padding: const EdgeInsets.symmetric(horizontal: 16.0),
        children: _selectedUserIds.map((id) {
          final user = widget.allUsers.firstWhere(
            (u) => (u['id'] ?? u['employee_id'] ?? '').toString() == id,
            orElse: () => {'name': id},
          );
          final name = (user['name'] ?? id).toString();

          return Container(
            margin: const EdgeInsets.only(right: 8.0),
            padding: const EdgeInsets.fromLTRB(10, 4, 6, 4),
            decoration: BoxDecoration(
              color: const Color(0xFFD4AF37).withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(20.0),
              border: Border.all(color: const Color(0xFFD4AF37).withValues(alpha: 0.4)),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  name,
                  style: GoogleFonts.kantumruyPro(
                    color: const Color(0xFFD4AF37),
                    fontSize: 12.0,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(width: 4.0),
                GestureDetector(
                  onTap: () {
                    _hapticLight();
                    setState(() => _selectedUserIds.remove(id));
                  },
                  child: const Icon(Icons.cancel_rounded, color: Color(0xFFD4AF37), size: 16.0),
                ),
              ],
            ),
          );
        }).toList(),
      ),
    );
  }

  // ==========================================
  // USER SELECT CARD
  // ==========================================
  Widget _buildUserSelectCard({
    required String id,
    required String name,
    required String avatarUrl,
    required String position,
    required bool isSelected,
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
            color: isSelected
                ? const Color(0xFFD4AF37).withValues(alpha: 0.1)
                : AppTheme.bgCard,
            borderRadius: BorderRadius.circular(16.0),
            border: Border.all(
              color: isSelected
                  ? const Color(0xFFD4AF37).withValues(alpha: 0.5)
                  : Colors.white.withValues(alpha: 0.05),
            ),
          ),
          child: Row(
            children: [
              // Avatar
              Container(
                width: 44.0,
                height: 44.0,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: isSelected
                        ? const Color(0xFFD4AF37)
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
              const SizedBox(width: 12.0),

              // Name & Position
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      name,
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary,
                        fontSize: 14.0,
                        fontWeight: FontWeight.bold,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    if (position.isNotEmpty) ...[
                      const SizedBox(height: 2.0),
                      Text(
                        position,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textSecondary,
                          fontSize: 11.5,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ],
                ),
              ),

              // Selection Radio / Check Indicator
              Container(
                width: 24,
                height: 24,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: isSelected ? const Color(0xFFD4AF37) : Colors.transparent,
                  border: Border.all(
                    color: isSelected ? const Color(0xFFD4AF37) : Colors.white38,
                    width: 1.8,
                  ),
                ),
                child: isSelected
                    ? const Icon(Icons.check_rounded, color: Colors.white, size: 16)
                    : null,
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
          fontSize: 16.0,
        ),
      ),
    );
  }
}
