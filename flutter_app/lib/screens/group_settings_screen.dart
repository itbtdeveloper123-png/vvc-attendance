import 'dart:io';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:image_picker/image_picker.dart';
import 'package:audioplayers/audioplayers.dart';
import '../services/api_service.dart';
import '../services/r2_storage_service.dart';

class _GSDark {
  static const Color bg = Color(0xFF1C1C1E);
  static const Color card = Color(0xFF2C2C2E);
  static const Color textMuted = Color(0xFF8E8E93);
  static const Color accent = Color(0xFF3388FF);
  static const Color danger = Color(0xFFFF453A);
  static const Color divider = Color(0x1AFFFFFF);
}

class GroupSettingsScreen extends StatefulWidget {
  final String groupId;
  final String currentUserId;
  final List<dynamic> allUsers;

  const GroupSettingsScreen({
    super.key,
    required this.groupId,
    required this.currentUserId,
    required this.allUsers,
  });

  @override
  State<GroupSettingsScreen> createState() => _GroupSettingsScreenState();
}

class _GroupSettingsScreenState extends State<GroupSettingsScreen> {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final ImagePicker _picker = ImagePicker();
  final R2StorageService _r2Service = R2StorageService();

  late final Stream<DocumentSnapshot> _groupStream;
  int _selectedTab = 0; // 0: Members, 1: Media, 2: Saved, 3: Files, 4: Voice

  @override
  void initState() {
    super.initState();
    _groupStream = _firestore.collection('groups').doc(widget.groupId).snapshots();
  }

  Future<void> _pickAndUpdateGroupPhoto() async {
    try {
      final XFile? file = await _picker.pickImage(source: ImageSource.gallery, imageQuality: 70);
      if (file == null) return;

      final r2Url = await _r2Service.uploadMedia(file: File(file.path), folder: 'group_photos');

      if (r2Url != null) {
        await _firestore.collection('groups').doc(widget.groupId).update({'photo': r2Url});
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('បានប្តូររូបភាពក្រុមជោគជ័យ!', style: GoogleFonts.kantumruyPro())),
          );
        }
      }
    } catch (e) {
      debugPrint('Error updating group photo: $e');
    }
  }

  void _leaveGroup(List<dynamic> participantIds) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: _GSDark.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Text('ចាកចេញពីក្រុម', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
        content: Text('តើអ្នកពិតជាចង់ចាកចេញពីក្រុមនេះមែនទេ?', style: GoogleFonts.kantumruyPro(color: Colors.white70)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: _GSDark.danger),
            onPressed: () async {
              Navigator.pop(ctx);
              final updated = List.from(participantIds)..remove(widget.currentUserId);
              await _firestore.collection('groups').doc(widget.groupId).update({'participantIds': updated});
              if (mounted) {
                Navigator.pop(context); // Pop profile
                Navigator.pop(context); // Pop chat
              }
            },
            child: Text('ចាកចេញ', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _GSDark.bg,
      body: StreamBuilder<DocumentSnapshot>(
        stream: _groupStream,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting && !snapshot.hasData) {
            return const Center(child: CircularProgressIndicator(color: _GSDark.accent));
          }

          if (!snapshot.hasData || !snapshot.data!.exists) {
            return Center(
              child: Text(
                'រកមិនឃើញក្រុមនេះឡើយ',
                style: GoogleFonts.kantumruyPro(color: Colors.white70),
              ),
            );
          }

          final groupData = snapshot.data!.data() as Map<String, dynamic>;
          final String name = groupData['name'] ?? 'ក្រុមការងារ';
          final String photo = groupData['photo'] ?? '';
          final String createdBy = groupData['createdBy'] ?? '';
          final List<dynamic> participantIds = groupData['participantIds'] ?? [];
          final Map<String, dynamic> admins = groupData['admins'] as Map<String, dynamic>? ?? {};

          final bool isOwner = createdBy == widget.currentUserId;
          final bool isAdmin = isOwner || (admins[widget.currentUserId] == true);

          return CustomScrollView(
            physics: const BouncingScrollPhysics(),
            slivers: [
              // Top AppBar with Edit Capsule Button (Matching Screenshot)
              SliverAppBar(
                backgroundColor: _GSDark.bg,
                elevation: 0,
                pinned: true,
                leading: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: InkWell(
                    onTap: () => Navigator.pop(context),
                    borderRadius: BorderRadius.circular(20),
                    child: Container(
                      decoration: const BoxDecoration(color: _GSDark.card, shape: BoxShape.circle),
                      child: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 18),
                    ),
                  ),
                ),
                actions: [
                  Padding(
                    padding: const EdgeInsets.only(right: 14, top: 10, bottom: 10),
                    child: ElevatedButton(
                      onPressed: () {
                        _showEditGroupModal(context, groupData);
                      },
                      style: ElevatedButton.styleFrom(
                        backgroundColor: _GSDark.card,
                        elevation: 0,
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
                      ),
                      child: Text('Edit', style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold)),
                    ),
                  ),
                ],
              ),

              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16.0),
                  child: Column(
                    children: [
                      // Group Avatar & Name Header (Telegram Dark Style)
                      Stack(
                        children: [
                          Container(
                            width: 96,
                            height: 96,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              gradient: photo.isEmpty
                                  ? const LinearGradient(
                                      colors: [Color(0xFFFF9500), Color(0xFFFF5E36)],
                                      begin: Alignment.topLeft,
                                      end: Alignment.bottomRight,
                                    )
                                  : null,
                              image: photo.isNotEmpty
                                  ? DecorationImage(
                                      image: NetworkImage(ApiService.getFullImageUrl(photo)),
                                      fit: BoxFit.cover,
                                    )
                                  : null,
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withValues(alpha: 0.3),
                                  blurRadius: 16,
                                  offset: const Offset(0, 4),
                                ),
                              ],
                            ),
                            child: photo.isEmpty
                                ? Center(
                                    child: Text(
                                      name.isNotEmpty ? name[0].toUpperCase() : 'G',
                                      style: GoogleFonts.inter(
                                        color: Colors.white,
                                        fontSize: 36,
                                        fontWeight: FontWeight.bold,
                                      ),
                                    ),
                                  )
                                : null,
                          ),
                          Positioned(
                            right: 0,
                            bottom: 0,
                            child: InkWell(
                              onTap: _pickAndUpdateGroupPhoto,
                              borderRadius: BorderRadius.circular(16),
                              child: Container(
                                padding: const EdgeInsets.all(6),
                                decoration: BoxDecoration(
                                  color: _GSDark.accent,
                                  shape: BoxShape.circle,
                                  border: Border.all(color: _GSDark.bg, width: 2.5),
                                ),
                                child: const Icon(Icons.camera_alt_rounded, color: Colors.white, size: 16),
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      Text(
                        name,
                        style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        '${participantIds.length} members',
                        style: GoogleFonts.inter(color: _GSDark.textMuted, fontSize: 13.5),
                      ),
                      const SizedBox(height: 20),

                      // Quick Action Grid 4 Buttons (mute, search, leave, more) (Matching Screenshot)
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                        children: [
                          _buildActionButton(Icons.notifications_active_rounded, 'mute', () {}),
                          _buildActionButton(Icons.search_rounded, 'search', () {
                            Navigator.pop(context, 'SEARCH');
                          }),
                          _buildActionButton(Icons.logout_rounded, 'leave', () {
                            _leaveGroup(participantIds);
                          }),
                          _buildActionButton(Icons.more_horiz_rounded, 'more', () {
                            _showGroupMoreMenu(context);
                          }),
                        ],
                      ),
                      const SizedBox(height: 20),

                      // Group Content Tabs (Members, Media, Saved, Files, Voice) (Matching Screenshot)
                      SingleChildScrollView(
                        scrollDirection: Axis.horizontal,
                        child: Row(
                          children: [
                            _buildTab('Members', 0),
                            _buildTab('Media', 1),
                            _buildTab('Saved', 2),
                            _buildTab('Files', 3),
                            _buildTab('Voice', 4),
                          ],
                        ),
                      ),
                      const SizedBox(height: 14),
                      // Dynamic Group Tab Content (Members, Media, Saved, Files, Voice)
                      _buildGroupTabContent(_selectedTab, participantIds, createdBy, admins, isAdmin),
                      const SizedBox(height: 20),

                      // Admin Group Control Section (If Owner / Admin)
                      if (isAdmin) ...[
                        Container(
                          decoration: BoxDecoration(
                            color: _GSDark.card,
                            borderRadius: BorderRadius.circular(20),
                            border: Border.all(color: _GSDark.divider, width: 0.8),
                          ),
                          child: Column(
                            children: [
                              ListTile(
                                leading: const Icon(Icons.link_rounded, color: _GSDark.accent),
                                title: Text('តំណភ្ជាប់អញ្ជើញ (Group Invite Link)', style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5)),
                                subtitle: Text('t.me/vvc_group_${widget.groupId.substring(0, widget.groupId.length > 6 ? 6 : widget.groupId.length)}', style: GoogleFonts.inter(color: _GSDark.textMuted, fontSize: 12)),
                                trailing: const Icon(Icons.copy_rounded, color: Colors.white54, size: 18),
                                onTap: () {
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    SnackBar(content: Text('បានចម្លង Invite Link រួចរាល់!', style: GoogleFonts.kantumruyPro())),
                                  );
                                },
                              ),
                              if (isOwner) ...[
                                const Divider(height: 1, color: _GSDark.divider, indent: 50),
                                ListTile(
                                  leading: const Icon(Icons.delete_forever_rounded, color: _GSDark.danger),
                                  title: Text('លុបក្រុមចោល (Delete Group)', style: GoogleFonts.kantumruyPro(color: _GSDark.danger, fontWeight: FontWeight.bold, fontSize: 14.5)),
                                  onTap: () {
                                    showDialog(
                                      context: context,
                                      builder: (ctx) => AlertDialog(
                                        backgroundColor: _GSDark.card,
                                        title: Text('លុបក្រុម', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
                                        content: Text('តើអ្នកពិតជាចង់លុបក្រុមនេះចោលទាំងស្រុងមែនទេ?', style: GoogleFonts.kantumruyPro(color: Colors.white70)),
                                        actions: [
                                          TextButton(onPressed: () => Navigator.pop(ctx), child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted))),
                                          ElevatedButton(
                                            style: ElevatedButton.styleFrom(backgroundColor: _GSDark.danger),
                                            onPressed: () async {
                                              Navigator.pop(ctx);
                                              await _firestore.collection('groups').doc(widget.groupId).delete();
                                              if (context.mounted) {
                                                Navigator.of(context).popUntil((route) => route.isFirst);
                                              }
                                            },
                                            child: Text('លុបក្រុម', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
                                          ),
                                        ],
                                      ),
                                    );
                                  },
                                ),
                              ],
                            ],
                          ),
                        ),
                      ],
                      const SizedBox(height: 30),
                    ],
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  Widget _buildActionButton(IconData icon, String label, VoidCallback onTap) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(18),
      child: Container(
        width: 76,
        padding: const EdgeInsets.symmetric(vertical: 12),
        decoration: BoxDecoration(
          color: _GSDark.card,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: _GSDark.divider, width: 0.8),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.2),
              blurRadius: 8,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: _GSDark.accent, size: 22),
            const SizedBox(height: 5),
            Text(
              label,
              style: GoogleFonts.inter(
                color: _GSDark.accent,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTab(String title, int index) {
    final isSelected = _selectedTab == index;
    return AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      margin: const EdgeInsets.only(right: 8),
      decoration: BoxDecoration(
        color: isSelected ? _GSDark.accent : _GSDark.card,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: isSelected ? Colors.transparent : _GSDark.divider,
          width: 0.8,
        ),
      ),
      child: InkWell(
        onTap: () => setState(() => _selectedTab = index),
        borderRadius: BorderRadius.circular(20),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Text(
            title,
            style: GoogleFonts.inter(
              color: isSelected ? Colors.white : _GSDark.textMuted,
              fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
              fontSize: 13,
            ),
          ),
        ),
      ),
    );
  }

  void _showGroupMoreMenu(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: _GSDark.card,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (ctx) => Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: 12),
          Container(width: 36, height: 4, decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(10))),
          ListTile(
            leading: const Icon(Icons.link_rounded, color: Colors.white),
            title: Text('ចម្លង Invite Link', style: GoogleFonts.kantumruyPro(color: Colors.white)),
            onTap: () => Navigator.pop(ctx),
          ),
          ListTile(
            leading: const Icon(Icons.cleaning_services_rounded, color: Colors.white),
            title: Text('សម្អាតសារក្នុងក្រុម', style: GoogleFonts.kantumruyPro(color: Colors.white)),
            onTap: () => Navigator.pop(ctx),
          ),
          ListTile(
            leading: const Icon(Icons.report_problem_outlined, color: _GSDark.danger),
            title: Text('រាយការណ៍ (Report Group)', style: GoogleFonts.kantumruyPro(color: _GSDark.danger)),
            onTap: () => Navigator.pop(ctx),
          ),
          const SizedBox(height: 16),
        ],
      ),
    );
  }

  void _showAddMembersModal(List<dynamic> existingIds) {
    final Set<String> selectedNew = {};
    showModalBottomSheet(
      context: context,
      backgroundColor: _GSDark.card,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (ctx) {
        return StatefulBuilder(
          builder: (context, setStateModal) {
            final available = widget.allUsers.where((u) {
              final uid = (u['employee_id'] ?? '').toString();
              return !existingIds.contains(uid);
            }).toList();

            return Container(
              height: MediaQuery.of(context).size.height * 0.75,
              padding: const EdgeInsets.all(16),
              child: Column(
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text('បន្ថែមសមាជិកចូលក្រុម', style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                      ElevatedButton(
                        style: ElevatedButton.styleFrom(backgroundColor: _GSDark.accent),
                        onPressed: selectedNew.isEmpty
                            ? null
                            : () async {
                                final updated = List.from(existingIds)..addAll(selectedNew);
                                await _firestore.collection('groups').doc(widget.groupId).update({'participantIds': updated});
                                if (ctx.mounted) Navigator.pop(ctx);
                              },
                        child: Text('រក្សាទុក (${selectedNew.length})', style: GoogleFonts.kantumruyPro(color: Colors.white)),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Expanded(
                    child: ListView.builder(
                      itemCount: available.length,
                      itemBuilder: (ctx, idx) {
                        final u = available[idx];
                        final uid = (u['employee_id'] ?? '').toString();
                        final name = u['name'] ?? uid;
                        final isSelected = selectedNew.contains(uid);

                        return CheckboxListTile(
                          activeColor: _GSDark.accent,
                          title: Text(name, style: GoogleFonts.inter(color: Colors.white)),
                          value: isSelected,
                          onChanged: (val) {
                            setStateModal(() {
                              if (val == true) {
                                selectedNew.add(uid);
                              } else {
                                selectedNew.remove(uid);
                              }
                            });
                          },
                        );
                      },
                    ),
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }

  void _showEditGroupModal(BuildContext context, Map<String, dynamic> groupData) {
    final nameCtrl = TextEditingController(text: groupData['name'] ?? '');
    final descCtrl = TextEditingController(text: groupData['description'] ?? groupData['bio'] ?? '');
    final String photo = groupData['photo'] ?? '';

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: _GSDark.bg,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (ctx) {
        return StatefulBuilder(
          builder: (ctx, setModalState) {
            return Padding(
              padding: EdgeInsets.fromLTRB(
                16,
                12,
                16,
                MediaQuery.of(ctx).viewInsets.bottom + 20,
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      TextButton(
                        onPressed: () => Navigator.pop(ctx),
                        child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 15)),
                      ),
                      Text(
                        'ការកំណត់ក្រុម',
                        style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                      ),
                      TextButton(
                        onPressed: () async {
                          final newName = nameCtrl.text.trim();
                          final newDesc = descCtrl.text.trim();
                          if (newName.isNotEmpty) {
                            await _firestore.collection('groups').doc(widget.groupId).update({
                              'name': newName,
                              'description': newDesc,
                            });
                          }
                          if (ctx.mounted) Navigator.pop(ctx);
                        },
                        child: Text('រក្សាទុក', style: GoogleFonts.kantumruyPro(color: _GSDark.accent, fontSize: 15, fontWeight: FontWeight.bold)),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),

                  GestureDetector(
                    onTap: () async {
                      await _pickAndUpdateGroupPhoto();
                      if (ctx.mounted) setModalState(() {});
                    },
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        CircleAvatar(
                          radius: 44,
                          backgroundImage: photo.isNotEmpty
                              ? NetworkImage(ApiService.getFullImageUrl(photo))
                              : null,
                          backgroundColor: const Color(0xFFFFB300),
                          child: photo.isEmpty
                              ? const Icon(Icons.groups_rounded, color: Colors.white, size: 44)
                              : null,
                        ),
                        Container(
                          width: 88,
                          height: 88,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: Colors.black.withValues(alpha: 0.35),
                          ),
                          child: const Icon(Icons.camera_alt_rounded, color: Colors.white, size: 28),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text('ប៉ះដើម្បីប្តូររូបភាពក្រុម', style: GoogleFonts.kantumruyPro(color: _GSDark.accent, fontSize: 12)),
                  const SizedBox(height: 20),

                  Container(
                    decoration: BoxDecoration(
                      color: _GSDark.card,
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: _GSDark.divider, width: 0.8),
                    ),
                    child: TextField(
                      controller: nameCtrl,
                      style: GoogleFonts.kantumruyPro(color: Colors.white),
                      decoration: InputDecoration(
                        hintText: 'ឈ្មោះក្រុម (Group Name)',
                        hintStyle: GoogleFonts.kantumruyPro(color: _GSDark.textMuted),
                        border: InputBorder.none,
                        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),

                  Container(
                    decoration: BoxDecoration(
                      color: _GSDark.card,
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: _GSDark.divider, width: 0.8),
                    ),
                    child: TextField(
                      controller: descCtrl,
                      maxLines: 3,
                      style: GoogleFonts.kantumruyPro(color: Colors.white),
                      decoration: InputDecoration(
                        hintText: 'ការពិពណ៌នាអំពីក្រុម (Description)',
                        hintStyle: GoogleFonts.kantumruyPro(color: _GSDark.textMuted),
                        border: InputBorder.none,
                        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                ],
              ),
            );
          },
        );
      },
    );
  }

  Widget _buildGroupTabContent(int selectedTab, List<dynamic> participantIds, String createdBy, Map<String, dynamic> admins, bool isAdmin) {
    if (selectedTab == 0) {
      // Member List Card
      return Container(
        decoration: BoxDecoration(
          color: _GSDark.card,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: _GSDark.divider, width: 0.8),
        ),
        child: Column(
          children: [
            ListTile(
              leading: Container(
                width: 38,
                height: 38,
                decoration: const BoxDecoration(
                  color: Colors.transparent,
                  shape: BoxShape.circle,
                ),
                child: const Icon(Icons.person_add_alt_1_rounded, color: _GSDark.accent, size: 24),
              ),
              title: Text(
                'Add Members',
                style: GoogleFonts.inter(color: _GSDark.accent, fontSize: 15, fontWeight: FontWeight.w500),
              ),
              onTap: () => _showAddMembersModal(participantIds),
            ),
            const Divider(height: 1, color: _GSDark.divider, indent: 16),
            ListView.separated(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: participantIds.length,
              separatorBuilder: (_, __) => const Divider(height: 1, color: _GSDark.divider, indent: 64),
              itemBuilder: (context, idx) {
                final uid = participantIds[idx].toString();
                final userObj = widget.allUsers.firstWhere(
                  (u) => (u['employee_id'] ?? '').toString() == uid,
                  orElse: () => {'name': uid, 'avatar': '', 'isOnline': false},
                );

                final String memberName = userObj['name'] ?? uid;
                final String avatar = userObj['avatar'] ?? '';
                final bool isOnline = userObj['isOnline'] == true || uid == widget.currentUserId;
                final bool isUserOwner = uid == createdBy;
                final bool isUserAdmin = isUserOwner || (admins[uid] == true);
                final String? customTag = userObj['tag']?.toString();

                String statusStr = isOnline ? 'online' : 'last seen recently';

                return ListTile(
                  leading: Stack(
                    children: [
                      CircleAvatar(
                        radius: 19,
                        backgroundImage: avatar.isNotEmpty
                            ? NetworkImage(ApiService.getFullImageUrl(avatar))
                            : null,
                        backgroundColor: _GSDark.accent,
                        child: avatar.isEmpty
                            ? Text(memberName.isNotEmpty ? memberName[0].toUpperCase() : 'U', style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold))
                            : null,
                      ),
                      if (isOnline)
                        Positioned(
                          right: 0,
                          bottom: 0,
                          child: Container(
                            width: 9,
                            height: 9,
                            decoration: BoxDecoration(
                              color: const Color(0xFF10B981),
                              shape: BoxShape.circle,
                              border: Border.all(color: _GSDark.card, width: 1.5),
                            ),
                          ),
                        ),
                    ],
                  ),
                  title: Text(
                    memberName,
                    style: GoogleFonts.inter(color: Colors.white, fontSize: 14.5, fontWeight: FontWeight.w500),
                  ),
                  subtitle: Text(
                    statusStr,
                    style: GoogleFonts.inter(
                      color: isOnline ? _GSDark.accent : _GSDark.textMuted,
                      fontSize: 12,
                    ),
                  ),
                  trailing: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (isUserOwner)
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                          decoration: BoxDecoration(
                            color: const Color(0x33A855F7),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: Text('owner', style: GoogleFonts.inter(color: const Color(0xFFC084FC), fontSize: 11, fontWeight: FontWeight.w600)),
                        )
                      else if (isUserAdmin)
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                          decoration: BoxDecoration(
                            color: const Color(0x3322C55E),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: Text('admin', style: GoogleFonts.inter(color: const Color(0xFF4ADE80), fontSize: 11, fontWeight: FontWeight.w600)),
                        )
                      else if (customTag != null && customTag.isNotEmpty)
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                          decoration: BoxDecoration(
                            color: const Color(0x330A84FF),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: Text(customTag, style: GoogleFonts.inter(color: _GSDark.accent, fontSize: 11, fontWeight: FontWeight.w600)),
                        ),
                      if (isAdmin && uid != widget.currentUserId && !isUserOwner)
                        PopupMenuButton<String>(
                          icon: const Icon(Icons.more_vert_rounded, color: Colors.white54, size: 20),
                          color: _GSDark.card,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                          onSelected: (val) async {
                            if (val == 'toggle_admin') {
                              admins[uid] = !(admins[uid] == true);
                              await _firestore.collection('groups').doc(widget.groupId).update({'admins': admins});
                            } else if (val == 'remove') {
                              final updated = List.from(participantIds)..remove(uid);
                              await _firestore.collection('groups').doc(widget.groupId).update({'participantIds': updated});
                            }
                          },
                          itemBuilder: (ctx) => [
                            PopupMenuItem(
                              value: 'toggle_admin',
                              child: Text(
                                isUserAdmin ? 'ដកសិទ្ធិ Admin' : 'ដំឡើងជា Admin',
                                style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                              ),
                            ),
                            PopupMenuItem(
                              value: 'remove',
                              child: Text(
                                'លុបចេញពីក្រុម',
                                style: GoogleFonts.kantumruyPro(color: _GSDark.danger, fontSize: 13.5),
                              ),
                            ),
                          ],
                        ),
                    ],
                  ),
                );
              },
            ),
          ],
        ),
      );
    }

    String targetType = 'media';
    if (selectedTab == 1) targetType = 'media';
    if (selectedTab == 2) targetType = 'saved';
    if (selectedTab == 3) targetType = 'file';
    if (selectedTab == 4) targetType = 'voice';

    return StreamBuilder<QuerySnapshot>(
      stream: _firestore
          .collection('chats')
          .doc(widget.groupId)
          .collection('messages')
          .orderBy('timestamp', descending: true)
          .snapshots(),
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(child: Padding(padding: EdgeInsets.all(24), child: CircularProgressIndicator(color: _GSDark.accent)));
        }

        final docs = snapshot.data!.docs.where((doc) {
          final data = doc.data() as Map<String, dynamic>;
          final type = data['type']?.toString() ?? '';
          if (targetType == 'media') return type == 'image' || type == 'video' || data['stickerUrl'] != null;
          if (targetType == 'file') return type == 'file' || type == 'document' || type == 'pdf';
          if (targetType == 'voice') return type == 'voice' || type == 'audio';
          if (targetType == 'saved') return data['isPinned'] == true || data['isSaved'] == true;
          return true;
        }).toList();

        if (docs.isEmpty) {
          return Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 36, horizontal: 16),
            decoration: BoxDecoration(
              color: _GSDark.card,
              borderRadius: BorderRadius.circular(20),
              border: Border.all(color: _GSDark.divider, width: 0.8),
            ),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.perm_media_outlined, color: _GSDark.textMuted, size: 40),
                const SizedBox(height: 10),
                Text(
                  'គ្មានប្រព័ន្ធផ្សព្វផ្សាយនៅឡើយទេ',
                  style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted, fontSize: 13.5),
                ),
              ],
            ),
          );
        }

        if (targetType == 'media') {
          return GridView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 3,
              crossAxisSpacing: 6,
              mainAxisSpacing: 6,
            ),
            itemCount: docs.length,
            itemBuilder: (context, idx) {
              final data = docs[idx].data() as Map<String, dynamic>;
              final url = data['fileUrl'] ?? data['text'] ?? data['stickerUrl'] ?? '';
              return ClipRRect(
                borderRadius: BorderRadius.circular(12),
                child: Container(
                  color: _GSDark.card,
                  child: Image.network(
                    ApiService.getFullImageUrl(url),
                    fit: BoxFit.cover,
                    errorBuilder: (_, __, ___) => const Center(child: Icon(Icons.image_not_supported_rounded, color: Colors.white38)),
                  ),
                ),
              );
            },
          );
        }

        return Container(
          decoration: BoxDecoration(
            color: _GSDark.card,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: _GSDark.divider, width: 0.8),
          ),
          child: ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: docs.length,
            separatorBuilder: (_, __) => const Divider(height: 1, color: _GSDark.divider, indent: 16),
            itemBuilder: (context, idx) {
              final data = docs[idx].data() as Map<String, dynamic>;
              final text = data['text'] ?? data['fileName'] ?? 'សារប្រព័ន្ធផ្សព្វផ្សាយ';
              final sender = data['senderName'] ?? 'សមាជិក';

              if (targetType == 'voice') {
                final audioUrl = (data['audioUrl'] ?? data['voiceUrl'] ?? data['base64Audio'] ?? '').toString();
                final durationSeconds = (data['audioDuration'] ?? data['duration'] ?? 3) as int;
                final Timestamp? ts = data['timestamp'] as Timestamp?;

                return _VoicePlayerTile(
                  audioUrl: audioUrl,
                  durationSeconds: durationSeconds,
                  senderName: sender,
                  timestamp: ts,
                );
              }

              return ListTile(
                leading: const Icon(
                  Icons.insert_drive_file_rounded,
                  color: _GSDark.accent,
                ),
                title: Text(text, style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14)),
                subtitle: Text('ផ្ញើដោយ: $sender', style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted, fontSize: 12)),
              );
            },
          ),
        );
      },
    );
  }
}

class _VoicePlayerTile extends StatefulWidget {
  final String audioUrl;
  final int durationSeconds;
  final String senderName;
  final Timestamp? timestamp;

  const _VoicePlayerTile({
    required this.audioUrl,
    required this.durationSeconds,
    required this.senderName,
    this.timestamp,
  });

  @override
  State<_VoicePlayerTile> createState() => _VoicePlayerTileState();
}

class _VoicePlayerTileState extends State<_VoicePlayerTile> {
  final AudioPlayer _audioPlayer = AudioPlayer();
  bool _isPlaying = false;
  Duration _position = Duration.zero;
  Duration _duration = Duration.zero;

  @override
  void initState() {
    super.initState();
    _duration = Duration(seconds: widget.durationSeconds);
    _audioPlayer.onPositionChanged.listen((p) {
      if (mounted) setState(() => _position = p);
    });
    _audioPlayer.onDurationChanged.listen((d) {
      if (mounted) setState(() => _duration = d);
    });
    _audioPlayer.onPlayerComplete.listen((_) {
      if (mounted) {
        setState(() {
          _isPlaying = false;
          _position = Duration.zero;
        });
      }
    });
  }

  @override
  void dispose() {
    _audioPlayer.dispose();
    super.dispose();
  }

  Future<void> _togglePlay() async {
    if (_isPlaying) {
      await _audioPlayer.pause();
      if (mounted) setState(() => _isPlaying = false);
    } else {
      if (widget.audioUrl.isNotEmpty) {
        await _audioPlayer.play(UrlSource(ApiService.getFullImageUrl(widget.audioUrl)));
        if (mounted) setState(() => _isPlaying = true);
      }
    }
  }

  String _formatDuration(Duration d) {
    final mins = d.inMinutes.remainder(60).toString().padLeft(2, '0');
    final secs = d.inSeconds.remainder(60).toString().padLeft(2, '0');
    return '$mins:$secs';
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      child: Row(
        children: [
          // Play / Pause Button
          InkWell(
            onTap: _togglePlay,
            borderRadius: BorderRadius.circular(22),
            child: Container(
              width: 44,
              height: 44,
              decoration: const BoxDecoration(
                color: Color(0xFF3388FF),
                shape: BoxShape.circle,
              ),
              child: Icon(
                _isPlaying ? Icons.pause_rounded : Icons.play_arrow_rounded,
                color: Colors.white,
                size: 26,
              ),
            ),
          ),
          const SizedBox(width: 12),
          // Waveform bar & Info
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      widget.senderName,
                      style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13.5),
                    ),
                    Text(
                      _formatDuration(_isPlaying ? _position : _duration),
                      style: GoogleFonts.inter(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.w600),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                // Audio Waveform Progress Bar
                LayoutBuilder(
                  builder: (context, constraints) {
                    final progress = _duration.inMilliseconds > 0
                        ? (_position.inMilliseconds / _duration.inMilliseconds).clamp(0.0, 1.0)
                        : 0.0;
                    return Container(
                      height: 5,
                      width: constraints.maxWidth,
                      decoration: BoxDecoration(
                        color: Colors.white24,
                        borderRadius: BorderRadius.circular(3),
                      ),
                      child: FractionallySizedBox(
                        alignment: Alignment.centerLeft,
                        widthFactor: progress,
                        child: Container(
                          decoration: BoxDecoration(
                            color: const Color(0xFF3388FF),
                            borderRadius: BorderRadius.circular(3),
                          ),
                        ),
                      ),
                    );
                  },
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
