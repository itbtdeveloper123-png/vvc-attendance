import 'dart:io';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:image_picker/image_picker.dart';
import '../services/api_service.dart';
import '../services/r2_storage_service.dart';

class _GSDark {
  static const Color bg = Color(0xFF0F172A);
  static const Color card = Color(0xFF1E293B);
  static const Color textMuted = Color(0xFF94A3B8);
  static const Color accent = Color(0xFF0A84FF);
  static const Color danger = Color(0xFFFF3B30);
  static const Color divider = Color(0xFF334155);
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
                        if (isAdmin) {
                          _pickAndUpdateGroupPhoto();
                        }
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
                      // Group Avatar & Name Header (Matching Screenshot)
                      CircleAvatar(
                        radius: 46,
                        backgroundImage: photo.isNotEmpty
                            ? NetworkImage(ApiService.getFullImageUrl(photo))
                            : null,
                        backgroundColor: const Color(0xFFFFB300),
                        child: photo.isEmpty
                            ? const Icon(Icons.groups_rounded, color: Colors.white, size: 48)
                            : null,
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

                      // Member List Card (Matching Screenshot 100%)
                      Container(
                        decoration: BoxDecoration(
                          color: _GSDark.card,
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(color: _GSDark.divider, width: 0.8),
                        ),
                        child: Column(
                          children: [
                            // Top Add Members Item inside Card
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

                            // Members List
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
                      ),
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
      borderRadius: BorderRadius.circular(16),
      child: Container(
        width: 68,
        height: 62,
        decoration: BoxDecoration(
          color: _GSDark.card,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: _GSDark.divider, width: 0.8),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, color: _GSDark.accent, size: 22),
            const SizedBox(height: 4),
            Text(label, style: GoogleFonts.inter(color: _GSDark.accent, fontSize: 11)),
          ],
        ),
      ),
    );
  }

  Widget _buildTab(String title, int index) {
    final isSelected = _selectedTab == index;
    return GestureDetector(
      onTap: () => setState(() => _selectedTab = index),
      child: Container(
        margin: const EdgeInsets.only(right: 8),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        decoration: BoxDecoration(
          color: isSelected ? _GSDark.divider : _GSDark.card,
          borderRadius: BorderRadius.circular(16),
        ),
        child: Text(
          title,
          style: GoogleFonts.inter(
            color: isSelected ? Colors.white : _GSDark.textMuted,
            fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
            fontSize: 13,
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
}
