import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:image_picker/image_picker.dart';
import '../services/api_service.dart';
import '../services/r2_storage_service.dart';

class _GSDark {
  static const Color bg = Color(0xFF111827);
  static const Color card = Color(0xFF1E293B);
  static const Color textMuted = Color(0xFF94A3B8);
  static const Color accent = Color(0xFF007AFF);
  static const Color danger = Color(0xFFEF4444);
  static const Color success = Color(0xFF10B981);
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
  bool _isUpdating = false;

  @override
  void initState() {
    super.initState();
    _groupStream = _firestore.collection('groups').doc(widget.groupId).snapshots();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _GSDark.bg,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          'ការកំណត់ក្រុម (Group Settings)',
          style: GoogleFonts.kantumruyPro(
            color: Colors.white,
            fontSize: 18,
            fontWeight: FontWeight.bold,
          ),
        ),
        centerTitle: true,
      ),
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
          final String description = groupData['description'] ?? 'គ្មានការពិពណ៌នាឡើយ';
          final String photo = groupData['photo'] ?? '';
          final String createdBy = groupData['createdBy'] ?? '';
          final String groupType = groupData['groupType'] ?? 'Private';
          final bool enableReactions = groupData['enableReactions'] ?? true;
          final String communityName = groupData['communityName'] ?? '';

          final List<dynamic> participantIds = groupData['participantIds'] ?? [];
          final Map<String, dynamic> admins = groupData['admins'] as Map<String, dynamic>? ?? {};
          final Map<String, dynamic> permissions = groupData['permissions'] as Map<String, dynamic>? ?? {
            'sendMessages': true,
            'sendMedia': true,
            'addMembers': true,
            'pinMessages': true,
            'editTags': true,
            'createTopics': true,
            'changeInfo': true,
          };
          final List<dynamic> topics = groupData['topics'] ?? ['General'];

          final bool isOwner = createdBy == widget.currentUserId;
          final bool isAdmin = isOwner || (admins[widget.currentUserId] == true);

          return ListView(
            physics: const BouncingScrollPhysics(),
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            children: [
              // 1. Group Avatar & Basic Info Header
              _buildHeaderSection(name, description, photo, isAdmin),

              const SizedBox(height: 20),

              // 2. Group Type & Invite Link Section
              _buildGroupTypeAndInviteSection(groupType, isAdmin),

              const SizedBox(height: 20),

              // 3. Permissions & Management Section
              _buildPermissionsSection(permissions, enableReactions, isAdmin),

              const SizedBox(height: 20),

              // 4. Topics & Community Section
              _buildTopicsAndCommunitySection(topics, communityName, isAdmin),

              const SizedBox(height: 20),

              // 5. Member Management Section
              _buildMemberManagementSection(participantIds, admins, createdBy, isAdmin, isOwner),

              const SizedBox(height: 20),

              // 6. Danger Zone (Delete Group)
              if (isAdmin) _buildDangerZoneSection(name, isOwner),

              const SizedBox(height: 30),
            ],
          );
        },
      ),
    );
  }

  // =========================================================================
  // 1. HEADER SECTION (PHOTO, NAME, DESC)
  // =========================================================================
  Widget _buildHeaderSection(String name, String description, String photo, bool isAdmin) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: _GSDark.card,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Column(
        children: [
          Stack(
            alignment: Alignment.center,
            children: [
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
              if (_isUpdating)
                const SizedBox(
                  width: 46,
                  height: 46,
                  child: CircularProgressIndicator(color: Colors.white, strokeWidth: 3),
                ),
              if (isAdmin)
                Positioned(
                  right: 0,
                  bottom: 0,
                  child: InkWell(
                    onTap: _pickAndUpdateGroupPhoto,
                    child: Container(
                      padding: const EdgeInsets.all(8),
                      decoration: const BoxDecoration(
                        color: _GSDark.accent,
                        shape: BoxShape.circle,
                      ),
                      child: const Icon(Icons.camera_alt_rounded, color: Colors.white, size: 18),
                    ),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 14),
          Text(
            name,
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontSize: 20,
              fontWeight: FontWeight.bold,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 6),
          Text(
            description,
            style: GoogleFonts.kantumruyPro(
              color: _GSDark.textMuted,
              fontSize: 13.5,
            ),
            textAlign: TextAlign.center,
          ),
          if (isAdmin) ...[
            const SizedBox(height: 14),
            OutlinedButton.icon(
              onPressed: () => _showEditGroupDialog(name, description),
              icon: const Icon(Icons.edit_rounded, size: 16, color: _GSDark.accent),
              label: Text(
                'កែសម្រួលឈ្មោះ និង Description',
                style: GoogleFonts.kantumruyPro(color: _GSDark.accent, fontSize: 13),
              ),
              style: OutlinedButton.styleFrom(
                side: const BorderSide(color: _GSDark.accent),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Future<void> _pickAndUpdateGroupPhoto() async {
    final XFile? picked = await _picker.pickImage(source: ImageSource.gallery, imageQuality: 80);
    if (picked == null) return;

    setState(() => _isUpdating = true);
    final String? uploadedUrl = await _r2Service.uploadMedia(
      file: File(picked.path),
      folder: 'group_photos',
    );

    if (uploadedUrl != null) {
      await _firestore.collection('groups').doc(widget.groupId).update({'photo': uploadedUrl});
    }

    if (mounted) setState(() => _isUpdating = false);
  }

  void _showEditGroupDialog(String currentName, String currentDesc) {
    final nameCtrl = TextEditingController(text: currentName);
    final descCtrl = TextEditingController(text: currentDesc);

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: _GSDark.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
        title: Text(
          'កែសម្រួលព័ត៌មានក្រុម',
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: nameCtrl,
              style: GoogleFonts.kantumruyPro(color: Colors.white),
              decoration: InputDecoration(
                labelText: 'ឈ្មោះក្រុម (Group Name)',
                labelStyle: GoogleFonts.kantumruyPro(color: _GSDark.textMuted),
                enabledBorder: const UnderlineInputBorder(borderSide: BorderSide(color: _GSDark.accent)),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: descCtrl,
              style: GoogleFonts.kantumruyPro(color: Colors.white),
              decoration: InputDecoration(
                labelText: 'ការពិពណ៌នា (Description)',
                labelStyle: GoogleFonts.kantumruyPro(color: _GSDark.textMuted),
                enabledBorder: const UnderlineInputBorder(borderSide: BorderSide(color: _GSDark.accent)),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: _GSDark.accent),
            onPressed: () async {
              Navigator.pop(ctx);
              await _firestore.collection('groups').doc(widget.groupId).update({
                'name': nameCtrl.text.trim(),
                'description': descCtrl.text.trim(),
              });
            },
            child: Text('រក្សាទុក', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  // =========================================================================
  // 2. GROUP TYPE & INVITE LINK SECTION
  // =========================================================================
  Widget _buildGroupTypeAndInviteSection(String groupType, bool isAdmin) {
    final String inviteUrl = 'https://vvc.asia/g/${widget.groupId}';

    return Container(
      decoration: BoxDecoration(
        color: _GSDark.card,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          ListTile(
            leading: const Icon(Icons.lock_outline_rounded, color: _GSDark.accent),
            title: Text(
              'ប្រភេទក្រុម (Group Type)',
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5, fontWeight: FontWeight.w600),
            ),
            subtitle: Text(
              groupType == 'Public' ? 'សាធារណៈ (Public)' : 'ឯកជន (Private)',
              style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted, fontSize: 12.5),
            ),
            trailing: isAdmin
                ? Switch(
                    value: groupType == 'Public',
                    activeTrackColor: _GSDark.accent,
                    onChanged: (val) async {
                      await _firestore.collection('groups').doc(widget.groupId).update({
                        'groupType': val ? 'Public' : 'Private',
                      });
                    },
                  )
                : null,
          ),
          const Divider(height: 1, color: _GSDark.divider, indent: 50),
          ListTile(
            leading: const Icon(Icons.link_rounded, color: _GSDark.success),
            title: Text(
              'លីងអញ្ជើញ (Invite Link)',
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5, fontWeight: FontWeight.w600),
            ),
            subtitle: Text(
              inviteUrl,
              style: GoogleFonts.inter(color: _GSDark.textMuted, fontSize: 12),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: IconButton(
              icon: const Icon(Icons.copy_rounded, color: Colors.white70, size: 20),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: inviteUrl));
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('បានចម្លង Invite Link រួចរាល់!', style: GoogleFonts.kantumruyPro()),
                    backgroundColor: _GSDark.success,
                    behavior: SnackBarBehavior.floating,
                  ),
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  // =========================================================================
  // 3. PERMISSIONS & REACTIONS SECTION
  // =========================================================================
  Widget _buildPermissionsSection(Map<String, dynamic> permissions, bool enableReactions, bool isAdmin) {
    return Container(
      decoration: BoxDecoration(
        color: _GSDark.card,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          ListTile(
            leading: const Icon(Icons.security_rounded, color: Color(0xFFAF52DE)),
            title: Text(
              'ការកំណត់សិទ្ធិ (Group Permissions)',
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5, fontWeight: FontWeight.w600),
            ),
            subtitle: Text(
              'កំណត់សិទ្ធិផ្ញើសារ, Media, បន្ថែមសមាជិក...',
              style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted, fontSize: 12.5),
            ),
            trailing: const Icon(Icons.chevron_right_rounded, color: Colors.white54),
            onTap: () => _showPermissionsBottomSheet(permissions, isAdmin),
          ),
          const Divider(height: 1, color: _GSDark.divider, indent: 50),
          ListTile(
            leading: const Icon(Icons.add_reaction_rounded, color: Color(0xFFFF9500)),
            title: Text(
              'Emoji Reactions',
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5, fontWeight: FontWeight.w600),
            ),
            subtitle: Text(
              'អនុញ្ញាតឱ្យសមាជិក Reaction លើសារ',
              style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted, fontSize: 12.5),
            ),
            trailing: Switch(
              value: enableReactions,
              activeTrackColor: _GSDark.accent,
              onChanged: isAdmin
                  ? (val) async {
                      await _firestore.collection('groups').doc(widget.groupId).update({
                        'enableReactions': val,
                      });
                    }
                  : null,
            ),
          ),
        ],
      ),
    );
  }

  void _showPermissionsBottomSheet(Map<String, dynamic> perms, bool isAdmin) {
    showModalBottomSheet(
      context: context,
      backgroundColor: _GSDark.card,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        return StatefulBuilder(
          builder: (context, setModalState) {
            Widget buildPermSwitch(String key, String title, IconData icon) {
              final val = perms[key] ?? true;
              return ListTile(
                leading: Icon(icon, color: Colors.white70, size: 20),
                title: Text(title, style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14)),
                trailing: Switch(
                  value: val,
                  activeTrackColor: _GSDark.accent,
                  onChanged: isAdmin
                      ? (newVal) async {
                          setModalState(() => perms[key] = newVal);
                          await _firestore.collection('groups').doc(widget.groupId).update({
                            'permissions': perms,
                          });
                        }
                      : null,
                ),
              );
            }

            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 16),
              child: ListView(
                shrinkWrap: true,
                children: [
                  Center(
                    child: Text(
                      'កំណត់សិទ្ធិសមាជិក (Member Permissions)',
                      style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                    ),
                  ),
                  const SizedBox(height: 10),
                  buildPermSwitch('sendMessages', 'ផ្ញើសារ (Send Messages)', Icons.chat_bubble_outline_rounded),
                  buildPermSwitch('sendMedia', 'ផ្ញើរូបភាព/វីដេអូ (Send Media)', Icons.photo_library_outlined),
                  buildPermSwitch('addMembers', 'បន្ថែមសមាជិក (Add Members)', Icons.person_add_outlined),
                  buildPermSwitch('pinMessages', 'ប៉ិនសារ (Pin Messages)', Icons.push_pin_outlined),
                  buildPermSwitch('editTags', 'កែសម្រួល Tag ខ្លួនឯង (Edit Own Tags)', Icons.tag_rounded),
                  buildPermSwitch('createTopics', 'បង្កើត Topic (Create Topics)', Icons.topic_outlined),
                  buildPermSwitch('changeInfo', 'កែប្រែព័ត៌មានក្រុម (Change Group Info)', Icons.info_outline_rounded),
                ],
              ),
            );
          },
        );
      },
    );
  }

  // =========================================================================
  // 4. TOPICS & COMMUNITY SECTION
  // =========================================================================
  Widget _buildTopicsAndCommunitySection(List<dynamic> topics, String communityName, bool isAdmin) {
    return Container(
      decoration: BoxDecoration(
        color: _GSDark.card,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          ListTile(
            leading: const Icon(Icons.topic_rounded, color: Color(0xFF30B0C7)),
            title: Text(
              'Topics / ប្រធានបទ (${topics.length})',
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5, fontWeight: FontWeight.w600),
            ),
            subtitle: Text(
              topics.join(', '),
              style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted, fontSize: 12),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: isAdmin
                ? IconButton(
                    icon: const Icon(Icons.add_circle_outline_rounded, color: _GSDark.accent),
                    onPressed: () => _showAddTopicDialog(topics),
                  )
                : null,
          ),
          const Divider(height: 1, color: _GSDark.divider, indent: 50),
          ListTile(
            leading: const Icon(Icons.hub_rounded, color: Colors.amber),
            title: Text(
              'បញ្ចូលក្នុង Community',
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5, fontWeight: FontWeight.w600),
            ),
            subtitle: Text(
              communityName.isNotEmpty ? communityName : 'មិនទាន់បានបញ្ចូលក្នុង Community',
              style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted, fontSize: 12),
            ),
            trailing: isAdmin
                ? IconButton(
                    icon: const Icon(Icons.edit_outlined, color: Colors.white54),
                    onPressed: () => _showCommunityDialog(communityName),
                  )
                : null,
          ),
        ],
      ),
    );
  }

  void _showAddTopicDialog(List<dynamic> currentTopics) {
    final ctrl = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: _GSDark.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Text('បន្ថែម Topic ថ្មី', style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16)),
        content: TextField(
          controller: ctrl,
          style: GoogleFonts.kantumruyPro(color: Colors.white),
          decoration: InputDecoration(
            hintText: 'ឈ្មោះ Topic (ឧ. Announcements)',
            hintStyle: GoogleFonts.kantumruyPro(color: _GSDark.textMuted),
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted))),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: _GSDark.accent),
            onPressed: () async {
              if (ctrl.text.trim().isNotEmpty) {
                Navigator.pop(ctx);
                final updated = List.from(currentTopics)..add(ctrl.text.trim());
                await _firestore.collection('groups').doc(widget.groupId).update({'topics': updated});
              }
            },
            child: Text('បន្ថែម', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  void _showCommunityDialog(String current) {
    final ctrl = TextEditingController(text: current);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: _GSDark.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Text('ឈ្មោះ Community', style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16)),
        content: TextField(
          controller: ctrl,
          style: GoogleFonts.kantumruyPro(color: Colors.white),
          decoration: InputDecoration(
            hintText: 'ឧ. VVC Corporate Community',
            hintStyle: GoogleFonts.kantumruyPro(color: _GSDark.textMuted),
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted))),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: _GSDark.accent),
            onPressed: () async {
              Navigator.pop(ctx);
              await _firestore.collection('groups').doc(widget.groupId).update({'communityName': ctrl.text.trim()});
            },
            child: Text('រក្សាទុក', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  // =========================================================================
  // 5. MEMBER MANAGEMENT & ADMINS
  // =========================================================================
  Widget _buildMemberManagementSection(
    List<dynamic> participantIds,
    Map<String, dynamic> admins,
    String createdBy,
    bool isAdmin,
    bool isOwner,
  ) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: _GSDark.card,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                'សមាជិកក្រុម (${participantIds.length})',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 15.5,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const Spacer(),
              if (isAdmin)
                TextButton.icon(
                  onPressed: () => _showAddMembersModal(participantIds),
                  icon: const Icon(Icons.person_add_rounded, size: 18, color: _GSDark.accent),
                  label: Text('បន្ថែម', style: GoogleFonts.kantumruyPro(color: _GSDark.accent)),
                ),
            ],
          ),
          const SizedBox(height: 10),

          ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: participantIds.length,
            separatorBuilder: (_, __) => const Divider(height: 1, color: _GSDark.divider),
            itemBuilder: (context, index) {
              final uid = participantIds[index].toString();
              final userObj = widget.allUsers.firstWhere(
                (u) => (u['employee_id'] ?? '').toString() == uid,
                orElse: () => {'name': uid, 'avatar': ''},
              );

              final String name = userObj['name'] ?? uid;
              final String avatar = userObj['avatar'] ?? '';
              final bool isUserOwner = uid == createdBy;
              final bool isUserAdmin = isUserOwner || (admins[uid] == true);

              return ListTile(
                contentPadding: EdgeInsets.zero,
                leading: CircleAvatar(
                  radius: 20,
                  backgroundImage: avatar.isNotEmpty ? NetworkImage(ApiService.getFullImageUrl(avatar)) : null,
                  backgroundColor: _GSDark.accent,
                  child: avatar.isEmpty
                      ? Text(name.isNotEmpty ? name[0].toUpperCase() : 'U', style: const TextStyle(color: Colors.white))
                      : null,
                ),
                title: Text(
                  name,
                  style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5, fontWeight: FontWeight.w500),
                ),
                subtitle: isUserOwner
                    ? Text('Owner (ម្ចាស់ក្រុម)', style: GoogleFonts.kantumruyPro(color: Colors.amber, fontSize: 11.5))
                    : (isUserAdmin
                        ? Text('Admin', style: GoogleFonts.kantumruyPro(color: _GSDark.accent, fontSize: 11.5))
                        : null),
                trailing: (isAdmin && uid != widget.currentUserId && !isUserOwner)
                    ? PopupMenuButton<String>(
                        icon: const Icon(Icons.more_vert_rounded, color: Colors.white54),
                        color: _GSDark.card,
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
                              style: GoogleFonts.kantumruyPro(color: Colors.white),
                            ),
                          ),
                          PopupMenuItem(
                            value: 'remove',
                            child: Text(
                              'លុបចេញពីក្រុម',
                              style: GoogleFonts.kantumruyPro(color: _GSDark.danger),
                            ),
                          ),
                        ],
                      )
                    : null,
              );
            },
          ),
        ],
      ),
    );
  }

  void _showAddMembersModal(List<dynamic> existingIds) {
    final Set<String> selectedNew = {};
    showModalBottomSheet(
      context: context,
      backgroundColor: _GSDark.card,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        return StatefulBuilder(
          builder: (context, setModalState) {
            final available = widget.allUsers.where((u) {
              final id = (u['employee_id'] ?? '').toString();
              return !existingIds.contains(id);
            }).toList();

            return Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                children: [
                  Text(
                    'បន្ថែមសមាជិកចូលក្រុម',
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 10),
                  Expanded(
                    child: ListView.builder(
                      itemCount: available.length,
                      itemBuilder: (ctx, i) {
                        final u = available[i];
                        final id = (u['employee_id'] ?? '').toString();
                        final name = u['name'] ?? id;
                        final isSel = selectedNew.contains(id);

                        return CheckboxListTile(
                          value: isSel,
                          activeColor: _GSDark.accent,
                          title: Text(name, style: GoogleFonts.kantumruyPro(color: Colors.white)),
                          onChanged: (val) {
                            setModalState(() {
                              if (val == true) {
                                selectedNew.add(id);
                              } else {
                                selectedNew.remove(id);
                              }
                            });
                          },
                        );
                      },
                    ),
                  ),
                  SizedBox(
                    width: double.infinity,
                    height: 48,
                    child: ElevatedButton(
                      style: ElevatedButton.styleFrom(backgroundColor: _GSDark.accent),
                      onPressed: selectedNew.isEmpty
                          ? null
                          : () async {
                              Navigator.pop(ctx);
                              final updated = List.from(existingIds)..addAll(selectedNew);
                              await _firestore.collection('groups').doc(widget.groupId).update({'participantIds': updated});
                            },
                      child: Text('បញ្ចូល ${selectedNew.length} នាក់', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
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

  // =========================================================================
  // 6. DANGER ZONE (DELETE GROUP)
  // =========================================================================
  Widget _buildDangerZoneSection(String name, bool isOwner) {
    return Container(
      decoration: BoxDecoration(
        color: _GSDark.card,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: _GSDark.danger.withValues(alpha: 0.4), width: 1),
      ),
      child: ListTile(
        leading: const Icon(Icons.delete_forever_rounded, color: _GSDark.danger),
        title: Text(
          'លុបក្រុម (Delete Group)',
          style: GoogleFonts.kantumruyPro(color: _GSDark.danger, fontSize: 14.5, fontWeight: FontWeight.bold),
        ),
        subtitle: Text(
          'លុបក្រុម "$name" និងទិន្នន័យឆាតទាំងអស់ជាអចិន្ត្រៃយ៍',
          style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted, fontSize: 12),
        ),
        onTap: () => _confirmDeleteGroup(name),
      ),
    );
  }

  void _confirmDeleteGroup(String groupName) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: _GSDark.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
        title: Text(
          'តើអ្នកពិតជាចង់លុបក្រុមនេះមែនទេ?',
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
        ),
        content: Text(
          'ការលុបក្រុម "$groupName" នឹងធ្វើឱ្យបាត់បង់ទិន្នន័យឆាត និងសមាជិកទាំងអស់ជាអចិន្ត្រៃយ៍។',
          style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13.5),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: _GSDark.textMuted)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: _GSDark.danger),
            onPressed: () async {
              Navigator.pop(ctx);
              await _firestore.collection('groups').doc(widget.groupId).delete();
              if (mounted) {
                Navigator.pop(context); // Pop GroupSettingsScreen
                Navigator.pop(context); // Pop ChatDetailScreen back to chat list
              }
            },
            child: Text('លុបក្រុម', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }
}
