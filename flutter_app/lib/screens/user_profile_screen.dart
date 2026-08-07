import 'dart:io';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:provider/provider.dart';
import 'package:audioplayers/audioplayers.dart';
import 'package:path_provider/path_provider.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../widgets/chat_wallpaper_picker.dart';
import '../widgets/vvc_global_alert.dart';

class UserProfileScreen extends StatefulWidget {
  final String userId;
  final String userName;
  final String userPhoto;

  const UserProfileScreen({
    super.key,
    required this.userId,
    required this.userName,
    this.userPhoto = '',
  });

  @override
  State<UserProfileScreen> createState() => _UserProfileScreenState();
}

class _UserProfileScreenState extends State<UserProfileScreen> {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  int _selectedTab = 1; // 0: Posts, 1: Media, 2: Files, 3: Music, 4: Voice

  void _showEditContactModal(String firstName, String lastName, String phone, String bio) {
    final fnCtrl = TextEditingController(text: firstName);
    final lnCtrl = TextEditingController(text: lastName);
    final notesCtrl = TextEditingController();

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF0F172A),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (ctx) {
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
              // Top Bar: Cancel, Avatar, Done
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  TextButton(
                    onPressed: () => Navigator.pop(ctx),
                    child: Text('Cancel', style: GoogleFonts.inter(color: Colors.white, fontSize: 16)),
                  ),
                  CircleAvatar(
                    radius: 26,
                    backgroundImage: widget.userPhoto.isNotEmpty
                        ? NetworkImage(ApiService.getFullImageUrl(widget.userPhoto))
                        : null,
                    backgroundColor: const Color(0xFF007AFF),
                    child: widget.userPhoto.isEmpty
                        ? Text(widget.userName[0].toUpperCase(), style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold))
                        : null,
                  ),
                  TextButton(
                    onPressed: () async {
                      final newName = '${fnCtrl.text.trim()} ${lnCtrl.text.trim()}'.trim();
                      if (newName.isNotEmpty) {
                        await _firestore.collection('users').doc(widget.userId).update({
                          'name': newName,
                        });
                      }
                      if (ctx.mounted) Navigator.pop(ctx);
                    },
                    child: Text('Done', style: GoogleFonts.inter(color: const Color(0xFF0A84FF), fontSize: 16, fontWeight: FontWeight.bold)),
                  ),
                ],
              ),
              const SizedBox(height: 20),

              // 1. Name Inputs Card (Matching Screenshot 2)
              Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Column(
                  children: [
                    TextField(
                      controller: fnCtrl,
                      style: GoogleFonts.inter(color: Colors.white),
                      decoration: InputDecoration(
                        hintText: 'First Name',
                        hintStyle: GoogleFonts.inter(color: Colors.white38),
                        border: InputBorder.none,
                        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                      ),
                    ),
                    const Divider(height: 1, color: Color(0xFF334155), indent: 16),
                    TextField(
                      controller: lnCtrl,
                      style: GoogleFonts.inter(color: Colors.white),
                      decoration: InputDecoration(
                        hintText: 'Last Name',
                        hintStyle: GoogleFonts.inter(color: Colors.white38),
                        border: InputBorder.none,
                        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),

              // 2. Add Notes Card (Matching Screenshot 2)
              Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: TextField(
                  controller: notesCtrl,
                  style: GoogleFonts.inter(color: Colors.white),
                  decoration: InputDecoration(
                    hintText: 'Add Notes',
                    hintStyle: GoogleFonts.inter(color: Colors.white38),
                    border: InputBorder.none,
                    contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                  ),
                ),
              ),
              const SizedBox(height: 4),
              Align(
                alignment: Alignment.centerLeft,
                child: Text('Notes are only visible to you.', style: GoogleFonts.inter(color: Colors.white38, fontSize: 12)),
              ),
              const SizedBox(height: 16),

              // 3. Photo Options Card (Matching Screenshot 2)
              Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Column(
                  children: [
                    ListTile(
                      leading: const Icon(Icons.wb_incandescent_outlined, color: Color(0xFF0A84FF)),
                      title: Text('Suggest Photo for ${fnCtrl.text}', style: GoogleFonts.inter(color: const Color(0xFF0A84FF))),
                      onTap: () {},
                    ),
                    const Divider(height: 1, color: Color(0xFF334155), indent: 50),
                    ListTile(
                      leading: const Icon(Icons.add_a_photo_outlined, color: Color(0xFF0A84FF)),
                      title: Text('Set Photo for ${fnCtrl.text}', style: GoogleFonts.inter(color: const Color(0xFF0A84FF))),
                      onTap: () {},
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 4),
              Align(
                alignment: Alignment.centerLeft,
                child: Text('You can replace photo with another photo that only you will see.', style: GoogleFonts.inter(color: Colors.white38, fontSize: 12)),
              ),
              const SizedBox(height: 20),

              // 4. Delete Contact Card (Matching Screenshot 2)
              Container(
                width: double.infinity,
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: TextButton(
                  onPressed: () => Navigator.pop(ctx),
                  child: Text('Delete Contact', style: GoogleFonts.inter(color: const Color(0xFFFF3B30), fontSize: 15, fontWeight: FontWeight.bold)),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  void _showTelegramMoreMenu(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E293B),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (ctx) {
        return Container(
          padding: const EdgeInsets.symmetric(vertical: 12),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(width: 36, height: 4, decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(10))),
              const SizedBox(height: 12),
              _buildMenuItem(Icons.brush_outlined, 'Change Wallpaper', () {
                Navigator.pop(ctx);
                showChatWallpaperPicker(
                  context,
                  targetId: widget.userId,
                  targetName: widget.userName,
                  onWallpaperSelected: (wp) {},
                );
              }),
              _buildMenuItem(Icons.lock_outline_rounded, 'Start Secret Chat', () {
                Navigator.pop(ctx);
                VvcAlert.showInfo(
                  context,
                  title: 'Secret Chat Active',
                  message: 'ការសន្ទនាសម្ងាត់ត្រូវបានបើក (End-to-End Encrypted)',
                );
              }),
              _buildMenuItem(Icons.ios_share_rounded, 'Share Contact', () {
                Navigator.pop(ctx);
              }),
              _buildMenuItem(Icons.card_giftcard_rounded, 'Send a Gift', () {
                Navigator.pop(ctx);
              }),
              const Divider(color: Color(0xFF334155), indent: 16, endIndent: 16, height: 16),
              _buildMenuItem(Icons.timer_outlined, 'Enable Auto-Delete', () {
                Navigator.pop(ctx);
              }),
              _buildMenuItem(Icons.do_not_disturb_on_outlined, 'Disable Sharing', () {
                Navigator.pop(ctx);
              }),
              _buildMenuItem(Icons.chat_bubble_outline_rounded, 'Clear Messages', () {
                Navigator.pop(ctx);
              }),
              _buildMenuItem(Icons.back_hand_outlined, 'Block User', () {
                Navigator.pop(ctx);
              }, isDanger: true),
            ],
          ),
        );
      },
    );
  }

  Widget _buildMenuItem(IconData icon, String title, VoidCallback onTap, {bool isDanger = false}) {
    return ListTile(
      leading: Icon(icon, color: isDanger ? const Color(0xFFFF3B30) : Colors.white, size: 22),
      title: Text(
        title,
        style: GoogleFonts.inter(
          color: isDanger ? const Color(0xFFFF3B30) : Colors.white,
          fontSize: 15,
          fontWeight: isDanger ? FontWeight.bold : FontWeight.w500,
        ),
      ),
      onTap: onTap,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      body: StreamBuilder<DocumentSnapshot>(
        stream: _firestore.collection('users').doc(widget.userId).snapshots(),
        builder: (context, snapshot) {
          Map<String, dynamic> data = {};
          if (snapshot.hasData && snapshot.data!.exists) {
            data = snapshot.data!.data() as Map<String, dynamic>;
          }

          final userProvider = Provider.of<UserProvider>(context, listen: false);
          final currentUserId = (userProvider.employeeId ?? '').toString();
          String roomId = '';
          if (currentUserId.isNotEmpty && widget.userId.isNotEmpty) {
            List<String> ids = [currentUserId, widget.userId]..sort();
            roomId = ids.join('_');
          }

          final String name = data['name'] ?? widget.userName;
          final String avatar = data['avatar'] ?? widget.userPhoto;
          final rawPhone = (data['phone'] ?? data['phone_number'] ?? data['mobile'] ?? data['telephone'] ?? '').toString();
          final String phone = rawPhone.isNotEmpty && rawPhone != 'null' ? rawPhone : (data['email'] ?? 'មិនទាន់បានបញ្ចូល').toString();
          
          final rawUsername = (data['username'] ?? '').toString();
          final String username = rawUsername.isNotEmpty && rawUsername != 'null'
              ? '@$rawUsername'
              : (data['email'] != null ? data['email'].toString() : '@${name.toLowerCase().replaceAll(' ', '_')}');
          
          final rawDob = (data['birthday'] ?? data['dob'] ?? '').toString();
          final String birthday = rawDob.isNotEmpty && rawDob != 'null' ? rawDob : 'មិនទាន់បានបញ្ចូល';
          
          final rawBio = (data['bio'] ?? data['position'] ?? data['department'] ?? '').toString();
          final String bio = rawBio.isNotEmpty && rawBio != 'null' ? rawBio : 'មន្ត្រីបំពេញការងារ';

          final nameParts = name.split(' ');
          final firstName = nameParts.isNotEmpty ? nameParts[0] : name;
          final lastName = nameParts.length > 1 ? nameParts.sublist(1).join(' ') : '';

          return CustomScrollView(
            physics: const BouncingScrollPhysics(),
            slivers: [
              // Top App Bar with Edit Capsule (Matching Screenshot 1)
              SliverAppBar(
                backgroundColor: const Color(0xFF0F172A),
                elevation: 0,
                pinned: true,
                leading: Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: InkWell(
                    onTap: () => Navigator.pop(context),
                    borderRadius: BorderRadius.circular(20),
                    child: Container(
                      decoration: const BoxDecoration(color: Color(0xFF1E293B), shape: BoxShape.circle),
                      child: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 18),
                    ),
                  ),
                ),
                actions: [
                  Padding(
                    padding: const EdgeInsets.only(right: 14, top: 10, bottom: 10),
                    child: ElevatedButton(
                      onPressed: () => _showEditContactModal(firstName, lastName, phone, bio),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF1E293B),
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
                      // Avatar & Name Header (Matching Screenshot 1)
                      CircleAvatar(
                        radius: 46,
                        backgroundImage: avatar.isNotEmpty
                            ? NetworkImage(ApiService.getFullImageUrl(avatar))
                            : null,
                        backgroundColor: const Color(0xFF007AFF),
                        child: avatar.isEmpty
                            ? Text(name[0].toUpperCase(), style: GoogleFonts.inter(color: Colors.white, fontSize: 32, fontWeight: FontWeight.bold))
                            : null,
                      ),
                      const SizedBox(height: 12),
                      Text(
                        name,
                        style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold),
                      ),
                      const SizedBox(height: 4),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Text('last seen recently', style: GoogleFonts.inter(color: const Color(0xFF94A3B8), fontSize: 13)),
                          const SizedBox(width: 6),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: const Color(0xFF1E293B),
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: Text('when?', style: GoogleFonts.inter(color: const Color(0xFF0A84FF), fontSize: 11)),
                          ),
                        ],
                      ),
                      const SizedBox(height: 20),

                      // Quick Action Grid 5 Buttons (Matching Screenshot 1)
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                        children: [
                          _buildProfileActionButton(Icons.call_rounded, 'call', () {
                            launchUrl(Uri.parse('tel:$phone'));
                          }),
                          _buildProfileActionButton(Icons.videocam_rounded, 'video', () {}),
                          _buildProfileActionButton(Icons.notifications_active_rounded, 'mute', () {}),
                          _buildProfileActionButton(Icons.search_rounded, 'search', () {
                            Navigator.pop(context, 'SEARCH');
                          }),
                          _buildProfileActionButton(Icons.more_horiz_rounded, 'more', () {
                            _showTelegramMoreMenu(context);
                          }),
                        ],
                      ),
                      const SizedBox(height: 20),

                      // Profile Info Card (Matching Screenshot 1)
                      Container(
                        decoration: BoxDecoration(
                          color: const Color(0xFF1E293B),
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(color: const Color(0xFF334155), width: 0.8),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            // Mobile
                            ListTile(
                              title: Text('mobile', style: GoogleFonts.inter(color: const Color(0xFF94A3B8), fontSize: 12.5)),
                              subtitle: Text(phone, style: GoogleFonts.inter(color: const Color(0xFF0A84FF), fontSize: 15, fontWeight: FontWeight.w500)),
                            ),
                            const Divider(height: 1, color: Color(0xFF334155), indent: 16),

                            // Username
                            ListTile(
                              title: Text('username', style: GoogleFonts.inter(color: const Color(0xFF94A3B8), fontSize: 12.5)),
                              subtitle: Text(username, style: GoogleFonts.inter(color: const Color(0xFF0A84FF), fontSize: 15, fontWeight: FontWeight.w500)),
                              trailing: const Icon(Icons.qr_code_rounded, color: Color(0xFF0A84FF), size: 22),
                            ),
                            const Divider(height: 1, color: Color(0xFF334155), indent: 16),

                            // Birthday
                            ListTile(
                              title: Text('birthday', style: GoogleFonts.inter(color: const Color(0xFF94A3B8), fontSize: 12.5)),
                              subtitle: Text(birthday, style: GoogleFonts.inter(color: Colors.white, fontSize: 14.5)),
                            ),
                            const Divider(height: 1, color: Color(0xFF334155), indent: 16),

                            // Bio
                            ListTile(
                              title: Text('bio', style: GoogleFonts.inter(color: const Color(0xFF94A3B8), fontSize: 12.5)),
                              subtitle: Text(bio, style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14, height: 1.4)),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 20),

                      // Media Category Tabs (Posts, Media, Files, Music, Voice) (Matching Screenshot 1)
                      SingleChildScrollView(
                        scrollDirection: Axis.horizontal,
                        child: Row(
                          children: [
                            _buildMediaTab('Posts', 0),
                            _buildMediaTab('Media', 1),
                            _buildMediaTab('Files', 2),
                            _buildMediaTab('Music', 3),
                            _buildMediaTab('Voice', 4),
                          ],
                        ),
                      ),
                      const SizedBox(height: 14),

                      // Dynamic Profile Tab Media Content
                      _buildProfileTabContent(_selectedTab, roomId),
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

  Widget _buildProfileActionButton(IconData icon, String label, VoidCallback onTap) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Container(
        width: 62,
        height: 62,
        decoration: BoxDecoration(
          color: const Color(0xFF1E293B),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: const Color(0xFF334155), width: 0.8),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, color: const Color(0xFF0A84FF), size: 22),
            const SizedBox(height: 4),
            Text(label, style: GoogleFonts.inter(color: const Color(0xFF0A84FF), fontSize: 11)),
          ],
        ),
      ),
    );
  }

  Widget _buildMediaTab(String title, int index) {
    final isSelected = _selectedTab == index;
    return GestureDetector(
      onTap: () => setState(() => _selectedTab = index),
      child: Container(
        margin: const EdgeInsets.only(right: 8),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        decoration: BoxDecoration(
          color: isSelected ? const Color(0xFF334155) : const Color(0xFF1E293B),
          borderRadius: BorderRadius.circular(16),
        ),
        child: Text(
          title,
          style: GoogleFonts.inter(
            color: isSelected ? Colors.white : const Color(0xFF94A3B8),
            fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
            fontSize: 13,
          ),
        ),
      ),
    );
  }

  void _openProfileImageModal(BuildContext context, String imageUrl) {
    showDialog(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.9),
      builder: (ctx) => Dialog(
        backgroundColor: Colors.transparent,
        insetPadding: EdgeInsets.zero,
        child: Stack(
          alignment: Alignment.center,
          children: [
            InteractiveViewer(
              child: Image.network(
                ApiService.getFullImageUrl(imageUrl),
                fit: BoxFit.contain,
                errorBuilder: (_, __, ___) => const Icon(Icons.image_not_supported_rounded, color: Colors.white38, size: 60),
              ),
            ),
            Positioned(
              top: MediaQuery.of(context).padding.top + 10,
              right: 16,
              child: IconButton(
                icon: const Icon(Icons.close_rounded, color: Colors.white, size: 30),
                onPressed: () => Navigator.pop(ctx),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildProfileTabContent(int selectedTab, String roomId) {
    if (roomId.isEmpty) {
      return _buildEmptyMediaState();
    }

    String targetCategory = 'media';
    if (selectedTab == 0) targetCategory = 'posts';
    if (selectedTab == 1) targetCategory = 'media';
    if (selectedTab == 2) targetCategory = 'file';
    if (selectedTab == 3) targetCategory = 'music';
    if (selectedTab == 4) targetCategory = 'voice';

    return StreamBuilder<QuerySnapshot>(
      stream: FirebaseFirestore.instance
          .collection('chats')
          .doc(roomId)
          .collection('messages')
          .orderBy('timestamp', descending: true)
          .snapshots(),
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(
            child: Padding(
              padding: EdgeInsets.all(24),
              child: CircularProgressIndicator(color: Color(0xFF0A84FF)),
            ),
          );
        }

        final docs = snapshot.data!.docs.where((doc) {
          final data = doc.data() as Map<String, dynamic>;
          final type = data['type']?.toString() ?? '';
          final imageUrl = (data['imageUrl'] ?? data['mediaUrl'] ?? data['fileUrl'] ?? (type == 'image' ? data['text'] : '') ?? '').toString();
          final audioUrl = (data['audioUrl'] ?? data['voiceUrl'] ?? data['base64Audio'] ?? (type == 'voice' || type == 'audio' || type == 'music' ? data['text'] : '') ?? '').toString();

          if (targetCategory == 'media') {
            return type == 'image' || type == 'video' || imageUrl.isNotEmpty || data['stickerUrl'] != null;
          }
          if (targetCategory == 'file') {
            return type == 'file' || type == 'document' || type == 'pdf' || (data['fileName'] != null);
          }
          if (targetCategory == 'music') {
            return type == 'music' || type == 'audio' || (data['fileName']?.toString().endsWith('.mp3') == true);
          }
          if (targetCategory == 'voice') {
            return type == 'voice' || type == 'audio' || audioUrl.isNotEmpty;
          }
          if (targetCategory == 'posts') {
            return type == 'link' || data['text']?.toString().contains('http') == true;
          }
          return true;
        }).toList();

        if (docs.isEmpty) {
          return _buildEmptyMediaState();
        }

        if (targetCategory == 'media') {
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
              final String rawUrl = (data['imageUrl'] ?? data['mediaUrl'] ?? data['fileUrl'] ?? data['stickerUrl'] ?? data['text'] ?? '').toString();
              return InkWell(
                onTap: rawUrl.isNotEmpty ? () => _openProfileImageModal(context, rawUrl) : null,
                borderRadius: BorderRadius.circular(12),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(12),
                  child: Container(
                    color: const Color(0xFF1E293B),
                    child: Image.network(
                      ApiService.getFullImageUrl(rawUrl),
                      fit: BoxFit.cover,
                      errorBuilder: (_, __, ___) => const Center(
                        child: Icon(Icons.image_not_supported_rounded, color: Colors.white38),
                      ),
                    ),
                  ),
                ),
              );
            },
          );
        }

        return Container(
          decoration: BoxDecoration(
            color: const Color(0xFF1E293B),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: const Color(0xFF334155), width: 0.8),
          ),
          child: ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: docs.length,
            separatorBuilder: (_, __) => const Divider(height: 1, color: Color(0xFF334155), indent: 16),
            itemBuilder: (context, idx) {
              final data = docs[idx].data() as Map<String, dynamic>;
              final text = data['text'] ?? data['fileName'] ?? 'សារប្រព័ន្ធផ្សព្វផ្សាយ';
              final sender = data['senderName'] ?? '';

              if (targetCategory == 'voice' || targetCategory == 'music') {
                final audioUrl = (data['audioUrl'] ?? data['voiceUrl'] ?? data['base64Audio'] ?? (data['type'] == 'voice' || data['type'] == 'music' ? data['text'] : '') ?? '').toString();
                final durationSeconds = (data['audioDuration'] ?? data['duration'] ?? 3) as int;
                final Timestamp? ts = data['timestamp'] as Timestamp?;

                return _ProfileVoiceTile(
                  audioUrl: audioUrl,
                  durationSeconds: durationSeconds,
                  senderName: sender.isNotEmpty ? sender : widget.userName,
                  timestamp: ts,
                );
              }

              final fileUrl = (data['fileUrl'] ?? data['mediaUrl'] ?? data['url'] ?? data['text'] ?? '').toString();

              return ListTile(
                leading: const Icon(
                  Icons.insert_drive_file_rounded,
                  color: Color(0xFF0A84FF),
                  size: 28,
                ),
                title: Text(text, style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14)),
                subtitle: Text(sender.isNotEmpty ? 'ផ្ញើដោយ: $sender' : 'សារចែករំលែក', style: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8), fontSize: 12)),
                onTap: () async {
                  if (fileUrl.startsWith('http')) {
                    await launchUrl(Uri.parse(fileUrl), mode: LaunchMode.externalApplication);
                  }
                },
              );
            },
          ),
        );
      },
    );
  }

  Widget _buildEmptyMediaState() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(vertical: 36, horizontal: 16),
      decoration: BoxDecoration(
        color: const Color(0xFF1E293B),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: const Color(0xFF334155), width: 0.8),
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.perm_media_outlined, color: Color(0xFF94A3B8), size: 40),
          const SizedBox(height: 10),
          Text(
            'គ្មានប្រព័ន្ធផ្សព្វផ្សាយនៅឡើយទេ',
            style: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8), fontSize: 13.5),
          ),
        ],
      ),
    );
  }
}

class _ProfileVoiceTile extends StatefulWidget {
  final String audioUrl;
  final int durationSeconds;
  final String senderName;
  final Timestamp? timestamp;

  const _ProfileVoiceTile({
    required this.audioUrl,
    required this.durationSeconds,
    required this.senderName,
    this.timestamp,
  });

  @override
  State<_ProfileVoiceTile> createState() => _ProfileVoiceTileState();
}

class _ProfileVoiceTileState extends State<_ProfileVoiceTile> {
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
    try {
      if (_isPlaying) {
        await _audioPlayer.pause();
        if (mounted) setState(() => _isPlaying = false);
        return;
      }

      final url = widget.audioUrl.trim();
      if (url.isEmpty) return;

      if (url.startsWith('data:audio')) {
        final base64Str = url.split(',').last;
        final bytes = base64Decode(base64Str);
        final dir = await getTemporaryDirectory();
        final tempFile = File('${dir.path}/temp_play_profile_${DateTime.now().millisecondsSinceEpoch}.m4a');
        await tempFile.writeAsBytes(bytes);
        await _audioPlayer.play(DeviceFileSource(tempFile.path));
      } else if (url.startsWith('http://') || url.startsWith('https://')) {
        await _audioPlayer.play(UrlSource(url));
      } else {
        await _audioPlayer.play(UrlSource(ApiService.getFullImageUrl(url)));
      }

      if (mounted) setState(() => _isPlaying = true);
    } catch (e) {
      debugPrint('Error playing voice in profile screen: $e');
      if (mounted) setState(() => _isPlaying = false);
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
          InkWell(
            onTap: _togglePlay,
            borderRadius: BorderRadius.circular(22),
            child: Container(
              width: 44,
              height: 44,
              decoration: const BoxDecoration(
                color: Color(0xFF0A84FF),
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
                            color: const Color(0xFF0A84FF),
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
