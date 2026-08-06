import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:image_picker/image_picker.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:path_provider/path_provider.dart';
import 'package:image/image.dart' as img;
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../services/r2_storage_service.dart';

class _CommunityDark {
  static const Color bg = Color(0xFF0F172A);
  static const Color card = Color(0xFF1E293B);
  static const Color accent = Color(0xFF0A84FF);
  static const Color success = Color(0xFF10B981);
  static const Color danger = Color(0xFFFF3B30);
}

class CommunityChannelScreen extends StatefulWidget {
  const CommunityChannelScreen({super.key});

  @override
  State<CommunityChannelScreen> createState() => _CommunityChannelScreenState();
}

class _CommunityChannelScreenState extends State<CommunityChannelScreen> {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final ImagePicker _picker = ImagePicker();
  final R2StorageService _r2Service = R2StorageService();

  // Auto Compress Image to Minimal Bytes (~150KB-200KB) while Retaining Crystal Clear HD Clarity
  Future<File> _compressImage(File file, {bool isCamera = false}) async {
    try {
      final bytes = await file.readAsBytes();
      final decoded = img.decodeImage(bytes);
      if (decoded == null) return file;

      img.Image oriented = img.bakeOrientation(decoded);
      if (isCamera) {
        oriented = img.flipHorizontal(oriented);
      }

      // Resize max dimension to 1200px
      if (oriented.width > 1200 || oriented.height > 1200) {
        oriented = img.copyResize(
          oriented,
          width: oriented.width > oriented.height ? 1200 : null,
          height: oriented.height >= oriented.width ? 1200 : null,
          interpolation: img.Interpolation.average,
        );
      }

      final compressedBytes = Uint8List.fromList(img.encodeJpg(oriented, quality: 72));
      final tempDir = await getTemporaryDirectory();
      final compressedFile = File('${tempDir.path}/comp_${DateTime.now().millisecondsSinceEpoch}.jpg');
      await compressedFile.writeAsBytes(compressedBytes);
      return compressedFile;
    } catch (e) {
      debugPrint('Auto compress image error: $e');
      return file;
    }
  }

  void _showCreatePostModal(UserProvider user) {
    final textController = TextEditingController();
    File? selectedImage;
    bool isPosting = false;

    showModalBottomSheet(
      context: context,
      backgroundColor: _CommunityDark.card,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (ctx) {
        return StatefulBuilder(
          builder: (context, setModalState) {
            return Padding(
              padding: EdgeInsets.fromLTRB(
                20,
                16,
                20,
                MediaQuery.of(context).viewInsets.bottom + 20,
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        'បង្កើតព័ត៌មានក្រុមហ៊ុន (Create Post)',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const Spacer(),
                      IconButton(
                        icon: const Icon(Icons.close_rounded, color: Colors.white70),
                        onPressed: () => Navigator.pop(ctx),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  TextField(
                    controller: textController,
                    maxLines: 4,
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5),
                    decoration: InputDecoration(
                      hintText: 'សរសេរព័ត៌មានក្រុមហ៊ុន ការប្រកាស ឬការផ្សព្វផ្សាយ...',
                      hintStyle: GoogleFonts.kantumruyPro(color: Colors.white38, fontSize: 14.0),
                      filled: true,
                      fillColor: _CommunityDark.bg,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(16),
                        borderSide: BorderSide.none,
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  if (selectedImage != null)
                    Stack(
                      children: [
                        ClipRRect(
                          borderRadius: BorderRadius.circular(16),
                          child: Image.file(selectedImage!, height: 160, width: double.infinity, fit: BoxFit.cover),
                        ),
                        Positioned(
                          right: 8,
                          top: 8,
                          child: InkWell(
                            onTap: () => setModalState(() => selectedImage = null),
                            child: Container(
                              padding: const EdgeInsets.all(5),
                              decoration: const BoxDecoration(color: Color(0x99000000), shape: BoxShape.circle),
                              child: const Icon(Icons.close_rounded, color: Colors.white, size: 18),
                            ),
                          ),
                        ),
                      ],
                    ),
                  const SizedBox(height: 14),
                  Row(
                    children: [
                      InkWell(
                        onTap: () async {
                          final picked = await _picker.pickImage(source: ImageSource.gallery, imageQuality: 85);
                          if (picked != null) {
                            final comp = await _compressImage(File(picked.path), isCamera: false);
                            setModalState(() => selectedImage = comp);
                          }
                        },
                        borderRadius: BorderRadius.circular(12),
                        child: Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: _CommunityDark.bg,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: const Icon(Icons.photo_library_rounded, color: _CommunityDark.accent, size: 24),
                        ),
                      ),
                      const SizedBox(width: 10),
                      InkWell(
                        onTap: () async {
                          final picked = await _picker.pickImage(source: ImageSource.camera, imageQuality: 85);
                          if (picked != null) {
                            final comp = await _compressImage(File(picked.path), isCamera: true);
                            setModalState(() => selectedImage = comp);
                          }
                        },
                        borderRadius: BorderRadius.circular(12),
                        child: Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: _CommunityDark.bg,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: const Icon(Icons.camera_alt_rounded, color: _CommunityDark.success, size: 24),
                        ),
                      ),
                      const Spacer(),
                      ElevatedButton(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: _CommunityDark.accent,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
                          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                        ),
                        onPressed: isPosting
                            ? null
                            : () async {
                                final text = textController.text.trim();
                                if (text.isEmpty && selectedImage == null) return;

                                setModalState(() => isPosting = true);

                                try {
                                  String mediaUrl = '';
                                  if (selectedImage != null) {
                                    final uploaded = await _r2Service.uploadMedia(
                                      file: selectedImage!,
                                      folder: 'community',
                                    );
                                    if (uploaded != null && uploaded.isNotEmpty) {
                                      mediaUrl = uploaded;
                                    } else {
                                      // Robust Fallback to Base64 image if R2 fails
                                      final imgBytes = await selectedImage!.readAsBytes();
                                      mediaUrl = 'data:image/jpeg;base64,${base64Encode(imgBytes)}';
                                    }
                                  }

                                  await _firestore.collection('community_posts').add({
                                    'authorId': user.employeeId ?? '',
                                    'authorName': user.name ?? 'VVC Admin',
                                    'authorAvatar': user.avatar ?? '',
                                    'roleTag': 'Official Announcement',
                                    'content': text,
                                    'mediaUrl': mediaUrl,
                                    'likes': [],
                                    'createdAt': FieldValue.serverTimestamp(),
                                  });

                                  if (context.mounted) {
                                    Navigator.pop(ctx);
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      SnackBar(
                                        content: Text('បានផ្សព្វផ្សាយព័ត៌មានក្រុមហ៊ុនរួចរាល់!', style: GoogleFonts.kantumruyPro()),
                                        backgroundColor: _CommunityDark.success,
                                      ),
                                    );
                                  }
                                } catch (e) {
                                  debugPrint('Create post error: $e');
                                  if (context.mounted) {
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      SnackBar(
                                        content: Text('មានបញ្ហាក្នុងការផ្សព្វផ្សាយ៖ $e', style: GoogleFonts.kantumruyPro()),
                                        backgroundColor: _CommunityDark.danger,
                                      ),
                                    );
                                  }
                                } finally {
                                  if (ctx.mounted) {
                                    setModalState(() => isPosting = false);
                                  }
                                }
                              },
                        child: isPosting
                            ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2))
                            : Text('ផ្សព្វផ្សាយ (Publish)', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
                      ),
                    ],
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final userProvider = Provider.of<UserProvider>(context);

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1E293B),
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(6),
              decoration: const BoxDecoration(
                color: Color(0xFF007AFF),
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.hub_rounded, color: Colors.white, size: 18),
            ),
            const SizedBox(width: 10),
            Text(
              'សហគមន៍ VVC (Community)',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 17,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _showCreatePostModal(userProvider),
        backgroundColor: const Color(0xFF007AFF),
        icon: const Icon(Icons.add_rounded, color: Colors.white),
        label: Text('បង្កើត Post', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
      ),
      body: StreamBuilder<QuerySnapshot>(
        stream: _firestore
            .collection('community_posts')
            .orderBy('createdAt', descending: true)
            .snapshots(),
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator(color: Color(0xFF007AFF)));
          }

          if (!snapshot.hasData || snapshot.data!.docs.isEmpty) {
            return Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(Icons.campaign_rounded, size: 64, color: Colors.white38),
                  const SizedBox(height: 12),
                  Text(
                    'មិនទាន់មានការប្រកាសព័ត៌មាននៅឡើយទេ',
                    style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 15),
                  ),
                ],
              ),
            );
          }

          final posts = snapshot.data!.docs;

          return ListView.builder(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
            itemCount: posts.length,
            itemBuilder: (context, index) {
              final doc = posts[index];
              final data = doc.data() as Map<String, dynamic>;

              final String authorName = data['authorName'] ?? 'VVC Official';
              final String authorAvatar = data['authorAvatar'] ?? '';
              final String roleTag = data['roleTag'] ?? 'Announcement';
              final String content = data['content'] ?? '';
              final String mediaUrl = data['mediaUrl'] ?? '';
              final List<dynamic> likes = data['likes'] ?? [];
              final Timestamp? ts = data['createdAt'] as Timestamp?;
              final String timeStr = ts != null ? DateFormat('dd/MM HH:mm').format(ts.toDate()) : 'ទើបតែ';

              final bool isLiked = likes.contains(userProvider.employeeId);

              return Container(
                margin: const EdgeInsets.only(bottom: 16),
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: const Color(0xFF334155), width: 0.8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Author Row
                    Row(
                      children: [
                        CircleAvatar(
                          radius: 20,
                          backgroundImage: authorAvatar.isNotEmpty
                              ? NetworkImage(ApiService.getFullImageUrl(authorAvatar))
                              : null,
                          backgroundColor: const Color(0xFF007AFF),
                          child: authorAvatar.isEmpty
                              ? Text(authorName[0].toUpperCase(), style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold))
                              : null,
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  Text(
                                    authorName,
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.white,
                                      fontSize: 15,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  const SizedBox(width: 6),
                                  const Icon(Icons.verified_rounded, color: Color(0xFF007AFF), size: 16),
                                ],
                              ),
                              Text(
                                '$roleTag • $timeStr',
                                style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 11.5),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),

                    // Post Content
                    if (content.isNotEmpty)
                      Text(
                        content,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 14.5,
                          height: 1.5,
                        ),
                      ),

                    // Media Image Attachment
                    if (mediaUrl.isNotEmpty) ...[
                      const SizedBox(height: 12),
                      ClipRRect(
                        borderRadius: BorderRadius.circular(14),
                        child: Image.network(
                          ApiService.getFullImageUrl(mediaUrl),
                          fit: BoxFit.cover,
                          width: double.infinity,
                        ),
                      ),
                    ],

                    const SizedBox(height: 14),

                    // Actions Bar (Like & Share)
                    Row(
                      children: [
                        InkWell(
                          onTap: () async {
                            final List updated = List.from(likes);
                            final myId = userProvider.employeeId ?? '';
                            if (isLiked) {
                              updated.remove(myId);
                            } else {
                              updated.add(myId);
                            }
                            await doc.reference.update({'likes': updated});
                          },
                          child: Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            child: Row(
                              children: [
                                Icon(
                                  isLiked ? Icons.thumb_up_alt_rounded : Icons.thumb_up_off_alt_rounded,
                                  color: isLiked ? const Color(0xFF007AFF) : Colors.white60,
                                  size: 20,
                                ),
                                const SizedBox(width: 6),
                                Text(
                                  '${likes.length}',
                                  style: GoogleFonts.inter(color: Colors.white70, fontSize: 13),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ],
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
}
