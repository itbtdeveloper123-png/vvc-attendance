import 'dart:io';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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

  late final Stream<QuerySnapshot> _postsStream;
  String _selectedTab = 'All';

  @override
  void initState() {
    super.initState();
    _postsStream = _firestore
        .collection('community_posts')
        .orderBy('createdAt', descending: true)
        .snapshots();
  }

  // Facebook Reactions Configuration
  static const Map<String, Map<String, dynamic>> _reactions = {
    'like': {'emoji': '👍', 'label': 'Like', 'color': Color(0xFF0A84FF)},
    'love': {'emoji': '❤️', 'label': 'Love', 'color': Color(0xFFFF3B30)},
    'haha': {'emoji': '😆', 'label': 'Haha', 'color': Color(0xFFFFCC00)},
    'wow': {'emoji': '😮', 'label': 'Wow', 'color': Color(0xFFFFCC00)},
    'sad': {'emoji': '😢', 'label': 'Sad', 'color': Color(0xFFFFCC00)},
    'angry': {'emoji': '😡', 'label': 'Angry', 'color': Color(0xFFFF9500)},
  };

  // Auto Compress Image to Minimal Bytes (~150KB-200KB) while Retaining HD Quality
  Future<File> _compressImage(File file, {bool isCamera = false}) async {
    try {
      final bytes = await file.readAsBytes();
      final decoded = img.decodeImage(bytes);
      if (decoded == null) return file;

      img.Image oriented = img.bakeOrientation(decoded);
      if (isCamera) {
        oriented = img.flipHorizontal(oriented);
      }

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

  // ==========================================
  // CREATE POST MODAL
  // ==========================================
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
                        'បង្កើតព័ត៌មាន (Create Post)',
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
                      hintText: 'សរសេរព័ត៌មាន ការប្រកាស ឬការផ្សព្វផ្សាយ...',
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
                          child: Image.file(selectedImage!, height: 180, width: double.infinity, fit: BoxFit.cover),
                        ),
                        Positioned(
                          right: 8,
                          top: 8,
                          child: InkWell(
                            onTap: () => setModalState(() => selectedImage = null),
                            child: Container(
                              padding: const EdgeInsets.all(6),
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
                          padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 12),
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
                                      final imgBytes = await selectedImage!.readAsBytes();
                                      mediaUrl = 'data:image/jpeg;base64,${base64Encode(imgBytes)}';
                                    }
                                  }

                                  await _firestore.collection('community_posts').add({
                                    'authorId': user.employeeId ?? '',
                                    'authorName': user.name ?? 'VVC Member',
                                    'authorAvatar': user.avatar ?? '',
                                    'roleTag': 'Official Announcement',
                                    'content': text,
                                    'mediaUrl': mediaUrl,
                                    'reactionsMap': {},
                                    'likes': [],
                                    'createdAt': FieldValue.serverTimestamp(),
                                  });

                                  if (context.mounted) {
                                    Navigator.pop(ctx);
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      SnackBar(
                                        content: Text('បានផ្សព្វផ្សាយព័ត៌មានរួចរាល់!', style: GoogleFonts.kantumruyPro()),
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

  // ==========================================
  // EDIT POST MODAL
  // ==========================================
  void _showEditPostModal(DocumentSnapshot postDoc) {
    final data = postDoc.data() as Map<String, dynamic>;
    final textController = TextEditingController(text: data['content'] ?? '');
    String currentMediaUrl = data['mediaUrl'] ?? '';
    File? newImage;
    bool isSaving = false;

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
                        'កែប្រែព័ត៌មាន (Edit Post)',
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
                      hintText: 'សរសេរព័ត៌មាន...',
                      filled: true,
                      fillColor: _CommunityDark.bg,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(16),
                        borderSide: BorderSide.none,
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  if (newImage != null) ...[
                    Stack(
                      children: [
                        ClipRRect(
                          borderRadius: BorderRadius.circular(16),
                          child: Image.file(newImage!, height: 180, width: double.infinity, fit: BoxFit.cover),
                        ),
                        Positioned(
                          right: 8,
                          top: 8,
                          child: InkWell(
                            onTap: () => setModalState(() => newImage = null),
                            child: Container(
                              padding: const EdgeInsets.all(6),
                              decoration: const BoxDecoration(color: Color(0x99000000), shape: BoxShape.circle),
                              child: const Icon(Icons.close_rounded, color: Colors.white, size: 18),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ] else if (currentMediaUrl.isNotEmpty) ...[
                    Stack(
                      children: [
                        ClipRRect(
                          borderRadius: BorderRadius.circular(16),
                          child: Image.network(ApiService.getFullImageUrl(currentMediaUrl), height: 180, width: double.infinity, fit: BoxFit.cover),
                        ),
                        Positioned(
                          right: 8,
                          top: 8,
                          child: InkWell(
                            onTap: () => setModalState(() => currentMediaUrl = ''),
                            child: Container(
                              padding: const EdgeInsets.all(6),
                              decoration: const BoxDecoration(color: Color(0x99000000), shape: BoxShape.circle),
                              child: const Icon(Icons.close_rounded, color: Colors.white, size: 18),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                  const SizedBox(height: 14),
                  Row(
                    children: [
                      InkWell(
                        onTap: () async {
                          final picked = await _picker.pickImage(source: ImageSource.gallery, imageQuality: 85);
                          if (picked != null) {
                            final comp = await _compressImage(File(picked.path), isCamera: false);
                            setModalState(() {
                              newImage = comp;
                              currentMediaUrl = '';
                            });
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
                            setModalState(() {
                              newImage = comp;
                              currentMediaUrl = '';
                            });
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
                          padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 12),
                        ),
                        onPressed: isSaving
                            ? null
                            : () async {
                                final text = textController.text.trim();
                                setModalState(() => isSaving = true);

                                try {
                                  String mediaUrl = currentMediaUrl;
                                  if (newImage != null) {
                                    final uploaded = await _r2Service.uploadMedia(
                                      file: newImage!,
                                      folder: 'community',
                                    );
                                    if (uploaded != null && uploaded.isNotEmpty) {
                                      mediaUrl = uploaded;
                                    } else {
                                      final imgBytes = await newImage!.readAsBytes();
                                      mediaUrl = 'data:image/jpeg;base64,${base64Encode(imgBytes)}';
                                    }
                                  }

                                  await postDoc.reference.update({
                                    'content': text,
                                    'mediaUrl': mediaUrl,
                                    'updatedAt': FieldValue.serverTimestamp(),
                                  });

                                  if (context.mounted) {
                                    Navigator.pop(ctx);
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      SnackBar(
                                        content: Text('បានរក្សាទុកការកែប្រែ!', style: GoogleFonts.kantumruyPro()),
                                        backgroundColor: _CommunityDark.success,
                                      ),
                                    );
                                  }
                                } catch (e) {
                                  debugPrint('Update post error: $e');
                                } finally {
                                  if (ctx.mounted) {
                                    setModalState(() => isSaving = false);
                                  }
                                }
                              },
                        child: isSaving
                            ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2))
                            : Text('រក្សាទុក (Save)', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
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

  // ==========================================
  // DELETE POST CONFIRMATION
  // ==========================================
  void _confirmDeletePost(DocumentSnapshot postDoc) {
    showDialog(
      context: context,
      builder: (dialogCtx) {
        return AlertDialog(
          backgroundColor: _CommunityDark.card,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
          title: Text(
            'លុប Post',
            style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold),
          ),
          content: Text(
            'តើអ្នកពិតជាចង់លុប Post នេះចេញពីសហគមន៍មែនទេ?',
            style: GoogleFonts.kantumruyPro(color: Colors.white70),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogCtx),
              child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: Colors.white54)),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(backgroundColor: _CommunityDark.danger),
              onPressed: () async {
                Navigator.pop(dialogCtx);
                await postDoc.reference.delete();
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('បានលុប Post រួចរាល់!', style: GoogleFonts.kantumruyPro()),
                      backgroundColor: _CommunityDark.danger,
                    ),
                  );
                }
              },
              child: Text('លុបចេញ', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
            ),
          ],
        );
      },
    );
  }

  // ==========================================
  // FACEBOOK REACTION PICKER POPUP
  // ==========================================
  void _showReactionPicker(BuildContext context, DocumentReference docRef, String currentUserId, Map<String, dynamic> currentReactionsMap) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (ctx) {
        return Container(
          margin: const EdgeInsets.fromLTRB(16, 0, 16, 20),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          decoration: BoxDecoration(
            color: const Color(0xFF1E293B),
            borderRadius: BorderRadius.circular(30),
            border: Border.all(color: Colors.white24, width: 0.8),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.4),
                blurRadius: 16,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceAround,
            children: _reactions.entries.map((entry) {
              final key = entry.key;
              final emoji = entry.value['emoji'] as String;

              return InkWell(
                onTap: () async {
                  Navigator.pop(ctx);
                  final Map<String, dynamic> updatedMap = Map.from(currentReactionsMap);
                  if (updatedMap[currentUserId] == key) {
                    updatedMap.remove(currentUserId);
                  } else {
                    updatedMap[currentUserId] = key;
                  }
                  await docRef.update({'reactionsMap': updatedMap});
                },
                child: Padding(
                  padding: const EdgeInsets.all(4.0),
                  child: Text(
                    emoji,
                    style: const TextStyle(fontSize: 32),
                  ),
                ),
              );
            }).toList(),
          ),
        );
      },
    );
  }

  // ==========================================
  // COMMENTS BOTTOM SHEET (FACEBOOK STYLE)
  // ==========================================
  void _showCommentsSheet(DocumentSnapshot postDoc, UserProvider user) {
    final commentController = TextEditingController();
    bool isSending = false;

    showModalBottomSheet(
      context: context,
      backgroundColor: _CommunityDark.card,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (sheetCtx) {
        return StatefulBuilder(
          builder: (context, setSheetState) {
            return Container(
              height: MediaQuery.of(context).size.height * 0.75,
              padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
              child: Column(
                children: [
                  // Top Header Bar
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
                    child: Row(
                      children: [
                        Text(
                          'មតិយោបល់ (Comments)',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        const Spacer(),
                        IconButton(
                          icon: const Icon(Icons.close_rounded, color: Colors.white70),
                          onPressed: () => Navigator.pop(sheetCtx),
                        ),
                      ],
                    ),
                  ),
                  const Divider(color: Colors.white12, height: 1),

                  // Real-time Comments List
                  Expanded(
                    child: StreamBuilder<QuerySnapshot>(
                      stream: postDoc.reference
                          .collection('comments')
                          .snapshots(),
                      builder: (context, snapshot) {
                        if (snapshot.hasError) {
                          return Center(
                            child: Padding(
                              padding: const EdgeInsets.all(20.0),
                              child: Text(
                                'មិនទាន់មានមតិយោបល់នៅឡើយទេ\nជាអ្នកដំបូងដែលបញ្ចេញមតិ!',
                                textAlign: TextAlign.center,
                                style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 13.5),
                              ),
                            ),
                          );
                        }

                        if (!snapshot.hasData) {
                          return const Center(child: CircularProgressIndicator(color: _CommunityDark.accent));
                        }

                        final comments = List<DocumentSnapshot>.from(snapshot.data!.docs);
                        // Sort by createdAt ascending safely on client side
                        comments.sort((a, b) {
                          final aData = a.data() as Map<String, dynamic>?;
                          final bData = b.data() as Map<String, dynamic>?;
                          final aTs = aData?['createdAt'] as Timestamp?;
                          final bTs = bData?['createdAt'] as Timestamp?;
                          if (aTs == null) return 1;
                          if (bTs == null) return -1;
                          return aTs.compareTo(bTs);
                        });

                        if (comments.isEmpty) {
                          return Center(
                            child: Text(
                              'មិនទាន់មានមតិយោបល់នៅឡើយទេ\nជាអ្នកដំបូងដែលបញ្ចេញមតិ!',
                              textAlign: TextAlign.center,
                              style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 13.5),
                            ),
                          );
                        }

                        return ListView.builder(
                          padding: const EdgeInsets.all(14),
                          itemCount: comments.length,
                          itemBuilder: (context, idx) {
                            final cDoc = comments[idx];
                            final cData = cDoc.data() as Map<String, dynamic>;
                            final String cAuthorId = cData['authorId'] ?? '';
                            final String cAuthorName = cData['authorName'] ?? 'Member';
                            final String cAuthorAvatar = cData['authorAvatar'] ?? '';
                            final String cText = cData['text'] ?? '';
                            final Timestamp? cTs = cData['createdAt'] as Timestamp?;
                            final String cTime = cTs != null ? DateFormat('HH:mm dd/MM').format(cTs.toDate()) : 'ទើបតែ';
                            final bool isMyComment = cAuthorId == user.employeeId;

                            return Container(
                              margin: const EdgeInsets.only(bottom: 12),
                              child: Row(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  CircleAvatar(
                                    radius: 16,
                                    backgroundImage: cAuthorAvatar.isNotEmpty
                                        ? NetworkImage(ApiService.getFullImageUrl(cAuthorAvatar))
                                        : null,
                                    backgroundColor: _CommunityDark.accent,
                                    child: cAuthorAvatar.isEmpty
                                        ? Text(cAuthorName[0].toUpperCase(), style: GoogleFonts.inter(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold))
                                        : null,
                                  ),
                                  const SizedBox(width: 10),
                                  Expanded(
                                    child: Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                                      decoration: BoxDecoration(
                                        color: _CommunityDark.bg,
                                        borderRadius: BorderRadius.circular(16),
                                      ),
                                      child: Column(
                                        crossAxisAlignment: CrossAxisAlignment.start,
                                        children: [
                                          Row(
                                            children: [
                                              Text(
                                                cAuthorName,
                                                style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold),
                                              ),
                                              const Spacer(),
                                              Text(
                                                cTime,
                                                style: GoogleFonts.inter(color: Colors.white38, fontSize: 10),
                                              ),
                                              if (isMyComment) ...[
                                                const SizedBox(width: 6),
                                                InkWell(
                                                  onTap: () async {
                                                    try {
                                                      await cDoc.reference.delete();
                                                      await postDoc.reference.update({'commentsCount': FieldValue.increment(-1)});
                                                    } catch (_) {}
                                                  },
                                                  child: const Icon(Icons.delete_outline_rounded, color: Colors.redAccent, size: 16),
                                                ),
                                              ],
                                            ],
                                          ),
                                          const SizedBox(height: 4),
                                          Text(
                                            cText,
                                            style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13.5),
                                          ),
                                        ],
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                            );
                          },
                        );
                      },
                    ),
                  ),

                  // Bottom Input Field
                  Container(
                    padding: const EdgeInsets.fromLTRB(14, 8, 14, 12),
                    decoration: const BoxDecoration(
                      color: Color(0xFF1E293B),
                      border: Border(top: BorderSide(color: Colors.white12, width: 0.5)),
                    ),
                    child: Row(
                      children: [
                        Expanded(
                          child: TextField(
                            controller: commentController,
                            style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14),
                            decoration: InputDecoration(
                              hintText: 'សរសេរមតិយោបល់...',
                              hintStyle: GoogleFonts.kantumruyPro(color: Colors.white38, fontSize: 13.5),
                              filled: true,
                              fillColor: _CommunityDark.bg,
                              isDense: true,
                              contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(20),
                                borderSide: BorderSide.none,
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        InkWell(
                          onTap: isSending
                              ? null
                              : () async {
                                  final text = commentController.text.trim();
                                  if (text.isEmpty) return;
                                  setSheetState(() => isSending = true);
                                  try {
                                    commentController.clear();
                                    await postDoc.reference.collection('comments').add({
                                      'authorId': user.employeeId ?? '',
                                      'authorName': user.name ?? 'Member',
                                      'authorAvatar': user.avatar ?? '',
                                      'text': text,
                                      'createdAt': FieldValue.serverTimestamp(),
                                    });
                                    await postDoc.reference.update({'commentsCount': FieldValue.increment(1)});
                                  } catch (e) {
                                    debugPrint('Add comment error: $e');
                                  } finally {
                                    if (sheetCtx.mounted) {
                                      setSheetState(() => isSending = false);
                                    }
                                  }
                                },
                          child: Container(
                            padding: const EdgeInsets.all(10),
                            decoration: const BoxDecoration(
                              color: _CommunityDark.accent,
                              shape: BoxShape.circle,
                            ),
                            child: isSending
                                ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2))
                                : const Icon(Icons.send_rounded, color: Colors.white, size: 18),
                          ),
                        ),
                      ],
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

  @override
  Widget build(BuildContext context) {
    final userProvider = Provider.of<UserProvider>(context);

    return Scaffold(
      backgroundColor: _CommunityDark.bg,
      appBar: PreferredSize(
        preferredSize: const Size.fromHeight(110),
        child: Container(
          decoration: BoxDecoration(
            color: _CommunityDark.bg,
            border: const Border(bottom: BorderSide(color: Color(0xFF1E293B), width: 1)),
          ),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              // Top Nav Row
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8.0, vertical: 8.0),
                child: Row(
                  children: [
                    IconButton(
                      icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 22),
                      onPressed: () => Navigator.pop(context),
                    ),
                    Text(
                      'VVC Community',
                      style: GoogleFonts.inter(
                        color: Colors.white,
                        fontSize: 20,
                        fontWeight: FontWeight.w700,
                        letterSpacing: -0.5,
                      ),
                    ),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.search_rounded, color: Colors.white, size: 26),
                      onPressed: () {},
                    ),
                    IconButton(
                      icon: const Icon(Icons.notifications_none_rounded, color: Colors.white, size: 26),
                      onPressed: () {},
                    ),
                  ],
                ),
              ),
              // Segment Filter Tabs
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 4.0),
                child: Row(
                  children: ['All', 'Announcements', 'Trending'].map((tab) {
                    final isSelected = _selectedTab == tab;
                    return GestureDetector(
                      onTap: () => setState(() => _selectedTab = tab),
                      child: Container(
                        margin: const EdgeInsets.only(right: 12),
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                        decoration: BoxDecoration(
                          color: isSelected ? _CommunityDark.card : Colors.transparent,
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(
                            color: isSelected ? _CommunityDark.accent.withValues(alpha: 0.5) : const Color(0xFF334155),
                            width: 1,
                          ),
                        ),
                        child: Text(
                          tab,
                          style: GoogleFonts.inter(
                            color: isSelected ? _CommunityDark.accent : Colors.white70,
                            fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
                            fontSize: 14,
                          ),
                        ),
                      ),
                    );
                  }).toList(),
                ),
              ),
              const SizedBox(height: 8),
            ],
          ),
        ),
      ),
      floatingActionButton: Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(30),
          boxShadow: [
            BoxShadow(
              color: _CommunityDark.accent.withValues(alpha: 0.4),
              blurRadius: 20,
              offset: const Offset(0, 8),
            ),
          ],
        ),
        child: FloatingActionButton.extended(
          onPressed: () => _showCreatePostModal(userProvider),
          backgroundColor: _CommunityDark.accent,
          elevation: 0,
          icon: const Icon(Icons.add_rounded, color: Colors.white, size: 24),
          label: Text('Create Post', style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 15)),
        ),
      ),
      body: StreamBuilder<QuerySnapshot>(
        stream: _postsStream,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator(color: _CommunityDark.accent));
          }

          final posts = snapshot.hasData ? snapshot.data!.docs : [];

          return CustomScrollView(
            slivers: [
              // Create Post Input Card
              SliverToBoxAdapter(
                child: GestureDetector(
                  onTap: () => _showCreatePostModal(userProvider),
                  child: Container(
                    margin: const EdgeInsets.fromLTRB(16, 16, 16, 8),
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: _CommunityDark.card,
                      borderRadius: BorderRadius.circular(24),
                      border: Border.all(color: const Color(0xFF334155), width: 0.8),
                    ),
                    child: Row(
                      children: [
                        CircleAvatar(
                          radius: 20,
                          backgroundColor: _CommunityDark.accent.withValues(alpha: 0.2),
                          backgroundImage: (userProvider.avatar?.isNotEmpty ?? false)
                              ? NetworkImage(ApiService.getFullImageUrl(userProvider.avatar!))
                              : null,
                          child: (userProvider.avatar?.isEmpty ?? true)
                              ? Text(
                                  (userProvider.name?.isNotEmpty ?? false) ? userProvider.name![0].toUpperCase() : 'U',
                                  style: GoogleFonts.inter(color: _CommunityDark.accent, fontWeight: FontWeight.bold),
                                )
                              : null,
                        ),
                        const SizedBox(width: 14),
                        Expanded(
                          child: Text(
                            "What's on your mind?",
                            style: GoogleFonts.inter(color: Colors.white54, fontSize: 15),
                          ),
                        ),
                        const Icon(Icons.image_outlined, color: _CommunityDark.success, size: 24),
                      ],
                    ),
                  ),
                ),
              ),

              // Empty State
              if (posts.isEmpty)
                SliverFillRemaining(
                  hasScrollBody: false,
                  child: Center(
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
                  ),
                )
              else
                // Feed Posts
                SliverList(
                  delegate: SliverChildBuilderDelegate(
                    (context, index) {
                      final doc = posts[index];
                      final data = doc.data() as Map<String, dynamic>;

                      final String authorId = data['authorId'] ?? '';
                      final String authorName = data['authorName'] ?? 'VVC Official';
                      final String authorAvatar = data['authorAvatar'] ?? '';
                      final String roleTag = data['roleTag'] ?? 'Official Announcement';
                      final String content = data['content'] ?? '';
                      final String mediaUrl = data['mediaUrl'] ?? '';
                      final Map<String, dynamic> reactionsMap = data['reactionsMap'] as Map<String, dynamic>? ?? {};
                      final List<dynamic> legacyLikes = data['likes'] ?? [];
                      final int commentsCount = (data['commentsCount'] as num?)?.toInt() ?? 0;
                      final Timestamp? ts = data['createdAt'] as Timestamp?;
                      final String timeStr = ts != null ? DateFormat('MMM dd, HH:mm').format(ts.toDate()) : 'Just now';

                      final String myId = userProvider.employeeId ?? '';
                      final bool isMyPost = authorId == myId || myId == 'super_admin' || myId == 'admin';

                      // Reaction Logic
                      String userReactionKey = reactionsMap[myId] ?? '';
                      if (userReactionKey.isEmpty && legacyLikes.contains(myId)) {
                        userReactionKey = 'like';
                      }

                      final Map<String, int> reactionCounts = {};
                      reactionsMap.forEach((uId, rKey) {
                        if (rKey is String && rKey.isNotEmpty) {
                          reactionCounts[rKey] = (reactionCounts[rKey] ?? 0) + 1;
                        }
                      });
                      if (reactionCounts.isEmpty && legacyLikes.isNotEmpty) {
                        reactionCounts['like'] = legacyLikes.length;
                      }

                      int totalReactions = 0;
                      reactionCounts.forEach((_, cnt) => totalReactions += cnt);

                      return Container(
                        margin: const EdgeInsets.fromLTRB(16, 8, 16, 12),
                        padding: const EdgeInsets.all(20),
                        decoration: BoxDecoration(
                          color: _CommunityDark.card,
                          borderRadius: BorderRadius.circular(24),
                          border: Border.all(color: const Color(0xFF334155), width: 0.8),
                          boxShadow: [
                            BoxShadow(
                              color: Colors.black.withValues(alpha: 0.2),
                              blurRadius: 10,
                              offset: const Offset(0, 4),
                            ),
                          ],
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            // Author Header
                            Row(
                              children: [
                                CircleAvatar(
                                  radius: 22,
                                  backgroundImage: authorAvatar.isNotEmpty
                                      ? NetworkImage(ApiService.getFullImageUrl(authorAvatar))
                                      : null,
                                  backgroundColor: _CommunityDark.accent.withValues(alpha: 0.2),
                                  child: authorAvatar.isEmpty
                                      ? Text(authorName[0].toUpperCase(), style: GoogleFonts.inter(color: _CommunityDark.accent, fontWeight: FontWeight.bold, fontSize: 18))
                                      : null,
                                ),
                                const SizedBox(width: 12),
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
                                              fontSize: 16,
                                              fontWeight: FontWeight.bold,
                                            ),
                                          ),
                                          const SizedBox(width: 4),
                                          const Icon(Icons.verified_rounded, color: _CommunityDark.accent, size: 16),
                                        ],
                                      ),
                                      const SizedBox(height: 2),
                                      Row(
                                        children: [
                                          Container(
                                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                            decoration: BoxDecoration(
                                              color: _CommunityDark.accent.withValues(alpha: 0.15),
                                              borderRadius: BorderRadius.circular(6),
                                            ),
                                            child: Text(
                                              roleTag,
                                              style: GoogleFonts.inter(color: _CommunityDark.accent, fontSize: 10, fontWeight: FontWeight.w600),
                                            ),
                                          ),
                                          const SizedBox(width: 6),
                                          Text(
                                            '•  $timeStr',
                                            style: GoogleFonts.inter(color: Colors.white54, fontSize: 12),
                                          ),
                                        ],
                                      ),
                                    ],
                                  ),
                                ),
                                if (isMyPost)
                                  PopupMenuButton<String>(
                                    icon: const Icon(Icons.more_horiz_rounded, color: Colors.white54),
                                    color: const Color(0xFF0F172A),
                                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                                    onSelected: (val) {
                                      if (val == 'edit') _showEditPostModal(doc);
                                      if (val == 'delete') _confirmDeletePost(doc);
                                    },
                                    itemBuilder: (context) => [
                                      PopupMenuItem(
                                        value: 'edit',
                                        child: Row(
                                          children: [
                                            const Icon(Icons.edit_rounded, color: Colors.white, size: 18),
                                            const SizedBox(width: 10),
                                            Text('កែប្រែ Post', style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5)),
                                          ],
                                        ),
                                      ),
                                      PopupMenuItem(
                                        value: 'delete',
                                        child: Row(
                                          children: [
                                            const Icon(Icons.delete_forever_rounded, color: Colors.redAccent, size: 18),
                                            const SizedBox(width: 10),
                                            Text('លុប Post', style: GoogleFonts.kantumruyPro(color: Colors.redAccent, fontSize: 13.5)),
                                          ],
                                        ),
                                      ),
                                    ],
                                  ),
                              ],
                            ),
                            const SizedBox(height: 14),

                            // Content
                            if (content.isNotEmpty)
                              Text(
                                content,
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white.withValues(alpha: 0.9),
                                  fontSize: 15,
                                  height: 1.5,
                                ),
                              ),

                            if (mediaUrl.isNotEmpty) ...[
                              const SizedBox(height: 16),
                              ClipRRect(
                                borderRadius: BorderRadius.circular(16),
                                child: Image.network(
                                  ApiService.getFullImageUrl(mediaUrl),
                                  fit: BoxFit.cover,
                                  width: double.infinity,
                                ),
                              ),
                            ],

                            const SizedBox(height: 16),
                            // Engagement Metrics
                            if (totalReactions > 0 || commentsCount > 0)
                              Padding(
                                padding: const EdgeInsets.only(bottom: 12),
                                child: Row(
                                  children: [
                                    if (totalReactions > 0) ...[
                                      Row(
                                        children: reactionCounts.keys.take(3).map((rKey) {
                                          final emoji = _reactions[rKey]?['emoji'] ?? '👍';
                                          return Padding(
                                            padding: const EdgeInsets.only(right: 2.0),
                                            child: Text(emoji, style: const TextStyle(fontSize: 14)),
                                          );
                                        }).toList(),
                                      ),
                                      const SizedBox(width: 6),
                                      Text(
                                        '$totalReactions',
                                        style: GoogleFonts.inter(color: Colors.white70, fontSize: 13, fontWeight: FontWeight.w500),
                                      ),
                                    ],
                                    const Spacer(),
                                    if (commentsCount > 0)
                                      Text(
                                        '$commentsCount Comments',
                                        style: GoogleFonts.inter(color: Colors.white54, fontSize: 13, fontWeight: FontWeight.w500),
                                      ),
                                  ],
                                ),
                              ),

                            const Divider(color: Color(0xFF334155), height: 1),
                            const SizedBox(height: 12),

                            // Actions
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                // Like
                                GestureDetector(
                                  onTap: () async {
                                    final Map<String, dynamic> updatedMap = Map.from(reactionsMap);
                                    if (userReactionKey.isNotEmpty) {
                                      updatedMap.remove(myId);
                                    } else {
                                      updatedMap[myId] = 'like';
                                    }
                                    await doc.reference.update({'reactionsMap': updatedMap});
                                  },
                                  onLongPress: () => _showReactionPicker(context, doc.reference, myId, reactionsMap),
                                  child: Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                                    child: Row(
                                      children: [
                                        Text(
                                          userReactionKey.isNotEmpty ? (_reactions[userReactionKey]?['emoji'] ?? '👍') : '👍',
                                          style: TextStyle(fontSize: userReactionKey.isNotEmpty ? 18 : 16),
                                        ),
                                        const SizedBox(width: 8),
                                        Text(
                                          userReactionKey.isNotEmpty ? (_reactions[userReactionKey]?['label'] ?? 'Like') : 'Like',
                                          style: GoogleFonts.inter(
                                            color: userReactionKey.isNotEmpty
                                                ? (_reactions[userReactionKey]?['color'] as Color? ?? _CommunityDark.accent)
                                                : Colors.white60,
                                            fontSize: 14,
                                            fontWeight: userReactionKey.isNotEmpty ? FontWeight.bold : FontWeight.w500,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                ),

                                // Comment
                                InkWell(
                                  onTap: () => _showCommentsSheet(doc, userProvider),
                                  borderRadius: BorderRadius.circular(12),
                                  child: Padding(
                                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                                    child: Row(
                                      children: [
                                        const Icon(Icons.mode_comment_outlined, color: Colors.white60, size: 20),
                                        const SizedBox(width: 8),
                                        Text(
                                          'Comment',
                                          style: GoogleFonts.inter(color: Colors.white60, fontSize: 14, fontWeight: FontWeight.w500),
                                        ),
                                      ],
                                    ),
                                  ),
                                ),

                                // Share
                                InkWell(
                                  onTap: () {
                                    Clipboard.setData(ClipboardData(text: content));
                                    ScaffoldMessenger.of(context).showSnackBar(
                                      SnackBar(
                                        content: Text('បានចម្លងអត្ថបទ Post!', style: GoogleFonts.kantumruyPro()),
                                        backgroundColor: _CommunityDark.accent,
                                      ),
                                    );
                                  },
                                  borderRadius: BorderRadius.circular(12),
                                  child: Padding(
                                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                                    child: Row(
                                      children: [
                                        const Icon(Icons.ios_share_rounded, color: Colors.white60, size: 20),
                                        const SizedBox(width: 8),
                                        Text(
                                          'Share',
                                          style: GoogleFonts.inter(color: Colors.white60, fontSize: 14, fontWeight: FontWeight.w500),
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
                    childCount: posts.length,
                  ),
                ),
              const SliverToBoxAdapter(child: SizedBox(height: 80)), // Padding for FAB
            ],
          );
        },
      ),
    );
  }
}
