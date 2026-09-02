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
import 'package:file_picker/file_picker.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:path/path.dart' as p;
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../services/r2_storage_service.dart';
import 'notification_screen.dart';

class _LocalAttachment {
  final File file;
  final String type; // 'image' or 'pdf'
  final String name;
  final int sizeBytes;

  _LocalAttachment({
    required this.file,
    required this.type,
    required this.name,
    required this.sizeBytes,
  });
}

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
  final ApiService _api = ApiService();

  late final Stream<QuerySnapshot> _postsStream;
  String _selectedTab = 'All';
  bool _isSearching = false;
  final TextEditingController _searchController = TextEditingController();

  void _openFullscreenGallery(List<Map<String, dynamic>> images, {int initialIndex = 0}) {
    if (images.isEmpty) return;
    final pageController = PageController(initialPage: initialIndex);
    int currentIndex = initialIndex;

    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => StatefulBuilder(
          builder: (context, setGalleryState) {
            return Scaffold(
              backgroundColor: Colors.black,
              appBar: AppBar(
                backgroundColor: Colors.black,
                elevation: 0,
                leading: IconButton(
                  icon: const Icon(Icons.close_rounded, color: Colors.white),
                  onPressed: () => Navigator.pop(context),
                ),
                title: Text(
                  '${currentIndex + 1} / ${images.length}',
                  style: GoogleFonts.inter(color: Colors.white, fontSize: 16),
                ),
                centerTitle: true,
              ),
              body: PageView.builder(
                controller: pageController,
                itemCount: images.length,
                onPageChanged: (idx) => setGalleryState(() => currentIndex = idx),
                itemBuilder: (context, index) {
                  final url = images[index]['url']?.toString() ?? '';
                  return Center(
                    child: InteractiveViewer(
                      minScale: 0.8,
                      maxScale: 4.0,
                      child: url.startsWith('data:image')
                          ? Image.memory(
                              base64Decode(url.split(',').last),
                              fit: BoxFit.contain,
                            )
                          : Image.network(
                              url.startsWith('http') ? url : ApiService.getFullImageUrl(url),
                              fit: BoxFit.contain,
                              errorBuilder: (_, __, ___) => const Icon(
                                Icons.broken_image_rounded,
                                color: Colors.white54,
                                size: 64,
                              ),
                            ),
                    ),
                  );
                },
              ),
            );
          },
        ),
      ),
    );
  }

  Widget _buildGridThumbnail(List<Map<String, dynamic>> images, int index, {required double height}) {
    final url = images[index]['url']?.toString() ?? '';
    return GestureDetector(
      onTap: () => _openFullscreenGallery(images, initialIndex: index),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(14),
        child: SizedBox(
          height: height,
          width: double.infinity,
          child: url.startsWith('data:image')
              ? Image.memory(
                  base64Decode(url.split(',').last),
                  fit: BoxFit.cover,
                )
              : Image.network(
                  url.startsWith('http') ? url : ApiService.getFullImageUrl(url),
                  fit: BoxFit.cover,
                  loadingBuilder: (context, child, progress) {
                    if (progress == null) return child;
                    return Container(
                      color: _CommunityDark.bg,
                      child: const Center(
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: _CommunityDark.accent,
                        ),
                      ),
                    );
                  },
                  errorBuilder: (_, __, ___) => Container(
                    color: _CommunityDark.bg,
                    child: const Center(
                      child: Icon(Icons.broken_image_rounded, color: Colors.white38, size: 28),
                    ),
                  ),
                ),
        ),
      ),
    );
  }

  Widget _buildImagesGrid(List<Map<String, dynamic>> images) {
    if (images.length == 1) {
      final url = images[0]['url']?.toString() ?? '';
      return _buildPostMedia(url);
    }

    if (images.length == 2) {
      return Padding(
        padding: const EdgeInsets.only(top: 14),
        child: Row(
          children: [
            Expanded(child: _buildGridThumbnail(images, 0, height: 180)),
            const SizedBox(width: 6),
            Expanded(child: _buildGridThumbnail(images, 1, height: 180)),
          ],
        ),
      );
    }

    if (images.length == 3) {
      return Padding(
        padding: const EdgeInsets.only(top: 14),
        child: Column(
          children: [
            _buildGridThumbnail(images, 0, height: 190),
            const SizedBox(height: 6),
            Row(
              children: [
                Expanded(child: _buildGridThumbnail(images, 1, height: 130)),
                const SizedBox(width: 6),
                Expanded(child: _buildGridThumbnail(images, 2, height: 130)),
              ],
            ),
          ],
        ),
      );
    }

    // 4 or more images (2x2 grid with +X more overlay)
    final extraCount = images.length - 4;
    return Padding(
      padding: const EdgeInsets.only(top: 14),
      child: Column(
        children: [
          Row(
            children: [
              Expanded(child: _buildGridThumbnail(images, 0, height: 140)),
              const SizedBox(width: 6),
              Expanded(child: _buildGridThumbnail(images, 1, height: 140)),
            ],
          ),
          const SizedBox(height: 6),
          Row(
            children: [
              Expanded(child: _buildGridThumbnail(images, 2, height: 140)),
              const SizedBox(width: 6),
              Expanded(
                child: Stack(
                  children: [
                    _buildGridThumbnail(images, 3, height: 140),
                    if (extraCount > 0)
                      Positioned.fill(
                        child: GestureDetector(
                          onTap: () => _openFullscreenGallery(images, initialIndex: 3),
                          child: Container(
                            decoration: BoxDecoration(
                              color: Colors.black.withValues(alpha: 0.65),
                              borderRadius: BorderRadius.circular(14),
                            ),
                            child: Center(
                              child: Text(
                                '+$extraCount',
                                style: GoogleFonts.outfit(
                                  color: Colors.white,
                                  fontSize: 22,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildPdfAttachmentTile(Map<String, dynamic> pdf) {
    final url = (pdf['url'] ?? '').toString();
    final name = (pdf['name'] ?? 'ឯកសារភ្ជាប់ (PDF)').toString();
    final size = (pdf['size'] as num?)?.toInt() ?? 0;
    final sizeFormatted = size > 0 ? '${(size / 1024).toStringAsFixed(1)} KB' : 'PDF';

    return Container(
      margin: const EdgeInsets.only(top: 8),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: _CommunityDark.bg,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: Colors.redAccent.withValues(alpha: 0.3),
          width: 0.8,
        ),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: Colors.redAccent.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(12),
            ),
            child: const Icon(
              Icons.picture_as_pdf_rounded,
              color: Colors.redAccent,
              size: 26,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  name,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontWeight: FontWeight.w600,
                    fontSize: 13.5,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  'PDF Document • $sizeFormatted',
                  style: GoogleFonts.inter(
                    color: Colors.white54,
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ),
          IconButton(
            icon: const Icon(
              Icons.open_in_new_rounded,
              color: _CommunityDark.accent,
              size: 20,
            ),
            onPressed: () async {
              final fullUrl = url.startsWith('http') ? url : ApiService.getFullImageUrl(url);
              final uri = Uri.parse(fullUrl);
              if (await canLaunchUrl(uri)) {
                await launchUrl(uri, mode: LaunchMode.externalApplication);
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildPostMediaGroup(Map<String, dynamic> data) {
    final List<dynamic> rawMediaList = data['mediaList'] as List<dynamic>? ?? [];
    final String singleMediaUrl = data['mediaUrl'] as String? ?? '';

    final List<Map<String, dynamic>> images = [];
    final List<Map<String, dynamic>> pdfs = [];

    if (rawMediaList.isNotEmpty) {
      for (final item in rawMediaList) {
        if (item is Map) {
          final m = Map<String, dynamic>.from(item);
          final type = (m['type'] ?? '').toString().toLowerCase();
          final url = (m['url'] ?? '').toString();
          if (type == 'pdf' || url.endsWith('.pdf')) {
            pdfs.add(m);
          } else {
            images.add(m);
          }
        }
      }
    } else if (singleMediaUrl.isNotEmpty) {
      if (singleMediaUrl.endsWith('.pdf')) {
        pdfs.add({'url': singleMediaUrl, 'type': 'pdf', 'name': 'ឯកសារភ្ជាប់ (PDF Document)'});
      } else {
        images.add({'url': singleMediaUrl, 'type': 'image'});
      }
    }

    if (images.isEmpty && pdfs.isEmpty) return const SizedBox.shrink();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (images.isNotEmpty) _buildImagesGrid(images),
        if (pdfs.isNotEmpty) ...[
          const SizedBox(height: 10),
          ...pdfs.map((pdf) => _buildPdfAttachmentTile(pdf)),
        ],
      ],
    );
  }

  void _openFullscreenImage(String mediaUrl) {
    _openFullscreenGallery([{'url': mediaUrl}], initialIndex: 0);
  }

  Widget _buildPostMedia(String mediaUrl) {
    if (mediaUrl.isEmpty) return const SizedBox.shrink();

    Widget imageWidget;
    if (mediaUrl.startsWith('data:image')) {
      try {
        final bytes = base64Decode(mediaUrl.split(',').last);
        imageWidget = Image.memory(
          bytes,
          fit: BoxFit.cover,
          width: double.infinity,
          gaplessPlayback: true,
        );
      } catch (_) {
        imageWidget = const SizedBox.shrink();
      }
    } else {
      final fullUrl = mediaUrl.startsWith('http')
          ? mediaUrl
          : ApiService.getFullImageUrl(mediaUrl);
      imageWidget = Image.network(
        fullUrl,
        fit: BoxFit.cover,
        width: double.infinity,
        loadingBuilder: (context, child, progress) {
          if (progress == null) return child;
          return Container(
            height: 200,
            color: _CommunityDark.bg,
            child: const Center(
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: _CommunityDark.accent,
              ),
            ),
          );
        },
        errorBuilder: (context, error, stackTrace) {
          return Container(
            height: 140,
            color: _CommunityDark.bg,
            child: const Center(
              child: Icon(
                Icons.broken_image_rounded,
                color: Colors.white38,
                size: 36,
              ),
            ),
          );
        },
      );
    }

    return Padding(
      padding: const EdgeInsets.only(top: 14),
      child: GestureDetector(
        onTap: () => _openFullscreenImage(mediaUrl),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(16),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 380),
            child: imageWidget,
          ),
        ),
      ),
    );
  }

  @override
  void initState() {
    super.initState();
    _postsStream =
        _firestore
            .collection('community_posts')
            .orderBy('createdAt', descending: true)
            .snapshots();
    _searchController.addListener(() {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
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

  // Auto Compress Image to Minimal Bytes (~70KB-150KB) while Retaining HD Quality
  Future<File> _compressImage(File file, {bool isCamera = false}) async {
    try {
      final bytes = await file.readAsBytes();
      final decoded = img.decodeImage(bytes);
      if (decoded == null) return file;

      img.Image oriented = img.bakeOrientation(decoded);
      if (isCamera) {
        oriented = img.flipHorizontal(oriented);
      }

      // Resize max dimension to 1280px for minimal storage & fast rendering
      if (oriented.width > 1280 || oriented.height > 1280) {
        oriented = img.copyResize(
          oriented,
          width: oriented.width >= oriented.height ? 1280 : null,
          height: oriented.height > oriented.width ? 1280 : null,
          interpolation: img.Interpolation.linear,
        );
      }

      final compressedBytes = Uint8List.fromList(
        img.encodeJpg(oriented, quality: 75),
      );
      final tempDir = await getTemporaryDirectory();
      final compressedFile = File(
        '${tempDir.path}/comp_${DateTime.now().millisecondsSinceEpoch}_${p.basename(file.path)}',
      );
      await compressedFile.writeAsBytes(compressedBytes);
      return compressedFile;
    } catch (e) {
      debugPrint('Auto compress image error: $e');
      return file;
    }
  }

  // ==========================================
  // CREATE POST MODAL (Multi-Media & PDF Group)
  // ==========================================
  void _showCreatePostModal(UserProvider user) {
    final textController = TextEditingController();
    final List<_LocalAttachment> attachments = [];
    bool isPosting = false;
    String selectedCategory = '📢 ការជូនដំណឹង';

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
                        icon: const Icon(
                          Icons.close_rounded,
                          color: Colors.white70,
                        ),
                        onPressed: () => Navigator.pop(ctx),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  // Category Selector Chips
                  Text(
                    'ប្រភេទការបង្ហោះ (Category)៖',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white70,
                      fontSize: 12.5,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 6),
                  SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    child: Row(
                      children: [
                        '📢 ការជូនដំណឹង',
                        '📚 ចំណេះដឹង & Tips',
                        '🔥 ព័ត៌មានទូទៅ',
                      ].map((cat) {
                        final isSel = selectedCategory == cat;
                        return GestureDetector(
                          onTap: () => setModalState(() => selectedCategory = cat),
                          child: AnimatedContainer(
                            duration: const Duration(milliseconds: 200),
                            margin: const EdgeInsets.only(right: 8),
                            padding: const EdgeInsets.symmetric(
                              horizontal: 12,
                              vertical: 6,
                            ),
                            decoration: BoxDecoration(
                              color: isSel
                                  ? _CommunityDark.accent.withValues(alpha: 0.2)
                                  : _CommunityDark.bg,
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(
                                color: isSel
                                    ? _CommunityDark.accent
                                    : const Color(0xFF334155),
                                width: isSel ? 1.2 : 0.8,
                              ),
                            ),
                            child: Text(
                              cat,
                              style: GoogleFonts.kantumruyPro(
                                color: isSel ? Colors.white : Colors.white60,
                                fontSize: 12,
                                fontWeight: isSel ? FontWeight.bold : FontWeight.normal,
                              ),
                            ),
                          ),
                        );
                      }).toList(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: textController,
                    maxLines: 4,
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 14.5,
                    ),
                    decoration: InputDecoration(
                      hintText: 'សរសេរព័ត៌មាន ការប្រកាស ឬការផ្សព្វផ្សាយ...',
                      hintStyle: GoogleFonts.kantumruyPro(
                        color: Colors.white38,
                        fontSize: 14.0,
                      ),
                      filled: true,
                      fillColor: _CommunityDark.bg,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(16),
                        borderSide: BorderSide.none,
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),

                  // Attachments Preview List (Grouped)
                  if (attachments.isNotEmpty) ...[
                    SizedBox(
                      height: 105,
                      child: ListView.separated(
                        scrollDirection: Axis.horizontal,
                        itemCount: attachments.length,
                        separatorBuilder: (_, __) => const SizedBox(width: 8),
                        itemBuilder: (context, idx) {
                          final att = attachments[idx];
                          final sizeKb = (att.sizeBytes / 1024).toStringAsFixed(0);

                          return Stack(
                            children: [
                              Container(
                                width: 100,
                                height: 100,
                                decoration: BoxDecoration(
                                  color: _CommunityDark.bg,
                                  borderRadius: BorderRadius.circular(14),
                                  border: Border.all(
                                    color: att.type == 'pdf'
                                        ? Colors.redAccent.withValues(alpha: 0.4)
                                        : _CommunityDark.accent.withValues(alpha: 0.3),
                                  ),
                                ),
                                child: att.type == 'pdf'
                                    ? Column(
                                        mainAxisAlignment: MainAxisAlignment.center,
                                        children: [
                                          const Icon(
                                            Icons.picture_as_pdf_rounded,
                                            color: Colors.redAccent,
                                            size: 32,
                                          ),
                                          const SizedBox(height: 4),
                                          Padding(
                                            padding: const EdgeInsets.symmetric(horizontal: 4),
                                            child: Text(
                                              att.name,
                                              maxLines: 1,
                                              overflow: TextOverflow.ellipsis,
                                              style: GoogleFonts.inter(
                                                color: Colors.white70,
                                                fontSize: 10,
                                              ),
                                            ),
                                          ),
                                          Text(
                                            '$sizeKb KB',
                                            style: GoogleFonts.inter(
                                              color: Colors.white38,
                                              fontSize: 9,
                                            ),
                                          ),
                                        ],
                                      )
                                    : ClipRRect(
                                        borderRadius: BorderRadius.circular(13),
                                        child: Stack(
                                          fit: StackFit.expand,
                                          children: [
                                            Image.file(
                                              att.file,
                                              fit: BoxFit.cover,
                                            ),
                                            Positioned(
                                              bottom: 4,
                                              left: 4,
                                              child: Container(
                                                padding: const EdgeInsets.symmetric(
                                                  horizontal: 4,
                                                  vertical: 1,
                                                ),
                                                decoration: BoxDecoration(
                                                  color: Colors.black87,
                                                  borderRadius: BorderRadius.circular(4),
                                                ),
                                                child: Text(
                                                  '$sizeKb KB',
                                                  style: GoogleFonts.inter(
                                                    color: Colors.white,
                                                    fontSize: 8.5,
                                                  ),
                                                ),
                                              ),
                                            ),
                                          ],
                                        ),
                                      ),
                              ),
                              Positioned(
                                top: 4,
                                right: 4,
                                child: GestureDetector(
                                  onTap: () => setModalState(() => attachments.removeAt(idx)),
                                  child: Container(
                                    padding: const EdgeInsets.all(3),
                                    decoration: const BoxDecoration(
                                      color: Color(0xCC000000),
                                      shape: BoxShape.circle,
                                    ),
                                    child: const Icon(
                                      Icons.close_rounded,
                                      color: Colors.white,
                                      size: 14,
                                    ),
                                  ),
                                ),
                              ),
                            ],
                          );
                        },
                      ),
                    ),
                    const SizedBox(height: 12),
                  ],

                  // Action Buttons (Multi-Image, Camera, PDF)
                  Row(
                    children: [
                      // Multi-Image Gallery
                      InkWell(
                        onTap: () async {
                          final pickedFiles = await _picker.pickMultiImage(imageQuality: 85);
                          if (pickedFiles.isNotEmpty) {
                            for (final p in pickedFiles) {
                              final comp = await _compressImage(File(p.path), isCamera: false);
                              final size = await comp.length();
                              attachments.add(_LocalAttachment(
                                file: comp,
                                type: 'image',
                                name: comp.path.split(RegExp(r'[\\/]')).last,
                                sizeBytes: size,
                              ));
                            }
                            setModalState(() {});
                          }
                        },
                        borderRadius: BorderRadius.circular(12),
                        child: Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: _CommunityDark.bg,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: const Icon(
                            Icons.photo_library_rounded,
                            color: _CommunityDark.accent,
                            size: 22,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),

                      // Camera
                      InkWell(
                        onTap: () async {
                          final picked = await _picker.pickImage(
                            source: ImageSource.camera,
                            imageQuality: 85,
                          );
                          if (picked != null) {
                            final comp = await _compressImage(File(picked.path), isCamera: true);
                            final size = await comp.length();
                            attachments.add(_LocalAttachment(
                              file: comp,
                              type: 'image',
                              name: comp.path.split(RegExp(r'[\\/]')).last,
                              sizeBytes: size,
                            ));
                            setModalState(() {});
                          }
                        },
                        borderRadius: BorderRadius.circular(12),
                        child: Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: _CommunityDark.bg,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: const Icon(
                            Icons.camera_alt_rounded,
                            color: _CommunityDark.success,
                            size: 22,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),

                      // PDF Document Picker
                      InkWell(
                        onTap: () async {
                          final res = await FilePicker.platform.pickFiles(
                            type: FileType.custom,
                            allowedExtensions: ['pdf'],
                            allowMultiple: true,
                          );
                          if (res != null && res.files.isNotEmpty) {
                            for (final f in res.files) {
                              if (f.path != null) {
                                final file = File(f.path!);
                                final size = await file.length();
                                attachments.add(_LocalAttachment(
                                  file: file,
                                  type: 'pdf',
                                  name: f.name,
                                  sizeBytes: size,
                                ));
                              }
                            }
                            setModalState(() {});
                          }
                        },
                        borderRadius: BorderRadius.circular(12),
                        child: Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: _CommunityDark.bg,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: const Icon(
                            Icons.picture_as_pdf_rounded,
                            color: Colors.redAccent,
                            size: 22,
                          ),
                        ),
                      ),

                      const Spacer(),

                      // Post Submit Button
                      ElevatedButton(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: _CommunityDark.accent,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(20),
                          ),
                          padding: const EdgeInsets.symmetric(
                            horizontal: 22,
                            vertical: 12,
                          ),
                        ),
                        onPressed:
                            isPosting
                                ? null
                                : () async {
                                  final text = textController.text.trim();
                                  if (text.isEmpty && attachments.isEmpty) {
                                    return;
                                  }

                                  setModalState(() => isPosting = true);

                                  try {
                                    final List<Map<String, dynamic>> uploadedMediaList = [];
                                    String firstMediaUrl = '';

                                    for (final att in attachments) {
                                      try {
                                        final upRes = await _api.uploadCommunityMedia(
                                          att.file,
                                          customExt: att.type == 'pdf' ? 'pdf' : 'jpg',
                                          fileName: att.name,
                                        );
                                        if (upRes['success'] == true && upRes['url'] != null) {
                                          final url = upRes['url'].toString();
                                          if (firstMediaUrl.isEmpty && att.type == 'image') {
                                            firstMediaUrl = url;
                                          }
                                          uploadedMediaList.add({
                                            'url': url,
                                            'type': att.type,
                                            'name': att.name,
                                            'size': att.sizeBytes,
                                          });
                                        }
                                      } catch (e) {
                                        debugPrint('Attachment upload error: $e');
                                      }
                                    }

                                    // Fallback for single attachment if upload failed
                                    if (uploadedMediaList.isEmpty && attachments.isNotEmpty) {
                                      for (final att in attachments) {
                                        if (att.type == 'image') {
                                          final imgBytes = await att.file.readAsBytes();
                                          final b64 = 'data:image/jpeg;base64,${base64Encode(imgBytes)}';
                                          if (firstMediaUrl.isEmpty) firstMediaUrl = b64;
                                          uploadedMediaList.add({
                                            'url': b64,
                                            'type': 'image',
                                            'name': att.name,
                                            'size': att.sizeBytes,
                                          });
                                        }
                                      }
                                    }

                                    final docRef = await _firestore
                                        .collection('community_posts')
                                        .add({
                                          'authorId': user.employeeId ?? '',
                                          'authorName':
                                              user.name ?? 'VVC Member',
                                          'authorAvatar': user.avatar ?? '',
                                          'roleTag': selectedCategory,
                                          'isAnnouncement': selectedCategory.contains('ជូនដំណឹង'),
                                          'isKnowledge': selectedCategory.contains('ចំណេះដឹង'),
                                          'content': text,
                                          'mediaUrl': firstMediaUrl,
                                          'mediaList': uploadedMediaList,
                                          'reactionsMap': {},
                                          'likes': [],
                                          'viewedBy': [user.employeeId ?? ''],
                                          'createdAt':
                                              FieldValue.serverTimestamp(),
                                        });

                                    // Trigger FCM External Push & In-app Notification to all employees
                                    _api.notifyCommunityPost(
                                      postId: docRef.id,
                                      category: selectedCategory,
                                      authorName: user.name ?? 'VVC Member',
                                      content: text,
                                      imageUrl: firstMediaUrl.isNotEmpty && !firstMediaUrl.startsWith('data:') ? firstMediaUrl : null,
                                    );

                                    if (context.mounted) {
                                      Navigator.pop(ctx);
                                      ScaffoldMessenger.of(
                                        context,
                                      ).showSnackBar(
                                        SnackBar(
                                          content: Text(
                                            'បានផ្សព្វផ្សាយព័ត៌មានរួចរាល់!',
                                            style: GoogleFonts.kantumruyPro(),
                                          ),
                                          backgroundColor:
                                              _CommunityDark.success,
                                        ),
                                      );
                                    }
                                  } catch (e) {
                                    debugPrint('Create post error: $e');
                                    if (context.mounted) {
                                      ScaffoldMessenger.of(
                                        context,
                                      ).showSnackBar(
                                        SnackBar(
                                          content: Text(
                                            'មានបញ្ហាក្នុងការផ្សព្វផ្សាយ៖ $e',
                                            style: GoogleFonts.kantumruyPro(),
                                          ),
                                          backgroundColor:
                                              _CommunityDark.danger,
                                        ),
                                      );
                                    }
                                  } finally {
                                    if (ctx.mounted) {
                                      setModalState(() => isPosting = false);
                                    }
                                  }
                                },
                        child:
                            isPosting
                                ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    color: Colors.white,
                                    strokeWidth: 2,
                                  ),
                                )
                                : Text(
                                  'ផ្សព្វផ្សាយ (Publish)',
                                  style: GoogleFonts.kantumruyPro(
                                    color: Colors.white,
                                    fontWeight: FontWeight.bold,
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
                        icon: const Icon(
                          Icons.close_rounded,
                          color: Colors.white70,
                        ),
                        onPressed: () => Navigator.pop(ctx),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  TextField(
                    controller: textController,
                    maxLines: 4,
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 14.5,
                    ),
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
                          child: Image.file(
                            newImage!,
                            height: 180,
                            width: double.infinity,
                            fit: BoxFit.cover,
                          ),
                        ),
                        Positioned(
                          right: 8,
                          top: 8,
                          child: InkWell(
                            onTap: () => setModalState(() => newImage = null),
                            child: Container(
                              padding: const EdgeInsets.all(6),
                              decoration: const BoxDecoration(
                                color: Color(0x99000000),
                                shape: BoxShape.circle,
                              ),
                              child: const Icon(
                                Icons.close_rounded,
                                color: Colors.white,
                                size: 18,
                              ),
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
                          child: Image.network(
                            ApiService.getFullImageUrl(currentMediaUrl),
                            height: 180,
                            width: double.infinity,
                            fit: BoxFit.cover,
                          ),
                        ),
                        Positioned(
                          right: 8,
                          top: 8,
                          child: InkWell(
                            onTap:
                                () => setModalState(() => currentMediaUrl = ''),
                            child: Container(
                              padding: const EdgeInsets.all(6),
                              decoration: const BoxDecoration(
                                color: Color(0x99000000),
                                shape: BoxShape.circle,
                              ),
                              child: const Icon(
                                Icons.close_rounded,
                                color: Colors.white,
                                size: 18,
                              ),
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
                          final picked = await _picker.pickImage(
                            source: ImageSource.gallery,
                            imageQuality: 85,
                          );
                          if (picked != null) {
                            final comp = await _compressImage(
                              File(picked.path),
                              isCamera: false,
                            );
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
                          child: const Icon(
                            Icons.photo_library_rounded,
                            color: _CommunityDark.accent,
                            size: 24,
                          ),
                        ),
                      ),
                      const SizedBox(width: 10),
                      InkWell(
                        onTap: () async {
                          final picked = await _picker.pickImage(
                            source: ImageSource.camera,
                            imageQuality: 85,
                          );
                          if (picked != null) {
                            final comp = await _compressImage(
                              File(picked.path),
                              isCamera: true,
                            );
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
                          child: const Icon(
                            Icons.camera_alt_rounded,
                            color: _CommunityDark.success,
                            size: 24,
                          ),
                        ),
                      ),
                      const Spacer(),
                      ElevatedButton(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: _CommunityDark.accent,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(20),
                          ),
                          padding: const EdgeInsets.symmetric(
                            horizontal: 22,
                            vertical: 12,
                          ),
                        ),
                        onPressed:
                            isSaving
                                ? null
                                : () async {
                                  final text = textController.text.trim();
                                  setModalState(() => isSaving = true);

                                  try {
                                    String mediaUrl = currentMediaUrl;
                                    if (newImage != null) {
                                      // 1. Backend server upload
                                      try {
                                        final upRes = await _api.uploadCommunityMedia(newImage!);
                                        if (upRes['success'] == true && upRes['url'] != null) {
                                          mediaUrl = upRes['url'].toString();
                                        }
                                      } catch (e) {
                                        debugPrint('Backend upload error: $e');
                                      }

                                      // 2. Cloudflare R2 fallback
                                      if (mediaUrl.isEmpty || mediaUrl == currentMediaUrl) {
                                        try {
                                          final uploaded = await _r2Service.uploadMedia(
                                            file: newImage!,
                                            folder: 'community',
                                          );
                                          if (uploaded != null && uploaded.isNotEmpty) {
                                            mediaUrl = uploaded;
                                          }
                                        } catch (e) {
                                          debugPrint('R2 upload error: $e');
                                        }
                                      }

                                      // 3. Fallback to base64
                                      if (mediaUrl.isEmpty || mediaUrl == currentMediaUrl) {
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
                                      ScaffoldMessenger.of(
                                        context,
                                      ).showSnackBar(
                                        SnackBar(
                                          content: Text(
                                            'បានរក្សាទុកការកែប្រែ!',
                                            style: GoogleFonts.kantumruyPro(),
                                          ),
                                          backgroundColor:
                                              _CommunityDark.success,
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
                        child:
                            isSaving
                                ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    color: Colors.white,
                                    strokeWidth: 2,
                                  ),
                                )
                                : Text(
                                  'រក្សាទុក (Save)',
                                  style: GoogleFonts.kantumruyPro(
                                    color: Colors.white,
                                    fontWeight: FontWeight.bold,
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
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(20),
          ),
          title: Text(
            'លុប Post',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
            ),
          ),
          content: Text(
            'តើអ្នកពិតជាចង់លុប Post នេះចេញពីសហគមន៍មែនទេ?',
            style: GoogleFonts.kantumruyPro(color: Colors.white70),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogCtx),
              child: Text(
                'បោះបង់',
                style: GoogleFonts.kantumruyPro(color: Colors.white54),
              ),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: _CommunityDark.danger,
              ),
              onPressed: () async {
                Navigator.pop(dialogCtx);
                await postDoc.reference.delete();
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(
                        'បានលុប Post រួចរាល់!',
                        style: GoogleFonts.kantumruyPro(),
                      ),
                      backgroundColor: _CommunityDark.danger,
                    ),
                  );
                }
              },
              child: Text(
                'លុបចេញ',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ],
        );
      },
    );
  }

  // ==========================================
  // SEND UNREAD REMINDER NOTIFICATION
  // ==========================================
  void _sendUnreadReminder(DocumentSnapshot postDoc) {
    final data = postDoc.data() as Map<String, dynamic>;
    final List<dynamic> rawViewed = data['viewedBy'] as List<dynamic>? ?? [];
    final List<String> viewedIds = rawViewed.map((e) => e.toString()).toList();
    final String category = data['roleTag'] ?? '📢 ការជូនដំណឹង';
    final String content = data['content'] ?? '';

    showDialog(
      context: context,
      builder: (dialogCtx) {
        return AlertDialog(
          backgroundColor: _CommunityDark.card,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(20),
          ),
          title: Row(
            children: [
              const Icon(
                Icons.notifications_active_rounded,
                color: Color(0xFFFFCC00),
                size: 24,
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'រំលឹកអ្នកមិនទាន់មើល',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                  ),
                ),
              ),
            ],
          ),
          content: Text(
            'ប្រព័ន្ធនឹងផ្ញើសាររំលឹក (Push Notification) ទៅកាន់បុគ្គលិកទាំងអស់ដែលមិនទាន់បានចូលមើលការប្រកាស/ព័ត៌មាននេះ។ តើអ្នកចង់បន្តផ្ញើមែនទេ?',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white70,
              fontSize: 13.5,
              height: 1.5,
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogCtx),
              child: Text(
                'បោះបង់',
                style: GoogleFonts.kantumruyPro(color: Colors.white54),
              ),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF0A84FF),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              ),
              onPressed: () async {
                Navigator.pop(dialogCtx);
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('កំពុងផ្ញើការជូនដំណឹងរំលឹក...'),
                    duration: Duration(seconds: 2),
                  ),
                );

                final res = await _api.remindUnreadCommunityPost(
                  postId: postDoc.id,
                  category: category,
                  content: content,
                  viewedEmployeeIds: viewedIds,
                );

                if (mounted) {
                  final int count = (res['reminded_count'] as num?)?.toInt() ?? 0;
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(
                        'បានផ្ញើការរំលឹកទៅកាន់បុគ្គលិកចំនួន $count នាក់រួចរាល់! 🔔',
                        style: GoogleFonts.kantumruyPro(),
                      ),
                      backgroundColor: _CommunityDark.success,
                    ),
                  );
                }
              },
              child: Text(
                'ផ្ញើការរំលឹក',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ],
        );
      },
    );
  }

  // ==========================================
  // FACEBOOK REACTION PICKER POPUP
  // ==========================================
  void _showReactionPicker(
    BuildContext context,
    DocumentReference docRef,
    String currentUserId,
    Map<String, dynamic> currentReactionsMap,
  ) {
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
            children:
                _reactions.entries.map((entry) {
                  final key = entry.key;
                  final emoji = entry.value['emoji'] as String;

                  return InkWell(
                    onTap: () async {
                      Navigator.pop(ctx);
                      final Map<String, dynamic> updatedMap = Map.from(
                        currentReactionsMap,
                      );
                      if (updatedMap[currentUserId] == key) {
                        updatedMap.remove(currentUserId);
                      } else {
                        updatedMap[currentUserId] = key;
                      }
                      await docRef.update({'reactionsMap': updatedMap});
                    },
                    child: Padding(
                      padding: const EdgeInsets.all(4.0),
                      child: Text(emoji, style: const TextStyle(fontSize: 32)),
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
              padding: EdgeInsets.only(
                bottom: MediaQuery.of(context).viewInsets.bottom,
              ),
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
                          icon: const Icon(
                            Icons.close_rounded,
                            color: Colors.white70,
                          ),
                          onPressed: () => Navigator.pop(sheetCtx),
                        ),
                      ],
                    ),
                  ),
                  const Divider(color: Colors.white12, height: 1),

                  // Real-time Comments List
                  Expanded(
                    child: StreamBuilder<QuerySnapshot>(
                      stream:
                          postDoc.reference.collection('comments').snapshots(),
                      builder: (context, snapshot) {
                        if (snapshot.hasError) {
                          return Center(
                            child: Padding(
                              padding: const EdgeInsets.all(20.0),
                              child: Text(
                                'មិនទាន់មានមតិយោបល់នៅឡើយទេ\nជាអ្នកដំបូងដែលបញ្ចេញមតិ!',
                                textAlign: TextAlign.center,
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white54,
                                  fontSize: 13.5,
                                ),
                              ),
                            ),
                          );
                        }

                        if (snapshot.connectionState ==
                                ConnectionState.waiting &&
                            !snapshot.hasData) {
                          return const Center(
                            child: SizedBox(
                              width: 24,
                              height: 24,
                              child: CircularProgressIndicator(
                                color: _CommunityDark.accent,
                                strokeWidth: 2.5,
                              ),
                            ),
                          );
                        }

                        final comments =
                            snapshot.hasData
                                ? List<DocumentSnapshot>.from(
                                  snapshot.data!.docs,
                                )
                                : <DocumentSnapshot>[];
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
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white54,
                                fontSize: 13.5,
                              ),
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
                            final String cAuthorName =
                                cData['authorName'] ?? 'Member';
                            final String cAuthorAvatar =
                                cData['authorAvatar'] ?? '';
                            final String cText = cData['text'] ?? '';
                            final Timestamp? cTs =
                                cData['createdAt'] as Timestamp?;
                            final String cTime =
                                cTs != null
                                    ? DateFormat(
                                      'HH:mm dd/MM',
                                    ).format(cTs.toDate())
                                    : 'ទើបតែ';
                            final bool isMyComment =
                                cAuthorId == user.employeeId;

                            return Container(
                              margin: const EdgeInsets.only(bottom: 12),
                              child: Row(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  CircleAvatar(
                                    radius: 16,
                                    backgroundImage:
                                        cAuthorAvatar.isNotEmpty
                                            ? NetworkImage(
                                              ApiService.getFullImageUrl(
                                                cAuthorAvatar,
                                              ),
                                            )
                                            : null,
                                    backgroundColor: _CommunityDark.accent,
                                    child:
                                        cAuthorAvatar.isEmpty
                                            ? Text(
                                              cAuthorName[0].toUpperCase(),
                                              style: GoogleFonts.inter(
                                                color: Colors.white,
                                                fontSize: 12,
                                                fontWeight: FontWeight.bold,
                                              ),
                                            )
                                            : null,
                                  ),
                                  const SizedBox(width: 10),
                                  Expanded(
                                    child: Container(
                                      padding: const EdgeInsets.symmetric(
                                        horizontal: 14,
                                        vertical: 10,
                                      ),
                                      decoration: BoxDecoration(
                                        color: _CommunityDark.bg,
                                        borderRadius: BorderRadius.circular(16),
                                      ),
                                      child: Column(
                                        crossAxisAlignment:
                                            CrossAxisAlignment.start,
                                        children: [
                                          Row(
                                            children: [
                                              Text(
                                                cAuthorName,
                                                style: GoogleFonts.kantumruyPro(
                                                  color: Colors.white,
                                                  fontSize: 13,
                                                  fontWeight: FontWeight.bold,
                                                ),
                                              ),
                                              const Spacer(),
                                              Text(
                                                cTime,
                                                style: GoogleFonts.inter(
                                                  color: Colors.white38,
                                                  fontSize: 10,
                                                ),
                                              ),
                                              if (isMyComment) ...[
                                                const SizedBox(width: 6),
                                                InkWell(
                                                  onTap: () async {
                                                    try {
                                                      await cDoc.reference
                                                          .delete();
                                                      await postDoc.reference
                                                          .update({
                                                            'commentsCount':
                                                                FieldValue.increment(
                                                                  -1,
                                                                ),
                                                          });
                                                    } catch (_) {}
                                                  },
                                                  child: const Icon(
                                                    Icons
                                                        .delete_outline_rounded,
                                                    color: Colors.redAccent,
                                                    size: 16,
                                                  ),
                                                ),
                                              ],
                                            ],
                                          ),
                                          const SizedBox(height: 4),
                                          Text(
                                            cText,
                                            style: GoogleFonts.kantumruyPro(
                                              color: Colors.white70,
                                              fontSize: 13.5,
                                            ),
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
                      border: Border(
                        top: BorderSide(color: Colors.white12, width: 0.5),
                      ),
                    ),
                    child: Row(
                      children: [
                        Expanded(
                          child: TextField(
                            controller: commentController,
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 14,
                            ),
                            decoration: InputDecoration(
                              hintText: 'សរសេរមតិយោបល់...',
                              hintStyle: GoogleFonts.kantumruyPro(
                                color: Colors.white38,
                                fontSize: 13.5,
                              ),
                              filled: true,
                              fillColor: _CommunityDark.bg,
                              isDense: true,
                              contentPadding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 10,
                              ),
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(20),
                                borderSide: BorderSide.none,
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        InkWell(
                          onTap:
                              isSending
                                  ? null
                                  : () async {
                                    final text = commentController.text.trim();
                                    if (text.isEmpty) return;
                                    setSheetState(() => isSending = true);
                                    try {
                                      commentController.clear();
                                      await postDoc.reference
                                          .collection('comments')
                                          .add({
                                            'authorId': user.employeeId ?? '',
                                            'authorName': user.name ?? 'Member',
                                            'authorAvatar': user.avatar ?? '',
                                            'text': text,
                                            'createdAt':
                                                FieldValue.serverTimestamp(),
                                          });
                                      await postDoc.reference.update({
                                        'commentsCount': FieldValue.increment(
                                          1,
                                        ),
                                      });
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
                            child:
                                isSending
                                    ? const SizedBox(
                                      width: 18,
                                      height: 18,
                                      child: CircularProgressIndicator(
                                        color: Colors.white,
                                        strokeWidth: 2,
                                      ),
                                    )
                                    : const Icon(
                                      Icons.send_rounded,
                                      color: Colors.white,
                                      size: 18,
                                    ),
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
          decoration: const BoxDecoration(
            color: _CommunityDark.bg,
            border: Border(
              bottom: BorderSide(color: Color(0xFF1E293B), width: 1),
            ),
          ),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              // Top Nav Row
              Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: 8.0,
                  vertical: 8.0,
                ),
                child: Row(
                  children: [
                    IconButton(
                      icon: const Icon(
                        Icons.arrow_back_ios_new_rounded,
                        color: Colors.white,
                        size: 20,
                      ),
                      onPressed: () => Navigator.pop(context),
                    ),
                    Expanded(
                      child:
                          _isSearching
                              ? TextField(
                                controller: _searchController,
                                autofocus: true,
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white,
                                  fontSize: 14.5,
                                ),
                                decoration: InputDecoration(
                                  hintText: 'ស្វែងរកព័ត៌មាន ឬអ្នកបង្ហោះ...',
                                  hintStyle: GoogleFonts.kantumruyPro(
                                    color: Colors.white38,
                                    fontSize: 13.5,
                                  ),
                                  filled: true,
                                  fillColor: const Color(0xFF1E293B),
                                  isDense: true,
                                  contentPadding: const EdgeInsets.symmetric(
                                    horizontal: 14,
                                    vertical: 9,
                                  ),
                                  border: OutlineInputBorder(
                                    borderRadius: BorderRadius.circular(16),
                                    borderSide: BorderSide.none,
                                  ),
                                  prefixIcon: const Icon(
                                    Icons.search_rounded,
                                    color: Colors.white60,
                                    size: 18,
                                  ),
                                  suffixIcon:
                                      _searchController.text.isNotEmpty
                                          ? IconButton(
                                            icon: const Icon(
                                              Icons.clear_rounded,
                                              color: Colors.white60,
                                              size: 18,
                                            ),
                                            onPressed:
                                                () => _searchController.clear(),
                                          )
                                          : null,
                                ),
                              )
                              : Text(
                                'VVC Community',
                                style: GoogleFonts.inter(
                                  color: Colors.white,
                                  fontSize: 20,
                                  fontWeight: FontWeight.w700,
                                  letterSpacing: -0.5,
                                ),
                              ),
                    ),
                    IconButton(
                      icon: Icon(
                        _isSearching
                            ? Icons.close_rounded
                            : Icons.search_rounded,
                        color:
                            _isSearching ? _CommunityDark.accent : Colors.white,
                        size: 24,
                      ),
                      onPressed: () {
                        setState(() {
                          _isSearching = !_isSearching;
                          if (!_isSearching) {
                            _searchController.clear();
                          }
                        });
                      },
                    ),
                    IconButton(
                      icon: const Icon(
                        Icons.notifications_none_rounded,
                        color: Colors.white,
                        size: 24,
                      ),
                      onPressed: () {
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (context) => const NotificationScreen(),
                          ),
                        );
                      },
                    ),
                  ],
                ),
              ),
              // Segment Filter Tabs
              Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: 16.0,
                  vertical: 6.0,
                ),
                child: SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(
                    children:
                        [
                          {'id': 'All', 'label': '🌟 ទាំងអស់', 'icon': Icons.public_rounded},
                          {'id': 'Announcements', 'label': '📢 ការជូនដំណឹង', 'icon': Icons.campaign_rounded},
                          {'id': 'Knowledge', 'label': '📚 ចំណេះដឹង', 'icon': Icons.menu_book_rounded},
                          {'id': 'Trending', 'label': '🔥 ពេញនិយម', 'icon': Icons.local_fire_department_rounded},
                        ].map((tabMap) {
                          final tabId = tabMap['id'] as String;
                          final label = tabMap['label'] as String;
                          final isSelected = _selectedTab == tabId;
                          return GestureDetector(
                            onTap: () => setState(() => _selectedTab = tabId),
                            child: AnimatedContainer(
                              duration: const Duration(milliseconds: 200),
                              margin: const EdgeInsets.only(right: 10),
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 8,
                              ),
                              decoration: BoxDecoration(
                                gradient: isSelected
                                    ? const LinearGradient(
                                        colors: [Color(0xFF0A84FF), Color(0xFF0066CC)],
                                      )
                                    : null,
                                color: isSelected
                                    ? null
                                    : _CommunityDark.card,
                                borderRadius: BorderRadius.circular(20),
                                border: Border.all(
                                  color: isSelected
                                      ? const Color(0xFF38BDF8)
                                      : const Color(0xFF334155),
                                  width: isSelected ? 1.2 : 0.8,
                                ),
                                boxShadow: isSelected
                                    ? [
                                        BoxShadow(
                                          color: const Color(0xFF0A84FF).withValues(alpha: 0.35),
                                          blurRadius: 8,
                                          offset: const Offset(0, 2),
                                        ),
                                      ]
                                    : null,
                              ),
                              child: Text(
                                label,
                                style: GoogleFonts.kantumruyPro(
                                  color: isSelected
                                      ? Colors.white
                                      : Colors.white70,
                                  fontWeight: isSelected
                                      ? FontWeight.w700
                                      : FontWeight.w500,
                                  fontSize: 13.0,
                                ),
                              ),
                            ),
                          );
                        }).toList(),
                  ),
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
          label: Text(
            'Create Post',
            style: GoogleFonts.inter(
              color: Colors.white,
              fontWeight: FontWeight.w600,
              fontSize: 15,
            ),
          ),
        ),
      ),
      body: StreamBuilder<QuerySnapshot>(
        stream: _postsStream,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting &&
              !snapshot.hasData) {
            return const Center(
              child: CircularProgressIndicator(color: _CommunityDark.accent),
            );
          }

          var posts =
              snapshot.hasData
                  ? List<DocumentSnapshot>.from(snapshot.data!.docs)
                  : <DocumentSnapshot>[];

          // 1. Search Query Filter
          final query = _searchController.text.trim().toLowerCase();
          if (query.isNotEmpty) {
            posts =
                posts.where((doc) {
                  final data = doc.data() as Map<String, dynamic>;
                  final content =
                      (data['content'] ?? '').toString().toLowerCase();
                  final authorName =
                      (data['authorName'] ?? '').toString().toLowerCase();
                  final roleTag =
                      (data['roleTag'] ?? '').toString().toLowerCase();
                  return content.contains(query) ||
                      authorName.contains(query) ||
                      roleTag.contains(query);
                }).toList();
          }

          // 2. Tab Category Filter & Sorting
          if (_selectedTab == 'Announcements') {
            posts =
                posts.where((doc) {
                  final data = doc.data() as Map<String, dynamic>;
                  final roleTag =
                      (data['roleTag'] ?? '').toString().toLowerCase();
                  return data['isAnnouncement'] == true ||
                      roleTag.contains('announcement') ||
                      roleTag.contains('official') ||
                      roleTag.contains('admin') ||
                      roleTag.contains('hrm');
                }).toList();
          } else if (_selectedTab == 'Knowledge') {
            posts =
                posts.where((doc) {
                  final data = doc.data() as Map<String, dynamic>;
                  final roleTag =
                      (data['roleTag'] ?? '').toString().toLowerCase();
                  return data['isKnowledge'] == true ||
                      roleTag.contains('ចំណេះដឹង') ||
                      roleTag.contains('knowledge') ||
                      roleTag.contains('tips') ||
                      roleTag.contains('ជំនាញ');
                }).toList();
          } else if (_selectedTab == 'Trending') {
            // Sort by total engagement (likes + comments) descending
            posts.sort((a, b) {
              final aData = a.data() as Map<String, dynamic>;
              final bData = b.data() as Map<String, dynamic>;
              final aReactions =
                  (aData['reactionsMap'] as Map?)?.length ??
                  (aData['likes'] as List?)?.length ??
                  0;
              final bReactions =
                  (bData['reactionsMap'] as Map?)?.length ??
                  (bData['likes'] as List?)?.length ??
                  0;
              final aComments = (aData['commentsCount'] as num?)?.toInt() ?? 0;
              final bComments = (bData['commentsCount'] as num?)?.toInt() ?? 0;
              final aScore = aReactions + aComments;
              final bScore = bReactions + bComments;
              return bScore.compareTo(aScore);
            });
          }

          return CustomScrollView(
            slivers: [
              // Create Post Input Card
              SliverToBoxAdapter(
                child: GestureDetector(
                  onTap: () => _showCreatePostModal(userProvider),
                  child: Container(
                    margin: const EdgeInsets.fromLTRB(16, 12, 16, 8),
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: _CommunityDark.card,
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(
                        color: const Color(0xFF334155),
                        width: 0.8,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.15),
                          blurRadius: 10,
                          offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    child: Row(
                      children: [
                        CircleAvatar(
                          radius: 20,
                          backgroundColor: _CommunityDark.accent.withValues(
                            alpha: 0.2,
                          ),
                          backgroundImage:
                              (userProvider.avatar?.isNotEmpty ?? false)
                                  ? NetworkImage(
                                    ApiService.getFullImageUrl(
                                      userProvider.avatar!,
                                    ),
                                  )
                                  : null,
                          child:
                              (userProvider.avatar?.isEmpty ?? true)
                                  ? Text(
                                    (userProvider.name?.isNotEmpty ?? false)
                                        ? userProvider.name![0].toUpperCase()
                                        : 'U',
                                    style: GoogleFonts.inter(
                                      color: _CommunityDark.accent,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  )
                                  : null,
                        ),
                        const SizedBox(width: 14),
                        Expanded(
                          child: Text(
                            "តើអ្នកកំពុងគិតអ្វី? ចែករំលែកនៅទីនេះ...",
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white54,
                              fontSize: 13.5,
                            ),
                          ),
                        ),
                        Container(
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: _CommunityDark.success.withValues(alpha: 0.12),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: const Icon(
                            Icons.image_rounded,
                            color: _CommunityDark.success,
                            size: 20,
                          ),
                        ),
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
                        const Icon(
                          Icons.campaign_rounded,
                          size: 64,
                          color: Colors.white38,
                        ),
                        const SizedBox(height: 12),
                        Text(
                          'មិនទាន់មានការប្រកាសព័ត៌មាននៅឡើយទេ',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white54,
                            fontSize: 15,
                          ),
                        ),
                      ],
                    ),
                  ),
                )
              else
                // Feed Posts
                SliverList(
                  delegate: SliverChildBuilderDelegate((context, index) {
                    final doc = posts[index];
                    final data = doc.data() as Map<String, dynamic>;

                    final String authorId = data['authorId'] ?? '';
                    final String authorName =
                        data['authorName'] ?? 'VVC Official';
                    final String authorAvatar = data['authorAvatar'] ?? '';
                    final String roleTag =
                        data['roleTag'] ?? 'Official Announcement';
                    final String content = data['content'] ?? '';
                    final Map<String, dynamic> reactionsMap =
                        data['reactionsMap'] as Map<String, dynamic>? ?? {};
                    final List<dynamic> legacyLikes = data['likes'] ?? [];
                    final int commentsCount =
                        (data['commentsCount'] as num?)?.toInt() ?? 0;
                    final Timestamp? ts = data['createdAt'] as Timestamp?;
                    final String timeStr =
                        ts != null
                            ? DateFormat('MMM dd, HH:mm').format(ts.toDate())
                            : 'Just now';

                    final String myId = userProvider.employeeId ?? '';
                    final bool isMyPost =
                        authorId == myId ||
                        myId == 'super_admin' ||
                        myId == 'admin';

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

                    final List<dynamic> viewedBy = (data['viewedBy'] as List<dynamic>?) ?? [];
                    if (myId.isNotEmpty && !viewedBy.contains(myId)) {
                      doc.reference.update({
                        'viewedBy': FieldValue.arrayUnion([myId]),
                      }).catchError((_) {});
                    }

                    return Container(
                      margin: const EdgeInsets.fromLTRB(16, 8, 16, 12),
                      padding: const EdgeInsets.all(20),
                      decoration: BoxDecoration(
                        color: _CommunityDark.card,
                        borderRadius: BorderRadius.circular(24),
                        border: Border.all(
                          color: const Color(0xFF334155),
                          width: 0.8,
                        ),
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
                                backgroundImage:
                                    authorAvatar.isNotEmpty
                                        ? NetworkImage(
                                          ApiService.getFullImageUrl(
                                            authorAvatar,
                                          ),
                                        )
                                        : null,
                                backgroundColor: _CommunityDark.accent
                                    .withValues(alpha: 0.2),
                                child:
                                    authorAvatar.isEmpty
                                        ? Text(
                                          authorName[0].toUpperCase(),
                                          style: GoogleFonts.inter(
                                            color: _CommunityDark.accent,
                                            fontWeight: FontWeight.bold,
                                            fontSize: 18,
                                          ),
                                        )
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
                                        const Icon(
                                          Icons.verified_rounded,
                                          color: _CommunityDark.accent,
                                          size: 16,
                                        ),
                                      ],
                                    ),
                                    const SizedBox(height: 2),
                                    Row(
                                      children: [
                                        Builder(
                                          builder: (context) {
                                            Color badgeBg = _CommunityDark.accent.withValues(alpha: 0.15);
                                            Color badgeText = _CommunityDark.accent;
                                            String displayTag = roleTag.isNotEmpty ? roleTag : '📢 ការជូនដំណឹង';

                                            if (roleTag.contains('ចំណេះដឹង') || roleTag.contains('Knowledge') || roleTag.contains('Tips')) {
                                              badgeBg = const Color(0xFF10B981).withValues(alpha: 0.15);
                                              badgeText = const Color(0xFF34D399);
                                              displayTag = '📚 ចំណេះដឹង & Tips';
                                            } else if (roleTag.contains('Trending') || roleTag.contains('ព័ត៌មានទូទៅ')) {
                                              badgeBg = const Color(0xFFF97316).withValues(alpha: 0.15);
                                              badgeText = const Color(0xFFFB923C);
                                              displayTag = '🔥 ព័ត៌មានទូទៅ';
                                            } else {
                                              displayTag = '📢 ការជូនដំណឹង';
                                            }

                                            return Container(
                                              padding: const EdgeInsets.symmetric(
                                                horizontal: 7,
                                                vertical: 2.5,
                                              ),
                                              decoration: BoxDecoration(
                                                color: badgeBg,
                                                borderRadius: BorderRadius.circular(6),
                                              ),
                                              child: Text(
                                                displayTag,
                                                style: GoogleFonts.kantumruyPro(
                                                  color: badgeText,
                                                  fontSize: 10.5,
                                                  fontWeight: FontWeight.w600,
                                                ),
                                              ),
                                            );
                                          },
                                        ),
                                        const SizedBox(width: 6),
                                        Text(
                                          '•  $timeStr',
                                          style: GoogleFonts.inter(
                                            color: Colors.white54,
                                            fontSize: 11.5,
                                          ),
                                        ),
                                        if (viewedBy.isNotEmpty) ...[
                                          const SizedBox(width: 6),
                                          Text(
                                            '•  👁️ ${viewedBy.length}',
                                            style: GoogleFonts.inter(
                                              color: Colors.white54,
                                              fontSize: 11.5,
                                            ),
                                          ),
                                        ],
                                      ],
                                    ),
                                  ],
                                ),
                              ),
                              if (isMyPost)
                                PopupMenuButton<String>(
                                  icon: const Icon(
                                    Icons.more_horiz_rounded,
                                    color: Colors.white54,
                                  ),
                                  color: const Color(0xFF0F172A),
                                  shape: RoundedRectangleBorder(
                                    borderRadius: BorderRadius.circular(16),
                                  ),
                                  onSelected: (val) {
                                    if (val == 'edit') {
                                      _showEditPostModal(doc);
                                    } else if (val == 'delete') {
                                      _confirmDeletePost(doc);
                                    } else if (val == 'remind') {
                                      _sendUnreadReminder(doc);
                                    }
                                  },
                                  itemBuilder:
                                      (context) => [
                                        PopupMenuItem(
                                          value: 'remind',
                                          child: Row(
                                            children: [
                                              const Icon(
                                                Icons.notifications_active_rounded,
                                                color: Color(0xFFFFCC00),
                                                size: 18,
                                              ),
                                              const SizedBox(width: 10),
                                              Text(
                                                'រំលឹកអ្នកមិនទាន់មើល',
                                                style: GoogleFonts.kantumruyPro(
                                                  color: const Color(0xFFFFCC00),
                                                  fontSize: 13.5,
                                                  fontWeight: FontWeight.w600,
                                                ),
                                              ),
                                            ],
                                          ),
                                        ),
                                        PopupMenuItem(
                                          value: 'edit',
                                          child: Row(
                                            children: [
                                              const Icon(
                                                Icons.edit_rounded,
                                                color: Colors.white,
                                                size: 18,
                                              ),
                                              const SizedBox(width: 10),
                                              Text(
                                                'កែប្រែ Post',
                                                style: GoogleFonts.kantumruyPro(
                                                  color: Colors.white,
                                                  fontSize: 13.5,
                                                ),
                                              ),
                                            ],
                                          ),
                                        ),
                                        PopupMenuItem(
                                          value: 'delete',
                                          child: Row(
                                            children: [
                                              const Icon(
                                                Icons.delete_forever_rounded,
                                                color: Colors.redAccent,
                                                size: 18,
                                              ),
                                              const SizedBox(width: 10),
                                              Text(
                                                'លុប Post',
                                                style: GoogleFonts.kantumruyPro(
                                                  color: Colors.redAccent,
                                                  fontSize: 13.5,
                                                ),
                                              ),
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

                          // Media (Multi-Image Collage Grid & PDF Attachments)
                          _buildPostMediaGroup(data),

                          const SizedBox(height: 16),
                          // Engagement Metrics
                          if (totalReactions > 0 || commentsCount > 0)
                            Padding(
                              padding: const EdgeInsets.only(bottom: 12),
                              child: Row(
                                children: [
                                  if (totalReactions > 0) ...[
                                    Row(
                                      children:
                                          reactionCounts.keys.take(3).map((
                                            rKey,
                                          ) {
                                            final emoji =
                                                _reactions[rKey]?['emoji'] ??
                                                '👍';
                                            return Padding(
                                              padding: const EdgeInsets.only(
                                                right: 2.0,
                                              ),
                                              child: Text(
                                                emoji,
                                                style: const TextStyle(
                                                  fontSize: 14,
                                                ),
                                              ),
                                            );
                                          }).toList(),
                                    ),
                                    const SizedBox(width: 6),
                                    Text(
                                      '$totalReactions',
                                      style: GoogleFonts.inter(
                                        color: Colors.white70,
                                        fontSize: 13,
                                        fontWeight: FontWeight.w500,
                                      ),
                                    ),
                                  ],
                                  const Spacer(),
                                  if (commentsCount > 0)
                                    Text(
                                      '$commentsCount Comments',
                                      style: GoogleFonts.inter(
                                        color: Colors.white54,
                                        fontSize: 13,
                                        fontWeight: FontWeight.w500,
                                      ),
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
                                  final Map<String, dynamic> updatedMap =
                                      Map.from(reactionsMap);
                                  if (userReactionKey.isNotEmpty) {
                                    updatedMap.remove(myId);
                                  } else {
                                    updatedMap[myId] = 'like';
                                  }
                                  await doc.reference.update({
                                    'reactionsMap': updatedMap,
                                  });
                                },
                                onLongPress:
                                    () => _showReactionPicker(
                                      context,
                                      doc.reference,
                                      myId,
                                      reactionsMap,
                                    ),
                                child: Container(
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 12,
                                    vertical: 8,
                                  ),
                                  child: Row(
                                    children: [
                                      Text(
                                        userReactionKey.isNotEmpty
                                            ? (_reactions[userReactionKey]?['emoji'] ??
                                                '👍')
                                            : '👍',
                                        style: TextStyle(
                                          fontSize:
                                              userReactionKey.isNotEmpty
                                                  ? 18
                                                  : 16,
                                        ),
                                      ),
                                      const SizedBox(width: 8),
                                      Text(
                                        userReactionKey.isNotEmpty
                                            ? (_reactions[userReactionKey]?['label'] ??
                                                'Like')
                                            : 'Like',
                                        style: GoogleFonts.inter(
                                          color:
                                              userReactionKey.isNotEmpty
                                                  ? (_reactions[userReactionKey]?['color']
                                                          as Color? ??
                                                      _CommunityDark.accent)
                                                  : Colors.white60,
                                          fontSize: 14,
                                          fontWeight:
                                              userReactionKey.isNotEmpty
                                                  ? FontWeight.bold
                                                  : FontWeight.w500,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),

                              // Comment
                              InkWell(
                                onTap:
                                    () => _showCommentsSheet(doc, userProvider),
                                borderRadius: BorderRadius.circular(12),
                                child: Padding(
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 12,
                                    vertical: 8,
                                  ),
                                  child: Row(
                                    children: [
                                      const Icon(
                                        Icons.mode_comment_outlined,
                                        color: Colors.white60,
                                        size: 20,
                                      ),
                                      const SizedBox(width: 8),
                                      Text(
                                        'Comment',
                                        style: GoogleFonts.inter(
                                          color: Colors.white60,
                                          fontSize: 14,
                                          fontWeight: FontWeight.w500,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),

                              // Share
                              InkWell(
                                onTap: () {
                                  Clipboard.setData(
                                    ClipboardData(text: content),
                                  );
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    SnackBar(
                                      content: Text(
                                        'បានចម្លងអត្ថបទ Post!',
                                        style: GoogleFonts.kantumruyPro(),
                                      ),
                                      backgroundColor: _CommunityDark.accent,
                                    ),
                                  );
                                },
                                borderRadius: BorderRadius.circular(12),
                                child: Padding(
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 12,
                                    vertical: 8,
                                  ),
                                  child: Row(
                                    children: [
                                      const Icon(
                                        Icons.ios_share_rounded,
                                        color: Colors.white60,
                                        size: 20,
                                      ),
                                      const SizedBox(width: 8),
                                      Text(
                                        'Share',
                                        style: GoogleFonts.inter(
                                          color: Colors.white60,
                                          fontSize: 14,
                                          fontWeight: FontWeight.w500,
                                        ),
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
                  }, childCount: posts.length),
                ),
              const SliverToBoxAdapter(
                child: SizedBox(height: 80),
              ), // Padding for FAB
            ],
          );
        },
      ),
    );
  }
}
