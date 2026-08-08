import 'dart:io';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:path_provider/path_provider.dart';
import 'package:path/path.dart' as path;
import '../services/isar_service.dart';
import '../widgets/app_widgets.dart';

class StorageCategory {
  final String id;
  final String name;
  final String nameKh;
  final Color color;
  final IconData icon;
  int sizeInBytes;
  bool isSelected;

  StorageCategory({
    required this.id,
    required this.name,
    required this.nameKh,
    required this.color,
    required this.icon,
    this.sizeInBytes = 0,
    this.isSelected = true,
  });
}

class StorageUsageScreen extends StatefulWidget {
  const StorageUsageScreen({super.key});

  @override
  State<StorageUsageScreen> createState() => _StorageUsageScreenState();
}

class _StorageUsageScreenState extends State<StorageUsageScreen> {
  bool _isCalculating = true;
  bool _isClearing = false;

  late List<StorageCategory> _categories;

  @override
  void initState() {
    super.initState();
    _initCategories();
    _calculateStorageUsage();
  }

  void _initCategories() {
    _categories = [
      StorageCategory(
        id: 'misc',
        name: 'Misc & Cache',
        nameKh: 'ទិន្នន័យផ្សេងៗ & Cache',
        color: const Color(0xFFFF9500), // Orange
        icon: Icons.folder_zip_rounded,
      ),
      StorageCategory(
        id: 'videos',
        name: 'Videos',
        nameKh: 'វីដេអូ (Videos)',
        color: const Color(0xFF007AFF), // Blue
        icon: Icons.videocam_rounded,
      ),
      StorageCategory(
        id: 'photos',
        name: 'Photos & Media',
        nameKh: 'រូបភាព (Photos)',
        color: const Color(0xFF30B0C7), // Light Cyan/Blue
        icon: Icons.photo_library_rounded,
      ),
      StorageCategory(
        id: 'files',
        name: 'Files & Documents',
        nameKh: 'ឯកសារ (Files)',
        color: const Color(0xFF34C759), // Green
        icon: Icons.insert_drive_file_rounded,
      ),
      StorageCategory(
        id: 'database',
        name: 'Local DB (Isar)',
        nameKh: 'ទិន្នន័យ Local DB',
        color: const Color(0xFFAF52DE), // Purple
        icon: Icons.dns_rounded,
      ),
    ];
  }

  Future<void> _calculateStorageUsage() async {
    setState(() {
      _isCalculating = true;
    });

    int miscSize = 0;
    int videoSize = 0;
    int photoSize = 0;
    int fileSize = 0;
    int dbSize = 0;

    try {
      final docDir = await getApplicationDocumentsDirectory();
      final tempDir = await getTemporaryDirectory();

      List<FileSystemEntity> allFiles = [];

      if (docDir.existsSync()) {
        allFiles.addAll(docDir.listSync(recursive: true, followLinks: false));
      }
      if (tempDir.existsSync()) {
        allFiles.addAll(tempDir.listSync(recursive: true, followLinks: false));
      }

      for (var entity in allFiles) {
        if (entity is File) {
          try {
            final length = entity.lengthSync();
            final ext = path.extension(entity.path).toLowerCase();

            if (['.mp4', '.mov', '.avi', '.mkv', '.3gp'].contains(ext)) {
              videoSize += length;
            } else if (['.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic'].contains(ext)) {
              photoSize += length;
            } else if (['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.zip', '.rar', '.txt'].contains(ext)) {
              fileSize += length;
            } else if (['.isar', '.lock', '.db', '.sqlite', '.sqlite-wal', '.sqlite-shm'].contains(ext) ||
                entity.path.contains('chat_db')) {
              dbSize += length;
            } else {
              miscSize += length;
            }
          } catch (_) {}
        }
      }
    } catch (e) {
      debugPrint('Error calculating storage size: $e');
    }

    if (mounted) {
      setState(() {
        for (var cat in _categories) {
          if (cat.id == 'misc') cat.sizeInBytes = miscSize;
          if (cat.id == 'videos') cat.sizeInBytes = videoSize;
          if (cat.id == 'photos') cat.sizeInBytes = photoSize;
          if (cat.id == 'files') cat.sizeInBytes = fileSize;
          if (cat.id == 'database') cat.sizeInBytes = dbSize;
        }
        _isCalculating = false;
      });
    }
  }

  int get _selectedTotalBytes {
    int total = 0;
    for (var cat in _categories) {
      if (cat.isSelected) {
        total += cat.sizeInBytes;
      }
    }
    return total;
  }

  int get _allTotalBytes {
    int total = 0;
    for (var cat in _categories) {
      total += cat.sizeInBytes;
    }
    return total;
  }

  String _formatBytes(int bytes) {
    if (bytes <= 0) return '0 B';
    const suffixes = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = (math.log(bytes) / math.log(1024)).floor();
    return '${(bytes / math.pow(1024, i)).toStringAsFixed(1)} ${suffixes[i]}';
  }

  Future<void> _clearSelectedCache() async {
    final bytesToClear = _selectedTotalBytes;
    if (bytesToClear == 0) return;

    setState(() {
      _isClearing = true;
    });

    try {
      final selectedIds = _categories.where((c) => c.isSelected).map((c) => c.id).toSet();

      if (selectedIds.contains('database')) {
        await IsarService().clearAll();
      }

      final docDir = await getApplicationDocumentsDirectory();
      final tempDir = await getTemporaryDirectory();

      List<FileSystemEntity> allFiles = [];
      if (docDir.existsSync()) {
        allFiles.addAll(docDir.listSync(recursive: true, followLinks: false));
      }
      if (tempDir.existsSync()) {
        allFiles.addAll(tempDir.listSync(recursive: true, followLinks: false));
      }

      for (var entity in allFiles) {
        if (entity is File) {
          try {
            final ext = path.extension(entity.path).toLowerCase();
            bool shouldDelete = false;

            if (selectedIds.contains('videos') && ['.mp4', '.mov', '.avi', '.mkv', '.3gp'].contains(ext)) {
              shouldDelete = true;
            } else if (selectedIds.contains('photos') && ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.heic'].contains(ext)) {
              shouldDelete = true;
            } else if (selectedIds.contains('files') && ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.zip', '.rar', '.txt'].contains(ext)) {
              shouldDelete = true;
            } else if (selectedIds.contains('misc') && !['.isar', '.lock', '.db', '.sqlite'].contains(ext) && !entity.path.contains('chat_db')) {
              shouldDelete = true;
            }

            if (shouldDelete) {
              entity.deleteSync();
            }
          } catch (_) {}
        }
      }
    } catch (e) {
      debugPrint('Error clearing cache: $e');
    }

    await _calculateStorageUsage();

    if (mounted) {
      setState(() {
        _isClearing = false;
      });

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'បានសម្អាតទិន្នន័យ Cache ${_formatBytes(bytesToClear)} រួចរាល់!',
            style: GoogleFonts.kantumruyPro(color: Colors.white),
          ),
          backgroundColor: const Color(0xFF34C759),
          behavior: SnackBarBehavior.floating,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final totalBytes = _allTotalBytes;

    return Scaffold(
      backgroundColor: const Color(0xFF111827), // Sleek Dark Theme
      appBar: VvcAppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          'Storage Usage',
          style: GoogleFonts.inter(
            color: Colors.white,
            fontWeight: FontWeight.w600,
            fontSize: 18,
          ),
        ),
        centerTitle: true,
      ),
      body: _isCalculating
          ? const Center(
              child: CircularProgressIndicator(color: Color(0xFF007AFF)),
            )
          : Column(
              children: [
                Expanded(
                  child: ListView(
                    physics: const BouncingScrollPhysics(),
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                    children: [
                      const SizedBox(height: 10),

                      // Donut Chart Container
                      Center(
                        child: SizedBox(
                          width: 220,
                          height: 220,
                          child: Stack(
                            alignment: Alignment.center,
                            children: [
                              CustomPaint(
                                size: const Size(220, 220),
                                painter: _DonutChartPainter(
                                  categories: _categories,
                                  totalBytes: totalBytes,
                                ),
                              ),
                              Column(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Text(
                                    _formatBytes(totalBytes),
                                    style: GoogleFonts.inter(
                                      color: Colors.white,
                                      fontSize: 22,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  Text(
                                    'ទំហំសរុប',
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.white54,
                                      fontSize: 12,
                                    ),
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ),
                      ),

                      const SizedBox(height: 24),

                      // Storage Usage Header
                      Center(
                        child: Text(
                          'ការប្រើប្រាស់ទំហំផ្ទុក (Storage Usage)',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                      const SizedBox(height: 6),
                      Center(
                        child: Text(
                          'VVC HRM ប្រើប្រាស់ ${_formatBytes(totalBytes)} នៃទំហំផ្ទុកលើទូរស័ព្ទរបស់អ្នក',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white54,
                            fontSize: 13,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ),

                      const SizedBox(height: 16),

                      // Linear Progress Bar
                      ClipRRect(
                        borderRadius: BorderRadius.circular(6),
                        child: SizedBox(
                          height: 8,
                          child: Row(
                            children: _categories.map((cat) {
                              final pct = totalBytes > 0 ? (cat.sizeInBytes / totalBytes) : 0.0;
                              if (pct <= 0) return const SizedBox.shrink();
                              return Expanded(
                                flex: (pct * 1000).toInt(),
                                child: Container(color: cat.color),
                              );
                            }).toList(),
                          ),
                        ),
                      ),

                      const SizedBox(height: 28),

                      // Category Breakdown Card
                      Container(
                        decoration: BoxDecoration(
                          color: const Color(0xFF1E293B),
                          borderRadius: BorderRadius.circular(16),
                        ),
                        child: Column(
                          children: _categories.asMap().entries.map((entry) {
                            final idx = entry.key;
                            final cat = entry.value;
                            final pct = totalBytes > 0
                                ? (cat.sizeInBytes / totalBytes * 100)
                                : 0.0;

                            return Column(
                              children: [
                                InkWell(
                                  onTap: () {
                                    setState(() {
                                      cat.isSelected = !cat.isSelected;
                                    });
                                  },
                                  borderRadius: BorderRadius.vertical(
                                    top: idx == 0 ? const Radius.circular(16) : Radius.zero,
                                    bottom: idx == _categories.length - 1
                                        ? const Radius.circular(16)
                                        : Radius.zero,
                                  ),
                                  child: Padding(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 16,
                                      vertical: 14,
                                    ),
                                    child: Row(
                                      children: [
                                        // Custom Round Checkbox / Indicator Dot
                                        Container(
                                          width: 22,
                                          height: 22,
                                          decoration: BoxDecoration(
                                            color: cat.isSelected
                                                ? cat.color
                                                : Colors.transparent,
                                            shape: BoxShape.circle,
                                            border: Border.all(
                                              color: cat.color,
                                              width: 2,
                                            ),
                                          ),
                                          child: cat.isSelected
                                              ? const Icon(
                                                  Icons.check,
                                                  size: 14,
                                                  color: Colors.white,
                                                )
                                              : null,
                                        ),
                                        const SizedBox(width: 14),

                                        // Category Name
                                        Expanded(
                                          child: Column(
                                            crossAxisAlignment: CrossAxisAlignment.start,
                                            children: [
                                              Text(
                                                '${cat.nameKh} ${pct > 0 ? '${pct.toStringAsFixed(1)}%' : ''}',
                                                style: GoogleFonts.kantumruyPro(
                                                  color: Colors.white,
                                                  fontSize: 14.5,
                                                  fontWeight: FontWeight.w500,
                                                ),
                                              ),
                                            ],
                                          ),
                                        ),

                                        // Size in MB
                                        Text(
                                          _formatBytes(cat.sizeInBytes),
                                          style: GoogleFonts.inter(
                                            color: Colors.white70,
                                            fontSize: 14,
                                            fontWeight: FontWeight.w500,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                ),
                                if (idx < _categories.length - 1)
                                  const Divider(
                                    height: 1,
                                    thickness: 1,
                                    color: Color(0xFF334155),
                                    indent: 52,
                                  ),
                              ],
                            );
                          }).toList(),
                        ),
                      ),

                      const SizedBox(height: 20),
                    ],
                  ),
                ),

                // Bottom Clear Button
                Padding(
                  padding: const EdgeInsets.fromLTRB(20, 10, 20, 24),
                  child: SizedBox(
                    width: double.infinity,
                    height: 52,
                    child: ElevatedButton(
                      onPressed: (_selectedTotalBytes > 0 && !_isClearing)
                          ? _clearSelectedCache
                          : null,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF007AFF), // Telegram Blue
                        disabledBackgroundColor: Colors.white12,
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(26),
                        ),
                        elevation: 0,
                      ),
                      child: _isClearing
                          ? const SizedBox(
                              width: 24,
                              height: 24,
                              child: CircularProgressIndicator(
                                color: Colors.white,
                                strokeWidth: 2.5,
                              ),
                            )
                          : Text(
                              _selectedTotalBytes > 0
                                  ? 'សម្អាត Cache ទាំងអស់ ${_formatBytes(_selectedTotalBytes)}'
                                  : 'គ្មាន Cache ត្រូវសម្អាត',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white,
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
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

/// Custom Painter for Donut Chart with multi-color categories
class _DonutChartPainter extends CustomPainter {
  final List<StorageCategory> categories;
  final int totalBytes;

  _DonutChartPainter({
    required this.categories,
    required this.totalBytes,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    const strokeWidth = 32.0;
    final radius = (size.width - strokeWidth) / 2;

    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.butt;

    if (totalBytes <= 0) {
      paint.color = const Color(0xFF334155);
      canvas.drawCircle(center, radius, paint);
      return;
    }

    double startAngle = -math.pi / 2; // Start from top

    for (var cat in categories) {
      if (cat.sizeInBytes <= 0) continue;

      final sweepAngle = (cat.sizeInBytes / totalBytes) * 2 * math.pi;
      paint.color = cat.color;

      canvas.drawArc(
        Rect.fromCircle(center: center, radius: radius),
        startAngle,
        sweepAngle,
        false,
        paint,
      );

      startAngle += sweepAngle;
    }
  }

  @override
  bool shouldRepaint(covariant _DonutChartPainter oldDelegate) {
    return oldDelegate.totalBytes != totalBytes || oldDelegate.categories != categories;
  }
}
