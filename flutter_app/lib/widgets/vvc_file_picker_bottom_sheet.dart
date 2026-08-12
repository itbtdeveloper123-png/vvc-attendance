import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:intl/intl.dart';

/// Reusable VVC Dark Theme "File" Attachment Modal Bottom Sheet Component
class VvcFilePickerBottomSheet extends StatefulWidget {
  final String? roomId;
  final VoidCallback? onSelectFromGallery;
  final VoidCallback? onSelectFromFiles;
  final VoidCallback? onScanDocument;
  final Function(Map<String, dynamic> file)? onSelectRecentFile;
  final Function(String category)? onTabChanged;

  const VvcFilePickerBottomSheet({
    super.key,
    this.roomId,
    this.onSelectFromGallery,
    this.onSelectFromFiles,
    this.onScanDocument,
    this.onSelectRecentFile,
    this.onTabChanged,
  });

  static Future<T?> show<T>({
    required BuildContext context,
    String? roomId,
    VoidCallback? onSelectFromGallery,
    VoidCallback? onSelectFromFiles,
    VoidCallback? onScanDocument,
    Function(Map<String, dynamic> file)? onSelectRecentFile,
    Function(String category)? onTabChanged,
  }) {
    return showModalBottomSheet<T>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => VvcFilePickerBottomSheet(
        roomId: roomId,
        onSelectFromGallery: onSelectFromGallery,
        onSelectFromFiles: onSelectFromFiles,
        onScanDocument: onScanDocument,
        onSelectRecentFile: onSelectRecentFile,
        onTabChanged: onTabChanged,
      ),
    );
  }

  @override
  State<VvcFilePickerBottomSheet> createState() => _VvcFilePickerBottomSheetState();
}

class _VvcFilePickerBottomSheetState extends State<VvcFilePickerBottomSheet> {
  final TextEditingController _searchController = TextEditingController();
  bool _isSearchActive = false;

  // Theme Colors
  static const Color _bgColor = Color(0xFF1C1C1E);
  static const Color _cardColor = Color(0xFF2C2C2E);
  static const Color _accentColor = Color(0xFF3388FF);
  static const Color _dividerColor = Color(0x1FFFFFFF);
  static const Color _mutedColor = Color(0xFF8E8E93);

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final double maxSheetHeight = MediaQuery.of(context).size.height * 0.85;

    return Container(
      constraints: BoxConstraints(maxHeight: maxSheetHeight),
      decoration: const BoxDecoration(
        color: _bgColor,
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Drag Handle Bar
          const SizedBox(height: 10),
          Center(
            child: Container(
              width: 36,
              height: 4.5,
              decoration: BoxDecoration(
                color: const Color(0xFF48484A),
                borderRadius: BorderRadius.circular(2.5),
              ),
            ),
          ),
          const SizedBox(height: 8),

          // Header Section
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 4.0),
            child: _isSearchActive ? _buildSearchBar() : _buildHeaderRow(),
          ),
          const SizedBox(height: 12),

          // Scrollable Content
          Expanded(
            child: SingleChildScrollView(
              physics: const BouncingScrollPhysics(),
              padding: const EdgeInsets.symmetric(horizontal: 16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildActionCard(),
                  const SizedBox(height: 24),

                  Text(
                    'RECENTLY SENT FILES',
                    style: GoogleFonts.inter(
                      color: _mutedColor,
                      fontSize: 12.0,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 0.5,
                    ),
                  ),
                  const SizedBox(height: 8),

                  _buildRecentFilesCard(),
                  const SizedBox(height: 20),
                ],
              ),
            ),
          ),

          _buildBottomNavBar(),
        ],
      ),
    );
  }

  Widget _buildHeaderRow() {
    return SizedBox(
      height: 40,
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          IconButton(
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
            icon: const Icon(Icons.close_rounded, color: Colors.white, size: 24),
            onPressed: () => Navigator.pop(context),
          ),
          Text(
            'File',
            style: GoogleFonts.inter(
              color: Colors.white,
              fontSize: 17,
              fontWeight: FontWeight.bold,
            ),
          ),
          IconButton(
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
            icon: const Icon(Icons.search_rounded, color: Colors.white, size: 24),
            onPressed: () {
              setState(() {
                _isSearchActive = true;
              });
            },
          ),
        ],
      ),
    );
  }

  Widget _buildSearchBar() {
    return Container(
      height: 38,
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(10),
      ),
      padding: const EdgeInsets.symmetric(horizontal: 10),
      child: Row(
        children: [
          const Icon(Icons.search_rounded, color: _mutedColor, size: 20),
          const SizedBox(width: 8),
          Expanded(
            child: TextField(
              controller: _searchController,
              autofocus: true,
              style: GoogleFonts.inter(color: Colors.white, fontSize: 14),
              cursorColor: _accentColor,
              decoration: InputDecoration(
                hintText: 'Search files',
                hintStyle: GoogleFonts.inter(color: _mutedColor, fontSize: 14),
                border: InputBorder.none,
                isDense: true,
              ),
              onChanged: (_) => setState(() {}),
            ),
          ),
          InkWell(
            onTap: () {
              _searchController.clear();
              setState(() {
                _isSearchActive = false;
              });
            },
            child: const Icon(Icons.cancel_rounded, color: _mutedColor, size: 18),
          ),
        ],
      ),
    );
  }

  Widget _buildActionCard() {
    return Container(
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          _buildActionTile(
            icon: Icons.photo_library_rounded,
            title: 'Select from Gallery',
            onTap: () {
              Navigator.pop(context);
              widget.onSelectFromGallery?.call();
            },
          ),
          const Divider(height: 1, color: _dividerColor, indent: 52),
          _buildActionTile(
            icon: Icons.cloud_upload_rounded,
            title: 'Select from Files',
            onTap: () {
              Navigator.pop(context);
              widget.onSelectFromFiles?.call();
            },
          ),
          const Divider(height: 1, color: _dividerColor, indent: 52),
          _buildActionTile(
            icon: Icons.document_scanner_rounded,
            title: 'Scan Document',
            onTap: () {
              Navigator.pop(context);
              widget.onScanDocument?.call();
            },
          ),
        ],
      ),
    );
  }

  Widget _buildActionTile({
    required IconData icon,
    required String title,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 14.0),
        child: Row(
          children: [
            Icon(icon, color: _accentColor, size: 24),
            const SizedBox(width: 14),
            Text(
              title,
              style: GoogleFonts.inter(
                color: Colors.white,
                fontSize: 16,
                fontWeight: FontWeight.w400,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildRecentFilesCard() {
    if (widget.roomId == null || widget.roomId!.isEmpty) {
      return _buildEmptyState();
    }

    return StreamBuilder<QuerySnapshot>(
      stream: FirebaseFirestore.instance
          .collection('chats')
          .doc(widget.roomId)
          .collection('messages')
          .where('type', isEqualTo: 'file')
          .orderBy('timestamp', descending: true)
          .limit(10)
          .snapshots(),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return Container(
            width: double.infinity,
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: _cardColor,
              borderRadius: BorderRadius.circular(16),
            ),
            child: const Center(
              child: SizedBox(
                width: 24,
                height: 24,
                child: CircularProgressIndicator(strokeWidth: 2, color: _accentColor),
              ),
            ),
          );
        }

        final docs = snapshot.data?.docs ?? [];
        final List<Map<String, dynamic>> fileList = [];

        for (final doc in docs) {
          final data = doc.data() as Map<String, dynamic>;
          final fileName = (data['fileName'] ?? data['text'] ?? 'Document').toString().replaceAll('📄 ឯកសារ៖ ', '');
          final fileSize = (data['fileSize'] ?? '').toString();
          final ts = data['timestamp'] as Timestamp?;
          final dateStr = ts != null ? DateFormat('dd MMM at HH:mm').format(ts.toDate()) : 'Recently';

          String ext = 'FILE';
          Color extColor = const Color(0xFFBF5AF2);

          final nameLower = fileName.toLowerCase();
          if (nameLower.endsWith('.pdf')) {
            ext = 'PDF';
            extColor = const Color(0xFFFF453A);
          } else if (nameLower.endsWith('.zip') || nameLower.endsWith('.rar') || nameLower.endsWith('.7z')) {
            ext = 'ZIP';
            extColor = const Color(0xFFFF9F0A);
          } else if (nameLower.endsWith('.xlsx') || nameLower.endsWith('.xls') || nameLower.endsWith('.csv')) {
            ext = 'XLS';
            extColor = const Color(0xFF30D158);
          } else if (nameLower.endsWith('.docx') || nameLower.endsWith('.doc')) {
            ext = 'DOC';
            extColor = const Color(0xFF0A84FF);
          } else if (nameLower.endsWith('.png') || nameLower.endsWith('.jpg') || nameLower.endsWith('.jpeg')) {
            ext = 'IMG';
            extColor = const Color(0xFF64D2FF);
          }

          fileList.add({
            'name': fileName,
            'extension': ext,
            'color': extColor,
            'size': fileSize.isNotEmpty ? fileSize : 'Document',
            'date': dateStr,
            'raw': data,
          });
        }

        final filtered = fileList.where((f) {
          if (_searchController.text.isEmpty) return true;
          return f['name'].toString().toLowerCase().contains(_searchController.text.toLowerCase());
        }).toList();

        if (filtered.isEmpty) {
          return _buildEmptyState();
        }

        return Container(
          decoration: BoxDecoration(
            color: _cardColor,
            borderRadius: BorderRadius.circular(16),
          ),
          child: ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: filtered.length,
            separatorBuilder: (context, index) => const Divider(
              height: 1,
              color: _dividerColor,
              indent: 62,
            ),
            itemBuilder: (context, index) {
              final file = filtered[index];
              return InkWell(
                onTap: () {
                  Navigator.pop(context);
                  widget.onSelectRecentFile?.call(file);
                },
                borderRadius: BorderRadius.circular(16),
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 11.0),
                  child: Row(
                    children: [
                      Container(
                        width: 40,
                        height: 40,
                        decoration: BoxDecoration(
                          color: file['color'] as Color,
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Center(
                          child: Text(
                            file['extension'].toString(),
                            style: GoogleFonts.inter(
                              color: Colors.white,
                              fontSize: 11.5,
                              fontWeight: FontWeight.w800,
                              letterSpacing: 0.5,
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              file['name'].toString(),
                              style: GoogleFonts.inter(
                                color: Colors.white,
                                fontSize: 15,
                                fontWeight: FontWeight.w500,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                            const SizedBox(height: 2),
                            Text(
                              '${file['size']} • ${file['date']}',
                              style: GoogleFonts.inter(
                                color: _mutedColor,
                                fontSize: 12.5,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              );
            },
          ),
        );
      },
    );
  }

  Widget _buildEmptyState() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          const Icon(Icons.insert_drive_file_outlined, color: _mutedColor, size: 36),
          const SizedBox(height: 8),
          Text(
            'មិនទាន់មានប្រវត្តិផ្ញើឯកសារទេ (No recently sent files)',
            style: GoogleFonts.kantumruyPro(color: _mutedColor, fontSize: 13),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildBottomNavBar() {
    final categories = [
      {'label': 'Gallery', 'icon': Icons.photo_library_outlined, 'selectedIcon': Icons.photo_library_rounded},
      {'label': 'File', 'icon': Icons.insert_drive_file_outlined, 'selectedIcon': Icons.insert_drive_file_rounded},
      {'label': 'Location', 'icon': Icons.location_on_outlined, 'selectedIcon': Icons.location_on_rounded},
      {'label': 'Poll', 'icon': Icons.poll_outlined, 'selectedIcon': Icons.poll_rounded},
      {'label': 'Contact', 'icon': Icons.person_outline_rounded, 'selectedIcon': Icons.person_rounded},
    ];

    return Container(
      decoration: const BoxDecoration(
        color: Color(0xFF141416),
        border: Border(top: BorderSide(color: Color(0x1AFFFFFF), width: 0.5)),
      ),
      padding: EdgeInsets.only(
        top: 8,
        bottom: MediaQuery.of(context).padding.bottom > 0
            ? MediaQuery.of(context).padding.bottom + 4
            : 10,
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: categories.map((cat) {
          final String label = cat['label'] as String;
          final bool isSelected = label == 'File';

          return InkWell(
            onTap: () {
              if (label != 'File') {
                widget.onTabChanged?.call(label);
              }
            },
            borderRadius: BorderRadius.circular(16),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    padding: const EdgeInsets.all(6),
                    decoration: BoxDecoration(
                      color: isSelected ? _accentColor.withValues(alpha: 0.2) : Colors.transparent,
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      isSelected ? (cat['selectedIcon'] as IconData) : (cat['icon'] as IconData),
                      color: isSelected ? _accentColor : _mutedColor,
                      size: 22,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    label,
                    style: GoogleFonts.inter(
                      color: isSelected ? _accentColor : _mutedColor,
                      fontSize: 11,
                      fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                    ),
                  ),
                ],
              ),
            ),
          );
        }).toList(),
      ),
    );
  }
}
