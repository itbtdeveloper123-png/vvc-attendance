import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:shared_preferences/shared_preferences.dart';

// ==========================================
// CHAT WALLPAPER MANAGER & SELECTION SHEET
// ==========================================
class ChatWallpaperItem {
  final String id;
  final String title;
  final String assetPath;

  const ChatWallpaperItem({
    required this.id,
    required this.title,
    required this.assetPath,
  });
}

class ChatWallpaperManager {
  static const List<ChatWallpaperItem> wallpapers = [
    ChatWallpaperItem(id: 'default', title: 'Default Dark', assetPath: ''),
    ChatWallpaperItem(id: '01', title: 'Wallpaper 1', assetPath: 'assets/wallpapers/01.jpg'),
    ChatWallpaperItem(id: '02', title: 'Wallpaper 2', assetPath: 'assets/wallpapers/02.jpg'),
    ChatWallpaperItem(id: '03', title: 'Wallpaper 3', assetPath: 'assets/wallpapers/03.jpg'),
    ChatWallpaperItem(id: '04', title: 'Wallpaper 4', assetPath: 'assets/wallpapers/04.jpg'),
    ChatWallpaperItem(id: '05', title: 'Wallpaper 5', assetPath: 'assets/wallpapers/05.jpg'),
  ];

  static Future<String> getWallpaper(String targetId) async {
    final prefs = await SharedPreferences.getInstance();
    final specific = prefs.getString('chat_wallpaper_$targetId');
    if (specific != null && specific.isNotEmpty) return specific;
    return prefs.getString('chat_wallpaper_global') ?? '';
  }

  static Future<void> setWallpaper(String targetId, String path, {bool isGlobal = false}) async {
    final prefs = await SharedPreferences.getInstance();
    if (isGlobal) {
      await prefs.setString('chat_wallpaper_global', path);
    } else {
      await prefs.setString('chat_wallpaper_$targetId', path);
    }
  }
}

Future<void> showChatWallpaperPicker(
  BuildContext context, {
  required String targetId,
  required String targetName,
  required Function(String newPath) onWallpaperSelected,
}) async {
  final currentPath = await ChatWallpaperManager.getWallpaper(targetId);

  if (!context.mounted) return;

  await showModalBottomSheet(
    context: context,
    backgroundColor: Colors.transparent,
    isScrollControlled: true,
    builder: (ctx) {
      return _WallpaperPickerSheet(
        targetId: targetId,
        targetName: targetName,
        currentPath: currentPath,
        onWallpaperSelected: onWallpaperSelected,
      );
    },
  );
}

class _WallpaperPickerSheet extends StatefulWidget {
  final String targetId;
  final String targetName;
  final String currentPath;
  final Function(String newPath) onWallpaperSelected;

  const _WallpaperPickerSheet({
    required this.targetId,
    required this.targetName,
    required this.currentPath,
    required this.onWallpaperSelected,
  });

  @override
  State<_WallpaperPickerSheet> createState() => _WallpaperPickerSheetState();
}

class _WallpaperPickerSheetState extends State<_WallpaperPickerSheet> {
  late String _selectedPath;
  bool _applyToAll = false;

  @override
  void initState() {
    super.initState();
    _selectedPath = widget.currentPath;
  }

  Future<void> _saveTheme() async {
    await ChatWallpaperManager.setWallpaper(
      widget.targetId,
      _selectedPath,
      isGlobal: _applyToAll,
    );
    widget.onWallpaperSelected(_selectedPath);
    if (mounted) {
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'បានប្តូរ Wallpaper Theme រួចរាល់!',
            style: GoogleFonts.kantumruyPro(color: Colors.white),
          ),
          backgroundColor: const Color(0xFF0084FF),
          duration: const Duration(seconds: 2),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        color: Color(0xFF1C1C1E),
        borderRadius: BorderRadius.vertical(top: Radius.circular(24.0)),
      ),
      padding: const EdgeInsets.fromLTRB(16.0, 12.0, 16.0, 24.0),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Drag handle
          Center(
            child: Container(
              width: 38.0,
              height: 4.5,
              decoration: BoxDecoration(
                color: Colors.white30,
                borderRadius: BorderRadius.circular(3.0),
              ),
            ),
          ),
          const SizedBox(height: 16.0),

          // Sheet Title
          Row(
            children: [
              const Icon(Icons.wallpaper_rounded, color: Color(0xFF0084FF), size: 24.0),
              const SizedBox(width: 10.0),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'ប្តូរប្រធានបទសារ (Chat Theme)',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontSize: 17.0,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    Text(
                      'សម្រាប់៖ ${widget.targetName}',
                      style: GoogleFonts.kantumruyPro(
                        color: const Color(0xFFB0B3B8),
                        fontSize: 13.0,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 18.0),

          // Wallpaper Grid Options
          SizedBox(
            height: 150.0,
            child: ListView.builder(
              scrollDirection: Axis.horizontal,
              physics: const BouncingScrollPhysics(),
              itemCount: ChatWallpaperManager.wallpapers.length,
              itemBuilder: (context, index) {
                final item = ChatWallpaperManager.wallpapers[index];
                final isSelected = _selectedPath == item.assetPath;

                return GestureDetector(
                  onTap: () {
                    setState(() {
                      _selectedPath = item.assetPath;
                    });
                  },
                  child: Container(
                    width: 95.0,
                    margin: const EdgeInsets.only(right: 12.0),
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(16.0),
                      border: Border.all(
                        color: isSelected ? const Color(0xFF0084FF) : Colors.white12,
                        width: isSelected ? 3.0 : 1.0,
                      ),
                      color: const Color(0xFF242526),
                    ),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(13.0),
                      child: Stack(
                        fit: StackFit.expand,
                        children: [
                          if (item.assetPath.isNotEmpty)
                            Image.asset(
                              item.assetPath,
                              fit: BoxFit.cover,
                            )
                          else
                            Container(
                              color: Colors.black,
                              child: const Center(
                                child: Icon(Icons.block_rounded, color: Colors.white38, size: 28.0),
                              ),
                            ),

                          // Semi-transparent overlay label
                          Positioned(
                            bottom: 0,
                            left: 0,
                            right: 0,
                            child: Container(
                              color: Colors.black54,
                              padding: const EdgeInsets.symmetric(vertical: 4.0),
                              child: Text(
                                item.title,
                                textAlign: TextAlign.center,
                                style: GoogleFonts.inter(
                                  color: Colors.white,
                                  fontSize: 10.5,
                                  fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                                ),
                              ),
                            ),
                          ),

                          // Active selection checkmark badge
                          if (isSelected)
                            Positioned(
                              top: 6.0,
                              right: 6.0,
                              child: Container(
                                padding: const EdgeInsets.all(3.0),
                                decoration: const BoxDecoration(
                                  color: Color(0xFF0084FF),
                                  shape: BoxShape.circle,
                                ),
                                child: const Icon(Icons.check_rounded, color: Colors.white, size: 14.0),
                              ),
                            ),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
          const SizedBox(height: 16.0),

          // Checkbox for applying to all chats
          GestureDetector(
            onTap: () => setState(() => _applyToAll = !_applyToAll),
            child: Row(
              children: [
                Checkbox(
                  value: _applyToAll,
                  activeColor: const Color(0xFF0084FF),
                  onChanged: (val) => setState(() => _applyToAll = val ?? false),
                ),
                Expanded(
                  child: Text(
                    'អនុវត្តប្រធានបទនេះទៅកាន់គ្រប់សារទាំងអស់ (Apply to all chats)',
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFFB0B3B8),
                      fontSize: 13.0,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12.0),

          // Apply Button
          SizedBox(
            width: double.infinity,
            height: 46.0,
            child: ElevatedButton(
              onPressed: _saveTheme,
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF0084FF),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14.0)),
              ),
              child: Text(
                'រក្សាទុកប្រធានបទ (Save Theme)',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 15.5,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
