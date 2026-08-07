import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:http/http.dart' as http;
import 'package:lottie/lottie.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';

class LocalStickerPack {
  final String id;
  final String title;
  final String iconAsset;
  final bool isAnimated;
  final List<String> stickerAssets;

  LocalStickerPack({
    required this.id,
    required this.title,
    required this.iconAsset,
    this.isAnimated = false,
    required this.stickerAssets,
  });
}

class GiphyStickerPickerBottomSheet extends StatefulWidget {
  final Function(String url, String type) onSelectSticker;

  const GiphyStickerPickerBottomSheet({
    super.key,
    required this.onSelectSticker,
  });

  @override
  State<GiphyStickerPickerBottomSheet> createState() => _GiphyStickerPickerBottomSheetState();
}

class _GiphyStickerPickerBottomSheetState extends State<GiphyStickerPickerBottomSheet> with SingleTickerProviderStateMixin {
  static const String _giphyApiKey = 'GKWqECiGomkByeuzii4JDChS1h2FPbA0';

  late TabController _tabController;
  final TextEditingController _searchController = TextEditingController();

  List<dynamic> _giphyItems = [];
  bool _isLoading = true;

  int _selectedLocalPackIndex = 0;

  // Local Sticker Packs from assets/sticker/
  late final List<LocalStickerPack> _localStickerPacks;

  // Preset Lottie Animated Stickers (High quality public animations)
  final List<Map<String, String>> _lottieStickers = [
    {
      'name': 'Happy Cat',
      'url': 'https://assets5.lottiefiles.com/packages/lf20_syqnfe7c.json',
    },
    {
      'name': 'Thumbs Up',
      'url': 'https://assets2.lottiefiles.com/packages/lf20_49rdyysj.json',
    },
    {
      'name': 'Love Heart',
      'url': 'https://assets10.lottiefiles.com/packages/lf20_7limp2s1.json',
    },
    {
      'name': 'Party Celebrate',
      'url': 'https://assets8.lottiefiles.com/packages/lf20_u4yrau.json',
    },
    {
      'name': 'Fire Flame',
      'url': 'https://assets9.lottiefiles.com/packages/lf20_yfiwop7w.json',
    },
    {
      'name': 'Laughing Face',
      'url': 'https://assets3.lottiefiles.com/packages/lf20_tou9atkw.json',
    },
  ];

  final List<String> _quickEmojis = [
    '👍', '❤️', '🔥', '😂', '🥳', '🎉', '👏', '🙏',
    '😍', '😮', '😢', '💯', '🚀', '⭐', '✨', '👌',
    '😎', '🤔', '😊', '🥰', '😴', '😭', '🤯', '💪',
  ];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 5, vsync: this);

    _initLocalStickerPacks();
    _fetchGiphyData();
  }

  void _initLocalStickerPacks() {
    _localStickerPacks = [
      LocalStickerPack(
        id: 'vvc_sticker',
        title: 'VVC Stickers',
        iconAsset: 'assets/sticker/vvc-sticker/0.webp',
        isAnimated: false,
        stickerAssets: List.generate(30, (i) => 'assets/sticker/vvc-sticker/$i.webp'),
      ),
      LocalStickerPack(
        id: 'vvc_shop',
        title: 'VVC Shop',
        iconAsset: 'assets/sticker/vvc-shop/0.png',
        isAnimated: false,
        stickerAssets: List.generate(20, (i) => 'assets/sticker/vvc-shop/$i.png'),
      ),
      LocalStickerPack(
        id: 'colorful_messages',
        title: 'Colorful',
        iconAsset: 'assets/sticker/ColorfulMessages/0.tgs',
        isAnimated: true,
        stickerAssets: List.generate(37, (i) => 'assets/sticker/ColorfulMessages/$i.tgs'),
      ),
      LocalStickerPack(
        id: 'japanese_shiba',
        title: 'Shiba',
        iconAsset: 'assets/sticker/JapaneseShiba/0.tgs',
        isAnimated: true,
        stickerAssets: List.generate(29, (i) => 'assets/sticker/JapaneseShiba/$i.tgs'),
      ),
      LocalStickerPack(
        id: 'hands_4_friends',
        title: 'Hands',
        iconAsset: 'assets/sticker/Hands4Friends/0.tgs',
        isAnimated: true,
        stickerAssets: List.generate(35, (i) => 'assets/sticker/Hands4Friends/$i.tgs'),
      ),
      LocalStickerPack(
        id: 'text_animated',
        title: 'Text Animated',
        iconAsset: 'assets/sticker/TextAnimated/0.tgs',
        isAnimated: true,
        stickerAssets: List.generate(25, (i) => 'assets/sticker/TextAnimated/$i.tgs'),
      ),
    ];
  }

  @override
  void dispose() {
    _tabController.dispose();
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _fetchGiphyData({String query = ''}) async {
    setState(() => _isLoading = true);

    // Tab 1 = Giphy Stickers, Tab 2 = Giphy GIFs
    final bool isStickerTab = _tabController.index == 1;
    final String endpoint = isStickerTab ? 'stickers' : 'gifs';
    final String action = query.trim().isNotEmpty ? 'search' : 'trending';

    String urlString = 'https://api.giphy.com/v1/$endpoint/$action?api_key=$_giphyApiKey&limit=36&rating=g';
    if (query.trim().isNotEmpty) {
      urlString += '&q=${Uri.encodeComponent(query.trim())}';
    }

    try {
      final response = await http.get(Uri.parse(urlString));
      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (mounted) {
          setState(() {
            _giphyItems = data['data'] ?? [];
            _isLoading = false;
          });
        }
      } else {
        if (mounted) setState(() => _isLoading = false);
      }
    } catch (_) {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      height: MediaQuery.of(context).size.height * 0.65,
      decoration: const BoxDecoration(
        color: Color(0xFF1C1C1E),
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      child: Column(
        children: [
          // Drag Handle
          const SizedBox(height: 10),
          Center(
            child: Container(
              width: 36,
              height: 5,
              decoration: BoxDecoration(
                color: Colors.white24,
                borderRadius: BorderRadius.circular(10),
              ),
            ),
          ),
          const SizedBox(height: 12),

          // Header Title
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'Stickers & GIFs',
                  style: GoogleFonts.inter(
                    color: Colors.white,
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                IconButton(
                  icon: const Icon(LucideIcons.x, color: Colors.white70, size: 20),
                  onPressed: () => Navigator.pop(context),
                  visualDensity: VisualDensity.compact,
                ),
              ],
            ),
          ),

          // Search Bar (only for Giphy tabs)
          if (_tabController.index == 1 || _tabController.index == 2) ...[
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
              child: Container(
                height: 38,
                padding: const EdgeInsets.symmetric(horizontal: 12),
                decoration: BoxDecoration(
                  color: const Color(0xFF2C2C2E),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Row(
                  children: [
                    const Icon(LucideIcons.search, color: Color(0xFF8E8E93), size: 16),
                    const SizedBox(width: 8),
                    Expanded(
                      child: TextField(
                        controller: _searchController,
                        style: GoogleFonts.inter(color: Colors.white, fontSize: 13),
                        decoration: InputDecoration(
                          hintText: 'Search Giphy stickers & GIFs...',
                          hintStyle: GoogleFonts.inter(color: const Color(0xFF8E8E93), fontSize: 13),
                          border: InputBorder.none,
                          isDense: true,
                        ),
                        onSubmitted: (query) => _fetchGiphyData(query: query),
                      ),
                    ),
                    if (_searchController.text.isNotEmpty)
                      InkWell(
                        onTap: () {
                          _searchController.clear();
                          _fetchGiphyData(query: '');
                        },
                        child: const Icon(LucideIcons.xCircle, color: Color(0xFF8E8E93), size: 16),
                      ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 4),
          ],

          // Category Tab Bar
          TabBar(
            controller: _tabController,
            indicatorColor: const Color(0xFF007AFF),
            indicatorWeight: 3.0,
            labelColor: Colors.white,
            unselectedLabelColor: const Color(0xFF8E8E93),
            labelStyle: GoogleFonts.inter(fontSize: 12.0, fontWeight: FontWeight.bold),
            isScrollable: true,
            tabAlignment: TabAlignment.start,
            onTap: (_) {
              setState(() {});
              if (_tabController.index == 1 || _tabController.index == 2) {
                _fetchGiphyData(query: _searchController.text);
              }
            },
            tabs: const [
              Tab(text: '✨ Packs'),
              Tab(text: 'Giphy'),
              Tab(text: 'GIFs'),
              Tab(text: 'Lottie'),
              Tab(text: 'Emojis'),
            ],
          ),

          // Tab Views Content
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                // 0. Local VVC Sticker Packs Grid
                _buildLocalStickerPacksView(),

                // 1. Giphy Stickers Grid
                _buildGiphyGrid(),

                // 2. Giphy GIFs Grid
                _buildGiphyGrid(),

                // 3. Lottie Animated Stickers Grid
                _buildLottieGrid(),

                // 4. Quick Emojis Grid
                _buildEmojiGrid(),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // Local Sticker Packs View (VVC Stickers, VVC Shop, Colorful, Shiba)
  Widget _buildLocalStickerPacksView() {
    final currentPack = _localStickerPacks[_selectedLocalPackIndex];

    return Column(
      children: [
        // Sub-Pack Category Selector Pills
        Container(
          height: 44,
          padding: const EdgeInsets.symmetric(vertical: 6, horizontal: 12),
          child: ListView.separated(
            scrollDirection: Axis.horizontal,
            itemCount: _localStickerPacks.length,
            separatorBuilder: (_, __) => const SizedBox(width: 8),
            itemBuilder: (context, index) {
              final pack = _localStickerPacks[index];
              final isSelected = index == _selectedLocalPackIndex;

              return ChoiceChip(
                showCheckmark: false,
                selected: isSelected,
                selectedColor: const Color(0xFF007AFF),
                backgroundColor: const Color(0xFF2C2C2E),
                side: BorderSide.none,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                label: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    SizedBox(
                      width: 18,
                      height: 18,
                      child: pack.isAnimated
                          ? Lottie.asset(pack.iconAsset, fit: BoxFit.contain)
                          : Image.asset(pack.iconAsset, fit: BoxFit.contain),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      pack.title,
                      style: GoogleFonts.inter(
                        color: isSelected ? Colors.white : Colors.white70,
                        fontSize: 12,
                        fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                      ),
                    ),
                  ],
                ),
                onSelected: (_) {
                  setState(() => _selectedLocalPackIndex = index);
                },
              );
            },
          ),
        ),

        // Sticker Grid for Selected Pack
        Expanded(
          child: GridView.builder(
            padding: const EdgeInsets.all(12),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 4,
              mainAxisSpacing: 12,
              crossAxisSpacing: 12,
            ),
            itemCount: currentPack.stickerAssets.length,
            itemBuilder: (context, index) {
              final assetPath = currentPack.stickerAssets[index];

              return InkWell(
                onTap: () {
                  Navigator.pop(context);
                  widget.onSelectSticker(
                    assetPath,
                    currentPack.isAnimated ? 'lottie' : 'asset',
                  );
                },
                borderRadius: BorderRadius.circular(16),
                child: Container(
                  padding: const EdgeInsets.all(6),
                  decoration: BoxDecoration(
                    color: const Color(0xFF2C2C2E).withValues(alpha: 0.6),
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
                  ),
                  child: currentPack.isAnimated
                      ? Lottie.asset(
                          assetPath,
                          fit: BoxFit.contain,
                          errorBuilder: (context, error, stackTrace) =>
                              const Center(child: Icon(LucideIcons.sparkles, color: Colors.amberAccent, size: 24)),
                        )
                      : Image.asset(
                          assetPath,
                          fit: BoxFit.contain,
                          errorBuilder: (context, error, stackTrace) =>
                              const Center(child: Icon(LucideIcons.imageOff, color: Colors.white38, size: 24)),
                        ),
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildGiphyGrid() {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator(color: Color(0xFF007AFF)));
    }

    if (_giphyItems.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(LucideIcons.imageOff, size: 48, color: Colors.white38),
            const SizedBox(height: 8),
            Text(
              'No Giphy items found',
              style: GoogleFonts.inter(color: Colors.white54, fontSize: 14),
            ),
          ],
        ),
      );
    }

    return GridView.builder(
      padding: const EdgeInsets.all(12),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 3,
        mainAxisSpacing: 10,
        crossAxisSpacing: 10,
      ),
      itemCount: _giphyItems.length,
      itemBuilder: (context, index) {
        final item = _giphyItems[index];
        final images = item['images'] as Map<String, dynamic>?;
        final String gifUrl = images?['fixed_height']?['url'] ?? images?['original']?['url'] ?? '';

        if (gifUrl.isEmpty) return const SizedBox.shrink();

        return InkWell(
          onTap: () {
            Navigator.pop(context);
            widget.onSelectSticker(gifUrl, 'giphy');
          },
          borderRadius: BorderRadius.circular(12),
          child: Container(
            decoration: BoxDecoration(
              color: const Color(0xFF2C2C2E),
              borderRadius: BorderRadius.circular(12),
            ),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(12),
              child: Image.network(
                gifUrl,
                fit: BoxFit.cover,
                loadingBuilder: (context, child, progress) {
                  if (progress == null) return child;
                  return const Center(child: SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Color(0xFF007AFF))));
                },
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildLottieGrid() {
    return GridView.builder(
      padding: const EdgeInsets.all(14),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 3,
        mainAxisSpacing: 12,
        crossAxisSpacing: 12,
      ),
      itemCount: _lottieStickers.length,
      itemBuilder: (context, index) {
        final item = _lottieStickers[index];
        final String url = item['url']!;

        return InkWell(
          onTap: () {
            Navigator.pop(context);
            widget.onSelectSticker(url, 'lottie');
          },
          borderRadius: BorderRadius.circular(16),
          child: Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: const Color(0xFF2C2C2E),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: Colors.white.withValues(alpha: 0.08), width: 0.5),
            ),
            child: Lottie.network(
              url,
              fit: BoxFit.contain,
              errorBuilder: (context, error, stackTrace) {
                return const Center(child: Icon(LucideIcons.sparkles, color: Colors.amberAccent));
              },
            ),
          ),
        );
      },
    );
  }

  Widget _buildEmojiGrid() {
    return GridView.builder(
      padding: const EdgeInsets.all(16),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 4,
        mainAxisSpacing: 14,
        crossAxisSpacing: 14,
      ),
      itemCount: _quickEmojis.length,
      itemBuilder: (context, index) {
        final emoji = _quickEmojis[index];

        return InkWell(
          onTap: () {
            Navigator.pop(context);
            widget.onSelectSticker(emoji, 'emoji');
          },
          borderRadius: BorderRadius.circular(20),
          child: Container(
            decoration: BoxDecoration(
              color: const Color(0xFF2C2C2E),
              borderRadius: BorderRadius.circular(20),
            ),
            child: Center(
              child: Text(
                emoji,
                style: const TextStyle(fontSize: 32),
              ),
            ),
          ),
        );
      },
    );
  }
}
