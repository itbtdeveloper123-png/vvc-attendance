import 'dart:async';
import 'dart:convert';

import 'package:animate_do/animate_do.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:image_picker/image_picker.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../services/api_service.dart';
import '../utils/app_theme.dart';

// ─── Models ───────────────────────────────────────────────────────────────────

class ProductAnalysis {
  final String productName;
  final String brand;
  final String countryOfOrigin;
  final String countryFlagEmoji;
  final String category;
  final List<String> usage;
  final List<String> benefits;
  final List<String> warnings;
  final String ingredientsSummary;
  final String priceRangeUsd;
  final String summary;
  final String? raw;
  final List<Map<String, String>> webSources;
  final List<String> webQueries;
  final bool isWebGrounded;

  const ProductAnalysis({
    required this.productName,
    required this.brand,
    required this.countryOfOrigin,
    required this.countryFlagEmoji,
    required this.category,
    required this.usage,
    required this.benefits,
    required this.warnings,
    required this.ingredientsSummary,
    required this.priceRangeUsd,
    required this.summary,
    this.raw,
    this.webSources = const [],
    this.webQueries = const [],
    this.isWebGrounded = false,
  });

  Map<String, dynamic> toJson() => {
        'product_name': productName,
        'brand': brand,
        'country_of_origin': countryOfOrigin,
        'country_flag_emoji': countryFlagEmoji,
        'category': category,
        'usage': usage,
        'benefits': benefits,
        'warnings': warnings,
        'ingredients_summary': ingredientsSummary,
        'price_range_usd': priceRangeUsd,
        'summary': summary,
        'raw': raw,
        'web_sources': webSources,
        'web_queries': webQueries,
        'is_web_grounded': isWebGrounded,
      };

  factory ProductAnalysis.fromJson(Map<String, dynamic> json) {
    List<String> listFromValue(dynamic v) {
      if (v is List) return v.map((e) => e.toString()).toList();
      if (v is String && v.isNotEmpty) return [v];
      return [];
    }

    final pName = json['product_name']?.toString() ?? 'មិនស្គាល់';
    final bName = json['brand']?.toString() ?? '—';
    final cName = json['category']?.toString() ?? '—';

    String rawSum = (json['summary']?.toString() ?? '').trim();
    if (rawSum.startsWith('{') ||
        rawSum.startsWith('[') ||
        rawSum.contains('"product_name"') ||
        rawSum.contains('":')) {
      final brandStr =
          (bName.isNotEmpty && bName != '—' && bName != 'មិនបានរកឃើញ')
              ? ' ម៉ាក $bName'
              : '';
      final catStr =
          (cName.isNotEmpty && cName != '—' && cName != 'ទូទៅ' && cName != 'មិនបានរកឃើញ')
              ? ' ស្ថិតក្នុងជំពូក $cName'
              : '';
      final originVal = json['country_of_origin']?.toString() ?? '';
      final originStr =
          (originVal.isNotEmpty && originVal != '—' && originVal != 'មិនបានរកឃើញ')
              ? ' មកពីប្រទេស $originVal'
              : '';
      rawSum =
          '$pName$brandStr$catStr$originStr គុណភាពខ្ពស់ និងបានឆ្លងកាត់ការផ្ទៀងផ្ទាត់ព័ត៌មានលម្អិតត្រឹមត្រូវ។';
    }

    final rawWebSources = json['web_sources'];
    final List<Map<String, String>> parsedSources = [];
    if (rawWebSources is List) {
      for (final item in rawWebSources) {
        if (item is Map) {
          final uri = item['uri']?.toString() ?? '';
          final title = item['title']?.toString() ?? '';
          if (uri.isNotEmpty) {
            parsedSources.add({
              'title': title.isNotEmpty ? title : uri,
              'uri': uri,
            });
          }
        }
      }
    }

    final rawQueries = json['web_queries'];
    final List<String> parsedQueries = [];
    if (rawQueries is List) {
      for (final q in rawQueries) {
        if (q != null && q.toString().trim().isNotEmpty) {
          parsedQueries.add(q.toString().trim());
        }
      }
    }

    final isGrounded = (json['is_web_grounded'] == true) ||
        parsedSources.isNotEmpty ||
        parsedQueries.isNotEmpty;

    return ProductAnalysis(
      productName: pName,
      brand: bName,
      countryOfOrigin: json['country_of_origin']?.toString() ?? '—',
      countryFlagEmoji: json['country_flag_emoji']?.toString() ?? '🌍',
      category: cName,
      usage: listFromValue(json['usage']),
      benefits: listFromValue(json['benefits']),
      warnings: listFromValue(json['warnings']),
      ingredientsSummary: json['ingredients_summary']?.toString() ?? '—',
      priceRangeUsd: json['price_range_usd']?.toString() ?? '—',
      summary: rawSum,
      raw: json['raw']?.toString(),
      webSources: parsedSources,
      webQueries: parsedQueries,
      isWebGrounded: isGrounded,
    );
  }

  bool get isBottleOrDrinkware {
    final text =
        '$productName $category $summary $ingredientsSummary $brand'.toLowerCase();
    return text.contains('bottle') ||
        text.contains('ដប') ||
        text.contains('កែវ') ||
        text.contains('tumbler') ||
        text.contains('flask') ||
        text.contains('thermos') ||
        text.contains('hydro flask') ||
        text.contains('stanley') ||
        text.contains('yeti') ||
        text.contains('locknlock') ||
        text.contains('lock&lock') ||
        text.contains('zebra') ||
        text.contains('tritan') ||
        text.contains('vacuum');
  }

  /// Extracts capacity like "500ml", "750ml", "1L", "24oz", "32oz", "40oz"
  String? get detectedCapacity {
    final fullText = '$productName $summary $ingredientsSummary';
    final reg = RegExp(
        r'(\b\d+(?:\.\d+)?\s*(?:ml|l|oz|ounce|លីត្រ|មីលីលីត្រ)\b)',
        caseSensitive: false);
    final match = reg.firstMatch(fullText);
    return match?.group(0);
  }

  /// Extracts material like SUS 304, SUS 316, Tritan, etc.
  String? get detectedMaterial {
    final fullText =
        '$ingredientsSummary $summary $productName'.toLowerCase();
    if (fullText.contains('316')) {
      return 'ដែកអ៊ីណុក SUS 316 (Food/Medical Grade)';
    }
    if (fullText.contains('304')) {
      return 'ដែកអ៊ីណុក SUS 304 (Food Grade)';
    }
    if (fullText.contains('tritan')) {
      return 'ប្លាស្ទិក Tritan (BPA-Free)';
    }
    if (fullText.contains('glass') || fullText.contains('កែវ')) {
      return 'កែវ Borosilicate Glass';
    }
    if (fullText.contains('stainless')) {
      return 'ដែកអ៊ីណុក Stainless Steel';
    }
    return null;
  }

  /// Detects thermal retention times if present
  String? get detectedInsulation {
    final fullText =
        '$summary $ingredientsSummary ${benefits.join(' ')}'.toLowerCase();
    final reg = RegExp(
        r'(\d+\s*(?:ម៉ោង|hours?|h)\s*(?:ត្រជាក់|cold|កម្តៅ|hot)?)',
        caseSensitive: false);
    final match = reg.firstMatch(fullText);
    if (match != null) return match.group(0);
    if (fullText.contains('vacuum') ||
        fullText.contains('កម្តៅ') ||
        fullText.contains('ត្រជាក់')) {
      return 'រក្សាកម្តៅ & ត្រជាក់ (Vacuum Insulated)';
    }
    return null;
  }
}

class ProductFolder {
  final String id;
  String name;
  final String iconCode;
  final int colorHex;
  final DateTime createdAt;

  ProductFolder({
    required this.id,
    required this.name,
    this.iconCode = 'folder',
    this.colorHex = 0xFF7C3AED,
    DateTime? createdAt,
  }) : createdAt = createdAt ?? DateTime.now();

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'icon_code': iconCode,
        'color_hex': colorHex,
        'created_at': createdAt.toIso8601String(),
      };

  factory ProductFolder.fromJson(Map<String, dynamic> json) => ProductFolder(
        id: json['id']?.toString() ?? '',
        name: json['name']?.toString() ?? 'Folder',
        iconCode: json['icon_code']?.toString() ?? 'folder',
        colorHex: json['color_hex'] is int ? json['color_hex'] : 0xFF7C3AED,
        createdAt: DateTime.tryParse(json['created_at']?.toString() ?? '') ??
            DateTime.now(),
      );
}

class SavedProductSession {
  final String id;
  String title;
  final String brand;
  final String country;
  final String countryFlag;
  final String category;
  String? folderId;
  String? folderName;
  final String barcode;
  final String? imageBase64;
  final ProductAnalysis analysis;
  final List<Map<String, dynamic>> chatHistory;
  final DateTime savedAt;

  SavedProductSession({
    required this.id,
    required this.title,
    required this.brand,
    required this.country,
    required this.countryFlag,
    required this.category,
    this.folderId,
    this.folderName,
    this.barcode = '',
    this.imageBase64,
    required this.analysis,
    required this.chatHistory,
    DateTime? savedAt,
  }) : savedAt = savedAt ?? DateTime.now();

  Map<String, dynamic> toJson() => {
        'id': id,
        'title': title,
        'brand': brand,
        'country': country,
        'country_flag': countryFlag,
        'category': category,
        'folder_id': folderId,
        'folder_name': folderName,
        'barcode': barcode,
        'image_base64': imageBase64,
        'analysis': analysis.toJson(),
        'chat_history': chatHistory,
        'saved_at': savedAt.toIso8601String(),
      };

  factory SavedProductSession.fromJson(Map<String, dynamic> json) =>
      SavedProductSession(
        id: json['id']?.toString() ?? '',
        title: json['title']?.toString() ?? 'ផលិតផល',
        brand: json['brand']?.toString() ?? '—',
        country: json['country']?.toString() ?? '—',
        countryFlag: json['country_flag']?.toString() ?? '🌍',
        category: json['category']?.toString() ?? 'ទូទៅ',
        folderId: json['folder_id']?.toString(),
        folderName: json['folder_name']?.toString(),
        barcode: json['barcode']?.toString() ?? '',
        imageBase64: json['image_base64']?.toString(),
        analysis: ProductAnalysis.fromJson(
            Map<String, dynamic>.from(json['analysis'] ?? {})),
        chatHistory: (json['chat_history'] as List? ?? [])
            .map((e) => Map<String, dynamic>.from(e as Map))
            .toList(),
        savedAt: DateTime.tryParse(json['saved_at']?.toString() ?? '') ??
            DateTime.now(),
      );
}

enum ChatSender { user, ai, system }

class ChatMessageItem {
  final String id;
  final ChatSender sender;
  final String text;
  final Uint8List? imageBytes;
  final String? barcode;
  final ProductAnalysis? analysis;
  final DateTime timestamp;
  final bool isLoading;

  ChatMessageItem({
    required this.id,
    required this.sender,
    required this.text,
    this.imageBytes,
    this.barcode,
    this.analysis,
    this.isLoading = false,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();

  Map<String, dynamic> toJson() => {
        'id': id,
        'sender': sender.name,
        'text': text,
        'barcode': barcode,
        'analysis': analysis?.toJson(),
        'timestamp': timestamp.toIso8601String(),
      };

  factory ChatMessageItem.fromJson(Map<String, dynamic> json,
          {Uint8List? imageBytes}) =>
      ChatMessageItem(
        id: json['id']?.toString() ?? '',
        sender: json['sender'] == 'user'
            ? ChatSender.user
            : (json['sender'] == 'system'
                ? ChatSender.system
                : ChatSender.ai),
        text: json['text']?.toString() ?? '',
        barcode: json['barcode']?.toString(),
        analysis: json['analysis'] != null
            ? ProductAnalysis.fromJson(
                Map<String, dynamic>.from(json['analysis']))
            : null,
        imageBytes: imageBytes,
        timestamp: DateTime.tryParse(json['timestamp']?.toString() ?? '') ??
            DateTime.now(),
      );
}

// ─── Storage Service ──────────────────────────────────────────────────────────

class ProductStorageService {
  static const String _foldersKey = 'vvc_product_folders_v2';
  static const String _historyKey = 'vvc_product_saved_history_v2';

  static List<ProductFolder> _defaultFolders() => [
        ProductFolder(
          id: 'f_bottles',
          name: 'ដបទឹក & កែវរក្សាកម្តៅ (Water Bottles)',
          iconCode: 'bottle',
          colorHex: 0xFF06B6D4,
        ),
        ProductFolder(
          id: 'f_cosmetics',
          name: 'គ្រឿងសំអាង (Cosmetics)',
          iconCode: 'sparkles',
          colorHex: 0xFFEC4899,
        ),
        ProductFolder(
          id: 'f_food',
          name: 'ភេសជ្ជៈ & អាហារ (Food & Drink)',
          iconCode: 'food',
          colorHex: 0xFFF59E0B,
        ),
        ProductFolder(
          id: 'f_medicine',
          name: 'ថ្នាំពេទ្យ & សុខភាព (Health)',
          iconCode: 'med',
          colorHex: 0xFF10B981,
        ),
        ProductFolder(
          id: 'f_electronics',
          name: 'គ្រឿងអេឡិចត្រូនិច (Electronics)',
          iconCode: 'devices',
          colorHex: 0xFF0EA5E9,
        ),
        ProductFolder(
          id: 'f_daily',
          name: 'ទំនិញប្រចាំថ្ងៃ (Daily Essentials)',
          iconCode: 'daily',
          colorHex: 0xFF8B5CF6,
        ),
      ];

  static Future<List<ProductFolder>> getFolders() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_foldersKey);
    if (raw == null || raw.isEmpty) {
      final defaults = _defaultFolders();
      await saveFolders(defaults);
      return defaults;
    }
    try {
      final list = jsonDecode(raw) as List;
      return list
          .map((e) => ProductFolder.fromJson(Map<String, dynamic>.from(e)))
          .toList();
    } catch (_) {
      return _defaultFolders();
    }
  }

  static Future<void> saveFolders(List<ProductFolder> folders) async {
    final prefs = await SharedPreferences.getInstance();
    final encoded = jsonEncode(folders.map((e) => e.toJson()).toList());
    await prefs.setString(_foldersKey, encoded);
  }

  static Future<ProductFolder> createFolder(String name,
      {String iconCode = 'folder', int colorHex = 0xFF7C3AED}) async {
    final folders = await getFolders();
    final newF = ProductFolder(
      id: 'f_${DateTime.now().millisecondsSinceEpoch}',
      name: name.trim(),
      iconCode: iconCode,
      colorHex: colorHex,
    );
    folders.add(newF);
    await saveFolders(folders);
    return newF;
  }

  static Future<void> renameFolder(String folderId, String newName) async {
    final folders = await getFolders();
    for (final f in folders) {
      if (f.id == folderId) {
        f.name = newName.trim();
        break;
      }
    }
    await saveFolders(folders);

    // Also update all saved products with this folder name
    final history = await getSavedProducts();
    for (final p in history) {
      if (p.folderId == folderId) {
        p.folderName = newName.trim();
      }
    }
    await saveSavedProducts(history);
  }

  static Future<void> deleteFolder(String folderId) async {
    final folders = await getFolders();
    folders.removeWhere((f) => f.id == folderId);
    await saveFolders(folders);

    // Unassign products from this folder
    final history = await getSavedProducts();
    for (final p in history) {
      if (p.folderId == folderId) {
        p.folderId = null;
        p.folderName = null;
      }
    }
    await saveSavedProducts(history);
  }

  static Future<List<SavedProductSession>> getSavedProducts() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_historyKey);
    if (raw == null || raw.isEmpty) return [];
    try {
      final list = jsonDecode(raw) as List;
      final items = list
          .map((e) =>
              SavedProductSession.fromJson(Map<String, dynamic>.from(e)))
          .toList();
      items.sort((a, b) => b.savedAt.compareTo(a.savedAt));
      return items;
    } catch (_) {
      return [];
    }
  }

  static Future<void> saveSavedProducts(
      List<SavedProductSession> products) async {
    final prefs = await SharedPreferences.getInstance();
    final encoded = jsonEncode(products.map((e) => e.toJson()).toList());
    await prefs.setString(_historyKey, encoded);
  }

  static Future<void> saveOrUpdateProduct(SavedProductSession session) async {
    final list = await getSavedProducts();
    final index = list.indexWhere((p) => p.id == session.id);
    if (index >= 0) {
      list[index] = session;
    } else {
      list.insert(0, session);
    }
    await saveSavedProducts(list);
  }

  static Future<void> updateProductFolder(
      String productId, String? folderId, String? folderName) async {
    final list = await getSavedProducts();
    for (final p in list) {
      if (p.id == productId) {
        p.folderId = folderId;
        p.folderName = folderName;
        break;
      }
    }
    await saveSavedProducts(list);
  }

  static Future<void> renameProduct(String productId, String newTitle) async {
    final list = await getSavedProducts();
    for (final p in list) {
      if (p.id == productId) {
        p.title = newTitle.trim();
        break;
      }
    }
    await saveSavedProducts(list);
  }

  static Future<void> deleteProduct(String productId) async {
    final list = await getSavedProducts();
    list.removeWhere((p) => p.id == productId);
    await saveSavedProducts(list);
  }
}

// ─── Main Screen ──────────────────────────────────────────────────────────────

class ProductAnalyzerScreen extends StatefulWidget {
  const ProductAnalyzerScreen({super.key});

  @override
  State<ProductAnalyzerScreen> createState() => _ProductAnalyzerScreenState();
}

class _ProductAnalyzerScreenState extends State<ProductAnalyzerScreen>
    with SingleTickerProviderStateMixin {
  final ApiService _api = ApiService();
  final ImagePicker _picker = ImagePicker();
  final TextEditingController _textCtrl = TextEditingController();
  final ScrollController _scrollCtrl = ScrollController();

  // Chat State
  final List<ChatMessageItem> _messages = [];
  bool _isAnalyzing = false;
  bool _isAiResponding = false;
  String? _currentSessionId;
  ProductAnalysis? _currentAnalysis;
  Uint8List? _currentImageBytes;
  String? _currentImageBase64;
  String? _currentBarcode;
  String? _currentFolderId;
  String? _currentFolderName;

  // Folders & History State
  List<ProductFolder> _folders = [];
  List<SavedProductSession> _savedHistory = [];

  // Barcode Scanner
  bool _showBarcodeScanner = false;
  final MobileScannerController _scanController = MobileScannerController(
    formats: [
      BarcodeFormat.ean8,
      BarcodeFormat.ean13,
      BarcodeFormat.code128,
      BarcodeFormat.qrCode,
      BarcodeFormat.upcA,
      BarcodeFormat.upcE,
    ],
    detectionTimeoutMs: 800,
    autoStart: false,
  );
  bool _barcodeLocked = false;

  // Analysis Timer
  Timer? _elapsedTimer;
  int _elapsedSeconds = 0;

  @override
  void initState() {
    super.initState();
    _loadFoldersAndHistory();
    _initWelcomeChat();
  }

  @override
  void dispose() {
    _elapsedTimer?.cancel();
    _textCtrl.dispose();
    _scrollCtrl.dispose();
    _scanController.dispose();
    super.dispose();
  }

  void _hapticLight() => HapticFeedback.lightImpact();

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollCtrl.hasClients) {
        _scrollCtrl.animateTo(
          _scrollCtrl.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  Future<void> _loadFoldersAndHistory() async {
    final f = await ProductStorageService.getFolders();
    final h = await ProductStorageService.getSavedProducts();
    if (mounted) {
      setState(() {
        _folders = f;
        _savedHistory = h;
      });
    }
  }

  void _initWelcomeChat() {
    _messages.clear();
    _currentSessionId = 'session_${DateTime.now().millisecondsSinceEpoch}';
    _currentAnalysis = null;
    _currentImageBytes = null;
    _currentImageBase64 = null;
    _currentBarcode = null;
    _currentFolderId = null;
    _currentFolderName = null;

    _messages.add(
      ChatMessageItem(
        id: 'welcome_msg',
        sender: ChatSender.ai,
        text:
            'សួស្តី! ខ្ញុំជា **AI Product Analyzer** ជំនួយការឆ្លាតវៃសម្រាប់វិភាគផលិតផល ដបទឹក & កែវរក្សាកម្តៅ (Water Bottles & Drinkware) និងទំនិញគ្រប់ប្រភេទ ស្វែងរកព័ត៌មានពិតពី Google Search និងផ្ទៀងផ្ទាត់ប្រទេសដើម។\n\nសូមថតរូបភាព ឬស្កេន Barcode ផលិតផលដើម្បីចាប់ផ្តើម!',
      ),
    );
  }

  void _startElapsedTimer() {
    _elapsedSeconds = 0;
    _elapsedTimer?.cancel();
    _elapsedTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) {
        setState(() => _elapsedSeconds++);
      }
    });
  }

  void _stopElapsedTimer() {
    _elapsedTimer?.cancel();
    _elapsedTimer = null;
  }

  String _formatElapsed(int totalSeconds) {
    final mins = totalSeconds ~/ 60;
    final secs = totalSeconds % 60;
    return '${mins.toString().padLeft(2, '0')}:${secs.toString().padLeft(2, '0')}';
  }

  // ─── Image Picking & Analysis ─────────────────────────────────────────────

  Future<void> _pickImage(ImageSource source) async {
    _hapticLight();
    try {
      final xfile = await _picker.pickImage(
        source: source,
        imageQuality: 75,
        maxWidth: 850,
      );
      if (xfile == null) return;
      final bytes = await xfile.readAsBytes();
      final b64 = base64Encode(bytes);
      final ext = xfile.path.split('.').last.toLowerCase();
      final mime = ext == 'png'
          ? 'image/png'
          : ext == 'webp'
              ? 'image/webp'
              : 'image/jpeg';

      setState(() {
        _currentImageBytes = bytes;
        _currentImageBase64 = 'data:$mime;base64,$b64';
        _currentBarcode = null;
      });

      // Add user message to chat
      _messages.add(
        ChatMessageItem(
          id: 'user_img_${DateTime.now().millisecondsSinceEpoch}',
          sender: ChatSender.user,
          text: 'រូបភាពផលិតផលសម្រាប់វិភាគ',
          imageBytes: bytes,
        ),
      );
      _scrollToBottom();

      // Trigger AI Analysis
      await _runAnalysis();
    } catch (e) {
      _showToast('មិនអាចបើករូបភាពបានទេ: $e', isError: true);
    }
  }

  // ─── Barcode Scanner ──────────────────────────────────────────────────────

  void _openBarcodeScanner() {
    _hapticLight();
    setState(() {
      _showBarcodeScanner = true;
      _barcodeLocked = false;
    });
    _scanController.start();
  }

  void _closeBarcodeScanner() {
    _scanController.stop();
    setState(() => _showBarcodeScanner = false);
  }

  void _onBarcodeDetected(BarcodeCapture capture) {
    if (_barcodeLocked) return;
    final code = capture.barcodes.firstOrNull?.rawValue ?? '';
    if (code.isEmpty) return;
    _barcodeLocked = true;
    _hapticLight();
    _scanController.stop();
    setState(() {
      _showBarcodeScanner = false;
      _currentBarcode = code;
      _currentImageBytes = null;
      _currentImageBase64 = null;
    });

    // Add user message to chat
    _messages.add(
      ChatMessageItem(
        id: 'user_barcode_${DateTime.now().millisecondsSinceEpoch}',
        sender: ChatSender.user,
        text: 'ស្កេនបាន Barcode: $code',
        barcode: code,
      ),
    );
    _scrollToBottom();

    // Trigger AI Analysis
    _runAnalysis();
  }

  // ─── Run Analysis ─────────────────────────────────────────────────────────

  Future<void> _runAnalysis({bool force = false}) async {
    if (_currentImageBase64 == null && _currentBarcode == null) return;

    _startElapsedTimer();
    setState(() {
      _isAnalyzing = true;
    });

    // Temporary thinking message
    final thinkingMsgId = 'thinking_${DateTime.now().millisecondsSinceEpoch}';
    _messages.add(
      ChatMessageItem(
        id: thinkingMsgId,
        sender: ChatSender.ai,
        text: 'AI កំពុងវិភាគ និងស្រាវជ្រាវលើ Google Search...',
        isLoading: true,
      ),
    );
    _scrollToBottom();

    try {
      final res = await _api.analyzeProductImage(
        imageBase64: _currentImageBase64 ?? '',
        barcode: _currentBarcode ?? '',
        force: force,
      );
      _stopElapsedTimer();

      // Remove thinking indicator
      _messages.removeWhere((m) => m.id == thinkingMsgId);

      if (!(res['success'] as bool? ?? false)) {
        final errMsg = res['message']?.toString() ?? 'ការវិភាគមិនជោគជ័យ';
        _messages.add(
          ChatMessageItem(
            id: 'err_${DateTime.now().millisecondsSinceEpoch}',
            sender: ChatSender.ai,
            text: '⚠️ សូមអភ័យទោស: $errMsg។ សូមព្យាយាមម្តងទៀត!',
          ),
        );
        setState(() => _isAnalyzing = false);
        _scrollToBottom();
        return;
      }

      final parsed = res['parsed'];
      Map<String, dynamic>? parsedMap;

      if (parsed is Map) {
        parsedMap = Map<String, dynamic>.from(
          parsed.map((k, v) => MapEntry(k.toString(), v)),
        );
      } else if (res['raw'] is String &&
          (res['raw'] as String).trim().isNotEmpty) {
        try {
          String rawStr = (res['raw'] as String).trim();
          rawStr = rawStr.replaceAll(
              RegExp(r'<think\b[^>]*>.*?<\/think>', dotAll: true), '');
          final firstBrace = rawStr.indexOf('{');
          final lastBrace = rawStr.lastIndexOf('}');
          if (firstBrace != -1 && lastBrace != -1 && lastBrace > firstBrace) {
            rawStr = rawStr.substring(firstBrace, lastBrace + 1);
          }
          final decoded = json.decode(rawStr);
          if (decoded is Map) {
            parsedMap = Map<String, dynamic>.from(
              decoded.map((k, v) => MapEntry(k.toString(), v)),
            );
          }
        } catch (_) {}
      }

      if (parsedMap != null && parsedMap.isNotEmpty) {
        final mergedMap = Map<String, dynamic>.from(parsedMap);
        if (res['web_sources'] != null &&
            !mergedMap.containsKey('web_sources')) {
          mergedMap['web_sources'] = res['web_sources'];
        }
        if (res['web_queries'] != null &&
            !mergedMap.containsKey('web_queries')) {
          mergedMap['web_queries'] = res['web_queries'];
        }
        if (res['is_web_grounded'] != null &&
            !mergedMap.containsKey('is_web_grounded')) {
          mergedMap['is_web_grounded'] = res['is_web_grounded'];
        }
        mergedMap['raw'] = res['raw'];

        final analysis = ProductAnalysis.fromJson(mergedMap);

        setState(() {
          _currentAnalysis = analysis;
          _isAnalyzing = false;
        });

        // Add Product Result Card to chat
        _messages.add(
          ChatMessageItem(
            id: 'result_${DateTime.now().millisecondsSinceEpoch}',
            sender: ChatSender.ai,
            text: 'លទ្ធផលវិភាគផលិតផល',
            analysis: analysis,
          ),
        );
        _scrollToBottom();

        // Auto Save to History
        _autoSaveCurrentSession();
      } else {
        _messages.add(
          ChatMessageItem(
            id: 'err_empty_${DateTime.now().millisecondsSinceEpoch}',
            sender: ChatSender.ai,
            text:
                '⚠️ មិនអាចស្រង់ព័ត៌មានផលិតផលបានទេ។ សូមសាកល្បងថតរូបភាពឱ្យកាន់តែច្បាស់។',
          ),
        );
        setState(() => _isAnalyzing = false);
        _scrollToBottom();
      }
    } catch (e) {
      _stopElapsedTimer();
      _messages.removeWhere((m) => m.id == thinkingMsgId);
      _messages.add(
        ChatMessageItem(
          id: 'err_catch_${DateTime.now().millisecondsSinceEpoch}',
          sender: ChatSender.ai,
          text: '⚠️ មានបញ្ហាប្រព័ន្ធ: $e',
        ),
      );
      setState(() => _isAnalyzing = false);
      _scrollToBottom();
    }
  }

  // ─── Auto Save Session ────────────────────────────────────────────────────

  Future<void> _autoSaveCurrentSession() async {
    if (_currentAnalysis == null) return;
    _currentSessionId ??= 'session_${DateTime.now().millisecondsSinceEpoch}';

    final session = SavedProductSession(
      id: _currentSessionId!,
      title: _currentAnalysis!.productName,
      brand: _currentAnalysis!.brand,
      country: _currentAnalysis!.countryOfOrigin,
      countryFlag: _currentAnalysis!.countryFlagEmoji,
      category: _currentAnalysis!.category,
      folderId: _currentFolderId,
      folderName: _currentFolderName,
      barcode: _currentBarcode ?? '',
      imageBase64: _currentImageBase64,
      analysis: _currentAnalysis!,
      chatHistory: _messages.map((m) => m.toJson()).toList(),
      savedAt: DateTime.now(),
    );

    await ProductStorageService.saveOrUpdateProduct(session);
    await _loadFoldersAndHistory();
  }

  // ─── Follow-up Q&A Chatbot ────────────────────────────────────────────────

  Future<void> _sendFollowUpMessage(String question) async {
    final text = question.trim();
    if (text.isEmpty) return;

    _textCtrl.clear();
    _hapticLight();

    // Add user question
    _messages.add(
      ChatMessageItem(
        id: 'user_q_${DateTime.now().millisecondsSinceEpoch}',
        sender: ChatSender.user,
        text: text,
      ),
    );

    setState(() => _isAiResponding = true);
    _scrollToBottom();

    // Prepare context
    String contextStr = '';
    if (_currentAnalysis != null) {
      final a = _currentAnalysis!;
      contextStr = 'ឈ្មោះផលិតផល: ${a.productName}\n'
          'ម៉ាក: ${a.brand}\n'
          'ប្រទេស: ${a.countryOfOrigin} (${a.countryFlagEmoji})\n'
          'ជំពូក: ${a.category}\n'
          'តម្លៃ: ${a.priceRangeUsd}\n'
          'សង្ខេប: ${a.summary}\n'
          'របៀបប្រើ: ${a.usage.join(', ')}\n'
          'អត្ថប្រយោជន៍: ${a.benefits.join(', ')}\n'
          'ការប្រុងប្រយ័ត្ន: ${a.warnings.join(', ')}\n'
          'សារធាតុផ្សំ: ${a.ingredientsSummary}';
    }

    try {
      final res = await _api.productChat(
        question: text,
        productContext: contextStr,
        history: _messages
            .where((m) => m.analysis == null && !m.isLoading)
            .map((m) => {
                  'role': m.sender == ChatSender.user ? 'user' : 'assistant',
                  'content': m.text,
                })
            .toList(),
      );

      final reply = res['reply']?.toString() ??
          res['message']?.toString() ??
          'អរគុណសម្រាប់សំណួរ។ ខ្ញុំមិនអាចរកចម្លើយបាននៅពេលនេះទេ។';

      _messages.add(
        ChatMessageItem(
          id: 'ai_reply_${DateTime.now().millisecondsSinceEpoch}',
          sender: ChatSender.ai,
          text: reply,
        ),
      );

      setState(() => _isAiResponding = false);
      _scrollToBottom();
      _autoSaveCurrentSession();
    } catch (e) {
      _messages.add(
        ChatMessageItem(
          id: 'ai_err_${DateTime.now().millisecondsSinceEpoch}',
          sender: ChatSender.ai,
          text: '⚠️ មិនអាចទាក់ទង AI បានទេ: $e',
        ),
      );
      setState(() => _isAiResponding = false);
      _scrollToBottom();
    }
  }

  // ─── Restore Saved Product from History (0 API calls) ────────────────────

  void _restoreSavedProduct(SavedProductSession saved) {
    _hapticLight();
    Navigator.pop(context); // Close history sheet

    setState(() {
      _currentSessionId = saved.id;
      _currentAnalysis = saved.analysis;
      _currentBarcode = saved.barcode.isNotEmpty ? saved.barcode : null;
      _currentImageBase64 = saved.imageBase64;
      if (saved.imageBase64 != null &&
          saved.imageBase64!.startsWith('data:image')) {
        try {
          final b64Part = saved.imageBase64!.split(',').last;
          _currentImageBytes = base64Decode(b64Part);
        } catch (_) {
          _currentImageBytes = null;
        }
      } else {
        _currentImageBytes = null;
      }
      _currentFolderId = saved.folderId;
      _currentFolderName = saved.folderName;

      _messages.clear();

      // Restore chat messages or build structured cards
      if (saved.chatHistory.isNotEmpty) {
        for (final mJson in saved.chatHistory) {
          final m = ChatMessageItem.fromJson(mJson);
          _messages.add(m);
        }
      } else {
        _messages.add(
          ChatMessageItem(
            id: 'restored_res_${saved.id}',
            sender: ChatSender.ai,
            text: 'លទ្ធផលវិភាគដែលបានរក្សាទុក',
            analysis: saved.analysis,
          ),
        );
      }
    });

    _showToast('បានបើកទិន្នន័យផលិតផល "${saved.title}" ភ្លាមៗ');
    _scrollToBottom();
  }

  // ─── Folder Management Modals ────────────────────────────────────────────

  void _openMoveToFolderSheet(SavedProductSession? session) {
    _hapticLight();
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => _buildMoveToFolderModal(session),
    );
  }

  Widget _buildMoveToFolderModal(SavedProductSession? targetSession) {
    final curFolderId = targetSession?.folderId ?? _currentFolderId;
    return Container(
      padding: EdgeInsets.fromLTRB(
          20, 16, 20, MediaQuery.paddingOf(context).bottom + 20),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
        border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Center(
            child: Container(
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: Colors.white24,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                '📁 ដាក់ក្នុង Folder',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 17,
                ),
              ),
              TextButton.icon(
                onPressed: () {
                  Navigator.pop(context);
                  _openCreateFolderDialog();
                },
                icon: const Icon(Icons.add_rounded,
                    color: Color(0xFFA78BFA), size: 18),
                label: Text(
                  'Folder ថ្មី',
                  style: GoogleFonts.kantumruyPro(
                    color: const Color(0xFFA78BFA),
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          // None / Uncategorized option
          ListTile(
            shape:
                RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
            tileColor: curFolderId == null
                ? const Color(0xFF7C3AED).withValues(alpha: 0.15)
                : Colors.transparent,
            leading: const Icon(Icons.folder_off_rounded, color: Colors.grey),
            title: Text(
              'គ្មាន Folder (Uncategorized)',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: curFolderId == null
                    ? FontWeight.bold
                    : FontWeight.normal,
              ),
            ),
            trailing: curFolderId == null
                ? const Icon(Icons.check_circle_rounded,
                    color: Color(0xFF10B981))
                : null,
            onTap: () async {
              Navigator.pop(context);
              if (targetSession != null) {
                await ProductStorageService.updateProductFolder(
                    targetSession.id, null, null);
              } else if (_currentSessionId != null) {
                await ProductStorageService.updateProductFolder(
                    _currentSessionId!, null, null);
                setState(() {
                  _currentFolderId = null;
                  _currentFolderName = null;
                });
              }
              await _loadFoldersAndHistory();
              _showToast('បានផ្លាស់ទីទៅកាន់ "គ្មាន Folder"');
            },
          ),
          const Divider(color: Colors.white12),
          ..._folders.map((folder) {
            final isSelected = curFolderId == folder.id;
            return ListTile(
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14)),
              tileColor: isSelected
                  ? const Color(0xFF7C3AED).withValues(alpha: 0.15)
                  : Colors.transparent,
              leading: Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Color(folder.colorHex).withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(Icons.folder_rounded,
                    color: Color(folder.colorHex), size: 20),
              ),
              title: Text(
                folder.name,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight:
                      isSelected ? FontWeight.bold : FontWeight.normal,
                ),
              ),
              trailing: isSelected
                  ? const Icon(Icons.check_circle_rounded,
                      color: Color(0xFF10B981))
                  : null,
              onTap: () async {
                Navigator.pop(context);
                if (targetSession != null) {
                  await ProductStorageService.updateProductFolder(
                      targetSession.id, folder.id, folder.name);
                } else if (_currentSessionId != null) {
                  await ProductStorageService.updateProductFolder(
                      _currentSessionId!, folder.id, folder.name);
                  setState(() {
                    _currentFolderId = folder.id;
                    _currentFolderName = folder.name;
                  });
                }
                await _loadFoldersAndHistory();
                _showToast('បានដាក់ក្នុង Folder "${folder.name}" រួចរាល់');
              },
            );
          }),
        ],
      ),
    );
  }

  void _openCreateFolderDialog() {
    final ctrl = TextEditingController();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1B4B),
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Row(
          children: [
            const Icon(Icons.create_new_folder_rounded,
                color: Color(0xFFA78BFA)),
            const SizedBox(width: 8),
            Text(
              'បង្កើត Folder ថ្មី',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 17,
              ),
            ),
          ],
        ),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          style: GoogleFonts.kantumruyPro(color: Colors.white),
          decoration: InputDecoration(
            hintText: 'ឧ. គ្រឿងសំអាង, អាហារបំប៉ន...',
            hintStyle: GoogleFonts.kantumruyPro(color: Colors.white38),
            filled: true,
            fillColor: Colors.white.withValues(alpha: 0.05),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(12),
              borderSide:
                  const BorderSide(color: Color(0xFF7C3AED), width: 1.5),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text('បោះបង់',
                style: GoogleFonts.kantumruyPro(color: Colors.white60)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF7C3AED),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10)),
            ),
            onPressed: () async {
              final name = ctrl.text.trim();
              if (name.isNotEmpty) {
                Navigator.pop(ctx);
                await ProductStorageService.createFolder(name);
                await _loadFoldersAndHistory();
                _showToast('បានបង្កើត Folder "$name" ដោយជោគជ័យ');
              }
            },
            child: Text('បង្កើត',
                style: GoogleFonts.kantumruyPro(
                    color: Colors.white, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  void _openRenameFolderDialog(ProductFolder folder) {
    final ctrl = TextEditingController(text: folder.name);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1B4B),
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Row(
          children: [
            const Icon(Icons.edit_note_rounded, color: Color(0xFFA78BFA)),
            const SizedBox(width: 8),
            Text(
              'ប្តូរឈ្មោះ Folder',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 17,
              ),
            ),
          ],
        ),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          style: GoogleFonts.kantumruyPro(color: Colors.white),
          decoration: InputDecoration(
            filled: true,
            fillColor: Colors.white.withValues(alpha: 0.05),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(12),
              borderSide:
                  const BorderSide(color: Color(0xFF7C3AED), width: 1.5),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text('បោះបង់',
                style: GoogleFonts.kantumruyPro(color: Colors.white60)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF7C3AED),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10)),
            ),
            onPressed: () async {
              final name = ctrl.text.trim();
              if (name.isNotEmpty) {
                Navigator.pop(ctx);
                await ProductStorageService.renameFolder(folder.id, name);
                await _loadFoldersAndHistory();
                _showToast('បានប្តូរឈ្មោះ Folder ជា "$name"');
              }
            },
            child: Text('រក្សាទុក',
                style: GoogleFonts.kantumruyPro(
                    color: Colors.white, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  void _openRenameProductDialog(SavedProductSession session) {
    final ctrl = TextEditingController(text: session.title);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E1B4B),
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Row(
          children: [
            const Icon(Icons.drive_file_rename_outline_rounded,
                color: Color(0xFFA78BFA)),
            const SizedBox(width: 8),
            Text(
              'ប្តូរឈ្មោះផលិតផល',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 17,
              ),
            ),
          ],
        ),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          style: GoogleFonts.kantumruyPro(color: Colors.white),
          decoration: InputDecoration(
            filled: true,
            fillColor: Colors.white.withValues(alpha: 0.05),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(12),
              borderSide:
                  const BorderSide(color: Color(0xFF7C3AED), width: 1.5),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text('បោះបង់',
                style: GoogleFonts.kantumruyPro(color: Colors.white60)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF7C3AED),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(10)),
            ),
            onPressed: () async {
              final name = ctrl.text.trim();
              if (name.isNotEmpty) {
                Navigator.pop(ctx);
                await ProductStorageService.renameProduct(session.id, name);
                await _loadFoldersAndHistory();
                if (_currentSessionId == session.id) {
                  setState(() => session.title = name);
                }
                _showToast('បានប្តូរឈ្មោះជា "$name"');
              }
            },
            child: Text('រក្សាទុក',
                style: GoogleFonts.kantumruyPro(
                    color: Colors.white, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  // ─── History & Folders BottomSheet ───────────────────────────────────────

  void _openHistoryModal() {
    _hapticLight();
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => _HistoryAndFoldersSheet(
        folders: _folders,
        history: _savedHistory,
        onSelectProduct: _restoreSavedProduct,
        onCreateFolder: _openCreateFolderDialog,
        onRenameFolder: _openRenameFolderDialog,
        onRenameProduct: _openRenameProductDialog,
        onMoveProduct: _openMoveToFolderSheet,
        onDeleteProduct: (id) async {
          await ProductStorageService.deleteProduct(id);
          await _loadFoldersAndHistory();
          _showToast('បានលុបផលិតផលពី History');
        },
        onDeleteFolder: (id) async {
          await ProductStorageService.deleteFolder(id);
          await _loadFoldersAndHistory();
          _showToast('បានលុប Folder');
        },
      ),
    );
  }

  void _showToast(String msg, {bool isError = false}) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          msg,
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13),
        ),
        backgroundColor:
            isError ? Colors.redAccent : const Color(0xFF10B981),
        duration: const Duration(seconds: 2),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
    );
  }

  // ─── Build UI ─────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: Stack(
        children: [
          SafeArea(
            child: Column(
              children: [
                _buildHeader(),
                Expanded(child: _buildChatStream()),
                if (_isAiResponding) _buildAiTypingBar(),
                _buildBottomInputBar(),
              ],
            ),
          ),
          if (_showBarcodeScanner) _buildBarcodeScannerOverlay(),
        ],
      ),
    );
  }

  // ─── Top Header ───────────────────────────────────────────────────────────

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        border: Border(
          bottom: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
        ),
      ),
      child: Row(
        children: [
          IconButton(
            icon: const Icon(Icons.arrow_back_ios_new_rounded,
                color: Colors.white, size: 20),
            onPressed: () => Navigator.pop(context),
          ),
          Container(
            width: 38,
            height: 38,
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF7C3AED), Color(0xFF4F46E5)],
              ),
              borderRadius: BorderRadius.circular(12),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFF7C3AED).withValues(alpha: 0.4),
                  blurRadius: 10,
                )
              ],
            ),
            child: const Icon(Icons.smart_toy_rounded,
                color: Colors.white, size: 22),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      'AI Product Analyzer',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 15,
                      ),
                    ),
                    const SizedBox(width: 6),
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 6, vertical: 1.5),
                      decoration: BoxDecoration(
                        gradient: const LinearGradient(
                          colors: [Color(0xFF6366F1), Color(0xFFA855F7)],
                        ),
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(
                        'Gemini',
                        style: GoogleFonts.inter(
                          color: Colors.white,
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
                  ],
                ),
                Text(
                  _currentFolderName != null
                      ? '📁 $_currentFolderName'
                      : 'ជំនួយការឆ្លាតវៃវិភាគផលិតផល',
                  style: GoogleFonts.kantumruyPro(
                    color: _currentFolderName != null
                        ? const Color(0xFFA78BFA)
                        : AppTheme.textMuted,
                    fontSize: 11,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          // History & Folders Button with Badge
          GestureDetector(
            onTap: _openHistoryModal,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: const Color(0xFF7C3AED).withValues(alpha: 0.18),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: const Color(0xFF7C3AED).withValues(alpha: 0.4),
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.folder_open_rounded,
                      color: Color(0xFFA78BFA), size: 18),
                  const SizedBox(width: 5),
                  Text(
                    '${_savedHistory.length}',
                    style: GoogleFonts.inter(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(width: 6),
          // Reset / New Session
          IconButton(
            tooltip: 'ចាប់ផ្តើមថ្មី',
            icon: const Icon(Icons.add_comment_outlined,
                color: Colors.white70, size: 22),
            onPressed: () {
              _hapticLight();
              setState(() {
                _initWelcomeChat();
              });
              _showToast('បានចាប់ផ្តើមការសន្ទនាថ្មី');
            },
          ),
        ],
      ),
    );
  }

  // ─── Chat Stream ──────────────────────────────────────────────────────────

  Widget _buildChatStream() {
    return ListView.builder(
      controller: _scrollCtrl,
      padding: const EdgeInsets.fromLTRB(14, 14, 14, 20),
      itemCount: _messages.length,
      itemBuilder: (ctx, i) {
        final msg = _messages[i];
        if (msg.id == 'welcome_msg') {
          return _buildWelcomeBubble(msg);
        }
        if (msg.sender == ChatSender.user) {
          return _buildUserBubble(msg);
        } else {
          return _buildAiBubble(msg);
        }
      },
    );
  }

  // ─── Welcome Bubble ───────────────────────────────────────────────────────

  Widget _buildWelcomeBubble(ChatMessageItem msg) {
    return FadeInDown(
      duration: const Duration(milliseconds: 350),
      child: Container(
        margin: const EdgeInsets.only(bottom: 20),
        padding: const EdgeInsets.all(18),
        decoration: BoxDecoration(
          gradient: const LinearGradient(
            colors: [Color(0xFF1E1B4B), Color(0xFF0F172A)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.circular(22),
          border: Border.all(
            color: const Color(0xFF7C3AED).withValues(alpha: 0.3),
          ),
          boxShadow: [
            BoxShadow(
              color: const Color(0xFF7C3AED).withValues(alpha: 0.15),
              blurRadius: 18,
              offset: const Offset(0, 4),
            )
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: const Color(0xFF7C3AED).withValues(alpha: 0.25),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: const Icon(Icons.auto_awesome_rounded,
                      color: Color(0xFFA78BFA), size: 20),
                ),
                const SizedBox(width: 10),
                Text(
                  'Chatbot Product Analyzer',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text(
              msg.text,
              style: GoogleFonts.kantumruyPro(
                color: const Color(0xFFE2E8F0),
                fontSize: 13.5,
                height: 1.5,
              ),
            ),
            const SizedBox(height: 16),
            // Quick Action Buttons Grid
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                _buildQuickActionBtn(
                  icon: Icons.camera_alt_rounded,
                  label: 'ថតរូបភាព',
                  color: const Color(0xFF7C3AED),
                  onTap: () => _pickImage(ImageSource.camera),
                ),
                _buildQuickActionBtn(
                  icon: Icons.photo_library_rounded,
                  label: 'ជ្រើសរូប Gallery',
                  color: const Color(0xFF0EA5E9),
                  onTap: () => _pickImage(ImageSource.gallery),
                ),
                _buildQuickActionBtn(
                  icon: Icons.qr_code_scanner_rounded,
                  label: 'Scan Barcode',
                  color: const Color(0xFF10B981),
                  onTap: _openBarcodeScanner,
                ),
                _buildQuickActionBtn(
                  icon: Icons.folder_special_rounded,
                  label: 'ប្រវត្តិ & Folders (${_savedHistory.length})',
                  color: const Color(0xFFF59E0B),
                  onTap: _openHistoryModal,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildQuickActionBtn({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: () {
        _hapticLight();
        onTap();
      },
      borderRadius: BorderRadius.circular(12),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.15),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withValues(alpha: 0.35)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: color, size: 16),
            const SizedBox(width: 6),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.w600,
                fontSize: 12.5,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ─── User Message Bubble ──────────────────────────────────────────────────

  Widget _buildUserBubble(ChatMessageItem msg) {
    return FadeInRight(
      duration: const Duration(milliseconds: 250),
      child: Align(
        alignment: Alignment.centerRight,
        child: Container(
          margin: const EdgeInsets.only(bottom: 12, left: 40),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: BoxDecoration(
            gradient: const LinearGradient(
              colors: [Color(0xFF6D28D9), Color(0xFF4F46E5)],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            borderRadius: const BorderRadius.only(
              topLeft: Radius.circular(18),
              topRight: Radius.circular(4),
              bottomLeft: Radius.circular(18),
              bottomRight: Radius.circular(18),
            ),
            boxShadow: [
              BoxShadow(
                color: const Color(0xFF6D28D9).withValues(alpha: 0.25),
                blurRadius: 10,
                offset: const Offset(0, 3),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              if (msg.imageBytes != null) ...[
                ClipRRect(
                  borderRadius: BorderRadius.circular(12),
                  child: ConstrainedBox(
                    constraints:
                        const BoxConstraints(maxHeight: 180, maxWidth: 220),
                    child: Image.memory(msg.imageBytes!, fit: BoxFit.cover),
                  ),
                ),
                const SizedBox(height: 8),
              ],
              if (msg.barcode != null) ...[
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.qr_code_2_rounded,
                        color: Colors.white70, size: 18),
                    const SizedBox(width: 6),
                    Text(
                      msg.barcode!,
                      style: GoogleFonts.inter(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 13,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
              ],
              Text(
                msg.text,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 14,
                  height: 1.4,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  // ─── AI Message Bubble ────────────────────────────────────────────────────

  Widget _buildAiBubble(ChatMessageItem msg) {
    if (msg.isLoading) {
      return _buildAiThinkingBubble();
    }

    if (msg.analysis != null) {
      return _buildProductAnalysisCard(msg.analysis!);
    }

    return FadeInLeft(
      duration: const Duration(milliseconds: 250),
      child: Align(
        alignment: Alignment.centerLeft,
        child: Container(
          margin: const EdgeInsets.only(bottom: 12, right: 36),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: const BorderRadius.only(
              topLeft: Radius.circular(4),
              topRight: Radius.circular(18),
              bottomLeft: Radius.circular(18),
              bottomRight: Radius.circular(18),
            ),
            border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.smart_toy_rounded,
                      color: Color(0xFFA78BFA), size: 16),
                  const SizedBox(width: 6),
                  Text(
                    'AI Assistant',
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFFA78BFA),
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                msg.text,
                style: GoogleFonts.kantumruyPro(
                  color: const Color(0xFFF1F5F9),
                  fontSize: 14,
                  height: 1.5,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildAiThinkingBubble() {
    return FadeIn(
      child: Container(
        margin: const EdgeInsets.only(bottom: 14, right: 40),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: const Color(0xFF1E1B4B),
          borderRadius: BorderRadius.circular(18),
          border: Border.all(
            color: const Color(0xFF7C3AED).withValues(alpha: 0.3),
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const SizedBox(
              width: 18,
              height: 18,
              child: CircularProgressIndicator(
                strokeWidth: 2.5,
                valueColor: AlwaysStoppedAnimation(Color(0xFFA78BFA)),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'AI កំពុងវិភាគ និងស្រាវជ្រាវ...',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  Text(
                    'រយៈពេល: ${_formatElapsed(_elapsedSeconds)}',
                    style: GoogleFonts.inter(
                      color: const Color(0xFFA78BFA),
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAiTypingBar() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 8),
      color: AppTheme.bgDark,
      child: Row(
        children: [
          const SizedBox(
            width: 14,
            height: 14,
            child: CircularProgressIndicator(
              strokeWidth: 2,
              valueColor: AlwaysStoppedAnimation(Color(0xFFA78BFA)),
            ),
          ),
          const SizedBox(width: 8),
          Text(
            'AI កំពុងឆ្លើយតប...',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white70,
              fontSize: 12,
            ),
          ),
        ],
      ),
    );
  }

  // ─── Product Analysis Card in Chat ────────────────────────────────────────

  Widget _buildProductAnalysisCard(ProductAnalysis r) {
    return FadeInUp(
      duration: const Duration(milliseconds: 350),
      child: Container(
        margin: const EdgeInsets.only(bottom: 16),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(22),
          border: Border.all(
            color: const Color(0xFF7C3AED).withValues(alpha: 0.35),
            width: 1.2,
          ),
          boxShadow: [
            BoxShadow(
              color: const Color(0xFF7C3AED).withValues(alpha: 0.12),
              blurRadius: 16,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header: Flag / Image, Name, Brand
            Container(
              padding: const EdgeInsets.all(18),
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  colors: [Color(0xFF2E1065), Color(0xFF0F172A)],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                borderRadius:
                    BorderRadius.vertical(top: Radius.circular(21)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      if (_currentImageBytes != null) ...[
                        ClipRRect(
                          borderRadius: BorderRadius.circular(10),
                          child: Image.memory(_currentImageBytes!,
                              width: 44, height: 44, fit: BoxFit.cover),
                        ),
                        const SizedBox(width: 10),
                      ] else ...[
                        Text(r.countryFlagEmoji,
                            style: const TextStyle(fontSize: 42)),
                        const SizedBox(width: 12),
                      ],
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              r.productName,
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white,
                                fontWeight: FontWeight.w800,
                                fontSize: 18,
                                height: 1.3,
                              ),
                            ),
                            if (r.brand.isNotEmpty && r.brand != '—') ...[
                              const SizedBox(height: 3),
                              Text(
                                r.brand,
                                style: GoogleFonts.inter(
                                  color: const Color(0xFFA78BFA),
                                  fontSize: 13.5,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ],
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  // Pills
                  Wrap(
                    spacing: 6,
                    runSpacing: 6,
                    children: [
                      _buildMiniBadge(
                        Icons.flag_rounded,
                        r.countryOfOrigin,
                        const Color(0xFF0EA5E9),
                      ),
                      _buildMiniBadge(
                        Icons.category_rounded,
                        r.category,
                        const Color(0xFF10B981),
                      ),
                      if (r.priceRangeUsd.isNotEmpty &&
                          r.priceRangeUsd != '—')
                        _buildMiniBadge(
                          Icons.attach_money_rounded,
                          r.priceRangeUsd,
                          const Color(0xFFF59E0B),
                        ),
                      if (_currentFolderName != null)
                        _buildMiniBadge(
                          Icons.folder_rounded,
                          _currentFolderName!,
                          const Color(0xFF8B5CF6),
                        ),
                    ],
                  ),
                ],
              ),
            ),

            // Live Web Grounding Banner
            if (r.isWebGrounded || r.webSources.isNotEmpty)
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  color: const Color(0xFF0284C7).withValues(alpha: 0.12),
                  border: Border(
                    bottom: BorderSide(
                        color:
                            const Color(0xFF38BDF8).withValues(alpha: 0.2)),
                  ),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.travel_explore_rounded,
                        color: Color(0xFF38BDF8), size: 16),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'ផ្ទៀងផ្ទាត់ផ្ទាល់ពី Google Search (Live Web Grounding)',
                        style: GoogleFonts.kantumruyPro(
                          color: const Color(0xFF38BDF8),
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ],
                ),
              ),

            // Dedicated Drinkware / Water Bottle Spec Card
            if (r.isBottleOrDrinkware)
              Container(
                margin: const EdgeInsets.fromLTRB(14, 12, 14, 4),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      const Color(0xFF0284C7).withValues(alpha: 0.18),
                      const Color(0xFF0D9488).withValues(alpha: 0.14),
                    ],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(
                    color: const Color(0xFF38BDF8).withValues(alpha: 0.35),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.water_drop_rounded,
                            color: Color(0xFF38BDF8), size: 17),
                        const SizedBox(width: 6),
                        Text(
                          'ព័ត៌មានលម្អិតដបទឹក & កែវរក្សាកម្តៅ (Drinkware Specs)',
                          style: GoogleFonts.kantumruyPro(
                            color: const Color(0xFF38BDF8),
                            fontSize: 12.5,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        if (r.detectedCapacity != null)
                          _buildBottleFeatureChip(
                            icon: Icons.local_drink_rounded,
                            label: 'ចំណុះ: ${r.detectedCapacity}',
                            color: const Color(0xFF0EA5E9),
                          ),
                        if (r.detectedMaterial != null)
                          _buildBottleFeatureChip(
                            icon: Icons.layers_rounded,
                            label: r.detectedMaterial!,
                            color: const Color(0xFF10B981),
                          ),
                        if (r.detectedInsulation != null)
                          _buildBottleFeatureChip(
                            icon: Icons.thermostat_rounded,
                            label: r.detectedInsulation!,
                            color: const Color(0xFFF59E0B),
                          ),
                        _buildBottleFeatureChip(
                          icon: Icons.lock_outline_rounded,
                          label: 'ការពារជ្រាបទឹក 100% & BPA-Free',
                          color: const Color(0xFF8B5CF6),
                        ),
                      ],
                    ),
                  ],
                ),
              ),

            // Action Toolbar: Move to Folder | Rename | Re-search | Copy
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.03),
                border: Border(
                  bottom: BorderSide(
                      color: Colors.white.withValues(alpha: 0.06)),
                ),
              ),
              child: Row(
                children: [
                  _buildToolbarBtn(
                    icon: Icons.create_new_folder_rounded,
                    label: _currentFolderName ?? 'ដាក់ក្នុង Folder',
                    color: const Color(0xFFA78BFA),
                    onTap: () => _openMoveToFolderSheet(null),
                  ),
                  const Spacer(),
                  _buildToolbarIcon(
                    icon: Icons.copy_rounded,
                    tooltip: 'ចម្លង',
                    onTap: () {
                      Clipboard.setData(ClipboardData(
                          text: '${r.productName}\n${r.summary}'));
                      _showToast('បានចម្លងព័ត៌មាន');
                    },
                  ),
                  _buildToolbarIcon(
                    icon: Icons.refresh_rounded,
                    tooltip: 'ស្រាវជ្រាវម្តងទៀត',
                    onTap: () => _runAnalysis(force: true),
                  ),
                ],
              ),
            ),

            // Summary Section
            if (r.summary.isNotEmpty)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 14, 16, 10),
                child: Text(
                  r.summary,
                  style: GoogleFonts.kantumruyPro(
                    color: const Color(0xFFF1F5F9),
                    fontSize: 14,
                    height: 1.55,
                  ),
                ),
              ),

            // Details Tabs / Accordion
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
              child: Column(
                children: [
                  if (r.usage.isNotEmpty)
                    _buildSectionBlock(
                      icon: r.isBottleOrDrinkware
                          ? Icons.water_drop_outlined
                          : Icons.play_circle_outline_rounded,
                      color: const Color(0xFF0EA5E9),
                      title: r.isBottleOrDrinkware
                          ? 'របៀបប្រើប្រាស់ & ការថែទាំដប'
                          : 'របៀបប្រើប្រាស់',
                      items: r.usage,
                    ),
                  if (r.benefits.isNotEmpty)
                    _buildSectionBlock(
                      icon: Icons.star_outline_rounded,
                      color: const Color(0xFFF59E0B),
                      title: r.isBottleOrDrinkware
                          ? 'អត្ថប្រយោជន៍ & សមត្ថភាពរក្សាសីតុណ្ហភាព'
                          : 'អត្ថប្រយោជន៍',
                      items: r.benefits,
                    ),
                  if (r.warnings.isNotEmpty)
                    _buildSectionBlock(
                      icon: Icons.warning_amber_rounded,
                      color: Colors.orangeAccent,
                      title: r.isBottleOrDrinkware
                          ? 'ការប្រុងប្រយ័ត្នចំពោះដបទឹក'
                          : 'ការប្រុងប្រយ័ត្ន',
                      items: r.warnings,
                    ),
                  if (r.ingredientsSummary.isNotEmpty &&
                      r.ingredientsSummary != '—')
                    _buildTextSectionBlock(
                      icon: r.isBottleOrDrinkware
                          ? Icons.layers_rounded
                          : Icons.science_outlined,
                      color: r.isBottleOrDrinkware
                          ? const Color(0xFF06B6D4)
                          : const Color(0xFF8B5CF6),
                      title: r.isBottleOrDrinkware
                          ? 'សម្ភារៈ & លក្ខណៈបច្ចេកទេស'
                          : 'សារធាតុផ្សំ',
                      text: r.ingredientsSummary,
                    ),
                ],
              ),
            ),

            // Suggested Follow-up Questions
            Container(
              padding: const EdgeInsets.fromLTRB(14, 10, 14, 14),
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.2),
                borderRadius: const BorderRadius.vertical(
                    bottom: Radius.circular(21)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.lightbulb_outline_rounded,
                          color: Color(0xFFFCD34D), size: 15),
                      const SizedBox(width: 6),
                      Text(
                        'សំណួរណែនាំ (ចុចដើម្បីសួរ AI):',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white70,
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Wrap(
                    spacing: 6,
                    runSpacing: 6,
                    children: r.isBottleOrDrinkware
                        ? [
                            _buildSuggestionChip('❄️ តើដបនេះរក្សាត្រជាក់ និងកម្តៅបានប៉ុន្មានម៉ោង?'),
                            _buildSuggestionChip('🛡️ តើផលិតពីដែកអ៊ីណុក SUS 304 ឬ 316 និងមាន BPA-Free ទេ?'),
                            _buildSuggestionChip('🧼 តើត្រូវលាងសម្អាត និងដោះកៅស៊ូគម្របយ៉ាងដូចម្តេច?'),
                            _buildSuggestionChip('⚠️ តើអាចដាក់ភេសជ្ជៈហ្គាស ឬទឹកដោះគោបានទេ?'),
                            _buildSuggestionChip('🚫 តើអាចដាក់ក្នុង Microwave ឬម៉ាស៊ីនលាងចានបានទេ?'),
                          ]
                        : [
                            _buildSuggestionChip('តើផលិតផលនេះក្មេងប្រើបានទេ?'),
                            _buildSuggestionChip('តើមានផលប៉ះពាល់ស្បែក ឬរាងកាយទេ?'),
                            _buildSuggestionChip('តើត្រូវរក្សាទុកយ៉ាងដូចម្តេច?'),
                            _buildSuggestionChip('តើមានសារធាតុគីមីគ្រោះថ្នាក់ទេ?'),
                          ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildBottleFeatureChip({
    required IconData icon,
    required String label,
    required Color color,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.16),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, color: color, size: 14),
          const SizedBox(width: 5),
          ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 240),
            child: Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 11.5,
                fontWeight: FontWeight.w600,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMiniBadge(IconData icon, String text, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.16),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, color: color, size: 12),
          const SizedBox(width: 4),
          ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 160),
            child: Text(
              text,
              style: GoogleFonts.kantumruyPro(
                color: color,
                fontSize: 11.5,
                fontWeight: FontWeight.w600,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildToolbarBtn({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: () {
        _hapticLight();
        onTap();
      },
      borderRadius: BorderRadius.circular(8),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: color, size: 16),
            const SizedBox(width: 6),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: color,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildToolbarIcon({
    required IconData icon,
    required String tooltip,
    required VoidCallback onTap,
  }) {
    return IconButton(
      tooltip: tooltip,
      icon: Icon(icon, color: Colors.white70, size: 18),
      padding: EdgeInsets.zero,
      constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
      onPressed: () {
        _hapticLight();
        onTap();
      },
    );
  }

  Widget _buildSectionBlock({
    required IconData icon,
    required Color color,
    required String title,
    required List<String> items,
  }) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.03),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: color, size: 16),
              const SizedBox(width: 6),
              Text(
                title,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 13.5,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          ...items.map((it) => Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('• ',
                        style: TextStyle(color: color, fontSize: 14)),
                    Expanded(
                      child: Text(
                        it,
                        style: GoogleFonts.kantumruyPro(
                          color: const Color(0xFFE2E8F0),
                          fontSize: 13,
                          height: 1.4,
                        ),
                      ),
                    ),
                  ],
                ),
              )),
        ],
      ),
    );
  }

  Widget _buildTextSectionBlock({
    required IconData icon,
    required Color color,
    required String title,
    required String text,
  }) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.03),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: color, size: 16),
              const SizedBox(width: 6),
              Text(
                title,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 13.5,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            text,
            style: GoogleFonts.kantumruyPro(
              color: const Color(0xFFE2E8F0),
              fontSize: 13,
              height: 1.4,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSuggestionChip(String text) {
    return InkWell(
      onTap: () => _sendFollowUpMessage(text),
      borderRadius: BorderRadius.circular(10),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
          color: const Color(0xFF7C3AED).withValues(alpha: 0.15),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: const Color(0xFF7C3AED).withValues(alpha: 0.35),
          ),
        ),
        child: Text(
          text,
          style: GoogleFonts.kantumruyPro(
            color: const Color(0xFFDDD6FE),
            fontSize: 11.5,
            fontWeight: FontWeight.w500,
          ),
        ),
      ),
    );
  }

  // ─── Bottom Chat Input Bar ────────────────────────────────────────────────

  Widget _buildBottomInputBar() {
    return Container(
      padding: EdgeInsets.fromLTRB(
        12,
        8,
        12,
        MediaQuery.paddingOf(context).bottom + 8,
      ),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        border: Border(
          top: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
        ),
      ),
      child: Row(
        children: [
          // Attachment Menu Button
          IconButton(
            icon: const Icon(Icons.add_circle_outline_rounded,
                color: Color(0xFFA78BFA), size: 26),
            onPressed: _showAttachmentSheet,
          ),
          // Text Input Field
          Expanded(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 14),
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.06),
                borderRadius: BorderRadius.circular(22),
                border: Border.all(
                    color: Colors.white.withValues(alpha: 0.1)),
              ),
              child: TextField(
                controller: _textCtrl,
                style: GoogleFonts.kantumruyPro(
                    color: Colors.white, fontSize: 13.5),
                decoration: InputDecoration(
                  hintText: 'សួរបន្ថែមអំពីផលិតផលនេះ...',
                  hintStyle: GoogleFonts.kantumruyPro(
                    color: Colors.white38,
                    fontSize: 13,
                  ),
                  border: InputBorder.none,
                  contentPadding: const EdgeInsets.symmetric(vertical: 10),
                ),
                onSubmitted: _sendFollowUpMessage,
              ),
            ),
          ),
          const SizedBox(width: 8),
          // Send Button
          GestureDetector(
            onTap: (_isAnalyzing || _isAiResponding)
                ? null
                : () => _sendFollowUpMessage(_textCtrl.text),
            child: Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                gradient: (_isAnalyzing || _isAiResponding)
                    ? const LinearGradient(
                        colors: [Colors.grey, Colors.black45],
                      )
                    : const LinearGradient(
                        colors: [Color(0xFF7C3AED), Color(0xFF4F46E5)],
                      ),
                shape: BoxShape.circle,
                boxShadow: [
                  if (!_isAnalyzing && !_isAiResponding)
                    BoxShadow(
                      color: const Color(0xFF7C3AED).withValues(alpha: 0.4),
                      blurRadius: 8,
                    )
                ],
              ),
              child: (_isAnalyzing || _isAiResponding)
                  ? const Center(
                      child: SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          valueColor: AlwaysStoppedAnimation(Colors.white70),
                        ),
                      ),
                    )
                  : const Icon(Icons.send_rounded,
                      color: Colors.white, size: 18),
            ),
          ),
        ],
      ),
    );
  }

  void _showAttachmentSheet() {
    _hapticLight();
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (ctx) => Container(
        padding: EdgeInsets.fromLTRB(
            20, 16, 20, MediaQuery.paddingOf(context).bottom + 20),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius:
              const BorderRadius.vertical(top: Radius.circular(24)),
          border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Center(
              child: Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: Colors.white24,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 16),
            Text(
              'ជ្រើសរើសវិធីវិភាគផលិតផល',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            const SizedBox(height: 16),
            ListTile(
              leading: Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: const Color(0xFF7C3AED).withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(Icons.camera_alt_rounded,
                    color: Color(0xFFA78BFA)),
              ),
              title: Text('ថតរូបភាពថ្មី',
                  style: GoogleFonts.kantumruyPro(color: Colors.white)),
              subtitle: Text('ប្រើ Camera ថតរូបកញ្ចប់ ឬដបផលិតផល',
                  style: GoogleFonts.kantumruyPro(
                      color: Colors.white54, fontSize: 12)),
              onTap: () {
                Navigator.pop(ctx);
                _pickImage(ImageSource.camera);
              },
            ),
            ListTile(
              leading: Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: const Color(0xFF0EA5E9).withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(Icons.photo_library_rounded,
                    color: Color(0xFF38BDF8)),
              ),
              title: Text('ជ្រើសរូបពី Gallery',
                  style: GoogleFonts.kantumruyPro(color: Colors.white)),
              subtitle: Text('ជ្រើសរូបភាពដែលធ្លាប់បានថតទុក',
                  style: GoogleFonts.kantumruyPro(
                      color: Colors.white54, fontSize: 12)),
              onTap: () {
                Navigator.pop(ctx);
                _pickImage(ImageSource.gallery);
              },
            ),
            ListTile(
              leading: Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: const Color(0xFF10B981).withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(Icons.qr_code_scanner_rounded,
                    color: Color(0xFF34D399)),
              ),
              title: Text('ស្កេន Barcode / QR Code',
                  style: GoogleFonts.kantumruyPro(color: Colors.white)),
              subtitle: Text('ស្កេនបាកូដនៅលើសម្បកផលិតផល',
                  style: GoogleFonts.kantumruyPro(
                      color: Colors.white54, fontSize: 12)),
              onTap: () {
                Navigator.pop(ctx);
                _openBarcodeScanner();
              },
            ),
          ],
        ),
      ),
    );
  }

  // ─── Barcode Scanner Overlay ──────────────────────────────────────────────

  Widget _buildBarcodeScannerOverlay() {
    return Positioned.fill(
      child: Material(
        color: Colors.transparent,
        child: Container(
          color: Colors.black,
          child: Stack(
            children: [
              MobileScanner(
                controller: _scanController,
                onDetect: _onBarcodeDetected,
              ),
              Positioned.fill(
                child: CustomPaint(painter: _ScanOverlayPainter()),
              ),
              SafeArea(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      GestureDetector(
                        onTap: _closeBarcodeScanner,
                        child: Container(
                          width: 40,
                          height: 40,
                          decoration: BoxDecoration(
                            color: Colors.black.withValues(alpha: 0.5),
                            shape: BoxShape.circle,
                          ),
                          child: const Icon(Icons.close_rounded,
                              color: Colors.white, size: 22),
                        ),
                      ),
                      const SizedBox(width: 14),
                      Text(
                        'ស្កេន Barcode ផលិតផល',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ─── History & Folders BottomSheet Widget ─────────────────────────────────────

class _HistoryAndFoldersSheet extends StatefulWidget {
  final List<ProductFolder> folders;
  final List<SavedProductSession> history;
  final Function(SavedProductSession) onSelectProduct;
  final VoidCallback onCreateFolder;
  final Function(ProductFolder) onRenameFolder;
  final Function(SavedProductSession) onRenameProduct;
  final Function(SavedProductSession) onMoveProduct;
  final Function(String) onDeleteProduct;
  final Function(String) onDeleteFolder;

  const _HistoryAndFoldersSheet({
    required this.folders,
    required this.history,
    required this.onSelectProduct,
    required this.onCreateFolder,
    required this.onRenameFolder,
    required this.onRenameProduct,
    required this.onMoveProduct,
    required this.onDeleteProduct,
    required this.onDeleteFolder,
  });

  @override
  State<_HistoryAndFoldersSheet> createState() =>
      _HistoryAndFoldersSheetState();
}

class _HistoryAndFoldersSheetState extends State<_HistoryAndFoldersSheet> {
  String? _selectedFolderId; // null = all
  String _searchQuery = '';

  @override
  Widget build(BuildContext context) {
    // Filter items
    final filtered = widget.history.where((p) {
      if (_selectedFolderId == 'uncategorized') {
        if (p.folderId != null && p.folderId!.isNotEmpty) return false;
      } else if (_selectedFolderId != null) {
        if (p.folderId != _selectedFolderId) return false;
      }

      if (_searchQuery.isNotEmpty) {
        final q = _searchQuery.toLowerCase();
        final matchTitle = p.title.toLowerCase().contains(q);
        final matchBrand = p.brand.toLowerCase().contains(q);
        final matchBarcode = p.barcode.contains(q);
        return matchTitle || matchBrand || matchBarcode;
      }
      return true;
    }).toList();

    return Container(
      height: MediaQuery.of(context).size.height * 0.86,
      decoration: BoxDecoration(
        color: AppTheme.bgDark,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
        border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
      ),
      child: Column(
        children: [
          // Drag handle
          const SizedBox(height: 12),
          Container(
            width: 40,
            height: 4,
            decoration: BoxDecoration(
              color: Colors.white24,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          // Title Bar
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 14, 20, 10),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    const Icon(Icons.folder_special_rounded,
                        color: Color(0xFFA78BFA), size: 22),
                    const SizedBox(width: 8),
                    Text(
                      'ប្រវត្តិវិភាគ & Folders',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 17,
                      ),
                    ),
                  ],
                ),
                TextButton.icon(
                  onPressed: widget.onCreateFolder,
                  icon: const Icon(Icons.create_new_folder_rounded,
                      color: Color(0xFF38BDF8), size: 18),
                  label: Text(
                    '+ Folder ថ្មី',
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFF38BDF8),
                      fontWeight: FontWeight.bold,
                      fontSize: 13,
                    ),
                  ),
                ),
              ],
            ),
          ),

          // Search Bar
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Container(
              height: 40,
              padding: const EdgeInsets.symmetric(horizontal: 12),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.white12),
              ),
              child: Row(
                children: [
                  const Icon(Icons.search_rounded,
                      color: Colors.white54, size: 18),
                  const SizedBox(width: 8),
                  Expanded(
                    child: TextField(
                      style: GoogleFonts.kantumruyPro(
                          color: Colors.white, fontSize: 13),
                      decoration: InputDecoration(
                        hintText: 'ស្វែងរកតាមឈ្មោះ, ម៉ាក ឬ Barcode...',
                        hintStyle: GoogleFonts.kantumruyPro(
                            color: Colors.white38, fontSize: 12.5),
                        border: InputBorder.none,
                        isDense: true,
                        contentPadding: EdgeInsets.zero,
                      ),
                      onChanged: (val) =>
                          setState(() => _searchQuery = val.trim()),
                    ),
                  ),
                  if (_searchQuery.isNotEmpty)
                    GestureDetector(
                      onTap: () => setState(() => _searchQuery = ''),
                      child: const Icon(Icons.close_rounded,
                          color: Colors.white54, size: 16),
                    ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),

          // Horizontal Folder Pills
          SizedBox(
            height: 38,
            child: ListView(
              scrollDirection: Axis.horizontal,
              padding: const EdgeInsets.symmetric(horizontal: 16),
              children: [
                _buildFolderPill(
                  id: null,
                  label: 'ទាំងអស់ (${widget.history.length})',
                  isSelected: _selectedFolderId == null,
                  color: const Color(0xFF7C3AED),
                ),
                const SizedBox(width: 6),
                _buildFolderPill(
                  id: 'uncategorized',
                  label: 'គ្មាន Folder',
                  isSelected: _selectedFolderId == 'uncategorized',
                  color: Colors.grey,
                ),
                const SizedBox(width: 6),
                ...widget.folders.map((f) {
                  final count =
                      widget.history.where((p) => p.folderId == f.id).length;
                  return Padding(
                    padding: const EdgeInsets.only(right: 6),
                    child: _buildFolderPill(
                      id: f.id,
                      label: '${f.name} ($count)',
                      isSelected: _selectedFolderId == f.id,
                      color: Color(f.colorHex),
                      folderObj: f,
                    ),
                  );
                }),
              ],
            ),
          ),
          const SizedBox(height: 10),

          // Active Folder Action bar (Rename / Delete)
          if (_selectedFolderId != null &&
              _selectedFolderId != 'uncategorized') ...[
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Row(
                children: [
                  Text(
                    'Folder សកម្ម៖',
                    style: GoogleFonts.kantumruyPro(
                        color: Colors.white54, fontSize: 11.5),
                  ),
                  const Spacer(),
                  GestureDetector(
                    onTap: () {
                      final f = widget.folders.firstWhere(
                          (element) => element.id == _selectedFolderId);
                      widget.onRenameFolder(f);
                    },
                    child: Row(
                      children: [
                        const Icon(Icons.edit_note_rounded,
                            color: Color(0xFFA78BFA), size: 16),
                        const SizedBox(width: 4),
                        Text(
                          'Rename Folder',
                          style: GoogleFonts.kantumruyPro(
                            color: const Color(0xFFA78BFA),
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 14),
                  GestureDetector(
                    onTap: () {
                      widget.onDeleteFolder(_selectedFolderId!);
                      setState(() => _selectedFolderId = null);
                    },
                    child: Row(
                      children: [
                        const Icon(Icons.delete_outline_rounded,
                            color: Colors.redAccent, size: 16),
                        const SizedBox(width: 4),
                        Text(
                          'លុប Folder',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.redAccent,
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 6),
          ],

          // Product List
          Expanded(
            child: filtered.isEmpty
                ? Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.folder_open_rounded,
                            color: Colors.white24, size: 48),
                        const SizedBox(height: 10),
                        Text(
                          'គ្មានទិន្នន័យផលិតផលក្នុង Folder នេះឡើយ',
                          style: GoogleFonts.kantumruyPro(
                              color: Colors.white54, fontSize: 13),
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.fromLTRB(16, 6, 16, 24),
                    itemCount: filtered.length,
                    itemBuilder: (ctx, idx) {
                      final item = filtered[idx];
                      return _buildProductHistoryTile(item);
                    },
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildFolderPill({
    required String? id,
    required String label,
    required bool isSelected,
    required Color color,
    ProductFolder? folderObj,
  }) {
    return GestureDetector(
      onTap: () => setState(() => _selectedFolderId = id),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
        decoration: BoxDecoration(
          color: isSelected
              ? color.withValues(alpha: 0.3)
              : Colors.white.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: isSelected ? color : Colors.white12,
            width: isSelected ? 1.5 : 1,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              id == null ? Icons.all_inbox_rounded : Icons.folder_rounded,
              color: isSelected ? color : Colors.white60,
              size: 14,
            ),
            const SizedBox(width: 5),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: isSelected ? Colors.white : Colors.white70,
                fontSize: 12,
                fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildProductHistoryTile(SavedProductSession item) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
      ),
      child: ListTile(
        contentPadding:
            const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
        leading: Container(
          width: 44,
          height: 44,
          decoration: BoxDecoration(
            color: const Color(0xFF7C3AED).withValues(alpha: 0.15),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Center(
            child: Text(
              item.countryFlag,
              style: const TextStyle(fontSize: 22),
            ),
          ),
        ),
        title: Text(
          item.title,
          style: GoogleFonts.kantumruyPro(
            color: Colors.white,
            fontWeight: FontWeight.bold,
            fontSize: 14,
          ),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const SizedBox(height: 2),
            Row(
              children: [
                if (item.brand.isNotEmpty && item.brand != '—') ...[
                  Text(
                    item.brand,
                    style: GoogleFonts.inter(
                      color: const Color(0xFFA78BFA),
                      fontSize: 11.5,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(width: 8),
                ],
                Text(
                  item.country,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white54,
                    fontSize: 11,
                  ),
                ),
              ],
            ),
            if (item.folderName != null) ...[
              const SizedBox(height: 4),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: const Color(0xFF7C3AED).withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  '📁 ${item.folderName}',
                  style: GoogleFonts.kantumruyPro(
                    color: const Color(0xFFA78BFA),
                    fontSize: 10.5,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ),
            ],
          ],
        ),
        trailing: PopupMenuButton<String>(
          icon: const Icon(Icons.more_vert_rounded,
              color: Colors.white54, size: 20),
          color: const Color(0xFF1E1B4B),
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          onSelected: (action) {
            if (action == 'open') {
              widget.onSelectProduct(item);
            } else if (action == 'move') {
              widget.onMoveProduct(item);
            } else if (action == 'rename') {
              widget.onRenameProduct(item);
            } else if (action == 'delete') {
              widget.onDeleteProduct(item.id);
            }
          },
          itemBuilder: (ctx) => [
            PopupMenuItem(
              value: 'open',
              child: Row(
                children: [
                  const Icon(Icons.chat_bubble_outline_rounded,
                      color: Color(0xFF10B981), size: 18),
                  const SizedBox(width: 8),
                  Text('បើកមើលភ្លាមៗ',
                      style: GoogleFonts.kantumruyPro(color: Colors.white)),
                ],
              ),
            ),
            PopupMenuItem(
              value: 'move',
              child: Row(
                children: [
                  const Icon(Icons.drive_file_move_rounded,
                      color: Color(0xFFA78BFA), size: 18),
                  const SizedBox(width: 8),
                  Text('ដាក់ក្នុង Folder',
                      style: GoogleFonts.kantumruyPro(color: Colors.white)),
                ],
              ),
            ),
            PopupMenuItem(
              value: 'rename',
              child: Row(
                children: [
                  const Icon(Icons.edit_rounded,
                      color: Color(0xFF38BDF8), size: 18),
                  const SizedBox(width: 8),
                  Text('ប្តូរឈ្មោះ',
                      style: GoogleFonts.kantumruyPro(color: Colors.white)),
                ],
              ),
            ),
            PopupMenuItem(
              value: 'delete',
              child: Row(
                children: [
                  const Icon(Icons.delete_outline_rounded,
                      color: Colors.redAccent, size: 18),
                  const SizedBox(width: 8),
                  Text('លុប',
                      style:
                          GoogleFonts.kantumruyPro(color: Colors.redAccent)),
                ],
              ),
            ),
          ],
        ),
        onTap: () => widget.onSelectProduct(item),
      ),
    );
  }
}

// ─── Scan Overlay Painter ─────────────────────────────────────────────────────

class _ScanOverlayPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final frameSide = size.width * 0.68;
    final frameTop = (size.height - frameSide) / 2.2;
    final frameLeft = (size.width - frameSide) / 2;

    final dimPaint = Paint()..color = Colors.black.withValues(alpha: 0.55);
    final borderPaint = Paint()
      ..color = const Color(0xFF10B981)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.5;
    const cornerLen = 24.0;
    const r = 4.0;

    canvas.drawRect(Rect.fromLTWH(0, 0, size.width, frameTop), dimPaint);
    canvas.drawRect(
      Rect.fromLTWH(
        0,
        frameTop + frameSide,
        size.width,
        size.height - frameTop - frameSide,
      ),
      dimPaint,
    );
    canvas.drawRect(Rect.fromLTWH(0, frameTop, frameLeft, frameSide), dimPaint);
    canvas.drawRect(
      Rect.fromLTWH(
        frameLeft + frameSide,
        frameTop,
        size.width - frameLeft - frameSide,
        frameSide,
      ),
      dimPaint,
    );

    final tl = Offset(frameLeft, frameTop);
    final tr = Offset(frameLeft + frameSide, frameTop);
    final bl = Offset(frameLeft, frameTop + frameSide);
    final br = Offset(frameLeft + frameSide, frameTop + frameSide);

    void drawCorner(Offset corner, double dx, double dy) {
      final path = Path()
        ..moveTo(corner.dx, corner.dy + dy * cornerLen)
        ..arcToPoint(
          Offset(corner.dx + dx * r, corner.dy + dy * r),
          radius: const Radius.circular(r),
          clockwise: dy > 0 && dx < 0 || dy < 0 && dx > 0,
        )
        ..lineTo(corner.dx + dx * r, corner.dy + dy * r);
      canvas.drawPath(path, borderPaint);

      final path2 = Path()
        ..moveTo(corner.dx + dx * cornerLen, corner.dy)
        ..arcToPoint(
          Offset(corner.dx + dx * r, corner.dy + dy * r),
          radius: const Radius.circular(r),
          clockwise: dy > 0 && dx > 0 || dy < 0 && dx < 0,
        )
        ..lineTo(corner.dx + dx * r, corner.dy + dy * r);
      canvas.drawPath(path2, borderPaint);
    }

    drawCorner(tl, 1, 1);
    drawCorner(tr, -1, 1);
    drawCorner(bl, 1, -1);
    drawCorner(br, -1, -1);
  }

  @override
  bool shouldRepaint(_) => false;
}
