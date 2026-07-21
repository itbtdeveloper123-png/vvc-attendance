import 'dart:convert';

import 'package:animate_do/animate_do.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:image_picker/image_picker.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../services/api_service.dart';
import '../utils/app_theme.dart';

// ─── Model ────────────────────────────────────────────────────────────────────

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
  });

  factory ProductAnalysis.fromJson(Map<String, dynamic> json) {
    List<String> listFromValue(dynamic v) {
      if (v is List) return v.map((e) => e.toString()).toList();
      if (v is String && v.isNotEmpty) return [v];
      return [];
    }

    return ProductAnalysis(
      productName: json['product_name']?.toString() ?? 'មិនស្គាល់',
      brand: json['brand']?.toString() ?? '—',
      countryOfOrigin: json['country_of_origin']?.toString() ?? '—',
      countryFlagEmoji: json['country_flag_emoji']?.toString() ?? '🌍',
      category: json['category']?.toString() ?? '—',
      usage: listFromValue(json['usage']),
      benefits: listFromValue(json['benefits']),
      warnings: listFromValue(json['warnings']),
      ingredientsSummary: json['ingredients_summary']?.toString() ?? '—',
      priceRangeUsd: json['price_range_usd']?.toString() ?? '—',
      summary: json['summary']?.toString() ?? '',
      raw: json['raw']?.toString(),
    );
  }
}

// ─── Screen ───────────────────────────────────────────────────────────────────

enum _ProductMode { initial, result }

class ProductAnalyzerScreen extends StatefulWidget {
  const ProductAnalyzerScreen({super.key});

  @override
  State<ProductAnalyzerScreen> createState() => _ProductAnalyzerScreenState();
}

class _ProductAnalyzerScreenState extends State<ProductAnalyzerScreen>
    with SingleTickerProviderStateMixin {
  final ApiService _api = ApiService();
  final ImagePicker _picker = ImagePicker();

  _ProductMode _mode = _ProductMode.initial;
  bool _isAnalyzing = false;
  String? _errorMsg;
  ProductAnalysis? _result;

  // Image state
  Uint8List? _pickedImageBytes;
  String? _imageBase64;

  // Barcode scanner
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
  String? _detectedBarcode;
  bool _barcodeLocked = false;

  late final AnimationController _pulseCtrl;

  @override
  void initState() {
    super.initState();
    _pulseCtrl = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _pulseCtrl.dispose();
    _scanController.dispose();
    super.dispose();
  }

  // ─── Haptics ──────────────────────────────────────────────────────────────
  void _hapticLight() => HapticFeedback.lightImpact();

  // ─── Image picking ────────────────────────────────────────────────────────

  Future<void> _pickImage(ImageSource source) async {
    _hapticLight();
    try {
      final xfile = await _picker.pickImage(
        source: source,
        imageQuality: 85,
        maxWidth: 1080,
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
        _pickedImageBytes = bytes;
        _imageBase64 = 'data:$mime;base64,$b64';
        _detectedBarcode = null;
        _result = null;
        _errorMsg = null;
        _mode = _ProductMode.initial;
      });
    } catch (e) {
      setState(() => _errorMsg = 'មិនអាចបើករូបភាពបានទេ: $e');
    }
  }

  // ─── Barcode scanner ──────────────────────────────────────────────────────

  void _openBarcodeScanner() {
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
      _detectedBarcode = code;
      _errorMsg = null;
    });
  }

  String _friendlyAnalysisErrorMessage(String raw) {
    final text = raw.trim();
    if (text.isEmpty) {
      return 'AI មិនអាចរៀបចំលទ្ធផលបានត្រឹមត្រូវទេ។ សូមព្យាយាមម្តងទៀត។';
    }

    if (text.contains('AI vision request failed')) {
      final detail = text.replaceAll('AI vision request failed:', '').trim();
      return 'មិនអាចទាក់ទងប្រព័ន្ធ AI វិភាគរូបភាពបានទេ ($detail)។ សូមពិនិត្យអ៊ីនធឺណិត ឬព្យាយាមម្តងទៀត។';
    }

    if (text.contains('<think') || text.contains('"product_name"')) {
      return 'AI មិនអាចរៀបចំលទ្ធផលបានត្រឹមត្រូវទេ។ សូមព្យាយាមម្តងទៀត។';
    }

    return text;
  }

  // ─── Analysis ─────────────────────────────────────────────────────────────

  Future<void> _analyze() async {
    if (_imageBase64 == null && _detectedBarcode == null) return;
    setState(() {
      _isAnalyzing = true;
      _errorMsg = null;
      _result = null;
      _mode = _ProductMode.initial;
    });
    try {
      final res = await _api.analyzeProductImage(
        imageBase64: _imageBase64 ?? '',
        barcode: _detectedBarcode ?? '',
      );
      if (!(res['success'] as bool? ?? false)) {
        setState(() {
          _isAnalyzing = false;
          _errorMsg = _friendlyAnalysisErrorMessage(
            res['message']?.toString() ?? '',
          );
        });
        return;
      }
      final parsed = res['parsed'];
      if (parsed is Map<String, dynamic>) {
        setState(() {
          _result = ProductAnalysis.fromJson({...parsed, 'raw': res['raw']});
          _mode = _ProductMode.result;
          _isAnalyzing = false;
        });
      } else {
        setState(() {
          _errorMsg = _friendlyAnalysisErrorMessage(
            res['raw']?.toString() ?? '',
          );
          _isAnalyzing = false;
        });
      }
    } catch (e) {
      setState(() {
        _isAnalyzing = false;
        _errorMsg = 'Error: $e';
      });
    }
  }

  // ─── Build ────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: Stack(
        children: [
          _buildMainContent(),
          if (_showBarcodeScanner) _buildBarcodeScannerOverlay(),
        ],
      ),
    );
  }

  Widget _buildMainContent() {
    return CustomScrollView(
      slivers: [
        _buildAppBar(),
        SliverPadding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 32),
          sliver: SliverList(
            delegate: SliverChildListDelegate([
              const SizedBox(height: 16),
              _buildImageSection(),
              const SizedBox(height: 16),
              _buildBarcodeSection(),
              const SizedBox(height: 20),
              if (_isAnalyzing) _buildAnalyzingCard(),
              if (_errorMsg != null && !_isAnalyzing) _buildErrorCard(),
              if (_result != null && _mode == _ProductMode.result)
                _buildResultSection(),
              if (_result == null && !_isAnalyzing) _buildAnalyzeButton(),
            ]),
          ),
        ),
      ],
    );
  }

  Widget _buildAppBar() {
    return SliverAppBar(
      backgroundColor: AppTheme.bgDark,
      surfaceTintColor: Colors.transparent,
      pinned: true,
      expandedHeight: 110,
      leading: IconButton(
        icon: const Icon(
          Icons.arrow_back_ios_new_rounded,
          color: Colors.white,
          size: 20,
        ),
        onPressed: () => Navigator.pop(context),
      ),
      flexibleSpace: FlexibleSpaceBar(
        titlePadding: const EdgeInsets.only(left: 56, bottom: 14),
        title: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'AI Product Analyzer',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 17,
              ),
            ),
            Text(
              'វិភាគផលិតផលដោយ AI',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textMuted,
                fontSize: 11,
              ),
            ),
          ],
        ),
        background: Container(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: [const Color(0xFF1a0533), AppTheme.bgDark],
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
            ),
          ),
        ),
      ),
    );
  }

  // ─── Image Section ────────────────────────────────────────────────────────

  Widget _buildImageSection() {
    return FadeInDown(
      duration: const Duration(milliseconds: 400),
      child: Container(
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
              child: Row(
                children: [
                  Container(
                    width: 32,
                    height: 32,
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(
                        colors: [Color(0xFF7C3AED), Color(0xFF4F46E5)],
                      ),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Icon(
                      Icons.camera_alt_rounded,
                      color: Colors.white,
                      size: 18,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'ថតរូប / ជ្រើសរើសរូប',
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontWeight: FontWeight.bold,
                          fontSize: 14,
                        ),
                      ),
                      Text(
                        'ថតផលិតផលដើម្បីឱ្យ AI វិភាគ',
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textMuted,
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),

            // Image preview or placeholder
            GestureDetector(
              onTap: () => _showImagePickerSheet(),
              child: Container(
                margin: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                height: 200,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: _pickedImageBytes != null
                        ? const Color(0xFF7C3AED).withValues(alpha: 0.4)
                        : Colors.white.withValues(alpha: 0.1),
                    width: 2,
                  ),
                  color: Colors.white.withValues(alpha: 0.03),
                ),
                child: _pickedImageBytes != null
                    ? ClipRRect(
                        borderRadius: BorderRadius.circular(14),
                        child: Stack(
                          fit: StackFit.expand,
                          children: [
                            Image.memory(_pickedImageBytes!, fit: BoxFit.cover),
                            Positioned(
                              bottom: 8,
                              right: 8,
                              child: GestureDetector(
                                onTap: _showImagePickerSheet,
                                child: Container(
                                  padding: const EdgeInsets.all(8),
                                  decoration: BoxDecoration(
                                    color: Colors.black.withValues(alpha: 0.6),
                                    shape: BoxShape.circle,
                                  ),
                                  child: const Icon(
                                    Icons.edit_rounded,
                                    color: Colors.white,
                                    size: 16,
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ),
                      )
                    : Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          AnimatedBuilder(
                            animation: _pulseCtrl,
                            builder: (_, child) => Opacity(
                              opacity: 0.5 + 0.5 * _pulseCtrl.value,
                              child: child,
                            ),
                            child: Container(
                              width: 60,
                              height: 60,
                              decoration: BoxDecoration(
                                color: const Color(
                                  0xFF7C3AED,
                                ).withValues(alpha: 0.12),
                                shape: BoxShape.circle,
                              ),
                              child: const Icon(
                                Icons.add_photo_alternate_rounded,
                                color: Color(0xFF7C3AED),
                                size: 30,
                              ),
                            ),
                          ),
                          const SizedBox(height: 12),
                          Text(
                            'ចុចដើម្បីថតឬជ្រើសរូបភាព',
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.textMuted,
                              fontSize: 13,
                            ),
                          ),
                        ],
                      ),
              ),
            ),

            // Pick buttons
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
              child: Row(
                children: [
                  Expanded(
                    child: _buildPickButton(
                      icon: Icons.camera_alt_rounded,
                      label: 'ថតរូប',
                      color: const Color(0xFF7C3AED),
                      onTap: () => _pickImage(ImageSource.camera),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: _buildPickButton(
                      icon: Icons.photo_library_rounded,
                      label: 'ជ្រើសរូប',
                      color: const Color(0xFF0EA5E9),
                      onTap: () => _pickImage(ImageSource.gallery),
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

  Widget _buildPickButton({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: () {
        _hapticLight();
        onTap();
      },
      child: Container(
        height: 44,
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withValues(alpha: 0.2)),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, color: color, size: 18),
            const SizedBox(width: 6),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: color,
                fontWeight: FontWeight.w600,
                fontSize: 13,
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showImagePickerSheet() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (_) => Container(
        padding: const EdgeInsets.all(24),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 36,
              height: 4,
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            const SizedBox(height: 20),
            Text(
              'ជ្រើសរើសរូបភាព',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            const SizedBox(height: 20),
            ListTile(
              leading: Container(
                width: 42,
                height: 42,
                decoration: BoxDecoration(
                  color: const Color(0xFF7C3AED).withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Icon(
                  Icons.camera_alt_rounded,
                  color: Color(0xFF7C3AED),
                ),
              ),
              title: Text(
                'ថតរូបភាព',
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontWeight: FontWeight.w600,
                ),
              ),
              subtitle: Text(
                'ប្រើ Camera ថតផលិតផល',
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textMuted,
                  fontSize: 12,
                ),
              ),
              onTap: () {
                Navigator.pop(context);
                _pickImage(ImageSource.camera);
              },
            ),
            ListTile(
              leading: Container(
                width: 42,
                height: 42,
                decoration: BoxDecoration(
                  color: const Color(0xFF0EA5E9).withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Icon(
                  Icons.photo_library_rounded,
                  color: Color(0xFF0EA5E9),
                ),
              ),
              title: Text(
                'ជ្រើសពី Gallery',
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontWeight: FontWeight.w600,
                ),
              ),
              subtitle: Text(
                'ជ្រើសរូបភាពពី Album',
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textMuted,
                  fontSize: 12,
                ),
              ),
              onTap: () {
                Navigator.pop(context);
                _pickImage(ImageSource.gallery);
              },
            ),
            SizedBox(height: MediaQuery.paddingOf(context).bottom + 8),
          ],
        ),
      ),
    );
  }

  // ─── Barcode Section ──────────────────────────────────────────────────────

  Widget _buildBarcodeSection() {
    return FadeInDown(
      delay: const Duration(milliseconds: 100),
      duration: const Duration(milliseconds: 400),
      child: Container(
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
        ),
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
              child: Row(
                children: [
                  Container(
                    width: 32,
                    height: 32,
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(
                        colors: [Color(0xFF059669), Color(0xFF10B981)],
                      ),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Icon(
                      Icons.qr_code_scanner_rounded,
                      color: Colors.white,
                      size: 18,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'ស្កេន Barcode / QR Code',
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textPrimary,
                            fontWeight: FontWeight.bold,
                            fontSize: 14,
                          ),
                        ),
                        Text(
                          'ស្គាល់ប្រទេសផ្ដល់ហ្វ្រិចចេញ',
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textMuted,
                            fontSize: 11,
                          ),
                        ),
                      ],
                    ),
                  ),
                  if (_detectedBarcode != null)
                    GestureDetector(
                      onTap: () => setState(() {
                        _detectedBarcode = null;
                        _result = null;
                        _mode = _ProductMode.initial;
                      }),
                      child: const Icon(
                        Icons.close_rounded,
                        color: Colors.redAccent,
                        size: 20,
                      ),
                    ),
                ],
              ),
            ),
            if (_detectedBarcode != null)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                child: Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: const Color(0xFF059669).withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: const Color(0xFF059669).withValues(alpha: 0.2),
                    ),
                  ),
                  child: Row(
                    children: [
                      const Icon(
                        Icons.check_circle_rounded,
                        color: Color(0xFF10B981),
                        size: 20,
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'បាន Scan ហើយ!',
                              style: GoogleFonts.kantumruyPro(
                                color: const Color(0xFF10B981),
                                fontWeight: FontWeight.bold,
                                fontSize: 12,
                              ),
                            ),
                            Text(
                              _detectedBarcode!,
                              style: GoogleFonts.inter(
                                color: AppTheme.textSecondary,
                                fontSize: 13,
                                fontWeight: FontWeight.w500,
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                            if (_barcodeCountryInfo(_detectedBarcode!) != null)
                              Text(
                                _barcodeCountryInfo(_detectedBarcode!)!,
                                style: GoogleFonts.kantumruyPro(
                                  color: AppTheme.primaryLight,
                                  fontSize: 12,
                                ),
                              ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              )
            else
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                child: GestureDetector(
                  onTap: () {
                    _hapticLight();
                    _openBarcodeScanner();
                  },
                  child: Container(
                    height: 48,
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(
                        colors: [Color(0xFF059669), Color(0xFF10B981)],
                      ),
                      borderRadius: BorderRadius.circular(14),
                      boxShadow: [
                        BoxShadow(
                          color: const Color(
                            0xFF059669,
                          ).withValues(alpha: 0.35),
                          blurRadius: 12,
                          offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(
                          Icons.qr_code_scanner_rounded,
                          color: Colors.white,
                          size: 20,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          'ចុចដើម្បី Scan Barcode',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: 14,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  // ─── Barcode country lookup (GS1 prefix) ─────────────────────────────────

  String? _barcodeCountryInfo(String barcode) {
    // Only EAN-13/UPC barcodes have GS1 country prefix
    final digits = barcode.replaceAll(RegExp(r'\D'), '');
    if (digits.length < 3) return null;
    final prefix3 = int.tryParse(digits.substring(0, 3)) ?? -1;
    final prefix2 = int.tryParse(digits.substring(0, 2)) ?? -1;

    const Map<int, String> gs1 = {
      0: '🇺🇸 សហរដ្ឋអាមេរិក (USA)',
      1: '🇺🇸 សហរដ្ឋអាមេរិក (USA)',
      2: '🇺🇸 សហរដ្ឋអាមេរិក (USA)',
      3: '🇺🇸 សហរដ្ឋអាមេរិក (USA)',
      4: '🇺🇸 សហរដ្ឋអាមេរិក (USA)',
      5: '🇺🇸 សហរដ្ឋអាមេរិក (USA)',
      6: '🇺🇸 សហរដ្ឋអាមេរិក (USA)',
      30: '🇫🇷 បារាំង (France)',
      37: '🇫🇷 បារាំង (France)',
      40: '🇩🇪 អាល្លឺម៉ង់ (Germany)',
      45: '🇯🇵 ជប៉ុន (Japan)',
      49: '🇯🇵 ជប៉ុន (Japan)',
      50: '🇬🇧 ចក្រភពអង់គ្លេស (UK)',
      54: '🇧🇪 បែលហ្ស៊ិក (Belgium)',
      57: '🇩🇰 ដាណឺម៉ាក (Denmark)',
      60: '🇿🇦 អាហ្វ្រិកខាងត្បូង (South Africa)',
      64: '🇫🇮 ហ្វាំងឡង់ (Finland)',
      70: '🇳🇴 នៃវេ (Norway)',
      73: '🇸🇪 ស៊ុយអែត (Sweden)',
      76: '🇨🇭 ស្វីស (Switzerland)',
      80: '🇮🇹 អ៊ីតាលី (Italy)',
      83: '🇮🇹 អ៊ីតាលី (Italy)',
      84: '🇪🇸 អេស្ប៉ាញ (Spain)',
      87: '🇳🇱 ហូល្លង់ (Netherlands)',
      90: '🇦🇹 អូទ្រីស (Austria)',
      93: '🇦🇺 អូស្ត្រាលី (Australia)',
    };

    const Map<int, String> gs1_3 = {
      400: '🇩🇪 អាល្លឺម៉ង់ (Germany)',
      430: '🇯🇵 ជប៉ុន (Japan)',
      480: '🇵🇭 ហ្វីលីពីន (Philippines)',
      482: '🇺🇦 អ៊ុយក្រែន (Ukraine)',
      484: '🇲🇩 ម៉ុលដាវ៉ា (Moldova)',
      485: '🇦🇲 អាមេនី (Armenia)',
      486: '🇬🇪 ហ្ស្វែហ្ស៊ី (Georgia)',
      487: '🇰🇿 កាហ្សាស្ថាន (Kazakhstan)',
      489: '🇭🇰 ហ่ំងកំង (Hong Kong)',
      490: '🇯🇵 ជប៉ុន (Japan)',
      499: '🇯🇵 ជប៉ុន (Japan)',
      500: '🇬🇧 ចក្រភពអង់គ្លេស (UK)',
      539: '🇮🇪 អៀរឡង់ (Ireland)',
      560: '🇵🇹 ព័រទុយហ្គាល់ (Portugal)',
      569: '🇮🇸 អ៊ីស្លង់ (Iceland)',
      590: '🇵🇱 ប៉ូឡូញ (Poland)',
      594: '🇷🇴 រូម៉ានី (Romania)',
      599: '🇭🇺 ហុងគ្រី (Hungary)',
      600: '🇿🇦 អាហ្វ្រិកខាងត្បូង (South Africa)',
      611: '🇲🇦 ម៉ារ៉ុក (Morocco)',
      613: '🇩🇿 អាល់ហ្ស៊េ (Algeria)',
      615: '🇬🇭 ហ្គាណា (Ghana)',
      616: '🇸🇳 សេណេហ្ស្គាល (Senegal)',
      619: '🇹🇳 ទុយនីស៊ី (Tunisia)',
      621: '🇸🇾 ស៊ីរី (Syria)',
      622: '🇪🇬 អេហ្ស៊ីប (Egypt)',
      624: '🇱🇾 លីប៊ី (Libya)',
      625: '🇯🇴 ហ្ស膿ហ្ស (Jordan)',
      626: '🇮🇷 អ៊ីរ៉ង់ (Iran)',
      627: '🇰🇼 គុយវ៉ៃ (Kuwait)',
      628: '🇸🇦 អារ៉ាប៊ីសាអូឌីត (Saudi Arabia)',
      629: '🇦🇪 អេ.អ.អ (UAE)',
      640: '🇫🇮 ហ្វាំងឡង់ (Finland)',
      649: '🇫🇮 ហ្វាំងឡង់ (Finland)',
      690: '🇨🇳 ចិន (China)',
      699: '🇨🇳 ចិន (China)',
      700: '🇳🇴 នៃវេ (Norway)',
      729: '🇮🇱 អ៊ីស្រាអែល (Israel)',
      730: '🇸🇪 ស៊ុយអែត (Sweden)',
      740: '🇬🇹 ហ្កាតេម៉ាឡា (Guatemala)',
      750: '🇲🇽 ម៉ិចស៊ិក (Mexico)',
      754: '🇨🇦 កាណាដា (Canada)',
      759: '🇻🇪 វ៉េណេស៊ុយអេឡា (Venezuela)',
      760: '🇨🇭 ស្វីស (Switzerland)',
      770: '🇨🇴 កូឡុំប៊ី (Colombia)',
      773: '🇺🇾 អ៊ុយរូហ្ស្វៃ (Uruguay)',
      775: '🇵🇪 ប៉េរូ (Peru)',
      777: '🇧🇴 បូលីវី (Bolivia)',
      780: '🇨🇱 ឈ្លេ (Chile)',
      784: '🇵🇾 ប៉ារ៉ាហ្ស្វ (Paraguay)',
      786: '🇪🇨 អេក្វាដ័រ (Ecuador)',
      789: '🇧🇷 ប្រេស៊ីល (Brazil)',
      800: '🇮🇹 អ៊ីតាលី (Italy)',
      840: '🇪🇸 អេស្ប៉ាញ (Spain)',
      850: '🇨🇺 គុយបា (Cuba)',
      858: '🇸🇰 ស្លូវ៉ាគី (Slovakia)',
      859: '🇨🇿 ឆែក (Czech Republic)',
      860: '🇷🇸 ស៊ែប (Serbia)',
      865: '🇲🇳 ម៉ុងហ្គោលី (Mongolia)',
      867: '🇰🇵 កូរ៉េខាងជើង (North Korea)',
      869: '🇹🇷 តួគីស (Turkey)',
      870: '🇳🇱 ហូល្លង់ (Netherlands)',
      880: '🇰🇷 កូរ៉េខាងត្បូង (South Korea)',
      885: '🇹🇭 ថៃ (Thailand)',
      888: '🇸🇬 សិង្ហបូរី (Singapore)',
      890: '🇮🇳 ឥណ្ឌា (India)',
      893: '🇻🇳 វៀតណាម (Vietnam)',
      896: '🇵🇰 ប៉ាគីស្ថាន (Pakistan)',
      899: '🇮🇩 ឥណ្ឌូណេស៊ី (Indonesia)',
      900: '🇦🇹 អូទ្រីស (Austria)',
      930: '🇦🇺 អូស្ត្រាលី (Australia)',
      940: '🇳🇿 នូវែលហ្សេឡង់ (New Zealand)',
      955: '🇲🇾 ម៉ាឡេស៊ី (Malaysia)',
      958: '🇲🇴 ម៉ាកាវ (Macau)',
    };

    // Try 3-digit prefix first
    if (gs1_3.containsKey(prefix3)) return gs1_3[prefix3];
    if (gs1.containsKey(prefix2)) return gs1[prefix2];
    return null;
  }

  // ─── Analyze button ───────────────────────────────────────────────────────

  Widget _buildAnalyzeButton() {
    final canAnalyze = _imageBase64 != null || _detectedBarcode != null;
    return FadeInUp(
      delay: const Duration(milliseconds: 200),
      duration: const Duration(milliseconds: 400),
      child: GestureDetector(
        onTap: canAnalyze ? _analyze : null,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 300),
          height: 56,
          decoration: BoxDecoration(
            gradient: canAnalyze
                ? const LinearGradient(
                    colors: [Color(0xFF7C3AED), Color(0xFF4F46E5)],
                  )
                : LinearGradient(
                    colors: [
                      Colors.white.withValues(alpha: 0.08),
                      Colors.white.withValues(alpha: 0.05),
                    ],
                  ),
            borderRadius: BorderRadius.circular(16),
            boxShadow: canAnalyze
                ? [
                    BoxShadow(
                      color: const Color(0xFF7C3AED).withValues(alpha: 0.4),
                      blurRadius: 16,
                      offset: const Offset(0, 6),
                    ),
                  ]
                : null,
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.auto_awesome_rounded,
                color: canAnalyze ? Colors.white : AppTheme.textMuted,
                size: 20,
              ),
              const SizedBox(width: 8),
              Text(
                canAnalyze
                    ? 'វិភាគផលិតផលដោយ AI'
                    : 'ជ្រើសរូបភាពឬ Scan Barcode ជាមុន',
                style: GoogleFonts.kantumruyPro(
                  color: canAnalyze ? Colors.white : AppTheme.textMuted,
                  fontWeight: FontWeight.bold,
                  fontSize: 15,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  // ─── Analyzing ────────────────────────────────────────────────────────────

  Widget _buildAnalyzingCard() {
    return FadeInUp(
      duration: const Duration(milliseconds: 400),
      child: Container(
        margin: const EdgeInsets.only(bottom: 16),
        padding: const EdgeInsets.all(24),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: const Color(0xFF7C3AED).withValues(alpha: 0.3),
          ),
        ),
        child: Column(
          children: [
            const CircularProgressIndicator(
              valueColor: AlwaysStoppedAnimation(Color(0xFF7C3AED)),
              strokeWidth: 3,
            ),
            const SizedBox(height: 16),
            Text(
              'AI កំពុងវិភាគ...',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            const SizedBox(height: 6),
            Text(
              'ចាំ AI ស្រាវជ្រាវព័ត៌មានផលិតផល',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textMuted,
                fontSize: 12,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ─── Error ────────────────────────────────────────────────────────────────

  Widget _buildErrorCard() {
    return FadeInUp(
      duration: const Duration(milliseconds: 300),
      child: Container(
        margin: const EdgeInsets.only(bottom: 16),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: Colors.redAccent.withValues(alpha: 0.1),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: Colors.redAccent.withValues(alpha: 0.3)),
        ),
        child: Row(
          children: [
            const Icon(
              Icons.error_outline_rounded,
              color: Colors.redAccent,
              size: 22,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                _errorMsg!,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.redAccent,
                  fontSize: 13,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ─── Result section ───────────────────────────────────────────────────────

  Widget _buildResultSection() {
    final r = _result!;
    return Column(
      children: [
        // Header card
        FadeInUp(
          duration: const Duration(milliseconds: 400),
          child: _buildResultHeaderCard(r),
        ),
        const SizedBox(height: 12),
        if (r.usage.isNotEmpty) ...[
          FadeInUp(
            delay: const Duration(milliseconds: 100),
            duration: const Duration(milliseconds: 400),
            child: _buildListCard(
              icon: Icons.play_circle_outline_rounded,
              color: const Color(0xFF0EA5E9),
              title: 'របៀបប្រើប្រាស់',
              items: r.usage,
            ),
          ),
          const SizedBox(height: 12),
        ],
        if (r.benefits.isNotEmpty) ...[
          FadeInUp(
            delay: const Duration(milliseconds: 150),
            duration: const Duration(milliseconds: 400),
            child: _buildListCard(
              icon: Icons.star_rounded,
              color: const Color(0xFFF59E0B),
              title: 'អត្ថប្រយោជន៍',
              items: r.benefits,
            ),
          ),
          const SizedBox(height: 12),
        ],
        if (r.warnings.isNotEmpty) ...[
          FadeInUp(
            delay: const Duration(milliseconds: 200),
            duration: const Duration(milliseconds: 400),
            child: _buildListCard(
              icon: Icons.warning_amber_rounded,
              color: Colors.orange,
              title: 'ការប្រុងប្រយ័ត្ន',
              items: r.warnings,
              accentColor: Colors.orange,
            ),
          ),
          const SizedBox(height: 12),
        ],
        if (r.ingredientsSummary.isNotEmpty && r.ingredientsSummary != '—') ...[
          FadeInUp(
            delay: const Duration(milliseconds: 250),
            duration: const Duration(milliseconds: 400),
            child: _buildInfoCard(
              icon: Icons.science_rounded,
              color: const Color(0xFF8B5CF6),
              title: 'សារធាតុផ្សំ',
              content: r.ingredientsSummary,
            ),
          ),
          const SizedBox(height: 12),
        ],
        // Analyze again button
        FadeInUp(
          delay: const Duration(milliseconds: 300),
          duration: const Duration(milliseconds: 400),
          child: GestureDetector(
            onTap: () {
              _hapticLight();
              setState(() {
                _result = null;
                _mode = _ProductMode.initial;
                _errorMsg = null;
              });
            },
            child: Container(
              height: 50,
              margin: const EdgeInsets.only(bottom: 8),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(
                  color: const Color(0xFF7C3AED).withValues(alpha: 0.3),
                ),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(
                    Icons.refresh_rounded,
                    color: Color(0xFF7C3AED),
                    size: 18,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'វិភាគម្ដងទៀត',
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFF7C3AED),
                      fontWeight: FontWeight.w600,
                      fontSize: 14,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildResultHeaderCard(ProductAnalysis r) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF1a0533), Color(0xFF0f172a)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: const Color(0xFF7C3AED).withValues(alpha: 0.3),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(r.countryFlagEmoji, style: const TextStyle(fontSize: 40)),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      r.productName,
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 18,
                      ),
                    ),
                    if (r.brand.isNotEmpty && r.brand != '—')
                      Text(
                        r.brand,
                        style: GoogleFonts.inter(
                          color: const Color(0xFFA78BFA),
                          fontSize: 13,
                        ),
                      ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _buildChip(
                Icons.flag_rounded,
                r.countryOfOrigin,
                const Color(0xFF0EA5E9),
              ),
              _buildChip(
                Icons.category_rounded,
                r.category,
                const Color(0xFF10B981),
              ),
              if (r.priceRangeUsd.isNotEmpty && r.priceRangeUsd != '—')
                _buildChip(
                  Icons.attach_money_rounded,
                  r.priceRangeUsd,
                  const Color(0xFFF59E0B),
                ),
            ],
          ),
          if (r.summary.isNotEmpty) ...[
            const SizedBox(height: 14),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.05),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                r.summary,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textSecondary,
                  fontSize: 12,
                  height: 1.6,
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildChip(IconData icon, String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withValues(alpha: 0.2)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, color: color, size: 12),
          const SizedBox(width: 4),
          Text(
            label,
            style: GoogleFonts.kantumruyPro(
              color: color,
              fontSize: 11,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildListCard({
    required IconData icon,
    required Color color,
    required String title,
    required List<String> items,
    Color? accentColor,
  }) {
    final accent = accentColor ?? color;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withValues(alpha: 0.07)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: color, size: 18),
              const SizedBox(width: 8),
              Text(
                title,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontWeight: FontWeight.bold,
                  fontSize: 14,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          ...items.asMap().entries.map((entry) {
            final i = entry.key + 1;
            return Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    width: 22,
                    height: 22,
                    decoration: BoxDecoration(
                      color: accent.withValues(alpha: 0.15),
                      shape: BoxShape.circle,
                    ),
                    child: Center(
                      child: Text(
                        '$i',
                        style: GoogleFonts.inter(
                          color: accent,
                          fontWeight: FontWeight.bold,
                          fontSize: 10,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      entry.value,
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textSecondary,
                        fontSize: 13,
                        height: 1.5,
                      ),
                    ),
                  ),
                ],
              ),
            );
          }),
        ],
      ),
    );
  }

  Widget _buildInfoCard({
    required IconData icon,
    required Color color,
    required String title,
    required String content,
  }) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withValues(alpha: 0.07)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: color, size: 18),
              const SizedBox(width: 8),
              Text(
                title,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontWeight: FontWeight.bold,
                  fontSize: 14,
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            content,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textSecondary,
              fontSize: 13,
              height: 1.5,
            ),
          ),
        ],
      ),
    );
  }

  // ─── Barcode scanner overlay ──────────────────────────────────────────────

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
              // Dark overlay with scan frame
              Positioned.fill(
                child: CustomPaint(painter: _ScanOverlayPainter()),
              ),
              // Top header
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
                          child: const Icon(
                            Icons.close_rounded,
                            color: Colors.white,
                            size: 22,
                          ),
                        ),
                      ),
                      const SizedBox(width: 14),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'ស្កេន Barcode',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white,
                                fontWeight: FontWeight.bold,
                                fontSize: 16,
                              ),
                            ),
                            Text(
                              'ដាក់ Barcode ក្នុងប្រអប់ស្កេន',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white70,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              // Bottom hint
              Positioned(
                bottom: 60,
                left: 0,
                right: 0,
                child: Center(
                  child: Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 16,
                      vertical: 8,
                    ),
                    decoration: BoxDecoration(
                      color: Colors.black.withValues(alpha: 0.6),
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Text(
                      'EAN-8, EAN-13, UPC, QR Code ជាដើម',
                      style: GoogleFonts.inter(
                        color: Colors.white70,
                        fontSize: 12,
                      ),
                    ),
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

    // Dim overlay (four rects around scan frame)
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

    // Corner brackets
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
