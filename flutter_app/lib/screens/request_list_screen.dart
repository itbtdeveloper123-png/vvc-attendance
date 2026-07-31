import 'dart:async';
import 'dart:convert';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import 'package:intl/intl.dart';
import 'package:pasteboard/pasteboard.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';

class RequestListScreen extends StatefulWidget {
  const RequestListScreen({super.key});

  @override
  State<RequestListScreen> createState() => _RequestListScreenState();
}

class _RequestListScreenState extends State<RequestListScreen> {
  final ApiService _api = ApiService();
  List<dynamic> _requests = [];
  List<dynamic> _filtered = [];
  bool _isLoading = true;
  final _searchController = TextEditingController();
  final GlobalKey _reportKey = GlobalKey(); // Key for PDF capture
  Map<String, dynamic>? _currentReportItem; // Item being processed for PDF

  String _errorMessage = '';
  Timer? _pollingTimer;

  static const Color _brandOrange = Color(0xFFF2994A);

  @override
  void initState() {
    super.initState();
    _loadData();
    _searchController.addListener(_onSearch);

    // Auto-polling for real-time vibe
    _pollingTimer = Timer.periodic(const Duration(seconds: 6), (timer) {
      if (mounted) {
        _loadDataSilently();
      }
    });
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    _searchController.dispose();
    super.dispose();
  }

  void _safeSetState(VoidCallback fn) {
    if (!mounted) return;
    setState(fn);
  }

  void _onSearch() {
    final q = _searchController.text.toLowerCase();
    _safeSetState(() {
      if (q.isEmpty) {
        _filtered = List.from(_requests);
      } else {
        _filtered = _requests.where((r) {
          final type = (r['request_type'] ?? '').toString().toLowerCase();
          final name = (r['requester_name'] ?? '').toString().toLowerCase();
          final reason = (r['reason'] ?? '').toString().toLowerCase();
          final dept = (r['department'] ?? '').toString().toLowerCase();
          return type.contains(q) ||
              name.contains(q) ||
              reason.contains(q) ||
              dept.contains(q);
        }).toList();
      }
    });
  }

  Future<void> _loadDataSilently() async {
    try {
      final res = await _api.fetchRequests(limit: 100);
      if (!mounted) return;

      if (res['success'] == true) {
        _safeSetState(() {
          _requests = res['requests'] ?? [];
          _onSearch(); // Reapply search filter to updated list
        });
      }
    } catch (_) {}
  }

  Future<void> _loadData() async {
    _safeSetState(() {
      _isLoading = true;
      _errorMessage = '';
    });
    try {
      final res = await _api.fetchRequests(limit: 100);
      if (!mounted) return;

      // Handle Unauthorized (token expired)
      if (res['success'] == false) {
        final msg = res['message']?.toString() ?? 'Unknown error';
        _safeSetState(() {
          _isLoading = false;
          _errorMessage = msg;
        });
        return;
      }

      _safeSetState(() {
        _requests = res['requests'] ?? [];
        _filtered = List.from(_requests);
        _isLoading = false;
      });
    } catch (e) {
      if (!mounted) return;
      _safeSetState(() {
        _errorMessage = 'មិនអាចភ្ជាប់ Server បាន';
        _isLoading = false;
      });
    }
  }

  // ========= Status helpers =========
  Color _statusColor(String status) {
    switch (status.toLowerCase()) {
      case 'approved':
        return const Color(0xFF10b981);
      case 'rejected':
        return const Color(0xFFe11d48);
      default:
        return const Color(0xFFf59e0b);
    }
  }

  String _statusLabel(String status) {
    switch (status.toLowerCase()) {
      case 'approved':
        return 'បានអនុម័ត';
      case 'rejected':
        return 'បានបដិសេធ';
      default:
        return 'រង់ចាំ';
    }
  }

  IconData _statusIcon(String status) {
    switch (status.toLowerCase()) {
      case 'approved':
        return Icons.check_circle_rounded;
      case 'rejected':
        return Icons.cancel_rounded;
      default:
        return Icons.pending_actions_rounded;
    }
  }

  // ========= Type badge color (matches table_report.php) =========
  Color _typeBadgeColor(String type) {
    final t = type.toLowerCase();
    if (t.contains('annual') || t.contains('leave') || t.contains('ឈប់')) {
      return const Color(0xFF059669);
    }
    if (t.contains('late') || t.contains('យឺត')) return const Color(0xFFe11d48);
    if (t.contains('ot') || t.contains('overtime') || t.contains('ថែម')) {
      return const Color(0xFF0284c7);
    }
    if (t.contains('forgot') || t.contains('forget') || t.contains('ភ្លេច')) {
      return const Color(0xFF475569);
    }
    if (t.contains('change') || t.contains('ប្តូរ')) {
      return const Color(0xFF7c3aed);
    }
    return const Color(0xFF64748b);
  }

  Color _typeBadgeBg(String type) {
    final t = type.toLowerCase();
    if (t.contains('annual') || t.contains('leave') || t.contains('ឈប់')) {
      return const Color(0xFFecfdf5);
    }
    if (t.contains('late') || t.contains('យឺត')) return const Color(0xFFfff1f2);
    if (t.contains('ot') || t.contains('overtime') || t.contains('ថែម')) {
      return const Color(0xFFf0f9ff);
    }
    if (t.contains('forgot') || t.contains('forget') || t.contains('ភ្លេច')) {
      return const Color(0xFFf8fafc);
    }
    if (t.contains('change') || t.contains('ប្តូរ')) {
      return const Color(0xFFf5f3ff);
    }
    return const Color(0xFFf9fafb);
  }

  // ========= Initials from name (like table_report.php) =========
  String _initials(String name) {
    final parts = name.trim().split(' ');
    String init = '';
    for (final p in parts) {
      if (p.isNotEmpty) {
        // Unicode-safe first char
        final runes = p.runes;
        if (runes.isNotEmpty) init += String.fromCharCode(runes.first);
      }
    }
    return init.isEmpty
        ? '?'
        : init.substring(0, init.length > 2 ? 2 : init.length);
  }

  String _formatDate(String? d) {
    if (d == null || d.isEmpty) return 'N/A';
    try {
      return DateFormat('dd/MM/yyyy').format(DateTime.parse(d));
    } catch (_) {
      return d;
    }
  }

  String _formatClockTime(String? t) {
    if (t == null || t.isEmpty || t == 'N/A') return 'N/A';
    try {
      DateTime? dt;
      if (t.contains('T') || t.contains('-')) {
        dt = DateTime.parse(t);
      } else if (t.contains(':')) {
        final parts = t.split(':');
        if (parts.length >= 2) {
          final hour = int.tryParse(parts[0]) ?? 0;
          final minute = int.tryParse(parts[1]) ?? 0;
          dt = DateTime(2024, 1, 1, hour, minute);
        }
      }
      if (dt != null) {
        return DateFormat('hh:mm a').format(dt);
      }
    } catch (_) {}
    return t;
  }

  String _formatDuration(String? duration) {
    if (duration == null || duration.isEmpty) return 'N/A';
    try {
      final parts = duration.split(':');
      if (parts.length >= 2) {
        final hours = int.tryParse(parts[0]) ?? 0;
        final minutes = int.tryParse(parts[1]) ?? 0;
        if (hours > 0) {
          return '$hoursម៉ោង $minutesនាទី';
        }
        return '$minutesនាទី';
      }
    } catch (_) {}
    return duration;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgSurface,
      appBar: AppBar(
        backgroundColor: AppTheme.bgCard,
        elevation: 0,
        leading: IconButton(
          icon: Icon(Icons.arrow_back_ios_new, color: AppTheme.textPrimary),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          "បញ្ជីសំណើ",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontWeight: FontWeight.bold,
            fontSize: 18,
          ),
        ),
        actions: [
          IconButton(
            icon: Icon(Icons.refresh, color: AppTheme.textPrimary),
            onPressed: _loadData,
            tooltip: 'ផ្ទុកឡើងវិញ',
          ),
        ],
      ),
      // Stack to add a hidden PDF report generator
      body: Stack(
        children: [
          // Hidden Report Generator (for capture)
          Offstage(
            offstage: true,
            child: RepaintBoundary(
              key: _reportKey,
              child: _hiddenReportWidget(item: _currentReportItem),
            ),
          ),
          
          // Main content
          _isLoading
              ? const Center(child: CircularProgressIndicator(color: Colors.orangeAccent))
              : _errorMessage.isNotEmpty
                  ? _buildErrorState()
                  : _buildContent(),
        ],
      ),
    );
  }

  Widget _buildErrorState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.error_outline, size: 64, color: Colors.red.shade300),
          const SizedBox(height: 16),
          Text(
            _errorMessage,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textSecondary,
              fontSize: 16,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 16),
          ElevatedButton.icon(
            onPressed: _loadData,
            icon: const Icon(Icons.refresh),
            label: Text("ព្យាយាមម្ដងទៀត", style: GoogleFonts.kantumruyPro()),
            style: ElevatedButton.styleFrom(
              backgroundColor: _brandOrange,
              foregroundColor: Colors.white,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildContent() {
    if (_filtered.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.inbox_outlined, size: 64, color: Colors.grey.shade300),
            const SizedBox(height: 16),
            Text(
              "មិនមានសំណើទេ",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textSecondary,
                fontSize: 16,
              ),
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _loadData,
      color: _brandOrange,
      child: AnimationLimiter(
        child: ListView.builder(
          padding: const EdgeInsets.all(16),
          itemCount: _filtered.length,
          itemBuilder: (context, index) {
            return AnimationConfiguration.staggeredList(
              position: index,
              duration: const Duration(milliseconds: 375),
              child: SlideAnimation(
                verticalOffset: 50.0,
                child: FadeInAnimation(
                  child: _buildRequestCard(_filtered[index]),
                ),
              ),
            );
          },
        ),
      ),
    );
  }

  Widget _buildRequestCard(Map<String, dynamic> item) {
    final status = item['status']?.toString() ?? 'pending';
    final type = item['request_type']?.toString() ?? '';
    final name = item['requester_name']?.toString() ?? 'Unknown';
    final department = item['department']?.toString() ?? '';
    final reason = item['reason']?.toString() ?? '';
    final requestDate = item['request_date']?.toString() ?? '';
    final createdDate = item['created_at']?.toString() ?? '';

    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.borderColor),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.05),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: _typeBadgeBg(type),
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(16),
                topRight: Radius.circular(16),
              ),
            ),
            child: Row(
              children: [
                // Avatar
                Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: _typeBadgeColor(type),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: AppTheme.primary.withValues(alpha: 0.3),
                    ),
                    image: (item['user_avatar'] != null &&
                        item['user_avatar'].toString().isNotEmpty)
                        ? DecorationImage(
                            image: NetworkImage(
                              ApiService.getFullImageUrl(
                                item['user_avatar'].toString(),
                              ),
                            ),
                            fit: BoxFit.cover,
                          )
                        : null,
                  ),
                  child: (item['user_avatar'] == null ||
                          item['user_avatar'].toString().isEmpty)
                      ? Center(
                          child: Text(
                            _initials(name),
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontWeight: FontWeight.bold,
                              fontSize: 18,
                            ),
                          ),
                        )
                      : null,
                ),
                const SizedBox(width: 12),
                // Info
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: Text(
                              name,
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textPrimary,
                                fontWeight: FontWeight.bold,
                                fontSize: 16,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 4,
                            ),
                            decoration: BoxDecoration(
                              color: _statusColor(status).withValues(alpha: 0.1),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  _statusIcon(status),
                                  size: 14,
                                  color: _statusColor(status),
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  _statusLabel(status),
                                  style: GoogleFonts.kantumruyPro(
                                    color: _statusColor(status),
                                    fontSize: 12,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Row(
                        children: [
                          Icon(Icons.badge_outlined, size: 14, color: AppTheme.textSecondary),
                          const SizedBox(width: 4),
                          Expanded(
                            child: Text(
                              type,
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textSecondary,
                                fontSize: 13,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ),
                      if (department.isNotEmpty) ...[
                        const SizedBox(height: 2),
                        Row(
                          children: [
                            Icon(Icons.business_outlined, size: 14, color: AppTheme.textSecondary),
                            const SizedBox(width: 4),
                            Expanded(
                              child: Text(
                                department,
                                style: GoogleFonts.kantumruyPro(
                                  color: AppTheme.textSecondary,
                                  fontSize: 12,
                                ),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ],
                  ),
                ),
              ],
            ),
          ),
          // Content
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (reason.isNotEmpty) ...[
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(Icons.description_outlined, size: 16, color: AppTheme.textSecondary),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          reason,
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textPrimary,
                            fontSize: 14,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                ],
                // Details
                Row(
                  children: [
                    Expanded(
                      child: _detailItem(
                        Icons.calendar_today_outlined,
                        "កាលបរិច្ឆេទស្នើ",
                        _formatDate(requestDate),
                      ),
                    ),
                    Expanded(
                      child: _detailItem(
                        Icons.access_time,
                        "បានបង្កើត",
                        _formatDate(createdDate),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                // Actions
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () => _viewRequestDetails(item),
                        icon: const Icon(Icons.visibility_outlined, size: 18),
                        label: Text(
                          "មើលលម្អិត",
                          style: GoogleFonts.kantumruyPro(
                            fontWeight: FontWeight.w600,
                            fontSize: 13,
                          ),
                        ),
                        style: OutlinedButton.styleFrom(
                          foregroundColor: AppTheme.primary,
                          side: BorderSide(color: AppTheme.primary),
                          padding: const EdgeInsets.symmetric(vertical: 10),
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: ElevatedButton.icon(
                        onPressed: () => _generatePDF(item),
                        icon: const Icon(Icons.picture_as_pdf_rounded, size: 18),
                        label: Text(
                          "PDF",
                          style: GoogleFonts.kantumruyPro(
                            fontWeight: FontWeight.w600,
                            fontSize: 13,
                          ),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: _brandOrange,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 10),
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _detailItem(IconData icon, String label, String value) {
    return Row(
      children: [
        Icon(icon, size: 14, color: AppTheme.textSecondary),
        const SizedBox(width: 6),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textSecondary,
                  fontSize: 11,
                ),
              ),
              Text(
                value,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Future<void> _viewRequestDetails(Map<String, dynamic> item) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Text(
          "មើលលម្អិតសំណើ",
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        content: Text(
          "តើអ្នកចង់មើលលម្អិតសំណើនេះជារូបភាពទេ?",
          style: GoogleFonts.kantumruyPro(),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text("បោះបង់", style: GoogleFonts.kantumruyPro()),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(backgroundColor: _brandOrange),
            child: Text("មើលរូបភាព", style: GoogleFonts.kantumruyPro(color: Colors.white)),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      if (!mounted) return;
      showDialog(
        context: context,
        builder: (ctx) => const Center(
          child: CircularProgressIndicator(color: Colors.orangeAccent),
        ),
      );

      if (!mounted) return;
      Navigator.pop(context); // Close loader
      
      // Navigate to detailed view
      await _viewAsImage(item);
    }
  }

  // Captures the hidden report widget as PNG bytes for PDF/image export.
  Future<Uint8List> _captureReportPng(Map<String, dynamic> item) async {
    // Ensure signatures are available (they are excluded from list API for performance).
    if (item['id'] != null &&
        ((item['signature'] ?? '').toString().isEmpty ||
            (item['department_head_signature'] ?? '').toString().isEmpty)) {
      final sigRes = await _api.fetchRequestSignatures(item['id'] as int);
      if (sigRes['success'] == true && sigRes['signatures'] is Map) {
        final sigMap = Map<String, dynamic>.from(sigRes['signatures'] as Map);
        item = {...item, ...sigMap};
      }
    }

    // 1. Set the item and trigger a rebuild of the hidden widget
    setState(() {
      _currentReportItem = item;
    });

    // 2. Wait for the widget to be rendered - multiple frames to ensure proper rendering
    await Future.delayed(const Duration(milliseconds: 100));
    
    // Force a layout pass
    if (mounted) {
      setState(() {});
    }
    
    await Future.delayed(const Duration(milliseconds: 300));

    // 3. Capture the hidden widget as an image
    try {
      final boundary =
          _reportKey.currentContext?.findRenderObject()
              as RenderRepaintBoundary?;
      if (boundary == null) throw "Could not find report boundary";

      // Check if boundary has valid dimensions
      final size = boundary.size;
      debugPrint("Boundary size: ${size.width}x${size.height}");
      
      if (size.width <= 0 || size.height <= 0 || !size.width.isFinite || !size.height.isFinite) {
        // Try one more time with longer delay
        await Future.delayed(const Duration(milliseconds: 500));
        final size2 = boundary.size;
        debugPrint("Retry boundary size: ${size2.width}x${size2.height}");
        
        if (size2.width <= 0 || size2.height <= 0 || !size2.width.isFinite || !size2.height.isFinite) {
          throw "Invalid widget dimensions after retry: ${size2.width}x${size2.height}";
        }
      }

      // Capture with proper null safety
      try {
        final ui.Image capturedImage = await boundary.toImage(pixelRatio: 3.0);
        
        final ByteData? byteData = await capturedImage.toByteData(
          format: ui.ImageByteFormat.png,
        );
        if (byteData == null) throw "Failed to convert image to bytes";
        return byteData.buffer.asUint8List();
      } catch (e) {
        throw "Image capture failed during toImage conversion: $e";
      }
    } catch (e) {
      throw "Image capture failed: $e";
    }
  }

  // ========= View Request as Image (with Copy Image support) =========
  Future<void> _viewAsImage(Map<String, dynamic> item) async {
    if (!mounted) return;
    
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => const Center(
        child: CircularProgressIndicator(color: Colors.orangeAccent),
      ),
    );

    try {
      final Uint8List pngBytes = await _captureReportPng(item);

      if (!mounted) return;
      Navigator.pop(context); // close loader

      showDialog(
        context: context,
        builder: (dialogCtx) => Dialog(
          backgroundColor: AppTheme.bgCard,
          insetPadding: const EdgeInsets.all(16),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(20),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(20, 16, 8, 0),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        "ឯកសារសំណើជារូបភាព",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                    IconButton(
                      onPressed: () => Navigator.pop(dialogCtx),
                      icon: Icon(
                        Icons.close_rounded,
                        color: AppTheme.textPrimary.withValues(alpha: 0.54),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 8),
              Padding(
                padding: const EdgeInsets.all(16),
                child: Container(
                  constraints: BoxConstraints(
                    maxHeight: MediaQuery.of(dialogCtx).size.height * 0.7,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: InteractiveViewer(
                    maxScale: 5,
                    child: Image.memory(pngBytes, fit: BoxFit.contain),
                  ),
                ),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
                child: ElevatedButton.icon(
                  onPressed: () => _copyImageToClipboard(dialogCtx, pngBytes),
                  icon: const Icon(Icons.copy_rounded, size: 20),
                  label: Text(
                    "Copy Image",
                    style: GoogleFonts.kantumruyPro(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _brandOrange,
                    foregroundColor: Colors.white,
                    minimumSize: const Size(double.infinity, 48),
                  ),
                ),
              ),
            ],
          ),
        ),
      );
    } catch (e) {
      if (mounted) Navigator.pop(context);
      debugPrint("IMAGE ERROR: $e");
      if (!mounted) return;
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              "កំហុសក្នុងការបង្កើតរូបភាព: $e",
              style: GoogleFonts.kantumruyPro(),
            ),
            backgroundColor: Colors.redAccent,
          ),
        );
      }
    }
  }

  Future<void> _copyImageToClipboard(
    BuildContext dialogCtx,
    Uint8List pngBytes,
  ) async {
    // Store context references before async operations
    final scaffoldMessenger = ScaffoldMessenger.of(context);
    
    try {
      await Pasteboard.writeImage(pngBytes);
      if (!mounted) return;
      Navigator.pop(dialogCtx);
      if (!mounted) return;
      scaffoldMessenger.showSnackBar(
        SnackBar(
          content: Text(
            "រូបភាពត្រូវបានចម្លងទៅក្នុង clipboard",
            style: GoogleFonts.kantumruyPro(),
          ),
          backgroundColor: Colors.green,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      scaffoldMessenger.showSnackBar(
        SnackBar(
          content: Text(
            "កំហុសក្នុងការចម្លង: $e",
            style: GoogleFonts.kantumruyPro(),
          ),
          backgroundColor: Colors.redAccent,
        ),
      );
    }
  }

  // ========= Improved PDF Generation using Widget Rendering (Fixes Khmer Shaping) =========
  Future<void> _generatePDF(Map<String, dynamic> item) async {
    if (!mounted) return;
    
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => const Center(
        child: CircularProgressIndicator(color: Colors.orangeAccent),
      ),
    );

    try {
      final Uint8List pngBytes = await _captureReportPng(item);

      // Validate PNG bytes
      if (pngBytes.isEmpty) {
        throw "Captured image is empty";
      }

      // 4. Generate the final PDF document
      final doc = pw.Document();
      final image = pw.MemoryImage(pngBytes);

      // Validate image dimensions for PDF
      try {
        doc.addPage(
          pw.Page(
            pageFormat: PdfPageFormat.a5,
            margin: pw.EdgeInsets.zero,
            build: (pw.Context context) {
              return pw.Center(child: pw.Image(image));
            },
          ),
        );
      } catch (e) {
        throw "Failed to add PDF page: $e";
      }

      final pdfBytes = await doc.save();

      // Validate PDF bytes
      if (pdfBytes.isEmpty) {
        throw "Generated PDF is empty";
      }

      final fileName = 'Request_${item['id']}_${item['requester_name']}.pdf';

      // 5. Use direct download for web, and default sharing for others
      await Printing.sharePdf(bytes: pdfBytes, filename: fileName);

      if (mounted) Navigator.pop(context); // close loader
    } catch (e) {
      if (mounted) Navigator.pop(context);
      debugPrint("PDF ERROR: $e");
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            "កំហុសក្នុងការបង្កើត PDF: $e",
            style: GoogleFonts.kantumruyPro(),
          ),
          backgroundColor: Colors.redAccent,
        ),
      );
    }
  }

  // ========= Hidden Report Widget (for capture) =========
  Widget _hiddenReportWidget({required Map<String, dynamic>? item}) {
    if (item == null) return const SizedBox.shrink();

    final screenWidth = MediaQuery.of(context).size.width;
    final screenHeight = MediaQuery.of(context).size.height;
    final maxHeight = screenHeight * 0.85;

    // Validate values to prevent Infinity or NaN
    if (!screenWidth.isFinite || screenWidth <= 0) {
      return const SizedBox.shrink();
    }
    if (!maxHeight.isFinite || maxHeight <= 0) {
      return const SizedBox.shrink();
    }

    // Calculate form dimensions
    double formWidth = screenWidth * 0.95;
    double formHeight = maxHeight * 0.95;

    // Validate calculated values
    if (!formHeight.isFinite || formHeight <= 0 || formHeight.isInfinite) {
      formHeight = maxHeight * 0.7; // Fallback to screen height
    }

    // Calculate content width with padding
    double contentWidth = formWidth - 32; // 16px padding on each side
    if (!contentWidth.isFinite || contentWidth <= 0) {
      contentWidth = screenWidth - 32;
    }

    // Ensure calculated values are valid
    if (!formWidth.isFinite || formWidth <= 0 || formWidth.isInfinite) {
      formWidth = screenWidth;
    }

    return Container(
      width: formWidth,
      constraints: BoxConstraints(maxHeight: maxHeight),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
      ),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            _buildHeader(item),
            const SizedBox(height: 16),
            
            // Request Details
            _buildRequestDetails(item),
            const SizedBox(height: 16),
            
            // Signature Section
            if ((item['signature'] ?? '').toString().startsWith('data:image') ||
                (item['department_head_signature'] ?? '').toString().startsWith('data:image'))
              _buildSignatureSection(item),
            
            const SizedBox(height: 16),
            
            // Footer
            _buildFooter(item),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader(Map<String, dynamic> item) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.orange.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.orange.withValues(alpha: 0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            "សំណើសុំច្បាប់",
            style: GoogleFonts.kantumruyPro(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Colors.orange.shade800,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            "ប័ណ្ណសម្រាប់: ${item['request_type'] ?? 'N/A'}",
            style: GoogleFonts.kantumruyPro(
              fontSize: 14,
              color: Colors.grey.shade700,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRequestDetails(Map<String, dynamic> item) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.grey.shade50,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.grey.shade300),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _detailRow("ឈ្មោះ", item['requester_name'] ?? 'N/A'),
          _detailRow("នាយក", item['department'] ?? 'N/A'),
          _detailRow("ប្រភេទសំណើ", item['request_type'] ?? 'N/A'),
          _detailRow("កាលបរិច្ឆេទស្នើ", _formatDate(item['request_date']?.toString())),
          _detailRow("កាលបរិច្ឆេទបង្កើត", _formatDate(item['created_at']?.toString())),
          if (item['reason'] != null && item['reason'].toString().isNotEmpty)
            _detailRow("មូលហេតុ", item['reason']),
          if (item['start_time'] != null && item['start_time'].toString().isNotEmpty)
            _detailRow("ពេលវេលាចាប់ផ្តើម", _formatClockTime(item['start_time']?.toString())),
          if (item['end_time'] != null && item['end_time'].toString().isNotEmpty)
            _detailRow("ពេលវេលាបញ្ចប់", _formatClockTime(item['end_time']?.toString())),
          if (item['duration'] != null && item['duration'].toString().isNotEmpty)
            _detailRow("រយៈពេល", _formatDuration(item['duration']?.toString())),
          _detailRow("ស្ថានភាព", _statusLabel(item['status']?.toString() ?? 'pending')),
        ],
      ),
    );
  }

  Widget _detailRow(String label, String? value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              label,
              style: GoogleFonts.kantumruyPro(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: Colors.grey.shade700,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value ?? 'N/A',
              style: GoogleFonts.kantumruyPro(
                fontSize: 12,
                color: Colors.grey.shade900,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSignatureSection(Map<String, dynamic> item) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.grey.shade50,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.grey.shade300),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            "ហត្ថលេខា",
            style: GoogleFonts.kantumruyPro(
              fontSize: 14,
              fontWeight: FontWeight.bold,
              color: Colors.grey.shade800,
            ),
          ),
          const SizedBox(height: 12),
          if ((item['signature'] ?? '').toString().startsWith('data:image'))
            _signatureRow("ហត្ថលេខាបុគ្គល", item['signature']),
          if ((item['department_head_signature'] ?? '').toString().startsWith('data:image'))
            _signatureRow("ហត្ថលេខាប្រធានផ្នែក", item['department_head_signature']),
          if ((item['admin_signature'] ?? '').toString().startsWith('data:image'))
            _signatureRow("ហត្ថលេខា Admin", item['admin_signature']),
        ],
      ),
    );
  }

  Widget _signatureRow(String label, String? base64Image) {
    if (base64Image == null || !base64Image.startsWith('data:image')) {
      return const SizedBox.shrink();
    }

    try {
      final base64String = base64Image.split(',').last;
      final imageBytes = base64Decode(base64String);

      return Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                fontSize: 11,
                fontWeight: FontWeight.w600,
                color: Colors.grey.shade600,
              ),
            ),
            const SizedBox(height: 4),
            Image.memory(
              imageBytes,
              height: 60,
              fit: BoxFit.contain,
            ),
          ],
        ),
      );
    } catch (e) {
      debugPrint("Error loading signature: $e");
      return const SizedBox.shrink();
    }
  }

  Widget _buildFooter(Map<String, dynamic> item) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.grey.shade100,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            "ព័ត៌មានបន្ថែម",
            style: GoogleFonts.kantumruyPro(
              fontSize: 12,
              fontWeight: FontWeight.bold,
              color: Colors.grey.shade700,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            "លេខសំណើ: #${item['id'] ?? 'N/A'}",
            style: GoogleFonts.kantumruyPro(
              fontSize: 10,
              color: Colors.grey.shade600,
            ),
          ),
          Text(
            "បានបង្កើតនៅ: ${_formatDate(item['created_at']?.toString())}",
            style: GoogleFonts.kantumruyPro(
              fontSize: 10,
              color: Colors.grey.shade600,
            ),
          ),
        ],
      ),
    );
  }
}