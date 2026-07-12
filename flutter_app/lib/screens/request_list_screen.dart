import 'dart:async';
import 'dart:convert';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import 'package:intl/intl.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import 'package:provider/provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../providers/user_provider.dart';
import '../widgets/app_widgets.dart';
import 'leave_request_screen.dart';

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

  String _debugInfo = '';
  String _errorMessage = '';
  Timer? _pollingTimer;

  static const Color _brandOrange = Color(0xFFF2994A);
  static const double _lblSize = 11.5;
  static const double _valSize = 11.5;

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
          _debugInfo = 'API Error: $msg';
        });
        return;
      }

      final debug = res['debug'];
      final debugStr = debug != null
          ? 'user_id: ${debug['my_user_id']} | emp: ${debug['my_employee_id']}\n'
                'name: ${debug['my_name']}\n'
                'matched: ${debug['matched_count']} / total: ${debug['total_in_db']}\n'
                'sample_ids: ${debug['sample_user_ids_in_db']}\n'
                'sample_names: ${debug['sample_names_in_db']}'
          : 'No debug info';

      _safeSetState(() {
        _requests = res['requests'] ?? [];
        _filtered = List.from(_requests);
        _debugInfo = debugStr;
        _isLoading = false;
      });
    } catch (e) {
      if (!mounted) return;
      _safeSetState(() {
        _debugInfo = 'Connection Error: $e';
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

  String _formatTime(String? dt) {
    if (dt == null || dt.isEmpty) return '';
    try {
      return DateFormat('hh:mm a').format(DateTime.parse(dt));
    } catch (_) {
      return dt;
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
        dt = DateTime(2000, 1, 1, int.parse(parts[0]), int.parse(parts[1]));
      }
      if (dt != null) {
        return DateFormat('hh:mm a').format(dt);
      }
      return t;
    } catch (_) {
      return t;
    }
  }

  String _formatPhone(String? p) {
    if (p == null || p.isEmpty || p == 'N/A') return 'N/A';
    String cleaned = p.replaceAll(RegExp(r'\D'), '');
    if (cleaned.length == 9) {
      return '${cleaned.substring(0, 3)} ${cleaned.substring(3, 6)} ${cleaned.substring(6)}';
    } else if (cleaned.length == 10) {
      return '${cleaned.substring(0, 3)} ${cleaned.substring(3, 7)} ${cleaned.substring(7)}';
    }
    return p;
  }

  @override
  Widget build(BuildContext context) {
    return DynamicAppBarWrapper(
      title: "បញ្ជីសំណើ",
      actions: [
        IconButton(
          icon: const Icon(Icons.refresh_rounded),
          onPressed: _loadData,
          tooltip: 'ផ្ទុកឡើងវិញ',
        ),
      ],
      // Stack to add a hidden PDF report generator
      body: Stack(
        children: [
          // Hidden Report Generator (for capture)
          Positioned(
            left: -5000, // Off screen
            child: RepaintBoundary(
              key: _reportKey,
              child: _buildHiddenReport(context),
            ),
          ),
          AppBackgroundShell(
            child: Column(
              children: [
                SizedBox(height: MediaQuery.of(context).padding.top + 70),
                // Search Bar
                Padding(
                  padding: EdgeInsets.fromLTRB(
                    AppResponsive.horizontalPadding(context),
                    0,
                    AppResponsive.horizontalPadding(context),
                    12,
                  ),
                  child: AppSearchField(
                    controller: _searchController,
                    hintText: 'ស្វែងរក ID, ឈ្មោះ, ប្រភេទ, ឬផ្នែក...',
                  ),
                ),

                // Summary statistics
                if (!_isLoading && _requests.isNotEmpty) _buildSummaryRow(),

                // Main list
                Expanded(
                  child: _isLoading
                      ? Center(
                          child: CircularProgressIndicator(
                            color: AppTheme.primary,
                          ),
                        )
                      : RefreshIndicator(
                          onRefresh: _loadData,
                          color: AppTheme.primary,
                          child: _filtered.isEmpty
                              ? _buildEmptyState()
                              : AnimationLimiter(
                                  child: ListView.builder(
                                    padding: EdgeInsets.fromLTRB(
                                      AppResponsive.horizontalPadding(context),
                                      0,
                                      AppResponsive.horizontalPadding(context),
                                      AppResponsive.bottomPadding(
                                        context,
                                        hasBottomNav:
                                            ModalRoute.of(context)?.isFirst ??
                                            false,
                                      ),
                                    ),
                                    physics: const BouncingScrollPhysics(),
                                    itemCount: _filtered.length,
                                    itemBuilder: (context, index) =>
                                        AnimationConfiguration.staggeredList(
                                          position: index,
                                          duration: const Duration(
                                            milliseconds: 400,
                                          ),
                                          child: SlideAnimation(
                                            verticalOffset: 50.0,
                                            child: FadeInAnimation(
                                              child: AppResponsive.maxWidth(
                                                context: context,
                                                child: _buildRequestCard(
                                                  _filtered[index],
                                                  index,
                                                ),
                                              ),
                                            ),
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
    );
  }

  Widget _buildSummaryRow() {
    int pending = _requests
        .where((r) => (r['status'] ?? '') == 'pending')
        .length;
    int approved = _requests
        .where((r) => (r['status'] ?? '') == 'approved')
        .length;
    int rejected = _requests
        .where((r) => (r['status'] ?? '') == 'rejected')
        .length;

    return Padding(
      padding: EdgeInsets.fromLTRB(
        AppResponsive.horizontalPadding(context),
        0,
        AppResponsive.horizontalPadding(context),
        12,
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        physics: const BouncingScrollPhysics(),
        child: Row(
          children: [
            _buildStatChip(
              'សរុប ${_requests.length}',
              Colors.blueAccent,
              Icons.list_alt_rounded,
            ),
            const SizedBox(width: 8),
            _buildStatChip(
              'រង់ចាំ $pending',
              const Color(0xFFf59e0b),
              Icons.pending_outlined,
            ),
            const SizedBox(width: 8),
            _buildStatChip(
              'បានអនុម័ត $approved',
              const Color(0xFF10b981),
              Icons.check_circle_outline_rounded,
            ),
            const SizedBox(width: 8),
            _buildStatChip(
              'បដិសេធ $rejected',
              const Color(0xFFe11d48),
              Icons.cancel_outlined,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatChip(String label, Color color, IconData icon) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.2)),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: 6),
          Text(
            label,
            style: GoogleFonts.kantumruyPro(
              color: color,
              fontSize: 11,
              fontWeight: FontWeight.bold,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return SingleChildScrollView(
      physics: const AlwaysScrollableScrollPhysics(
        parent: BouncingScrollPhysics(),
      ),
      padding: EdgeInsets.only(
        bottom: AppResponsive.bottomPadding(
          context,
          hasBottomNav: ModalRoute.of(context)?.isFirst ?? false,
        ),
      ),
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const SizedBox(height: 60),
              // Show error icon if there's an error
              Icon(
                _errorMessage.isNotEmpty
                    ? Icons.wifi_off_rounded
                    : Icons.folder_open_rounded,
                size: 80,
                color: _errorMessage.isNotEmpty
                    ? Colors.redAccent.withValues(alpha: 0.4)
                    : AppTheme.textPrimary.withValues(alpha: 0.15),
              ),
              const SizedBox(height: 16),
              Text(
                _errorMessage.isNotEmpty
                    ? (_errorMessage.toLowerCase().contains('unauthorized')
                          ? 'Session អស់សុពលភាព\nសូម Login ម្ដងទៀត'
                          : _errorMessage)
                    : (_searchController.text.isEmpty
                          ? "មិនទាន់មានការស្នើសុំណាមួយ"
                          : "រកមិនឃើញ \"${_searchController.text}\""),
                textAlign: TextAlign.center,
                style: GoogleFonts.kantumruyPro(
                  color: _errorMessage.isNotEmpty
                      ? Colors.redAccent.withValues(alpha: 0.8)
                      : AppTheme.textPrimary.withValues(alpha: 0.38),
                  fontSize: 16,
                ),
              ),
              if (_errorMessage.isNotEmpty) ...[
                const SizedBox(height: 16),
                ElevatedButton.icon(
                  onPressed: _loadData,
                  icon: const Icon(Icons.refresh_rounded, size: 18),
                  label: Text(
                    'ព្យាយាមម្ដងទៀត',
                    style: GoogleFonts.kantumruyPro(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF4f46e5),
                    padding: const EdgeInsets.symmetric(
                      horizontal: 20,
                      vertical: 12,
                    ),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                ),
              ],
              if (_debugInfo.isNotEmpty) ...[
                const SizedBox(height: 24),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.orange.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: Colors.orange.withValues(alpha: 0.3),
                    ),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        '🔍 DEBUG INFO',
                        style: GoogleFonts.inter(
                          color: Colors.orange,
                          fontWeight: FontWeight.bold,
                          fontSize: 11,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        _debugInfo,
                        style: GoogleFonts.inter(
                          color: AppTheme.textPrimary.withValues(alpha: 0.60),
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildRequestCard(Map<String, dynamic> item, int index) {
    final type = item['request_type'] ?? 'សំណើ';
    final name = item['requester_name'] ?? 'N/A';
    final dept = item['department'] ?? '';
    final branch = item['branch'] ?? '';
    final reqDate = _formatDate(item['request_date']);
    final createdTime = _formatTime(item['created_at']);
    final reason = item['reason'] ?? '';
    final status = (item['status'] ?? 'pending');
    final statusColor = _statusColor(status);
    final badgeBg = _typeBadgeBg(type);
    final badgeColor = _typeBadgeColor(type);

    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.05)),
        boxShadow: AppTheme.cardShadow,
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(18),
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            onTap: () => _showDetails(item),
            child: Column(
              children: [
                // Colored top accent based on status
                Container(
                  height: 3,
                  decoration: BoxDecoration(
                    borderRadius: const BorderRadius.vertical(
                      top: Radius.circular(18),
                    ),
                    color: statusColor.withValues(alpha: 0.7),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Row 1: Type badge + Status
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          // Type badge
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 5,
                            ),
                            decoration: BoxDecoration(
                              color: badgeBg,
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(
                                color: badgeColor.withValues(alpha: 0.3),
                              ),
                            ),
                            child: Text(
                              type,
                              style: GoogleFonts.kantumruyPro(
                                color: badgeColor,
                                fontWeight: FontWeight.bold,
                                fontSize: 11,
                              ),
                            ),
                          ),
                          // Status chip
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 5,
                            ),
                            decoration: BoxDecoration(
                              color: statusColor.withValues(alpha: 0.12),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  _statusIcon(status),
                                  color: statusColor,
                                  size: 14,
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  _statusLabel(status),
                                  style: GoogleFonts.kantumruyPro(
                                    color: statusColor,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),

                      // Requester Info
                      Row(
                        children: [
                          // Avatar circle
                          Container(
                            width: 36,
                            height: 36,
                            decoration: BoxDecoration(
                              color: AppTheme.primary.withValues(alpha: 0.15),
                              borderRadius: BorderRadius.circular(10),
                              border: Border.all(
                                color: AppTheme.primary.withValues(alpha: 0.3),
                              ),
                              image:
                                  (item['user_avatar'] != null &&
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
                            alignment: Alignment.center,
                            child:
                                (item['user_avatar'] == null ||
                                    item['user_avatar'].toString().isEmpty)
                                ? Text(
                                    _initials(name),
                                    style: GoogleFonts.inter(
                                      color: AppTheme.primaryLight,
                                      fontWeight: FontWeight.bold,
                                      fontSize: 12,
                                    ),
                                  )
                                : null,
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  name,
                                  style: GoogleFonts.kantumruyPro(
                                    color: AppTheme.textPrimary,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 13,
                                  ),
                                ),
                                if (dept.isNotEmpty || branch.isNotEmpty)
                                  Text(
                                    [
                                      dept,
                                      branch,
                                    ].where((s) => s.isNotEmpty).join(' · '),
                                    style: GoogleFonts.kantumruyPro(
                                      color: AppTheme.textPrimary.withValues(
                                        alpha: 0.54,
                                      ),
                                      fontSize: 11,
                                    ),
                                  ),
                              ],
                            ),
                          ),
                        ],
                      ),

                      if (reason.isNotEmpty) ...[
                        const SizedBox(height: 10),
                        Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: AppTheme.textPrimary.withValues(alpha: 0.04),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: Text(
                            reason,
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.textPrimary.withValues(
                                alpha: 0.70,
                              ),
                              fontSize: 12,
                            ),
                          ),
                        ),
                      ],

                      const SizedBox(height: 10),
                      Divider(
                        color: AppTheme.textPrimary.withValues(alpha: 0.10),
                        height: 1,
                      ),
                      const SizedBox(height: 10),

                      // Footer: date + time
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Row(
                            children: [
                              Icon(
                                Icons.calendar_today_rounded,
                                color: AppTheme.textPrimary.withValues(
                                  alpha: 0.38,
                                ),
                                size: 13,
                              ),
                              const SizedBox(width: 5),
                              Text(
                                reqDate,
                                style: GoogleFonts.inter(
                                  color: AppTheme.textPrimary.withValues(
                                    alpha: 0.54,
                                  ),
                                  fontSize: 11,
                                ),
                              ),
                            ],
                          ),
                          if (createdTime.isNotEmpty)
                            Text(
                              createdTime,
                              style: GoogleFonts.inter(
                                color: AppTheme.textPrimary.withValues(
                                  alpha: 0.30,
                                ),
                                fontSize: 10,
                              ),
                            ),
                          // Request ID badge
                          if (item['id'] != null)
                            Text(
                              '#${item['id']}',
                              style: GoogleFonts.inter(
                                color: AppTheme.textPrimary.withValues(
                                  alpha: 0.24,
                                ),
                                fontSize: 10,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  void _showDetails(Map<String, dynamic> item) {
    final status = (item['status'] ?? 'pending').toString();
    final statusColor = _statusColor(status);

    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (context) {
        final user = Provider.of<UserProvider>(context, listen: false);
        return DraggableScrollableSheet(
          initialChildSize: 0.85,
          maxChildSize: 0.95,
          minChildSize: 0.5,
          builder: (_, scrollController) => Container(
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
            ),
            child: Column(
              children: [
                // Handle bar
                Container(
                  margin: const EdgeInsets.only(top: 12, bottom: 4),
                  width: 40,
                  height: 4,
                  decoration: BoxDecoration(
                    color: AppTheme.textPrimary.withValues(alpha: 0.24),
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),

                // Header
                Padding(
                  padding: const EdgeInsets.fromLTRB(24, 12, 24, 0),
                  child: Row(
                    children: [
                      Expanded(
                        child: Text(
                          "ព័ត៌មានលម្អិតនៃសំណើ",
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textPrimary,
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                      // Status badge
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 12,
                          vertical: 6,
                        ),
                        decoration: BoxDecoration(
                          color: statusColor.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                            color: statusColor.withValues(alpha: 0.3),
                          ),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              _statusIcon(status),
                              color: statusColor,
                              size: 14,
                            ),
                            const SizedBox(width: 5),
                            Text(
                              _statusLabel(status),
                              style: GoogleFonts.kantumruyPro(
                                color: statusColor,
                                fontWeight: FontWeight.bold,
                                fontSize: 12,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),

                Divider(
                  color: AppTheme.textPrimary.withValues(alpha: 0.10),
                  height: 20,
                ),

                // Scrollable content
                Expanded(
                  child: ListView(
                    controller: scrollController,
                    padding: const EdgeInsets.fromLTRB(24, 0, 24, 16),
                    children: [
                      // =========== Section 1: ព័ត៌មានបុគ្គល ===========
                      _buildSection("ព័ត៌មានបុគ្គល", Icons.person_rounded, [
                        _detailRow("ID", '#${item['id'] ?? '-'}'),
                        _detailRow("ឈ្មោះ", item['requester_name'] ?? '-'),
                        _detailRow("ប្រភេទ", item['request_type'] ?? '-'),
                      ]),

                      // =========== Section 2: ទីតាំងការងារ ===========
                      _buildSection("ទីតាំងការងារ", Icons.business_rounded, [
                        _detailRow("ផ្នែក", item['department'] ?? '-'),
                        _detailRow("តួនាទី", item['position'] ?? '-'),
                        _detailRow("សាខា", item['branch'] ?? '-'),
                        if ((item['department_head_name'] ?? '')
                            .toString()
                            .isNotEmpty)
                          _detailRow(
                            "ប្រធានផ្នែក",
                            item['department_head_name'] ?? '-',
                          ),
                      ]),

                      // =========== Section 3: ព័ត៌មានសំណើ ===========
                      _buildSection("ព័ត៌មានសំណើ", Icons.assignment_rounded, [
                        _detailRow(
                          "កាលបរិច្ឆេទស្នើ",
                          _formatDate(item['request_date']),
                        ),
                        if ((item['return_date'] ?? '').toString().isNotEmpty)
                          _detailRow(
                            "កាលបរិច្ឆេទត្រឡប់",
                            _formatDate(item['return_date']),
                          ),
                        if ((item['number_of_days'] ?? '')
                                .toString()
                                .isNotEmpty &&
                            item['number_of_days'].toString() != '0')
                          _detailRow(
                            "ចំនួនថ្ងៃ",
                            item['number_of_days'].toString(),
                          ),
                        if ((item['time_in'] ?? '').toString().isNotEmpty)
                          _detailRow(
                            "ម៉ោងចូល",
                            _formatClockTime(item['time_in'].toString()),
                          ),
                        if ((item['time_out'] ?? '').toString().isNotEmpty)
                          _detailRow(
                            "ម៉ោងចេញ",
                            _formatClockTime(item['time_out'].toString()),
                          ),
                        if ((item['late_hours'] ?? '').toString().isNotEmpty)
                          _detailRow("ម៉ោងយឺត", item['late_hours'].toString()),
                        if ((item['total_hours'] ?? '').toString().isNotEmpty)
                          _detailRow(
                            "សរុបម៉ោង",
                            item['total_hours'].toString(),
                          ),
                        if ((item['repay_time_in'] ?? '').toString().isNotEmpty)
                          _detailRow(
                            "ម៉ោងសងចូល",
                            _formatClockTime(item['repay_time_in'].toString()),
                          ),
                        if ((item['repay_time_out'] ?? '')
                            .toString()
                            .isNotEmpty)
                          _detailRow(
                            "ម៉ោងសងចេញ",
                            _formatClockTime(item['repay_time_out'].toString()),
                          ),
                        if ((item['forgot_scan_in'] ?? '')
                            .toString()
                            .isNotEmpty)
                          _detailRow(
                            "ភ្លេចស្កេនចូល",
                            _formatClockTime(item['forgot_scan_in'].toString()),
                          ),
                        if ((item['forgot_scan_out'] ?? '')
                            .toString()
                            .isNotEmpty)
                          _detailRow(
                            "ភ្លេចស្កេនចេញ",
                            _formatClockTime(
                              item['forgot_scan_out'].toString(),
                            ),
                          ),
                      ]),

                      // =========== Section 4: ព័ត៌មានផ្សេង ===========
                      _buildSection(
                        "ព័ត៌មានផ្សេង",
                        Icons.info_outline_rounded,
                        [
                          if ((item['reason'] ?? '').toString().isNotEmpty)
                            _detailRow("មូលហេតុ", item['reason'].toString()),
                          if ((item['contact_number'] ?? '')
                              .toString()
                              .isNotEmpty)
                            _detailRow(
                              "លេខទូរស័ព្ទ",
                              _formatPhone(item['contact_number'].toString()),
                            ),
                          if ((item['assigned_to'] ?? '').toString().isNotEmpty)
                            _detailRow(
                              "ទទួលជំទាវវិញ",
                              item['assigned_to'].toString(),
                            ),
                          if ((item['location'] ?? '').toString().isNotEmpty)
                            _detailRow("ទីតាំង", item['location'].toString()),
                          _detailRow("ស្ថានភាព", _statusLabel(status)),
                          if ((item['approved_by'] ?? '').toString().isNotEmpty)
                            _detailRow("អ្នកអនុម័ត", item['approved_by']),
                          if ((item['admin_comment'] ?? '')
                              .toString()
                              .isNotEmpty)
                            _detailRow("មតិ Admin", item['admin_comment']),
                          if (item['created_at'] != null)
                            _detailRow(
                              "ម៉ោងបញ្ជូន",
                              _formatTime(item['created_at']),
                            ),
                        ],
                      ),

                      // =========== Section 5: ហត្ថលេខា ===========
                      if ((item['signature'] ?? '').toString().startsWith(
                            'data:image',
                          ) ||
                          (item['department_head_signature'] ?? '')
                              .toString()
                              .startsWith('data:image'))
                        _buildSection("ហត្ថលេខា", Icons.draw_rounded, [
                          if ((item['signature'] ?? '').toString().startsWith(
                            'data:image',
                          ))
                            _signatureRow("ហត្ថលេខាបុគ្គល", item['signature']),
                          if ((item['department_head_signature'] ?? '')
                              .toString()
                              .startsWith('data:image'))
                            _signatureRow(
                              "ហត្ថលេខាប្រធានផ្នែក",
                              item['department_head_signature'],
                            ),
                          if ((item['admin_signature'] ?? '')
                              .toString()
                              .startsWith('data:image'))
                            _signatureRow(
                              "ហត្ថលេខា Admin",
                              item['admin_signature'],
                            ),
                        ]),

                      const SizedBox(height: 24),

                      // Actions Row
                      Row(
                        children: [
                          // PDF Button
                          Expanded(
                            child: ElevatedButton.icon(
                              onPressed: () => _generatePDF(item),
                              icon: const Icon(
                                Icons.picture_as_pdf_rounded,
                                size: 20,
                              ),
                              label: Text(
                                "ទាញយក PDF",
                                style: GoogleFonts.kantumruyPro(
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Colors.orangeAccent,
                                foregroundColor: AppTheme.textPrimary,
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(14),
                                ),
                                minimumSize: const Size(0, 50),
                              ),
                            ),
                          ),
                          const SizedBox(width: 12),
                          // Edit/Approve logic
                          if (status == 'pending') ...[
                            if (user.systemRole == SystemRole.admin ||
                                user.systemRole == SystemRole.hrm)
                              Expanded(
                                child: ElevatedButton.icon(
                                  onPressed: () => _handleStatusUpdate(
                                    item['id'],
                                    'approved',
                                  ),
                                  icon: const Icon(
                                    Icons.check_circle_rounded,
                                    size: 20,
                                  ),
                                  label: Text(
                                    "អនុម័ត",
                                    style: GoogleFonts.kantumruyPro(
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  style: ElevatedButton.styleFrom(
                                    backgroundColor: const Color(0xFF10b981),
                                    foregroundColor: AppTheme.textPrimary,
                                    shape: RoundedRectangleBorder(
                                      borderRadius: BorderRadius.circular(14),
                                    ),
                                    minimumSize: const Size(0, 50),
                                  ),
                                ),
                              )
                            else
                              Expanded(
                                child: ElevatedButton.icon(
                                  onPressed: () => _handleEdit(item),
                                  icon: const Icon(
                                    Icons.edit_rounded,
                                    size: 20,
                                  ),
                                  label: Text(
                                    "កែសម្រួល",
                                    style: GoogleFonts.kantumruyPro(
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  style: ElevatedButton.styleFrom(
                                    backgroundColor: AppTheme.primary,
                                    foregroundColor: AppTheme.textPrimary,
                                    shape: RoundedRectangleBorder(
                                      borderRadius: BorderRadius.circular(14),
                                    ),
                                    minimumSize: const Size(0, 50),
                                  ),
                                ),
                              ),
                          ],
                        ],
                      ),

                      if (status == 'pending') ...[
                        const SizedBox(height: 12),
                        if (user.systemRole == SystemRole.admin ||
                            user.systemRole == SystemRole.hrm)
                          OutlinedButton.icon(
                            onPressed: () =>
                                _handleStatusUpdate(item['id'], 'rejected'),
                            icon: const Icon(
                              Icons.cancel_rounded,
                              color: Colors.redAccent,
                            ),
                            label: Text(
                              "បដិសេធសំណើ",
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.redAccent,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            style: OutlinedButton.styleFrom(
                              side: const BorderSide(color: Colors.redAccent),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(14),
                              ),
                              minimumSize: const Size(double.infinity, 50),
                            ),
                          )
                        else
                          OutlinedButton.icon(
                            onPressed: () =>
                                _confirmDelete(context, item['id']),
                            icon: const Icon(
                              Icons.delete_outline_rounded,
                              color: Colors.redAccent,
                            ),
                            label: Text(
                              "លុបសំណើនេះ",
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.redAccent,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            style: OutlinedButton.styleFrom(
                              side: const BorderSide(color: Colors.redAccent),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(14),
                              ),
                              minimumSize: const Size(double.infinity, 50),
                            ),
                          ),
                      ],

                      const SizedBox(height: 12),

                      ElevatedButton(
                        onPressed: () => Navigator.pop(context),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppTheme.textPrimary.withValues(
                            alpha: 0.10,
                          ),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(14),
                          ),
                          minimumSize: const Size(double.infinity, 50),
                        ),
                        child: Text(
                          "បិទ",
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textPrimary,
                            fontWeight: FontWeight.bold,
                          ),
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
    );
  }

  // Handle Approve/Reject
  Future<void> _handleStatusUpdate(int id, String status) async {
    final commentController = TextEditingController();
    final bool? confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Text(
          status == 'approved' ? "អនុម័តសំណើ" : "បដិសេធសំណើ",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontWeight: FontWeight.bold,
          ),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              "តើអ្នកពិតជាចង់ ${status == 'approved' ? 'អនុម័ត' : 'បដិសេធ'} សំណើនេះមែនទេ?",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.70),
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: commentController,
              style: TextStyle(color: AppTheme.textPrimary),
              decoration: InputDecoration(
                hintText: "មតិយោបល់ (Admin Comment)...",
                hintStyle: TextStyle(
                  color: AppTheme.textPrimary.withValues(alpha: 0.30),
                ),
                filled: true,
                fillColor: AppTheme.textPrimary.withValues(alpha: 0.05),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide.none,
                ),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text(
              "បោះបង់",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.38),
              ),
            ),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: status == 'approved'
                  ? const Color(0xFF10b981)
                  : Colors.redAccent,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(10),
              ),
            ),
            child: Text(
              status == 'approved' ? "យល់ព្រម" : "បដិសេធ",
              style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
            ),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      if (!mounted) return;
      showDialog(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => const Center(child: CircularProgressIndicator()),
      );

      final res = await _api.approveRequest(
        requestId: id,
        status: status,
        adminComment: commentController.text,
      );

      if (!mounted) return;
      Navigator.pop(context); // Close loader
      if (res['success'] == true) {
        Navigator.pop(context); // Close details sheet
        _loadData(); // Refresh list
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              status == 'approved' ? "បានអនុម័តជោគជ័យ" : "បានបដិសេធជោគជ័យ",
              style: GoogleFonts.kantumruyPro(),
            ),
            backgroundColor: status == 'approved' ? Colors.green : Colors.red,
          ),
        );
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(res['message'] ?? "មានបញ្ហាក្នុងការរក្សាទុក"),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  // ========= Improved PDF Generation using Widget Rendering (Fixes Khmer Shaping) =========
  Future<void> _generatePDF(Map<String, dynamic> item) async {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => const Center(
        child: CircularProgressIndicator(color: Colors.orangeAccent),
      ),
    );

    try {
      // Ensure signatures are available for the PDF (they are excluded from list API for performance).
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

      // 2. Wait for the widget to be rendered in the current frame
      await Future.delayed(const Duration(milliseconds: 100));

      // 3. Capture the hidden widget as an image
      final boundary =
          _reportKey.currentContext?.findRenderObject()
              as RenderRepaintBoundary?;
      if (boundary == null) throw "Could not find report boundary";

      final ui.Image capturedImage = await boundary.toImage(pixelRatio: 3.0);
      final ByteData? byteData = await capturedImage.toByteData(
        format: ui.ImageByteFormat.png,
      );
      final Uint8List pngBytes = byteData!.buffer.asUint8List();

      // 4. Generate the final PDF document
      final doc = pw.Document();
      final image = pw.MemoryImage(pngBytes);
      doc.addPage(
        pw.Page(
          pageFormat: PdfPageFormat.a4,
          margin: pw.EdgeInsets.zero,
          build: (pw.Context context) {
            return pw.Center(child: pw.Image(image));
          },
        ),
      );

      final pdfBytes = await doc.save();
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
        ),
      );
    }
  }

  // Hidden Report Widget that renders in the background for capture
  Widget _buildHiddenReport(BuildContext context) {
    if (_currentReportItem == null) {
      return Container(color: AppTheme.textPrimary, width: 600, height: 850);
    }

    final item = _currentReportItem!;
    final requestType = (item['request_type'] ?? '').toString();
    final types = [
      'សម្រាកប្រចាំឆ្នាំ (Annual Leave)',
      'សម្រាកដោយជំងឺ (Sick Leave)',
      'ភ្លេចស្កេនមេដៃ (Forgot FP)',
      'សម្រាកលំហែមាតុភាព (Maternity Leave)',
      'ថែមម៉ោង (OT)',
      'ចេញមុនម៉ោង (Early)',
      'ប្តូរថ្ងៃសម្រាក (Changing day off)',
      'សម្រាកពិសេស (Special Leave)',
      'មកយឺត (Late)',
    ];

    String formatD(String? d) {
      if (d == null || d.isEmpty || d == 'N/A') return 'N/A';
      try {
        return DateFormat('dd/MM/yyyy').format(DateTime.parse(d));
      } catch (_) {
        return d;
      }
    }

    String formatT(String? t) {
      if (t == null || t.isEmpty || t == 'N/A') return 'N/A';
      try {
        DateTime? dt;
        if (t.contains('T') || t.contains('-')) {
          dt = DateTime.parse(t);
        } else if (t.contains(':')) {
          final parts = t.split(':');
          dt = DateTime(2000, 1, 1, int.parse(parts[0]), int.parse(parts[1]));
        }
        if (dt != null) {
          return DateFormat('hh:mm a').format(dt);
        }
        return t;
      } catch (_) {
        return t;
      }
    }

    String formatP(String? p) {
      if (p == null || p.isEmpty || p == 'N/A') return 'N/A';
      String cleaned = p.replaceAll(RegExp(r'\D'), '');
      if (cleaned.length == 9) {
        return '${cleaned.substring(0, 3)} ${cleaned.substring(3, 6)} ${cleaned.substring(6)}';
      } else if (cleaned.length == 10) {
        return '${cleaned.substring(0, 3)} ${cleaned.substring(3, 7)} ${cleaned.substring(7)}';
      }
      return p;
    }

    // Process signatures
    Uint8List? reqSigBytes;
    if (item['signature'] != null &&
        item['signature'].toString().startsWith('data:image')) {
      reqSigBytes = base64.decode(item['signature'].split(',').last);
    }
    Uint8List? deptSigBytes;
    if (item['department_head_signature'] != null &&
        item['department_head_signature'].toString().startsWith('data:image')) {
      deptSigBytes = base64.decode(
        item['department_head_signature'].split(',').last,
      );
    }

    return Material(
      color: AppTheme.textPrimary,
      child: Container(
        width: 800, // Increased to fill A4 better
        padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 10),
        child: Container(
          // Outer document frame
          decoration: BoxDecoration(
            border: Border.all(color: Colors.black, width: 1.5),
            borderRadius: BorderRadius.circular(2),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 15),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Header
              Column(
                children: [
                  // Logo only
                  Image.network(
                    'https://i.ibb.co/r2JWnd2x/Logo-Van-Van-1.png',
                    width: 100,
                    height: 100,
                    errorBuilder: (_, _, _) =>
                        const SizedBox(width: 100, height: 80),
                  ),
                  const SizedBox(height: 10),
                  const Text(
                    "សំណើសុំច្បាប់ឈប់សម្រាក ប្តូរវេន ចូលមុនម៉ោង មកយឺត និងភ្លេចស្កេនមេដៃផ្សេងៗ",
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: Colors.black,
                      fontFamily: 'KhmerFont',
                    ),
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
              const SizedBox(height: 25),

              // Request Selection Area (Refined Chips Grid)
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 15,
                  vertical: 12,
                ),
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.grey.shade400, width: 0.8),
                  borderRadius: BorderRadius.circular(10),
                  color: Colors.grey.shade50.withValues(alpha: 0.5),
                ),
                child: Wrap(
                  spacing: 15,
                  runSpacing: 10,
                  alignment: WrapAlignment.center,
                  children: types.map((t) {
                    final isSelected =
                        requestType.contains(t) || t.contains(requestType);
                    return Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          width: 14,
                          height: 14,
                          decoration: BoxDecoration(
                            shape: BoxShape.rectangle,
                            border: Border.all(
                              color: isSelected
                                  ? _brandOrange
                                  : Colors.grey.shade500,
                              width: 1.2,
                            ),
                            color: isSelected
                                ? _brandOrange
                                : Colors.transparent,
                            borderRadius: BorderRadius.circular(3),
                          ),
                          child: isSelected
                              ? Icon(
                                  Icons.check,
                                  size: 10,
                                  color: AppTheme.textPrimary,
                                )
                              : null,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          t,
                          style: TextStyle(
                            fontSize: 10,
                            color: isSelected ? Colors.black : Colors.black54,
                            fontWeight: isSelected
                                ? FontWeight.w600
                                : FontWeight.normal,
                            fontFamily: 'KhmerFont',
                          ),
                        ),
                      ],
                    );
                  }).toList(),
                ),
              ),
              const SizedBox(height: 20),

              // Main Table (Enlarged and Full Width)
              Table(
                border: TableBorder.all(color: Colors.black, width: 1.0),
                columnWidths: const {
                  0: FlexColumnWidth(1.2),
                  1: FlexColumnWidth(1.4),
                  2: FlexColumnWidth(1.2),
                  3: FlexColumnWidth(1.0),
                  4: FlexColumnWidth(0.6),
                },
                children: [
                  _buildTablePremiumRow([
                    "ឈ្មោះអ្នកស្នើសុំ៖",
                    item['requester_name'] ?? 'N/A',
                    "ចំនួនថ្ងៃ/ច្បាប់នៅសល់៖",
                    "${item['number_of_days'] ?? '0'} ថ្ងៃ",
                    "N/A ថ្ងៃ",
                  ]),
                  _buildTablePremiumRow([
                    "ផ្នែក/មុខតំណែង/សាខា៖",
                    item['department'] ?? 'N/A',
                    item['position'] ?? 'N/A',
                    item['branch'] ?? 'N/A',
                    "",
                  ]),
                  _buildTablePremiumRow([
                    "ថ្ងៃខែឆ្នាំសុំឈប់៖",
                    formatD(item['request_date']),
                    "ចំនួនម៉ោងយឺត/ចេញមុន៖",
                    item['late_hours']?.toString() ?? 'N/A',
                    "",
                  ]),
                  _buildTablePremiumRow([
                    "ថ្ងៃចូលធ្វើការវិញ៖",
                    formatD(item['return_date']),
                    "ភ្លេចស្កេនមេដៃ៖",
                    item['forgot_scan_in']?.toString() ?? 'N/A',
                    item['forgot_scan_out']?.toString() ?? 'N/A',
                  ]),
                  _buildTablePremiumRow([
                    "ម៉ោងចេញចូល៖",
                    "ចូល៖ ${formatT(item['time_in'])}",
                    "ចេញ៖ ${formatT(item['time_out'])}",
                    "សរុប៖ ${item['total_hours'] ?? 'N/A'}",
                    "",
                  ]),
                  _buildTablePremiumRow([
                    "ម៉ោងធ្វើការសងវិញ៖",
                    "ចូលសង៖ ${formatT(item['repay_time_in'])}",
                    "ចេញសង៖ ${formatT(item['repay_time_out'])}",
                    "សរុប៖ ${item['repay_total_hours'] ?? 'N/A'}",
                    "",
                  ]),
                  _buildTablePremiumRow(
                    ["មូលហេតុ៖", item['reason'] ?? 'N/A', "", "", ""],
                    colSpans: [1, 4],
                  ),
                  _buildTablePremiumRow(
                    [
                      "ទីកន្លែងអំឡុងពេលឈប់៖",
                      item['location'] ?? 'N/A',
                      "",
                      "",
                      "",
                    ],
                    colSpans: [1, 4],
                  ),
                  _buildTablePremiumRow([
                    "ទំនាក់ទំនងបន្ទាន់៖",
                    formatP(item['contact_number']),
                    "ប្រគល់ការងារឱ្យ៖",
                    item['assigned_to'] ?? 'N/A',
                    "",
                  ]),
                ],
              ),

              const SizedBox(height: 30),

              // Signatures Table Footer (High Contrast)
              Table(
                border: TableBorder.all(color: Colors.black, width: 1.2),
                children: [
                  TableRow(
                    children: [
                      _headerCell("បញ្ជាក់/អនុម័តដោយ"),
                      _headerCell("ឈ្មោះ (Name)"),
                      _headerCell("ហត្ថលេខា (Signature)"),
                      _headerCell("ថ្ងៃខែឆ្នាំ (Date)"),
                    ],
                  ),
                  _signatureRowWidget(
                    "អ្នកស្នើសុំ",
                    item['requester_name'] ?? 'N/A',
                    reqSigBytes,
                    formatD(item['signature_date'] ?? item['request_date']),
                  ),
                  _signatureRowWidget(
                    "ប្រធានផ្នែក",
                    item['department_head_name'] ?? '',
                    deptSigBytes,
                    formatD(item['department_head_signature_date']),
                  ),
                  _signatureRowWidget("ប្រធានធនធានមនុស្ស", "", null, ""),
                  _signatureRowWidget("ប្រធានគ្រប់គ្រងទូទៅ", "", null, ""),
                  _signatureRowWidget("អគ្គនាយិកា", "", null, ""),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  // Helper for Table Content in Widget Report - PREMIUM DESIGN
  TableRow _buildTablePremiumRow(List<String> values, {List<int>? colSpans}) {
    // Labels are columns 0 and 2
    return TableRow(
      children: values.asMap().entries.map((entry) {
        int idx = entry.key;
        String v = entry.value;

        // Skip if colSpanned away (basic logic)
        final isLabel = (idx == 0 || idx == 2);

        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          child: Text(
            v,
            style: TextStyle(
              fontSize: isLabel ? _lblSize : _valSize,
              fontFamily: 'KhmerFont',
              fontWeight: isLabel ? FontWeight.w600 : FontWeight.normal,
              color: isLabel ? Colors.black87 : Colors.black,
            ),
            maxLines: 4,
            overflow: TextOverflow.visible,
          ),
        );
      }).toList(),
    );
  }

  Widget _headerCell(String text) {
    return Container(
      padding: const EdgeInsets.all(15),
      color: Colors.grey.shade50,
      child: Center(
        child: Text(
          text,
          style: const TextStyle(
            fontSize: _lblSize,
            fontWeight: FontWeight.bold,
            color: Colors.black,
            fontFamily: 'KhmerFont',
          ),
        ),
      ),
    );
  }

  TableRow _signatureRowWidget(
    String label,
    String name,
    Uint8List? sig,
    String date,
  ) {
    return TableRow(
      children: [
        Padding(
          padding: const EdgeInsets.all(18),
          child: Text(
            label,
            style: const TextStyle(
              fontSize: _lblSize,
              fontWeight: FontWeight.bold,
              color: Colors.black,
              fontFamily: 'KhmerFont',
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.all(18),
          child: Center(
            child: Text(
              name,
              style: const TextStyle(
                fontSize: _valSize,
                color: Colors.black,
                fontFamily: 'KhmerFont',
              ),
            ),
          ),
        ),
        Container(
          height: 80,
          padding: const EdgeInsets.all(8),
          child: sig != null
              ? Image.memory(sig, fit: BoxFit.contain)
              : Center(
                  child: Container(
                    width: 70,
                    height: 1.0,
                    color: Colors.black45,
                  ),
                ),
        ),
        Padding(
          padding: const EdgeInsets.all(18),
          child: Center(
            child: Text(
              date,
              style: const TextStyle(
                fontSize: _valSize,
                color: Colors.black,
                fontFamily: 'KhmerFont',
              ),
            ),
          ),
        ),
      ],
    );
  }

  void _handleEdit(Map<String, dynamic> item) {
    Navigator.pop(context); // close modal

    // Check type and navigate to respective screen with initialData
    if (item['request_type'] == 'Leave') {
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => LeaveRequestScreen(initialData: item),
        ),
      ).then((_) => _loadData());
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text("មុខងារកែសម្រួលសម្រាប់ប្រភេទនេះនឹងមកដល់ឆាប់ៗ"),
        ),
      );
    }
  }

  Widget _buildSection(String title, IconData icon, List<Widget> children) {
    if (children.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 16, color: AppTheme.primaryLight),
              const SizedBox(width: 8),
              Text(
                title,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.primaryLight,
                  fontSize: 13,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Container(
            decoration: BoxDecoration(
              color: AppTheme.textPrimary.withValues(alpha: 0.03),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(
                color: AppTheme.textPrimary.withValues(alpha: 0.07),
              ),
            ),
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Column(children: children),
          ),
        ],
      ),
    );
  }

  Widget _detailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 110,
            child: Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.38),
                fontSize: 12,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value.isEmpty ? '-' : value,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 13,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _signatureRow(String label, String? base64Image) {
    if (base64Image == null || !base64Image.startsWith('data:image')) {
      return const SizedBox.shrink();
    }
    final base64Data = base64Image.split(',').last;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary.withValues(alpha: 0.38),
              fontSize: 12,
            ),
          ),
          const SizedBox(height: 8),
          Container(
            height: 80,
            width: double.infinity,
            decoration: BoxDecoration(
              color: AppTheme.textPrimary.withValues(alpha: 0.06),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(
                color: AppTheme.textPrimary.withValues(alpha: 0.12),
              ),
            ),
            child: Image.memory(
              base64.decode(base64Data),
              fit: BoxFit.contain,
              errorBuilder: (_, _, _) => Icon(
                Icons.broken_image_rounded,
                color: AppTheme.textPrimary.withValues(alpha: 0.24),
              ),
            ),
          ),
        ],
      ),
    );
  }

  void _confirmDelete(BuildContext sheetContext, dynamic id) {
    showDialog(
      context: context,
      builder: (dialogCtx) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Text(
          "បញ្ជាក់ការលុប",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontWeight: FontWeight.bold,
          ),
        ),
        content: Text(
          "តើអ្នកពិតជាចង់លុបសំណើ #$id មែនទេ?",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary.withValues(alpha: 0.70),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogCtx),
            child: Text(
              "បោះបង់",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.38),
              ),
            ),
          ),
          TextButton(
            onPressed: () {
              Navigator.pop(dialogCtx);
              Navigator.pop(sheetContext);
              _performDelete(id);
            },
            child: Text(
              "លុប",
              style: GoogleFonts.kantumruyPro(
                color: Colors.redAccent,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _performDelete(dynamic id) async {
    final res = await _api.deleteRequest(int.parse(id.toString()));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          res['success'] == true
              ? (res['message'] ?? 'លុបបានជោគជ័យ')
              : (res['message'] ?? 'បរាជ័យ'),
          style: GoogleFonts.kantumruyPro(),
        ),
        backgroundColor: res['success'] == true
            ? const Color(0xFF10b981)
            : Colors.redAccent,
        behavior: SnackBarBehavior.floating,
      ),
    );
    if (res['success'] == true) _loadData();
  }
}
