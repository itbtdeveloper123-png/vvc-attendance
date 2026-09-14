import 'dart:async';
import 'dart:ui' as ui;
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/api_service.dart';
import '../widgets/vvc_liquid_glass_scaffold.dart';

enum HistoryDateFilter {
  today,
  last7Days,
  thisMonth,
  custom,
}

class ScanHistoryScreen extends StatefulWidget {
  const ScanHistoryScreen({super.key});

  @override
  State<ScanHistoryScreen> createState() => _ScanHistoryScreenState();
}

class _ScanHistoryScreenState extends State<ScanHistoryScreen> {
  final ApiService _apiService = ApiService();
  final ScrollController _scrollController = ScrollController();

  bool _isLoading = true;
  bool _isLoadingMore = false;
  bool _isScrolled = false;
  List<dynamic> _logs = [];
  String? _error;

  int _offset = 0;
  final int _limit = 20;
  bool _hasMore = true;
  Timer? _pollingTimer;

  // Active filter state
  HistoryDateFilter _selectedFilter = HistoryDateFilter.thisMonth;
  DateTime? _startDate;
  DateTime? _endDate;

  @override
  void initState() {
    super.initState();
    final now = DateTime.now();
    _startDate = DateTime(now.year, now.month, 1);
    _endDate = DateTime(now.year, now.month + 1, 0, 23, 59, 59);

    _fetchHistory();
    _scrollController.addListener(_onScroll);
    _pollingTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (mounted) _fetchHistorySilently();
    });
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    _scrollController.dispose();
    super.dispose();
  }

  void _onScroll() {
    if (_scrollController.hasClients) {
      final scrolled = _scrollController.offset > 12;
      if (scrolled != _isScrolled) {
        setState(() => _isScrolled = scrolled);
      }
    }
    if (_scrollController.position.pixels >=
        _scrollController.position.maxScrollExtent - 200) {
      if (!_isLoading && !_isLoadingMore && _hasMore) {
        _fetchMore();
      }
    }
  }

  String _fmtApi(DateTime d) =>
      '${d.year}-${d.month.toString().padLeft(2, '0')}-${d.day.toString().padLeft(2, '0')}';

  String _fmtDisplay(DateTime d) =>
      '${d.day.toString().padLeft(2, '0')}/${d.month.toString().padLeft(2, '0')}/${d.year}';

  String _getKhmerMonthYear(DateTime d) {
    const months = [
      'មករា', 'កុម្ភៈ', 'មីនា', 'មេសា', 'ឧសភា', 'មិថុនា',
      'កក្កដា', 'សីហា', 'កញ្ញា', 'តុលា', 'វិច្ឆិកា', 'ធ្នូ'
    ];
    final monthName = months[d.month - 1];
    return 'ខែ$monthName ${d.year}';
  }

  String get _activePeriodLabel {
    final now = DateTime.now();
    switch (_selectedFilter) {
      case HistoryDateFilter.today:
        return 'ថ្ងៃនេះ • ${_fmtDisplay(now)}';
      case HistoryDateFilter.last7Days:
        return '៧ ថ្ងៃចុងក្រោយ';
      case HistoryDateFilter.thisMonth:
        return _getKhmerMonthYear(_startDate ?? now);
      case HistoryDateFilter.custom:
        if (_startDate != null && _endDate != null) {
          if (_startDate!.year == _endDate!.year &&
              _startDate!.month == _endDate!.month &&
              _startDate!.day == _endDate!.day) {
            return _fmtDisplay(_startDate!);
          }
          return '${_fmtDisplay(_startDate!)} - ${_fmtDisplay(_endDate!)}';
        }
        return 'ចន្លោះថ្ងៃជ្រើសរើស';
    }
  }

  void _selectQuickFilter(HistoryDateFilter filter) {
    HapticFeedback.lightImpact();
    if (filter == HistoryDateFilter.custom) {
      _pickCustomDateRange();
      return;
    }

    final now = DateTime.now();
    setState(() {
      _selectedFilter = filter;
      switch (filter) {
        case HistoryDateFilter.today:
          _startDate = DateTime(now.year, now.month, now.day);
          _endDate = DateTime(now.year, now.month, now.day, 23, 59, 59);
          break;
        case HistoryDateFilter.last7Days:
          final start = now.subtract(const Duration(days: 6));
          _startDate = DateTime(start.year, start.month, start.day);
          _endDate = DateTime(now.year, now.month, now.day, 23, 59, 59);
          break;
        case HistoryDateFilter.thisMonth:
          _startDate = DateTime(now.year, now.month, 1);
          _endDate = DateTime(now.year, now.month + 1, 0, 23, 59, 59);
          break;
        case HistoryDateFilter.custom:
          break;
      }
    });
    _fetchHistory();
  }

  Future<void> _pickCustomDateRange() async {
    HapticFeedback.lightImpact();
    final now = DateTime.now();
    final initialRange = (_startDate != null && _endDate != null)
        ? DateTimeRange(start: _startDate!, end: _endDate!)
        : DateTimeRange(
            start: DateTime(now.year, now.month, 1),
            end: now,
          );

    final picked = await showDateRangePicker(
      context: context,
      initialDateRange: initialRange,
      firstDate: DateTime(2020),
      lastDate: now,
      helpText: 'ជ្រើសរើសចន្លោះកាលបរិច្ឆេទ',
      cancelText: 'បោះបង់',
      confirmText: 'យល់ព្រម',
      builder: (context, child) => Theme(
        data: Theme.of(context).copyWith(
          colorScheme: const ColorScheme.dark(
            primary: Color(0xFF0A84FF),
            onPrimary: Colors.white,
            surface: Color(0xFF1C1C1E),
            onSurface: Colors.white,
          ),
          scaffoldBackgroundColor: const Color(0xFF000000),
          dialogTheme: const DialogThemeData(backgroundColor: Color(0xFF1C1C1E)),
          appBarTheme: const AppBarTheme(
            backgroundColor: Color(0xFF1C1C1E),
            foregroundColor: Colors.white,
          ),
        ),
        child: child!,
      ),
    );

    if (picked != null) {
      setState(() {
        _selectedFilter = HistoryDateFilter.custom;
        _startDate = picked.start;
        _endDate = DateTime(picked.end.year, picked.end.month, picked.end.day, 23, 59, 59);
      });
      _fetchHistory();
    }
  }

  Future<void> _fetchHistorySilently() async {
    try {
      final res = await _apiService.fetchAllAttendanceLogs(
        limit: _limit,
        offset: 0,
        startDate: _startDate != null ? _fmtApi(_startDate!) : null,
        endDate: _endDate != null ? _fmtApi(_endDate!) : null,
      );
      if (res['success'] == true && mounted) {
        final List<dynamic> data = res['data'] ?? [];
        setState(() {
          _logs = data;
        });
      }
    } catch (_) {}
  }

  Future<void> _fetchHistory() async {
    setState(() {
      _isLoading = true;
      _error = null;
      _offset = 0;
      _hasMore = true;
    });
    try {
      final res = await _apiService.fetchAllAttendanceLogs(
        limit: _limit,
        offset: _offset,
        startDate: _startDate != null ? _fmtApi(_startDate!) : null,
        endDate: _endDate != null ? _fmtApi(_endDate!) : null,
      );
      if (res['success'] == true) {
        final List<dynamic> data = res['data'] ?? [];
        setState(() {
          _logs = data;
          _isLoading = false;
          _offset += data.length;
          if (data.length < _limit) _hasMore = false;
        });
      } else {
        setState(() {
          _error = res['message'] ?? 'បរាជ័យក្នុងការទាញយកទិន្នន័យ';
          _isLoading = false;
        });
      }
    } catch (e) {
      setState(() {
        _error = 'កំហុស: $e';
        _isLoading = false;
      });
    }
  }

  Future<void> _fetchMore() async {
    if (_isLoadingMore || !_hasMore) return;
    setState(() => _isLoadingMore = true);
    try {
      final res = await _apiService.fetchAllAttendanceLogs(
        limit: _limit,
        offset: _offset,
        startDate: _startDate != null ? _fmtApi(_startDate!) : null,
        endDate: _endDate != null ? _fmtApi(_endDate!) : null,
      );
      if (res['success'] == true) {
        final List<dynamic> data = res['data'] ?? [];
        setState(() {
          _logs.addAll(data);
          _isLoadingMore = false;
          _offset += data.length;
          if (data.length < _limit) _hasMore = false;
        });
      } else {
        setState(() {
          _isLoadingMore = false;
          _hasMore = false;
        });
      }
    } catch (e) {
      setState(() {
        _isLoadingMore = false;
        _hasMore = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final topPadding = MediaQuery.paddingOf(context).top;
    final headerTotalHeight = topPadding + 6 + 44 + 10 + 36 + 10;
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return VvcLiquidGlassScaffold(
      showHeader: true,
      showTopTransitionZone: true,
      topTransitionZoneHeight: headerTotalHeight,
      backgroundColor: isDark ? const Color(0xFF000000) : const Color(0xFFF8FAFC),
      onScrollChanged: (scrolled) {
        if (scrolled != _isScrolled) {
          setState(() => _isScrolled = scrolled);
        }
      },
      customHeaderBuilder: (context, isScrolled) => Positioned(
        top: 0,
        left: 0,
        right: 0,
        child: SafeArea(
          bottom: false,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 6),
              _buildDualPodHeader(context),
              const SizedBox(height: 10),
              _buildQuickFilterChips(),
              const SizedBox(height: 10),
            ],
          ),
        ),
      ),
      body: RefreshIndicator(
        onRefresh: _fetchHistory,
        color: const Color(0xFF0A84FF),
        edgeOffset: headerTotalHeight,
        child: _buildBody(topPadding: headerTotalHeight),
      ),
    );
  }

  // ===========================================================================
  // 1. DYNAMIC LIQUID GLASS DUAL-POD HEADER
  // ===========================================================================
  Widget _buildDualPodHeader(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 14),
      child: Row(
        children: [
          // Left Pod: Back Capsule (44x44)
          ClipRRect(
            borderRadius: BorderRadius.circular(22),
            child: BackdropFilter(
              filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 250),
                curve: Curves.easeInOutCubic,
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  color: _isScrolled
                      ? const Color(0xFF24272E).withValues(alpha: 0.94)
                      : const Color(0xFF1C1C1E).withValues(alpha: 0.65),
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: _isScrolled
                        ? Colors.white.withValues(alpha: 0.22)
                        : Colors.white.withValues(alpha: 0.10),
                    width: 1.0,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: _isScrolled ? 0.55 : 0.15),
                      blurRadius: _isScrolled ? 16 : 4,
                      offset: Offset(0, _isScrolled ? 4 : 2),
                    ),
                  ],
                ),
                child: Material(
                  color: Colors.transparent,
                  child: InkWell(
                    borderRadius: BorderRadius.circular(22),
                    onTap: () {
                      HapticFeedback.lightImpact();
                      Navigator.maybePop(context);
                    },
                    child: const Center(
                      child: Icon(
                        CupertinoIcons.chevron_back,
                        color: Colors.white,
                        size: 20,
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(width: 10),

          // Right Pod: Title & Filter Capsule (Height: 44)
          Expanded(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(22),
              child: BackdropFilter(
                filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 250),
                  curve: Curves.easeInOutCubic,
                  height: 44,
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  decoration: BoxDecoration(
                    color: _isScrolled
                        ? const Color(0xFF24272E).withValues(alpha: 0.94)
                        : const Color(0xFF1C1C1E).withValues(alpha: 0.65),
                    borderRadius: BorderRadius.circular(22),
                    border: Border.all(
                      color: _isScrolled
                          ? Colors.white.withValues(alpha: 0.22)
                          : Colors.white.withValues(alpha: 0.10),
                      width: 1.0,
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: _isScrolled ? 0.55 : 0.15),
                        blurRadius: _isScrolled ? 16 : 4,
                        offset: Offset(0, _isScrolled ? 4 : 2),
                      ),
                    ],
                  ),
                  child: Row(
                    children: [
                      // Title & Sub-label
                      Expanded(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'ប្រវត្តិចុះវត្តមាន',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white,
                                fontSize: 14,
                                fontWeight: FontWeight.bold,
                                letterSpacing: 0.2,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                            Text(
                              _activePeriodLabel,
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white54,
                                fontSize: 10.5,
                                fontWeight: FontWeight.w500,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ],
                        ),
                      ),

                      // Trailing Action: Interactive Calendar Icon
                      Material(
                        color: Colors.transparent,
                        child: InkWell(
                          borderRadius: BorderRadius.circular(16),
                          onTap: _pickCustomDateRange,
                          child: const Padding(
                            padding: EdgeInsets.all(6),
                            child: Icon(
                              CupertinoIcons.calendar,
                              color: Color(0xFF0A84FF),
                              size: 20,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ===========================================================================
  // 2. SLEEK QUICK-FILTER CHIPS
  // ===========================================================================
  Widget _buildQuickFilterChips() {
    final chips = [
      {'filter': HistoryDateFilter.today, 'label': 'ថ្ងៃនេះ'},
      {'filter': HistoryDateFilter.last7Days, 'label': '៧ ថ្ងៃចុងក្រោយ'},
      {'filter': HistoryDateFilter.thisMonth, 'label': 'ខែនេះ'},
      {'filter': HistoryDateFilter.custom, 'label': 'ជ្រើសរើសថ្ងៃ...'},
    ];

    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      physics: const BouncingScrollPhysics(),
      padding: const EdgeInsets.symmetric(horizontal: 14),
      child: Row(
        children: chips.map((item) {
          final filter = item['filter'] as HistoryDateFilter;
          final isSelected = _selectedFilter == filter;
          String label = item['label'] as String;

          if (filter == HistoryDateFilter.custom &&
              isSelected &&
              _startDate != null &&
              _endDate != null) {
            label = '${_startDate!.day}/${_startDate!.month} - ${_endDate!.day}/${_endDate!.month}';
          }

          return Padding(
            padding: const EdgeInsets.only(right: 8),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(16),
              child: BackdropFilter(
                filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 250),
                  curve: Curves.easeOutCubic,
                  decoration: BoxDecoration(
                    color: isSelected
                        ? const Color(0xFF0A84FF).withValues(alpha: 0.22)
                        : _isScrolled
                            ? const Color(0xFF1C1C1E).withValues(alpha: 0.82)
                            : const Color(0xFF1C1C1E).withValues(alpha: 0.55),
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(
                      color: isSelected
                          ? const Color(0xFF0A84FF).withValues(alpha: 0.70)
                          : _isScrolled
                              ? Colors.white.withValues(alpha: 0.14)
                              : Colors.white.withValues(alpha: 0.07),
                      width: isSelected ? 1.2 : 1.0,
                    ),
                    boxShadow: isSelected
                        ? [
                            BoxShadow(
                              color: const Color(0xFF0A84FF).withValues(alpha: 0.25),
                              blurRadius: 8,
                              offset: const Offset(0, 2),
                            ),
                          ]
                        : null,
                  ),
                  child: Material(
                    color: Colors.transparent,
                    child: InkWell(
                      borderRadius: BorderRadius.circular(16),
                      onTap: () => _selectQuickFilter(filter),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 14,
                          vertical: 7,
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            if (filter == HistoryDateFilter.custom) ...[
                              Icon(
                                CupertinoIcons.calendar,
                                size: 12,
                                color: isSelected
                                    ? const Color(0xFF0A84FF)
                                    : Colors.white.withValues(alpha: 0.65),
                              ),
                              const SizedBox(width: 5),
                            ],
                            Text(
                              label,
                              style: GoogleFonts.kantumruyPro(
                                color: isSelected
                                    ? const Color(0xFF38BDF8)
                                    : Colors.white.withValues(alpha: 0.65),
                                fontSize: 12,
                                fontWeight: isSelected
                                    ? FontWeight.bold
                                    : FontWeight.w500,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ),
          );
        }).toList(),
      ),
    );
  }

  // ===========================================================================
  // 3. BODY & LIST VIEW
  // ===========================================================================
  Widget _buildBody({required double topPadding}) {
    if (_isLoading) {
      return Center(
        child: Padding(
          padding: EdgeInsets.only(top: topPadding / 2),
          child: const CircularProgressIndicator(
            color: Color(0xFF0A84FF),
            strokeWidth: 2.2,
          ),
        ),
      );
    }

    if (_error != null) {
      return Center(
        child: Padding(
          padding: EdgeInsets.only(top: topPadding / 2),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(CupertinoIcons.exclamationmark_triangle,
                  color: Colors.redAccent, size: 54),
              const SizedBox(height: 16),
              Text(
                _error!,
                style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 20),
              ElevatedButton.icon(
                onPressed: _fetchHistory,
                icon: const Icon(CupertinoIcons.refresh, size: 16),
                label: Text('ព្យាយាមម្តងទៀត',
                    style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF0A84FF),
                  foregroundColor: Colors.white,
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14)),
                  padding:
                      const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                ),
              ),
            ],
          ),
        ),
      );
    }

    if (_logs.isEmpty) {
      return Center(
        child: Padding(
          padding: EdgeInsets.only(top: topPadding / 2),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                CupertinoIcons.doc_text_search,
                color: Colors.white.withValues(alpha: 0.3),
                size: 54,
              ),
              const SizedBox(height: 16),
              Text(
                'មិនមានទិន្នន័យក្នុងចន្លោះពេលនេះ',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white.withValues(alpha: 0.6),
                  fontSize: 14,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 14),
              TextButton.icon(
                onPressed: () => _selectQuickFilter(HistoryDateFilter.thisMonth),
                icon: const Icon(CupertinoIcons.calendar_today, size: 16),
                label: Text(
                  'បង្ហាញខែនេះ',
                  style: GoogleFonts.kantumruyPro(
                      fontSize: 13, fontWeight: FontWeight.bold),
                ),
                style: TextButton.styleFrom(foregroundColor: const Color(0xFF0A84FF)),
              ),
            ],
          ),
        ),
      );
    }

    return ListView.builder(
      controller: _scrollController,
      physics:
          const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics()),
      padding: EdgeInsets.fromLTRB(16, topPadding + 4, 16, 24),
      itemCount: _logs.length + (_hasMore ? 1 : 0),
      itemBuilder: (context, index) {
        if (index == _logs.length) {
          return const Padding(
            padding: EdgeInsets.symmetric(vertical: 20),
            child: Center(
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: Color(0xFF0A84FF),
              ),
            ),
          );
        }
        return _buildLogItem(_logs[index] as Map<String, dynamic>);
      },
    );
  }

  // ===========================================================================
  // 4. CHECK-IN / CHECK-OUT LOG CARD (APPLE / TELEGRAM DARK STYLE)
  // ===========================================================================
  Widget _buildLogItem(Map<String, dynamic> log) {
    final bool isCheckIn = log['action_type'] == 'Check-In';
    final Color ac = isCheckIn
        ? const Color(0xFF06B6D4) // Cyan / Turquoise
        : const Color(0xFFF97316); // Orange / Coral
    final Color sc = (log['status'] == 'Good' || log['status'] == 'Normal')
        ? const Color(0xFF10B981)
        : const Color(0xFFEF4444);

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: const Color(0xFF1C1C1E).withValues(alpha: 0.85),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: Colors.white.withValues(alpha: 0.08),
          width: 1.0,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.25),
            blurRadius: 10,
            offset: const Offset(0, 3),
          ),
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: ac.withValues(alpha: 0.12),
                shape: BoxShape.circle,
              ),
              child: Icon(
                isCheckIn ? Icons.login_rounded : Icons.logout_rounded,
                color: ac,
                size: 20,
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        log['action_type'] ?? 'N/A',
                        style: GoogleFonts.inter(
                          color: Colors.white,
                          fontSize: 15,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      Container(
                        padding:
                            const EdgeInsets.symmetric(horizontal: 9, vertical: 3),
                        decoration: BoxDecoration(
                          color: sc.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(
                            color: sc.withValues(alpha: 0.3),
                            width: 0.8,
                          ),
                        ),
                        child: Text(
                          log['status'] ?? 'N/A',
                          style: GoogleFonts.inter(
                            color: sc,
                            fontSize: 10.5,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Row(
                    children: [
                      Icon(
                        CupertinoIcons.time,
                        color: Colors.white.withValues(alpha: 0.45),
                        size: 13,
                      ),
                      const SizedBox(width: 5),
                      Text(
                        log['log_datetime'] ?? 'N/A',
                        style: GoogleFonts.inter(
                          color: Colors.white.withValues(alpha: 0.65),
                          fontSize: 12,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      Icon(
                        CupertinoIcons.location_solid,
                        color: Colors.white.withValues(alpha: 0.45),
                        size: 13,
                      ),
                      const SizedBox(width: 5),
                      Expanded(
                        child: Text(
                          log['location_name'] ?? 'Unknown',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white.withValues(alpha: 0.45),
                            fontSize: 11,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
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
    );
  }
}
