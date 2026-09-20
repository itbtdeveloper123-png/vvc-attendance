import 'dart:async';
import 'dart:ui' as ui;
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/vvc_liquid_glass_scaffold.dart';
import '../widgets/attendance_calendar_picker_dialog.dart';

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
    final picked = await AttendanceCalendarPickerDialog.show(
      context,
      initialStartDate: _startDate,
      initialEndDate: _endDate,
    );

    if (picked != null) {
      setState(() {
        _selectedFilter = HistoryDateFilter.custom;
        _startDate = picked.start;
        _endDate = DateTime(
          picked.end.year,
          picked.end.month,
          picked.end.day,
          23,
          59,
          59,
        );
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
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;

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
              _buildDualPodHeader(context, isDark),
              const SizedBox(height: 10),
              _buildQuickFilterChips(isDark),
              const SizedBox(height: 10),
            ],
          ),
        ),
      ),
      body: RefreshIndicator(
        onRefresh: _fetchHistory,
        color: const Color(0xFF0A84FF),
        edgeOffset: headerTotalHeight,
        child: _buildBody(topPadding: headerTotalHeight, isDark: isDark),
      ),
    );
  }

  // ===========================================================================
  // 1. DYNAMIC LIQUID GLASS DUAL-POD HEADER
  // ===========================================================================
  Widget _buildDualPodHeader(BuildContext context, bool isDark) {
    final podBg = isDark
        ? (_isScrolled
            ? const Color(0xFF24272E).withValues(alpha: 0.94)
            : const Color(0xFF1C1C1E).withValues(alpha: 0.70))
        : (_isScrolled
            ? Colors.white.withValues(alpha: 0.96)
            : Colors.white.withValues(alpha: 0.90));

    final podBorder = isDark
        ? (_isScrolled
            ? Colors.white.withValues(alpha: 0.22)
            : Colors.white.withValues(alpha: 0.10))
        : const Color(0xFFE2E8F0);

    final podShadow = isDark
        ? [
            BoxShadow(
              color: Colors.black.withValues(alpha: _isScrolled ? 0.55 : 0.15),
              blurRadius: _isScrolled ? 16 : 4,
              offset: Offset(0, _isScrolled ? 4 : 2),
            ),
          ]
        : [
            BoxShadow(
              color: const Color(0xFF0F172A).withValues(alpha: 0.06),
              blurRadius: 10,
              offset: const Offset(0, 2),
            ),
          ];

    final textColor = isDark ? Colors.white : const Color(0xFF0F172A);
    final subtextColor = isDark ? Colors.white54 : const Color(0xFF64748B);

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
                  color: podBg,
                  shape: BoxShape.circle,
                  border: Border.all(color: podBorder, width: 1.0),
                  boxShadow: podShadow,
                ),
                child: Material(
                  color: Colors.transparent,
                  child: InkWell(
                    borderRadius: BorderRadius.circular(22),
                    onTap: () {
                      HapticFeedback.lightImpact();
                      Navigator.maybePop(context);
                    },
                    child: Center(
                      child: Icon(
                        CupertinoIcons.chevron_back,
                        color: textColor,
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
                    color: podBg,
                    borderRadius: BorderRadius.circular(22),
                    border: Border.all(color: podBorder, width: 1.0),
                    boxShadow: podShadow,
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
                                color: textColor,
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
                                color: subtextColor,
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
  Widget _buildQuickFilterChips(bool isDark) {
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
            if (_startDate!.day == _endDate!.day &&
                _startDate!.month == _endDate!.month &&
                _startDate!.year == _endDate!.year) {
              label = '${_startDate!.day}/${_startDate!.month}/${_startDate!.year}';
            } else {
              label = '${_startDate!.day}/${_startDate!.month} - ${_endDate!.day}/${_endDate!.month}';
            }
          }

          final Color chipBg;
          final Color chipBorder;
          final Color chipText;
          final List<BoxShadow>? chipShadow;

          if (isSelected) {
            chipBg = isDark
                ? const Color(0xFF0A84FF).withValues(alpha: 0.22)
                : const Color(0xFF0A84FF).withValues(alpha: 0.12);
            chipBorder = isDark
                ? const Color(0xFF0A84FF).withValues(alpha: 0.70)
                : const Color(0xFF0A84FF);
            chipText = isDark ? const Color(0xFF38BDF8) : const Color(0xFF0284C7);
            chipShadow = [
              BoxShadow(
                color: const Color(0xFF0A84FF).withValues(alpha: isDark ? 0.25 : 0.15),
                blurRadius: 8,
                offset: const Offset(0, 2),
              ),
            ];
          } else {
            chipBg = isDark
                ? (_isScrolled
                    ? const Color(0xFF1C1C1E).withValues(alpha: 0.82)
                    : const Color(0xFF1C1C1E).withValues(alpha: 0.55))
                : Colors.white.withValues(alpha: 0.95);
            chipBorder = isDark
                ? (_isScrolled
                    ? Colors.white.withValues(alpha: 0.14)
                    : Colors.white.withValues(alpha: 0.07))
                : const Color(0xFFE2E8F0);
            chipText = isDark
                ? Colors.white.withValues(alpha: 0.65)
                : const Color(0xFF475569);
            chipShadow = isDark
                ? null
                : [
                    BoxShadow(
                      color: const Color(0xFF0F172A).withValues(alpha: 0.04),
                      blurRadius: 6,
                      offset: const Offset(0, 2),
                    ),
                  ];
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
                    color: chipBg,
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(
                      color: chipBorder,
                      width: isSelected ? 1.2 : 1.0,
                    ),
                    boxShadow: chipShadow,
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
                                size: 13,
                                color: isSelected
                                    ? const Color(0xFF0A84FF)
                                    : (isDark
                                        ? Colors.white.withValues(alpha: 0.65)
                                        : const Color(0xFF64748B)),
                              ),
                              const SizedBox(width: 5),
                            ],
                            Text(
                              label,
                              style: GoogleFonts.kantumruyPro(
                                color: chipText,
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
  Widget _buildBody({required double topPadding, required bool isDark}) {
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
          padding: EdgeInsets.only(top: topPadding / 2, left: 24, right: 24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(CupertinoIcons.exclamationmark_triangle,
                  color: Colors.redAccent, size: 54),
              const SizedBox(height: 16),
              Text(
                _error!,
                style: GoogleFonts.kantumruyPro(
                  color: isDark ? Colors.white : const Color(0xFF1E293B),
                  fontSize: 14,
                ),
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
          padding: EdgeInsets.only(top: topPadding / 2, left: 24, right: 24),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
            decoration: isDark
                ? null
                : BoxDecoration(
                    color: Colors.white,
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(color: const Color(0xFFE2E8F0)),
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFF0F172A).withValues(alpha: 0.05),
                        blurRadius: 16,
                        offset: const Offset(0, 4),
                      ),
                    ],
                  ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(
                  CupertinoIcons.doc_text_search,
                  color: isDark
                      ? Colors.white.withValues(alpha: 0.3)
                      : const Color(0xFF94A3B8),
                  size: 54,
                ),
                const SizedBox(height: 16),
                Text(
                  'មិនមានទិន្នន័យក្នុងចន្លោះពេលនេះ',
                  style: GoogleFonts.kantumruyPro(
                    color: isDark
                        ? Colors.white.withValues(alpha: 0.8)
                        : const Color(0xFF1E293B),
                    fontSize: 15,
                    fontWeight: FontWeight.bold,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 6),
                Text(
                  'សូមសាកល្បងជ្រើសរើសចន្លោះកាលបរិច្ឆេទផ្សេង ឬជ្រើសរើសខែនេះ',
                  style: GoogleFonts.kantumruyPro(
                    color: isDark
                        ? Colors.white.withValues(alpha: 0.45)
                        : const Color(0xFF64748B),
                    fontSize: 12,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 16),
                TextButton.icon(
                  onPressed: () => _selectQuickFilter(HistoryDateFilter.thisMonth),
                  icon: const Icon(CupertinoIcons.calendar_today, size: 16),
                  label: Text(
                    'បង្ហាញខែនេះ',
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 13,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  style: TextButton.styleFrom(
                    foregroundColor: const Color(0xFF0A84FF),
                    backgroundColor: const Color(0xFF0A84FF).withValues(alpha: 0.1),
                    padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 9),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                  ),
                ),
              ],
            ),
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
        return _buildLogItem(_logs[index] as Map<String, dynamic>, isDark);
      },
    );
  }

  // ===========================================================================
  // 4. CHECK-IN / CHECK-OUT LOG CARD (ADAPTIVE DARK & LIGHT MODE)
  // ===========================================================================
  Widget _buildLogItem(Map<String, dynamic> log, bool isDark) {
    final bool isCheckIn = log['action_type'] == 'Check-In';
    final Color ac = isCheckIn
        ? const Color(0xFF06B6D4) // Cyan / Turquoise
        : const Color(0xFFF97316); // Orange / Coral

    final bool isGood = log['status'] == 'Good' || log['status'] == 'Normal';
    final Color sc = isGood
        ? (isDark ? const Color(0xFF10B981) : const Color(0xFF16A34A))
        : const Color(0xFFEF4444);

    final Color statusBg = isGood
        ? (isDark
            ? const Color(0xFF10B981).withValues(alpha: 0.15)
            : const Color(0xFFDCFCE7))
        : (isDark
            ? const Color(0xFFEF4444).withValues(alpha: 0.15)
            : const Color(0xFFFEE2E2));

    final Color statusBorder = isGood
        ? (isDark
            ? const Color(0xFF10B981).withValues(alpha: 0.3)
            : const Color(0xFF86EFAC))
        : (isDark
            ? const Color(0xFFEF4444).withValues(alpha: 0.3)
            : const Color(0xFFFCA5A5));

    final cardBg = isDark
        ? const Color(0xFF1C1C1E).withValues(alpha: 0.85)
        : Colors.white;

    final cardBorder = isDark
        ? Colors.white.withValues(alpha: 0.08)
        : const Color(0xFFE2E8F0);

    final cardShadow = isDark
        ? [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.25),
              blurRadius: 10,
              offset: const Offset(0, 3),
            ),
          ]
        : [
            BoxShadow(
              color: const Color(0xFF0F172A).withValues(alpha: 0.04),
              blurRadius: 10,
              offset: const Offset(0, 3),
            ),
          ];

    final titleColor = isDark ? Colors.white : const Color(0xFF0F172A);
    final subtextColor = isDark
        ? Colors.white.withValues(alpha: 0.65)
        : const Color(0xFF64748B);
    final iconColor = isDark
        ? Colors.white.withValues(alpha: 0.45)
        : const Color(0xFF94A3B8);

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: cardBg,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: cardBorder,
          width: 1.0,
        ),
        boxShadow: cardShadow,
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
                          color: titleColor,
                          fontSize: 15,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      Container(
                        padding:
                            const EdgeInsets.symmetric(horizontal: 9, vertical: 3),
                        decoration: BoxDecoration(
                          color: statusBg,
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(
                            color: statusBorder,
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
                        color: iconColor,
                        size: 13,
                      ),
                      const SizedBox(width: 5),
                      Text(
                        log['log_datetime'] ?? 'N/A',
                        style: GoogleFonts.inter(
                          color: subtextColor,
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
                        color: iconColor,
                        size: 13,
                      ),
                      const SizedBox(width: 5),
                      Expanded(
                        child: Text(
                          log['location_name'] ?? 'Unknown',
                          style: GoogleFonts.kantumruyPro(
                            color: subtextColor,
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
