import 'dart:ui' as ui;
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';

/// Attendance stats for a specific day
class DayAttendanceStats {
  final int day;
  final int totalCount;
  final int checkInCount;
  final int checkOutCount;
  final int lateCount;
  final int goodCount;

  const DayAttendanceStats({
    required this.day,
    required this.totalCount,
    this.checkInCount = 0,
    this.checkOutCount = 0,
    this.lateCount = 0,
    this.goodCount = 0,
  });

  factory DayAttendanceStats.fromJson(Map<String, dynamic> json) {
    return DayAttendanceStats(
      day: int.tryParse(json['day']?.toString() ?? '0') ?? 0,
      totalCount: int.tryParse(json['count']?.toString() ?? '0') ?? 0,
      checkInCount: int.tryParse(json['check_in_count']?.toString() ?? '0') ?? 0,
      checkOutCount: int.tryParse(json['check_out_count']?.toString() ?? '0') ?? 0,
      lateCount: int.tryParse(json['late_count']?.toString() ?? '0') ?? 0,
      goodCount: int.tryParse(json['good_count']?.toString() ?? '0') ?? 0,
    );
  }
}

/// Attendance stats for a specific month
class MonthAttendanceStats {
  final int month;
  final int totalCount;
  final int activeDays;

  const MonthAttendanceStats({
    required this.month,
    required this.totalCount,
    required this.activeDays,
  });

  factory MonthAttendanceStats.fromJson(Map<String, dynamic> json) {
    return MonthAttendanceStats(
      month: int.tryParse(json['month']?.toString() ?? '0') ?? 0,
      totalCount: int.tryParse(json['count']?.toString() ?? '0') ?? 0,
      activeDays: int.tryParse(json['active_days']?.toString() ?? '0') ?? 0,
    );
  }
}

/// A modern, high-aesthetic Liquid Glass Attendance Calendar & Date Range Picker
class AttendanceCalendarPickerDialog extends StatefulWidget {
  final DateTime? initialStartDate;
  final DateTime? initialEndDate;
  final DateTime? minDate;
  final DateTime? maxDate;

  const AttendanceCalendarPickerDialog({
    super.key,
    this.initialStartDate,
    this.initialEndDate,
    this.minDate,
    this.maxDate,
  });

  /// Displays the picker as a beautiful full-featured modal sheet
  static Future<DateTimeRange?> show(
    BuildContext context, {
    DateTime? initialStartDate,
    DateTime? initialEndDate,
    DateTime? minDate,
    DateTime? maxDate,
  }) {
    return showModalBottomSheet<DateTimeRange?>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      barrierColor: Colors.black.withValues(alpha: 0.75),
      builder: (context) => AttendanceCalendarPickerDialog(
        initialStartDate: initialStartDate,
        initialEndDate: initialEndDate,
        minDate: minDate,
        maxDate: maxDate,
      ),
    );
  }

  @override
  State<AttendanceCalendarPickerDialog> createState() =>
      _AttendanceCalendarPickerDialogState();
}

class _AttendanceCalendarPickerDialogState
    extends State<AttendanceCalendarPickerDialog> {
  final ApiService _apiService = ApiService();

  late DateTime _currentMonth;
  DateTime? _startDate;
  DateTime? _endDate;
  DateTime? _previewDate;

  // View mode: false = calendar days view, true = month grid view
  bool _isMonthGridView = false;

  // Caches for fast switching
  final Map<String, Map<int, DayAttendanceStats>> _monthDaysCache = {};
  final Map<int, Map<int, MonthAttendanceStats>> _yearMonthsCache = {};

  bool _isLoadingMonth = false;
  bool _isLoadingPreview = false;
  List<Map<String, dynamic>> _previewDayRecords = [];

  static const List<String> _khmerMonths = [
    'មករា',
    'កុម្ភៈ',
    'មីនា',
    'មេសា',
    'ឧសភា',
    'មិថុនា',
    'កក្កដា',
    'សីហា',
    'កញ្ញា',
    'តុលា',
    'វិច្ឆិកា',
    'ធ្នូ',
  ];

  static const List<String> _khmerWeekDays = [
    'អា',
    'ច',
    'អ',
    'ព',
    'ព្រ',
    'សុ',
    'ស',
  ];

  @override
  void initState() {
    super.initState();
    final now = DateTime.now();
    _startDate = widget.initialStartDate;
    _endDate = widget.initialEndDate;

    final baseDate = _endDate ?? _startDate ?? now;
    _currentMonth = DateTime(baseDate.year, baseDate.month, 1);
    _previewDate = _endDate ?? _startDate ?? now;

    _loadMonthDaysData(_currentMonth.year, _currentMonth.month);
    _loadYearMonthsData(_currentMonth.year);
    if (_previewDate != null) {
      _loadDayRecords(_previewDate!);
    }
  }

  String _cacheKey(int year, int month) => '$year-$month';

  Future<void> _loadMonthDaysData(int year, int month) async {
    final key = _cacheKey(year, month);
    if (_monthDaysCache.containsKey(key)) return;

    setState(() => _isLoadingMonth = true);
    try {
      final res = await _apiService.fetchLogTree(year: year, month: month);
      if (res['success'] == true && res['data'] is List) {
        final map = <int, DayAttendanceStats>{};
        for (final item in (res['data'] as List)) {
          if (item is Map<String, dynamic>) {
            final stats = DayAttendanceStats.fromJson(item);
            if (stats.day > 0) map[stats.day] = stats;
          }
        }
        if (mounted) {
          setState(() {
            _monthDaysCache[key] = map;
            _isLoadingMonth = false;
          });
        }
        return;
      }
    } catch (_) {}

    if (mounted) setState(() => _isLoadingMonth = false);
  }

  Future<void> _loadYearMonthsData(int year) async {
    if (_yearMonthsCache.containsKey(year)) return;

    try {
      final res = await _apiService.fetchLogTree(year: year);
      if (res['success'] == true && res['data'] is List) {
        final map = <int, MonthAttendanceStats>{};
        for (final item in (res['data'] as List)) {
          if (item is Map<String, dynamic>) {
            final stats = MonthAttendanceStats.fromJson(item);
            if (stats.month > 0) map[stats.month] = stats;
          }
        }
        if (mounted) {
          setState(() {
            _yearMonthsCache[year] = map;
          });
        }
      }
    } catch (_) {}
  }

  Future<void> _loadDayRecords(DateTime date) async {
    setState(() {
      _isLoadingPreview = true;
      _previewDayRecords = [];
    });
    try {
      final res = await _apiService.fetchLogTree(
        year: date.year,
        month: date.month,
        day: date.day,
      );
      if (res['success'] == true && res['data'] is List) {
        if (mounted) {
          setState(() {
            _previewDayRecords =
                (res['data'] as List).cast<Map<String, dynamic>>();
            _isLoadingPreview = false;
          });
          return;
        }
      }
    } catch (_) {}

    if (mounted) setState(() => _isLoadingPreview = false);
  }

  void _onDayTapped(DateTime day) {
    HapticFeedback.selectionClick();
    setState(() {
      _previewDate = day;
      if (_startDate == null || (_startDate != null && _endDate != null)) {
        _startDate = day;
        _endDate = null;
      } else if (_startDate != null && _endDate == null) {
        if (day.isBefore(_startDate!)) {
          _startDate = day;
        } else {
          _endDate = DateTime(day.year, day.month, day.day, 23, 59, 59);
        }
      }
    });
    _loadDayRecords(day);
  }

  void _applyQuickPreset(String type) {
    HapticFeedback.lightImpact();
    final now = DateTime.now();
    DateTime s;
    DateTime e;

    switch (type) {
      case 'today':
        s = DateTime(now.year, now.month, now.day);
        e = DateTime(now.year, now.month, now.day, 23, 59, 59);
        break;
      case 'yesterday':
        final y = now.subtract(const Duration(days: 1));
        s = DateTime(y.year, y.month, y.day);
        e = DateTime(y.year, y.month, y.day, 23, 59, 59);
        break;
      case 'last7':
        final start = now.subtract(const Duration(days: 6));
        s = DateTime(start.year, start.month, start.day);
        e = DateTime(now.year, now.month, now.day, 23, 59, 59);
        break;
      case 'thisMonth':
        s = DateTime(now.year, now.month, 1);
        e = DateTime(now.year, now.month + 1, 0, 23, 59, 59);
        break;
      default:
        return;
    }

    setState(() {
      _startDate = s;
      _endDate = e;
      _previewDate = s;
      _currentMonth = DateTime(s.year, s.month, 1);
      _isMonthGridView = false;
    });

    _loadMonthDaysData(s.year, s.month);
    _loadDayRecords(s);
  }

  void _confirmSelection() {
    HapticFeedback.mediumImpact();
    if (_startDate == null) {
      Navigator.pop(context);
      return;
    }

    final start = _startDate!;
    final end = _endDate ??
        DateTime(start.year, start.month, start.day, 23, 59, 59);

    Navigator.pop(
      context,
      DateTimeRange(start: start, end: end),
    );
  }

  void _prevMonth() {
    HapticFeedback.selectionClick();
    setState(() {
      _currentMonth = DateTime(_currentMonth.year, _currentMonth.month - 1, 1);
    });
    _loadMonthDaysData(_currentMonth.year, _currentMonth.month);
  }

  void _nextMonth() {
    HapticFeedback.selectionClick();
    setState(() {
      _currentMonth = DateTime(_currentMonth.year, _currentMonth.month + 1, 1);
    });
    _loadMonthDaysData(_currentMonth.year, _currentMonth.month);
  }

  String _formatRangeKhmer() {
    if (_startDate == null) return 'ជ្រើសរើសថ្ងៃ';
    final s = _startDate!;
    final sMonth = _khmerMonths[s.month - 1];

    if (_endDate == null ||
        (_startDate!.year == _endDate!.year &&
            _startDate!.month == _endDate!.month &&
            _startDate!.day == _endDate!.day)) {
      return '${s.day} $sMonth ${s.year}';
    }

    final e = _endDate!;
    final eMonth = _khmerMonths[e.month - 1];

    if (s.month == e.month && s.year == e.year) {
      return '${s.day} – ${e.day} $sMonth ${s.year}';
    }
    return '${s.day} $sMonth – ${e.day} $eMonth ${e.year}';
  }

  @override
  Widget build(BuildContext context) {
    final bottomInset = MediaQuery.paddingOf(context).bottom;
    final maxH = MediaQuery.sizeOf(context).height * 0.92;
    final isDark = Theme.of(context).brightness == Brightness.dark || AppTheme.isDarkMode;

    final modalBg = isDark ? const Color(0xFF141416) : Colors.white;
    final modalBorder = isDark ? Colors.white.withValues(alpha: 0.12) : const Color(0xFFE2E8F0);
    final dividerColor = isDark ? const Color(0x1FFFFFFF) : const Color(0xFFF1F5F9);

    return Container(
      constraints: BoxConstraints(maxHeight: maxH),
      decoration: BoxDecoration(
        color: modalBg,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
        border: Border.all(
          color: modalBorder,
          width: 1,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.6 : 0.15),
            blurRadius: 32,
            offset: const Offset(0, -8),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
        child: BackdropFilter(
          filter: ui.ImageFilter.blur(sigmaX: 25, sigmaY: 25),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              _buildDragHandle(isDark),
              _buildTopHeader(isDark),
              Divider(color: dividerColor, height: 1),
              _buildQuickChips(isDark),
              Expanded(
                child: SingleChildScrollView(
                  physics: const BouncingScrollPhysics(),
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: Column(
                    children: [
                      const SizedBox(height: 8),
                      _buildMonthNavigator(isDark),
                      const SizedBox(height: 12),
                      if (_isMonthGridView)
                        _buildYearMonthsGrid(isDark)
                      else ...[
                        _buildWeekdaysHeader(isDark),
                        const SizedBox(height: 8),
                        _buildDaysGrid(isDark),
                        const SizedBox(height: 14),
                        _buildLegendAndSummary(isDark),
                        const SizedBox(height: 12),
                        _buildDayPreviewCard(isDark),
                      ],
                      const SizedBox(height: 16),
                    ],
                  ),
                ),
              ),
              _buildBottomActionBar(bottomInset, isDark),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDragHandle(bool isDark) {
    return Padding(
      padding: const EdgeInsets.only(top: 8, bottom: 4),
      child: Container(
        width: 38,
        height: 4.5,
        decoration: BoxDecoration(
          color: isDark
              ? Colors.white.withValues(alpha: 0.25)
              : const Color(0xFFCBD5E1),
          borderRadius: BorderRadius.circular(3),
        ),
      ),
    );
  }

  // ===========================================================================
  // 1. TOP HEADER
  // ===========================================================================
  Widget _buildTopHeader(bool isDark) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Row(
        children: [
          // Close button
          Material(
            color: Colors.transparent,
            child: InkWell(
              borderRadius: BorderRadius.circular(20),
              onTap: () {
                HapticFeedback.lightImpact();
                Navigator.pop(context);
              },
              child: Container(
                padding: const EdgeInsets.all(7),
                decoration: BoxDecoration(
                  color: isDark
                      ? Colors.white.withValues(alpha: 0.08)
                      : const Color(0xFFF1F5F9),
                  shape: BoxShape.circle,
                ),
                child: Icon(
                  CupertinoIcons.xmark,
                  color: isDark ? Colors.white : const Color(0xFF0F172A),
                  size: 18,
                ),
              ),
            ),
          ),
          const SizedBox(width: 12),

          // Title & active selection range
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  'ជ្រើសរើសចន្លោះកាលបរិច្ឆេទ',
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? Colors.white70 : const Color(0xFF64748B),
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  _formatRangeKhmer(),
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? const Color(0xFF00D1FF) : const Color(0xFF0284C7),
                    fontSize: 17,
                    fontWeight: FontWeight.bold,
                    letterSpacing: -0.2,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),

          // Confirm button
          Material(
            color: Colors.transparent,
            child: InkWell(
              borderRadius: BorderRadius.circular(16),
              onTap: _confirmSelection,
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                decoration: BoxDecoration(
                  gradient: const LinearGradient(
                    colors: [Color(0xFF0A84FF), Color(0xFF00D1FF)],
                  ),
                  borderRadius: BorderRadius.circular(16),
                  boxShadow: [
                    BoxShadow(
                      color: const Color(0xFF0A84FF).withValues(alpha: 0.35),
                      blurRadius: 10,
                      offset: const Offset(0, 3),
                    ),
                  ],
                ),
                child: Text(
                  'រក្សាទុក',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontSize: 13.5,
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

  // ===========================================================================
  // 2. QUICK CHIPS
  // ===========================================================================
  Widget _buildQuickChips(bool isDark) {
    final chips = [
      {'id': 'today', 'label': 'ថ្ងៃនេះ'},
      {'id': 'yesterday', 'label': 'ម្សិលមិញ'},
      {'id': 'last7', 'label': '៧ ថ្ងៃចុងក្រោយ'},
      {'id': 'thisMonth', 'label': 'ខែនេះទាំងមូល'},
    ];

    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      physics: const BouncingScrollPhysics(),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      child: Row(
        children: chips.map((item) {
          final id = item['id'] as String;
          final label = item['label'] as String;
          return Padding(
            padding: const EdgeInsets.only(right: 8),
            child: Material(
              color: Colors.transparent,
              child: InkWell(
                borderRadius: BorderRadius.circular(12),
                onTap: () => _applyQuickPreset(id),
                child: Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  decoration: BoxDecoration(
                    color: isDark ? const Color(0xFF222226) : const Color(0xFFF8FAFC),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: isDark
                          ? Colors.white.withValues(alpha: 0.1)
                          : const Color(0xFFE2E8F0),
                    ),
                    boxShadow: isDark
                        ? null
                        : [
                            BoxShadow(
                              color: const Color(0xFF0F172A).withValues(alpha: 0.03),
                              blurRadius: 4,
                              offset: const Offset(0, 1),
                            ),
                          ],
                  ),
                  child: Text(
                    label,
                    style: GoogleFonts.kantumruyPro(
                      color: isDark
                          ? Colors.white.withValues(alpha: 0.85)
                          : const Color(0xFF475569),
                      fontSize: 11.5,
                      fontWeight: FontWeight.w500,
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
  // 3. MONTH NAVIGATOR (Supports switching to 12 Months Grid)
  // ===========================================================================
  Widget _buildMonthNavigator(bool isDark) {
    final mName = _khmerMonths[_currentMonth.month - 1];
    final yr = _currentMonth.year;

    // Monthly stats badge if available
    final key = _cacheKey(yr, _currentMonth.month);
    final daysStats = _monthDaysCache[key];
    final activeDaysCount = daysStats?.length ?? 0;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF1D1D20) : const Color(0xFFF8FAFC),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: isDark
              ? Colors.white.withValues(alpha: 0.08)
              : const Color(0xFFE2E8F0),
        ),
      ),
      child: Row(
        children: [
          // Previous month arrow
          IconButton(
            icon: Icon(CupertinoIcons.chevron_left,
                size: 18,
                color: isDark ? Colors.white : const Color(0xFF0F172A)),
            onPressed: _prevMonth,
            visualDensity: VisualDensity.compact,
          ),

          // Tappable Month / Year Center
          Expanded(
            child: Material(
              color: Colors.transparent,
              child: InkWell(
                borderRadius: BorderRadius.circular(12),
                onTap: () {
                  HapticFeedback.lightImpact();
                  setState(() => _isMonthGridView = !_isMonthGridView);
                  if (_isMonthGridView) {
                    _loadYearMonthsData(_currentMonth.year);
                  }
                },
                child: Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        '$mName $yr',
                        style: GoogleFonts.kantumruyPro(
                          color: isDark ? Colors.white : const Color(0xFF0F172A),
                          fontSize: 15.5,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(width: 4),
                      Icon(
                        _isMonthGridView
                            ? CupertinoIcons.chevron_up
                            : CupertinoIcons.chevron_down,
                        size: 14,
                        color: const Color(0xFF00D1FF),
                      ),
                      if (activeDaysCount > 0 && !_isMonthGridView) ...[
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 7, vertical: 2),
                          decoration: BoxDecoration(
                            color: const Color(0xFF10B981)
                                .withValues(alpha: 0.18),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(
                              color: const Color(0xFF10B981)
                                  .withValues(alpha: 0.4),
                              width: 0.8,
                            ),
                          ),
                          child: Text(
                            '$activeDaysCount ថ្ងៃស្កេន',
                            style: GoogleFonts.kantumruyPro(
                              color: const Color(0xFF34D399),
                              fontSize: 10,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ),
          ),

          // Next month arrow
          IconButton(
            icon: Icon(CupertinoIcons.chevron_right,
                size: 18,
                color: isDark ? Colors.white : const Color(0xFF0F172A)),
            onPressed: _nextMonth,
            visualDensity: VisualDensity.compact,
          ),
        ],
      ),
    );
  }

  // ===========================================================================
  // 4. MONTH GRID (Shows which months have attendance in the year)
  // ===========================================================================
  Widget _buildYearMonthsGrid(bool isDark) {
    final year = _currentMonth.year;
    final yearStats = _yearMonthsCache[year] ?? {};

    return Container(
      margin: const EdgeInsets.only(top: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF19191C) : const Color(0xFFF8FAFC),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: isDark
              ? Colors.white.withValues(alpha: 0.08)
              : const Color(0xFFE2E8F0),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 6),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'ជ្រើសរើសខែក្នុងឆ្នាំ $year',
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? Colors.white70 : const Color(0xFF1E293B),
                    fontSize: 13,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                Text(
                  'បង្ហាញវត្តមានតាមខែនីមួយៗ',
                  style: GoogleFonts.kantumruyPro(
                    color: isDark ? const Color(0xFF00D1FF) : const Color(0xFF0284C7),
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 8),
          GridView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: 12,
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 3,
              mainAxisSpacing: 10,
              crossAxisSpacing: 10,
              childAspectRatio: 1.7,
            ),
            itemBuilder: (context, index) {
              final mIndex = index + 1;
              final mName = _khmerMonths[index];
              final isCurrent = _currentMonth.month == mIndex;
              final stats = yearStats[mIndex];
              final hasAttendance = stats != null && stats.totalCount > 0;

              final tileBg = isCurrent
                  ? (isDark
                      ? const Color(0xFF0A84FF).withValues(alpha: 0.25)
                      : const Color(0xFF0A84FF).withValues(alpha: 0.12))
                  : hasAttendance
                      ? (isDark ? const Color(0xFF22252C) : const Color(0xFFF0FDF4))
                      : (isDark ? const Color(0xFF1E1E22) : Colors.white);

              final tileBorder = isCurrent
                  ? const Color(0xFF0A84FF)
                  : hasAttendance
                      ? (isDark
                          ? const Color(0xFF10B981).withValues(alpha: 0.45)
                          : const Color(0xFF86EFAC))
                      : (isDark
                          ? Colors.white.withValues(alpha: 0.08)
                          : const Color(0xFFE2E8F0));

              final textColor = isCurrent
                  ? const Color(0xFF0A84FF)
                  : (isDark ? Colors.white : const Color(0xFF0F172A));

              return Material(
                color: Colors.transparent,
                child: InkWell(
                  borderRadius: BorderRadius.circular(14),
                  onTap: () {
                    HapticFeedback.lightImpact();
                    setState(() {
                      _currentMonth = DateTime(year, mIndex, 1);
                      _isMonthGridView = false;
                    });
                    _loadMonthDaysData(year, mIndex);
                  },
                  child: Container(
                    decoration: BoxDecoration(
                      color: tileBg,
                      borderRadius: BorderRadius.circular(14),
                      border: Border.all(
                        color: tileBorder,
                        width: isCurrent ? 1.4 : 1.0,
                      ),
                    ),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          mName,
                          style: GoogleFonts.kantumruyPro(
                            color: textColor,
                            fontSize: 13,
                            fontWeight: isCurrent
                                ? FontWeight.bold
                                : FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 3),
                        if (hasAttendance)
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 6, vertical: 1.5),
                            decoration: BoxDecoration(
                              color: const Color(0xFF10B981)
                                  .withValues(alpha: isDark ? 0.2 : 0.15),
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Text(
                              '${stats.activeDays > 0 ? stats.activeDays : stats.totalCount} ថ្ងៃស្កេន',
                              style: GoogleFonts.kantumruyPro(
                                color: isDark
                                    ? const Color(0xFF34D399)
                                    : const Color(0xFF16A34A),
                                fontSize: 9.5,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          )
                        else
                          Text(
                            'គ្មានទិន្នន័យ',
                            style: GoogleFonts.kantumruyPro(
                              color: isDark ? Colors.white24 : const Color(0xFF94A3B8),
                              fontSize: 9.5,
                            ),
                          ),
                      ],
                    ),
                  ),
                ),
              );
            },
          ),
        ],
      ),
    );
  }

  // ===========================================================================
  // 5. WEEKDAYS HEADER (Sun - Sat)
  // ===========================================================================
  Widget _buildWeekdaysHeader(bool isDark) {
    return Row(
      children: _khmerWeekDays.map((name) {
        final isWeekend = name == 'អា' || name == 'ស';
        return Expanded(
          child: Center(
            child: Text(
              name,
              style: GoogleFonts.kantumruyPro(
                color: isWeekend
                    ? const Color(0xFFEF4444).withValues(alpha: 0.85)
                    : (isDark ? Colors.white54 : const Color(0xFF64748B)),
                fontSize: 12.5,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        );
      }).toList(),
    );
  }

  // ===========================================================================
  // 6. DAYS GRID WITH ATTENDANCE INDICATORS
  // ===========================================================================
  Widget _buildDaysGrid(bool isDark) {
    final yr = _currentMonth.year;
    final m = _currentMonth.month;
    final firstDayOfMonth = DateTime(yr, m, 1);
    final totalDaysInMonth = DateTime(yr, m + 1, 0).day;

    // In Khmer/US calendar: Sunday is index 0
    final startOffset = firstDayOfMonth.weekday % 7;
    final totalCells = startOffset + totalDaysInMonth;
    final rowCount = ((totalCells - 1) / 7).floor() + 1;

    final key = _cacheKey(yr, m);
    final monthDaysStats = _monthDaysCache[key] ?? {};

    final now = DateTime.now();
    final today = DateTime(now.year, now.month, now.day);

    return Stack(
      children: [
        Column(
          children: List.generate(rowCount, (rowIndex) {
            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 3.5),
              child: Row(
                children: List.generate(7, (colIndex) {
                  final cellIndex = rowIndex * 7 + colIndex;
                  final dayNumber = cellIndex - startOffset + 1;

                  if (dayNumber < 1 || dayNumber > totalDaysInMonth) {
                    return const Expanded(child: SizedBox(height: 48));
                  }

                  final date = DateTime(yr, m, dayNumber);
                  final isToday = date.isAtSameMomentAs(today);
                  final isFuture = date.isAfter(today);

                  final stats = monthDaysStats[dayNumber];
                  final hasScanned = stats != null && stats.totalCount > 0;

                  // Selection State
                  final bool isStart = _startDate != null &&
                      date.year == _startDate!.year &&
                      date.month == _startDate!.month &&
                      date.day == _startDate!.day;

                  final bool isEnd = _endDate != null &&
                      date.year == _endDate!.year &&
                      date.month == _endDate!.month &&
                      date.day == _endDate!.day;

                  final bool isSelected = isStart || isEnd;
                  final bool isInRange = _startDate != null &&
                      _endDate != null &&
                      date.isAfter(_startDate!) &&
                      date.isBefore(_endDate!);

                  return Expanded(
                    child: _buildDayCell(
                      date: date,
                      dayNumber: dayNumber,
                      isToday: isToday,
                      isFuture: isFuture,
                      hasScanned: hasScanned,
                      stats: stats,
                      isStart: isStart,
                      isEnd: isEnd,
                      isSelected: isSelected,
                      isInRange: isInRange,
                      isDark: isDark,
                    ),
                  );
                }),
              ),
            );
          }),
        ),
        if (_isLoadingMonth)
          Positioned.fill(
            child: Container(
              color: Colors.black.withValues(alpha: isDark ? 0.25 : 0.08),
              child: const Center(
                child: CupertinoActivityIndicator(radius: 12),
              ),
            ),
          ),
      ],
    );
  }

  Widget _buildDayCell({
    required DateTime date,
    required int dayNumber,
    required bool isToday,
    required bool isFuture,
    required bool hasScanned,
    required DayAttendanceStats? stats,
    required bool isStart,
    required bool isEnd,
    required bool isSelected,
    required bool isInRange,
    required bool isDark,
  }) {
    // Range highlight styling (mimics iOS Date Range bar)
    BoxDecoration? rangeDecoration;
    final rangeHighlightColor = const Color(0xFF00D1FF)
        .withValues(alpha: isDark ? 0.18 : 0.12);

    if (isInRange) {
      rangeDecoration = BoxDecoration(
        color: rangeHighlightColor,
        borderRadius: BorderRadius.zero,
      );
    } else if (isStart && _endDate != null) {
      rangeDecoration = BoxDecoration(
        color: rangeHighlightColor,
        borderRadius: const BorderRadius.horizontal(left: Radius.circular(22)),
      );
    } else if (isEnd && _startDate != null) {
      rangeDecoration = BoxDecoration(
        color: rangeHighlightColor,
        borderRadius:
            const BorderRadius.horizontal(right: Radius.circular(22)),
      );
    }

    final Color dayTextColor;
    if (isSelected) {
      dayTextColor = Colors.white;
    } else if (isFuture) {
      dayTextColor = isDark ? Colors.white24 : const Color(0xFFCBD5E1);
    } else if (hasScanned) {
      dayTextColor = isDark ? Colors.white : const Color(0xFF0F172A);
    } else {
      dayTextColor = isDark ? Colors.white70 : const Color(0xFF475569);
    }

    return Container(
      height: 48,
      decoration: rangeDecoration,
      child: Center(
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            borderRadius: BorderRadius.circular(22),
            onTap: () => _onDayTapped(date),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 200),
              width: 42,
              height: 42,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: isSelected
                    ? const LinearGradient(
                        colors: [Color(0xFF0A84FF), Color(0xFF00D1FF)],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      )
                    : null,
                color: isSelected
                    ? null
                    : isToday
                        ? const Color(0xFF0A84FF).withValues(alpha: isDark ? 0.14 : 0.08)
                        : null,
                border: isToday && !isSelected
                    ? Border.all(
                        color: const Color(0xFF00D1FF).withValues(alpha: 0.8),
                        width: 1.2,
                      )
                    : null,
                boxShadow: isSelected
                    ? [
                        BoxShadow(
                          color: const Color(0xFF00D1FF).withValues(alpha: 0.4),
                          blurRadius: 8,
                          offset: const Offset(0, 2),
                        ),
                      ]
                    : null,
              ),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    '$dayNumber',
                    style: GoogleFonts.inter(
                      color: dayTextColor,
                      fontSize: 14,
                      fontWeight: isSelected
                          ? FontWeight.bold
                          : hasScanned
                              ? FontWeight.w700
                              : FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 2),

                  // Attendance Dots Indicator
                  _buildAttendanceDots(
                    hasScanned: hasScanned,
                    stats: stats,
                    isSelected: isSelected,
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildAttendanceDots({
    required bool hasScanned,
    required DayAttendanceStats? stats,
    required bool isSelected,
  }) {
    if (!hasScanned || stats == null) {
      return const SizedBox(height: 4);
    }

    final bool hasCheckIn = stats.checkInCount > 0;
    final bool hasCheckOut = stats.checkOutCount > 0;

    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        if (hasCheckIn)
          Container(
            width: 4,
            height: 4,
            decoration: BoxDecoration(
              color: isSelected ? Colors.white : const Color(0xFF00D1FF),
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFF00D1FF).withValues(alpha: 0.8),
                  blurRadius: 3,
                ),
              ],
            ),
          ),
        if (hasCheckIn && hasCheckOut) const SizedBox(width: 3),
        if (hasCheckOut)
          Container(
            width: 4,
            height: 4,
            decoration: BoxDecoration(
              color: isSelected ? Colors.white70 : const Color(0xFFF97316),
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFFF97316).withValues(alpha: 0.8),
                  blurRadius: 3,
                ),
              ],
            ),
          ),
        if (!hasCheckIn && !hasCheckOut)
          Container(
            width: 4.5,
            height: 4.5,
            decoration: BoxDecoration(
              color: isSelected ? Colors.white : const Color(0xFF10B981),
              shape: BoxShape.circle,
            ),
          ),
      ],
    );
  }

  // ===========================================================================
  // 7. LEGEND & MONTHLY SUMMARY
  // ===========================================================================
  Widget _buildLegendAndSummary(bool isDark) {
    final yr = _currentMonth.year;
    final m = _currentMonth.month;
    final key = _cacheKey(yr, m);
    final daysStats = _monthDaysCache[key] ?? {};

    int totalMonthLogs = 0;
    for (final s in daysStats.values) {
      totalMonthLogs += s.totalCount;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF1B1B1E) : const Color(0xFFF8FAFC),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(
          color: isDark
              ? Colors.white.withValues(alpha: 0.06)
              : const Color(0xFFE2E8F0),
        ),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          // Dot Legends
          Row(
            children: [
              _buildLegendDot(const Color(0xFF00D1FF), 'ចូល (Check-In)', isDark),
              const SizedBox(width: 12),
              _buildLegendDot(const Color(0xFFF97316), 'ចេញ (Check-Out)', isDark),
            ],
          ),

          // Monthly Scanned Summary Badge
          Text(
            '${daysStats.length} ថ្ងៃ ($totalMonthLogs លើក)',
            style: GoogleFonts.kantumruyPro(
              color: isDark ? const Color(0xFF34D399) : const Color(0xFF15803D),
              fontSize: 11,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLegendDot(Color color, String label, bool isDark) {
    return Row(
      children: [
        Container(
          width: 6,
          height: 6,
          decoration: BoxDecoration(
            color: color,
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: color.withValues(alpha: 0.5),
                blurRadius: 4,
              ),
            ],
          ),
        ),
        const SizedBox(width: 5),
        Text(
          label,
          style: GoogleFonts.kantumruyPro(
            color: isDark ? Colors.white60 : const Color(0xFF64748B),
            fontSize: 10.5,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }

  // ===========================================================================
  // 8. INTERACTIVE DAY PREVIEW CARD
  // ===========================================================================
  Widget _buildDayPreviewCard(bool isDark) {
    if (_previewDate == null) return const SizedBox.shrink();

    final date = _previewDate!;
    final mName = _khmerMonths[date.month - 1];
    final yr = date.year;
    final key = _cacheKey(yr, date.month);
    final stats = _monthDaysCache[key]?[date.day];
    final hasScanned = stats != null && stats.totalCount > 0;

    final cardBg = isDark ? const Color(0xFF1E1E22) : const Color(0xFFF8FAFC);
    final cardBorder = isDark
        ? (hasScanned
            ? const Color(0xFF0A84FF).withValues(alpha: 0.35)
            : Colors.white.withValues(alpha: 0.08))
        : (hasScanned
            ? const Color(0xFF0A84FF).withValues(alpha: 0.35)
            : const Color(0xFFE2E8F0));

    final titleColor = isDark ? Colors.white : const Color(0xFF0F172A);

    return AnimatedContainer(
      duration: const Duration(milliseconds: 250),
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: cardBg,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: cardBorder),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  const Icon(
                    CupertinoIcons.calendar_today,
                    size: 14,
                    color: Color(0xFF00D1FF),
                  ),
                  const SizedBox(width: 6),
                  Text(
                    'ថ្ងៃទី ${date.day} $mName $yr',
                    style: GoogleFonts.kantumruyPro(
                      color: titleColor,
                      fontSize: 13.5,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
              if (hasScanned)
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 2.5),
                  decoration: BoxDecoration(
                    color: const Color(0xFF10B981)
                        .withValues(alpha: isDark ? 0.15 : 0.12),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: const Color(0xFF10B981).withValues(alpha: 0.3),
                      width: 0.8,
                    ),
                  ),
                  child: Text(
                    'ស្កេនបាន ${stats.totalCount} លើក',
                    style: GoogleFonts.kantumruyPro(
                      color: isDark
                          ? const Color(0xFF34D399)
                          : const Color(0xFF15803D),
                      fontSize: 10.5,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 8),

          // Detail Content
          if (_isLoadingPreview)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 8),
              child: Center(
                child: CupertinoActivityIndicator(radius: 9),
              ),
            )
          else if (!hasScanned && _previewDayRecords.isEmpty)
            Text(
              'គ្មានកំណត់ត្រាចុះវត្តមាននៅថ្ងៃនេះទេ',
              style: GoogleFonts.kantumruyPro(
                color: isDark ? Colors.white38 : const Color(0xFF94A3B8),
                fontSize: 12,
              ),
            )
          else if (_previewDayRecords.isNotEmpty) ...[
            Column(
              children: _previewDayRecords.map((r) {
                final action = r['action_type'] ?? 'N/A';
                final isCheckIn = action == 'Check-In';
                final time = r['time_str'] ??
                    (r['log_datetime']?.toString().split(' ').sublist(1).join(' ') ??
                        '');
                final status = r['status'] ?? '';
                final isGood = status == 'Good' || status == 'Normal';

                return Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: Row(
                    children: [
                      Icon(
                        isCheckIn
                            ? Icons.login_rounded
                            : Icons.logout_rounded,
                        size: 15,
                        color: isCheckIn
                            ? const Color(0xFF00D1FF)
                            : const Color(0xFFF97316),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        action,
                        style: GoogleFonts.inter(
                          color: isDark ? Colors.white : const Color(0xFF0F172A),
                          fontSize: 12,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        time,
                        style: GoogleFonts.inter(
                          color: isDark ? Colors.white70 : const Color(0xFF64748B),
                          fontSize: 11.5,
                        ),
                      ),
                      const Spacer(),
                      if (status.isNotEmpty)
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 1.5),
                          decoration: BoxDecoration(
                            color: (isGood
                                    ? const Color(0xFF10B981)
                                    : const Color(0xFFEF4444))
                                .withValues(alpha: isDark ? 0.15 : 0.12),
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Text(
                            status,
                            style: GoogleFonts.inter(
                              color: isGood
                                  ? (isDark ? const Color(0xFF34D399) : const Color(0xFF15803D))
                                  : (isDark ? const Color(0xFFF87171) : const Color(0xFFDC2626)),
                              fontSize: 9.5,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                    ],
                  ),
                );
              }).toList(),
            ),
          ] else if (stats != null) ...[
            // Fallback to stats counts if raw records array isn't populated
            Row(
              children: [
                if (stats.checkInCount > 0)
                  Text(
                    'Check-In: ${stats.checkInCount} លើក   ',
                    style: GoogleFonts.inter(
                        color: const Color(0xFF00D1FF), fontSize: 11.5),
                  ),
                if (stats.checkOutCount > 0)
                  Text(
                    'Check-Out: ${stats.checkOutCount} លើក',
                    style: GoogleFonts.inter(
                        color: const Color(0xFFF97316), fontSize: 11.5),
                  ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  // ===========================================================================
  // 9. BOTTOM ACTION BAR
  // ===========================================================================
  Widget _buildBottomActionBar(double bottomInset, bool isDark) {
    return Container(
      padding: EdgeInsets.fromLTRB(16, 10, 16, bottomInset > 0 ? bottomInset : 14),
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF161618) : Colors.white,
        border: Border(
          top: BorderSide(
            color: isDark
                ? Colors.white.withValues(alpha: 0.08)
                : const Color(0xFFE2E8F0),
          ),
        ),
      ),
      child: Row(
        children: [
          // Clear / Reset
          TextButton(
            onPressed: () {
              HapticFeedback.lightImpact();
              final now = DateTime.now();
              setState(() {
                _startDate = DateTime(now.year, now.month, 1);
                _endDate =
                    DateTime(now.year, now.month + 1, 0, 23, 59, 59);
                _previewDate = now;
              });
            },
            child: Text(
              'កំណត់ឡើងវិញ',
              style: GoogleFonts.kantumruyPro(
                color: isDark ? Colors.white60 : const Color(0xFF64748B),
                fontSize: 13,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          const Spacer(),

          // Single day shortcut if previewDate is active
          if (_previewDate != null &&
              (_startDate != _previewDate || _endDate != _previewDate))
            Padding(
              padding: const EdgeInsets.only(right: 10),
              child: OutlinedButton(
                onPressed: () {
                  HapticFeedback.selectionClick();
                  setState(() {
                    _startDate = _previewDate;
                    _endDate = DateTime(_previewDate!.year, _previewDate!.month,
                        _previewDate!.day, 23, 59, 59);
                  });
                },
                style: OutlinedButton.styleFrom(
                  foregroundColor: const Color(0xFF00D1FF),
                  side: const BorderSide(color: Color(0xFF00D1FF), width: 1),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(14),
                  ),
                  padding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                ),
                child: Text(
                  'យកតែថ្ងៃនេះ',
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ),

          // Primary Select / Confirm Button
          ElevatedButton(
            onPressed: _confirmSelection,
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF0A84FF),
              foregroundColor: Colors.white,
              elevation: 0,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(14),
              ),
              padding:
                  const EdgeInsets.symmetric(horizontal: 22, vertical: 10),
            ),
            child: Text(
              'ជ្រើសរើស',
              style: GoogleFonts.kantumruyPro(
                fontSize: 13.5,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
