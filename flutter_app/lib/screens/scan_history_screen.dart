import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

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
  List<dynamic> _logs = [];
  String? _error;

  int _offset = 0;
  final int _limit = 20;
  bool _hasMore = true;

  // Date filter
  DateTime? _startDate;
  DateTime? _endDate;

  @override
  void initState() {
    super.initState();
    _fetchHistory();
    _scrollController.addListener(_onScroll);
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  void _onScroll() {
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

  bool get _isFiltered => _startDate != null || _endDate != null;

  Future<void> _pickDate({required bool isStart}) async {
    final now = DateTime.now();
    final initial = isStart ? (_startDate ?? now) : (_endDate ?? now);
    final picked = await showDatePicker(
      context: context,
      initialDate: initial,
      firstDate: DateTime(2020),
      lastDate: now,
      builder: (context, child) => Theme(
        data: Theme.of(context).copyWith(
          colorScheme: ColorScheme.dark(
            primary: AppTheme.primary,
            onPrimary: Colors.white,
            surface: AppTheme.bgCard,
            onSurface: AppTheme.textPrimary,
          ),
        ),
        child: child!,
      ),
    );
    if (picked != null) {
      setState(() {
        if (isStart) {
          _startDate = picked;
          if (_endDate == null || _endDate!.isBefore(picked)) _endDate = picked;
        } else {
          _endDate = picked;
          if (_startDate == null || _startDate!.isAfter(picked)) _startDate = picked;
        }
      });
      _fetchHistory();
    }
  }

  void _clearFilter() {
    setState(() {
      _startDate = null;
      _endDate = null;
    });
    _fetchHistory();
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
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        title: Text(
          'ប្រវត្តិស្កេនវត្តមាន',
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        backgroundColor: AppTheme.bgDark.withValues(alpha: 0.95),
        elevation: 0,
        centerTitle: true,
      ),
      body: AppBackgroundShell(
        child: Column(
          children: [
            _buildFilterBar(),
            Expanded(
              child: RefreshIndicator(
                onRefresh: _fetchHistory,
                color: AppTheme.primary,
                child: _buildBody(),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFilterBar() {
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 12, 16, 4),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: _isFiltered
              ? AppTheme.primary.withValues(alpha: 0.5)
              : AppTheme.borderColor,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.filter_list_rounded,
                  color: _isFiltered ? AppTheme.primary : AppTheme.textMuted,
                  size: 16),
              const SizedBox(width: 6),
              Text(
                'តម្រង​ថ្ងៃខែ',
                style: GoogleFonts.kantumruyPro(
                  color: _isFiltered ? AppTheme.primary : AppTheme.textMuted,
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const Spacer(),
              if (_isFiltered)
                GestureDetector(
                  onTap: _clearFilter,
                  child: Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 8, vertical: 3),
                    decoration: BoxDecoration(
                      color: Colors.redAccent.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.close_rounded,
                            color: Colors.redAccent, size: 12),
                        const SizedBox(width: 4),
                        Text(
                          'លុបតម្រង',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.redAccent,
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                  child: _buildDateBtn(label: 'ចាប់ពី', date: _startDate, isStart: true)),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8),
                child: Icon(Icons.arrow_forward_rounded,
                    color: AppTheme.textMuted, size: 16),
              ),
              Expanded(
                  child: _buildDateBtn(label: 'ដល់', date: _endDate, isStart: false)),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildDateBtn({
    required String label,
    required DateTime? date,
    required bool isStart,
  }) {
    final hasDate = date != null;
    final safeDate = date ?? DateTime.now();
    return GestureDetector(
      onTap: () => _pickDate(isStart: isStart),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
        decoration: BoxDecoration(
          color: hasDate
              ? AppTheme.primary.withValues(alpha: 0.1)
              : AppTheme.bgDark.withValues(alpha: 0.5),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: hasDate
                ? AppTheme.primary.withValues(alpha: 0.4)
                : AppTheme.borderColor,
          ),
        ),
        child: Row(
          children: [
            Icon(Icons.calendar_month_rounded,
                size: 14,
                color: hasDate ? AppTheme.primaryLight : AppTheme.textMuted),
            const SizedBox(width: 6),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(label,
                      style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textMuted, fontSize: 10)),
                  Text(
                    hasDate ? _fmtDisplay(safeDate) : 'ជ្រើសរើស...',
                    style: GoogleFonts.inter(
                      color: hasDate ? AppTheme.textPrimary : AppTheme.textMuted,
                      fontSize: 12,
                      fontWeight:
                          hasDate ? FontWeight.bold : FontWeight.normal,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildBody() {
    if (_isLoading) return const Center(child: CircularProgressIndicator());

    if (_error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, color: Colors.redAccent, size: 64),
            const SizedBox(height: 16),
            Text(_error!,
                style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary),
                textAlign: TextAlign.center),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: _fetchHistory,
              style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary),
              child: Text('ព្យាយាមម្តងទៀត',
                  style: GoogleFonts.kantumruyPro()),
            ),
          ],
        ),
      );
    }

    if (_logs.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.search_off_rounded,
                color: AppTheme.textMuted, size: 64),
            const SizedBox(height: 16),
            Text(
              _isFiltered
                  ? 'មិនមានទិន្នន័យក្នុងចន្លោះថ្ងៃដែលបានជ្រើស'
                  : 'មិនទាន់មានប្រវត្តិស្កេននៅឡើយទេ',
              style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textMuted, fontSize: 14),
              textAlign: TextAlign.center,
            ),
            if (_isFiltered) ...[
              const SizedBox(height: 16),
              TextButton.icon(
                onPressed: _clearFilter,
                icon: const Icon(Icons.clear_rounded, size: 16),
                label: Text('លុបតម្រង',
                    style: GoogleFonts.kantumruyPro(fontSize: 13)),
                style: TextButton.styleFrom(foregroundColor: AppTheme.primary),
              ),
            ],
          ],
        ),
      );
    }

    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      itemCount: _logs.length + (_hasMore ? 1 : 0),
      itemBuilder: (context, index) {
        if (index == _logs.length) {
          return const Padding(
            padding: EdgeInsets.symmetric(vertical: 20),
            child: Center(child: CircularProgressIndicator(strokeWidth: 2)),
          );
        }
        return _buildLogItem(_logs[index] as Map<String, dynamic>);
      },
    );
  }

  Widget _buildLogItem(Map<String, dynamic> log) {
    final bool isCheckIn = log['action_type'] == 'Check-In';
    final Color ac = isCheckIn
        ? Colors.cyanAccent.shade700
        : Colors.deepOrangeAccent.shade200;
    final Color sc =
        (log['status'] == 'Good' || log['status'] == 'Normal')
            ? AppTheme.success
            : Colors.redAccent;

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.borderColor),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: ac.withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: Icon(
                  isCheckIn ? Icons.login_rounded : Icons.logout_rounded,
                  color: ac,
                  size: 20),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(log['action_type'] ?? 'N/A',
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textPrimary,
                            fontSize: 15,
                            fontWeight: FontWeight.bold,
                          )),
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 2),
                        decoration: BoxDecoration(
                          color: sc.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(log['status'] ?? 'N/A',
                            style: GoogleFonts.inter(
                                color: sc,
                                fontSize: 10,
                                fontWeight: FontWeight.bold)),
                      ),
                    ],
                  ),
                  const SizedBox(height: 5),
                  Row(children: [
                    Icon(Icons.access_time_rounded,
                        color: AppTheme.textMuted, size: 13),
                    const SizedBox(width: 4),
                    Text(log['log_datetime'] ?? 'N/A',
                        style: GoogleFonts.inter(
                            color: AppTheme.textSecondary, fontSize: 12)),
                  ]),
                  const SizedBox(height: 3),
                  Row(children: [
                    Icon(Icons.location_on_outlined,
                        color: AppTheme.textMuted, size: 13),
                    const SizedBox(width: 4),
                    Expanded(
                      child: Text(log['location_name'] ?? 'Unknown',
                          style: GoogleFonts.kantumruyPro(
                              color: AppTheme.textMuted, fontSize: 11),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis),
                    ),
                  ]),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
