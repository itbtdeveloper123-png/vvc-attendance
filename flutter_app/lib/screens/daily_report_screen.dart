import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import 'package:provider/provider.dart';
import 'package:intl/intl.dart';
import 'dart:ui' as ui;
import 'dart:typed_data';
import 'package:flutter/rendering.dart';
import 'package:pasteboard/pasteboard.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../providers/user_provider.dart';
import '../widgets/app_widgets.dart';

class DailyReportScreen extends StatefulWidget {
  const DailyReportScreen({super.key});

  @override
  State<DailyReportScreen> createState() => _DailyReportScreenState();
}

class _DailyReportScreenState extends State<DailyReportScreen> {
  final ApiService _api = ApiService();
  final TextEditingController _contentController = TextEditingController();
  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _nameController = TextEditingController();

  final List<Map<String, TextEditingController>> _tasks = [];
  DateTime _nextPlanDate = DateTime.now().add(const Duration(days: 1));
  final TextEditingController _nextPlanDetailsController =
      TextEditingController();

  List<dynamic> _reports = [];
  List<dynamic> _positions = [];
  bool _isLoading = true;
  bool _isLoadingPositions = true;
  bool _isSubmitting = false;
  String _selectedPosition = '';
  DateTime _selectedDate = DateTime.now();
  Timer? _pollingTimer;

  // Tree-navigation state for history tab
  int _treeLevel = 0;
  int? _treeYear;
  String? _treeName;
  int? _treeMonth;
  int? _treeDay;

  static const _khmerMonths = [
    '',
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

  bool _isComplexRole(BuildContext context) {
    final user = Provider.of<UserProvider>(context, listen: false);
    if (user.isAdmin || user.systemRole == SystemRole.it) return true;
    final lower = _selectedPosition.toLowerCase();
    return lower.contains('it') || lower.contains('admin');
  }

  void _addTaskRow() {
    setState(() {
      _tasks.add({
        'time': TextEditingController(),
        'task': TextEditingController(),
        'status': TextEditingController(text: '100%'),
        'dueDate': TextEditingController(),
        'description': TextEditingController(),
        'problem': TextEditingController(),
        'solution': TextEditingController(),
      });
    });
  }

  void _removeTaskRow(int index) {
    if (_tasks.length > 1) {
      setState(() {
        for (var c in _tasks[index].values) {
          c.dispose();
        }
        _tasks.removeAt(index);
      });
    }
  }

  @override
  void initState() {
    super.initState();
    _addTaskRow();
    // Initialize data immediately from provider to avoid loading state
    _initializeLocalUserData();
    _loadData();
    _pollingTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (mounted) _fetchReports();
    });
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    _contentController.dispose();
    _emailController.dispose();
    _nameController.dispose();
    _nextPlanDetailsController.dispose();
    super.dispose();
  }

  void _initializeLocalUserData() {
    final user = Provider.of<UserProvider>(context, listen: false);
    _nameController.text = user.name ?? '';
    _emailController.text = "${user.employeeId ?? ''}@vvc.com";

    final userPosition = user.position ?? '';
    if (userPosition.isNotEmpty) {
      _positions = [
        {'name': userPosition, 'thread_id': null, 'chat_id': null},
      ];
      _selectedPosition = userPosition;
      _isLoadingPositions = false;
    }
  }

  Future<void> _loadData() async {
    // Only show global loading if we have no reports yet
    if (_reports.isEmpty) {
      setState(() => _isLoading = true);
    }

    // Load reports and positions independently
    _fetchReports();
    _fetchPositions();
  }

  Future<void> _fetchReports() async {
    try {
      final userProvider = Provider.of<UserProvider>(context, listen: false);
      final isHRMOnly = userProvider.systemRole == SystemRole.hrm;

      final res = isHRMOnly
          ? await _api.fetchAllDailyReports()
          : await _api.fetchMyDailyReports();

      if (res['status'] == 'success' || res['success'] == true) {
        if (mounted) {
          setState(() {
            _reports = res['data'] ?? [];
            _isLoading = false;
          });
        }
      } else {
        debugPrint("API Error fetching reports: ${res['message']}");
        if (mounted) setState(() => _isLoading = false);
      }
    } catch (e) {
      debugPrint("Catch Error fetching reports: $e");
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _fetchPositions() async {
    try {
      final res = await _api.fetchReportPositions();
      if (res['success'] == true) {
        final List<dynamic> loadedPositions = res['positions'] ?? [];
        if (loadedPositions.isNotEmpty) {
          if (mounted) {
            setState(() {
              _positions = loadedPositions;
              // Only update selected if current one isn't in the list
              bool exists = loadedPositions.any(
                (p) => p['name'] == _selectedPosition,
              );
              if (!exists || _selectedPosition.isEmpty) {
                _selectedPosition = loadedPositions[0]['name'] ?? '';
              }
              _isLoadingPositions = false;
            });
          }
        } else {
          if (mounted) setState(() => _isLoadingPositions = false);
        }
      } else {
        if (mounted) setState(() => _isLoadingPositions = false);
      }
    } catch (e) {
      debugPrint("Catch Error fetching positions: $e");
      if (mounted) setState(() => _isLoadingPositions = false);
    }
  }

  Future<void> _submitReport() async {
    String finalContent = _contentController.text.trim();
    if (_isComplexRole(context)) {
      bool hasTasks = false;
      String structured = "📋 *របាយការណ៍ការងារ*\n";
      for (int i = 0; i < _tasks.length; i++) {
        var t = _tasks[i];
        if (t['task']!.text.trim().isEmpty) continue;
        hasTasks = true;
        structured += "\n*កិច្ចការទី ${i + 1}:* ${t['task']!.text}\n";
        if (t['time']!.text.isNotEmpty) {
          structured += "  - ម៉ោង: ${t['time']!.text}\n";
        }
        if (t['status']!.text.isNotEmpty) {
          structured += "  - ស្ថានភាព: ${t['status']!.text}\n";
        }
        if (t['dueDate']!.text.isNotEmpty) {
          structured += "  - កាលបរិច្ឆេទកំណត់: ${t['dueDate']!.text}\n";
        }
        if (t['description']!.text.isNotEmpty) {
          structured += "  - ពិពណ៌នា: ${t['description']!.text}\n";
        }
        if (t['problem']!.text.isNotEmpty) {
          structured += "  - បញ្ហា: ${t['problem']!.text}\n";
        }
        if (t['solution']!.text.isNotEmpty) {
          structured += "  - ដំណោះស្រាយ: ${t['solution']!.text}\n";
        }
      }
      if (!hasTasks) {
        structured += "_មិនមានកិច្ចការត្រូវរាយការណ៍_\n";
      }
      structured += "\n--------------------------------------\n";
      structured +=
          "📋 *ផែនការសម្រាប់ថ្ងៃបន្ទាប់* (${DateFormat('dd-MMM-yyyy').format(_nextPlanDate)})\n";
      structured += _nextPlanDetailsController.text.trim().isNotEmpty
          ? _nextPlanDetailsController.text.trim()
          : "មិនមាន";
      finalContent = structured;
    }

    if (finalContent.isEmpty) return;
    setState(() => _isSubmitting = true);
    try {
      // Find the selected position's thread_id and chat_id
      final selectedMapping = _positions.firstWhere(
        (p) => p['name'] == _selectedPosition,
        orElse: () => <String, dynamic>{},
      );
      final threadId = selectedMapping['thread_id']?.toString() ?? '';
      final chatId = selectedMapping['chat_id']?.toString() ?? '';

      final res = await _api.submitDailyReport(
        finalContent,
        position: _selectedPosition,
        threadId: threadId,
        chatId: chatId,
      );
      if (res['status'] == 'success') {
        _contentController.clear();
        _nextPlanDetailsController.clear();
        for (var t in _tasks) {
          for (var c in t.values) {
            c.clear();
          }
          t['status']!.text = '100%';
        }
        _loadData();
        if (mounted) _showSuccessDialog();
      }
    } catch (e) {
      if (mounted) _showErrorDialog("ការផ្ញើរបាយការណ៍បានបរាជ័យ");
    } finally {
      if (mounted) setState(() => _isSubmitting = false);
    }
  }

  void _showSuccessDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.check_circle_outline_rounded,
              color: AppTheme.success,
              size: 64,
            ),
            const SizedBox(height: 20),
            Text(
              "ជោគជ័យ!",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 10),
            Text(
              "បញ្ជូនរបាយការណ៍បានជោគជ័យ",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.70),
                fontSize: 14,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            SizedBox(
              width: double.infinity,
              height: 50,
              child: ElevatedButton(
                onPressed: () => Navigator.pop(context),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.success,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                child: Text(
                  "យល់ព្រម",
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showErrorDialog(String msg) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline_rounded, color: AppTheme.danger, size: 64),
            const SizedBox(height: 20),
            Text(
              "បរាជ័យ",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 10),
            Text(
              msg,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.70),
                fontSize: 14,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            SizedBox(
              width: double.infinity,
              height: 50,
              child: ElevatedButton(
                onPressed: () => Navigator.pop(context),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.danger,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                child: Text(
                  "យល់ព្រម",
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final userProvider = Provider.of<UserProvider>(context);
    final isHRMOnly = userProvider.systemRole == SystemRole.hrm;

    if (isHRMOnly) {
      return Scaffold(
        backgroundColor: AppTheme.bgDark,
        extendBodyBehindAppBar: true,
        appBar: AppBar(
          backgroundColor: Colors.transparent,
          elevation: 0,
          centerTitle: true,
          title: Text(
            "របាយការណ៍ប្រចាំថ្ងៃ",
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary,
              fontWeight: FontWeight.bold,
              fontSize: 18,
            ),
          ),
          leading: IconButton(
            icon: Icon(
              Icons.arrow_back_ios_new_rounded,
              color: AppTheme.textPrimary,
            ),
            onPressed: () => Navigator.pop(context),
          ),
        ),
        body: AppBackgroundShell(child: _buildHistoryTab(isAdmin: true)),
      );
    }

    return DefaultTabController(
      length: 2,
      child: Scaffold(
        backgroundColor: AppTheme.bgDark,
        extendBodyBehindAppBar: true,
        appBar: AppBar(
          backgroundColor: Colors.transparent,
          elevation: 0,
          centerTitle: true,
          title: Text(
            "របាយការណ៍ប្រចាំថ្ងៃ",
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary,
              fontWeight: FontWeight.bold,
              fontSize: 18,
            ),
          ),
          leading: IconButton(
            icon: Icon(
              Icons.arrow_back_ios_new_rounded,
              color: AppTheme.textPrimary,
            ),
            onPressed: () => Navigator.pop(context),
          ),
          bottom: TabBar(
            indicatorColor: AppTheme.primary,
            indicatorWeight: 3,
            indicatorSize: TabBarIndicatorSize.label,
            labelStyle: GoogleFonts.kantumruyPro(
              fontWeight: FontWeight.bold,
              fontSize: 14,
            ),
            unselectedLabelStyle: GoogleFonts.kantumruyPro(
              fontWeight: FontWeight.normal,
              fontSize: 14,
            ),
            labelColor: AppTheme.primary,
            unselectedLabelColor: AppTheme.textPrimary.withValues(alpha: 0.38),
            tabs: const [
              Tab(text: "បញ្ជូនរបាយការណ៍"),
              Tab(text: "ប្រវត្តិនៃការបញ្ជូន"),
            ],
          ),
        ),
        body: AppBackgroundShell(
          child: TabBarView(
            physics: const BouncingScrollPhysics(),
            children: [_buildSubmitTab(), _buildHistoryTab(isAdmin: false)],
          ),
        ),
      ),
    );
  }

  Widget _buildSubmitTab() {
    final topPadding = MediaQuery.of(context).padding.top + kToolbarHeight + 60;
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      padding: EdgeInsets.fromLTRB(
        AppResponsive.horizontalPadding(context),
        topPadding,
        AppResponsive.horizontalPadding(context),
        AppResponsive.bottomPadding(context),
      ),
      child: FadeInUp(
        duration: const Duration(milliseconds: 400),
        child: AppResponsive.maxWidth(
          context: context,
          child: Column(
            children: [
              Container(
                padding: const EdgeInsets.all(24),
                decoration: AppTheme.cardDecoration(
                  color: AppTheme.bgCard.withValues(alpha: 0.8),
                  radius: AppTheme.radiusXl,
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: _buildLabelField(
                            "អុីមែល",
                            _buildFormTextField(
                              controller: _emailController,
                              readOnly: true,
                            ),
                          ),
                        ),
                        const SizedBox(width: 16),
                        Expanded(
                          child: _buildLabelField(
                            "ឈ្មោះ:",
                            _buildFormTextField(
                              controller: _nameController,
                              readOnly: true,
                              isKhmer: true,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 20),

                    _buildLabelField(
                      "តួនាទី",
                      _isLoadingPositions
                          ? Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 16,
                              ),
                              decoration: BoxDecoration(
                                color: AppTheme.textPrimary.withValues(
                                  alpha: 0.05,
                                ),
                                borderRadius: BorderRadius.circular(16),
                                border: Border.all(
                                  color: AppTheme.textPrimary.withValues(
                                    alpha: 0.1,
                                  ),
                                ),
                              ),
                              child: Row(
                                children: [
                                  SizedBox(
                                    height: 16,
                                    width: 16,
                                    child: CircularProgressIndicator(
                                      color: AppTheme.primary,
                                      strokeWidth: 2,
                                    ),
                                  ),
                                  const SizedBox(width: 12),
                                  Text(
                                    "កំពុងផ្ទុក...",
                                    style: GoogleFonts.kantumruyPro(
                                      color: AppTheme.textPrimary.withValues(
                                        alpha: 0.5,
                                      ),
                                      fontSize: 14,
                                    ),
                                  ),
                                ],
                              ),
                            )
                          : _positions.isEmpty
                          ? Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 16,
                              ),
                              decoration: BoxDecoration(
                                color: AppTheme.textPrimary.withValues(
                                  alpha: 0.05,
                                ),
                                borderRadius: BorderRadius.circular(16),
                                border: Border.all(
                                  color: AppTheme.textPrimary.withValues(
                                    alpha: 0.1,
                                  ),
                                ),
                              ),
                              child: Text(
                                "មិនមានតួនាទីដែលបានកំណត់",
                                style: GoogleFonts.kantumruyPro(
                                  color: AppTheme.textPrimary.withValues(
                                    alpha: 0.5,
                                  ),
                                  fontSize: 14,
                                ),
                              ),
                            )
                          : _buildDropdown(
                              _selectedPosition,
                              _positions
                                  .map((p) => p['name']?.toString() ?? '')
                                  .where((n) => n.isNotEmpty)
                                  .toList(),
                              (v) => setState(() => _selectedPosition = v!),
                            ),
                    ),
                    const SizedBox(height: 20),

                    _buildLabelField(
                      "ថ្ងៃខែឆ្នាំ និងម៉ោង",
                      _buildDatePicker(
                        _selectedDate,
                        (d) => setState(() => _selectedDate = d),
                        showTime: true,
                      ),
                    ),
                    const SizedBox(height: 20),

                    if (_isComplexRole(context))
                      _buildComplexForm()
                    else
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              Text(
                                "របាយការណ៍ប្រចាំថ្ងៃ",
                                style: GoogleFonts.kantumruyPro(
                                  color: AppTheme.textPrimary,
                                  fontWeight: FontWeight.bold,
                                  fontSize: 15,
                                ),
                              ),
                              TextButton.icon(
                                onPressed: () {
                                  if (_reports.isNotEmpty) {
                                    _contentController.text =
                                        _reports.first['content'] ?? '';
                                  }
                                },
                                icon: const Icon(
                                  Icons.history_rounded,
                                  size: 18,
                                ),
                                label: Text(
                                  "របាយការណ៍ម្សិលមិញ",
                                  style: GoogleFonts.kantumruyPro(fontSize: 12),
                                ),
                                style: TextButton.styleFrom(
                                  foregroundColor: AppTheme.primaryLight,
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 8,
                                  ),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 12),
                          TextField(
                            controller: _contentController,
                            maxLines: 8,
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.textPrimary,
                              fontSize: 14,
                            ),
                            decoration: _inputDecoration(
                              "រៀបរាប់ពីការងាររបស់អ្នក...",
                              icon: Icons.description_rounded,
                            ),
                          ),
                        ],
                      ),
                    const SizedBox(height: 32),

                    SizedBox(
                      width: double.infinity,
                      height: 55,
                      child: ElevatedButton(
                        onPressed: _isSubmitting ? null : _submitReport,
                        style: AppTheme.filledButtonStyle(
                          backgroundColor: AppTheme.primary,
                        ),
                        child: _isSubmitting
                            ? SizedBox(
                                height: 24,
                                width: 24,
                                child: CircularProgressIndicator(
                                  color: AppTheme.textPrimary,
                                  strokeWidth: 2,
                                ),
                              )
                            : Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  const Icon(Icons.send_rounded, size: 20),
                                  const SizedBox(width: 12),
                                  Text(
                                    "បញ្ជូនរបាយការណ៍",
                                    style: GoogleFonts.kantumruyPro(
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
            ],
          ),
        ),
      ),
    );
  }

  // ── Parse dd/MM/yyyy from report_date ────────────────────────────────
  (int year, int month, int day) _parseDate(String raw) {
    try {
      final parts = raw.split('/');
      return (int.parse(parts[2]), int.parse(parts[1]), int.parse(parts[0]));
    } catch (_) {
      return (0, 0, 0);
    }
  }

  // ── Build grouped tree from flat list ─────────────────────────────────
  dynamic _buildTree(bool isAdmin) {
    if (isAdmin) {
      final tree = <int, Map<String, Map<int, Map<int, List<dynamic>>>>>{};
      for (final r in _reports) {
        final (y, m, d) = _parseDate(r['report_date']?.toString() ?? '');
        if (y == 0) continue;
        final name = r['user_name']?.toString() ?? 'មិនស្គាល់ឈ្មោះ';

        tree.putIfAbsent(y, () => {});
        tree[y]!.putIfAbsent(name, () => {});
        tree[y]![name]!.putIfAbsent(m, () => {});
        tree[y]![name]![m]!.putIfAbsent(d, () => []);
        tree[y]![name]![m]![d]!.add(r);
      }
      return tree;
    } else {
      final tree = <int, Map<int, Map<int, List<dynamic>>>>{};
      for (final r in _reports) {
        final (y, m, d) = _parseDate(r['report_date']?.toString() ?? '');
        if (y == 0) continue;
        tree.putIfAbsent(y, () => {});
        tree[y]!.putIfAbsent(m, () => {});
        tree[y]![m]!.putIfAbsent(d, () => []);
        tree[y]![m]![d]!.add(r);
      }
      return tree;
    }
  }

  void _treeOpen({
    int? year,
    String? name,
    int? month,
    int? day,
    required bool isAdmin,
  }) {
    setState(() {
      _treeYear = year;
      _treeName = name;
      _treeMonth = month;
      _treeDay = day;
      if (isAdmin) {
        if (day != null) {
          _treeLevel = 4;
        } else if (month != null) {
          _treeLevel = 3;
        } else if (name != null) {
          _treeLevel = 2;
        } else if (year != null) {
          _treeLevel = 1;
        } else {
          _treeLevel = 0;
        }
      } else {
        if (day != null) {
          _treeLevel = 3;
        } else if (month != null) {
          _treeLevel = 2;
        } else if (year != null) {
          _treeLevel = 1;
        } else {
          _treeLevel = 0;
        }
      }
    });
  }

  Widget _buildHistoryTab({bool isAdmin = false}) {
    // If Admin/HRM, there's no TabBar, so we need less top padding.
    final offset = isAdmin ? 20 : 60;
    final topPadding =
        MediaQuery.of(context).padding.top + kToolbarHeight + offset;

    if (_isLoading) {
      return ListView.builder(
        padding: EdgeInsets.fromLTRB(
          AppResponsive.horizontalPadding(context),
          topPadding,
          AppResponsive.horizontalPadding(context),
          AppResponsive.bottomPadding(context),
        ),
        itemCount: 5,
        itemBuilder: (_, i) => Padding(
          padding: const EdgeInsets.only(bottom: 14),
          child: AppShimmer(
            child: Container(
              height: 68,
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: BorderRadius.circular(16),
              ),
            ),
          ),
        ),
      );
    }

    if (_reports.isEmpty) {
      return AppStateView(
        icon: Icons.description_outlined,
        title: 'មិនទាន់មានរបាយការណ៍នៅឡើយ',
        message: 'របាយការណ៍ដែលបានបញ្ជូននឹងបង្ហាញនៅទីនេះ',
        color: AppTheme.primary,
      );
    }

    final tree = _buildTree(isAdmin);
    return Column(
      children: [
        _buildTreeBreadcrumb(isAdmin: isAdmin),
        Expanded(
          child: RefreshIndicator(
            onRefresh: _loadData,
            color: AppTheme.primary,
            child: _buildTreeBody(tree, isAdmin),
          ),
        ),
      ],
    );
  }

  Widget _buildTreeBreadcrumb({bool isAdmin = false}) {
    final crumbs = <(String, VoidCallback?)>[];
    crumbs.add((
      'ទាំងអស់',
      _treeLevel > 0 ? () => _treeOpen(isAdmin: isAdmin) : null,
    ));
    if (_treeYear != null) {
      crumbs.add((
        '$_treeYear',
        _treeLevel > 1
            ? () => _treeOpen(year: _treeYear, isAdmin: isAdmin)
            : null,
      ));
    }
    if (isAdmin && _treeName != null) {
      crumbs.add((
        _treeName!,
        _treeLevel > 2
            ? () =>
                  _treeOpen(year: _treeYear, name: _treeName, isAdmin: isAdmin)
            : null,
      ));
    }
    if (_treeMonth != null) {
      final canClickMonth = isAdmin ? (_treeLevel > 3) : (_treeLevel > 2);
      crumbs.add((
        _khmerMonths[_treeMonth!],
        canClickMonth
            ? () => _treeOpen(
                year: _treeYear,
                name: _treeName,
                month: _treeMonth,
                isAdmin: isAdmin,
              )
            : null,
      ));
    }
    if (_treeDay != null) crumbs.add(('$_treeDay', null));

    final offset = isAdmin ? 20 : 60;
    final topMargin =
        MediaQuery.of(context).padding.top + kToolbarHeight + offset;
    return Container(
      margin: EdgeInsets.fromLTRB(
        AppResponsive.horizontalPadding(context),
        topMargin,
        AppResponsive.horizontalPadding(context),
        10,
      ),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: AppTheme.cardDecoration(
        color: AppTheme.bgCard.withValues(alpha: 0.6),
        radius: AppTheme.radiusSm,
        borderColor: AppTheme.cardBorder,
        shadows: const [],
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          children: [
            Icon(Icons.grid_view_rounded, size: 13, color: AppTheme.textMuted),
            const SizedBox(width: 6),
            ...crumbs.asMap().entries.map((e) {
              final isLast = e.key == crumbs.length - 1;
              final (label, onTap) = e.value;
              return Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  GestureDetector(
                    onTap: onTap,
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 3,
                      ),
                      decoration: BoxDecoration(
                        color: isLast
                            ? AppTheme.primary.withValues(alpha: 0.18)
                            : Colors.transparent,
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(
                        label,
                        style: GoogleFonts.kantumruyPro(
                          color: isLast ? AppTheme.primary : AppTheme.textMuted,
                          fontSize: 11.5,
                          fontWeight: isLast
                              ? FontWeight.bold
                              : FontWeight.normal,
                        ),
                      ),
                    ),
                  ),
                  if (!isLast)
                    Icon(
                      Icons.chevron_right_rounded,
                      color: AppTheme.textMuted,
                      size: 13,
                    ),
                ],
              );
            }),
          ],
        ),
      ),
    );
  }

  Widget _buildTreeBody(dynamic treeUncast, bool isAdmin) {
    EdgeInsets listPadding({double top = 6}) => EdgeInsets.fromLTRB(
      AppResponsive.horizontalPadding(context),
      top,
      AppResponsive.horizontalPadding(context),
      AppResponsive.bottomPadding(context),
    );

    if (isAdmin) {
      Map<int, Map<String, Map<int, Map<int, List<dynamic>>>>> tree =
          treeUncast;
      if (_treeLevel == 0) {
        final years = tree.keys.toList()..sort((a, b) => b.compareTo(a));
        return ListView.builder(
          padding: listPadding(),
          itemCount: years.length,
          itemBuilder: (_, i) {
            final y = years[i];
            int reportCount = 0;
            tree[y]!.forEach((name, mMap) {
              mMap.forEach((m, dMap) {
                dMap.forEach((d, list) {
                  reportCount += list.length;
                });
              });
            });
            final usersCount = tree[y]!.length;
            return _folderTile(
              icon: Icons.folder_special_rounded,
              color: const Color(0xFF4F8EF7),
              label: '$y',
              count: reportCount,
              subtitle: '$usersCount នាក់',
              onTap: () => _treeOpen(year: y, isAdmin: isAdmin),
            );
          },
        );
      } else if (_treeLevel == 1) {
        Map<String, Map<int, Map<int, List<dynamic>>>> t =
            tree[_treeYear] ?? {};
        final names = t.keys.toList()..sort();
        return ListView.builder(
          padding: listPadding(),
          itemCount: names.length,
          itemBuilder: (_, i) {
            final name = names[i];
            int reportCount = 0;
            t[name]!.forEach((m, dMap) {
              dMap.forEach((d, list) => reportCount += list.length);
            });
            final monthCount = t[name]!.length;
            return _folderTile(
              icon: Icons.person_rounded,
              color: const Color(0xFFF59E0B),
              label: name,
              count: reportCount,
              subtitle: '$monthCount ខែ',
              onTap: () =>
                  _treeOpen(year: _treeYear, name: name, isAdmin: isAdmin),
            );
          },
        );
      } else if (_treeLevel == 2) {
        Map<int, Map<int, List<dynamic>>> t = tree[_treeYear]?[_treeName] ?? {};
        final months = t.keys.toList()..sort((a, b) => b.compareTo(a));
        return ListView.builder(
          padding: listPadding(),
          itemCount: months.length,
          itemBuilder: (_, i) {
            final m = months[i];
            int reportCount = 0;
            t[m]!.forEach((d, list) => reportCount += list.length);
            final dayCount = t[m]!.length;
            return _folderTile(
              icon: Icons.folder_rounded,
              color: const Color(0xFF9B59F5),
              label: _khmerMonths[m],
              count: reportCount,
              subtitle: '$dayCount ថ្ងៃ',
              onTap: () => _treeOpen(
                year: _treeYear,
                name: _treeName,
                month: m,
                isAdmin: isAdmin,
              ),
            );
          },
        );
      } else if (_treeLevel == 3) {
        Map<int, List<dynamic>> t =
            tree[_treeYear]?[_treeName]?[_treeMonth] ?? {};
        final days = t.keys.toList()..sort((a, b) => b.compareTo(a));
        return ListView.builder(
          padding: listPadding(),
          itemCount: days.length,
          itemBuilder: (_, i) {
            final d = days[i];
            final count = t[d]!.length;
            return _folderTile(
              icon: Icons.calendar_today_rounded,
              color: const Color(0xFF14B8A6),
              label:
                  '${d.toString().padLeft(2, '0')} ${_khmerMonths[_treeMonth!]} $_treeYear',
              count: count,
              onTap: () => _treeOpen(
                year: _treeYear,
                name: _treeName,
                month: _treeMonth,
                day: d,
                isAdmin: isAdmin,
              ),
            );
          },
        );
      } else {
        List<dynamic> dayReports =
            tree[_treeYear]?[_treeName]?[_treeMonth]?[_treeDay] ?? [];
        if (dayReports.isEmpty) {
          return AppStateView(
            icon: Icons.folder_open_rounded,
            title: 'មិនមានរបាយការណ៍',
            color: AppTheme.primary,
          );
        }
        return ListView.builder(
          padding: listPadding(top: 4),
          itemCount: dayReports.length,
          itemBuilder: (_, i) => AppResponsive.maxWidth(
            context: context,
            child: _buildReportCard(dayReports[i]),
          ),
        );
      }
    } else {
      Map<int, Map<int, Map<int, List<dynamic>>>> tree = treeUncast;
      if (_treeLevel == 0) {
        final years = tree.keys.toList()..sort((a, b) => b.compareTo(a));
        return ListView.builder(
          padding: listPadding(),
          itemCount: years.length,
          itemBuilder: (_, i) {
            final y = years[i];
            final count = tree[y]!.values.fold<int>(
              0,
              (s, m) => s + m.values.fold(0, (s2, l) => s2 + l.length),
            );
            final monthCount = tree[y]!.length;
            return _folderTile(
              icon: Icons.folder_special_rounded,
              color: const Color(0xFF4F8EF7),
              label: '$y',
              count: count,
              subtitle: '$monthCount ខែ',
              onTap: () => _treeOpen(year: y, isAdmin: isAdmin),
            );
          },
        );
      }
      if (_treeLevel == 1) {
        final months = (tree[_treeYear] ?? {}).keys.toList()
          ..sort((a, b) => b.compareTo(a));
        return ListView.builder(
          padding: listPadding(),
          itemCount: months.length,
          itemBuilder: (_, i) {
            final m = months[i];
            final count = (tree[_treeYear]![m] ?? {}).values.fold<int>(
              0,
              (s, l) => s + l.length,
            );
            final dayCount = (tree[_treeYear]![m] ?? {}).length;
            return _folderTile(
              icon: Icons.folder_rounded,
              color: const Color(0xFF9B59F5),
              label: _khmerMonths[m],
              count: count,
              subtitle: '$dayCount ថ្ងៃ',
              onTap: () =>
                  _treeOpen(year: _treeYear, month: m, isAdmin: isAdmin),
            );
          },
        );
      }
      if (_treeLevel == 2) {
        final days = (tree[_treeYear]?[_treeMonth] ?? {}).keys.toList()
          ..sort((a, b) => b.compareTo(a));
        return ListView.builder(
          padding: listPadding(),
          itemCount: days.length,
          itemBuilder: (_, i) {
            final d = days[i];
            final count = (tree[_treeYear]?[_treeMonth]?[d] ?? []).length;
            return _folderTile(
              icon: Icons.calendar_today_rounded,
              color: const Color(0xFF14B8A6),
              label:
                  '${d.toString().padLeft(2, '0')} ${_khmerMonths[_treeMonth!]} $_treeYear',
              count: count,
              onTap: () => _treeOpen(
                year: _treeYear,
                month: _treeMonth,
                day: d,
                isAdmin: isAdmin,
              ),
            );
          },
        );
      }
      final dayReports = (tree[_treeYear]?[_treeMonth]?[_treeDay] ?? []);
      if (dayReports.isEmpty) {
        return AppStateView(
          icon: Icons.folder_open_rounded,
          title: 'មិនមានរបាយការណ៍',
          color: AppTheme.primary,
        );
      }
      return ListView.builder(
        padding: listPadding(top: 4),
        itemCount: dayReports.length,
        itemBuilder: (_, i) => AppResponsive.maxWidth(
          context: context,
          child: _buildReportCard(dayReports[i]),
        ),
      );
    }
  }

  Widget _folderTile({
    required IconData icon,
    required Color color,
    required String label,
    required int count,
    required VoidCallback onTap,
    String? subtitle,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        margin: const EdgeInsets.only(bottom: 12),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: color.withValues(alpha: 0.18), width: 1.2),
          boxShadow: [
            BoxShadow(
              color: color.withValues(alpha: 0.08),
              blurRadius: 14,
              spreadRadius: 1,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(20),
          child: Stack(
            children: [
              // Left accent bar
              Positioned(
                left: 0,
                top: 0,
                bottom: 0,
                child: Container(
                  width: 4,
                  decoration: BoxDecoration(
                    color: color,
                    borderRadius: const BorderRadius.only(
                      topLeft: Radius.circular(20),
                      bottomLeft: Radius.circular(20),
                    ),
                  ),
                ),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(20, 16, 16, 16),
                child: Row(
                  children: [
                    // Folder icon
                    Container(
                      width: 50,
                      height: 50,
                      decoration: BoxDecoration(
                        color: color.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: Icon(icon, color: color, size: 24),
                    ),
                    const SizedBox(width: 16),
                    // Text
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            label,
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.textPrimary,
                              fontSize: 15,
                              fontWeight: FontWeight.bold,
                              height: 1.3,
                            ),
                          ),
                          if (subtitle != null) ...[
                            const SizedBox(height: 2),
                            Text(
                              subtitle,
                              style: GoogleFonts.inter(
                                color: AppTheme.textMuted,
                                fontSize: 11,
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                    const SizedBox(width: 10),
                    // Count badge
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.end,
                      children: [
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 10,
                            vertical: 4,
                          ),
                          decoration: BoxDecoration(
                            color: color.withValues(alpha: 0.12),
                            borderRadius: BorderRadius.circular(20),
                          ),
                          child: Text(
                            '$count',
                            style: GoogleFonts.inter(
                              color: color,
                              fontSize: 13,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                        const SizedBox(height: 3),
                        Text(
                          'របាយការណ៍',
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textMuted,
                            fontSize: 9,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Icon(
                          Icons.arrow_forward_ios_rounded,
                          color: color.withValues(alpha: 0.5),
                          size: 11,
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
    );
  }

  Widget _buildReportCard(dynamic item) {
    // Position color mapping
    final pos = item['position']?.toString() ?? '';
    const posColor = Color(0xFF6366F1);

    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.06)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.12),
            blurRadius: 14,
            offset: const Offset(0, 5),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header strip
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
            decoration: BoxDecoration(
              color: AppTheme.primary.withValues(alpha: 0.10),
              borderRadius: const BorderRadius.vertical(
                top: Radius.circular(20),
              ),
              border: Border(
                bottom: BorderSide(
                  color: AppTheme.primary.withValues(alpha: 0.1),
                ),
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    if (item['user_name'] != null) ...[
                      // Avatar
                      Container(
                        width: 28,
                        height: 28,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: AppTheme.primary.withValues(alpha: 0.2),
                          border: Border.all(
                            color: AppTheme.primary.withValues(alpha: 0.5),
                          ),
                        ),
                        clipBehavior: Clip.hardEdge,
                        child:
                            (item['avatar'] != null &&
                                item['avatar'].toString().isNotEmpty)
                            ? Image.network(
                                ApiService.getFullImageUrl(item['avatar']),
                                fit: BoxFit.cover,
                                errorBuilder: (c, e, s) => Center(
                                  child: Text(
                                    (item['user_name'] as String)
                                        .substring(0, 1)
                                        .toUpperCase(),
                                    style: GoogleFonts.inter(
                                      color: AppTheme.primary,
                                      fontSize: 12,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ),
                              )
                            : Center(
                                child: Text(
                                  (item['user_name'] as String).isNotEmpty
                                      ? (item['user_name'] as String)
                                            .substring(0, 1)
                                            .toUpperCase()
                                      : '?',
                                  style: GoogleFonts.inter(
                                    color: AppTheme.primary,
                                    fontSize: 12,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              ),
                      ),
                      const SizedBox(width: 8),
                      // Name
                      Expanded(
                        child: Text(
                          item['user_name'] ?? '',
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textPrimary,
                            fontWeight: FontWeight.bold,
                            fontSize: 13,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(width: 8),
                    ] else ...[
                      const Spacer(),
                    ],
                    // Sent badge
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 4,
                      ),
                      decoration: BoxDecoration(
                        color: AppTheme.success.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            Icons.check_circle_rounded,
                            color: AppTheme.success,
                            size: 11,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            'Sent',
                            style: GoogleFonts.inter(
                              color: AppTheme.success,
                              fontSize: 10,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                if (item['user_name'] != null ||
                    pos.isNotEmpty ||
                    item['report_date'] != null) ...[
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      // Date badge
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 10,
                          vertical: 5,
                        ),
                        decoration: BoxDecoration(
                          color: AppTheme.primary.withValues(alpha: 0.15),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.calendar_today_rounded,
                              color: AppTheme.primary,
                              size: 12,
                            ),
                            const SizedBox(width: 5),
                            Text(
                              item['report_date'] ?? '',
                              style: GoogleFonts.inter(
                                color: AppTheme.primary,
                                fontSize: 11.5,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 8),
                      // Position badge
                      if (pos.isNotEmpty)
                        Flexible(
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 5,
                            ),
                            decoration: BoxDecoration(
                              color: posColor.withValues(alpha: 0.12),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              pos,
                              style: GoogleFonts.kantumruyPro(
                                color: posColor,
                                fontSize: 10,
                                fontWeight: FontWeight.w600,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ),
                    ],
                  ),
                ],
              ],
            ),
          ),
          // Content
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text(
              item['content'] ?? '',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.80),
                fontSize: 13.5,
                height: 1.7,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLabelField(String label, Widget field) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(left: 4, bottom: 8),
          child: Text(
            label,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary.withValues(alpha: 0.70),
              fontSize: 13,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
        field,
      ],
    );
  }

  Widget _buildDropdown(
    String value,
    List<String> items,
    Function(String?) onChanged,
  ) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      decoration: BoxDecoration(
        color: AppTheme.textPrimary.withValues(alpha: 0.05),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.1)),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<String>(
          value: value,
          isExpanded: true,
          dropdownColor: AppTheme.bgCard,
          icon: Icon(
            Icons.keyboard_arrow_down_rounded,
            color: AppTheme.textPrimary.withValues(alpha: 0.38),
          ),
          items: items
              .map(
                (String v) => DropdownMenuItem(
                  value: v,
                  child: Text(
                    v,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary,
                      fontSize: 14,
                    ),
                  ),
                ),
              )
              .toList(),
          onChanged: onChanged,
        ),
      ),
    );
  }

  Widget _buildDatePicker(
    DateTime date,
    Function(DateTime) onPicked, {
    bool showTime = false,
  }) {
    return InkWell(
      onTap: () async {
        final picked = await showDatePicker(
          context: context,
          initialDate: date,
          firstDate: DateTime(2020),
          lastDate: DateTime(2030),
        );
        if (picked != null) {
          if (showTime) {
            if (!mounted) return;
            final time = await showTimePicker(
              context: context,
              initialTime: TimeOfDay.fromDateTime(date),
            );
            if (time != null) {
              onPicked(
                DateTime(
                  picked.year,
                  picked.month,
                  picked.day,
                  time.hour,
                  time.minute,
                ),
              );
            } else {
              onPicked(picked);
            }
          } else {
            onPicked(picked);
          }
        }
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
        decoration: BoxDecoration(
          color: AppTheme.textPrimary.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: AppTheme.textPrimary.withValues(alpha: 0.1),
          ),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              DateFormat(
                showTime ? 'dd/MM/yyyy hh:mm a' : 'dd/MM/yyyy',
              ).format(date),
              style: GoogleFonts.inter(
                color: AppTheme.textPrimary,
                fontSize: 14,
              ),
            ),
            Icon(
              Icons.calendar_month_rounded,
              color: AppTheme.primary,
              size: 20,
            ),
          ],
        ),
      ),
    );
  }

  InputDecoration _inputDecoration(String hint, {IconData? icon}) {
    return InputDecoration(
      hintText: hint,
      prefixIcon: icon != null
          ? Padding(
              padding: const EdgeInsets.only(bottom: 120),
              child: Icon(
                icon,
                color: AppTheme.textPrimary.withValues(alpha: 0.24),
                size: 20,
              ),
            )
          : null,
      hintStyle: GoogleFonts.kantumruyPro(
        color: AppTheme.textPrimary.withValues(alpha: 0.24),
        fontSize: 13,
      ),
      filled: true,
      fillColor: AppTheme.textPrimary.withValues(alpha: 0.05),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide.none,
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide(
          color: AppTheme.textPrimary.withValues(alpha: 0.05),
        ),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide(color: AppTheme.primary, width: 1.5),
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
    );
  }

  Widget _buildFormTextField({
    required TextEditingController controller,
    bool readOnly = false,
    bool isKhmer = false,
    String? hint,
    IconData? icon,
    int maxLines = 1,
  }) {
    return TextFormField(
      controller: controller,
      readOnly: readOnly,
      maxLines: maxLines,
      style: (isKhmer ? GoogleFonts.kantumruyPro : GoogleFonts.inter)(
        color: readOnly
            ? AppTheme.textPrimary.withValues(alpha: 0.38)
            : AppTheme.textPrimary,
        fontSize: 14,
      ),
      decoration: _inputDecoration(hint ?? "", icon: icon),
    );
  }

  Widget _buildComplexForm() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              "បញ្ជីកិច្ចការ",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
            TextButton.icon(
              onPressed: () => setState(() => _addTaskRow()),
              icon: const Icon(Icons.add_circle_outline, size: 18),
              label: Text("បន្ថែមថ្មី", style: GoogleFonts.kantumruyPro()),
              style: TextButton.styleFrom(foregroundColor: AppTheme.primary),
            ),
          ],
        ),
        ..._tasks.asMap().entries.map((e) {
          int index = e.key;
          var item = e.value;
          return Container(
            margin: const EdgeInsets.only(bottom: 16),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.textPrimary.withValues(alpha: 0.03),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: AppTheme.textPrimary.withValues(alpha: 0.1),
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      "កិច្ចការទី ${index + 1}",
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.primary,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    if (_tasks.length > 1)
                      IconButton(
                        icon: Icon(
                          Icons.delete_outline,
                          color: AppTheme.danger,
                          size: 20,
                        ),
                        onPressed: () => _removeTaskRow(index),
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints(),
                      ),
                  ],
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Expanded(
                      child: _buildLabelField(
                        "ម៉ោង",
                        _buildFormTextField(
                          controller: item['time']!,
                          hint: "--:--",
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: _buildLabelField(
                        "ស្ថានភាព",
                        _buildFormTextField(
                          controller: item['status']!,
                          hint: "100%",
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                _buildLabelField(
                  "កាលបរិច្ឆេទកំណត់",
                  _buildDatePicker(
                    item['dueDate']!.text.isEmpty
                        ? DateTime.now()
                        : (DateTime.tryParse(item['dueDate']!.text) ??
                              DateTime.now()),
                    (d) => setState(
                      () => item['dueDate']!.text = DateFormat(
                        'yyyy-MM-dd',
                      ).format(d),
                    ),
                  ),
                ),
                if (item['dueDate']!.text.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text(
                      "កំណត់: ${item['dueDate']!.text}",
                      style: GoogleFonts.inter(
                        color: AppTheme.primary,
                        fontSize: 13,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                const SizedBox(height: 12),
                _buildLabelField(
                  "កិច្ចការ / បញ្ហា",
                  _buildFormTextField(
                    controller: item['task']!,
                    hint: "អធិប្បាយពីកិច្ចការ...",
                    maxLines: 2,
                  ),
                ),
                const SizedBox(height: 12),
                _buildLabelField(
                  "ពិពណ៌នា",
                  _buildFormTextField(
                    controller: item['description']!,
                    hint: "ពិពណ៌នាលម្អិត...",
                    maxLines: 2,
                  ),
                ),
                const SizedBox(height: 12),
                _buildLabelField(
                  "បញ្ហា",
                  _buildFormTextField(
                    controller: item['problem']!,
                    hint: "បញ្ហាជួបប្រទះ (បើមាន)...",
                    maxLines: 2,
                  ),
                ),
                const SizedBox(height: 12),
                _buildLabelField(
                  "ដំណោះស្រាយ",
                  _buildFormTextField(
                    controller: item['solution']!,
                    hint: "ដំណោះស្រាយ (បើមាន)...",
                    maxLines: 2,
                  ),
                ),
              ],
            ),
          );
        }),

        const SizedBox(height: 24),
        Container(
          height: 1,
          color: AppTheme.textPrimary.withValues(alpha: 0.1),
        ),
        const SizedBox(height: 24),

        Text(
          "ផែនការសម្រាប់ថ្ងៃបន្ទាប់",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontWeight: FontWeight.bold,
            fontSize: 16,
          ),
        ),
        const SizedBox(height: 16),
        _buildLabelField(
          "កាលបរិច្ឆេទផែនការ",
          _buildDatePicker(
            _nextPlanDate,
            (d) => setState(() => _nextPlanDate = d),
          ),
        ),
        const SizedBox(height: 12),
        _buildLabelField(
          "ព័ត៌មានលម្អិតអំពីផែនការ",
          _buildFormTextField(
            controller: _nextPlanDetailsController,
            hint: "សរសេរផែនការរបស់អ្នកនៅទីនេះ...",
            maxLines: 4,
          ),
        ),

        const SizedBox(height: 24),
        SizedBox(
          width: double.infinity,
          height: 50,
          child: OutlinedButton.icon(
            onPressed: () {
              showDialog(
                context: context,
                builder: (_) => _DailyReportScreenshotPreview(
                  tasks: _tasks,
                  nextPlanDate: _nextPlanDate,
                  nextPlanDetails: _nextPlanDetailsController.text,
                  name: _nameController.text,
                  position: _selectedPosition,
                  department: Provider.of<UserProvider>(
                    context,
                    listen: false,
                  ).systemRoleLabel,
                ),
              );
            },
            icon: Icon(Icons.camera_alt_outlined, color: AppTheme.primary),
            label: Text(
              "មើល និងថតរូប (Screenshot)",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.primary,
                fontWeight: FontWeight.bold,
              ),
            ),
            style: OutlinedButton.styleFrom(
              side: BorderSide(color: AppTheme.primary),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

class _DailyReportScreenshotPreview extends StatefulWidget {
  final List<Map<String, TextEditingController>> tasks;
  final DateTime nextPlanDate;
  final String nextPlanDetails;
  final String name;
  final String position;
  final String department;

  const _DailyReportScreenshotPreview({
    required this.tasks,
    required this.nextPlanDate,
    required this.nextPlanDetails,
    required this.name,
    required this.position,
    required this.department,
  });

  @override
  State<_DailyReportScreenshotPreview> createState() =>
      _DailyReportScreenshotPreviewState();
}

class _DailyReportScreenshotPreviewState
    extends State<_DailyReportScreenshotPreview> {
  final GlobalKey _globalKey = GlobalKey();
  bool _isSaving = false;

  Future<void> _captureAndCopy() async {
    setState(() => _isSaving = true);
    try {
      RenderRepaintBoundary boundary =
          _globalKey.currentContext!.findRenderObject()
              as RenderRepaintBoundary;
      ui.Image image = await boundary.toImage(pixelRatio: 2.0);
      ByteData? byteData = await image.toByteData(
        format: ui.ImageByteFormat.png,
      );
      if (byteData != null) {
        Uint8List pngBytes = byteData.buffer.asUint8List();
        await Pasteboard.writeImage(pngBytes);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                'បានថតរូប និង Copy រួចរាល់! អ្នកអាច Paste ចូល Telegram បាន។',
                style: GoogleFonts.kantumruyPro(color: Colors.white),
              ),
              backgroundColor: Colors.green.shade700,
            ),
          );
          Navigator.pop(context);
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('បរាជ័យ: $e')));
      }
    } finally {
      if (mounted) setState(() => _isSaving = false);
    }
  }

  Widget _buildCell(
    String text, {
    bool isHeader = false,
    double padding = 8.0,
  }) {
    return Container(
      padding: EdgeInsets.all(padding),
      child: Text(
        text.trim().isEmpty ? "-" : text.trim(),
        style: isHeader
            ? GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 13,
              )
            : GoogleFonts.kantumruyPro(
                color: const Color(0xFF333333),
                fontSize: 13,
              ),
      ),
    );
  }

  Widget _buildInfoItem(String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.kantumruyPro(
            fontSize: 12,
            color: Colors.black54,
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 4),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: const Color(0xFFFAFAFA),
            border: Border.all(color: Colors.grey.shade300),
            borderRadius: BorderRadius.circular(4),
          ),
          child: Text(
            value.trim().isEmpty ? "-" : value.trim(),
            style: GoogleFonts.kantumruyPro(
              fontSize: 13,
              color: Colors.black87,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black87,
      appBar: AppBar(
        title: Text(
          "មើលជាមុន (Preview Report)",
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16),
        ),
        backgroundColor: Colors.transparent,
        iconTheme: const IconThemeData(color: Colors.white),
      ),
      body: Center(
        child: SingleChildScrollView(
          scrollDirection: Axis.vertical,
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: RepaintBoundary(
              key: _globalKey,
              child: Container(
                width: 1000,
                color: Colors.white,
                padding: const EdgeInsets.all(32),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Title Header
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(
                          Icons.description,
                          color: Color(0xFF2E7D32),
                          size: 28,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          "Individual Daily Report",
                          style: GoogleFonts.inter(
                            color: const Color(0xFF2E7D32),
                            fontSize: 22,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 24),

                    // Info Row
                    Container(
                      decoration: BoxDecoration(
                        color: Colors.white,
                        border: Border.all(color: Colors.grey.shade300),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      padding: const EdgeInsets.all(12),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          _buildInfoItem(
                            "កាលបរិច្ឆេទរបាយការណ៍",
                            DateFormat('dd/MM/yyyy').format(DateTime.now()),
                          ),
                          _buildInfoItem("ឈ្មោះបុគ្គលិក", widget.name),
                          _buildInfoItem("តួនាទី", widget.position),
                          _buildInfoItem("ផ្នែក", widget.department),
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),

                    // Table Data
                    Table(
                      border: TableBorder.all(color: Colors.grey.shade300),
                      columnWidths: const {
                        0: FixedColumnWidth(100),
                        1: FlexColumnWidth(3),
                        2: FixedColumnWidth(80),
                        3: FixedColumnWidth(120),
                        4: FlexColumnWidth(2),
                        5: FlexColumnWidth(2),
                        6: FlexColumnWidth(2),
                      },
                      children: [
                        TableRow(
                          decoration: const BoxDecoration(
                            color: Color(0xFF2E7D32),
                          ),
                          children: [
                            _buildCell("ម៉ោង", isHeader: true, padding: 12),
                            _buildCell(
                              "កិច្ចការ / បញ្ហា",
                              isHeader: true,
                              padding: 12,
                            ),
                            _buildCell("ស្ថានភាព", isHeader: true, padding: 12),
                            _buildCell(
                              "កាលបរិច្ឆេទកំណត់",
                              isHeader: true,
                              padding: 12,
                            ),
                            _buildCell("ពិពណ៌នា", isHeader: true, padding: 12),
                            _buildCell("បញ្ហា", isHeader: true, padding: 12),
                            _buildCell(
                              "ដំណោះស្រាយ",
                              isHeader: true,
                              padding: 12,
                            ),
                          ],
                        ),
                        ...widget.tasks
                            .where((t) => t['task']!.text.trim().isNotEmpty)
                            .map((t) {
                              return TableRow(
                                decoration: const BoxDecoration(
                                  color: Colors.white,
                                ),
                                children: [
                                  _buildCell(t['time']!.text, padding: 12),
                                  _buildCell(t['task']!.text, padding: 12),
                                  _buildCell(t['status']!.text, padding: 12),
                                  _buildCell(t['dueDate']!.text, padding: 12),
                                  _buildCell(
                                    t['description']!.text,
                                    padding: 12,
                                  ),
                                  _buildCell(t['problem']!.text, padding: 12),
                                  _buildCell(t['solution']!.text, padding: 12),
                                ],
                              );
                            }),
                      ],
                    ),
                    const SizedBox(height: 32),

                    // Next Plan Section
                    Container(
                      width: double.infinity,
                      decoration: BoxDecoration(
                        border: Border.all(color: Colors.grey.shade300),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Container(
                            width: double.infinity,
                            padding: const EdgeInsets.symmetric(
                              horizontal: 16,
                              vertical: 12,
                            ),
                            decoration: const BoxDecoration(
                              color: Color(0xFFF1F8E9),
                              border: Border(
                                bottom: BorderSide(
                                  color: Color(0xFFE8F5E9),
                                  width: 2,
                                ),
                              ),
                            ),
                            child: Row(
                              children: [
                                const Icon(
                                  Icons.calendar_today_rounded,
                                  color: Color(0xFF2E7D32),
                                  size: 18,
                                ),
                                const SizedBox(width: 8),
                                Text(
                                  "ផែនការសម្រាប់ថ្ងៃបន្ទាប់",
                                  style: GoogleFonts.kantumruyPro(
                                    fontSize: 15,
                                    fontWeight: FontWeight.bold,
                                    color: const Color(0xFF2E7D32),
                                  ),
                                ),
                              ],
                            ),
                          ),
                          Padding(
                            padding: const EdgeInsets.all(16),
                            child: Row(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                SizedBox(
                                  width: 200,
                                  child: _buildInfoItem(
                                    "កាលបរិច្ឆេទផែនការ",
                                    DateFormat(
                                      'dd/MM/yyyy',
                                    ).format(widget.nextPlanDate),
                                  ),
                                ),
                                const SizedBox(width: 24),
                                Expanded(
                                  child: _buildInfoItem(
                                    "ព័ត៌មានលម្អិតអំពីផែនការ",
                                    widget.nextPlanDetails,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        backgroundColor: const Color(0xFF2E7D32),
        onPressed: _isSaving ? null : _captureAndCopy,
        icon: _isSaving
            ? const SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(
                  color: Colors.white,
                  strokeWidth: 2,
                ),
              )
            : const Icon(Icons.camera_alt, color: Colors.white),
        label: Text(
          _isSaving ? "កំពុងដំណើរការ..." : "ថតរូប និង Copy ទៅ Telegram",
          style: GoogleFonts.kantumruyPro(
            color: Colors.white,
            fontWeight: FontWeight.bold,
          ),
        ),
      ),
    );
  }
}
