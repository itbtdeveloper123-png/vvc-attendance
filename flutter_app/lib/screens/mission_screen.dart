import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import 'package:intl/intl.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import 'mission_detail_screen.dart';

class MissionScreen extends StatefulWidget {
  const MissionScreen({super.key});

  @override
  State<MissionScreen> createState() => _MissionScreenState();
}

class _MissionScreenState extends State<MissionScreen> {
  final ApiService _api = ApiService();

  // Basic info
  final _locationController = TextEditingController();
  final _purposeController = TextEditingController();

  // Schedule
  DateTime _startDate = DateTime.now();
  TimeOfDay _startTime = const TimeOfDay(hour: 8, minute: 0);
  DateTime _endDate = DateTime.now().add(const Duration(days: 1));
  TimeOfDay _endTime = const TimeOfDay(hour: 17, minute: 0);

  // Transport & materials
  final _transportController = TextEditingController();
  final _materialsController = TextEditingController();

  // Khmer date
  final _dateKhmerPart1Controller = TextEditingController();
  final _dateKhmerPart2Controller = TextEditingController(
    text: 'រាជធានីភ្នំពេញ, ថ្ងៃទី  ខែ  ឆ្នាំ២០២៦',
  );

  // Personnel list: each item = {name, role}
  final List<Map<String, TextEditingController>> _personnel = [];

  List<dynamic> _missions = [];
  bool _isLoading = true;
  bool _isSubmitting = false;

  // Tree state for navigation
  int _treeLevel = 0;
  int? _treeYear;
  int? _treeMonth;

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

  @override
  void initState() {
    super.initState();
    // Start with 3 personnel rows
    for (int i = 0; i < 3; i++) {
      _personnel.add({
        'name': TextEditingController(),
        'role': TextEditingController(),
      });
    }
    _loadData();
  }

  @override
  void dispose() {
    _locationController.dispose();
    _purposeController.dispose();
    _transportController.dispose();
    _materialsController.dispose();
    _dateKhmerPart1Controller.dispose();
    _dateKhmerPart2Controller.dispose();
    for (final row in _personnel) {
      row['name']!.dispose();
      row['role']!.dispose();
    }
    super.dispose();
  }

  Future<void> _loadData() async {
    if (_missions.isEmpty) {
      if (mounted) setState(() => _isLoading = true);
    }
    try {
      final res = await _api.fetchMissionLetters();
      if (res['status'] == 'success' || res['success'] == true) {
        if (mounted) {
          setState(() {
            _missions = res['data'] ?? [];
            _isLoading = false;
          });
        }
      } else {
        if (mounted) setState(() => _isLoading = false);
      }
    } catch (e) {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  String _formatTime(TimeOfDay t) {
    final h = t.hour.toString().padLeft(2, '0');
    final m = t.minute.toString().padLeft(2, '0');
    return '$h:$m';
  }

  Future<void> _submitMission() async {
    if (_locationController.text.trim().isEmpty ||
        _purposeController.text.trim().isEmpty) {
      return;
    }

    setState(() => _isSubmitting = true);
    try {
      final personnelData = _personnel
          .map(
            (row) => {
              'name': row['name']!.text.trim(),
              'role': row['role']!.text.trim(),
            },
          )
          .where((row) => row['name']!.isNotEmpty)
          .toList();

      final res = await _api.submitMissionLetter(
        location: _locationController.text.trim(),
        purpose: _purposeController.text.trim(),
        startDate: DateFormat('yyyy-MM-dd').format(_startDate),
        startTime: _formatTime(_startTime),
        endDate: DateFormat('yyyy-MM-dd').format(_endDate),
        endTime: _formatTime(_endTime),
        transport: _transportController.text.trim(),
        materials: _materialsController.text.trim(),
        dateKhmerPart1: _dateKhmerPart1Controller.text.trim(),
        dateKhmerPart2: _dateKhmerPart2Controller.text.trim(),
        personnel: personnelData,
      );
      if (res['status'] == 'success') {
        _resetForm();
        _loadData();
        _showDialog(
          title: "ជោគជ័យ!",
          msg: "ស្នើសុំបេសកកម្មបានជោគជ័យ",
          isError: false,
        );
      } else {
        _showDialog(
          title: "បរាជ័យ",
          msg: res['message'] ?? "ការផ្ញើបានបរាជ័យ",
          isError: true,
        );
      }
    } catch (e) {
      _showDialog(
        title: "កំហុស",
        msg: "ការផ្ញើលិខិតបេសកកម្មបានបរាជ័យ",
        isError: true,
      );
    } finally {
      if (mounted) setState(() => _isSubmitting = false);
    }
  }

  void _resetForm() {
    _locationController.clear();
    _purposeController.clear();
    _transportController.clear();
    _materialsController.clear();
    _dateKhmerPart1Controller.clear();
    for (final row in _personnel) {
      row['name']!.clear();
      row['role']!.clear();
    }
  }

  // Helper to parse yyyy-MM-dd
  (int year, int month, int day) _parseDate(String raw) {
    try {
      final parts = raw.split('-');
      return (int.parse(parts[0]), int.parse(parts[1]), int.parse(parts[2]));
    } catch (_) {
      return (0, 0, 0);
    }
  }

  // Build tree Map<Year, Map<Month, List<Mission>>>
  Map<int, Map<int, List<dynamic>>> _buildTree() {
    final tree = <int, Map<int, List<dynamic>>>{};
    for (final m in _missions) {
      final (y, mon, d) = _parseDate(m['start_date']?.toString() ?? '');
      if (y == 0) continue;
      tree.putIfAbsent(y, () => {});
      tree[y]!.putIfAbsent(mon, () => []);
      tree[y]![mon]!.add(m);
    }
    return tree;
  }

  void _treeOpen({int? year, int? month}) {
    setState(() {
      _treeYear = year;
      _treeMonth = month;
      if (month != null) {
        _treeLevel = 2;
      } else if (year != null) {
        _treeLevel = 1;
      } else {
        _treeLevel = 0;
      }
    });
  }

  @override
  Widget build(BuildContext context) {
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
            "លិខិតបេសកកម្ម",
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
            labelColor: AppTheme.primary,
            labelStyle: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
            unselectedLabelColor: AppTheme.textPrimary.withValues(alpha: 0.4),
            tabs: const [
              Tab(text: "ស្នើសុំបេសកកម្ម"),
              Tab(text: "ប្រវត្តិនៃការចុះ"),
            ],
          ),
        ),
        body: AppBackgroundShell(
          child: TabBarView(
            physics: const BouncingScrollPhysics(),
            children: [_buildSubmitTab(), _buildHistoryTab()],
          ),
        ),
      ),
    );
  }

  Widget _buildSubmitTab() {
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      padding: const EdgeInsets.fromLTRB(20, 160, 20, 24),
      child: FadeInUp(
        child: Column(
          children: [
            _buildSection(
              icon: Icons.info_outline,
              title: 'ព័ត៌មានបេសកកម្ម',
              body: _buildInfoFields(),
            ),
            const SizedBox(height: 16),
            _buildSection(
              icon: Icons.group_rounded,
              title: 'បុគ្គលិកបេសកកម្ម',
              body: _buildPersonnelList(),
            ),
            const SizedBox(height: 16),
            _buildSection(
              icon: Icons.calendar_today,
              title: 'កាលវិភាគ',
              body: _buildScheduleFields(),
            ),
            const SizedBox(height: 16),
            _buildSection(
              icon: Icons.directions_car,
              title: 'មធ្យោបាយ និងសម្ភារៈ',
              body: _buildMiscFields(),
            ),
            const SizedBox(height: 32),
            _buildSubmitButton(),
          ],
        ),
      ),
    );
  }

  Widget _buildHistoryTab() {
    if (_isLoading) return _buildShimmerList();
    if (_missions.isEmpty) return _buildEmptyState();

    final tree = _buildTree();
    return Column(
      children: [
        _buildTreeBreadcrumb(),
        Expanded(
          child: RefreshIndicator(
            onRefresh: _loadData,
            color: AppTheme.primary,
            child: _buildTreeBody(tree),
          ),
        ),
      ],
    );
  }

  Widget _buildTreeBreadcrumb() {
    final crumbs = <(String, VoidCallback?)>[];
    crumbs.add(('បេសកកម្មទាំងអស់', _treeLevel > 0 ? () => _treeOpen() : null));
    if (_treeYear != null) {
      crumbs.add((
        'ឆ្នាំ $_treeYear',
        _treeLevel > 1 ? () => _treeOpen(year: _treeYear) : null,
      ));
    }
    if (_treeMonth != null) {
      crumbs.add(('ខែ ${_khmerMonths[_treeMonth!]}', null));
    }

    return Container(
      margin: const EdgeInsets.fromLTRB(20, 160, 20, 10),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: AppTheme.bgCard.withValues(alpha: 0.6),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.borderColor),
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          children: [
            Icon(Icons.folder_open_rounded, size: 16, color: AppTheme.primary),
            const SizedBox(width: 8),
            ...crumbs.asMap().entries.map((e) {
              final isLast = e.key == crumbs.length - 1;
              final (label, onTap) = e.value;
              return Row(
                children: [
                  InkWell(
                    onTap: onTap,
                    borderRadius: BorderRadius.circular(8),
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 4,
                      ),
                      decoration: BoxDecoration(
                        color: isLast
                            ? AppTheme.primary.withValues(alpha: 0.15)
                            : Colors.transparent,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        label,
                        style: GoogleFonts.kantumruyPro(
                          color: isLast ? AppTheme.primary : AppTheme.textMuted,
                          fontSize: 13,
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
                      size: 16,
                    ),
                ],
              );
            }),
          ],
        ),
      ),
    );
  }

  Widget _buildTreeBody(Map<int, Map<int, List<dynamic>>> tree) {
    if (_treeLevel == 0) {
      final years = tree.keys.toList()..sort((a, b) => b.compareTo(a));
      return ListView.builder(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
        physics: const BouncingScrollPhysics(),
        itemCount: years.length,
        itemBuilder: (_, i) {
          final y = years[i];
          final missionCount = tree[y]!.values.fold<int>(
            0,
            (s, l) => s + l.length,
          );
          final monthCount = tree[y]!.length;
          return _folderTile(
            icon: Icons.folder_special_rounded,
            color: const Color(0xFF4F8EF7),
            label: 'ឆ្នាំ $y',
            count: missionCount,
            subtitle: '$monthCount ខែ',
            onTap: () => _treeOpen(year: y),
          );
        },
      );
    }
    if (_treeLevel == 1) {
      final months = (tree[_treeYear] ?? {}).keys.toList()
        ..sort((a, b) => b.compareTo(a));
      return ListView.builder(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
        physics: const BouncingScrollPhysics(),
        itemCount: months.length,
        itemBuilder: (_, i) {
          final m = months[i];
          final count = tree[_treeYear]![m]!.length;
          return _folderTile(
            icon: Icons.folder_rounded,
            color: const Color(0xFF9B59F5),
            label: 'ខែ ${_khmerMonths[m]}',
            count: count,
            onTap: () => _treeOpen(year: _treeYear, month: m),
          );
        },
      );
    }

    final missionList = tree[_treeYear]?[_treeMonth] ?? [];
    return ListView.builder(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
      physics: const BouncingScrollPhysics(),
      itemCount: missionList.length,
      itemBuilder: (_, i) => AnimationConfiguration.staggeredList(
        position: i,
        duration: const Duration(milliseconds: 500),
        child: SlideAnimation(
          verticalOffset: 50.0,
          child: FadeInAnimation(child: _buildMissionCard(missionList[i])),
        ),
      ),
    );
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
      child: Container(
        margin: const EdgeInsets.only(bottom: 12),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(24),
          border: Border.all(color: color.withValues(alpha: 0.15)),
          boxShadow: [
            BoxShadow(
              color: color.withValues(alpha: 0.05),
              blurRadius: 10,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Row(
          children: [
            Container(
              width: 50,
              height: 50,
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Icon(icon, color: color, size: 26),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                    ),
                  ),
                  if (subtitle != null) ...[
                    const SizedBox(height: 4),
                    Text(
                      subtitle,
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textMuted,
                        fontSize: 13,
                      ),
                    ),
                  ],
                ],
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                '$count',
                style: GoogleFonts.inter(
                  color: color,
                  fontWeight: FontWeight.bold,
                  fontSize: 13,
                ),
              ),
            ),
            const SizedBox(width: 10),
            Icon(
              Icons.arrow_forward_ios_rounded,
              size: 14,
              color: color.withValues(alpha: 0.4),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildShimmerList() {
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(20, 160, 20, 20),
      itemCount: 6,
      itemBuilder: (context, index) => Padding(
        padding: const EdgeInsets.only(bottom: 16),
        child: AppShimmer(
          child: Container(
            height: 90,
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(20),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.history_toggle_off_rounded,
            size: 80,
            color: AppTheme.textMuted.withValues(alpha: 0.2),
          ),
          const SizedBox(height: 16),
          Text(
            "មិនទាន់មានប្រវត្តិបេសកកម្មនៅឡើយ",
            style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary),
          ),
        ],
      ),
    );
  }

  Widget _buildMissionCard(dynamic item) {
    final location = item['location'] ?? 'គ្មានទីតាំង';
    final purpose = item['purpose'] ?? 'បេសកកម្មការងារ';
    final String dateString =
        "${item['start_date_fmt'] ?? '-'}  →  ${item['end_date_fmt'] ?? '-'}";

    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      decoration: BoxDecoration(
        color: AppTheme.bgCardLight.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.2),
            blurRadius: 15,
            offset: const Offset(0, 8),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(24),
          onTap: () => Navigator.push(
            context,
            MaterialPageRoute(
              builder: (context) => MissionDetailScreen(mission: item),
            ),
          ),
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Row(
              children: [
                // Premium Icon Box
                Container(
                  width: 56,
                  height: 56,
                  decoration: BoxDecoration(
                    color: AppTheme.primary.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(18),
                    border: Border.all(
                      color: AppTheme.primary.withValues(alpha: 0.3),
                    ),
                  ),
                  child: Center(
                    child: Icon(
                      Icons.explore_rounded,
                      color: AppTheme.primary,
                      size: 28,
                    ),
                  ),
                ),
                const SizedBox(width: 16),

                // Content Stack
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        location,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          letterSpacing: 0.3,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        purpose,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.primaryLight,
                          fontSize: 13,
                        ),
                      ),
                      const SizedBox(height: 8),
                      // Date Row with Micro-Icon
                      Row(
                        children: [
                          Icon(
                            Icons.calendar_month_rounded,
                            size: 14,
                            color: AppTheme.textMuted,
                          ),
                          const SizedBox(width: 6),
                          Expanded(
                            child: Text(
                              dateString,
                              style: GoogleFonts.inter(
                                color: AppTheme.textSecondary,
                                fontSize: 12,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),

                // Circular Trailing Button
                Container(
                  width: 36,
                  height: 36,
                  decoration: BoxDecoration(
                    color: AppTheme.bgDark.withValues(alpha: 0.6),
                    shape: BoxShape.circle,
                    border: Border.all(
                      color: Colors.white.withValues(alpha: 0.05),
                    ),
                  ),
                  child: const Icon(
                    Icons.arrow_forward_ios_rounded,
                    color: Colors.white70,
                    size: 16,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildSection({
    required IconData icon,
    required String title,
    required Widget body,
  }) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppTheme.bgCard.withValues(alpha: 0.8),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: AppTheme.borderColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: AppTheme.primary, size: 18),
              const SizedBox(width: 10),
              Text(
                title,
                style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
              ),
            ],
          ),
          const Divider(height: 24),
          body,
        ],
      ),
    );
  }

  Widget _buildInfoFields() {
    return Column(
      children: [
        _buildTextField(
          controller: _locationController,
          hint: "បញ្ជាក់ទីតាំង...",
          label: "ទីតាំង *",
          icon: Icons.location_on,
        ),
        const SizedBox(height: 12),
        _buildTextField(
          controller: _purposeController,
          hint: "បញ្ជាក់គោលបំណង...",
          label: "គោលបំណង *",
          icon: Icons.flag,
        ),
      ],
    );
  }

  Widget _buildPersonnelList() {
    return Column(
      children: [
        ...List.generate(
          _personnel.length,
          (i) => Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: Row(
              children: [
                Expanded(
                  child: _buildTextField(
                    controller: _personnel[i]['name']!,
                    hint: "ឈ្មោះ...",
                    label: "បុគ្គលិក ${i + 1}",
                    icon: Icons.person,
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: _buildTextField(
                    controller: _personnel[i]['role']!,
                    hint: "តួនាទី...",
                    label: "តួនាទី",
                    icon: Icons.work,
                  ),
                ),
              ],
            ),
          ),
        ),
        TextButton.icon(
          onPressed: () {
            if (_personnel.length >= 10) {
              _showDialog(
                title: "ចំណាំ",
                msg: "អាចបន្ថែមបុគ្គលិកបានច្រើនបំផុត 10 នាក់ប៉ុណ្ណោះ។",
                isError: true,
              );
              return;
            }
            setState(
              () => _personnel.add({
                'name': TextEditingController(),
                'role': TextEditingController(),
              }),
            );
          },
          icon: const Icon(Icons.add_circle_outline),
          label: const Text("បន្ថែមបុគ្គលិក"),
        ),
      ],
    );
  }

  Widget _buildScheduleFields() {
    return Column(
      children: [
        Row(
          children: [
            Expanded(
              child: _buildDateField(
                label: "ថ្ងៃចេញ",
                date: _startDate,
                onTap: () async {
                  final d = await showDatePicker(
                    context: context,
                    initialDate: _startDate,
                    firstDate: DateTime(2020),
                    lastDate: DateTime(2030),
                  );
                  if (d != null) setState(() => _startDate = d);
                },
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: _buildTimeField(
                label: "ម៉ោងចេញ",
                time: _startTime,
                onTap: () async {
                  final t = await showTimePicker(
                    context: context,
                    initialTime: _startTime,
                  );
                  if (t != null) setState(() => _startTime = t);
                },
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: _buildDateField(
                label: "ថ្ងៃត្រឡប់",
                date: _endDate,
                onTap: () async {
                  final d = await showDatePicker(
                    context: context,
                    initialDate: _endDate,
                    firstDate: DateTime(2020),
                    lastDate: DateTime(2030),
                  );
                  if (d != null) setState(() => _endDate = d);
                },
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: _buildTimeField(
                label: "ម៉ោងត្រឡប់",
                time: _endTime,
                onTap: () async {
                  final t = await showTimePicker(
                    context: context,
                    initialTime: _endTime,
                  );
                  if (t != null) setState(() => _endTime = t);
                },
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildMiscFields() {
    return Column(
      children: [
        _buildTextField(
          controller: _transportController,
          hint: "ឡានក្រុមហ៊ុន...",
          label: "មធ្យោបាយ *",
          icon: Icons.directions_car,
        ),
        const SizedBox(height: 12),
        _buildTextField(
          controller: _materialsController,
          hint: "ឯកសារ...",
          label: "សម្ភារៈ",
          icon: Icons.inventory,
        ),
        const SizedBox(height: 12),
        _buildTextField(
          controller: _dateKhmerPart1Controller,
          hint: "ឧ. ថ្ងៃសីល...",
          label: "ខ្មែរ បន្ទាត់១",
          icon: Icons.edit,
        ),
        const SizedBox(height: 12),
        _buildTextField(
          controller: _dateKhmerPart2Controller,
          hint: "រាជធានីភ្នំពេញ...",
          label: "ខ្មែរ បន្ទាត់២",
          icon: Icons.place,
        ),
      ],
    );
  }

  Widget _buildSubmitButton() {
    return SizedBox(
      width: double.infinity,
      height: 55,
      child: ElevatedButton(
        onPressed: _isSubmitting ? null : _submitMission,
        style: ElevatedButton.styleFrom(
          backgroundColor: AppTheme.primary, // Yellow
          foregroundColor: Colors.black87, // High contrast text on yellow!
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
          ),
        ),
        child: _isSubmitting
            ? const SizedBox(
                width: 24,
                height: 24,
                child: CircularProgressIndicator(
                  color: Colors.black87,
                  strokeWidth: 2,
                ),
              )
            : Text(
                "ស្នើសុំបេសកកម្ម",
                style: GoogleFonts.kantumruyPro(
                  fontWeight: FontWeight.bold,
                  fontSize: 16,
                ),
              ),
      ),
    );
  }

  Widget _buildTextField({
    required TextEditingController controller,
    required String hint,
    required String label,
    required IconData icon,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.kantumruyPro(
            fontSize: 12,
            color: AppTheme.textSecondary,
          ),
        ),
        const SizedBox(height: 5),
        TextField(
          controller: controller,
          decoration: AppTheme.inputDecoration(hint, icon),
          style: GoogleFonts.kantumruyPro(fontSize: 14),
        ),
      ],
    );
  }

  Widget _buildDateField({
    required String label,
    required DateTime date,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: GoogleFonts.kantumruyPro(
              fontSize: 12,
              color: AppTheme.textSecondary,
            ),
          ),
          const SizedBox(height: 5),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(15),
              border: Border.all(color: AppTheme.borderColor),
            ),
            child: Row(
              children: [
                const Icon(Icons.calendar_today, size: 16),
                const SizedBox(width: 8),
                Text(DateFormat('dd/MM/yyyy').format(date)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTimeField({
    required String label,
    required TimeOfDay time,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: GoogleFonts.kantumruyPro(
              fontSize: 12,
              color: AppTheme.textSecondary,
            ),
          ),
          const SizedBox(height: 5),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(15),
              border: Border.all(color: AppTheme.borderColor),
            ),
            child: Row(
              children: [
                const Icon(Icons.access_time, size: 16),
                const SizedBox(width: 8),
                Text(_formatTime(time)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showDialog({
    required String title,
    required String msg,
    required bool isError,
  }) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        title: Text(
          title,
          style: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.bold,
            color: isError ? AppTheme.danger : AppTheme.success,
          ),
        ),
        content: Text(msg, style: GoogleFonts.kantumruyPro()),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text("OK"),
          ),
        ],
      ),
    );
  }
}
