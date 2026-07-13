import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import 'package:image_picker/image_picker.dart';
import 'package:intl/intl.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:vvc_hrm/services/api_service.dart';
import 'package:vvc_hrm/services/notification_service.dart';
import 'package:vvc_hrm/utils/app_theme.dart';
import 'package:vvc_hrm/widgets/app_widgets.dart';
import 'dart:convert';
import 'dart:io';

class ChecklistScreen extends StatefulWidget {
  const ChecklistScreen({super.key});

  @override
  State<ChecklistScreen> createState() => _ChecklistScreenState();
}

class _ChecklistScreenState extends State<ChecklistScreen> {
  final ApiService _api = ApiService();
  final ImagePicker _picker = ImagePicker();
  List<dynamic> _items = [];
  bool _isLoading = true;
  Timer? _pollingTimer;

  // Controllers for Add/Edit
  final TextEditingController _taskController = TextEditingController();
  DateTime? _startDate;
  TimeOfDay? _startTime;
  DateTime? _endDate;
  TimeOfDay? _endTime;
  File? _selectedImage;
  String _selectedCategory = 'General';

  final List<String> _categories = [
    'General',
    'Work',
    'Personal',
    'Meeting',
    'Shopping',
    'Other',
  ];

  @override
  void initState() {
    super.initState();
    _loadData();
    _pollingTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (mounted) _loadData();
    });
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    _taskController.dispose();
    super.dispose();
  }

  Future<void> _loadData() async {
    try {
      final res = await _api.fetchChecklist();
      if (res['status'] == 'success') {
        setState(() {
          _items = res['data'] ?? [];
          _isLoading = false;
        });
        _checkDeadlines();
        _scheduleItemsNotifications();
      } else {
        setState(() => _isLoading = false);
      }
    } catch (e) {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  void _scheduleItemsNotifications() async {
    if (kIsWeb) return;
    final service = NotificationService();
    for (var item in _items) {
      final bool isDone = (item['is_done'] == 1 || item['is_done'] == '1');
      if (isDone) {
        service.cancelNotification(
          item['id'] is int ? item['id'] : int.parse(item['id'].toString()),
        );
        continue;
      }

      final String? edate = item['end_date'];
      final String? etime = item['end_time'];
      if (edate != null && edate.isNotEmpty) {
        try {
          DateTime due = DateTime.parse(edate);
          if (etime != null && etime.isNotEmpty) {
            final tparts = etime.split(':');
            due = DateTime(
              due.year,
              due.month,
              due.day,
              int.parse(tparts[0]),
              int.parse(tparts[1]),
            );
          }

          if (due.isAfter(DateTime.now())) {
            service.scheduleNotification(
              id: item['id'] is int
                  ? item['id']
                  : int.parse(item['id'].toString()),
              title: "ការរំលឹកកិច្ចការងារ៖ ${item['category'] ?? 'General'}",
              body: item['task'] ?? '',
              scheduledDate: due,
            );
          }
        } catch (e) {
          debugPrint("Error scheduling notification for checklist: $e");
        }
      }
    }
  }

  void _checkDeadlines() {
    final now = DateTime.now();
    final urgentCount = _items.where((it) {
      if (it['is_done'] == 1 || it['is_done'] == '1') return false;
      if (it['end_date'] == null || it['end_date'].toString().isEmpty) {
        return false;
      }
      try {
        final due = DateTime.parse(it['end_date']);
        return due.difference(now).inDays <= 1;
      } catch (e) {
        return false;
      }
    }).length;

    if (urgentCount > 0 && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text("អ្នកមានការងារ $urgentCount ដែលជិតផុតកំណត់!"),
          backgroundColor: AppTheme.warning,
          behavior: SnackBarBehavior.floating,
        ),
      );
    }
  }

  Future<void> _addTask() async {
    if (_taskController.text.trim().isEmpty) return;

    String? imageBase64;
    if (_selectedImage != null) {
      imageBase64 = base64Encode(await _selectedImage!.readAsBytes());
    }

    try {
      final res = await _api.addChecklistItem(
        _taskController.text.trim(),
        startDate: _startDate != null
            ? DateFormat('yyyy-MM-dd').format(_startDate!)
            : null,
        startTime: _startTime != null
            ? "${_startTime!.hour.toString().padLeft(2, '0')}:${_startTime!.minute.toString().padLeft(2, '0')}"
            : null,
        endDate: _endDate != null
            ? DateFormat('yyyy-MM-dd').format(_endDate!)
            : null,
        endTime: _endTime != null
            ? "${_endTime!.hour.toString().padLeft(2, '0')}:${_endTime!.minute.toString().padLeft(2, '0')}"
            : null,
        category: _selectedCategory,
        imageBase64: imageBase64,
      );

      if (res['status'] == 'success') {
        _resetForm();
        if (mounted) Navigator.pop(context);
        _loadData();
        HapticFeedback.mediumImpact();
      } else {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text("កំហុស៖ ${res['message'] ?? 'មិនអាចរក្សាទុកបាន'}"),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text("Failed to add task")));
    }
  }

  void _resetForm() {
    _taskController.clear();
    _startDate = null;
    _startTime = null;
    _endDate = null;
    _endTime = null;
    _selectedImage = null;
    _selectedCategory = 'General';
  }

  Future<void> _toggleTask(int id, bool currentStatus) async {
    HapticFeedback.lightImpact();
    // Cancel notification if it's being marked as done
    if (!currentStatus) NotificationService().cancelNotification(id);

    try {
      final newStatus = currentStatus ? 'pending' : 'completed';
      final res = await _api.toggleChecklistStatus(id, newStatus);
      if (res['status'] == 'success') {
        _loadData();
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text("Failed to update status")));
    }
  }

  Future<void> _deleteTask(int id) async {
    HapticFeedback.heavyImpact();
    NotificationService().cancelNotification(id);
    try {
      final res = await _api.deleteChecklistItem(id);
      if (res['status'] == 'success') {
        _loadData();
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text("Failed to delete task")));
    }
  }

  void _showAddBottomSheet() {
    _resetForm();
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => StatefulBuilder(
        builder: (context, setModalState) => Container(
          padding: EdgeInsets.only(
            bottom: MediaQuery.of(context).viewInsets.bottom,
          ),
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(30)),
          ),
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const SizedBox(height: 12),
                Container(
                  width: 40,
                  height: 4,
                  decoration: BoxDecoration(
                    color: Colors.white24,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(24),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        "បន្ថែមការងារថ្មី",
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 20,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 20),

                      // Task Input
                      Container(
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.05),
                          borderRadius: BorderRadius.circular(16),
                          border: Border.all(color: Colors.white10),
                        ),
                        child: TextField(
                          controller: _taskController,
                          autofocus: true,
                          style: GoogleFonts.kantumruyPro(color: Colors.white),
                          decoration: InputDecoration(
                            hintText: "តើអ្នកចង់ធ្វើអ្វីនៅថ្ងៃនេះ?",
                            hintStyle: GoogleFonts.kantumruyPro(
                              color: Colors.white24,
                            ),
                            border: InputBorder.none,
                            contentPadding: const EdgeInsets.all(16),
                          ),
                        ),
                      ),
                      const SizedBox(height: 15),

                      // Dates selection row
                      Row(
                        children: [
                          Expanded(
                            child: _buildModalActionButton(
                              icon: Icons.play_arrow_rounded,
                              label: _startDate == null
                                  ? "ចាប់ផ្តើម"
                                  : DateFormat('dd/MM hh:mm a').format(
                                      DateTime(
                                        _startDate!.year,
                                        _startDate!.month,
                                        _startDate!.day,
                                        _startTime?.hour ?? 0,
                                        _startTime?.minute ?? 0,
                                      ),
                                    ),
                              onTap: () async {
                                final date = await showDatePicker(
                                  context: context,
                                  initialDate: DateTime.now(),
                                  firstDate: DateTime.now().subtract(
                                    const Duration(days: 365),
                                  ),
                                  lastDate: DateTime.now().add(
                                    const Duration(days: 365),
                                  ),
                                );
                                if (date != null && context.mounted) {
                                  setModalState(() => _startDate = date);
                                  final time = await showTimePicker(
                                    context: context,
                                    initialTime: TimeOfDay.now(),
                                  );
                                  if (time != null) {
                                    setModalState(() => _startTime = time);
                                  }
                                }
                              },
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: _buildModalActionButton(
                              icon: Icons.stop_rounded,
                              label: _endDate == null
                                  ? "បញ្ជប់"
                                  : DateFormat('dd/MM hh:mm a').format(
                                      DateTime(
                                        _endDate!.year,
                                        _endDate!.month,
                                        _endDate!.day,
                                        _endTime?.hour ?? 0,
                                        _endTime?.minute ?? 0,
                                      ),
                                    ),
                              onTap: () async {
                                final date = await showDatePicker(
                                  context: context,
                                  initialDate: _startDate ?? DateTime.now(),
                                  firstDate: DateTime.now().subtract(
                                    const Duration(days: 365),
                                  ),
                                  lastDate: DateTime.now().add(
                                    const Duration(days: 365),
                                  ),
                                );
                                if (date != null && context.mounted) {
                                  setModalState(() => _endDate = date);
                                  final time = await showTimePicker(
                                    context: context,
                                    initialTime: TimeOfDay.now(),
                                  );
                                  if (time != null) {
                                    setModalState(() => _endTime = time);
                                  }
                                }
                              },
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 15),

                      Row(
                        children: [
                          Expanded(
                            child: _buildModalActionButton(
                              icon: Icons.category_rounded,
                              label: _selectedCategory,
                              onTap: () {
                                _showCategoryPicker(context, (cat) {
                                  setModalState(() => _selectedCategory = cat);
                                });
                              },
                            ),
                          ),
                          const SizedBox(width: 10),
                          const Spacer(), // Placeholder for layout balance
                        ],
                      ),
                      const SizedBox(height: 15),

                      // Image Selection
                      GestureDetector(
                        onTap: () async {
                          final XFile? image = await _picker.pickImage(
                            source: ImageSource.gallery,
                            imageQuality: 50,
                          );
                          if (image != null) {
                            setModalState(
                              () => _selectedImage = File(image.path),
                            );
                          }
                        },
                        child: Container(
                          height: 100,
                          width: double.infinity,
                          decoration: BoxDecoration(
                            color: Colors.white.withValues(alpha: 0.05),
                            borderRadius: BorderRadius.circular(16),
                            border: Border.all(
                              color: Colors.white.withValues(alpha: 0.1),
                            ),
                          ),
                          child: _selectedImage != null
                              ? ClipRRect(
                                  borderRadius: BorderRadius.circular(15),
                                  child: Image.file(
                                    _selectedImage!,
                                    fit: BoxFit.cover,
                                  ),
                                )
                              : Column(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Icon(
                                      Icons.add_photo_alternate_rounded,
                                      color: Colors.white.withValues(
                                        alpha: 0.3,
                                      ),
                                    ),
                                    const SizedBox(height: 5),
                                    Text(
                                      "បន្ថែមរូបភាព",
                                      style: GoogleFonts.kantumruyPro(
                                        color: Colors.white24,
                                        fontSize: 12,
                                      ),
                                    ),
                                  ],
                                ),
                        ),
                      ),

                      const SizedBox(height: 24),
                      SizedBox(
                        width: double.infinity,
                        height: 55,
                        child: ElevatedButton(
                          onPressed: _addTask,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: AppTheme.primary,
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(16),
                            ),
                            elevation: 0,
                          ),
                          child: Text(
                            "រក្សាទុក",
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                            ),
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
      ),
    );
  }

  Widget _buildModalActionButton({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
        decoration: BoxDecoration(
          color: Colors.white.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: Colors.white10),
        ),
        child: Row(
          children: [
            Icon(icon, size: 18, color: AppTheme.primary),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                label,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white70,
                  fontSize: 13,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showCategoryPicker(BuildContext context, Function(String) onSelected) {
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.bgCard,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) => Column(
        mainAxisSize: MainAxisSize.min,
        children: _categories
            .map(
              (cat) => ListTile(
                title: Text(
                  cat,
                  style: GoogleFonts.kantumruyPro(color: Colors.white),
                ),
                onTap: () {
                  onSelected(cat);
                  Navigator.pop(context);
                },
              ),
            )
            .toList(),
      ),
    );
  }

  void _showEditDialog(dynamic item) {
    // Basic edit same as before but could be enhanced later if requested
    final TextEditingController editController = TextEditingController(
      text: item['task'],
    );
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        title: Text(
          "កែសម្រួលការងារ",
          style: GoogleFonts.kantumruyPro(
            color: Colors.white,
            fontSize: 18,
            fontWeight: FontWeight.bold,
          ),
        ),
        content: TextField(
          controller: editController,
          autofocus: true,
          style: GoogleFonts.kantumruyPro(color: Colors.white),
          decoration: InputDecoration(
            hintText: "បញ្ចូលការងារថ្មី...",
            hintStyle: GoogleFonts.kantumruyPro(color: Colors.white24),
            enabledBorder: const UnderlineInputBorder(
              borderSide: BorderSide(color: Colors.white10),
            ),
            focusedBorder: UnderlineInputBorder(
              borderSide: BorderSide(color: AppTheme.primary),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(
              "បោះបង់",
              style: GoogleFonts.kantumruyPro(color: Colors.white38),
            ),
          ),
          ElevatedButton(
            onPressed: () {
              if (editController.text.trim().isNotEmpty) {
                final navigator = Navigator.of(context);
                _api
                    .editChecklistItem(item['id'], editController.text.trim())
                    .then((_) {
                      if (!mounted) return;
                      _loadData();
                      navigator.pop();
                    });
              }
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.primary,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            child: Text(
              "រក្សាទុក",
              style: GoogleFonts.kantumruyPro(color: Colors.white),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    int total = _items.length;
    int done = _items
        .where((it) => it['is_done'] == 1 || it['is_done'] == '1')
        .length;
    double progress = total == 0 ? 0 : done / total;

    return Container(
      color: AppTheme.bgSurface,
      child: Stack(
        children: [
          Positioned(
            top: -100,
            right: -50,
            child: Container(
              width: 300,
              height: 300,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: AppTheme.primary.withValues(alpha: 0.1),
              ),
            ),
          ),
          Scaffold(
            backgroundColor: Colors.transparent,
            appBar: AppBar(
              backgroundColor: Colors.transparent,
              elevation: 0,
              leading: IconButton(
                icon: const Icon(
                  Icons.arrow_back_ios_new_rounded,
                  color: Colors.white,
                  size: 20,
                ),
                onPressed: () => Navigator.pop(context),
              ),
              title: Text(
                "បញ្ជីការងារ",
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 22,
                ),
              ),
              centerTitle: true,
              actions: [
                IconButton(
                  icon: const Icon(
                    Icons.notifications_none_rounded,
                    color: Colors.white24,
                  ),
                  onPressed: _checkDeadlines,
                ),
              ],
            ),
            body: Column(
              children: [
                _buildProgressHeader(done, total, progress),
                Expanded(
                  child: _isLoading
                      ? _buildShimmerList()
                      : RefreshIndicator(
                          onRefresh: _loadData,
                          color: AppTheme.primary,
                          backgroundColor: AppTheme.bgCard,
                          child: _items.isEmpty
                              ? _buildEmptyState()
                              : _buildTaskList(),
                        ),
                ),
                _buildBottomReminder(done, total),
              ],
            ),
            floatingActionButton: FloatingActionButton(
              onPressed: _showAddBottomSheet,
              backgroundColor: AppTheme.primary,
              elevation: 4,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(18),
              ),
              child: const Icon(
                Icons.add_rounded,
                size: 32,
                color: Colors.white,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBottomReminder(int done, int total) {
    if (total == 0) return const SizedBox.shrink();

    final int remaining = total - done;
    final int urgent = _items.where((it) {
      if (it['is_done'] == 1 || it['is_done'] == '1') return false;
      if (it['end_date'] == null || it['end_date'].toString().isEmpty) {
        return false;
      }
      try {
        final due = DateTime.parse(it['end_date']);
        return due.difference(DateTime.now()).inDays <= 1;
      } catch (e) {
        return false;
      }
    }).length;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      decoration: BoxDecoration(
        color: AppTheme.bgCard.withValues(alpha: 0.8),
        border: const Border(top: BorderSide(color: Colors.white10)),
      ),
      child: SafeArea(
        top: false,
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: urgent > 0
                    ? AppTheme.warning.withValues(alpha: 0.1)
                    : AppTheme.primary.withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: Icon(
                urgent > 0
                    ? Icons.notification_important_rounded
                    : Icons.info_outline_rounded,
                size: 18,
                color: urgent > 0 ? AppTheme.warning : AppTheme.primary,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    urgent > 0
                        ? "អ្នកមានការងារបន្ទាន់ $urgent"
                        : "អ្នកមានការងារសេសសល់ $remaining",
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  Text(
                    urgent > 0
                        ? "សូមបញ្ចប់ឱ្យបានមុនពេលកំណត់!"
                        : "ព្យាយាមឱ្យអស់ពីសមត្ថភាព!",
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white38,
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),
            if (done == total && total > 0)
              Text(
                "រួចរាល់ទាំងអស់! 🎉",
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.success,
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildProgressHeader(int done, int total, double progress) {
    return Padding(
      padding: EdgeInsets.all(AppResponsive.horizontalPadding(context)),
      child: AppResponsive.maxWidth(
        context: context,
        child: Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: AppTheme.primary,
            borderRadius: BorderRadius.circular(AppTheme.radiusXl),
            boxShadow: AppTheme.primaryShadow,
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        "វឌ្ឍនភាពថ្ងៃនេះ",
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white.withValues(alpha: 0.9),
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        total == 0
                            ? "មិនទាន់មានការងារ"
                            : "$done / $total ការងាររួចរាល់",
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 20,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(alpha: 0.2),
                      shape: BoxShape.circle,
                    ),
                    child: Text(
                      "${(progress * 100).toInt()}%",
                      style: GoogleFonts.inter(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              ClipRRect(
                borderRadius: BorderRadius.circular(10),
                child: LinearProgressIndicator(
                  value: progress,
                  minHeight: 8,
                  backgroundColor: Colors.white.withValues(alpha: 0.1),
                  valueColor: const AlwaysStoppedAnimation<Color>(Colors.white),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildShimmerList() {
    return ListView.builder(
      padding: EdgeInsets.fromLTRB(
        AppResponsive.horizontalPadding(context),
        0,
        AppResponsive.horizontalPadding(context),
        AppResponsive.bottomPadding(context, extra: 110),
      ),
      itemCount: 8,
      itemBuilder: (context, index) => Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: AppShimmer(
          child: Container(
            height: 80,
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
    return AppStateView(
      icon: Icons.assignment_turned_in_outlined,
      title: "មិនទាន់មានការងារនៅឡើយ",
      message: "ចុចប៊ូតុង + ដើម្បីបន្ថែមការងាររបស់អ្នក",
      color: AppTheme.primary,
    );
  }

  Widget _buildTaskList() {
    return AnimationLimiter(
      child: ListView.builder(
        padding: EdgeInsets.fromLTRB(
          AppResponsive.horizontalPadding(context),
          10,
          AppResponsive.horizontalPadding(context),
          AppResponsive.bottomPadding(context, extra: 112),
        ),
        physics: const BouncingScrollPhysics(),
        itemCount: _items.length,
        itemBuilder: (context, index) {
          final item = _items[index];
          return AnimationConfiguration.staggeredList(
            position: index,
            duration: const Duration(milliseconds: 500),
            child: SlideAnimation(
              verticalOffset: 30.0,
              child: FadeInAnimation(
                child: Dismissible(
                  key: Key('task_${item['id']}'),
                  direction: DismissDirection.endToStart,
                  onDismissed: (_) => _deleteTask(item['id']),
                  background: Container(
                    margin: const EdgeInsets.only(bottom: 12),
                    decoration: BoxDecoration(
                      color: Colors.redAccent.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(20),
                    ),
                    alignment: Alignment.centerRight,
                    padding: const EdgeInsets.only(right: 25),
                    child: const Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          Icons.delete_outline_rounded,
                          color: Colors.redAccent,
                          size: 28,
                        ),
                        SizedBox(height: 4),
                        Text(
                          "លុប",
                          style: TextStyle(
                            color: Colors.redAccent,
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                  child: _buildTaskItem(item),
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _buildTaskItem(dynamic item) {
    final bool isDone = (item['is_done'] == 1 || item['is_done'] == '1');
    final String? imgUrl = item['image_url'];
    final String? startDateStr = item['start_date'];
    final String? startTimeStr = item['start_time'];
    final String? endDateStr = item['end_date'];
    final String? endTimeStr = item['end_time'];

    String formatToAmPm(String? dateStr, String? timeStr) {
      if (dateStr == null || dateStr.isEmpty) return "";
      try {
        DateTime dt = DateTime.parse(dateStr);
        if (timeStr != null && timeStr.isNotEmpty) {
          final parts = timeStr.split(':');
          dt = DateTime(
            dt.year,
            dt.month,
            dt.day,
            int.parse(parts[0]),
            int.parse(parts[1]),
          );
          return DateFormat('dd/MM/yy hh:mm a').format(dt);
        }
        return DateFormat('dd/MM/yy').format(dt);
      } catch (e) {
        return dateStr;
      }
    }

    String dateRange = "";
    final String startFmt = formatToAmPm(startDateStr, startTimeStr);
    final String endFmt = formatToAmPm(endDateStr, endTimeStr);

    if (startFmt.isNotEmpty) dateRange = startFmt;
    if (endFmt.isNotEmpty) {
      if (dateRange.isNotEmpty) dateRange += " - ";
      dateRange += endFmt;
    }
    bool isUrgent = false;
    if (!isDone && endDateStr != null && endDateStr.isNotEmpty) {
      try {
        final due = DateTime.parse(endDateStr);
        isUrgent = due.difference(DateTime.now()).inDays <= 1;
      } catch (e) {
        // Silently handle invalid date formats for urgency check
      }
    }

    return GestureDetector(
      onLongPress: () => _showEditDialog(item),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 300),
        margin: const EdgeInsets.only(bottom: 12),
        decoration: BoxDecoration(
          color: isDone
              ? Colors.white.withValues(alpha: 0.02)
              : AppTheme.bgCard,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: isUrgent
                ? AppTheme.warning.withValues(alpha: 0.3)
                : (isDone
                      ? Colors.white.withValues(alpha: 0.02)
                      : Colors.white.withValues(alpha: 0.05)),
            width: isUrgent ? 1.5 : 1,
          ),
          boxShadow: isDone
              ? []
              : [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.1),
                    blurRadius: 10,
                    offset: const Offset(0, 4),
                  ),
                ],
        ),
        child: Column(
          children: [
            if (imgUrl != null && imgUrl.isNotEmpty)
              ClipRRect(
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(20),
                ),
                child: CachedNetworkImage(
                  imageUrl: imgUrl,
                  height: 120,
                  width: double.infinity,
                  fit: BoxFit.cover,
                  placeholder: (c, url) => Container(
                    color: Colors.white.withValues(alpha: 0.05),
                    alignment: Alignment.center,
                    child: const CircularProgressIndicator(),
                  ),
                  errorWidget: (c, url, e) => const SizedBox.shrink(),
                ),
              ),
            ListTile(
              contentPadding: const EdgeInsets.symmetric(
                horizontal: 16,
                vertical: 8,
              ),
              leading: GestureDetector(
                onTap: () => _toggleTask(item['id'], isDone),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 200),
                  width: 28,
                  height: 28,
                  decoration: BoxDecoration(
                    color: isDone ? AppTheme.success : Colors.transparent,
                    shape: BoxShape.circle,
                    border: Border.all(
                      color: isDone ? AppTheme.success : Colors.white24,
                      width: 2,
                    ),
                  ),
                  child: isDone
                      ? const Icon(
                          Icons.check_rounded,
                          color: Colors.white,
                          size: 18,
                        )
                      : null,
                ),
              ),
              title: Text(
                item['task'] ?? '',
                style: GoogleFonts.kantumruyPro(
                  color: isDone
                      ? Colors.white.withValues(alpha: 0.2)
                      : Colors.white,
                  decoration: isDone ? TextDecoration.lineThrough : null,
                  fontSize: 16,
                  fontWeight: isDone ? FontWeight.normal : FontWeight.w500,
                ),
              ),
              subtitle: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 2,
                        ),
                        decoration: BoxDecoration(
                          color: AppTheme.primary.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(
                          item['category'] ?? 'General',
                          style: GoogleFonts.inter(
                            color: AppTheme.primary,
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                      if (dateRange.isNotEmpty) ...[
                        const SizedBox(width: 10),
                        Icon(
                          Icons.calendar_today_rounded,
                          size: 10,
                          color: isUrgent ? AppTheme.warning : Colors.white24,
                        ),
                        const SizedBox(width: 4),
                        Flexible(
                          child: Text(
                            dateRange,
                            style: GoogleFonts.inter(
                              color: isUrgent
                                  ? AppTheme.warning
                                  : (isDone ? Colors.white10 : Colors.white24),
                              fontSize: 11,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
              trailing: IconButton(
                icon: Icon(
                  Icons.more_vert_rounded,
                  color: Colors.white.withValues(alpha: 0.2),
                ),
                onPressed: () => _showEditDialog(item),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
