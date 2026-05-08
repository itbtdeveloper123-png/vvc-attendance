import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:http/http.dart' as http;
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import 'package:vvc_hrm/utils/app_theme.dart';
import 'package:vvc_hrm/providers/user_provider.dart';
import 'package:vvc_hrm/widgets/app_widgets.dart';
import 'package:provider/provider.dart';
import 'dart:ui' as ui;
import 'package:flutter/rendering.dart';
import 'package:pasteboard/pasteboard.dart';

class EmployeeReportScreen extends StatefulWidget {
  const EmployeeReportScreen({super.key});

  @override
  State<EmployeeReportScreen> createState() => _EmployeeReportScreenState();
}

class _EmployeeReportScreenState extends State<EmployeeReportScreen> {
  DateTime _selectedDate = DateTime.now();
  String _store = 'ks2';
  bool _isLoading = false;
  final GlobalKey _previewKey = GlobalKey();
  // Data State
  Map<String, dynamic> _attendanceData = {};
  List<dynamic> _staffList = [];

  @override
  void initState() {
    super.initState();
    Future.microtask(() => _initializeData());
  }

  void _initializeData() {
    final user = Provider.of<UserProvider>(context, listen: false);
    String detectedStore = 'ks2';
    final myId = (user.employeeId ?? '').trim();
    final id318 = (user.settings['employee_report_ids_318'] ?? '').toString();
    final idKS2 = (user.settings['employee_report_ids_ks2'] ?? '').toString();
    final idNR3 = (user.settings['employee_report_ids_nr3'] ?? '').toString();

    if (id318.split(',').map((e) => e.trim()).contains(myId)) {
      detectedStore = '318';
    } else if (idKS2.split(',').map((e) => e.trim()).contains(myId)) {
      detectedStore = 'ks2';
    } else if (idNR3.split(',').map((e) => e.trim()).contains(myId)) {
      detectedStore = 'nr3';
    } else {
      final pos = (user.position ?? '').toLowerCase();
      if (pos.contains('nr3')) {
        detectedStore = 'nr3';
      } else if (pos.contains('318')) {
        detectedStore = '318';
      }
    }

    setState(() {
      _store = detectedStore;
    });
    _fetchReportData();
  }

  Future<void> _fetchReportData() async {
    setState(() => _isLoading = true);
    try {
      final dateStr = DateFormat('yyyy-MM-dd').format(_selectedDate);
      final response = await http.post(
        Uri.parse('https://app.vvc.asia/flutter/public_report.php'),
        body: {
          'ajax_action': 'get_report_data_json',
          'store': _store,
          'date': dateStr,
        },
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (data['success'] == true) {
          setState(() {
            _attendanceData = data['attendance'] ?? {};
            _staffList = data['staff'] ?? [];
            _isLoading = false;
          });
          return;
        }
      }

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('មិនអាចទាញយកទិន្នន័យបានទេ (API មិនទាន់មាន)'),
          ),
        );
      }
    } catch (e) {
      debugPrint('Error fetching report: $e');
    }
    setState(() => _isLoading = false);
  }

  @override
  Widget build(BuildContext context) {
    return DynamicAppBarWrapper(
      title: 'របាយការណ៍វត្តមាន ($_store)',
      actions: [
        IconButton(
          icon: const Icon(Icons.refresh),
          onPressed: _fetchReportData,
        ),
        IconButton(
          icon: const Icon(Icons.copy_all),
          onPressed: _generateAndCopyReport,
          tooltip: 'ចម្លងរបាយការណ៍',
        ),
      ],
      body: Stack(
        children: [
          AppBackgroundShell(
            child: _isLoading
                ? const Center(child: CircularProgressIndicator())
                : AnimationLimiter(
                    child: SingleChildScrollView(
                      physics: const BouncingScrollPhysics(),
                      padding: const EdgeInsets.fromLTRB(16, 110, 16, 100),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: AnimationConfiguration.toStaggeredList(
                          duration: const Duration(milliseconds: 500),
                          childAnimationBuilder: (widget) => SlideAnimation(
                            horizontalOffset: 50.0,
                            child: FadeInAnimation(child: widget),
                          ),
                          children: [
                            _buildDatePicker(),
                            const SizedBox(height: 20),
                            _buildAttendanceForm(),
                            const SizedBox(height: 30),
                            _buildStaffListSection(),
                          ],
                        ),
                      ),
                    ),
                  ),
          ),
          Positioned(
            bottom: 20,
            right: 20,
            child: FloatingActionButton.extended(
              onPressed: _takePictureOfReport,
              label: const Text('ថតរូបតារាង'),
              icon: const Icon(Icons.camera_alt),
              backgroundColor: Colors.orangeAccent,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDatePicker() {
    return Card(
      elevation: 2,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: ListTile(
        leading: Icon(Icons.calendar_today, color: AppTheme.primary),
        title: Text(
          DateFormat('dd-MM-yyyy').format(_selectedDate),
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        subtitle: const Text('ជ្រើសរើសថ្ងៃ'),
        trailing: const Icon(Icons.arrow_forward_ios, size: 16),
        onTap: () async {
          final picked = await showDatePicker(
            context: context,
            initialDate: _selectedDate,
            firstDate: DateTime(2020),
            lastDate: DateTime.now().add(const Duration(days: 365)),
          );
          if (picked != null && picked != _selectedDate) {
            setState(() => _selectedDate = picked);
            _fetchReportData();
          }
        },
      ),
    );
  }

  Widget _buildAttendanceForm() {
    final Map<String, String> departments = _getDepartmentsForStore();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'ចំនួនបុគ្គលិកតាមផ្នែក',
          style: GoogleFonts.kantumruyPro(
            fontSize: 18,
            fontWeight: FontWeight.bold,
          ),
        ),
        const SizedBox(height: 10),
        ...departments.entries.map(
          (entry) => _buildDeptCard(entry.key, entry.value),
        ),
      ],
    );
  }

  Map<String, String> _getDepartmentsForStore() {
    if (_store == 'ks2') {
      return {
        'cosmetic': 'ហាងគ្រឿងក្រអូប',
        'stock': 'ផ្នែកស្តុក',
        'sales': 'ផ្នែកលក់',
        'cashier': 'ផ្នែកគិតលុយ',
        'delivery': 'ផ្នែកដឹកជញ្ជូន',
      };
    } else if (_store == 'nr3') {
      return {
        'store': 'បុគ្គលិក NR3',
        'intern': 'បុគ្គលិកកម្មសិក្សា',
        'stock': 'ផ្នែកស្តុក',
        'sales': 'ផ្នែកលក់',
        'cashier': 'ផ្នែកគិតលុយ',
      };
    } else {
      return {
        'store': 'បុគ្គលិកហាងទំនិញ៣១៨',
        'intern': 'បុគ្គលិកកម្មករ',
        'stock': 'ផ្នែកស្តុក',
        'sales': 'ផ្នែកលក់',
        'cashier': 'ផ្នែកគិតលុយ',
      };
    }
  }

  Widget _buildDeptCard(String key, String label) {
    bool isKS2 = _store == 'ks2';
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                fontWeight: FontWeight.bold,
                color: AppTheme.primary,
              ),
            ),
            const Divider(),
            if (isKS2) ...[
              _buildShiftInputs(key, 'morning', 'វេនព្រឹក'),
              const SizedBox(height: 10),
              _buildShiftInputs(key, 'evening', 'វេនល្ងាច'),
            ] else ...[
              _buildSimpleInputs(key),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildShiftInputs(String dept, String shift, String label) {
    return Row(
      children: [
        SizedBox(
          width: 80,
          child: Text(label, style: GoogleFonts.kantumruyPro(fontSize: 12)),
        ),
        Expanded(child: _buildNumberInput('${dept}_female_$shift', 'ស្រី')),
        const SizedBox(width: 10),
        Expanded(child: _buildNumberInput('${dept}_male_$shift', 'ប្រុស')),
      ],
    );
  }

  Widget _buildSimpleInputs(String dept) {
    return Row(
      children: [
        Expanded(child: _buildNumberInput('${dept}_female', 'ស្រី')),
        const SizedBox(width: 10),
        Expanded(child: _buildNumberInput('${dept}_male', 'ប្រុស')),
      ],
    );
  }

  Widget _buildNumberInput(String col, String label) {
    final val = _attendanceData[col]?.toString() ?? '0';
    final controller = TextEditingController(text: val)
      ..selection = TextSelection.collapsed(offset: val.length);

    return Focus(
      onFocusChange: (hasFocus) {
        if (!hasFocus) {
          _updateAttendance(col, controller.text);
        }
      },
      child: TextField(
        controller: controller,
        keyboardType: TextInputType.number,
        style: GoogleFonts.notoSansKhmer(fontSize: 16),
        decoration: InputDecoration(
          labelText: label,
          labelStyle: const TextStyle(fontSize: 12),
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
          contentPadding: const EdgeInsets.symmetric(
            horizontal: 10,
            vertical: 8,
          ),
          filled: true,
          fillColor: Colors.grey.withValues(alpha: 0.05),
        ),
        onSubmitted: (newVal) => _updateAttendance(col, newVal),
      ),
    );
  }

  Future<void> _updateAttendance(String col, String val) async {
    final intValue = int.tryParse(val) ?? 0;

    // Safely compare even if it's a string from the API
    final currentVal =
        int.tryParse(_attendanceData[col]?.toString() ?? '0') ?? 0;
    if (currentVal == intValue) return;

    // Optimistic Update
    setState(() {
      _attendanceData[col] = intValue;
    });

    try {
      final response = await http.post(
        Uri.parse('https://app.vvc.asia/flutter/public_report.php'),
        body: {
          'ajax_action': 'update_single_attendance',
          'store': _store,
          'date': DateFormat('yyyy-MM-dd').format(_selectedDate),
          'column': col,
          'value': intValue.toString(),
        },
      );
      if (response.statusCode == 200) {
        final res = json.decode(response.body);
        if (res['success'] == true) {
          // Success
          return;
        } else {
          _showError('រក្សាទុកមិនបានសម្រេច: ${res['message']}');
        }
      }
    } catch (e) {
      debugPrint('Error updating attendance: $e');
      _showError('មានបញ្ហាក្នុងការរក្សាទុក');
    }
  }

  void _showError(String msg) {
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(msg), backgroundColor: Colors.redAccent),
      );
    }
  }

  Widget _buildStaffListSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              'បុគ្គលិកសុំច្បាប់/ដេអូស',
              style: GoogleFonts.kantumruyPro(
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
            IconButton(
              icon: const Icon(Icons.add_circle, color: Colors.green),
              onPressed: _addNewStaffRow,
            ),
          ],
        ),
        const SizedBox(height: 10),
        if (_staffList.isEmpty)
          const Center(child: Text('មិនមានទិន្នន័យ'))
        else
          ..._staffList.map((staff) => _buildStaffCard(staff)),
      ],
    );
  }

  Widget _buildStaffCard(dynamic staff) {
    final String name = (staff['name'] ?? '').toString();
    final String role = (staff['role'] ?? '').toString();
    final String number = (staff['number'] ?? '').toString();
    final String note = (staff['note'] ?? '').toString();

    bool isEmpty = name.isEmpty && role.isEmpty && note.isEmpty;

    return Card(
      elevation: 1,
      margin: const EdgeInsets.only(bottom: 12),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        title: isEmpty
            ? Text(
                'ចុចដើម្បីបញ្ចូលព័ត៌មាន...',
                style: GoogleFonts.notoSansKhmer(
                  color: Colors.grey,
                  fontSize: 14,
                  fontStyle: FontStyle.italic,
                ),
              )
            : Text(
                '$number. $name${role.isNotEmpty ? ' ($role)' : ''}',
                style: GoogleFonts.notoSansKhmer(
                  fontWeight: FontWeight.bold,
                  fontSize: 16,
                ),
              ),
        subtitle: !isEmpty && note.isNotEmpty
            ? Text(note, maxLines: 2, overflow: TextOverflow.ellipsis)
            : null,
        trailing: IconButton(
          icon: const Icon(Icons.delete_outline, color: Colors.redAccent),
          onPressed: () => _deleteStaffRow(staff['id']),
        ),
        onTap: () => _editStaffRow(staff),
      ),
    );
  }

  Future<void> _addNewStaffRow() async {
    try {
      final response = await http.post(
        Uri.parse('https://app.vvc.asia/flutter/public_report.php'),
        body: {
          'ajax_action': 'create_leave_deo_row',
          'store': _store,
          'date': DateFormat('yyyy-MM-dd').format(_selectedDate),
        },
      );
      if (response.statusCode == 200) {
        final res = json.decode(response.body);
        if (res['success'] == true) {
          _fetchReportData();
        }
      }
    } catch (e) {
      debugPrint('Error adding row: $e');
    }
  }

  Future<void> _deleteStaffRow(dynamic id) async {
    bool? confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        title: Text(
          'លុបទិន្នន័យ',
          style: GoogleFonts.notoSansKhmer(color: Colors.white),
        ),
        content: Text(
          'តើអ្នកពិតជាចង់លុបទិន្នន័យនេះមែនទេ?',
          style: GoogleFonts.notoSansKhmer(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('ទេ', style: TextStyle(color: Colors.grey)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text(
              'បាទ/ចាស',
              style: TextStyle(color: Colors.redAccent),
            ),
          ),
        ],
      ),
    );
    if (confirm != true) return;
    if (!mounted) return;

    setState(() => _isLoading = true);
    final messenger = ScaffoldMessenger.of(context);
    try {
      final response = await http.post(
        Uri.parse('https://app.vvc.asia/flutter/public_report.php'),
        body: {
          'ajax_action': 'delete_leave_deo_ajax',
          'store': _store,
          'id': id.toString(),
        },
      );
      if (response.statusCode == 200) {
        final res = json.decode(response.body);
        if (res['success'] == true) {
          if (!mounted) return;
          messenger.showSnackBar(
            const SnackBar(content: Text('បានលុបទិន្នន័យរួចរាល់')),
          );
          _fetchReportData();
          return;
        }
      }
      if (!mounted) return;
      _showError('មិនអាចលុបទិន្នន័យបានទេ');
    } catch (e) {
      debugPrint('Error deleting row: $e');
      if (!mounted) return;
      _showError('មានបញ្ហាបច្ចេកទេសក្នុងការលុប');
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  void _editStaffRow(dynamic staff) {
    final numCtrl = TextEditingController(
      text: staff['number']?.toString() ?? '',
    );
    final nameCtrl = TextEditingController(
      text: staff['name']?.toString() ?? '',
    );
    final roleCtrl = TextEditingController(
      text: staff['role']?.toString() ?? '',
    );
    final noteCtrl = TextEditingController(
      text: staff['note']?.toString() ?? '',
    );

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => Container(
        padding: EdgeInsets.only(
          bottom: MediaQuery.of(ctx).viewInsets.bottom,
          left: 24,
          right: 24,
          top: 24,
        ),
        decoration: const BoxDecoration(
          color: Color(0xFF0F172A), // Use dark background matching the app
          borderRadius: BorderRadius.vertical(top: Radius.circular(25)),
        ),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'កែសម្រួលព័ត៌មាន',
                    style: GoogleFonts.notoSansKhmer(
                      fontWeight: FontWeight.bold,
                      fontSize: 18,
                      color: Colors.white,
                    ),
                  ),
                  IconButton(
                    onPressed: () => Navigator.pop(ctx),
                    icon: const Icon(Icons.close, color: Colors.white),
                  ),
                ],
              ),
              const SizedBox(height: 20),
              _buildEditTextField(numCtrl, 'ល.រ (ឧ: ១)'),
              const SizedBox(height: 16),
              _buildEditTextField(nameCtrl, 'ឈ្មោះបុគ្គលិក'),
              const SizedBox(height: 16),
              _buildEditTextField(roleCtrl, 'តួនាទី (ឧ: អ្នកលក់)'),
              const SizedBox(height: 16),
              _buildEditTextField(
                noteCtrl,
                'អធិប្បាយ (ឧ: សុំច្បាប់ ៣ថ្ងៃ)',
                maxLines: 3,
              ),
              const SizedBox(height: 30),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.blueAccent,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                    elevation: 5,
                  ),
                  onPressed: () async {
                    setState(() => _isLoading = true);
                    await Future.wait([
                      _updateStaffField(staff['id'], 'number', numCtrl.text),
                      _updateStaffField(staff['id'], 'name', nameCtrl.text),
                      _updateStaffField(staff['id'], 'role', roleCtrl.text),
                      _updateStaffField(staff['id'], 'note', noteCtrl.text),
                    ]);
                    _fetchReportData();
                    if (mounted) {
                      Navigator.pop(context);
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('បានរក្សាទុកព័ត៌មាន')),
                      );
                    }
                  },
                  child: Text(
                    'រក្សាទុកទិន្នន័យ',
                    style: GoogleFonts.notoSansKhmer(
                      fontWeight: FontWeight.bold,
                      fontSize: 16,
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 40),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildEditTextField(
    TextEditingController ctrl,
    String label, {
    int maxLines = 1,
  }) {
    return TextField(
      controller: ctrl,
      maxLines: maxLines,
      style: const TextStyle(color: Colors.white),
      decoration: InputDecoration(
        labelText: label,
        labelStyle: const TextStyle(color: Colors.blueAccent),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: BorderSide(
            color: Colors.blueAccent.withValues(alpha: 0.3),
          ),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: Colors.blueAccent),
        ),
        filled: true,
        fillColor: Colors.white.withValues(alpha: 0.05),
        contentPadding: const EdgeInsets.all(16),
      ),
    );
  }

  Future<bool> _updateStaffField(dynamic id, String col, String val) async {
    try {
      final response = await http.post(
        Uri.parse('https://app.vvc.asia/flutter/public_report.php'),
        body: {
          'ajax_action': 'update_leave_deo_inline',
          'store': _store,
          'id': id.toString(),
          'column': col,
          'value': val,
        },
      );
      if (response.statusCode == 200) {
        final res = json.decode(response.body);
        return res['success'] == true;
      }
    } catch (e) {
      debugPrint('Error updating staff field: $e');
    }
    return false;
  }

  void _generateAndCopyReport() {
    StringBuffer sb = StringBuffer();
    sb.writeln('📋 របាយការណ៍វត្តមានបុគ្គលិក - $_store');
    sb.writeln('📅 ថ្ងៃទី: ${DateFormat('dd-MM-yyyy').format(_selectedDate)}');
    sb.writeln('--------------------------');
    final deps = _getDepartmentsForStore();
    deps.forEach((key, label) {
      sb.writeln('📍 $label:');
      if (_store == 'ks2') {
        int fm =
            int.tryParse(
              _attendanceData['${key}_female_morning']?.toString() ?? '0',
            ) ??
            0;
        int mm =
            int.tryParse(
              _attendanceData['${key}_male_morning']?.toString() ?? '0',
            ) ??
            0;
        int fe =
            int.tryParse(
              _attendanceData['${key}_female_evening']?.toString() ?? '0',
            ) ??
            0;
        int me =
            int.tryParse(
              _attendanceData['${key}_male_evening']?.toString() ?? '0',
            ) ??
            0;
        sb.writeln('  - ព្រឹក: ស្រី $fm, ប្រុស $mm');
        sb.writeln('  - ល្ងាច: ស្រី $fe, ប្រុស $me');
      } else {
        int f =
            int.tryParse(_attendanceData['${key}_female']?.toString() ?? '0') ??
            0;
        int m =
            int.tryParse(_attendanceData['${key}_male']?.toString() ?? '0') ??
            0;
        sb.writeln('  - ស្រី $f, ប្រុស $m');
      }
    });
    if (_staffList.isNotEmpty) {
      sb.writeln('\n📝 បុគ្គលិកសុំច្បាប់/ដេអូស:');
      for (var s in _staffList) {
        sb.writeln('${s['number']}. ${s['name']} (${s['role']}): ${s['note']}');
      }
    }

    Clipboard.setData(ClipboardData(text: sb.toString()));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('បានចម្លងរបាយការណ៍! (ស្ទីលអត្ថបទ)')),
    );
  }

  void _takePictureOfReport() {
    showDialog(
      context: context,
      builder: (ctx) => Dialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        insetPadding: const EdgeInsets.all(20),
        child: Container(
          width: double.maxFinite,
          padding: const EdgeInsets.all(16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Expanded(
                child: InteractiveViewer(
                  constrained: false,
                  child: RepaintBoundary(
                    key: _previewKey,
                    child: Container(
                      color: Colors.white,
                      padding: const EdgeInsets.all(24),
                      width: 800, // Fixed width for A4-like preview
                      child: _buildPrintableContent(),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: () => Navigator.pop(ctx),
                    child: const Text(
                      'បិទ',
                      style: TextStyle(color: Colors.grey),
                    ),
                  ),
                  const SizedBox(width: 12),
                  ElevatedButton.icon(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.blueAccent,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                    onPressed: () async {
                      try {
                        RenderRepaintBoundary? boundary =
                            _previewKey.currentContext?.findRenderObject()
                                as RenderRepaintBoundary?;
                        if (boundary == null) return;
                        ui.Image image = await boundary.toImage(
                          pixelRatio: 3.0,
                        );
                        ByteData? byteData = await image.toByteData(
                          format: ui.ImageByteFormat.png,
                        );
                        if (byteData != null) {
                          final Uint8List pngBytes = byteData.buffer
                              .asUint8List();
                          await Pasteboard.writeImage(pngBytes);
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text(
                                  'បានចម្លងរូបភាពតារាងរួចរាល់ អាចយកទៅ Paste ប្រើប្រាស់បាន',
                                ),
                              ),
                            );
                          }
                        }
                      } catch (e) {
                        debugPrint('Error capturing table image: $e');
                        if (mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(
                              content: Text('មិនអាចចម្លងរូបភាពបានទេ: $e'),
                            ),
                          );
                        }
                      }
                    },
                    icon: const Icon(Icons.copy, color: Colors.white),
                    label: const Text(
                      'ចម្លងរូបភាព',
                      style: TextStyle(color: Colors.white),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPrintableContent() {
    final titleStyle = GoogleFonts.kantumruyPro(
      color: const Color(0xFF1E3A8A),
      fontSize: 20,
      fontWeight: FontWeight.bold,
    );
    final dateStyle = GoogleFonts.kantumruyPro(
      color: const Color(0xFF1E3A8A),
      fontSize: 14,
    );
    final headingStyle = GoogleFonts.kantumruyPro(
      color: const Color(0xFF1E3A8A),
      fontSize: 16,
      fontWeight: FontWeight.bold,
    );
    final thStyle = GoogleFonts.kantumruyPro(
      color: Colors.white,
      fontSize: 13,
      fontWeight: FontWeight.bold,
    );
    final tdStyle = GoogleFonts.kantumruyPro(
      color: Colors.black87,
      fontSize: 13,
    );
    final tdBoldStyle = GoogleFonts.kantumruyPro(
      color: Colors.black,
      fontSize: 13,
      fontWeight: FontWeight.bold,
    );

    final deps = _getDepartmentsForStore();
    final columnsCount = deps.length + 2;

    String storeName = _store;
    if (_store == 'ks2') storeName = 'ហាងគ្រឿងក្រអូប (KS2)';
    if (_store == 'nr3') storeName = 'NR3';

    // Main Table
    final tableHeader = TableRow(
      decoration: const BoxDecoration(color: Color(0xFF0F172A)),
      children: [
        _buildTh('ព័ត៌មាន', thStyle),
        ...deps.values.map((v) => _buildTh(v, thStyle)),
        _buildTh('សរុប', thStyle),
      ],
    );

    List<TableRow> rows = [tableHeader];

    if (_store == 'ks2') {
      rows.add(
        _buildKs2Row(
          'វេនព្រឹក',
          'ស្រី',
          'morning',
          'female',
          tdStyle,
          isFirstGrp: true,
        ),
      );
      rows.add(_buildKs2Row('', 'ប្រុស', 'morning', 'male', tdStyle));
      rows.add(
        _buildKs2Row(
          '',
          'សរុប (ព្រឹក)',
          'morning',
          'total',
          tdBoldStyle,
          isTotal: true,
        ),
      );

      rows.add(
        _buildKs2Row(
          'វេនល្ងាច',
          'ស្រី',
          'evening',
          'female',
          tdStyle,
          isFirstGrp: true,
        ),
      );
      rows.add(_buildKs2Row('', 'ប្រុស', 'evening', 'male', tdStyle));
      rows.add(
        _buildKs2Row(
          '',
          'សរុប (ល្ងាច)',
          'evening',
          'total',
          tdBoldStyle,
          isTotal: true,
        ),
      );

      rows.add(_buildOverallKs2Row('សរុបរួមតាមផ្នែក', tdBoldStyle));
    } else {
      rows.add(_buildSimpleRow('ស្រី', 'female', tdStyle));
      rows.add(_buildSimpleRow('ប្រុស', 'male', tdStyle));
      rows.add(_buildSimpleRow('សរុប', 'total', tdBoldStyle, isTotal: true));
    }

    // Staff Table
    final staffHeader = TableRow(
      decoration: const BoxDecoration(color: Color(0xFF0F172A)),
      children: [
        _buildTh('ល.រ', thStyle),
        _buildTh('ឈ្មោះ', thStyle),
        _buildTh('តួនាទី', thStyle),
        _buildTh('អធិប្បាយ', thStyle),
        _buildTh('ថ្ងៃរាយការណ៍', thStyle),
      ],
    );

    List<TableRow> staffRows = [staffHeader];
    for (var s in _staffList) {
      staffRows.add(
        TableRow(
          decoration: const BoxDecoration(color: Colors.white),
          children: [
            _buildTd(s['number']?.toString() ?? '', tdStyle),
            _buildTd(
              s['name']?.toString() ?? '',
              tdStyle,
              align: TextAlign.left,
            ),
            _buildTd(
              s['role']?.toString() ?? '',
              tdStyle,
              align: TextAlign.left,
            ),
            _buildTd(
              s['note']?.toString() ?? '',
              tdStyle,
              align: TextAlign.left,
            ),
            _buildTd(DateFormat('yyyy-MM-dd').format(_selectedDate), tdStyle),
          ],
        ),
      );
    }

    if (_staffList.isEmpty) {
      staffRows.add(
        TableRow(
          decoration: const BoxDecoration(color: Colors.white),
          children: List.generate(5, (_) => _buildTd('', tdStyle)),
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        Text('របាយការណ៍វត្តមានបុគ្គលិក - $storeName', style: titleStyle),
        const SizedBox(height: 8),
        Text(
          'ថ្ងៃទី ${DateFormat('dd').format(_selectedDate)} ខែ ${DateFormat('MM').format(_selectedDate)} ឆ្នាំ ${DateFormat('yyyy').format(_selectedDate)}',
          style: dateStyle,
        ),
        const SizedBox(height: 24),
        Text('ចំនួនបុគ្គលិកតាមផ្នែក', style: headingStyle),
        const SizedBox(height: 12),
        Table(
          border: TableBorder.all(color: Colors.grey.shade300, width: 1),
          columnWidths: {
            0: const FlexColumnWidth(1.2),
            for (int i = 1; i < columnsCount - 1; i++)
              i: const FlexColumnWidth(1),
            columnsCount - 1: const FlexColumnWidth(0.8),
          },
          children: rows,
        ),
        const SizedBox(height: 32),
        Text(
          'បុគ្គលិកសុំច្បាប់, ដេអូស, ប្តូរវេនអូស និងចូលថ្មី',
          style: headingStyle,
        ),
        const SizedBox(height: 12),
        Table(
          border: TableBorder.all(color: Colors.grey.shade300, width: 1),
          columnWidths: const {
            0: FlexColumnWidth(0.5),
            1: FlexColumnWidth(2),
            2: FlexColumnWidth(2),
            3: FlexColumnWidth(3),
            4: FlexColumnWidth(1.5),
          },
          children: staffRows,
        ),
      ],
    );
  }

  Widget _buildTh(String text, TextStyle style) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
      child: Text(text, style: style, textAlign: TextAlign.center),
    );
  }

  Widget _buildTd(
    String text,
    TextStyle style, {
    TextAlign align = TextAlign.center,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
      child: Text(text, style: style, textAlign: align),
    );
  }

  int _getVal(String key) =>
      int.tryParse(_attendanceData[key]?.toString() ?? '0') ?? 0;

  TableRow _buildKs2Row(
    String grp,
    String sub,
    String shift,
    String type,
    TextStyle style, {
    bool isFirstGrp = false,
    bool isTotal = false,
  }) {
    final deps = _getDepartmentsForStore().keys.toList();
    Color bgColor = isTotal ? Colors.grey.shade100 : Colors.white;

    int rowTotal = 0;
    List<Widget> cells = [];

    // Group / Sub Layout
    cells.add(
      Container(
        color: bgColor,
        child: Row(
          children: [
            if (grp.isNotEmpty)
              Expanded(
                flex: 1,
                child: Padding(
                  padding: const EdgeInsets.only(left: 8),
                  child: Text(
                    grp,
                    style: style.copyWith(fontWeight: FontWeight.bold),
                  ),
                ),
              ),
            if (grp.isEmpty) const Expanded(flex: 1, child: SizedBox()),
            Expanded(flex: 1, child: Text(sub, style: style)),
          ],
        ),
      ),
    );

    for (var d in deps) {
      int val;
      if (isTotal) {
        val = _getVal('${d}_female_$shift') + _getVal('${d}_male_$shift');
      } else {
        val = _getVal('${d}_${type}_$shift');
      }
      rowTotal += val;
      cells.add(
        Container(color: bgColor, child: _buildTd(val.toString(), style)),
      );
    }

    cells.add(
      Container(
        color: bgColor,
        child: _buildTd(
          rowTotal.toString(),
          style.copyWith(fontWeight: FontWeight.bold),
        ),
      ),
    );

    return TableRow(children: cells);
  }

  TableRow _buildOverallKs2Row(String title, TextStyle style) {
    final deps = _getDepartmentsForStore().keys.toList();
    Color bgColor = Colors.grey.shade200;
    int overallTotal = 0;
    List<Widget> cells = [];

    cells.add(
      Container(
        color: bgColor,
        child: _buildTd(title, style, align: TextAlign.left),
      ),
    );

    for (var d in deps) {
      int val =
          _getVal('${d}_female_morning') +
          _getVal('${d}_male_morning') +
          _getVal('${d}_female_evening') +
          _getVal('${d}_male_evening');
      overallTotal += val;
      cells.add(
        Container(color: bgColor, child: _buildTd(val.toString(), style)),
      );
    }

    cells.add(
      Container(
        color: bgColor,
        child: _buildTd(overallTotal.toString(), style),
      ),
    );
    return TableRow(children: cells);
  }

  TableRow _buildSimpleRow(
    String title,
    String type,
    TextStyle style, {
    bool isTotal = false,
  }) {
    final deps = _getDepartmentsForStore().keys.toList();
    Color bgColor = isTotal ? Colors.grey.shade100 : Colors.white;

    int rowTotal = 0;
    List<Widget> cells = [];
    cells.add(Container(color: bgColor, child: _buildTd(title, style)));

    for (var d in deps) {
      int val;
      if (isTotal) {
        val = _getVal('${d}_female') + _getVal('${d}_male');
      } else {
        val = _getVal('${d}_$type');
      }
      rowTotal += val;
      cells.add(
        Container(color: bgColor, child: _buildTd(val.toString(), style)),
      );
    }

    cells.add(
      Container(
        color: bgColor,
        child: _buildTd(
          rowTotal.toString(),
          style.copyWith(fontWeight: FontWeight.bold),
        ),
      ),
    );

    return TableRow(children: cells);
  }
}
