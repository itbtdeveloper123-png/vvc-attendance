import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import '../widgets/app_widgets.dart';

import 'package:provider/provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../utils/request_form_helpers.dart';
import '../providers/user_provider.dart';
import '../widgets/dept_head_selector.dart';

class LateRequestScreen extends StatefulWidget {
  final Map<String, dynamic>? initialData;
  const LateRequestScreen({super.key, this.initialData});

  @override
  State<LateRequestScreen> createState() => _LateRequestScreenState();
}

class _LateRequestScreenState extends State<LateRequestScreen> {
  final _formKey = GlobalKey<FormState>();
  final _apiService = ApiService();

  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _nameController = TextEditingController();
  final TextEditingController _reasonController = TextEditingController();

  DateTime _selectedDate = DateTime.now();
  TimeOfDay _actualTime = TimeOfDay.now();
  final TextEditingController _branchController = TextEditingController();
  final TextEditingController _positionController = TextEditingController();
  final TextEditingController _departmentController = TextEditingController();
  final TextEditingController _deptHeadController = TextEditingController();
  String? _deptHeadSignature;
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final user = Provider.of<UserProvider>(context, listen: false);
      if (widget.initialData != null) {
        final d = widget.initialData!;
        _nameController.text = d['requester_name'] ?? '';
        _reasonController.text = d['reason'] ?? '';
        _deptHeadController.text = d['department_head_name'] ?? '';
        _deptHeadSignature = d['department_head_signature'];

        if (d['request_date'] != null) {
          try {
            _selectedDate = DateTime.parse(d['request_date'].toString());
          } catch (_) {}
        }
        _actualTime = _parseTime(d['time_in']?.toString());

        applyUserPositionAndDepartment(
          positionController: _positionController,
          departmentController: _departmentController,
          initialData: d,
          user: user,
        );
        applyUserBranch(
          controller: _branchController,
          initialData: d,
          user: user,
        );
        if (mounted) setState(() {});
      } else {
        _nameController.text = user.name ?? '';
        _emailController.text = "${user.employeeId ?? ''}@vvc.com";
        applyUserPositionAndDepartment(
          positionController: _positionController,
          departmentController: _departmentController,
          user: user,
        );
        applyUserBranch(controller: _branchController, user: user);
        if (mounted) setState(() {});
      }
    });
  }

  TimeOfDay _parseTime(String? raw) {
    if (raw == null || raw.isEmpty) {
      return TimeOfDay.now();
    }
    try {
      if (raw.contains('T') || raw.contains('-')) {
        final dt = DateTime.parse(raw);
        return TimeOfDay(hour: dt.hour, minute: dt.minute);
      }
      final parts = raw.split(':');
      if (parts.length >= 2) {
        return TimeOfDay(
          hour: int.parse(parts[0]),
          minute: int.parse(parts[1]),
        );
      }
    } catch (_) {}
    return TimeOfDay.now();
  }

  void _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() => _isLoading = true);

    final formData = {
      'late_date': DateFormat('yyyy-MM-dd').format(_selectedDate),
      'actual_check_in_time':
          "${_actualTime.hour.toString().padLeft(2, '0')}:${_actualTime.minute.toString().padLeft(2, '0')}",
      'time_in':
          "${_actualTime.hour.toString().padLeft(2, '0')}:${_actualTime.minute.toString().padLeft(2, '0')}",
      'late_reason_text': _reasonController.text,
      'reason': _reasonController.text,
      'position': _positionController.text.trim(),
      'department': _departmentController.text.trim(),
      'branch': _branchController.text.trim(),
      'department_head_name': _deptHeadController.text,
      'department_head_signature': _deptHeadSignature,
      'number_of_days': "0",
    };

    final result = widget.initialData != null
        ? await _apiService.updateRequest(
            int.parse(widget.initialData!['id'].toString()),
            formData,
          )
        : await _apiService.submitRequest('Late', formData);
    setState(() => _isLoading = false);

    if (!mounted) return;
    if (result['success'] == true) {
      _showResultPopup(
        result['message'],
        Icons.check_circle_outline_rounded,
        AppTheme.success,
        true,
      );
    } else {
      _showResultPopup(
        result['message'],
        Icons.error_outline_rounded,
        AppTheme.danger,
        false,
      );
    }
  }

  void _showResultPopup(
    String message,
    IconData icon,
    Color color,
    bool isSuccess,
  ) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(24),
          side: BorderSide(color: color.withValues(alpha: 0.3)),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: Icon(icon, color: color, size: 48),
            ),
            const SizedBox(height: 20),
            Text(
              message,
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 24),
            SizedBox(
              width: double.infinity,
              height: 50,
              child: ElevatedButton(
                onPressed: () {
                  Navigator.pop(context);
                  if (isSuccess) Navigator.pop(context);
                },
                style: ElevatedButton.styleFrom(
                  backgroundColor: color,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                child: Text(
                  "យល់ព្រម",
                  style: GoogleFonts.kantumruyPro(
                    fontWeight: FontWeight.bold,
                    color: AppTheme.textPrimary,
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
    return DynamicAppBarWrapper(
      title: "សុំចូលយឺត",
      leading: IconButton(
        icon: const Icon(Icons.arrow_back_ios_new_rounded),
        onPressed: () => Navigator.pop(context),
      ),
      bottomNavigationBar: VvcFrostedBottomBar(
        child: _isLoading
            ? const SizedBox(
                height: 52,
                child: Center(child: CircularProgressIndicator()),
              )
            : Container(
                width: double.infinity,
                height: 52,
                decoration: BoxDecoration(
                  gradient: const LinearGradient(
                    colors: [Color(0xFFF59E0B), Color(0xFFD97706)],
                  ),
                  borderRadius: BorderRadius.circular(16),
                  boxShadow: [
                    BoxShadow(
                      color: const Color(0xFFD97706).withValues(alpha: 0.35),
                      blurRadius: 14,
                      offset: const Offset(0, 6),
                    ),
                  ],
                ),
                child: ElevatedButton(
                  onPressed: _submit,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.transparent,
                    shadowColor: Colors.transparent,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(16),
                    ),
                  ),
                  child: Text(
                    widget.initialData != null
                        ? "រក្សាទុកការកែសម្រួល"
                        : "បញ្ជូនសំណើចូលយឺត",
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                ),
              ),
      ),
      body: AppBackgroundShell(
        child: SingleChildScrollView(
          physics: const BouncingScrollPhysics(),
          padding: const EdgeInsets.fromLTRB(20, 100, 20, 140),
          child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Center(
                      child: Column(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(16),
                            decoration: BoxDecoration(
                              color: AppTheme.accent.withValues(alpha: 0.1),
                              shape: BoxShape.circle,
                              border: Border.all(
                                color: AppTheme.accent.withValues(alpha: 0.2),
                              ),
                            ),
                            child: Icon(
                              Icons.history_toggle_off_rounded,
                              color: AppTheme.accent,
                              size: 40,
                            ),
                          ),
                          const SizedBox(height: 16),
                          Text(
                            widget.initialData != null
                                ? "កែសម្រួលសំណើចូលយឺត"
                                : "បំពេញព័ត៌មានចូលយឺត",
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.textPrimary,
                              fontSize: 22,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            "សូមបំពេញព័ត៌មានឱ្យបានត្រឹមត្រូវ",
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.helperTextColor,
                              fontSize: 13,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 32),
                    Container(
                      padding: const EdgeInsets.all(24),
                      decoration: BoxDecoration(
                        color: AppTheme.isDarkMode
                            ? const Color(0xFF1C1C1E)
                            : Colors.white.withValues(alpha: 0.94),
                        borderRadius: BorderRadius.circular(28),
                        border: Border.all(
                          color: AppTheme.isDarkMode
                              ? const Color(0x38545458)
                              : Colors.white,
                          width: 1.5,
                        ),
                        boxShadow: AppTheme.cardShadow,
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
                            "មុខតំណែង",
                            buildReadOnlyUserField(_positionController),
                          ),
                          const SizedBox(height: 20),
                          _buildLabelField(
                            "ផ្នែក",
                            buildReadOnlyUserField(_departmentController),
                          ),
                          const SizedBox(height: 20),
                          _buildLabelField(
                            "សាខា",
                            buildReadOnlyBranchField(_branchController),
                          ),
                          const SizedBox(height: 20),
                          _buildLabelField(
                            "ឈ្មោះប្រធានផ្នែក (អ្នកអនុម័ត)",
                            DeptHeadSelector(
                              initialName: _deptHeadController.text,
                              initialSignature: _deptHeadSignature,
                              onSelected: (name, sig) {
                                setState(() {
                                  _deptHeadController.text = name;
                                  _deptHeadSignature = sig;
                                });
                              },
                            ),
                          ),
                          const SizedBox(height: 20),
                          _buildLabelField(
                            "កាលបរិច្ឆេទចូលយឺត",
                            _buildDatePicker(
                              _selectedDate,
                              (d) => setState(() => _selectedDate = d),
                            ),
                          ),
                          const SizedBox(height: 20),
                          _buildLabelField(
                            "ម៉ោងមកដល់ជាក់ស្ដែង",
                            _buildTimeSelector(
                              _actualTime,
                              (t) => setState(() => _actualTime = t),
                              Icons.access_time_filled_rounded,
                            ),
                          ),
                          const SizedBox(height: 20),
                          _buildLabelField(
                            "មូលហេតុនៃការចូលយឺត",
                            TextFormField(
                              controller: _reasonController,
                              maxLines: 3,
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textPrimary,
                                fontSize: 14,
                              ),
                              decoration: _inputDecoration(
                                "បញ្ជាក់មូលហេតុដែលមកយឺត...",
                              ),
                              validator: (v) =>
                                  v!.isEmpty ? "សូមបញ្ចូលមូលហេតុ" : null,
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

  Widget _buildLabelField(String label, Widget field) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(left: 4, bottom: 8),
          child: Text(
            label,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.labelColor,
              fontSize: 13,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
        field,
      ],
    );
  }

  Widget _buildDatePicker(DateTime date, Function(DateTime) onPicked) {
    return InkWell(
      onTap: () async {
        final picked = await showDatePicker(
          context: context,
          initialDate: date,
          firstDate: DateTime.now().subtract(const Duration(days: 30)),
          lastDate: DateTime.now(),
        );
        if (picked != null) onPicked(picked);
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
        decoration: BoxDecoration(
          color: AppTheme.fieldFill,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: AppTheme.fieldBorder),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              DateFormat('dd/MM/yyyy').format(date),
              style: GoogleFonts.inter(
                color: AppTheme.textPrimary,
                fontSize: 14,
              ),
            ),
            Icon(
              Icons.calendar_month_rounded,
              color: AppTheme.helperTextColor,
              size: 20,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTimeSelector(
    TimeOfDay time,
    Function(TimeOfDay) onPicked,
    IconData icon,
  ) {
    return InkWell(
      onTap: () async {
        final picked = await showTimePicker(
          context: context,
          initialTime: time,
        );
        if (picked != null) onPicked(picked);
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
        decoration: BoxDecoration(
          color: AppTheme.fieldFill,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: AppTheme.fieldBorder),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              time.format(context),
              style: GoogleFonts.inter(
                color: AppTheme.textPrimary,
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
            Icon(icon, color: AppTheme.accent, size: 20),
          ],
        ),
      ),
    );
  }

  InputDecoration _inputDecoration(String hint, {IconData? icon}) {
    return InputDecoration(
      hintText: hint,
      prefixIcon: icon != null
          ? Icon(icon, color: AppTheme.fieldIconColor, size: 20)
          : null,
      hintStyle: GoogleFonts.kantumruyPro(
        color: AppTheme.fieldHintColor,
        fontSize: 13,
      ),
      filled: true,
      fillColor: AppTheme.fieldFill,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide.none,
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide(color: AppTheme.fieldBorder),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide(color: AppTheme.accent, width: 1.5),
      ),
      errorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide(color: AppTheme.danger.withValues(alpha: 0.75)),
      ),
      focusedErrorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(16),
        borderSide: BorderSide(color: AppTheme.danger, width: 1.5),
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
    );
  }

  Widget _buildFormTextField({
    required TextEditingController controller,
    bool readOnly = false,
    bool isKhmer = false,
  }) {
    return TextFormField(
      controller: controller,
      readOnly: readOnly,
      style: (isKhmer ? GoogleFonts.kantumruyPro : GoogleFonts.inter)(
        color: readOnly ? AppTheme.helperTextColor : AppTheme.textPrimary,
        fontSize: 14,
      ),
      decoration: _inputDecoration(""),
    );
  }
}
