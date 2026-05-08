import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import '../widgets/app_widgets.dart';
import 'package:provider/provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../providers/user_provider.dart';
import '../widgets/dept_head_selector.dart';

class LateRequestScreen extends StatefulWidget {
  const LateRequestScreen({super.key});

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
  String _selectedPosition = 'ព័ត៌មានវិទ្យា';
  String _selectedDepartment = 'ព័ត៌មានវិទ្យា (IT)';
  String _selectedBranch = 'VVC-HQ';
  final TextEditingController _deptHeadController = TextEditingController();
  String? _deptHeadSignature;
  bool _isLoading = false;

  final List<String> _positions = [
    'ព័ត៌មានវិទ្យា',
    'គណនេយ្យ',
    'រដ្ឋបាល',
    'លក់',
    'ទីផ្សារ',
    'ដឹកញ្ជូន',
  ];

  final List<String> _departments = [
    'ព័ត៌មានវិទ្យា (IT)',
    'ស្ដុក (Stock)',
    'គណនេយ្យ (Accountant)',
    'រដ្ឋបាល (Admin)',
    'ផ្នែកលក់ (Sale)',
    'ផ្នែកផលិត/កម្មករ (Worker)',
  ];

  final List<String> _branches = [
    'VVC-HQ',
    'VVC-Branch 1',
    'VVC-Branch 2',
    'VVC-Branch 3',
    'VVC-Warehouse',
  ];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final user = Provider.of<UserProvider>(context, listen: false);
      _nameController.text = user.name ?? '';
      _emailController.text = "${user.employeeId ?? ''}@vvc.com";
    });
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
      'position': _selectedPosition,
      'department': _selectedDepartment,
      'branch': _selectedBranch,
      'department_head_name': _deptHeadController.text,
      'department_head_signature': _deptHeadSignature,
      'number_of_days': "0",
    };

    final result = await _apiService.submitRequest('Late', formData);
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
      body: Stack(
        children: [
          AppBackgroundShell(
            child: SingleChildScrollView(
              physics: const BouncingScrollPhysics(),
              padding: const EdgeInsets.fromLTRB(20, 110, 20, 100),
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
                            "បំពេញព័ត៌មានចូលយឺត",
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
                              color: AppTheme.textPrimary.withValues(
                                alpha: 0.38,
                              ),
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
                        color: AppTheme.bgCard.withValues(alpha: 0.8),
                        borderRadius: BorderRadius.circular(32),
                        border: Border.all(
                          color: AppTheme.textPrimary.withValues(alpha: 0.08),
                        ),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withValues(alpha: 0.3),
                            blurRadius: 20,
                            offset: const Offset(0, 10),
                          ),
                        ],
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
                            _buildDropdown(
                              _selectedPosition,
                              _positions,
                              (v) => setState(() => _selectedPosition = v!),
                            ),
                          ),
                          const SizedBox(height: 20),
                          _buildLabelField(
                            "ផ្នែក",
                            _buildDropdown(
                              _selectedDepartment,
                              _departments,
                              (v) => setState(() => _selectedDepartment = v!),
                            ),
                          ),
                          const SizedBox(height: 20),
                          _buildLabelField(
                            "សាខា",
                            _buildDropdown(
                              _selectedBranch,
                              _branches,
                              (v) => setState(() => _selectedBranch = v!),
                            ),
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
                            "កាលបរិច្ឆេទ",
                            _buildDatePicker(
                              _selectedDate,
                              (d) => setState(() => _selectedDate = d),
                            ),
                          ),
                          const SizedBox(height: 20),
                          _buildLabelField(
                            "ម៉ោងដែលបានមកដល់",
                            _buildTimeSelector(
                              _actualTime,
                              (t) => setState(() => _actualTime = t),
                              Icons.access_time_filled_rounded,
                            ),
                          ),
                          const SizedBox(height: 20),
                          _buildLabelField(
                            "មូលហេតុយឺត",
                            TextFormField(
                              controller: _reasonController,
                              maxLines: 3,
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textPrimary,
                                fontSize: 14,
                              ),
                              decoration: _inputDecoration(
                                "បញ្ជាក់មូលហេតុនៃការមកយឺត...",
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
          Positioned(
            bottom: 0,
            left: 0,
            right: 0,
            child: Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: AppTheme.bgDark.withValues(alpha: 0.96),
              ),
              child: SafeArea(
                child: _isLoading
                    ? const Center(child: CircularProgressIndicator())
                    : SizedBox(
                        width: double.infinity,
                        height: 55,
                        child: ElevatedButton(
                          onPressed: _submit,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: AppTheme.accent,
                            foregroundColor: AppTheme.textPrimary,
                            elevation: 8,
                            shadowColor: AppTheme.accent.withValues(alpha: 0.4),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(16),
                            ),
                          ),
                          child: Text(
                            "បញ្ជូនសំណើចូលយឺត",
                            style: GoogleFonts.kantumruyPro(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ),
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
              DateFormat('dd/MM/yyyy').format(date),
              style: GoogleFonts.inter(
                color: AppTheme.textPrimary,
                fontSize: 14,
              ),
            ),
            Icon(
              Icons.calendar_month_rounded,
              color: AppTheme.textPrimary.withValues(alpha: 0.38),
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
          ? Icon(
              icon,
              color: AppTheme.textPrimary.withValues(alpha: 0.24),
              size: 20,
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
        borderSide: BorderSide(color: AppTheme.accent, width: 1.5),
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
        color: readOnly
            ? AppTheme.textPrimary.withValues(alpha: 0.38)
            : AppTheme.textPrimary,
        fontSize: 14,
      ),
      decoration: _inputDecoration(""),
    );
  }
}
