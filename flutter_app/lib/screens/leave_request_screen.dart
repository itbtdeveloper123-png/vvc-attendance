import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../providers/user_provider.dart';
import '../widgets/dept_head_selector.dart';
import '../widgets/app_widgets.dart';

class LeaveRequestScreen extends StatefulWidget {
  final Map<String, dynamic>? initialData;
  const LeaveRequestScreen({super.key, this.initialData});

  @override
  State<LeaveRequestScreen> createState() => _LeaveRequestScreenState();
}

class _LeaveRequestScreenState extends State<LeaveRequestScreen> {
  final _formKey = GlobalKey<FormState>();
  final _apiService = ApiService();

  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _nameController = TextEditingController();
  final TextEditingController _reasonController = TextEditingController();
  final TextEditingController _contactController = TextEditingController();
  final TextEditingController _handoffController = TextEditingController();

  DateTime _selectedDate = DateTime.now(); // From date
  DateTime _returnDate = DateTime.now().add(const Duration(days: 1));
  final TextEditingController _deptHeadController = TextEditingController();
  final TextEditingController _daysController = TextEditingController(
    text: "1",
  );

  String _selectedPosition = 'ព័ត៌មានវិទ្យា';
  String _selectedDepartment = 'ព័ត៌មានវិទ្យា (IT)';
  String _selectedBranch = 'VVC-HQ';
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
      if (widget.initialData != null) {
        final d = widget.initialData!;
        _nameController.text = d['requester_name'] ?? '';
        _reasonController.text = d['reason'] ?? '';
        _contactController.text = d['contact_number'] ?? '';
        _handoffController.text = d['assigned_to'] ?? '';
        _deptHeadController.text = d['department_head_name'] ?? '';
        _deptHeadSignature = d['department_head_signature'];
        _daysController.text = (d['number_of_days'] ?? 1).toString();

        if (d['request_date'] != null) {
          try {
            _selectedDate = DateTime.parse(d['request_date']);
          } catch (_) {}
        }
        if (d['return_date'] != null) {
          try {
            _returnDate = DateTime.parse(d['return_date']);
          } catch (_) {}
        }

        if (d['position'] != null && _positions.contains(d['position'])) {
          _selectedPosition = d['position'];
        }
        if (d['department'] != null && _departments.contains(d['department'])) {
          _selectedDepartment = d['department'];
        }
        if (d['branch'] != null && _branches.contains(d['branch'])) {
          _selectedBranch = d['branch'];
        }
        if (mounted) setState(() {});
      } else {
        final user = Provider.of<UserProvider>(context, listen: false);
        _nameController.text = user.name ?? '';
        _emailController.text = "${user.employeeId ?? ''}@vvc.com";
      }
    });
  }

  void _submit() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() => _isLoading = true);

    final formData = {
      'leave_date': DateFormat('yyyy-MM-dd').format(_selectedDate),
      'return_date': DateFormat('yyyy-MM-dd').format(_returnDate),
      'leave_reason': _reasonController.text,
      'leave_contact': _contactController.text,
      'leave_handoff': _handoffController.text,
      'leave_total_hours': (double.tryParse(_daysController.text) ?? 1.0 * 8)
          .toString(),
      'number_of_days': _daysController.text,
      'position': _selectedPosition,
      'department': _selectedDepartment,
      'branch': _selectedBranch,
      'department_head_name': _deptHeadController.text,
      'department_head_signature': _deptHeadSignature,
    };

    try {
      final result = widget.initialData != null
          ? await _apiService.updateRequest(
              int.parse(widget.initialData!['id'].toString()),
              formData,
            )
          : await _apiService.submitRequest('Leave', formData);

      if (mounted) setState(() => _isLoading = false);

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
    } catch (e) {
      if (mounted) setState(() => _isLoading = false);
      if (mounted) {
        _showResultPopup(
          "មានបញ្ហាក្នុងការភ្ជាប់ទៅកាន់ម៉ាស៊ីនបម្រើ",
          Icons.error_outline_rounded,
          AppTheme.danger,
          false,
        );
      }
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
      title: "ស្នើសុំច្បាប់ឈប់សម្រាក",
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
                              color: AppTheme.primary.withValues(alpha: 0.1),
                              shape: BoxShape.circle,
                              border: Border.all(
                                color: AppTheme.primary.withValues(alpha: 0.2),
                              ),
                            ),
                            child: Icon(
                              Icons.description_rounded,
                              color: AppTheme.primary,
                              size: 40,
                            ),
                          ),
                          const SizedBox(height: 16),
                          Text(
                            "បំពេញព័ត៌មានសំណើ",
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.textPrimary,
                              fontSize: 22,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            "សូមបំពេញព័ត៌មានខាងក្រោមឱ្យបានត្រឹមត្រូវ",
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
                            "កាលបរិច្ឆេទឈប់",
                            _buildDatePicker(
                              _selectedDate,
                              (d) => setState(() => _selectedDate = d),
                            ),
                          ),
                          const SizedBox(height: 20),

                          _buildLabelField(
                            "កាលបរិច្ឆេទចូលវិញ",
                            _buildDatePicker(
                              _returnDate,
                              (d) => setState(() => _returnDate = d),
                              firstDate: _selectedDate,
                            ),
                          ),
                          const SizedBox(height: 20),

                          _buildLabelField(
                            "ចំនួនថ្ងៃឈប់",
                            TextFormField(
                              controller: _daysController,
                              keyboardType: TextInputType.number,
                              style: GoogleFonts.inter(
                                color: AppTheme.textPrimary,
                                fontSize: 14,
                              ),
                              decoration: _inputDecoration(
                                "ចំនួនថ្ងៃ (ឧ: 1, 0.5)...",
                              ),
                              validator: (v) =>
                                  v!.isEmpty ? "សូមបញ្ចូលចំនួនថ្ងៃ" : null,
                            ),
                          ),
                          const SizedBox(height: 20),

                          _buildLabelField(
                            "មូលហេតុ",
                            TextFormField(
                              controller: _reasonController,
                              maxLines: 3,
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textPrimary,
                                fontSize: 14,
                              ),
                              decoration: _inputDecoration(
                                "បញ្ជាក់មូលហេតុនៃការឈប់...",
                              ),
                              validator: (v) =>
                                  v!.isEmpty ? "សូមបញ្ចូលមូលហេតុ" : null,
                            ),
                          ),
                          const SizedBox(height: 20),

                          _buildLabelField(
                            "លេខទូរស័ព្ទ",
                            TextFormField(
                              controller: _contactController,
                              style: GoogleFonts.inter(
                                color: AppTheme.textPrimary,
                                fontSize: 14,
                              ),
                              decoration: _inputDecoration(
                                "លេខសម្រាប់ទំនាក់ទំនង...",
                                icon: Icons.phone_rounded,
                              ),
                              keyboardType: TextInputType.phone,
                            ),
                          ),
                          const SizedBox(height: 20),

                          _buildLabelField(
                            "អ្នកទទួលការងារបន្ត (បើមាន)",
                            TextFormField(
                              controller: _handoffController,
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textPrimary,
                                fontSize: 14,
                              ),
                              decoration: _inputDecoration(
                                "ឈ្មោះបុគ្គលិកទទួលបន្ត...",
                                icon: Icons.person_add_alt_1_rounded,
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
          Positioned(
            bottom: 0,
            left: 0,
            right: 0,
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: SafeArea(
                child: _isLoading
                    ? const Center(child: CircularProgressIndicator())
                    : SizedBox(
                        width: double.infinity,
                        height: 55,
                        child: ElevatedButton(
                          onPressed: _submit,
                          style: AppTheme.filledButtonStyle(
                            backgroundColor: AppTheme.primary,
                          ),
                          child: Text(
                            widget.initialData != null
                                ? "រក្សាទុកការកែសម្រួល"
                                : "បញ្ជូនសំណើ",
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

  Widget _buildDropdown(
    String value,
    List<String> items,
    Function(String?) onChanged,
  ) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      decoration: BoxDecoration(
        color: AppTheme.fieldFill,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.fieldBorder),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<String>(
          value: value,
          isExpanded: true,
          dropdownColor: AppTheme.bgCard,
          icon: Icon(
            Icons.keyboard_arrow_down_rounded,
            color: AppTheme.helperTextColor,
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
    DateTime? firstDate,
  }) {
    return InkWell(
      onTap: () async {
        final picked = await showDatePicker(
          context: context,
          initialDate: (firstDate != null && date.isBefore(firstDate))
              ? firstDate
              : date,
          firstDate:
              firstDate ?? DateTime.now().subtract(const Duration(days: 30)),
          lastDate: DateTime.now().add(const Duration(days: 365)),
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
        borderSide: BorderSide(color: AppTheme.primary, width: 1.5),
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
