import 'dart:math';
import 'package:animate_do/animate_do.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/glass_widgets.dart';

const Color _emeraldColor = Color(0xFF10B981);
const Color _roseColor = Color(0xFFF43F5E);

class RegisterScreen extends StatefulWidget {
  const RegisterScreen({super.key});

  @override
  State<RegisterScreen> createState() => _RegisterScreenState();
}

enum ShiftPreset { office, store, custom }

class _RegisterScreenState extends State<RegisterScreen> {
  final _formKey = GlobalKey<FormState>();
  final ApiService _apiService = ApiService();

  // Basic Information Controllers
  final TextEditingController _empIdController = TextEditingController();
  final TextEditingController _nameController = TextEditingController();
  final TextEditingController _latinNameController = TextEditingController();
  final TextEditingController _positionController = TextEditingController(text: 'Staff / IT');
  final TextEditingController _deptController = TextEditingController(text: 'Store 318');
  final TextEditingController _branchController = TextEditingController(text: 'VVC-HQ');

  // Account & Credentials Controllers
  final TextEditingController _usernameController = TextEditingController();
  final TextEditingController _phoneController = TextEditingController();
  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _addressController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final TextEditingController _confirmPasswordController = TextEditingController();

  bool _obscurePassword = true;
  bool _obscureConfirmPassword = true;
  bool _isLoading = false;

  // Work Rules / Shift Settings
  ShiftPreset _selectedPreset = ShiftPreset.office;
  TimeOfDay _checkinTime = const TimeOfDay(hour: 8, minute: 0);
  int _gracePeriodMinutes = 15;
  TimeOfDay _checkoutTime = const TimeOfDay(hour: 17, minute: 0);

  // Common quick picks
  final List<String> _positionOptions = [
    'Staff / IT',
    'Sales',
    'HRM',
    'គណនេយ្យ',
    'រដ្ឋបាល',
    'ឃ្លាំង',
    'ដឹកជញ្ជូន',
    'ជាងបច្ចេកទេស',
  ];

  final List<String> _deptOptions = [
    'Store 318',
    'IT Department',
    'HRM',
    'Accounting',
    'Warehouse',
    'HQ Operations',
  ];

  final List<String> _branchOptions = [
    'VVC-HQ',
    'Store 318',
    'NR3 Branch',
    'KS2 Branch',
    'Battambang',
    'Siem Reap',
  ];

  @override
  void initState() {
    super.initState();
    _generateRandomEmpId();
  }

  @override
  void dispose() {
    _empIdController.dispose();
    _nameController.dispose();
    _latinNameController.dispose();
    _positionController.dispose();
    _deptController.dispose();
    _branchController.dispose();
    _usernameController.dispose();
    _phoneController.dispose();
    _emailController.dispose();
    _addressController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  void _generateRandomEmpId() {
    final rand = 100 + Random().nextInt(900);
    _empIdController.text = 'VVC-$rand';
  }

  void _applyPreset(ShiftPreset preset) {
    setState(() {
      _selectedPreset = preset;
      if (preset == ShiftPreset.office) {
        _checkinTime = const TimeOfDay(hour: 8, minute: 0);
        _gracePeriodMinutes = 15;
        _checkoutTime = const TimeOfDay(hour: 17, minute: 0);
      } else if (preset == ShiftPreset.store) {
        _checkinTime = const TimeOfDay(hour: 7, minute: 30);
        _gracePeriodMinutes = 15;
        _checkoutTime = const TimeOfDay(hour: 16, minute: 30);
      }
    });
  }

  String _formatTime(TimeOfDay t) {
    final h = t.hour.toString().padLeft(2, '0');
    final m = t.minute.toString().padLeft(2, '0');
    return '$h:$m:00';
  }

  String _formatDisplayTime(TimeOfDay t) {
    final hour = t.hourOfPeriod == 0 ? 12 : t.hourOfPeriod;
    final period = t.period == DayPeriod.am ? 'ព្រឹក' : 'ល្ងាច';
    final minute = t.minute.toString().padLeft(2, '0');
    return '$hour:$minute $period';
  }

  List<Map<String, dynamic>> _generateAttendanceRules() {
    final checkinStartMin = (_checkinTime.hour * 60 + _checkinTime.minute) - 30;
    final checkinGoodEndMin = (_checkinTime.hour * 60 + _checkinTime.minute) + _gracePeriodMinutes;
    final checkinLateEndMin = checkinGoodEndMin + 45;

    String minToTime(int totalMin) {
      final h = (totalMin ~/ 60).clamp(0, 23).toString().padLeft(2, '0');
      final m = (totalMin % 60).clamp(0, 59).toString().padLeft(2, '0');
      return '$h:$m:00';
    }

    final checkinGoodStartStr = minToTime(checkinStartMin < 0 ? 0 : checkinStartMin);
    final checkinGoodEndStr = minToTime(checkinGoodEndMin);
    final checkinLateStartStr = minToTime(checkinGoodEndMin + 1);
    final checkinLateEndStr = minToTime(checkinLateEndMin);
    final checkinAbsentStartStr = minToTime(checkinLateEndMin + 1);

    final checkoutGoodStartStr = _formatTime(_checkoutTime);
    const checkoutLateStartStr = '12:00:00';
    final checkoutLateEndMinutes = (_checkoutTime.hour * 60 + _checkoutTime.minute) - 1;
    final checkoutLateEndStr = minToTime(checkoutLateEndMinutes < 720 ? 720 : checkoutLateEndMinutes);

    return [
      {
        'type': 'checkin',
        'start_time': checkinGoodStartStr,
        'end_time': checkinGoodEndStr,
        'status': 'Good',
      },
      {
        'type': 'checkin',
        'start_time': checkinLateStartStr,
        'end_time': checkinLateEndStr,
        'status': 'Late',
      },
      {
        'type': 'checkin',
        'start_time': checkinAbsentStartStr,
        'end_time': '12:00:00',
        'status': 'Absent',
      },
      {
        'type': 'checkout',
        'start_time': checkoutGoodStartStr,
        'end_time': '23:59:59',
        'status': 'Good',
      },
      {
        'type': 'checkout',
        'start_time': checkoutLateStartStr,
        'end_time': checkoutLateEndStr,
        'status': 'Late',
      },
    ];
  }

  Future<void> _pickCheckinTime() async {
    final picked = await showTimePicker(
      context: context,
      initialTime: _checkinTime,
      builder: (context, child) => Theme(
        data: Theme.of(context).copyWith(
          timePickerTheme: TimePickerThemeData(
            backgroundColor: const Color(0xFF1E2235),
            hourMinuteTextColor: Colors.white,
            dayPeriodTextColor: Colors.white,
            dialHandColor: AppTheme.primary,
            dialBackgroundColor: const Color(0xFF131726),
          ),
        ),
        child: child!,
      ),
    );
    if (picked != null) {
      setState(() {
        _checkinTime = picked;
        _selectedPreset = ShiftPreset.custom;
      });
    }
  }

  Future<void> _pickCheckoutTime() async {
    final picked = await showTimePicker(
      context: context,
      initialTime: _checkoutTime,
      builder: (context, child) => Theme(
        data: Theme.of(context).copyWith(
          timePickerTheme: TimePickerThemeData(
            backgroundColor: const Color(0xFF1E2235),
            hourMinuteTextColor: Colors.white,
            dayPeriodTextColor: Colors.white,
            dialHandColor: AppTheme.primary,
            dialBackgroundColor: const Color(0xFF131726),
          ),
        ),
        child: child!,
      ),
    );
    if (picked != null) {
      setState(() {
        _checkoutTime = picked;
        _selectedPreset = ShiftPreset.custom;
      });
    }
  }

  Future<void> _handleRegister() async {
    if (!_formKey.currentState!.validate()) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'សូមបំពេញព័ត៌មានចាំបាច់ (*) ឱ្យបានត្រឹមត្រូវ!',
            style: GoogleFonts.kantumruyPro(color: Colors.white),
          ),
          backgroundColor: Colors.redAccent,
          behavior: SnackBarBehavior.floating,
        ),
      );
      return;
    }

    if (_passwordController.text.isNotEmpty &&
        _passwordController.text != _confirmPasswordController.text) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'លេខសម្ងាត់ និងការបញ្ជាក់លេខសម្ងាត់មិនត្រូវគ្នាទេ!',
            style: GoogleFonts.kantumruyPro(color: Colors.white),
          ),
          backgroundColor: Colors.redAccent,
          behavior: SnackBarBehavior.floating,
        ),
      );
      return;
    }

    setState(() => _isLoading = true);

    try {
      final rules = _generateAttendanceRules();
      final res = await _apiService.registerUser(
        employeeId: _empIdController.text.trim(),
        name: _nameController.text.trim(),
        latinName: _latinNameController.text.trim(),
        position: _positionController.text.trim(),
        department: _deptController.text.trim(),
        branch: _branchController.text.trim(),
        username: _usernameController.text.trim().isNotEmpty
            ? _usernameController.text.trim()
            : _empIdController.text.trim(),
        phone: _phoneController.text.trim(),
        email: _emailController.text.trim(),
        address: _addressController.text.trim(),
        password: _passwordController.text.trim().isNotEmpty
            ? _passwordController.text.trim()
            : '123456',
        rules: rules,
      );

      if (!mounted) return;
      setState(() => _isLoading = false);

      if (res['success'] == true || res['status'] == 'success') {
        _showSuccessDialog();
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              res['message'] ?? 'កំហុសក្នុងការចុះឈ្មោះបុគ្គលិក!',
              style: GoogleFonts.kantumruyPro(color: Colors.white),
            ),
            backgroundColor: Colors.redAccent,
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    } catch (e) {
      if (!mounted) return;
      setState(() => _isLoading = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'កំហុសបណ្តាញ៖ $e',
            style: GoogleFonts.kantumruyPro(color: Colors.white),
          ),
          backgroundColor: Colors.redAccent,
          behavior: SnackBarBehavior.floating,
        ),
      );
    }
  }

  void _showSuccessDialog() {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => Dialog(
        backgroundColor: Colors.transparent,
        child: GlassCard(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 72,
                height: 72,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: _emeraldColor.withValues(alpha: 0.15),
                  border: Border.all(color: _emeraldColor.withValues(alpha: 0.5), width: 2),
                ),
                child: const Icon(
                  Icons.check_circle_rounded,
                  color: _emeraldColor,
                  size: 44,
                ),
              ),
              const SizedBox(height: 20),
              Text(
                "ចុះឈ្មោះជោគជ័យ!",
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 10),
              Text(
                "គណនីបុគ្គលិក និងច្បាប់ម៉ោងត្រូវបានរក្សាទុកក្នុង Database ដោយជោគជ័យ។ ខាង Admin Panel អាចមើលឃើញ និងគ្រប់គ្រងបានភ្លាមៗ។",
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary.withValues(alpha: 0.7),
                  fontSize: 13,
                  height: 1.5,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 20),
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: AppTheme.textPrimary.withValues(alpha: 0.05),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.08)),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceAround,
                  children: [
                    Column(
                      children: [
                        Text("អត្តលេខ", style: GoogleFonts.kantumruyPro(fontSize: 11, color: AppTheme.textPrimary.withValues(alpha: 0.5))),
                        const SizedBox(height: 4),
                        Text(_empIdController.text, style: GoogleFonts.outfit(fontWeight: FontWeight.bold, color: AppTheme.primaryLight)),
                      ],
                    ),
                    Container(width: 1, height: 28, color: AppTheme.textPrimary.withValues(alpha: 0.1)),
                    Column(
                      children: [
                        Text("ឈ្មោះបុគ្គលិក", style: GoogleFonts.kantumruyPro(fontSize: 11, color: AppTheme.textPrimary.withValues(alpha: 0.5))),
                        const SizedBox(height: 4),
                        Text(_nameController.text, style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, color: AppTheme.textPrimary)),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),
              Row(
                children: [
                  Expanded(
                    child: GlassButton(
                      label: "ត្រឡប់ទៅ Login",
                      icon: Icons.login_rounded,
                      color: AppTheme.primary,
                      onPressed: () {
                        Navigator.of(ctx).pop();
                        Navigator.of(context).pop(_empIdController.text.trim());
                      },
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

  @override
  Widget build(BuildContext context) {
    return GlassOrbBackground(
      primaryOrbColor: const Color(0xFF6366F1),
      secondaryOrbColor: const Color(0xFF06B6D4),
      accentOrbColor: _emeraldColor,
      child: SafeArea(
        child: Column(
          children: [
            // Top App Bar
            _buildHeader(),

            // Scrollable Form
            Expanded(
              child: SingleChildScrollView(
                physics: const BouncingScrollPhysics(),
                padding: const EdgeInsets.fromLTRB(20, 8, 20, 32),
                child: Form(
                  key: _formKey,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Card 1: Basic Information
                      FadeInDown(
                        duration: const Duration(milliseconds: 600),
                        child: _buildBasicInfoCard(),
                      ),
                      const SizedBox(height: 20),

                      // Card 2: Account & Security
                      FadeInDown(
                        duration: const Duration(milliseconds: 700),
                        child: _buildAccountCard(),
                      ),
                      const SizedBox(height: 20),

                      // Card 3: Work Rules / Schedule Settings
                      FadeInDown(
                        duration: const Duration(milliseconds: 800),
                        child: _buildWorkRulesCard(),
                      ),
                      const SizedBox(height: 28),

                      // Submit Button
                      FadeInUp(
                        duration: const Duration(milliseconds: 900),
                        child: _buildSubmitSection(),
                      ),
                      const SizedBox(height: 24),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Row(
        children: [
          IconButton(
            onPressed: () => Navigator.of(context).pop(),
            style: IconButton.styleFrom(
              backgroundColor: AppTheme.textPrimary.withValues(alpha: 0.08),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
            ),
            icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18, color: Colors.white),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  "បង្កើតអ្នកប្រើប្រាស់ថ្មី",
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                Text(
                  "Create New User (ដូចក្នុង Admin Panel)",
                  style: GoogleFonts.outfit(
                    color: AppTheme.textPrimary.withValues(alpha: 0.5),
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ----------------------------------------------------
  // Card 1: Basic Information
  // ----------------------------------------------------
  Widget _buildBasicInfoCard() {
    return GlassCard(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: AppTheme.primary.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(Icons.badge_rounded, color: AppTheme.primaryLight, size: 20),
              ),
              const SizedBox(width: 12),
              Text(
                "ព័ត៌មានមូលដ្ឋាន (Basic Info)",
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),

          // Employee ID
          _buildInputLabel("អត្តលេខ (Employee ID) *"),
          Row(
            children: [
              Expanded(
                child: _buildTextField(
                  controller: _empIdController,
                  hintText: "ឧ. VVC-768",
                  icon: Icons.fingerprint_rounded,
                  validator: (val) => (val == null || val.trim().isEmpty) ? 'សូមបញ្ចូលអត្តលេខ' : null,
                ),
              ),
              const SizedBox(width: 10),
              IconButton(
                onPressed: _generateRandomEmpId,
                tooltip: "បង្កើតលេខកូដស្វ័យប្រវត្តិ",
                style: IconButton.styleFrom(
                  backgroundColor: AppTheme.primary.withValues(alpha: 0.15),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                  padding: const EdgeInsets.all(12),
                ),
                icon: Icon(Icons.auto_mode_rounded, color: AppTheme.primaryLight, size: 20),
              ),
            ],
          ),
          const SizedBox(height: 14),

          // Khmer Name
          _buildInputLabel("ឈ្មោះបុគ្គលិក (Khmer Name) *"),
          _buildTextField(
            controller: _nameController,
            hintText: "ឧ. សុខ គឹមហុង",
            icon: Icons.person_outline_rounded,
            validator: (val) => (val == null || val.trim().isEmpty) ? 'សូមបញ្ចូលឈ្មោះបុគ្គលិក' : null,
          ),
          const SizedBox(height: 14),

          // Latin Name
          _buildInputLabel("ឈ្មោះអក្សរឡាតាំង (Latin Name)"),
          _buildTextField(
            controller: _latinNameController,
            hintText: "ឧ. SOK KIMHONG",
            icon: Icons.translate_rounded,
          ),
          const SizedBox(height: 14),

          // Position
          _buildInputLabel("មុខតំណែង (Position) *"),
          _buildTextField(
            controller: _positionController,
            hintText: "ឧ. Staff / IT",
            icon: Icons.work_outline_rounded,
            validator: (val) => (val == null || val.trim().isEmpty) ? 'សូមបញ្ចូលមុខតំណែង' : null,
          ),
          const SizedBox(height: 8),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: _positionOptions.map((pos) {
                final isSelected = _positionController.text == pos;
                return Padding(
                  padding: const EdgeInsets.only(right: 6),
                  child: ChoiceChip(
                    label: Text(pos, style: GoogleFonts.kantumruyPro(fontSize: 11, color: isSelected ? Colors.white : AppTheme.textPrimary.withValues(alpha: 0.7))),
                    selected: isSelected,
                    selectedColor: AppTheme.primary,
                    backgroundColor: AppTheme.textPrimary.withValues(alpha: 0.05),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    side: BorderSide.none,
                    onSelected: (selected) {
                      if (selected) setState(() => _positionController.text = pos);
                    },
                  ),
                );
              }).toList(),
            ),
          ),
          const SizedBox(height: 14),

          // Department & Branch in Row
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildInputLabel("ផ្នែក (Department)"),
                    _buildDropdown(
                      value: _deptController.text,
                      items: _deptOptions,
                      onChanged: (val) {
                        if (val != null) setState(() => _deptController.text = val);
                      },
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildInputLabel("សាខា (Branch)"),
                    _buildDropdown(
                      value: _branchController.text,
                      items: _branchOptions,
                      onChanged: (val) {
                        if (val != null) setState(() => _branchController.text = val);
                      },
                    ),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // ----------------------------------------------------
  // Card 2: Account & Credentials
  // ----------------------------------------------------
  Widget _buildAccountCard() {
    return GlassCard(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.cyanAccent.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(Icons.security_rounded, color: Colors.cyanAccent, size: 20),
              ),
              const SizedBox(width: 12),
              Text(
                "គណនី & សុវត្ថិភាព (Account & Login)",
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),

          // Username & Phone
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildInputLabel("ឈ្មោះគណនី (Username)"),
                    _buildTextField(
                      controller: _usernameController,
                      hintText: "ឧ. vvc",
                      icon: Icons.alternate_email_rounded,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildInputLabel("លេខទូរស័ព្ទ (Phone)"),
                    _buildTextField(
                      controller: _phoneController,
                      hintText: "ឧ. 012 345 678",
                      icon: Icons.phone_android_rounded,
                      keyboardType: TextInputType.phone,
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),

          // Email
          _buildInputLabel("អ៊ីមែល (Email)"),
          _buildTextField(
            controller: _emailController,
            hintText: "ឧ. user@vvc.asia",
            icon: Icons.mail_outline_rounded,
            keyboardType: TextInputType.emailAddress,
          ),
          const SizedBox(height: 14),

          // Password
          _buildInputLabel("លេខសម្ងាត់ (Password) *"),
          _buildTextField(
            controller: _passwordController,
            hintText: "•••••••• (លំនាំដើម: 123456)",
            icon: Icons.lock_outline_rounded,
            obscureText: _obscurePassword,
            suffixIcon: IconButton(
              icon: Icon(
                _obscurePassword ? Icons.visibility_off_rounded : Icons.visibility_rounded,
                color: AppTheme.textPrimary.withValues(alpha: 0.4),
                size: 20,
              ),
              onPressed: () => setState(() => _obscurePassword = !_obscurePassword),
            ),
          ),
          const SizedBox(height: 14),

          // Confirm Password
          _buildInputLabel("បញ្ជាក់លេខសម្ងាត់ (Confirm Password)"),
          _buildTextField(
            controller: _confirmPasswordController,
            hintText: "••••••••",
            icon: Icons.lock_reset_rounded,
            obscureText: _obscureConfirmPassword,
            suffixIcon: IconButton(
              icon: Icon(
                _obscureConfirmPassword ? Icons.visibility_off_rounded : Icons.visibility_rounded,
                color: AppTheme.textPrimary.withValues(alpha: 0.4),
                size: 20,
              ),
              onPressed: () => setState(() => _obscureConfirmPassword = !_obscureConfirmPassword),
            ),
          ),
        ],
      ),
    );
  }

  // ----------------------------------------------------
  // Card 3: Work Rules / Shift Settings
  // ----------------------------------------------------
  Widget _buildWorkRulesCard() {
    return GlassCard(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: _emeraldColor.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(Icons.schedule_rounded, color: _emeraldColor, size: 20),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      "កំណត់ច្បាប់ម៉ោងចូល/ចេញ (Work Rules)",
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary,
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    Text(
                      "កំណត់ម៉ោងស្កេនចូល និងចេញសម្រាប់បុគ្គលិកនេះ",
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary.withValues(alpha: 0.5),
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),

          // Preset Buttons
          Text(
            "ជ្រើសរើសវេនការងារលំនាំដើម (Quick Presets)៖",
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary.withValues(alpha: 0.7),
              fontSize: 12,
            ),
          ),
          const SizedBox(height: 10),
          Row(
            children: [
              Expanded(
                child: _buildPresetChip(
                  label: "ការិយាល័យ",
                  timeRange: "08:00 - 17:00",
                  isSelected: _selectedPreset == ShiftPreset.office,
                  onTap: () => _applyPreset(ShiftPreset.office),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: _buildPresetChip(
                  label: "វេនសាខា/ហាង",
                  timeRange: "07:30 - 16:30",
                  isSelected: _selectedPreset == ShiftPreset.store,
                  onTap: () => _applyPreset(ShiftPreset.store),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: _buildPresetChip(
                  label: "ផ្ទាល់ខ្លួន",
                  timeRange: "កំណត់ដោយដៃ",
                  isSelected: _selectedPreset == ShiftPreset.custom,
                  onTap: () => setState(() => _selectedPreset = ShiftPreset.custom),
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Interactive Time Cards (Check-in & Check-out)
          Row(
            children: [
              // Check-in Picker Box
              Expanded(
                child: InkWell(
                  onTap: _pickCheckinTime,
                  borderRadius: BorderRadius.circular(16),
                  child: Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: AppTheme.textPrimary.withValues(alpha: 0.05),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(
                        color: AppTheme.primaryLight.withValues(alpha: 0.3),
                      ),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.login_rounded, size: 16, color: _emeraldColor),
                            const SizedBox(width: 6),
                            Text(
                              "ម៉ោងចូល (Check-in)",
                              style: GoogleFonts.kantumruyPro(
                                fontSize: 11,
                                color: AppTheme.textPrimary.withValues(alpha: 0.7),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(
                          _formatDisplayTime(_checkinTime),
                          style: GoogleFonts.outfit(
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          "ចុចដើម្បីផ្លាស់ប្តូរ",
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 10,
                            color: AppTheme.primaryLight,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 12),

              // Check-out Picker Box
              Expanded(
                child: InkWell(
                  onTap: _pickCheckoutTime,
                  borderRadius: BorderRadius.circular(16),
                  child: Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: AppTheme.textPrimary.withValues(alpha: 0.05),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(
                        color: Colors.amberAccent.withValues(alpha: 0.3),
                      ),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.logout_rounded, size: 16, color: Colors.amberAccent),
                            const SizedBox(width: 6),
                            Text(
                              "ម៉ោងចេញ (Check-out)",
                              style: GoogleFonts.kantumruyPro(
                                fontSize: 11,
                                color: AppTheme.textPrimary.withValues(alpha: 0.7),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(
                          _formatDisplayTime(_checkoutTime),
                          style: GoogleFonts.outfit(
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          "ចុចដើម្បីផ្លាស់ប្តូរ",
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 10,
                            color: Colors.amberAccent,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          // Grace period dropdown
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: AppTheme.textPrimary.withValues(alpha: 0.03),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  "រយៈពេលអនុគ្រោះពេលចូល (Grace Period)៖",
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 11,
                    color: AppTheme.textPrimary.withValues(alpha: 0.7),
                  ),
                ),
                DropdownButton<int>(
                  value: _gracePeriodMinutes,
                  dropdownColor: const Color(0xFF1E2235),
                  underline: const SizedBox.shrink(),
                  style: GoogleFonts.outfit(
                    color: AppTheme.primaryLight,
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                  items: [0, 5, 10, 15, 20, 30].map((m) {
                    return DropdownMenuItem<int>(
                      value: m,
                      child: Text("$m នាទី"),
                    );
                  }).toList(),
                  onChanged: (val) {
                    if (val != null) {
                      setState(() {
                        _gracePeriodMinutes = val;
                        _selectedPreset = ShiftPreset.custom;
                      });
                    }
                  },
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Status Preview Badges
          Text(
            "ច្បាប់កំណត់ពេលស្កេនជាក់ស្តែង (Status Rules)៖",
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary.withValues(alpha: 0.7),
              fontSize: 11,
            ),
          ),
          const SizedBox(height: 8),
          _buildRuleStatusRow(
            status: "ទាន់ពេល (Good)",
            desc: "ស្កេនចូលមុនម៉ោង ${_checkinTime.hour}:${(_checkinTime.minute + _gracePeriodMinutes).toString().padLeft(2, '0')}",
            color: _emeraldColor,
          ),
          _buildRuleStatusRow(
            status: "ចូលយឺត (Late)",
            desc: "ស្កេនចូលលើស $_gracePeriodMinutes នាទីឡើងទៅ",
            color: Colors.amberAccent,
          ),
          _buildRuleStatusRow(
            status: "អវត្តមាន (Absent)",
            desc: "ស្កេនចូលយឺតលើសពី ៦០ នាទីឡើងទៅ",
            color: _roseColor,
          ),
          _buildRuleStatusRow(
            status: "ចេញត្រឹមត្រូវ (Good)",
            desc: "ស្កេនចេញចាប់ពីម៉ោង ${_formatDisplayTime(_checkoutTime)} តទៅ",
            color: Colors.tealAccent,
          ),
        ],
      ),
    );
  }

  Widget _buildPresetChip({
    required String label,
    required String timeRange,
    required bool isSelected,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 8),
        decoration: BoxDecoration(
          color: isSelected
              ? AppTheme.primary.withValues(alpha: 0.25)
              : AppTheme.textPrimary.withValues(alpha: 0.04),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: isSelected ? AppTheme.primaryLight : AppTheme.textPrimary.withValues(alpha: 0.08),
            width: isSelected ? 1.5 : 1,
          ),
        ),
        child: Column(
          children: [
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                fontSize: 11,
                fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                color: isSelected ? Colors.white : AppTheme.textPrimary.withValues(alpha: 0.8),
              ),
              textAlign: TextAlign.center,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 2),
            Text(
              timeRange,
              style: GoogleFonts.outfit(
                fontSize: 10,
                color: isSelected ? AppTheme.primaryLight : AppTheme.textPrimary.withValues(alpha: 0.45),
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildRuleStatusRow({
    required String status,
    required String desc,
    required Color color,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(shape: BoxShape.circle, color: color),
          ),
          const SizedBox(width: 8),
          Text(
            status,
            style: GoogleFonts.kantumruyPro(
              color: color,
              fontSize: 11,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              desc,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.5),
                fontSize: 11,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  // ----------------------------------------------------
  // Submit & Action Section
  // ----------------------------------------------------
  Widget _buildSubmitSection() {
    return Row(
      children: [
        // Cancel Button
        Expanded(
          flex: 1,
          child: OutlinedButton(
            onPressed: () => Navigator.of(context).pop(),
            style: OutlinedButton.styleFrom(
              padding: const EdgeInsets.symmetric(vertical: 16),
              side: BorderSide(color: AppTheme.textPrimary.withValues(alpha: 0.15)),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
            ),
            child: Text(
              "បោះបង់ (Cancel)",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.7),
                fontSize: 14,
              ),
            ),
          ),
        ),
        const SizedBox(width: 14),

        // Submit Button
        Expanded(
          flex: 2,
          child: Container(
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(16),
              gradient: const LinearGradient(
                colors: [Color(0xFF6366F1), Color(0xFF4F46E5)],
              ),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFF6366F1).withValues(alpha: 0.4),
                  blurRadius: 16,
                  offset: const Offset(0, 6),
                ),
              ],
            ),
            child: ElevatedButton(
              onPressed: _isLoading ? null : _handleRegister,
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.transparent,
                shadowColor: Colors.transparent,
                padding: const EdgeInsets.symmetric(vertical: 16),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
              ),
              child: _isLoading
                  ? const SizedBox(
                      width: 22,
                      height: 22,
                      child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                    )
                  : Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.save_rounded, color: Colors.white, size: 20),
                        const SizedBox(width: 8),
                        Text(
                          "រក្សាទុកអ្នកប្រើប្រាស់ (Save)",
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontSize: 15,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
            ),
          ),
        ),
      ],
    );
  }

  // ----------------------------------------------------
  // Helpers
  // ----------------------------------------------------
  Widget _buildInputLabel(String label) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Text(
        label,
        style: GoogleFonts.kantumruyPro(
          color: AppTheme.textPrimary.withValues(alpha: 0.85),
          fontSize: 13,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }

  Widget _buildTextField({
    required TextEditingController controller,
    required String hintText,
    required IconData icon,
    bool obscureText = false,
    Widget? suffixIcon,
    TextInputType keyboardType = TextInputType.text,
    String? Function(String?)? validator,
  }) {
    return TextFormField(
      controller: controller,
      obscureText: obscureText,
      keyboardType: keyboardType,
      validator: validator,
      style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 14),
      decoration: InputDecoration(
        filled: true,
        fillColor: AppTheme.textPrimary.withValues(alpha: 0.05),
        hintText: hintText,
        hintStyle: GoogleFonts.kantumruyPro(
          color: AppTheme.textPrimary.withValues(alpha: 0.35),
          fontSize: 13,
        ),
        prefixIcon: Icon(icon, color: AppTheme.textPrimary.withValues(alpha: 0.4), size: 18),
        suffixIcon: suffixIcon,
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide(color: AppTheme.textPrimary.withValues(alpha: 0.1)),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide(color: AppTheme.textPrimary.withValues(alpha: 0.08)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide(color: AppTheme.primaryLight, width: 1.5),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: const BorderSide(color: Colors.redAccent),
        ),
      ),
    );
  }

  Widget _buildDropdown({
    required String value,
    required List<String> items,
    required ValueChanged<String?> onChanged,
  }) {
    final selectedVal = items.contains(value) ? value : items.first;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14),
      decoration: BoxDecoration(
        color: AppTheme.textPrimary.withValues(alpha: 0.05),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.08)),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<String>(
          value: selectedVal,
          isExpanded: true,
          dropdownColor: const Color(0xFF1E2235),
          icon: Icon(Icons.arrow_drop_down_rounded, color: AppTheme.textPrimary.withValues(alpha: 0.5)),
          style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 13),
          items: items.map((item) {
            return DropdownMenuItem<String>(
              value: item,
              child: Text(item, overflow: TextOverflow.ellipsis),
            );
          }).toList(),
          onChanged: onChanged,
        ),
      ),
    );
  }
}
