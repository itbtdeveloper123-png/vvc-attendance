import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';

class SendNotificationScreen extends StatefulWidget {
  const SendNotificationScreen({super.key});

  @override
  State<SendNotificationScreen> createState() => _SendNotificationScreenState();
}

class _SendNotificationScreenState extends State<SendNotificationScreen> {
  final ApiService _apiService = ApiService();
  final _formKey = GlobalKey<FormState>();

  String _recipientType = 'all';
  final TextEditingController _titleController = TextEditingController();
  final TextEditingController _messageController = TextEditingController();
  DateTime? _expiryDate;

  List<String> _selectedRoles = [];
  List<String> _selectedUsers = [];

  List<String> _availableRoles = [];
  List<Map<String, dynamic>> _availableUsers = [];

  bool _isLoading = false;
  bool _isLoadingData = false;

  @override
  void initState() {
    super.initState();
    _fetchMetaData();
  }

  Future<void> _fetchMetaData() async {
    setState(() => _isLoadingData = true);
    try {
      final roleRes = await _apiService.fetchAppConfig();
      if (roleRes['success'] == true) {
        // We can extract roles from users instead for accuracy
      }
      
      final userRes = await _apiService.fetchUsers();
      if (userRes['success'] == true) {
        final List users = userRes['users'] ?? [];
        final roles = users.map((e) => e['system_role']?.toString() ?? '').where((e) => e.isNotEmpty).toSet().toList();
        
        setState(() {
          _availableUsers = List<Map<String, dynamic>>.from(users);
          _availableRoles = roles;
        });
      }
    } catch (_) {}
    setState(() => _isLoadingData = false);
  }

  Future<void> _selectExpiryDate() async {
    final DateTime? picked = await showDatePicker(
      context: context,
      initialDate: DateTime.now().add(const Duration(days: 7)),
      firstDate: DateTime.now(),
      lastDate: DateTime.now().add(const Duration(days: 365)),
    );
    if (picked != null) {
      setState(() {
        _expiryDate = picked;
      });
    }
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    
    if (_recipientType == 'role' && _selectedRoles.isEmpty) {
      _showError("សូមជ្រើសរើសតួនាទីយ៉ាងហោចណាស់មួយ");
      return;
    }
    if (_recipientType == 'user' && _selectedUsers.isEmpty) {
      _showError("សូមជ្រើសរើសអ្នកប្រើប្រាស់យ៉ាងហោចណាស់ម្នាក់");
      return;
    }

    setState(() => _isLoading = true);

    try {
      final Map<String, dynamic> data = {
        'recipient_type': _recipientType,
        'notification_title': _titleController.text,
        'notification_message': _messageController.text,
        'target_roles': _selectedRoles.join(','),
        'target_users': _selectedUsers.join(','),
        'expiry_date': _expiryDate?.toIso8601String(),
      };

      final result = await _apiService.sendNotification(data);

      if (result['success'] == true || result['status'] == 'success') {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text("ផ្ញើបានជោគជ័យ"), backgroundColor: Colors.green),
        );
        Navigator.pop(context);
      } else {
        _showError(result['message'] ?? "បរាជ័យ");
      }
    } catch (e) {
      _showError("កំហុស: $e");
    } finally {
      setState(() => _isLoading = false);
    }
  }

  void _showError(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(msg), backgroundColor: Colors.red),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        leading: IconButton(
          icon: Icon(Icons.close_rounded, color: AppTheme.textPrimary),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          "ផ្ញើការជូនដំណឹង",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontWeight: FontWeight.bold,
          ),
        ),
      ),
      body: _isLoadingData 
          ? const Center(child: CircularProgressIndicator(color: Colors.blueAccent))
          : SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              FadeInDown(duration: const Duration(milliseconds: 500), child: _buildSectionTitle("អ្នកទទួល")),
              const SizedBox(height: 12),
              _buildRecipientDropdown(),
              
              if (_recipientType == 'role') ...[
                const SizedBox(height: 20),
                _buildMultiSelectRoles(),
              ],
              
              if (_recipientType == 'user') ...[
                const SizedBox(height: 20),
                _buildMultiSelectUsers(),
              ],

              const SizedBox(height: 24),
              _buildSectionTitle("ប្រធានបទ"),
              const SizedBox(height: 12),
              _buildTextField(_titleController, "បញ្ចូលចំណងជើង...", Icons.title_rounded),
              
              const SizedBox(height: 24),
              _buildSectionTitle("ខ្លឹមសារ"),
              const SizedBox(height: 12),
              _buildTextField(_messageController, "បញ្ចូលសារជូនដំណឹងរបស់អ្នក...", Icons.message_rounded, maxLines: 5),
              
              const SizedBox(height: 24),
              _buildSectionTitle("ថ្ងៃផុតកំណត់ (ស្រេចចិត្ត)"),
              const SizedBox(height: 12),
              _buildDatePicker(),
              
              const SizedBox(height: 48),
              _buildSubmitButton(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildRecipientDropdown() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      decoration: BoxDecoration(
        color: AppTheme.textPrimary.withValues(alpha: 0.05),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.10)),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<String>(
          isExpanded: true,
          value: _recipientType,
          dropdownColor: const Color(0xFF1E293B),
          style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary),
          items: const [
            DropdownMenuItem(value: 'all', child: Text("ទាំងអស់ (All Users)")),
            DropdownMenuItem(value: 'role', child: Text("តាមតួនាទី (By Group/Role)")),
            DropdownMenuItem(value: 'user', child: Text("បុគ្គលជាក់លាក់ (Specific Users)")),
          ],
          onChanged: (val) => setState(() {
            _recipientType = val!;
            if (_recipientType == 'all') { _selectedRoles = []; _selectedUsers = []; }
          }),
        ),
      ),
    );
  }

  Widget _buildMultiSelectRoles() {
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: _availableRoles.map((role) {
        final isSelected = _selectedRoles.contains(role);
        return FilterChip(
          label: Text(role),
          selected: isSelected,
          onSelected: (selected) {
            setState(() {
              if (selected) {
                _selectedRoles.add(role);
              } else {
                _selectedRoles.remove(role);
              }
            });
          },
          selectedColor: Colors.blueAccent.withValues(alpha: 0.3),
          checkmarkColor: Colors.blueAccent,
          backgroundColor: AppTheme.textPrimary.withValues(alpha: 0.05),
          labelStyle: GoogleFonts.kantumruyPro(color: isSelected ? Colors.blueAccent : AppTheme.textPrimary),
        );
      }).toList(),
    );
  }

  Widget _buildMultiSelectUsers() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTheme.textPrimary.withValues(alpha: 0.05),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.10)),
      ),
      child: Column(
        children: _availableUsers.take(15).map((u) {
          final id = u['employee_id']?.toString() ?? '';
          final name = u['name'] ?? 'Unknown';
          final isSelected = _selectedUsers.contains(id);
          return CheckboxListTile(
            title: Text(name, style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 14)),
            subtitle: Text("ID: $id", style: GoogleFonts.inter(color: AppTheme.textSecondary, fontSize: 11)),
            value: isSelected,
            activeColor: Colors.blueAccent,
            onChanged: (val) {
              setState(() {
                if (val == true) {
                  _selectedUsers.add(id);
                } else {
                  _selectedUsers.remove(id);
                }
              });
            },
            controlAffinity: ListTileControlAffinity.leading,
            contentPadding: EdgeInsets.zero,
          );
        }).toList(),
      ),
    );
  }

  Widget _buildDatePicker() {
    return GestureDetector(
      onTap: _selectExpiryDate,
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: AppTheme.textPrimary.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.10)),
        ),
        child: Row(
          children: [
            const Icon(Icons.calendar_today_rounded, color: Colors.blueAccent, size: 20),
            const SizedBox(width: 12),
            Text(
              _expiryDate == null ? "ជ្រើសរើសថ្ងៃ" : "${_expiryDate!.day}/${_expiryDate!.month}/${_expiryDate!.year}",
              style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary.withValues(alpha: 0.70)),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSubmitButton() {
    return SizedBox(
      width: double.infinity,
      height: 60,
      child: ElevatedButton(
        onPressed: _isLoading ? null : _submit,
        style: ElevatedButton.styleFrom(
          backgroundColor: Colors.blueAccent,
          foregroundColor: AppTheme.textPrimary,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
          elevation: 8,
          shadowColor: Colors.blueAccent.withValues(alpha: 0.5),
        ),
        child: _isLoading
            ? CircularProgressIndicator(color: AppTheme.textPrimary)
            : Text("ផ្ញើឥឡូវនេះ", style: GoogleFonts.kantumruyPro(fontSize: 18, fontWeight: FontWeight.bold)),
      ),
    );
  }

  Widget _buildSectionTitle(String title) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8.0),
      child: Text(title, style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 16, fontWeight: FontWeight.w600)),
    );
  }

  Widget _buildTextField(TextEditingController controller, String hint, IconData icon, {int maxLines = 1}) {
    return TextFormField(
      controller: controller,
      maxLines: maxLines,
      style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary),
      decoration: InputDecoration(
        hintText: hint,
        hintStyle: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary.withValues(alpha: 0.24)),
        prefixIcon: Icon(icon, color: Colors.blueAccent, size: 20),
        filled: true,
        fillColor: AppTheme.textPrimary.withValues(alpha: 0.05),
        enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: BorderSide(color: AppTheme.textPrimary.withValues(alpha: 0.10))),
        focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(16), borderSide: const BorderSide(color: Colors.blueAccent)),
      ),
      validator: (val) => val == null || val.isEmpty ? "សូមបំពេញចន្លោះនេះ" : null,
    );
  }
}
