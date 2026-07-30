import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import '../utils/app_theme.dart';
import '../widgets/a5_paper_form.dart';
import '../widgets/app_widgets.dart';
import '../providers/user_provider.dart';
import 'package:intl/intl.dart';

/// A5 Request Form Screen - Test screen for A5 paper format with checkbox system
class A5RequestFormScreen extends StatefulWidget {
  const A5RequestFormScreen({super.key});

  @override
  State<A5RequestFormScreen> createState() => _A5RequestFormScreenState();
}

class _A5RequestFormScreenState extends State<A5RequestFormScreen> {
  String _selectedRequestType = '';
  final TextEditingController _reasonController = TextEditingController();
  final TextEditingController _commentsController = TextEditingController();
  final TextEditingController _approvedByController = TextEditingController();
  final TextEditingController _adminCommentController = TextEditingController();
  
  DateTime _requestDate = DateTime.now();
  DateTime? _approvalDate;

  @override
  void initState() {
    super.initState();
    _requestDate = DateTime.now();
  }

  @override
  void dispose() {
    _reasonController.dispose();
    _commentsController.dispose();
    _approvedByController.dispose();
    _adminCommentController.dispose();
    super.dispose();
  }

  void _fillSampleData() {
    setState(() {
      _selectedRequestType = 'leave';
      _reasonController.text = 'សូមស្នើសុំច្បាប់សម្រាកក្នុងការងារដោយសារមានកិច្ចការគ្រួសារសំខាន់។';
      _commentsController.text = 'នឹងត្រឡប់ធ្វើការវិញនៅថ្ងៃទី ១៥ ខែកក្កដា ។';
      _approvedByController.text = 'សោ សុខា';
      _approvalDate = DateTime.now();
      _adminCommentController.text = 'យល់ព្រមបន្ថែមថ្ងៃឈប់សម្រាក ១ ថ្ងៃ។';
    });
  }

  void _clearForm() {
    setState(() {
      _selectedRequestType = '';
      _reasonController.clear();
      _commentsController.clear();
      _approvedByController.clear();
      _adminCommentController.clear();
      _approvalDate = null;
    });
  }

  void _showInfo() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(
          'ព័ត៌មានសាកល្បង',
          style: GoogleFonts.koulen(),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildInfoItem('✅', 'ប្រើបានតាម A5 paper size (148mm x 210mm)'),
            _buildInfoItem('✅', 'ប្រើបានលើ mobile, tablet, និង desktop'),
            _buildInfoItem('✅', 'មានប្រព័ន្ធ checkbox សម្រាប់ជ្រើសរើសប្រភេទសំណើ'),
            _buildInfoItem('✅', 'សម្រាប់បោះពុម្ពដោយចុច print icon'),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(
              'បិទ',
              style: GoogleFonts.battambang(),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoItem(String icon, String text) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(icon),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: GoogleFonts.battambang(fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final user = Provider.of<UserProvider>(context);

    return Scaffold(
      appBar: AppBar(
        title: Text(
          'A5 Request Form Test',
          style: GoogleFonts.koulen(),
        ),
        backgroundColor: AppTheme.primary,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline),
            onPressed: _showInfo,
          ),
        ],
      ),
      body: AppBackgroundShell(
        child: SingleChildScrollView(
          padding: EdgeInsets.all(AppResponsive.horizontalPadding(context)),
          child: Column(
            children: [
              // Action buttons
              _buildActionButtons(),
              
              const SizedBox(height: 20),
              
              // A5 Form
              A5PaperForm(
                title: 'សំណើសុំសេវា',
                subtitle: 'SERVICE REQUEST FORM',
                onPrint: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(
                        'បោះពុម្ព functionality នឹងត្រូវបានបន្ថែមនៅពេលក្រោយ',
                        style: GoogleFonts.battambang(),
                      ),
                    ),
                  );
                },
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Request Type Section
                    A5FormSection(
                      title: 'ប្រភេទសំណើ (Request Type)',
                      icon: Icons.checklist,
                      isRequired: true,
                      children: [
                        A5RequestTypeCheckboxGroup(
                          selectedValue: _selectedRequestType,
                          onChanged: (value) {
                            setState(() {
                              _selectedRequestType = value;
                            });
                          },
                        ),
                      ],
                    ),
                    
                    // Employee Information Section
                    A5FormSection(
                      title: 'ព័ត៌មានបុគ្គលិក (Employee Information)',
                      icon: Icons.person,
                      children: [
                        A5FormRow(
                          children: [
                            A5FormField(
                              label: 'ឈ្មោះ (Name)',
                              child: A5TextValue(
                                text: user.name ?? '',
                                placeholder: '_____________________',
                              ),
                            ),
                            A5FormField(
                              label: 'លេខសម្គាល់ (Employee ID)',
                              child: A5TextValue(
                                text: user.employeeId ?? '',
                                placeholder: '_____________________',
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        A5FormRow(
                          children: [
                            A5FormField(
                              label: 'ផ្នែក (Department)',
                              child: A5TextValue(
                                text: user.department ?? '',
                                placeholder: '_____________________',
                              ),
                            ),
                            A5FormField(
                              label: 'មុខតំណែង (Position)',
                              child: A5TextValue(
                                text: user.position ?? '',
                                placeholder: '_____________________',
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                    
                    // Request Details Section
                    A5FormSection(
                      title: 'ព័ត៌មានសំណើ (Request Details)',
                      icon: Icons.calendar_today,
                      children: [
                        A5FormRow(
                          children: [
                            A5FormField(
                              label: 'កាលបរិច្ឆេទស្នើ (Request Date)',
                              child: A5TextValue(
                                text: DateFormat('yyyy-MM-dd').format(_requestDate),
                                placeholder: '_____________________',
                              ),
                            ),
                            A5FormField(
                              label: 'ស្ថានភាព (Status)',
                              child: const A5StatusBadge(status: 'Pending'),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        A5FormField(
                          label: 'មូលហេតុ (Reason)',
                          child: Container(
                            height: 80,
                            decoration: BoxDecoration(
                              color: AppTheme.fieldFill,
                              border: Border.all(color: AppTheme.fieldBorder),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: TextField(
                              controller: _reasonController,
                              maxLines: null,
                              expands: true,
                              style: GoogleFonts.battambang(
                                fontSize: 12,
                                color: AppTheme.textPrimary,
                              ),
                              decoration: const InputDecoration(
                                hintText: '_____________________________________________________',
                                border: InputBorder.none,
                                contentPadding: EdgeInsets.all(10),
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                    
                    // Additional Notes Section
                    A5FormSection(
                      title: 'កំណត់សម្គាល់ (Additional Notes)',
                      icon: Icons.note,
                      children: [
                        A5FormField(
                          label: 'មតិយោបល់ (Comments)',
                          child: Container(
                            height: 60,
                            decoration: BoxDecoration(
                              color: AppTheme.fieldFill,
                              border: Border.all(color: AppTheme.fieldBorder),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: TextField(
                              controller: _commentsController,
                              maxLines: null,
                              expands: true,
                              style: GoogleFonts.battambang(
                                fontSize: 12,
                                color: AppTheme.textPrimary,
                              ),
                              decoration: const InputDecoration(
                                hintText: '_____________________________________________________',
                                border: InputBorder.none,
                                contentPadding: EdgeInsets.all(10),
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                    
                    // Approval Section
                    A5FormSection(
                      title: 'ការយល់ព្រម (Approval)',
                      icon: Icons.verified,
                      children: [
                        A5FormRow(
                          children: [
                            A5FormField(
                              label: 'អ្នកយល់ព្រម (Approved By)',
                              child: Container(
                                decoration: BoxDecoration(
                                  color: AppTheme.fieldFill,
                                  border: Border.all(color: AppTheme.fieldBorder),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: TextField(
                                  controller: _approvedByController,
                                  style: GoogleFonts.battambang(
                                    fontSize: 12,
                                    color: AppTheme.textPrimary,
                                  ),
                                  decoration: const InputDecoration(
                                    hintText: '_____________________',
                                    border: InputBorder.none,
                                    contentPadding: EdgeInsets.all(10),
                                  ),
                                ),
                              ),
                            ),
                            A5FormField(
                              label: 'កាលបរិច្ឆេទយល់ព្រម (Approval Date)',
                              child: A5TextValue(
                                text: _approvalDate != null
                                    ? DateFormat('yyyy-MM-dd').format(_approvalDate!)
                                    : '',
                                placeholder: '_____________________',
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        A5FormField(
                          label: 'មតិយោបល់របស់អ្នកគ្រប់គ្រង (Admin Comment)',
                          child: Container(
                            height: 60,
                            decoration: BoxDecoration(
                              color: AppTheme.fieldFill,
                              border: Border.all(color: AppTheme.fieldBorder),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: TextField(
                              controller: _adminCommentController,
                              maxLines: null,
                              expands: true,
                              style: GoogleFonts.battambang(
                                fontSize: 12,
                                color: AppTheme.textPrimary,
                              ),
                              decoration: const InputDecoration(
                                hintText: '_____________________________________________________',
                                border: InputBorder.none,
                                contentPadding: EdgeInsets.all(10),
                              ),
                            ),
                          ),
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

  Widget _buildActionButtons() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(8),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.1),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'សកម្មភាព (Actions)',
            style: GoogleFonts.koulen(
              fontSize: 16,
              color: AppTheme.primary,
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _fillSampleData,
                  icon: const Icon(Icons.edit, size: 20),
                  label: Text(
                    'បំពេញទិន្នន័យឧទាហរណ៍',
                    style: GoogleFonts.battambang(fontSize: 12),
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.primary,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                  ),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: _clearForm,
                  icon: const Icon(Icons.clear, size: 20),
                  label: Text(
                    'សម្អាត',
                    style: GoogleFonts.battambang(fontSize: 12),
                  ),
                  style: OutlinedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 12),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}