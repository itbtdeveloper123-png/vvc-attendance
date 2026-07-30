import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import '../models/form_template.dart';
import '../services/form_builder_service.dart';
import '../services/api_service.dart';
import '../widgets/dynamic_form_renderer.dart';
import '../widgets/a5_paper_form.dart';
import '../utils/app_theme.dart';
import '../providers/user_provider.dart';
import '../widgets/app_widgets.dart';

class DynamicFormScreen extends StatefulWidget {
  final int templateId;
  final Map<String, dynamic>? initialData;

  const DynamicFormScreen({
    super.key,
    required this.templateId,
    this.initialData,
  });

  @override
  State<DynamicFormScreen> createState() => _DynamicFormScreenState();
}

class _DynamicFormScreenState extends State<DynamicFormScreen> {
  final FormBuilderService _formBuilderService = FormBuilderService(
    baseUrl: ApiService.baseUrl.replaceAll('/api.php', ''),
  );

  FormTemplate? _template;
  bool _isLoading = true;
  String? _errorMessage;
  bool _isSubmitting = false;

  @override
  void initState() {
    super.initState();
    _loadTemplate();
  }

  Future<void> _loadTemplate() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final template = await _formBuilderService.getTemplate(widget.templateId);
      
      if (mounted) {
        setState(() {
          _template = template;
          _isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLoading = false;
          _errorMessage = e.toString();
        });
      }
    }
  }

  Future<void> _handleSubmit(Map<String, dynamic> formData) async {
    setState(() {
      _isSubmitting = true;
    });

    try {
      // Add user information to form data
      final user = Provider.of<UserProvider>(context, listen: false);
      formData['user_id'] = int.tryParse(user.employeeId ?? '') ?? 0;
      formData['requester_name'] = user.name;
      formData['department'] = user.department;
      formData['position'] = user.position;
      formData['branch'] = user.branch;

      // Create submission
      await _formBuilderService.createSubmission(
        templateId: widget.templateId,
        userId: int.tryParse(user.employeeId ?? ''),
        submissionData: formData,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'បានដាក់ស្នើដោយជោគជ័យ!',
              style: GoogleFonts.battambang(),
            ),
            backgroundColor: Colors.green,
          ),
        );
        Navigator.pop(context);
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isSubmitting = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'កំហុស: $e',
              style: GoogleFonts.battambang(),
            ),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(
          _template?.name ?? 'សំណើ',
          style: GoogleFonts.koulen(),
        ),
        backgroundColor: AppTheme.primary,
        elevation: 0,
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return Center(
        child: CircularProgressIndicator(color: AppTheme.primary),
      );
    }

    if (_errorMessage != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 64, color: Colors.red),
            const SizedBox(height: 16),
            Text(
              'កំហុសក្នុងការផ្ទុកសំណើ',
              style: GoogleFonts.battambang(fontSize: 16),
            ),
            const SizedBox(height: 8),
            Text(
              _errorMessage!,
              style: GoogleFonts.battambang(fontSize: 14, color: Colors.grey),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _loadTemplate,
              child: Text('ព្យាយាមម្តងទៀត', style: GoogleFonts.battambang()),
            ),
          ],
        ),
      );
    }

    if (_template == null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.folder_open, size: 64, color: Colors.grey),
            const SizedBox(height: 16),
            Text(
              'រកមិនឃើញ Template',
              style: GoogleFonts.battambang(fontSize: 16),
            ),
          ],
        ),
      );
    }

    return AppBackgroundShell(
      child: SingleChildScrollView(
        padding: EdgeInsets.all(AppResponsive.horizontalPadding(context)),
        child: A5PaperForm(
          title: _template!.name,
          subtitle: _template!.description.isNotEmpty ? _template!.description : null,
          onBack: () => Navigator.pop(context),
          child: DynamicFormRenderer(
            template: _template!,
            initialData: widget.initialData,
            onSubmit: _isSubmitting ? (_) {} : _handleSubmit,
          ),
        ),
      ),
    );
  }
}
