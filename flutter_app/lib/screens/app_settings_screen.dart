import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

/// App Settings Screen - Admin panel for controlling feature visibility
/// Allows HRM and Admin users to control which features are shown to different roles
class AppSettingsScreen extends StatefulWidget {
  const AppSettingsScreen({super.key});

  @override
  State<AppSettingsScreen> createState() => _AppSettingsScreenState();
}

class _AppSettingsScreenState extends State<AppSettingsScreen> {
  final ApiService _api = ApiService();
  bool _isLoading = true;
  bool _isSaving = false;
  Map<String, dynamic> _settings = {};
  


  // Feature display names
  final Map<String, String> _featureNames = {
    'show_attendance_card': 'ស្កេនវត្តមាន',
    'show_outside_attendance_card': 'វត្តមានខាងក្រៅ',
    'show_product_analyzer_card': 'វិភាគផលិតផល',
    'show_training_quiz_card': 'ការប្រលងបណ្តាញ',
    'show_poll_voting_card': 'ការបោះឆ្នោត',
    'show_announcements_card': 'ការជូនដំណឹង',
    'show_meetings_card': 'កិច្ចប្រជុំ',
    'show_checklist_card': 'បញ្ជីពិនិត្យ',
    'show_daily_report_card': 'របាយការណ៍ប្រចាំថ្ងៃ',
    'show_mission_card': 'បេសកកម្ម',
    'show_trip_card': 'ការធ្វើដំណើរ',
    'show_user_management_card': 'គ្រប់គ្រងអ្នកប្រើប្រាស់',
    'show_request_form_card': 'សំណើរ',
    'show_reports_card': 'របាយការណ៍',
    'show_material_request_card': 'សំណើរសម្ភារៈ',
    'show_notification_card': 'ការជូនដំណឹង',
    'show_payroll_card': 'ប្រាក់បៀវត្ស',
    'show_document_scanner_card': 'ស្កេនឯកសារ',
  };

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    final user = context.read<UserProvider>();
    try {
      final response = await _api.get('/app-settings');
      
      if (response['settings'] != null) {
        setState(() {
          _settings = Map<String, dynamic>.from(response['settings']);
          _isLoading = false;
        });
      } else {
        // Use local settings if API fails
        setState(() {
          _settings = Map<String, dynamic>.from(user.settings);
          _isLoading = false;
        });
      }
    } catch (e) {
      // Fallback to local settings
      setState(() {
        _settings = Map<String, dynamic>.from(user.settings);
        _isLoading = false;
      });
    }
  }

  Future<void> _saveSettings() async {
    final user = context.read<UserProvider>();
    setState(() => _isSaving = true);
    
    try {
      final response = await _api.post('/app-settings', {
        'settings': json.encode(_settings),
      });
      
      if (response['success'] == true) {
        // Update local user settings
        user.updateSettings(_settings);
        
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                'រក្សាទុកការកំណត់ដោយជោគជ័យ',
                style: GoogleFonts.kantumruyPro(),
              ),
              backgroundColor: Colors.green,
            ),
          );
        }
      } else {
        throw Exception('Failed to save settings');
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'បរាជ័យក្នុងការរក្សាទុក: $e',
              style: GoogleFonts.kantumruyPro(),
            ),
            backgroundColor: Colors.red,
          ),
        );
      }
    } finally {
      setState(() => _isSaving = false);
    }
  }

  bool _getSettingValue(String key) {
    return _settings[key] == '1' || _settings[key] == true;
  }

  void _toggleSetting(String key, bool value) {
    setState(() {
      _settings[key] = value ? '1' : '0';
    });
  }

  @override
  Widget build(BuildContext context) {
    final user = context.read<UserProvider>();
    
    // Only allow HRM and Admin
    if (!user.isHRM && !user.isAdmin) {
      return Scaffold(
        appBar: VvcAppBar(
          title: Text(
            'ការកំណត់កម្មវិធី',
            style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
          ),
        ),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.lock, size: 64, color: Colors.grey),
              const SizedBox(height: 16),
              Text(
                'អ្នកមិនមានសិទ្ធិចូលទៅកាន់កាប់ការកំណត់នេះទេ',
                style: GoogleFonts.kantumruyPro(fontSize: 16),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      );
    }

    return Scaffold(
      appBar: VvcAppBar(
        title: Text(
          'ការកំណត់កម្មវិធី',
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        actions: [
          if (!_isLoading && !_isSaving)
            IconButton(
              icon: const Icon(Icons.save),
              onPressed: _saveSettings,
              tooltip: 'រក្សាទុក',
            ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : _isSaving
              ? const Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      CircularProgressIndicator(),
                      SizedBox(height: 16),
                      Text('កំពុងរក្សាទុក...'),
                    ],
                  ),
                )
              : _buildSettingsContent(),
    );
  }

  Widget _buildSettingsContent() {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _buildSectionHeader('ការកំណត់មុខងារតាមតួនាទី'),
        const SizedBox(height: 16),
        
        // Document Scanner Section (Highlighted)
        _buildFeatureSection(
          'ស្កេនឯកសារ (Document Scanner)',
          Icons.document_scanner,
          Colors.orange,
          ['show_document_scanner_card'],
        ),
        
        const SizedBox(height: 24),
        
        // Core Features
        _buildFeatureSection(
          'មុខងារសំខាន់ៗ',
          Icons.star,
          AppTheme.primary,
          [
            'show_attendance_card',
            'show_outside_attendance_card',
            'show_announcements_card',
            'show_meetings_card',
          ],
        ),
        
        const SizedBox(height: 24),
        
        // Reporting Features
        _buildFeatureSection(
          'មុខងាររបាយការណ៍',
          Icons.assessment,
          Colors.blue,
          [
            'show_daily_report_card',
            'show_reports_card',
            'show_employee_report_card',
          ],
        ),
        
        const SizedBox(height: 24),
        
        // Communication Features
        _buildFeatureSection(
          'មុខងារទំនាក់ទំនង',
          Icons.chat,
          Colors.green,
          [
            'show_notification_card',
            'show_poll_voting_card',
          ],
        ),
        
        const SizedBox(height: 24),
        
        // HR Features
        _buildFeatureSection(
          'មុខងារ HRM',
          Icons.people,
          Colors.purple,
          [
            'show_user_management_card',
            'show_request_form_card',
            'show_payroll_card',
          ],
        ),
        
        const SizedBox(height: 24),
        
        // Additional Features
        _buildFeatureSection(
          'មុខងារផ្សេងៗ',
          Icons.apps,
          Colors.teal,
          [
            'show_product_analyzer_card',
            'show_training_quiz_card',
            'show_checklist_card',
            'show_mission_card',
            'show_trip_card',
            'show_material_request_card',
          ],
        ),
        
        const SizedBox(height: 32),
        
        // Info Card
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: Colors.blue.withValues(alpha: 0.1),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: Colors.blue.withValues(alpha: 0.3)),
          ),
          child: Row(
            children: [
              const Icon(Icons.info_outline, color: Colors.blue),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  'ការកំណត់ទាំងនេះត្រូវបានអនុវត្តតាមតួនាទីរបស់អ្នកប្រើប្រាស់។ '
                  'ការផ្លាស់ប្តូរនឹងមានប្រសិទ្ធិភ្លាមៗសម្រាប់អ្នកប្រើប្រាស់ដែលបានកំណត់។',
                  style: GoogleFonts.kantumruyPro(fontSize: 12),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildSectionHeader(String title) {
    return Text(
      title,
      style: GoogleFonts.kantumruyPro(
        fontSize: 18,
        fontWeight: FontWeight.bold,
        color: AppTheme.textPrimary,
      ),
    );
  }

  Widget _buildFeatureSection(String title, IconData icon, Color color, List<String> features) {
    return Container(
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.borderColor),
      ),
      child: Column(
        children: [
          // Section Header
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.1),
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(16),
                topRight: Radius.circular(16),
              ),
            ),
            child: Row(
              children: [
                Icon(icon, color: color),
                const SizedBox(width: 12),
                Text(
                  title,
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: color,
                  ),
                ),
              ],
            ),
          ),
          
          // Feature Toggles
          ...features.map((feature) => _buildFeatureToggle(feature)),
        ],
      ),
    );
  }

  Widget _buildFeatureToggle(String featureKey) {
    final featureName = _featureNames[featureKey] ?? featureKey;
    final isEnabled = _getSettingValue(featureKey);
    
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Row(
        children: [
          Expanded(
            child: Text(
              featureName,
              style: GoogleFonts.kantumruyPro(
                fontSize: 14,
                color: AppTheme.textPrimary,
              ),
            ),
          ),
          Switch(
            value: isEnabled,
            onChanged: (value) => _toggleSetting(featureKey, value),
            activeTrackColor: AppTheme.primary,
          ),
        ],
      ),
    );
  }
}
