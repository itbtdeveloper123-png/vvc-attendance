import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

class PayrollAdminScreen extends StatefulWidget {
  const PayrollAdminScreen({super.key});

  @override
  State<PayrollAdminScreen> createState() => _PayrollAdminScreenState();
}

class _PayrollAdminScreenState extends State<PayrollAdminScreen> {
  final ApiService _api = ApiService();
  List<dynamic> _allPayroll = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadPayroll();
  }

  Future<void> _loadPayroll() async {
    setState(() => _isLoading = true);
    try {
      final res = await _api.fetchAllPayroll();
      if (res['success'] == true) {
        setState(() {
          _allPayroll = res['data'] ?? [];
          _isLoading = false;
        });
      } else {
        setState(() => _isLoading = false);
        _showError(res['message'] ?? 'Error fetching payroll');
      }
    } catch (e) {
      setState(() => _isLoading = false);
      _showError('Connection error: $e');
    }
  }

  void _showError(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(msg), backgroundColor: Colors.redAccent),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        title: Text(
          "ព័ត៌មានប្រាក់បៀវត្ស (HR)",
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        centerTitle: true,
        backgroundColor: Colors.transparent,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _loadPayroll,
          ),
        ],
      ),
      body: AppBackgroundShell(
        child: _isLoading
            ? const Center(child: CircularProgressIndicator())
            : _allPayroll.isEmpty
                ? const Center(child: Text("មិនទាន់មានទិន្នន័យ", style: TextStyle(color: Colors.white54)))
                : ListView.builder(
                    padding: const EdgeInsets.all(16),
                    itemCount: _allPayroll.length,
                    itemBuilder: (context, index) {
                      final item = _allPayroll[index];
                      final name = item['name'] ?? 'N/A';
                      final eid = item['employee_id'] ?? 'N/A';
                      final pos = item['position'] ?? '';
                      final double salary = double.tryParse(item['salary']?.toString() ?? '0') ?? 0.0;
                      
                      return FadeInUp(
                        duration: Duration(milliseconds: 300 + (index * 50)),
                        child: Container(
                          margin: const EdgeInsets.only(bottom: 12),
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            color: AppTheme.bgCard,
                            borderRadius: BorderRadius.circular(20),
                            border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.05)),
                          ),
                          child: Row(
                            children: [
                              Container(
                                width: 50,
                                height: 50,
                                decoration: BoxDecoration(
                                  color: AppTheme.primary.withValues(alpha: 0.1),
                                  borderRadius: BorderRadius.circular(15),
                                ),
                                child: Icon(Icons.person_rounded, color: AppTheme.primary),
                              ),
                              const SizedBox(width: 16),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      name,
                                      style: GoogleFonts.kantumruyPro(
                                        color: AppTheme.textPrimary,
                                        fontWeight: FontWeight.bold,
                                        fontSize: 15,
                                      ),
                                    ),
                                    Text(
                                      "ID: $eid | $pos",
                                      style: GoogleFonts.kantumruyPro(
                                        color: AppTheme.textPrimary.withValues(alpha: 0.5),
                                        fontSize: 12,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                              Column(
                                crossAxisAlignment: CrossAxisAlignment.end,
                                children: [
                                  Text(
                                    "\$${salary.toStringAsFixed(2)}",
                                    style: GoogleFonts.inter(
                                      color: Colors.greenAccent,
                                      fontWeight: FontWeight.bold,
                                      fontSize: 16,
                                    ),
                                  ),
                                  Text(
                                    "ប្រាក់ខែគោល",
                                    style: GoogleFonts.kantumruyPro(
                                      color: AppTheme.textPrimary.withValues(alpha: 0.3),
                                      fontSize: 10,
                                    ),
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
      ),
    );
  }
}
