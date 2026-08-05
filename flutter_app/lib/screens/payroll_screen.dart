import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import 'package:local_auth/local_auth.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../services/payslip_pdf_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

class PayrollScreen extends StatefulWidget {
  const PayrollScreen({super.key});

  @override
  State<PayrollScreen> createState() => _PayrollScreenState();
}

class _PayrollScreenState extends State<PayrollScreen> {
  final ApiService _api = ApiService();
  final LocalAuthentication _localAuth = LocalAuthentication();
  List<dynamic> _history = [];
  double _baseSalary = 0;
  bool _isLoading = true;
  bool _isUnlocked = false;
  bool _isAuthenticating = false;
  String? _authError;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback(
      (_) => _preparePayrollAccess(),
    );
  }

  Future<void> _preparePayrollAccess() async {
    try {
      final userProvider = context.read<UserProvider>();
      await userProvider.refreshConfig();
      final requiresBiometric = userProvider.canShow(
        'payroll_biometric_required',
        defaultValue: true,
      );

      if (!requiresBiometric) {
        if (!mounted) return;
        setState(() {
          _isUnlocked = true;
          _isLoading = true;
          _authError = null;
        });
        await _loadData();
        return;
      }
    } catch (_) {
      // Keep salary protected if config cannot be refreshed.
    }

    await _unlockPayroll();
  }

  Future<void> _unlockPayroll() async {
    if (_isAuthenticating) return;
    setState(() {
      _isAuthenticating = true;
      _authError = null;
    });

    try {
      final canCheckBiometrics = await _localAuth.canCheckBiometrics;
      final isDeviceSupported = await _localAuth.isDeviceSupported();

      if (!canCheckBiometrics && !isDeviceSupported) {
        if (!mounted) return;
        setState(() {
          _isAuthenticating = false;
          _isLoading = false;
          _authError =
              "ឧបករណ៍នេះមិនគាំទ្រ Face ID, ស្នាមម្រាមដៃ ឬលេខសម្ងាត់ទេ។";
        });
        return;
      }

      final didAuthenticate = await _localAuth.authenticate(
        localizedReason: "សូមផ្ទៀងផ្ទាត់អត្តសញ្ញាណ ដើម្បីមើលប្រាក់ខែរបស់អ្នក",
        options: const AuthenticationOptions(
          biometricOnly: false,
          stickyAuth: true,
        ),
      );

      if (!mounted) return;

      if (!didAuthenticate) {
        setState(() {
          _isAuthenticating = false;
          _isLoading = false;
          _authError = "មិនអាចបើកមើលប្រាក់ខែបានទេ។ សូមសាកល្បងម្ដងទៀត។";
        });
        return;
      }

      setState(() {
        _isUnlocked = true;
        _isAuthenticating = false;
        _isLoading = true;
      });
      await _recordBiometricVerification();
      await _loadData();
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isAuthenticating = false;
        _isLoading = false;
        _authError =
            "ការផ្ទៀងផ្ទាត់មិនបានជោគជ័យ។ សូមពិនិត្យការកំណត់សុវត្ថិភាពទូរស័ព្ទ។";
      });
    }
  }

  Future<void> _recordBiometricVerification() async {
    try {
      await _api.recordPayrollBiometricVerification(platform: _platformLabel);
    } catch (_) {
      // Salary remains unlocked even if the audit record cannot be saved.
    }
  }

  String get _platformLabel {
    if (kIsWeb) return 'Web';
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
        return 'Android';
      case TargetPlatform.iOS:
        return 'iOS';
      case TargetPlatform.macOS:
        return 'macOS';
      case TargetPlatform.windows:
        return 'Windows';
      case TargetPlatform.linux:
        return 'Linux';
      case TargetPlatform.fuchsia:
        return 'Fuchsia';
    }
  }

  Future<void> _loadData() async {
    if (!_isUnlocked) return;
    setState(() => _isLoading = true);
    try {
      final res = await _api.fetchPayrollHistory();
      if (res['success'] == true) {
        if (mounted) {
          setState(() {
            _history = res['data'] ?? [];
            _baseSalary =
                double.tryParse(res['base_salary']?.toString() ?? '0') ?? 0;
            _isLoading = false;
          });
        }
      } else {
        if (mounted) setState(() => _isLoading = false);
      }
    } catch (e) {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return DynamicAppBarWrapper(
      title: "ព័ត៌មានប្រាក់បៀវត្ស",
      leading: IconButton(
        icon: const Icon(Icons.arrow_back_ios_new_rounded),
        onPressed: () => Navigator.pop(context),
      ),
      body: AppBackgroundShell(
        child: !_isUnlocked
            ? _buildLockedState()
            : _isLoading
            ? _buildShimmerList()
            : RefreshIndicator(
                onRefresh: _loadData,
                color: AppTheme.primary,
                child: _history.isEmpty ? _buildEmptyState() : _buildList(),
              ),
      ),
    );
  }

  Widget _buildLockedState() {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(28, 120, 28, 32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.account_balance_wallet_outlined,
              color: AppTheme.textPrimary.withValues(alpha: 0.12),
              size: 86,
            ),
            const SizedBox(height: 22),
            Text(
              "ព័ត៌មានប្រាក់ខែត្រូវបានការពារ",
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
                fontSize: 18,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              "សូមស្កេន Face ID / ស្នាមម្រាមដៃ ដើម្បីបង្ហាញទិន្នន័យ",
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.45),
                fontSize: 13,
                height: 1.5,
              ),
            ),
            const SizedBox(height: 30),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 20),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: BorderRadius.circular(24),
                border: Border.all(
                  color: AppTheme.primary.withValues(alpha: 0.12),
                ),
              ),
              child: Column(
                children: [
                  Text(
                    "ប្រាក់ខែគោលបច្ចុប្បន្ន",
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textSecondary,
                      fontSize: 14,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    "\$••••••",
                    style: GoogleFonts.poppins(
                      color: AppTheme.primary,
                      fontWeight: FontWeight.bold,
                      fontSize: 34,
                      letterSpacing: 0,
                    ),
                  ),
                ],
              ),
            ),
            if (_authError != null) ...[
              const SizedBox(height: 18),
              Text(
                _authError!,
                textAlign: TextAlign.center,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.redAccent,
                  fontSize: 12,
                  height: 1.5,
                ),
              ),
            ],
            const SizedBox(height: 24),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: _isAuthenticating ? null : _unlockPayroll,
                icon: _isAuthenticating
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.fingerprint_rounded),
                label: Text(
                  _isAuthenticating ? "កំពុងផ្ទៀងផ្ទាត់..." : "ស្កេនឥឡូវនេះ",
                  style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
                ),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.primary,
                  foregroundColor: Colors.white,
                  disabledBackgroundColor: AppTheme.primary.withValues(
                    alpha: 0.35,
                  ),
                  disabledForegroundColor: Colors.white70,
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(18),
                  ),
                  elevation: 0,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildShimmerList() {
    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(20, 110, 20, 20),
      itemCount: 5,
      itemBuilder: (context, index) => Padding(
        padding: const EdgeInsets.only(bottom: 20),
        child: AppShimmer(
          child: Container(
            height: 180,
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(28),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.account_balance_wallet_outlined,
            color: AppTheme.textPrimary.withValues(alpha: 0.10),
            size: 80,
          ),
          const SizedBox(height: 16),
          Text(
            "មិនទាន់មានទិន្នន័យបើកប្រាក់ខែទេ",
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary.withValues(alpha: 0.38),
            ),
          ),
          if (_baseSalary > 0) ...[
            const SizedBox(height: 32),
            Container(
              margin: const EdgeInsets.symmetric(horizontal: 40),
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: AppTheme.primary.withValues(alpha: 0.05),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: AppTheme.primary.withValues(alpha: 0.1),
                ),
              ),
              child: Column(
                children: [
                  Text(
                    "ប្រាក់ខែគោលបច្ចុប្បន្ន",
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textSecondary,
                      fontSize: 14,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    "\$${_baseSalary.toStringAsFixed(2)}",
                    style: GoogleFonts.poppins(
                      color: AppTheme.primary,
                      fontWeight: FontWeight.bold,
                      fontSize: 28,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildList() {
    return AnimationLimiter(
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(20, 110, 20, 20),
        physics: const AlwaysScrollableScrollPhysics(
          parent: BouncingScrollPhysics(),
        ),
        itemCount: _history.length,
        itemBuilder: (context, index) {
          final item = _history[index];
          return AnimationConfiguration.staggeredList(
            position: index,
            duration: const Duration(milliseconds: 500),
            child: SlideAnimation(
              verticalOffset: 50.0,
              child: FadeInAnimation(child: _buildPayrollCard(item)),
            ),
          );
        },
      ),
    );
  }

  Widget _buildPayrollCard(dynamic item) {
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    double baseSalary = double.tryParse(item['base_salary']?.toString() ?? '0') ?? 0;
    double otHours = double.tryParse(item['ot_hours']?.toString() ?? '0') ?? 0;
    double otPay = double.tryParse(item['ot_pay']?.toString() ?? '0') ?? 0;
    double allowances = double.tryParse(item['allowances']?.toString() ?? '0') ?? 0;
    double lateDeductions = double.tryParse(item['late_deductions']?.toString() ?? '0') ?? 0;
    double nssfDeductions = double.tryParse(item['nssf_deductions']?.toString() ?? '0') ?? 0;
    double taxDeductions = double.tryParse(item['tax_deductions']?.toString() ?? '0') ?? 0;
    double calculatedSalary = double.tryParse(item['calculated_salary']?.toString() ?? '0') ?? (baseSalary + otPay + allowances - lateDeductions - nssfDeductions - taxDeductions);
    int presentDays = int.tryParse(item['present_days']?.toString() ?? '0') ?? 0;

    return Container(
      margin: const EdgeInsets.only(bottom: 20),
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(28),
        border: Border.all(color: AppTheme.primary.withValues(alpha: 0.1)),
        boxShadow: [
          BoxShadow(
            color: AppTheme.primary.withValues(alpha: 0.05),
            blurRadius: 20,
            offset: const Offset(0, 10),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: AppTheme.primary.withValues(alpha: 0.1),
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      Icons.payments_rounded,
                      color: AppTheme.primary,
                      size: 24,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        "ប្រាក់ខែ / ខែ ${item['payroll_month']}",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                      Text(
                        "ឆ្នាំ ${item['payroll_year']}",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textSecondary,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 6,
                ),
                decoration: BoxDecoration(
                  color: Colors.green.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                    color: Colors.green.withValues(alpha: 0.3),
                  ),
                ),
                child: Text(
                  item['status'] == 'Paid' ? "បានបើក" : "រង់ចាំ",
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.green,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 16),
            child: Divider(height: 1),
          ),
          _buildInfoRow(
            "ប្រាក់ខែគោល (Base Salary)",
            "\$${baseSalary.toStringAsFixed(2)}",
          ),
          const SizedBox(height: 8),
          _buildInfoRow(
            "វត្តមាន (Present Days)",
            "$presentDays ថ្ងៃ",
          ),
          if (otPay > 0 || otHours > 0) ...[
            const SizedBox(height: 8),
            _buildInfoRow(
              "ប្រាក់ថែមម៉ោង (OT Pay)",
              "\$${otPay.toStringAsFixed(2)} (${otHours.toStringAsFixed(1)}h)",
              valueColor: Colors.greenAccent,
            ),
          ],
          if (allowances > 0) ...[
            const SizedBox(height: 8),
            _buildInfoRow(
              "ប្រាក់ឧបត្ថម្ភ (Allowances)",
              "\$${allowances.toStringAsFixed(2)}",
              valueColor: Colors.greenAccent,
            ),
          ],
          if (lateDeductions > 0) ...[
            const SizedBox(height: 8),
            _buildInfoRow(
              "កាត់ការអវត្តមាន/យឺត (Deduction)",
              "-\$${lateDeductions.toStringAsFixed(2)}",
              valueColor: Colors.redAccent,
            ),
          ],
          if (nssfDeductions > 0 || taxDeductions > 0) ...[
            const SizedBox(height: 8),
            _buildInfoRow(
              "ប.ស.ស. & ពន្ធ (NSSF & Tax)",
              "-\$${(nssfDeductions + taxDeductions).toStringAsFixed(2)}",
              valueColor: Colors.redAccent,
            ),
          ],
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.primary.withValues(alpha: 0.05),
              borderRadius: BorderRadius.circular(16),
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  "ប្រាក់ទទួលបានសរុប",
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                Text(
                  "\$${calculatedSalary.toStringAsFixed(2)}",
                  style: GoogleFonts.poppins(
                    color: AppTheme.primary,
                    fontWeight: FontWeight.bold,
                    fontSize: 20,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 14),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                "កាលបរិច្ឆេទ: ${item['payment_date'] ?? '-'}",
                style: GoogleFonts.inter(
                  color: AppTheme.textSecondary.withValues(alpha: 0.7),
                  fontSize: 11,
                ),
              ),
              OutlinedButton.icon(
                onPressed: () => PayslipPdfService.printOrSharePayslip(
                  employeeName: userProvider.name ?? 'Employee',
                  position: userProvider.position ?? '',
                  department: userProvider.department ?? '',
                  month: '${item['payroll_month']}',
                  year: '${item['payroll_year']}',
                  baseSalary: baseSalary,
                  presentDays: presentDays,
                  otHours: otHours,
                  otPay: otPay,
                  allowances: allowances,
                  lateDeductions: lateDeductions,
                  nssfDeductions: nssfDeductions,
                  taxDeductions: taxDeductions,
                  netSalary: calculatedSalary,
                  paymentDate: '${item['payment_date'] ?? ''}',
                  paymentStatus: '${item['status'] ?? 'Paid'}',
                ),
                icon: const Icon(Icons.picture_as_pdf_rounded, size: 16),
                label: Text(
                  'ទាញយក Payslip',
                  style: GoogleFonts.kantumruyPro(fontSize: 12, fontWeight: FontWeight.bold),
                ),
                style: OutlinedButton.styleFrom(
                  foregroundColor: AppTheme.primary,
                  side: BorderSide(color: AppTheme.primary.withValues(alpha: 0.5)),
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildInfoRow(String label, String value, {Color? valueColor}) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textSecondary,
            fontSize: 13.5,
          ),
        ),
        Text(
          value,
          style: GoogleFonts.poppins(
            color: valueColor ?? AppTheme.textPrimary,
            fontWeight: FontWeight.w600,
            fontSize: 13.5,
          ),
        ),
      ],
    );
  }
}
