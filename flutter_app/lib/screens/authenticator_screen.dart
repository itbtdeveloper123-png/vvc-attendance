import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../services/authenticator_service.dart';
import '../utils/app_theme.dart';

class AuthenticatorScreen extends StatefulWidget {
  const AuthenticatorScreen({super.key});

  @override
  State<AuthenticatorScreen> createState() => _AuthenticatorScreenState();
}

class _AuthenticatorScreenState extends State<AuthenticatorScreen>
    with SingleTickerProviderStateMixin {
  final AuthenticatorService _authService = AuthenticatorService();
  List<AuthenticatorAccount> _accounts = [];
  bool _isLoading = true;
  bool _is2FaEnabled = true;
  bool _isToggling2Fa = false;

  Timer? _countdownTimer;
  int _secondsLeft = 30;
  double _progress = 1.0;

  @override
  void initState() {
    super.initState();
    _loadData();
    _startTimer();
  }

  @override
  void dispose() {
    _countdownTimer?.cancel();
    super.dispose();
  }

  void _startTimer() {
    _updateTimerValues();
    _countdownTimer?.cancel();
    _countdownTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (mounted) {
        setState(() {
          _updateTimerValues();
        });
      }
    });
  }

  void _updateTimerValues() {
    _secondsLeft = TotpHelper.getRemainingSeconds();
    _progress = TotpHelper.getRemainingProgress();
  }

  Future<void> _loadData() async {
    setState(() => _isLoading = true);
    final user = Provider.of<UserProvider>(context, listen: false);
    final empId = user.employeeId ?? 'ADMIN01';

    try {
      final results = await Future.wait([
        _authService.getAccounts(),
        _authService.get2FaStatus(empId),
      ]);

      if (mounted) {
        setState(() {
          _accounts = results[0] as List<AuthenticatorAccount>;
          _is2FaEnabled = results[1] as bool;
          _isLoading = false;
        });
      }
    } catch (e) {
      debugPrint('Error loading 2FA accounts: $e');
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  Future<void> _toggle2Fa(bool val) async {
    final user = Provider.of<UserProvider>(context, listen: false);
    final empId = user.employeeId ?? 'ADMIN01';

    setState(() {
      _isToggling2Fa = true;
      _is2FaEnabled = val;
    });

    await _authService.toggle2FaStatus(empId, val);

    if (mounted) {
      setState(() {
        _isToggling2Fa = false;
      });

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Row(
            children: [
              Icon(
                val ? Icons.check_circle_rounded : Icons.info_outline_rounded,
                color: Colors.white,
                size: 20,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  val
                      ? 'បានបើកប្រព័ន្ធការពារ ២ ជាន់ (2FA) លើ Admin Panel រួចរាល់'
                      : 'បានបិទប្រព័ន្ធការពារ ២ ជាន់ (2FA) លើ Admin Panel រួចរាល់',
                  style: GoogleFonts.kantumruyPro(fontSize: 13),
                ),
              ),
            ],
          ),
          backgroundColor: val ? const Color(0xFF10B981) : const Color(0xFF64748B),
          behavior: SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          duration: const Duration(seconds: 3),
        ),
      );
    }
  }

  void _copyOtpCode(String code, String accountName) {
    Clipboard.setData(ClipboardData(text: code));
    HapticFeedback.mediumImpact();

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            const Icon(Icons.copy_rounded, color: Colors.white, size: 18),
            const SizedBox(width: 10),
            Text(
              'បានចម្លងកូដ $code ($accountName) រួចរាល់!',
              style: GoogleFonts.kantumruyPro(fontSize: 13),
            ),
          ],
        ),
        backgroundColor: const Color(0xFF0284C7),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        duration: const Duration(seconds: 2),
      ),
    );
  }

  void _showAddOptionsSheet() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 24),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
          border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 44,
              height: 4,
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            const SizedBox(height: 18),
            Text(
              'បន្ថែមគណនីផ្ទៀងផ្ទាត់ (Add 2FA)',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 17,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 20),

            // Option 1: Scan QR Code
            ListTile(
              leading: Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xFF0284C7).withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(14),
                ),
                child: const Icon(Icons.qr_code_scanner_rounded, color: Color(0xFF38BDF8), size: 24),
              ),
              title: Text(
                'ស្កេន QR Code តាម Camera',
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontSize: 14.5,
                  fontWeight: FontWeight.w600,
                ),
              ),
              subtitle: Text(
                'ស្កេនរូប QR ពីផ្ទាំង Admin Panel ឬគេហទំព័រ',
                style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 12),
              ),
              trailing: const Icon(Icons.arrow_forward_ios_rounded, size: 14, color: Colors.grey),
              onTap: () {
                Navigator.pop(context);
                _openQrCameraScanner();
              },
            ),

            const SizedBox(height: 8),

            // Option 2: Manual Key Entry
            ListTile(
              leading: Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xFFD97706).withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(14),
                ),
                child: const Icon(Icons.keyboard_rounded, color: Color(0xFFFBBF24), size: 24),
              ),
              title: Text(
                'បញ្ចូល Secret Key ដោយដៃ',
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontSize: 14.5,
                  fontWeight: FontWeight.w600,
                ),
              ),
              subtitle: Text(
                'វាយបញ្ចូលឈ្មោះគណនី និងកូដសម្ងាត់ Base32',
                style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 12),
              ),
              trailing: const Icon(Icons.arrow_forward_ios_rounded, size: 14, color: Colors.grey),
              onTap: () {
                Navigator.pop(context);
                _showManualEntryDialog();
              },
            ),
            const SizedBox(height: 12),
          ],
        ),
      ),
    );
  }

  void _openQrCameraScanner() async {
    final result = await Navigator.push<String>(
      context,
      MaterialPageRoute(builder: (_) => const _AuthenticatorQrScannerView()),
    );

    if (result != null && result.isNotEmpty) {
      final parsed = TotpHelper.parseOtpAuthUri(result);
      if (parsed != null && parsed['secret'] != null && parsed['secret']!.isNotEmpty) {
        final newAcc = AuthenticatorAccount(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          name: parsed['account'] ?? 'VVC Admin',
          issuer: parsed['issuer'] ?? 'VVC Attendance',
          secret: parsed['secret']!,
          createdAt: DateTime.now(),
        );

        await _authService.saveAccount(newAcc);
        await _loadData();

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Row(
                children: [
                  const Icon(Icons.check_circle_rounded, color: Colors.white),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'បានស្កេន និងបន្ថែមគណនី ${newAcc.issuer} (${newAcc.name}) ជោគជ័យ!',
                      style: GoogleFonts.kantumruyPro(fontSize: 13),
                    ),
                  ),
                ],
              ),
              backgroundColor: const Color(0xFF10B981),
              behavior: SnackBarBehavior.floating,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            ),
          );
        }
      } else {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                'QR Code មិនត្រឹមត្រូវសម្រាប់ Authenticator ឡើយ!',
                style: GoogleFonts.kantumruyPro(fontSize: 13),
              ),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  void _showManualEntryDialog() {
    final nameCtrl = TextEditingController(text: 'Super Administrator');
    final issuerCtrl = TextEditingController(text: 'VVC Attendance');
    final secretCtrl = TextEditingController(text: 'VVCATTENDANCE2FAKEY2026');

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(24),
          side: BorderSide(color: Colors.white.withValues(alpha: 0.1)),
        ),
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: const Color(0xFF0284C7).withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(10),
              ),
              child: const Icon(Icons.key_rounded, color: Color(0xFF38BDF8), size: 20),
            ),
            const SizedBox(width: 10),
            Text(
              'បញ្ចូល Secret Key',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: issuerCtrl,
                style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 13.5),
                decoration: InputDecoration(
                  labelText: 'ស្ថាប័ន / Issuer',
                  labelStyle: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 12),
                  filled: true,
                  fillColor: Colors.black.withValues(alpha: 0.2),
                  border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: nameCtrl,
                style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontSize: 13.5),
                decoration: InputDecoration(
                  labelText: 'ឈ្មោះគណនី / Account Name',
                  labelStyle: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 12),
                  filled: true,
                  fillColor: Colors.black.withValues(alpha: 0.2),
                  border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: secretCtrl,
                style: const TextStyle(
                  color: Color(0xFF38BDF8),
                  fontSize: 14,
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.bold,
                  letterSpacing: 1.2,
                ),
                decoration: InputDecoration(
                  labelText: 'Secret Key (Base32)',
                  labelStyle: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 12),
                  filled: true,
                  fillColor: Colors.black.withValues(alpha: 0.2),
                  border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(
              'បោះបង់',
              style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted),
            ),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF0284C7),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            ),
            onPressed: () async {
              final secret = secretCtrl.text.trim().toUpperCase().replaceAll(' ', '');
              if (secret.isEmpty) return;

              final newAcc = AuthenticatorAccount(
                id: DateTime.now().millisecondsSinceEpoch.toString(),
                name: nameCtrl.text.trim().isNotEmpty ? nameCtrl.text.trim() : 'Admin',
                issuer: issuerCtrl.text.trim().isNotEmpty ? issuerCtrl.text.trim() : 'VVC Attendance',
                secret: secret,
                createdAt: DateTime.now(),
              );

              await _authService.saveAccount(newAcc);
              if (context.mounted) Navigator.pop(context);
              await _loadData();
            },
            child: Text(
              'រក្សាទុក',
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold),
            ),
          ),
        ],
      ),
    );
  }

  void _confirmDeleteAccount(AuthenticatorAccount acc) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Text(
          'លុបគណនីនេះ?',
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontSize: 16,
            fontWeight: FontWeight.bold,
          ),
        ),
        content: Text(
          'តើអ្នកប្រាកដជាចង់លុប ${acc.issuer} (${acc.name}) ចេញពី Authenticator ដែរឬទេ?',
          style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () async {
              await _authService.deleteAccount(acc.id);
              if (context.mounted) Navigator.pop(context);
              await _loadData();
            },
            child: Text('លុបចេញ', style: GoogleFonts.kantumruyPro(color: Colors.white)),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isWarningTime = _secondsLeft <= 5;
    final timerColor = isWarningTime ? const Color(0xFFEF4444) : const Color(0xFF0284C7);

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: AppTheme.bgCard,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'កូដផ្ទៀងផ្ទាត់ (Authenticator)',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
            Text(
              '2FA TOTP Security Engine',
              style: GoogleFonts.inter(
                color: const Color(0xFF38BDF8),
                fontSize: 11,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: Container(
              padding: const EdgeInsets.all(6),
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  colors: [Color(0xFF38BDF8), Color(0xFF0284C7)],
                ),
                borderRadius: BorderRadius.circular(10),
                boxShadow: [
                  BoxShadow(
                    color: const Color(0xFF0284C7).withValues(alpha: 0.4),
                    blurRadius: 8,
                  ),
                ],
              ),
              child: const Icon(Icons.add_rounded, color: Colors.white, size: 22),
            ),
            tooltip: 'បន្ថែម Code ថ្មី',
            onPressed: _showAddOptionsSheet,
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : RefreshIndicator(
              onRefresh: _loadData,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  // Top 2FA Master Switch Card
                  _buildMaster2FaSwitchCard(),

                  const SizedBox(height: 20),

                  // Section Header: Accounts
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        'គណនីផ្ទៀងផ្ទាត់ (${_accounts.length})',
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontSize: 14.5,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Row(
                        children: [
                          SizedBox(
                            width: 14,
                            height: 14,
                            child: CircularProgressIndicator(
                              value: _progress,
                              strokeWidth: 2.5,
                              valueColor: AlwaysStoppedAnimation<Color>(timerColor),
                              backgroundColor: Colors.white.withValues(alpha: 0.1),
                            ),
                          ),
                          const SizedBox(width: 6),
                          Text(
                            '$_secondsLeft វិនាទី',
                            style: GoogleFonts.kantumruyPro(
                              color: timerColor,
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),

                  const SizedBox(height: 12),

                  // Accounts List
                  if (_accounts.isEmpty)
                    _buildEmptyState()
                  else
                    ..._accounts.map((acc) => _buildOtpAccountCard(acc, timerColor)),

                  const SizedBox(height: 24),

                  // Info Tips Banner
                  _buildInfoSecurityBanner(),
                ],
              ),
            ),
    );
  }

  Widget _buildMaster2FaSwitchCard() {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(22),
        border: Border.all(
          color: _is2FaEnabled
              ? const Color(0xFF10B981).withValues(alpha: 0.35)
              : Colors.white.withValues(alpha: 0.08),
        ),
        boxShadow: [
          if (_is2FaEnabled)
            BoxShadow(
              color: const Color(0xFF10B981).withValues(alpha: 0.1),
              blurRadius: 16,
            ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: _is2FaEnabled
                      ? const Color(0xFF10B981).withValues(alpha: 0.15)
                      : Colors.grey.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(14),
                ),
                child: Icon(
                  _is2FaEnabled ? Icons.shield_rounded : Icons.shield_outlined,
                  color: _is2FaEnabled ? const Color(0xFF10B981) : Colors.grey,
                  size: 24,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'ប្រព័ន្ធការពារ ២ ជាន់ (2FA)',
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary,
                        fontSize: 15,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      _is2FaEnabled
                          ? 'កំពុងការពារការ Login លើ Admin Panel'
                          : 'បានបិទ (ចូល Login លើ Admin Panel ផ្ទាល់)',
                      style: GoogleFonts.kantumruyPro(
                        color: _is2FaEnabled ? const Color(0xFF10B981) : AppTheme.textMuted,
                        fontSize: 11.5,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ],
                ),
              ),
              if (_isToggling2Fa)
                const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(strokeWidth: 2.5),
                )
              else
                Switch(
                  value: _is2FaEnabled,
                  onChanged: _toggle2Fa,
                  activeThumbColor: const Color(0xFF10B981),
                  activeTrackColor: const Color(0xFF10B981).withValues(alpha: 0.3),
                  inactiveThumbColor: Colors.grey,
                  inactiveTrackColor: Colors.white.withValues(alpha: 0.1),
                ),
            ],
          ),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: Colors.black.withValues(alpha: 0.25),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Row(
              children: [
                Icon(
                  Icons.info_outline_rounded,
                  size: 14,
                  color: _is2FaEnabled ? const Color(0xFF38BDF8) : Colors.grey,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    _is2FaEnabled
                        ? 'ពេល Login លើ Admin Panel វានឹងទាមទារកូដ ៦ ខ្ទង់ខាងក្រោមនេះ។'
                        : 'ពេលបិទ Admin Panel នឹងអនុញ្ញាតឱ្យ Login ដោយមិនបាច់វាយកូដ OTP ឡើយ។',
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textMuted,
                      fontSize: 11,
                      height: 1.4,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildOtpAccountCard(AuthenticatorAccount acc, Color timerColor) {
    final otpCode = TotpHelper.generateTotp(acc.secret);
    final part1 = otpCode.substring(0, 3);
    final part2 = otpCode.substring(3, 6);

    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.2),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header: Issuer & Account
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  Container(
                    width: 32,
                    height: 32,
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(
                        colors: [Color(0xFFD4AF37), Color(0xFF996515)],
                      ),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: const Icon(Icons.lock_rounded, color: Colors.black87, size: 18),
                  ),
                  const SizedBox(width: 10),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        acc.issuer,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontSize: 14,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Text(
                        acc.name,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textMuted,
                          fontSize: 11.5,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              IconButton(
                icon: Icon(Icons.delete_outline_rounded, size: 20, color: Colors.red.shade300),
                onPressed: () => _confirmDeleteAccount(acc),
                tooltip: 'លុបចេញ',
              ),
            ],
          ),

          const SizedBox(height: 16),

          // Live 6-Digit Code Row
          GestureDetector(
            onTap: () => _copyOtpCode(otpCode, acc.name),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.35),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: const Color(0xFF38BDF8).withValues(alpha: 0.2)),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Row(
                    children: [
                      Text(
                        part1,
                        style: GoogleFonts.jetBrainsMono(
                          color: const Color(0xFF38BDF8),
                          fontSize: 28,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 4,
                        ),
                      ),
                      const SizedBox(width: 14),
                      Text(
                        part2,
                        style: GoogleFonts.jetBrainsMono(
                          color: const Color(0xFF38BDF8),
                          fontSize: 28,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 4,
                        ),
                      ),
                    ],
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0284C7).withValues(alpha: 0.2),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.copy_rounded, color: Color(0xFF38BDF8), size: 14),
                        const SizedBox(width: 4),
                        Text(
                          'Copy',
                          style: GoogleFonts.kantumruyPro(
                            color: const Color(0xFF38BDF8),
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),

          const SizedBox(height: 12),

          // Linear Progress Indicator
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: _progress,
              minHeight: 4,
              backgroundColor: Colors.white.withValues(alpha: 0.08),
              valueColor: AlwaysStoppedAnimation<Color>(timerColor),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Container(
      padding: const EdgeInsets.all(32),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Column(
        children: [
          const Icon(Icons.security_rounded, size: 48, color: Colors.grey),
          const SizedBox(height: 12),
          Text(
            'មិនទាន់មានគណនី 2FA ឡើយ',
            style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 6),
          Text(
            'សូមចុចប៊ូតុង + នៅខាងលើស្តាំ ដើម្បីស្កេន QR Code',
            style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 12),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildInfoSecurityBanner() {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0xFF0284C7).withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFF0284C7).withValues(alpha: 0.2)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.verified_user_rounded, color: Color(0xFF38BDF8), size: 20),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'VVC In-App Authenticator (ជំនួស Google Authenticator)',
                  style: GoogleFonts.kantumruyPro(
                    color: const Color(0xFF38BDF8),
                    fontSize: 12.5,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  'អ្នកអាចប្រើប្រាស់ផ្ទាំងនេះដើម្បីយកកូដ ៦ ខ្ទង់ផ្ទៀងផ្ទាត់ពេល Login លើ Admin Panel ដោយពុំចាំបាច់ដំឡើង App ក្រៅឡើយ។',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textMuted,
                    fontSize: 11,
                    height: 1.4,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// CAMERA QR SCANNER FOR 2FA AUTHENTICATOR
// ─────────────────────────────────────────────────────────────────────────────
class _AuthenticatorQrScannerView extends StatefulWidget {
  const _AuthenticatorQrScannerView();

  @override
  State<_AuthenticatorQrScannerView> createState() => _AuthenticatorQrScannerViewState();
}

class _AuthenticatorQrScannerViewState extends State<_AuthenticatorQrScannerView> {
  final MobileScannerController _controller = MobileScannerController(
    formats: [BarcodeFormat.qrCode],
    detectionTimeoutMs: 1000,
    autoStart: true,
  );
  bool _hasDetected = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_hasDetected) return;
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue;
      if (raw != null && raw.isNotEmpty) {
        _hasDetected = true;
        HapticFeedback.heavyImpact();
        Navigator.pop(context, raw);
        break;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Stack(
        children: [
          // Camera Preview
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
            errorBuilder: (context, error) => Center(
              child: Text(
                'កំហុសកាមេរ៉ា៖ ${error.errorCode}',
                style: GoogleFonts.kantumruyPro(color: Colors.white),
              ),
            ),
          ),

          // Custom Scanner Overlay with Cutout
          SafeArea(
            child: Column(
              children: [
                // Top App Bar Controls
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      IconButton(
                        icon: Container(
                          padding: const EdgeInsets.all(8),
                          decoration: const BoxDecoration(
                            color: Colors.black54,
                            shape: BoxShape.circle,
                          ),
                          child: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 18),
                        ),
                        onPressed: () => Navigator.pop(context),
                      ),
                      Text(
                        'ស្កេន 2FA QR Code',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      IconButton(
                        icon: Container(
                          padding: const EdgeInsets.all(8),
                          decoration: const BoxDecoration(
                            color: Colors.black54,
                            shape: BoxShape.circle,
                          ),
                          child: const Icon(Icons.flash_on_rounded, color: Colors.white, size: 20),
                        ),
                        onPressed: () => _controller.toggleTorch(),
                      ),
                    ],
                  ),
                ),

                const Spacer(),

                // Scanner Target Box
                Center(
                  child: Container(
                    width: 250,
                    height: 250,
                    decoration: BoxDecoration(
                      border: Border.all(color: const Color(0xFF38BDF8), width: 2.5),
                      borderRadius: BorderRadius.circular(20),
                      boxShadow: [
                        BoxShadow(
                          color: const Color(0xFF0284C7).withValues(alpha: 0.3),
                          blurRadius: 20,
                        ),
                      ],
                    ),
                  ),
                ),

                const SizedBox(height: 20),

                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
                  decoration: BoxDecoration(
                    color: Colors.black87,
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: Text(
                    'សូមតម្រង់កាមេរ៉ាទៅលើ QR Code លើផ្ទាំង Admin',
                    style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5),
                  ),
                ),

                const Spacer(flex: 2),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
