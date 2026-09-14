import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../services/authenticator_service.dart';
import '../widgets/app_widgets.dart';

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
          color: const Color(0xFF0F172A),
          borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
          border: Border.all(color: const Color(0xFF334155), width: 1.2),
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
                color: Colors.white,
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
                  color: const Color(0xFF0284C7).withValues(alpha: 0.18),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: const Color(0xFF38BDF8).withValues(alpha: 0.30)),
                ),
                child: const Icon(Icons.qr_code_scanner_rounded, color: Color(0xFF38BDF8), size: 24),
              ),
              title: Text(
                'ស្កេន QR Code តាម Camera',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 14.5,
                  fontWeight: FontWeight.w600,
                ),
              ),
              subtitle: Text(
                'ស្កេនរូប QR ពីផ្ទាំង Admin Panel ឬគេហទំព័រ',
                style: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8), fontSize: 12),
              ),
              trailing: const Icon(Icons.arrow_forward_ios_rounded, size: 14, color: Color(0xFF64748B)),
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
                  color: const Color(0xFFD97706).withValues(alpha: 0.18),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: const Color(0xFFFBBF24).withValues(alpha: 0.30)),
                ),
                child: const Icon(Icons.keyboard_rounded, color: Color(0xFFFBBF24), size: 24),
              ),
              title: Text(
                'បញ្ចូល Secret Key ដោយដៃ',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 14.5,
                  fontWeight: FontWeight.w600,
                ),
              ),
              subtitle: Text(
                'វាយបញ្ចូលឈ្មោះគណនី និងកូដសម្ងាត់ Base32',
                style: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8), fontSize: 12),
              ),
              trailing: const Icon(Icons.arrow_forward_ios_rounded, size: 14, color: Color(0xFF64748B)),
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

  Future<void> _openAdminLoginCameraScanner(AuthenticatorAccount acc) async {
    final result = await Navigator.push<Map<String, dynamic>>(
      context,
      MaterialPageRoute(
        builder: (_) => _AdminLoginQrScannerView(account: acc),
      ),
    );

    if (result != null && result['success'] == true && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Row(
            children: [
              const Icon(Icons.check_circle_rounded, color: Colors.white, size: 22),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  'បានអនុញ្ញាតការ Login ចូល Admin Panel ដោយជោគជ័យ!',
                  style: GoogleFonts.kantumruyPro(fontSize: 13, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
          backgroundColor: const Color(0xFF10B981),
          behavior: SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
          duration: const Duration(seconds: 4),
        ),
      );
    }
  }

  void _showManualEntryDialog() {
    final nameCtrl = TextEditingController(text: 'Super Administrator');
    final issuerCtrl = TextEditingController(text: 'VVC Attendance');
    final secretCtrl = TextEditingController(text: 'VVCATTENDANCE2FAKEY2026');

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF0F172A),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(24),
          side: const BorderSide(color: Color(0xFF334155), width: 1.2),
        ),
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: const Color(0xFF0284C7).withValues(alpha: 0.20),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: const Color(0xFF38BDF8).withValues(alpha: 0.35)),
              ),
              child: const Icon(Icons.key_rounded, color: Color(0xFF38BDF8), size: 20),
            ),
            const SizedBox(width: 10),
            Text(
              'បញ្ចូល Secret Key',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
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
                style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                decoration: InputDecoration(
                  labelText: 'ស្ថាប័ន / Issuer',
                  labelStyle: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8), fontSize: 12),
                  filled: true,
                  fillColor: const Color(0xFF1E293B),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: const BorderSide(color: Color(0xFF334155)),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: const BorderSide(color: Color(0xFF38BDF8), width: 1.5),
                  ),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: nameCtrl,
                style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                decoration: InputDecoration(
                  labelText: 'ឈ្មោះគណនី / Account Name',
                  labelStyle: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8), fontSize: 12),
                  filled: true,
                  fillColor: const Color(0xFF1E293B),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: const BorderSide(color: Color(0xFF334155)),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: const BorderSide(color: Color(0xFF38BDF8), width: 1.5),
                  ),
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
                  labelStyle: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8), fontSize: 12),
                  filled: true,
                  fillColor: const Color(0xFF1E293B),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: const BorderSide(color: Color(0xFF334155)),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: const BorderSide(color: Color(0xFF38BDF8), width: 1.5),
                  ),
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
              style: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8)),
            ),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF0284C7),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
              padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 10),
              elevation: 4,
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
        backgroundColor: const Color(0xFF0F172A),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(20),
          side: const BorderSide(color: Color(0xFF334155), width: 1.2),
        ),
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: const Color(0xFFEF4444).withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(10),
              ),
              child: const Icon(Icons.delete_forever_rounded, color: Color(0xFFEF4444), size: 20),
            ),
            const SizedBox(width: 10),
            Text(
              'លុបគណនីនេះ?',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        content: Text(
          'តើអ្នកប្រាកដជាចង់លុប ${acc.issuer} (${acc.name}) ចេញពី Authenticator ដែរឬទេ?',
          style: GoogleFonts.kantumruyPro(color: const Color(0xFFCBD5E1), fontSize: 13, height: 1.4),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8))),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFDC2626),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            ),
            onPressed: () async {
              await _authService.deleteAccount(acc.id);
              if (context.mounted) Navigator.pop(context);
              await _loadData();
            },
            child: Text('លុបចេញ', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final isWarningTime = _secondsLeft <= 5;
    final timerColor = isWarningTime ? const Color(0xFFEF4444) : const Color(0xFF38BDF8);

    return Scaffold(
      backgroundColor: const Color(0xFF0B0F19),
      appBar: VvcAppBar(
        backgroundColor: const Color(0xFF131B2A).withValues(alpha: 0.92),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 18),
          onPressed: () => Navigator.pop(context),
        ),
        title: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(6),
              decoration: BoxDecoration(
                color: const Color(0xFF0284C7).withValues(alpha: 0.20),
                shape: BoxShape.circle,
                border: Border.all(color: const Color(0xFF38BDF8).withValues(alpha: 0.35)),
              ),
              child: const Icon(Icons.shield_rounded, color: Color(0xFF38BDF8), size: 16),
            ),
            const SizedBox(width: 8),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  'កូដផ្ទៀងផ្ទាត់ (Authenticator)',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontSize: 15,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                Row(
                  children: [
                    Container(
                      width: 6,
                      height: 6,
                      decoration: const BoxDecoration(
                        color: Color(0xFF10B981),
                        shape: BoxShape.circle,
                        boxShadow: [
                          BoxShadow(color: Color(0xFF10B981), blurRadius: 4),
                        ],
                      ),
                    ),
                    const SizedBox(width: 5),
                    Text(
                      '2FA TOTP Security Engine',
                      style: GoogleFonts.inter(
                        color: const Color(0xFF38BDF8),
                        fontSize: 10.5,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: Container(
              padding: const EdgeInsets.all(7),
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  colors: [Color(0xFF0284C7), Color(0xFF0EA5E9)],
                ),
                borderRadius: BorderRadius.circular(10),
                boxShadow: [
                  BoxShadow(
                    color: const Color(0xFF0284C7).withValues(alpha: 0.45),
                    blurRadius: 8,
                    offset: const Offset(0, 2),
                  ),
                ],
              ),
              child: const Icon(Icons.add_rounded, color: Colors.white, size: 20),
            ),
            tooltip: 'បន្ថែម Code ថ្មី',
            onPressed: _showAddOptionsSheet,
          ),
          const SizedBox(width: 6),
        ],
      ),
      body: _isLoading
          ? const Center(
              child: CircularProgressIndicator(
                valueColor: AlwaysStoppedAnimation<Color>(Color(0xFF38BDF8)),
              ),
            )
          : RefreshIndicator(
              onRefresh: _loadData,
              color: const Color(0xFF38BDF8),
              backgroundColor: const Color(0xFF131B2A),
              child: ListView(
                physics: const AlwaysScrollableScrollPhysics(parent: BouncingScrollPhysics()),
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 32),
                children: [
                  // Top 2FA Master Switch Card
                  _buildMaster2FaSwitchCard(),

                  const SizedBox(height: 22),

                  // Section Header: Accounts & Dynamic Timer
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Row(
                        children: [
                          Text(
                            'គណនីផ្ទៀងផ្ទាត់',
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 15.0,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(width: 8),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                            decoration: BoxDecoration(
                              color: const Color(0xFF1E293B),
                              borderRadius: BorderRadius.circular(10),
                              border: Border.all(
                                color: const Color(0xFF38BDF8).withValues(alpha: 0.35),
                                width: 1.0,
                              ),
                            ),
                            child: Text(
                              '${_accounts.length}',
                              style: GoogleFonts.inter(
                                color: const Color(0xFF38BDF8),
                                fontSize: 11.5,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ],
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                        decoration: BoxDecoration(
                          color: timerColor.withValues(alpha: 0.14),
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(
                            color: timerColor.withValues(alpha: 0.35),
                            width: 1.0,
                          ),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            SizedBox(
                              width: 13,
                              height: 13,
                              child: CircularProgressIndicator(
                                value: _progress,
                                strokeWidth: 2.2,
                                valueColor: AlwaysStoppedAnimation<Color>(timerColor),
                                backgroundColor: Colors.white.withValues(alpha: 0.12),
                              ),
                            ),
                            const SizedBox(width: 6),
                            Text(
                              '$_secondsLeft វិនាទី',
                              style: GoogleFonts.kantumruyPro(
                                color: timerColor,
                                fontSize: 11.5,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 12),

                  // Accounts List
                  if (_accounts.isEmpty)
                    _buildEmptyState()
                  else
                    ..._accounts.map((acc) => _buildOtpAccountCard(acc, timerColor)),

                  const SizedBox(height: 20),

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
        color: const Color(0xFF131B2A),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(
          color: _is2FaEnabled
              ? const Color(0xFF10B981).withValues(alpha: 0.40)
              : Colors.white.withValues(alpha: 0.10),
          width: 1.2,
        ),
        boxShadow: [
          BoxShadow(
            color: _is2FaEnabled
                ? const Color(0xFF10B981).withValues(alpha: 0.12)
                : Colors.black.withValues(alpha: 0.25),
            blurRadius: 18,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(11),
                decoration: BoxDecoration(
                  gradient: _is2FaEnabled
                      ? const LinearGradient(
                          colors: [Color(0xFF10B981), Color(0xFF059669)],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        )
                      : null,
                  color: _is2FaEnabled ? null : const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(15),
                  boxShadow: _is2FaEnabled
                      ? [
                          BoxShadow(
                            color: const Color(0xFF10B981).withValues(alpha: 0.35),
                            blurRadius: 10,
                            offset: const Offset(0, 2),
                          ),
                        ]
                      : null,
                ),
                child: Icon(
                  _is2FaEnabled ? Icons.shield_rounded : Icons.shield_outlined,
                  color: Colors.white,
                  size: 24,
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'ប្រព័ន្ធការពារ ២ ជាន់ (2FA)',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontSize: 15.5,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Row(
                      children: [
                        Container(
                          width: 6,
                          height: 6,
                          decoration: BoxDecoration(
                            color: _is2FaEnabled ? const Color(0xFF10B981) : const Color(0xFF64748B),
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 6),
                        Expanded(
                          child: Text(
                            _is2FaEnabled
                                ? 'កំពុងការពារការ Login លើ Admin Panel'
                                : 'បានបិទ (ចូល Login លើ Admin Panel ផ្ទាល់)',
                            style: GoogleFonts.kantumruyPro(
                              color: _is2FaEnabled ? const Color(0xFF34D399) : const Color(0xFF94A3B8),
                              fontSize: 12.0,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              if (_isToggling2Fa)
                const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(
                    strokeWidth: 2.5,
                    valueColor: AlwaysStoppedAnimation<Color>(Color(0xFF10B981)),
                  ),
                )
              else
                Transform.scale(
                  scale: 0.92,
                  child: Switch(
                    value: _is2FaEnabled,
                    onChanged: _toggle2Fa,
                    activeThumbColor: Colors.white,
                    activeTrackColor: const Color(0xFF10B981),
                    inactiveThumbColor: const Color(0xFF94A3B8),
                    inactiveTrackColor: const Color(0xFF1E293B),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 14),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: const Color(0xFF1E2638).withValues(alpha: 0.85),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: const Color(0xFF38BDF8).withValues(alpha: 0.20),
                width: 1.0,
              ),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Padding(
                  padding: EdgeInsets.only(top: 1.5),
                  child: Icon(
                    Icons.info_outline_rounded,
                    size: 16,
                    color: Color(0xFF38BDF8),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    _is2FaEnabled
                        ? 'ពេល Login លើ Admin Panel វានឹងទាមទារកូដ ៦ ខ្ទង់ខាងក្រោមនេះ។'
                        : 'ពេលបិទ Admin Panel នឹងអនុញ្ញាតឱ្យ Login ដោយមិនបាច់វាយកូដ OTP ឡើយ។',
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFFCBD5E1),
                      fontSize: 12,
                      height: 1.45,
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
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: const Color(0xFF131B2A),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(
          color: const Color(0xFF38BDF8).withValues(alpha: 0.22),
          width: 1.2,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.35),
            blurRadius: 16,
            offset: const Offset(0, 5),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header: Issuer & Account & Actions
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  Container(
                    width: 36,
                    height: 36,
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(
                        colors: [Color(0xFFF59E0B), Color(0xFFD97706)],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      ),
                      borderRadius: BorderRadius.circular(10),
                      boxShadow: [
                        BoxShadow(
                          color: const Color(0xFFF59E0B).withValues(alpha: 0.35),
                          blurRadius: 8,
                          offset: const Offset(0, 2),
                        ),
                      ],
                    ),
                    child: const Icon(Icons.lock_rounded, color: Colors.white, size: 20),
                  ),
                  const SizedBox(width: 12),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        acc.issuer,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 15,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 1),
                      Text(
                        acc.name,
                        style: GoogleFonts.kantumruyPro(
                          color: const Color(0xFF94A3B8),
                          fontSize: 12.0,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Camera Icon button for QR Admin Login
                  Tooltip(
                    message: 'ស្កេន QR Login Admin',
                    child: Material(
                      color: Colors.transparent,
                      child: InkWell(
                        onTap: () => _openAdminLoginCameraScanner(acc),
                        borderRadius: BorderRadius.circular(10),
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                          decoration: BoxDecoration(
                            gradient: const LinearGradient(
                              colors: [Color(0xFF0284C7), Color(0xFF0369A1)],
                            ),
                            borderRadius: BorderRadius.circular(10),
                            border: Border.all(
                              color: const Color(0xFF38BDF8).withValues(alpha: 0.40),
                              width: 1.0,
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: const Color(0xFF0284C7).withValues(alpha: 0.35),
                                blurRadius: 8,
                                offset: const Offset(0, 2),
                              ),
                            ],
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              const Icon(Icons.camera_alt_rounded, size: 14, color: Colors.white),
                              const SizedBox(width: 5),
                              Text(
                                'ស្កេន Login',
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white,
                                  fontSize: 11.5,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 4),
                  IconButton(
                    icon: Container(
                      padding: const EdgeInsets.all(5),
                      decoration: BoxDecoration(
                        color: const Color(0xFFEF4444).withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: const Icon(Icons.delete_outline_rounded, size: 18, color: Color(0xFFF87171)),
                    ),
                    onPressed: () => _confirmDeleteAccount(acc),
                    tooltip: 'លុបចេញ',
                  ),
                ],
              ),
            ],
          ),

          const SizedBox(height: 16),

          // Live 6-Digit Code Hero Row
          GestureDetector(
            onTap: () => _copyOtpCode(otpCode, acc.name),
            behavior: HitTestBehavior.opaque,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              decoration: BoxDecoration(
                color: const Color(0xFF090D16),
                borderRadius: BorderRadius.circular(18),
                border: Border.all(
                  color: timerColor.withValues(alpha: 0.35),
                  width: 1.2,
                ),
                boxShadow: [
                  BoxShadow(
                    color: timerColor.withValues(alpha: 0.08),
                    blurRadius: 14,
                  ),
                ],
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Row(
                    children: [
                      Text(
                        part1,
                        style: GoogleFonts.jetBrainsMono(
                          color: timerColor,
                          fontSize: 30,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 4.5,
                        ),
                      ),
                      const SizedBox(width: 14),
                      Text(
                        part2,
                        style: GoogleFonts.jetBrainsMono(
                          color: timerColor,
                          fontSize: 30,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 4.5,
                        ),
                      ),
                    ],
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 7),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0284C7).withValues(alpha: 0.22),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(
                        color: const Color(0xFF38BDF8).withValues(alpha: 0.35),
                        width: 1.0,
                      ),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.copy_rounded, color: Color(0xFF38BDF8), size: 14),
                        const SizedBox(width: 5),
                        Text(
                          'Copy',
                          style: GoogleFonts.inter(
                            color: const Color(0xFF38BDF8),
                            fontSize: 12,
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

          const SizedBox(height: 14),

          // Linear Progress Indicator
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: _progress,
              minHeight: 5,
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
        color: const Color(0xFF131B2A),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
      ),
      child: Column(
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF0284C7).withValues(alpha: 0.15),
              shape: BoxShape.circle,
            ),
            child: const Icon(Icons.security_rounded, size: 40, color: Color(0xFF38BDF8)),
          ),
          const SizedBox(height: 14),
          Text(
            'មិនទាន់មានគណនី 2FA ឡើយ',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontSize: 16,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            'សូមចុចប៊ូតុង + នៅខាងលើស្តាំ ដើម្បីស្កេន QR Code ឬបញ្ចូល Key ដោយដៃ',
            style: GoogleFonts.kantumruyPro(
              color: const Color(0xFF94A3B8),
              fontSize: 12.5,
              height: 1.4,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildInfoSecurityBanner() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [
            Color(0xFF0F1E36),
            Color(0xFF091424),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: const Color(0xFF0284C7).withValues(alpha: 0.35),
          width: 1.2,
        ),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF0284C7).withValues(alpha: 0.10),
            blurRadius: 16,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: const Color(0xFF0284C7).withValues(alpha: 0.20),
              shape: BoxShape.circle,
            ),
            child: const Icon(Icons.verified_user_rounded, color: Color(0xFF38BDF8), size: 20),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'VVC In-App Authenticator (ជំនួស Google Authenticator)',
                  style: GoogleFonts.kantumruyPro(
                    color: const Color(0xFF38BDF8),
                    fontSize: 13.0,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 5),
                Text(
                  'អ្នកអាចប្រើប្រាស់ផ្ទាំងនេះដើម្បីយកកូដ ៦ ខ្ទង់ផ្ទៀងផ្ទាត់ពេល Login លើ Admin Panel ដោយពុំចាំបាច់ដំឡើង App ក្រៅឡើយ។',
                  style: GoogleFonts.kantumruyPro(
                    color: const Color(0xFFCBD5E1),
                    fontSize: 12.0,
                    height: 1.5,
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

// ─────────────────────────────────────────────────────────────────────────────
// CAMERA QR SCANNER FOR ADMIN PANEL LOGIN
// ─────────────────────────────────────────────────────────────────────────────
class _AdminLoginQrScannerView extends StatefulWidget {
  final AuthenticatorAccount account;
  const _AdminLoginQrScannerView({required this.account});

  @override
  State<_AdminLoginQrScannerView> createState() => _AdminLoginQrScannerViewState();
}

class _AdminLoginQrScannerViewState extends State<_AdminLoginQrScannerView> {
  final MobileScannerController _controller = MobileScannerController(
    formats: [BarcodeFormat.qrCode],
    detectionTimeoutMs: 1200,
    autoStart: true,
  );
  final AuthenticatorService _authService = AuthenticatorService();
  bool _isProcessing = false;
  bool _isApproved = false;
  String? _statusMessage;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _handleQrData(String rawData) async {
    if (_isProcessing || _isApproved) return;

    setState(() {
      _isProcessing = true;
      _statusMessage = 'កំពុងពិនិត្យមើល QR Code...';
    });

    HapticFeedback.mediumImpact();

    try {
      String qrToken = '';
      String adminId = widget.account.name;

      // 1. Try parsing JSON format: {"type":"vvc_admin_qr_login","qr_token":"...","admin_id":"..."}
      if (rawData.trim().startsWith('{') && rawData.trim().endsWith('}')) {
        try {
          final decoded = jsonDecode(rawData);
          if (decoded is Map<String, dynamic>) {
            qrToken = decoded['qr_token'] ?? decoded['token'] ?? '';
            if (decoded['admin_id'] != null && decoded['admin_id'].toString().isNotEmpty) {
              adminId = decoded['admin_id'].toString();
            }
          }
        } catch (_) {}
      }

      // 2. Try URI format: vvcauth://admin-login?token=...&admin_id=...
      if (qrToken.isEmpty && rawData.contains('token=')) {
        try {
          final uri = Uri.parse(rawData);
          qrToken = uri.queryParameters['token'] ?? uri.queryParameters['qr_token'] ?? '';
          if (uri.queryParameters['admin_id'] != null) {
            adminId = uri.queryParameters['admin_id']!;
          }
        } catch (_) {}
      }

      // 3. Raw token fallback
      if (qrToken.isEmpty && rawData.startsWith('vvc_qr_')) {
        qrToken = rawData.trim();
      }

      if (qrToken.isEmpty) {
        // Not an admin login QR
        setState(() {
          _isProcessing = false;
          _statusMessage = null;
        });
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                '⚠️ QR Code នេះមិនមែនសម្រាប់ Admin Panel Login ឡើយ!',
                style: GoogleFonts.kantumruyPro(),
              ),
              backgroundColor: const Color(0xFFEF4444),
              behavior: SnackBarBehavior.floating,
              duration: const Duration(seconds: 2),
            ),
          );
        }
        return;
      }

      // Generate live TOTP Code using account secret
      final totpCode = TotpHelper.generateTotp(widget.account.secret);

      setState(() {
        _statusMessage = 'កំពុងអនុញ្ញាតការ Login ចូល Admin Panel...';
      });

      final result = await _authService.approveQrLogin(
        qrToken: qrToken,
        adminId: adminId,
        totpCode: totpCode,
        deviceInfo: 'Mobile App (${widget.account.issuer})',
      );

      if (result['success'] == true) {
        HapticFeedback.heavyImpact();
        if (mounted) {
          setState(() {
            _isProcessing = false;
            _isApproved = true;
            _statusMessage = 'អនុញ្ញាតជោគជ័យ!';
          });

          await Future.delayed(const Duration(milliseconds: 1200));
          if (mounted) {
            Navigator.pop(context, {'success': true, 'token': qrToken});
          }
        }
      } else {
        HapticFeedback.vibrate();
        final msg = result['message'] ?? 'ការផ្ទៀងផ្ទាត់មិនជោគជ័យឡើយ';
        if (mounted) {
          setState(() {
            _isProcessing = false;
            _statusMessage = null;
          });
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(msg, style: GoogleFonts.kantumruyPro()),
              backgroundColor: const Color(0xFFEF4444),
              behavior: SnackBarBehavior.floating,
              duration: const Duration(seconds: 3),
            ),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isProcessing = false;
          _statusMessage = null;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('កំហុស៖ $e', style: GoogleFonts.kantumruyPro()),
            backgroundColor: const Color(0xFFEF4444),
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    }
  }

  void _onDetect(BarcodeCapture capture) {
    if (_isProcessing || _isApproved) return;
    for (final barcode in capture.barcodes) {
      final raw = barcode.rawValue;
      if (raw != null && raw.isNotEmpty) {
        _handleQrData(raw);
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

          // Custom Scanner Overlay
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
                      Column(
                        children: [
                          Text(
                            'ស្កេន Login Admin Panel',
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Text(
                            widget.account.issuer,
                            style: GoogleFonts.kantumruyPro(
                              color: const Color(0xFF38BDF8),
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ],
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

                // Target Box with dynamic animations
                Center(
                  child: Container(
                    width: 260,
                    height: 260,
                    decoration: BoxDecoration(
                      border: Border.all(
                        color: _isApproved
                            ? const Color(0xFF10B981)
                            : _isProcessing
                            ? const Color(0xFFF59E0B)
                            : const Color(0xFF38BDF8),
                        width: 3,
                      ),
                      borderRadius: BorderRadius.circular(24),
                      boxShadow: [
                        BoxShadow(
                          color: (_isApproved
                                  ? const Color(0xFF10B981)
                                  : _isProcessing
                                  ? const Color(0xFFF59E0B)
                                  : const Color(0xFF0284C7))
                              .withValues(alpha: 0.4),
                          blurRadius: 25,
                        ),
                      ],
                    ),
                    child: _isApproved
                        ? const Center(
                            child: Icon(Icons.check_circle_rounded, color: Color(0xFF10B981), size: 70),
                          )
                        : _isProcessing
                        ? const Center(
                            child: CircularProgressIndicator(
                              color: Color(0xFF38BDF8),
                              strokeWidth: 3.5,
                            ),
                          )
                        : null,
                  ),
                ),

                const SizedBox(height: 20),

                // Status Pill
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                  margin: const EdgeInsets.symmetric(horizontal: 24),
                  decoration: BoxDecoration(
                    color: Colors.black87,
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(
                      color: _isApproved
                          ? const Color(0xFF10B981)
                          : _isProcessing
                          ? const Color(0xFFF59E0B)
                          : Colors.white24,
                    ),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (_isProcessing)
                        const Padding(
                          padding: EdgeInsets.only(right: 8),
                          child: SizedBox(
                            width: 14,
                            height: 14,
                            child: CircularProgressIndicator(color: Color(0xFF38BDF8), strokeWidth: 2),
                          ),
                        )
                      else if (_isApproved)
                        const Padding(
                          padding: EdgeInsets.only(right: 8),
                          child: Icon(Icons.check_circle_rounded, color: Color(0xFF10B981), size: 16),
                        ),
                      Flexible(
                        child: Text(
                          _statusMessage ?? 'សូមតម្រង់កាមេរ៉ាទៅលើ QR Code លើផ្ទាំង Admin Login',
                          style: GoogleFonts.kantumruyPro(
                            color: _isApproved
                                ? const Color(0xFF34D399)
                                : _isProcessing
                                ? const Color(0xFFFCD34D)
                                : Colors.white,
                            fontSize: 12.5,
                            fontWeight: FontWeight.w600,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ],
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
