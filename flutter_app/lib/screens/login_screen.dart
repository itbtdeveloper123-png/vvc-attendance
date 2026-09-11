import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:animate_do/animate_do.dart';
import 'package:google_fonts/google_fonts.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../utils/app_assets.dart';
import 'home_screen.dart';
import 'register_screen.dart';
import '../utils/app_theme.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _employeeIdController = TextEditingController();
  final FocusNode _focusNode = FocusNode();
  final String _selectedType = 'Employee';
  bool _isLoading = false;
  bool _isInputFocused = false;
  List<Map<String, dynamic>> _recentAccounts = [];

  @override
  void initState() {
    super.initState();
    _loadRecentAccounts();
    _focusNode.addListener(() {
      if (mounted) {
        setState(() {
          _isInputFocused = _focusNode.hasFocus;
        });
      }
    });
    _employeeIdController.addListener(() {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _employeeIdController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  Future<void> _loadRecentAccounts() async {
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final accounts = await userProvider.getRecentAccounts();
    if (!mounted) return;
    setState(() {
      _recentAccounts = accounts;
    });
  }

  Future<void> _removeRecentAccount(String employeeId) async {
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    await userProvider.removeRecentAccount(employeeId);
    await _loadRecentAccounts();
  }

  void _selectRecentAccount(Map<String, dynamic> account) {
    _employeeIdController.text = account['employeeId']?.toString() ?? '';
  }

  void _handleLogin() async {
    if (_employeeIdController.text.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'សូមបញ្ចូលអត្តលេខបុគ្គលិក',
            style: GoogleFonts.kantumruyPro(),
          ),
          backgroundColor: Colors.redAccent,
          behavior: SnackBarBehavior.floating,
        ),
      );
      return;
    }

    setState(() => _isLoading = true);

    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final result = await userProvider.login(
      _employeeIdController.text.trim(),
      _selectedType,
    );

    if (!mounted) return;

    setState(() => _isLoading = false);

    if (result['success'] == true) {
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (context) => const HomeScreen()),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            result['message'] ?? 'ការចូលប្រើបរាជ័យ',
            style: GoogleFonts.kantumruyPro(),
          ),
          backgroundColor: Colors.redAccent,
          behavior: SnackBarBehavior.floating,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          // Flat solid background
          Container(decoration: BoxDecoration(color: AppTheme.bgSurface)),
          // Animated Glow Orbs
          Positioned(
            top: -100,
            right: -100,
            child: FadeIn(
              duration: const Duration(seconds: 2),
              child: Container(
                width: 300,
                height: 300,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: Colors.blueAccent.withValues(alpha: 0.15),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.blueAccent.withValues(alpha: 0.2),
                      blurRadius: 100,
                      spreadRadius: 50,
                    ),
                  ],
                ),
              ),
            ),
          ),
          Positioned(
            bottom: -50,
            left: -50,
            child: FadeIn(
              duration: const Duration(seconds: 3),
              child: Container(
                width: 250,
                height: 250,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: Colors.indigoAccent.withValues(alpha: 0.15),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.indigoAccent.withValues(alpha: 0.2),
                      blurRadius: 100,
                      spreadRadius: 50,
                    ),
                  ],
                ),
              ),
            ),
          ),
          // Content
          SafeArea(
            bottom: false,
            child: Center(
              child: SingleChildScrollView(
                padding: const EdgeInsets.symmetric(horizontal: 24),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    ElasticInDown(
                      duration: const Duration(milliseconds: 1500),
                      child: Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          boxShadow: [
                            BoxShadow(
                              color: Colors.amberAccent.withValues(alpha: 0.15),
                              blurRadius: 40,
                              spreadRadius: 10,
                            ),
                          ],
                        ),
                        child: Consumer<UserProvider>(
                          builder: (context, up, child) {
                            final logoUrl = ApiService.getFullImageUrl(
                              up.getConfig('header_logo_path'),
                            );
                            return logoUrl.isNotEmpty
                                ? Image.network(
                                    logoUrl,
                                    width: 140,
                                    height: 140,
                                    fit: BoxFit.contain,
                                    errorBuilder:
                                        (context, error, stackTrace) =>
                                            _buildDefaultLogo(),
                                  )
                                : _buildDefaultLogo();
                          },
                        ),
                      ),
                    ),
                    const SizedBox(height: 30),
                    FadeInDown(
                      duration: const Duration(milliseconds: 1200),
                      child: Consumer<UserProvider>(
                        builder: (context, up, child) => Text(
                          up.getConfig(
                            'app_display_name',
                            defaultValue: 'VVC ATTENDANCE',
                          ),
                          style: GoogleFonts.inter(
                            color: AppTheme.textPrimary,
                            fontSize: 28,
                            fontWeight: FontWeight.w900,
                            letterSpacing: 2,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ),
                    FadeInDown(
                      duration: const Duration(milliseconds: 1400),
                      child: Text(
                        "សូមចូលប្រើប្រាស់គណនីរបស់អ្នក",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary.withValues(alpha: 0.60),
                          fontSize: 16,
                          letterSpacing: 0.5,
                        ),
                      ),
                    ),
                    const SizedBox(height: 48),
                    // Glassmorphic Card
                    FadeInUp(
                      duration: const Duration(milliseconds: 600),
                      child: Container(
                        padding: const EdgeInsets.all(32),
                        decoration: BoxDecoration(
                          color: AppTheme.textPrimary.withValues(alpha: 0.08),
                          borderRadius: BorderRadius.circular(32),
                          border: Border.all(
                            color: AppTheme.textPrimary.withValues(alpha: 0.1),
                            width: 1.5,
                          ),
                        ),
                        child: Column(
                          children: [
                            // Employee ID Input
                            _buildTextField(
                              controller: _employeeIdController,
                              hintText: "អត្តលេខបុគ្គលិក",
                              icon: Icons.person_outline_rounded,
                            ),
                            const SizedBox(height: 32),
                            // Login Button
                            _buildLoginButton(),
                            const SizedBox(height: 24),
                            _buildRecentAccountsSection(),
                            const SizedBox(height: 20),
                            // Register New User Link
                            InkWell(
                              onTap: () async {
                                final registeredId = await Navigator.of(context).push<String?>(
                                  MaterialPageRoute(builder: (_) => const RegisterScreen()),
                                );
                                if (registeredId != null && registeredId.isNotEmpty) {
                                  _employeeIdController.text = registeredId;
                                }
                              },
                              borderRadius: BorderRadius.circular(12),
                              child: Padding(
                                padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 12),
                                child: Row(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Icon(
                                      Icons.person_add_alt_1_rounded,
                                      size: 16,
                                      color: AppTheme.primary,
                                    ),
                                    const SizedBox(width: 8),
                                    Text(
                                      "មិនទាន់មានគណនី? ចុះឈ្មោះបុគ្គលិកថ្មី",
                                      style: GoogleFonts.kantumruyPro(
                                        color: AppTheme.primary,
                                        fontSize: 13,
                                        fontWeight: FontWeight.w600,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 40),
                    FadeInUp(
                      duration: const Duration(milliseconds: 1000),
                      child: Column(
                        children: [
                          Consumer<UserProvider>(
                            builder: (context, up, child) => Text(
                              "រក្សាសិទ្ធិដោយ ${up.getConfig('app_display_name', defaultValue: 'Vvc HRM')} © ${DateTime.now().year}",
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textPrimary.withValues(
                                  alpha: 0.45,
                                ),
                                fontSize: 12,
                                letterSpacing: 0.5,
                              ),
                            ),
                          ),
                          const SizedBox(height: 8),
                          Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Text(
                                "Developed by ",
                                style: GoogleFonts.inter(
                                  color: AppTheme.textPrimary.withValues(
                                    alpha: 0.3,
                                  ),
                                  fontSize: 11,
                                  fontWeight: FontWeight.w400,
                                ),
                              ),
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 6,
                                  vertical: 2,
                                ),
                                decoration: BoxDecoration(
                                  color: Colors.blueAccent.withValues(
                                    alpha: 0.1,
                                  ),
                                  borderRadius: BorderRadius.circular(4),
                                  border: Border.all(
                                    color: Colors.blueAccent.withValues(
                                      alpha: 0.2,
                                    ),
                                  ),
                                ),
                                child: Text(
                                  "IT-VVC",
                                  style: GoogleFonts.inter(
                                    color: Colors.blueAccent.withValues(
                                      alpha: 0.9,
                                    ),
                                    fontSize: 10,
                                    fontWeight: FontWeight.bold,
                                    letterSpacing: 1.2,
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
          ),
        ],
      ),
    );
  }

  Widget _buildRecentAccountsSection() {
    if (_recentAccounts.isEmpty) {
      return const SizedBox.shrink();
    }

    final isDark = Theme.of(context).brightness == Brightness.dark;
    final currentInput = _employeeIdController.text.trim();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(
              Icons.history_rounded,
              size: 16,
              color: AppTheme.primary,
            ),
            const SizedBox(width: 6),
            Text(
              "គណនីចុងក្រោយ",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 13,
                fontWeight: FontWeight.bold,
              ),
            ),
            const Spacer(),
            Text(
              "${_recentAccounts.length} គណនី",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.40),
                fontSize: 11,
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        // Flex / Wrap Container (Clean, compact & responsive)
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: _recentAccounts.map((account) {
            final empId = account['employeeId']?.toString().trim() ?? '';
            final name = account['name']?.toString().trim() ?? empId;
            final isSelected = currentInput == empId && empId.isNotEmpty;

            return Material(
              color: Colors.transparent,
              child: InkWell(
                onTap: () {
                  HapticFeedback.selectionClick();
                  _selectRecentAccount(account);
                },
                borderRadius: BorderRadius.circular(24),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 200),
                  padding: const EdgeInsets.fromLTRB(5, 5, 8, 5),
                  decoration: BoxDecoration(
                    color: isSelected
                        ? AppTheme.primary.withValues(alpha: 0.14)
                        : (isDark
                            ? const Color(0xFF1E293B).withValues(alpha: 0.75)
                            : Colors.white.withValues(alpha: 0.95)),
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(
                      color: isSelected
                          ? AppTheme.primary
                          : AppTheme.textPrimary.withValues(alpha: 0.10),
                      width: isSelected ? 1.4 : 1.0,
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: isSelected
                            ? AppTheme.primary.withValues(alpha: 0.20)
                            : Colors.black.withValues(alpha: isDark ? 0.20 : 0.04),
                        blurRadius: isSelected ? 8 : 4,
                        offset: const Offset(0, 1.5),
                      ),
                    ],
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      // User Profile Avatar
                      _buildAccountAvatar(account, size: 34),
                      const SizedBox(width: 8),
                      // Name & ID
                      ConstrainedBox(
                        constraints: const BoxConstraints(maxWidth: 130),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              name,
                              style: GoogleFonts.kantumruyPro(
                                color: isSelected ? AppTheme.primary : AppTheme.textPrimary,
                                fontSize: 12.5,
                                fontWeight: FontWeight.bold,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                            Text(
                              empId,
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textSecondary,
                                fontSize: 10.5,
                                fontWeight: FontWeight.w500,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 6),
                      // Delete button (X)
                      GestureDetector(
                        onTap: () {
                          HapticFeedback.lightImpact();
                          _removeRecentAccount(empId);
                        },
                        behavior: HitTestBehavior.opaque,
                        child: Container(
                          width: 20,
                          height: 20,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: AppTheme.textPrimary.withValues(alpha: 0.08),
                          ),
                          child: Center(
                            child: Icon(
                              Icons.close_rounded,
                              size: 12,
                              color: AppTheme.textPrimary.withValues(alpha: 0.50),
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            );
          }).toList(),
        ),
        const SizedBox(height: 8),
        Text(
          "ចុចលើគណនីដើម្បីបំពេញអត្តលេខឆាប់រហ័ស",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textSecondary,
            fontSize: 11.5,
          ),
        ),
      ],
    );
  }

  Widget _buildAccountAvatar(Map<String, dynamic> account, {double size = 34}) {
    final rawAvatar = account['avatar']?.toString().trim() ?? '';
    final name = account['name']?.toString() ?? account['employeeId']?.toString() ?? '';

    if (rawAvatar.isNotEmpty) {
      final fullUrl = ApiService.getFullImageUrl(rawAvatar);
      if (fullUrl.startsWith('http')) {
        return Container(
          width: size,
          height: size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            border: Border.all(
              color: AppTheme.primary.withValues(alpha: 0.50),
              width: 1.2,
            ),
          ),
          child: ClipOval(
            child: Image.network(
              fullUrl,
              width: size,
              height: size,
              fit: BoxFit.cover,
              errorBuilder: (context, error, stackTrace) =>
                  _buildAvatarFallback(name, size),
              loadingBuilder: (context, child, loadingProgress) {
                if (loadingProgress == null) return child;
                return Center(
                  child: SizedBox(
                    width: size * 0.5,
                    height: size * 0.5,
                    child: CircularProgressIndicator(
                      strokeWidth: 1.5,
                      color: AppTheme.primary,
                    ),
                  ),
                );
              },
            ),
          ),
        );
      }
    }
    return _buildAvatarFallback(name, size);
  }

  Widget _buildAvatarFallback(String name, double size) {
    final trimmed = name.trim();
    final initial = trimmed.isNotEmpty ? trimmed.characters.first : '';

    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: LinearGradient(
          colors: [
            AppTheme.primary.withValues(alpha: 0.25),
            AppTheme.primary.withValues(alpha: 0.10),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        border: Border.all(
          color: AppTheme.primary.withValues(alpha: 0.45),
          width: 1.1,
        ),
      ),
      child: Center(
        child: initial.isNotEmpty && !RegExp(r'^[0-9]').hasMatch(initial)
            ? Text(
                initial,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.primary,
                  fontWeight: FontWeight.bold,
                  fontSize: size * 0.44,
                ),
              )
            : Icon(
                Icons.person_rounded,
                color: AppTheme.primary,
                size: size * 0.55,
              ),
      ),
    );
  }

  Widget _buildTextField({
    required TextEditingController controller,
    required String hintText,
    required IconData icon,
  }) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      height: 56,
      padding: const EdgeInsets.symmetric(horizontal: 16),
      decoration: BoxDecoration(
        color: isDark
            ? const Color(0xFF1E293B).withValues(alpha: 0.70)
            : const Color(0xFFF1F5F9).withValues(alpha: 0.90),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: _isInputFocused
              ? AppTheme.primary
              : AppTheme.textPrimary.withValues(alpha: 0.12),
          width: _isInputFocused ? 1.5 : 1.0,
        ),
        boxShadow: _isInputFocused
            ? [
                BoxShadow(
                  color: AppTheme.primary.withValues(alpha: 0.20),
                  blurRadius: 12,
                  spreadRadius: -1,
                  offset: const Offset(0, 2),
                ),
              ]
            : [
                BoxShadow(
                  color: Colors.black.withValues(alpha: isDark ? 0.20 : 0.03),
                  blurRadius: 6,
                  offset: const Offset(0, 1),
                ),
              ],
      ),
      child: Row(
        children: [
          Icon(
            icon,
            color: _isInputFocused
                ? AppTheme.primary
                : AppTheme.textPrimary.withValues(alpha: 0.50),
            size: 22,
          ),
          const SizedBox(width: 14),
          Expanded(
            child: TextField(
              controller: controller,
              focusNode: _focusNode,
              cursorColor: AppTheme.primary,
              textInputAction: TextInputAction.done,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 15,
                fontWeight: FontWeight.w600,
              ),
              decoration: InputDecoration(
                border: InputBorder.none,
                enabledBorder: InputBorder.none,
                focusedBorder: InputBorder.none,
                errorBorder: InputBorder.none,
                disabledBorder: InputBorder.none,
                filled: false,
                fillColor: Colors.transparent,
                isDense: true,
                contentPadding: const EdgeInsets.symmetric(vertical: 14),
                hintText: hintText,
                hintStyle: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary.withValues(alpha: 0.40),
                  fontSize: 14.5,
                  fontWeight: FontWeight.normal,
                ),
              ),
              onSubmitted: (_) => _isLoading ? null : _handleLogin(),
            ),
          ),
          if (controller.text.isNotEmpty)
            GestureDetector(
              onTap: () {
                controller.clear();
                setState(() {});
              },
              behavior: HitTestBehavior.opaque,
              child: Padding(
                padding: const EdgeInsets.all(4.0),
                child: Icon(
                  Icons.cancel_rounded,
                  size: 18,
                  color: AppTheme.textPrimary.withValues(alpha: 0.35),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildLoginButton() {
    return Container(
      width: double.infinity,
      height: 56,
      decoration: BoxDecoration(
        color: AppTheme.primary,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: AppTheme.primary.withValues(alpha: 0.3),
            blurRadius: 20,
            offset: const Offset(0, 8),
          ),
        ],
      ),
      child: ElevatedButton(
        onPressed: _isLoading ? null : _handleLogin,
        style: ElevatedButton.styleFrom(
          backgroundColor: Colors.transparent,
          shadowColor: Colors.transparent,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
          ),
        ),
        child: _isLoading
            ? SizedBox(
                height: 24,
                width: 24,
                child: CircularProgressIndicator(
                  color: AppTheme.textPrimary,
                  strokeWidth: 2,
                ),
              )
            : Text(
                "ចូលប្រើប្រាស់",
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontWeight: FontWeight.bold,
                  fontSize: 18,
                ),
              ),
      ),
    );
  }

  Widget _buildDefaultLogo() {
    return Image.asset(
      AppAssets.logo,
      width: 140,
      height: 140,
      fit: BoxFit.contain,
      errorBuilder: (context, error, stackTrace) => Icon(
        Icons.security_rounded,
        size: 100,
        color: AppTheme.textPrimary.withValues(alpha: 0.9),
      ),
    );
  }
}
