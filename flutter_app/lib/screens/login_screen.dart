import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:animate_do/animate_do.dart';
import 'package:google_fonts/google_fonts.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../utils/app_assets.dart';
import 'home_screen.dart';
import '../utils/app_theme.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _employeeIdController = TextEditingController();
  final String _selectedType = 'Employee';
  bool _isLoading = false;

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
        MaterialPageRoute(builder: (context) => HomeScreen()),
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

  Widget _buildTextField({
    required TextEditingController controller,
    required String hintText,
    required IconData icon,
  }) {
    return Container(
      decoration: BoxDecoration(
        color: Colors.black.withValues(alpha: 0.2),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.1)),
      ),
      child: TextField(
        controller: controller,
        style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary),
        decoration: InputDecoration(
          hintText: hintText,
          hintStyle: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary.withValues(alpha: 0.38),
          ),
          prefixIcon: Icon(
            icon,
            color: AppTheme.textPrimary.withValues(alpha: 0.54),
            size: 22,
          ),
          border: InputBorder.none,
          contentPadding: EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        ),
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
