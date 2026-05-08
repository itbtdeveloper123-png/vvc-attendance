import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:animate_do/animate_do.dart';
import '../core/theme/theme_provider.dart';
import '../core/theme/app_theme_season.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

class ThemeSelectionScreen extends StatelessWidget {
  const ThemeSelectionScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final themeProvider = Provider.of<SeasonalThemeProvider>(context);

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        centerTitle: true,
        title: Text(
          "ជម្រើសស្បែក (Themes)",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontWeight: FontWeight.bold,
            fontSize: 18,
          ),
        ),
        leading: IconButton(
          icon: Icon(Icons.arrow_back_ios_new_rounded, color: AppTheme.textPrimary),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: AppBackgroundShell(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 110, 20, 20),
          physics: const BouncingScrollPhysics(),
          children: [
            FadeInDown(
              child: Text(
                "ជ្រើសរើសស្បែកកម្មវិធីតាមចំណូលចិត្ត ឬកំណត់តាមរដូវកាល",
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textSecondary,
                  fontSize: 14,
                ),
                textAlign: TextAlign.center,
              ),
            ),
            const SizedBox(height: 20),
            _buildThemeOption(
              context: context,
              themeProvider: themeProvider,
              isAuto: true,
              season: AppThemeSeason.defaultHRM,
              title: "ស្វ័យប្រវត្តិ (Auto)",
              icon: Icons.auto_mode_rounded,
              color: AppTheme.textPrimary,
            ),
            const SizedBox(height: 20),
            ...AppThemeSeason.values.map((season) {
              IconData icon;
              Color color;
              switch (season) {
                case AppThemeSeason.khmerNewYear:
                  icon = Icons.celebration_rounded;
                  color = const Color(0xFFEAB308);
                  break;
                case AppThemeSeason.chineseNewYear:
                  icon = Icons.festival_rounded;
                  color = const Color(0xFFDC2626);
                  break;
                case AppThemeSeason.pchumBen:
                  icon = Icons.volunteer_activism_rounded;
                  color = const Color(0xFF9333EA);
                  break;
                case AppThemeSeason.waterFestival:
                  icon = Icons.sailing_rounded;
                  color = const Color(0xFF0284C7);
                  break;
                case AppThemeSeason.bayonSpirit:
                  icon = Icons.temple_hindu_rounded;
                  color = const Color(0xFF1F4B99);
                  break;
                case AppThemeSeason.angkorEmpire:
                  icon = Icons.account_balance_rounded;
                  color = const Color(0xFFD4AF37);
                  break;
                case AppThemeSeason.romduolBloom:
                  icon = Icons.local_florist_rounded;
                  color = const Color(0xFFDB2777);
                  break;
                case AppThemeSeason.silverPagoda:
                  icon = Icons.church_rounded;
                  color = const Color(0xFF94A3B8);
                  break;
                case AppThemeSeason.defaultHRM:
                  icon = Icons.palette_rounded;
                  color = const Color(0xFF6366F1);
                  break;
              }

              return Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: _buildThemeOption(
                  context: context,
                  themeProvider: themeProvider,
                  isAuto: false,
                  season: season,
                  title: season.displayName,
                  icon: icon,
                  color: color,
                ),
              );
            }),
          ],
        ),
      ),
    );
  }

  Widget _buildThemeOption({
    required BuildContext context,
    required SeasonalThemeProvider themeProvider,
    required bool isAuto,
    required AppThemeSeason season,
    required String title,
    required IconData icon,
    required Color color,
  }) {
    final bool isSelected = isAuto 
        ? themeProvider.isAutoMode 
        : (!themeProvider.isAutoMode && themeProvider.currentSeason == season);

    return GestureDetector(
      onTap: () {
        if (isAuto) {
          themeProvider.setAutoMode();
        } else {
          themeProvider.setTheme(season);
        }
      },
      child: FadeInUp(
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: isSelected ? color.withValues(alpha: 0.1) : AppTheme.bgCard,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
              color: isSelected ? color : AppTheme.textPrimary.withValues(alpha: 0.05),
              width: isSelected ? 2 : 1,
            ),
          ),
          child: Row(
            children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: color.withValues(alpha: 0.2),
                  shape: BoxShape.circle,
                ),
                child: Icon(icon, color: color, size: 24),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Text(
                  title,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                    fontSize: 16,
                  ),
                ),
              ),
              if (isSelected)
                Icon(Icons.check_circle_rounded, color: color, size: 24),
            ],
          ),
        ),
      ),
    );
  }
}
