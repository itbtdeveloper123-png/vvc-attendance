import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

/// ═══════════════════════════════════════════════════════════════════════════════
/// CUPERTINO COMPONENTS SHOWCASE SCREEN
/// ═══════════════════════════════════════════════════════════════════════════════
/// ទំព័របង្ហាញ និងតេស្តផ្ទាល់នូវឈុត Apple Cupertino Native Components ទាំង ៥
/// ស្របតាមគំរូរូបភាពដែលបានស្នើសុំ ១០០% (Popup Menu, Segmented Control, Switch, Slider, Button Suite)
class CupertinoComponentsShowcaseScreen extends StatefulWidget {
  const CupertinoComponentsShowcaseScreen({super.key});

  @override
  State<CupertinoComponentsShowcaseScreen> createState() =>
      _CupertinoComponentsShowcaseScreenState();
}

class _CupertinoComponentsShowcaseScreenState
    extends State<CupertinoComponentsShowcaseScreen> {
  // 1. Popup Menu State
  String _selectedAction = 'គ្មាន (ចុចប៊ូតុងខាងក្រោមដើម្បីជ្រើសរើស)';

  // 2. Segmented Control State
  String _selectedSegment = 'One';
  int _selectedKhmerIndex = 0;

  // 3. Switch State
  bool _basicOn = true;
  bool _notificationOn = true;
  bool _biometricOn = false;

  // 4. Slider State
  double _sliderValue = 0.42;

  @override
  Widget build(BuildContext context) {
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;

    return VvcLiquidGlassScaffold(
      title: 'Cupertino Components',
      body: SingleChildScrollView(
        physics: const BouncingScrollPhysics(),
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header Info
            _buildSectionHeader(
              title: 'Apple Cupertino Native Suite',
              subtitle: 'ឈុត Components បែប Apple iOS Native រចនាឡើងតាមគំរូរូបភាពទាំង ៥',
            ),
            const SizedBox(height: 20),

            // ═══════════════════════════════════════════════════════════════════
            // ១. POPUP MENU BUTTON (រូបភាពទី ១)
            // ═══════════════════════════════════════════════════════════════════
            _buildShowcaseCard(
              title: '១. Popup Menu Button (Apple Context Menu)',
              subtitle: 'ប៊ូតុង 3-Dots អណ្តែត បើក Menu Card មូលស្អាត មាន SF Symbols, Divider និង Delete',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      VvcPopupMenuButton<String>(
                        onSelected: (val) {
                          setState(() => _selectedAction = val);
                        },
                        items: const [
                          VvcPopupMenuItem(
                            value: 'New File',
                            title: 'New File',
                            icon: CupertinoIcons.doc,
                          ),
                          VvcPopupMenuItem(
                            value: 'New Folder',
                            title: 'New Folder',
                            icon: CupertinoIcons.folder,
                            isDividerAfter: true,
                          ),
                          VvcPopupMenuItem(
                            value: 'Rename',
                            title: 'Rename',
                            icon: CupertinoIcons.pencil,
                          ),
                          VvcPopupMenuItem(
                            value: 'Delete',
                            title: 'Delete',
                            icon: CupertinoIcons.trash,
                            isDestructive: true,
                          ),
                        ],
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Text(
                          'បានជ្រើសរើស៖ $_selectedAction',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 13,
                            color: isDark ? Colors.white70 : Colors.black87,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 18),

            // ═══════════════════════════════════════════════════════════════════
            // ២. SEGMENTED CONTROL (រូបភាពទី ២)
            // ═══════════════════════════════════════════════════════════════════
            _buildShowcaseCard(
              title: '២. Segmented Control (Sliding Capsule Pill)',
              subtitle: 'Capsule Track ជាមួយ Sliding Pill សសុទ្ធរលោង និង Haptic Click',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Original "One / Two / Three" from Image 2
                  VvcSegmentedControl<String>(
                    items: const ['One', 'Two', 'Three'],
                    selectedValue: _selectedSegment,
                    onValueChanged: (val) => setState(() => _selectedSegment = val),
                    itemTitle: (val) => val,
                  ),
                  const SizedBox(height: 14),

                  // Khmer Language version
                  VvcSegmentedControl<int>(
                    items: const [0, 1, 2],
                    selectedValue: _selectedKhmerIndex,
                    onValueChanged: (val) => setState(() => _selectedKhmerIndex = val),
                    itemTitle: (val) => ['ទូទៅ', 'វត្តមាន', 'របាយការណ៍'][val],
                    itemIcon: (val) => [
                      CupertinoIcons.square_grid_2x2,
                      CupertinoIcons.checkmark_seal,
                      CupertinoIcons.chart_bar,
                    ][val],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 18),

            // ═══════════════════════════════════════════════════════════════════
            // ៣. SWITCH & SWITCH TILE (រូបភាពទី ៣)
            // ═══════════════════════════════════════════════════════════════════
            _buildShowcaseCard(
              title: '៣. Cupertino Switch (Basic ON Tile)',
              subtitle: 'Switch រាងពងក្រពើ Apple Blue #0A84FF ជាមួយ White Smooth Knob',
              child: Column(
                children: [
                  // Exact match for Image 3 "Basic ON"
                  VvcSwitchTile(
                    padding: EdgeInsets.zero,
                    title: 'Basic ON',
                    value: _basicOn,
                    onChanged: (val) => setState(() => _basicOn = val),
                  ),
                  const Divider(height: 20, thickness: 0.5),
                  VvcSwitchTile(
                    padding: EdgeInsets.zero,
                    title: 'ការជូនដំណឹង (Push Notifications)',
                    subtitle: 'ទទួលបានដំណឹងវត្តមាន និងការអនុញ្ញាតច្បាប់',
                    value: _notificationOn,
                    onChanged: (val) => setState(() => _notificationOn = val),
                  ),
                  const Divider(height: 20, thickness: 0.5),
                  VvcSwitchTile(
                    padding: EdgeInsets.zero,
                    title: 'ស្កេនម្រាមដៃ / Face ID',
                    subtitle: 'ប្រើប្រាស់ Face Recognition ស្វ័យប្រវត្តិ',
                    value: _biometricOn,
                    onChanged: (val) => setState(() => _biometricOn = val),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 18),

            // ═══════════════════════════════════════════════════════════════════
            // ៤. SLIDER (រូបភាពទី ៤)
            // ═══════════════════════════════════════════════════════════════════
            _buildShowcaseCard(
              title: '៤. Cupertino Slider (Slim Track & Ambient Thumb)',
              subtitle: 'Track ស្ដើងប្រណិត 4.5px ជាមួយដុំ White Thumb 28px និង Ambient Shadow',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        'កម្រិតពន្លឺ / សំឡេង៖',
                        style: GoogleFonts.kantumruyPro(
                          fontSize: 14,
                          fontWeight: FontWeight.w500,
                          color: isDark ? Colors.white70 : Colors.black87,
                        ),
                      ),
                      Text(
                        '${(_sliderValue * 100).toInt()}%',
                        style: GoogleFonts.kantumruyPro(
                          fontSize: 15,
                          fontWeight: FontWeight.bold,
                          color: CupertinoTokens.appleBlue,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  VvcSlider(
                    value: _sliderValue,
                    min: 0.0,
                    max: 1.0,
                    onChanged: (val) => setState(() => _sliderValue = val),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 18),

            // ═══════════════════════════════════════════════════════════════════
            // ៥. BUTTON SUITE & ICON BUTTONS (រូបភាពទី ៥)
            // ═══════════════════════════════════════════════════════════════════
            _buildShowcaseCard(
              title: '៥. Button Suite & Circular Icon Buttons',
              subtitle: 'គ្រប់ Style ទាំង ៩ [Plain, Gray, Tinted, Bordered, BorderedProminent, Filled, Glass, ProminentGlass, Disabled]',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Text Pills Row 1
                  Wrap(
                    spacing: 8,
                    runSpacing: 10,
                    children: [
                      VvcButton(
                        label: 'Plain',
                        variant: VvcButtonVariant.plain,
                        onPressed: () {},
                      ),
                      VvcButton(
                        label: 'Gray',
                        variant: VvcButtonVariant.gray,
                        onPressed: () {},
                      ),
                      VvcButton(
                        label: 'Tinted',
                        variant: VvcButtonVariant.tinted,
                        onPressed: () {},
                      ),
                      VvcButton(
                        label: 'Bordered',
                        variant: VvcButtonVariant.bordered,
                        onPressed: () {},
                      ),
                      VvcButton(
                        label: 'BorderedProminent',
                        variant: VvcButtonVariant.borderedProminent,
                        onPressed: () {},
                      ),
                      VvcButton(
                        label: 'Filled',
                        variant: VvcButtonVariant.filled,
                        onPressed: () {},
                      ),
                      VvcButton(
                        label: 'Glass',
                        variant: VvcButtonVariant.glass,
                        onPressed: () {},
                      ),
                      VvcButton(
                        label: 'ProminentGlass',
                        variant: VvcButtonVariant.prominentGlass,
                        onPressed: () {},
                      ),
                      const VvcButton(
                        label: 'Disabled',
                        variant: VvcButtonVariant.disabled,
                        onPressed: null,
                      ),
                    ],
                  ),
                  const SizedBox(height: 20),

                  // Circular Heart Icon Buttons (Image 5 bottom)
                  Text(
                    'Circular Icon Buttons (ដូចរូបបេះដូងក្នុងគំរូ)៖',
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 13,
                      fontWeight: FontWeight.bold,
                      color: isDark ? Colors.white70 : Colors.black87,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 12,
                    runSpacing: 12,
                    children: [
                      VvcIconButton(
                        icon: CupertinoIcons.heart_fill,
                        variant: VvcButtonVariant.plain,
                        onPressed: () {},
                      ),
                      VvcIconButton(
                        icon: CupertinoIcons.heart_fill,
                        variant: VvcButtonVariant.gray,
                        onPressed: () {},
                      ),
                      VvcIconButton(
                        icon: CupertinoIcons.heart_fill,
                        variant: VvcButtonVariant.tinted,
                        onPressed: () {},
                      ),
                      VvcIconButton(
                        icon: CupertinoIcons.heart_fill,
                        variant: VvcButtonVariant.bordered,
                        onPressed: () {},
                      ),
                      VvcIconButton(
                        icon: CupertinoIcons.heart_fill,
                        variant: VvcButtonVariant.filled,
                        onPressed: () {},
                      ),
                      VvcIconButton(
                        icon: CupertinoIcons.heart_fill,
                        variant: VvcButtonVariant.prominentGlass,
                        onPressed: () {},
                      ),
                      VvcIconButton(
                        icon: CupertinoIcons.heart_fill,
                        variant: VvcButtonVariant.gray,
                        iconColor: isDark ? Colors.white : Colors.black,
                        onPressed: () {},
                      ),
                      VvcIconButton(
                        icon: CupertinoIcons.heart_fill,
                        variant: VvcButtonVariant.filled,
                        onPressed: () {},
                      ),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(height: 40),
          ],
        ),
      ),
    );
  }

  Widget _buildSectionHeader({required String title, required String subtitle}) {
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: GoogleFonts.kantumruyPro(
            fontSize: 20,
            fontWeight: FontWeight.bold,
            color: isDark ? Colors.white : Colors.black87,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          subtitle,
          style: GoogleFonts.kantumruyPro(
            fontSize: 13,
            color: isDark ? Colors.white54 : Colors.black54,
          ),
        ),
      ],
    );
  }

  Widget _buildShowcaseCard({
    required String title,
    required String subtitle,
    required Widget child,
  }) {
    final isDark = AppTheme.isDarkMode || Theme.of(context).brightness == Brightness.dark;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF1C1C1E) : Colors.white,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: isDark ? Colors.white.withValues(alpha: 0.08) : Colors.black.withValues(alpha: 0.05),
          width: 0.8,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: isDark ? 0.35 : 0.04),
            blurRadius: 16,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: GoogleFonts.kantumruyPro(
              fontSize: 15,
              fontWeight: FontWeight.bold,
              color: isDark ? Colors.white : Colors.black87,
            ),
          ),
          const SizedBox(height: 3),
          Text(
            subtitle,
            style: GoogleFonts.kantumruyPro(
              fontSize: 12,
              color: isDark ? Colors.white54 : Colors.black54,
            ),
          ),
          const SizedBox(height: 16),
          child,
        ],
      ),
    );
  }
}
