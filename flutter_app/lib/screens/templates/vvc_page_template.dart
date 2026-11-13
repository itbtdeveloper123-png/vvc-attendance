import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../widgets/app_widgets.dart';

/// ═══════════════════════════════════════════════════════════════════════════════
/// VVC STANDARD PAGE TEMPLATE (BOILERPLATE)
/// ═══════════════════════════════════════════════════════════════════════════════
/// គំរូទំព័រស្តង់ដាររួមសម្រាប់ចម្លងយកទៅប្រើប្រាស់ពេលបង្កើត Page ថ្មីៗ។
/// មានរួចជាស្រេចនូវ៖ Header Pods, Search Bar, Telegram Filter Chips,
/// Bento Cards, Empty State with Lottie, និង Hero CTA Capsule Button។

class VvcStandardPageTemplate extends StatefulWidget {
  const VvcStandardPageTemplate({super.key});

  @override
  State<VvcStandardPageTemplate> createState() => _VvcStandardPageTemplateState();
}

class _VvcStandardPageTemplateState extends State<VvcStandardPageTemplate> {
  final TextEditingController _searchController = TextEditingController();
  String _selectedFilter = 'all';
  bool _isLoading = false;
  List<String> _items = ['Item 1', 'Item 2', 'Item 3'];

  Future<void> _refreshData() async {
    setState(() => _isLoading = true);
    await Future.delayed(const Duration(milliseconds: 600));
    if (mounted) {
      setState(() => _isLoading = false);
    }
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final scaffoldBg = isDark ? AppTokens.bgDark : AppTokens.bgLight;

    return Scaffold(
      backgroundColor: scaffoldBg,
      // 1. Unified Header Bar
      appBar: VvcAppBar(
        title: Text(
          'ទំព័រគំរូស្តង់ដារ',
          style: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.bold,
            fontSize: 15.5,
          ),
        ),
        actions: [
          IconButton(
            icon: const Icon(CupertinoIcons.add, size: 20),
            onPressed: () {
              // Action handler (e.g. Create new item)
            },
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            const SizedBox(height: 8),

            // 2. Full Capsule Search Bar
            VvcSearchBar(
              controller: _searchController,
              hintText: 'ស្វែងរកទិន្នន័យ...',
              onChanged: (val) => setState(() {}),
            ),
            const SizedBox(height: 10),

            // 3. Telegram-Style Category Filter Tabs
            VvcFilterChips(
              selectedKey: _selectedFilter,
              onSelected: (key) => setState(() => _selectedFilter = key),
              items: [
                VvcFilterItem(key: 'all', label: 'ទាំងអស់', count: _items.length),
                const VvcFilterItem(key: 'pending', label: 'រង់ចាំ', count: 1),
                const VvcFilterItem(key: 'completed', label: 'ជោគជ័យ', count: 2),
              ],
            ),
            const SizedBox(height: 12),

            // 4. Content Area / List View
            Expanded(
              child: _isLoading
                  ? const Center(child: CircularProgressIndicator(color: AppTokens.gold))
                  : _items.isEmpty
                      ? VvcEmptyState(
                          useLottie: true,
                          title: 'មិនទាន់មានទិន្នន័យឡើយ',
                          subtitle: 'សូមចុចប៊ូតុងខាងក្រោមដើម្បីបង្កើតទិន្នន័យដំបូង',
                          buttonLabel: 'បង្កើតថ្មី',
                          buttonIcon: CupertinoIcons.plus_circle,
                          onButtonTap: () {
                            setState(() {
                              _items = ['Item 1', 'Item 2'];
                            });
                          },
                        )
                      : RefreshIndicator(
                          onRefresh: _refreshData,
                          color: AppTokens.gold,
                          child: ListView.builder(
                            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                            itemCount: _items.length,
                            itemBuilder: (context, index) {
                              return _buildBentoCard(index);
                            },
                          ),
                        ),
            ),

            // 5. Fixed Bottom Hero Capsule CTA Button (Optional)
            Padding(
              padding: const EdgeInsets.all(14.0),
              child: VvcPillButton(
                text: 'បញ្ជាក់ទិន្នន័យ (Confirm Action)',
                icon: CupertinoIcons.checkmark_seal_fill,
                variant: VvcPillVariant.gold,
                size: VvcButtonSize.hero,
                isFullWidth: true,
                onTap: () {
                  // Hero CTA action
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  // Example Bento Item Card
  Widget _buildBentoCard(int index) {
    return VvcBentoCard(
      margin: const EdgeInsets.only(bottom: 12),
      onTap: () {
        // Item tap handler
      },
      child: Row(
        children: [
          // Circular Icon Pod
          Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              color: AppTokens.gold.withValues(alpha: 0.15),
              shape: BoxShape.circle,
            ),
            child: const Center(
              child: Icon(CupertinoIcons.doc_text_fill, color: AppTokens.gold, size: 20),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'ឯកសារគំរូទី ${index + 1}',
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 14.5,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  'ព័ត៌មានលម្អិតសង្ខេបសម្រាប់បង្ហាញ...',
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 12,
                    color: const Color(0xFF94A3B8),
                  ),
                ),
              ],
            ),
          ),
          // Compact Status Pill
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              color: AppTokens.emeraldGreen.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(AppTokens.radiusPill),
              border: Border.all(color: AppTokens.emeraldGreen.withValues(alpha: 0.3)),
            ),
            child: Text(
              'សកម្ម',
              style: GoogleFonts.kantumruyPro(
                fontSize: 11,
                color: AppTokens.emeraldGreen,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
