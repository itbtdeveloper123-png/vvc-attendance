import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../utils/app_theme.dart';
import '../services/api_service.dart';
import '../widgets/app_widgets.dart';

class MaterialItem {
  final int id;
  final String name;
  final int stock;
  final String icon;

  MaterialItem({
    required this.id,
    required this.name,
    required this.stock,
    required this.icon,
  });
}

class RequestItem {
  MaterialItem? material;
  int quantity;
  String note;

  RequestItem({this.material, this.quantity = 1, this.note = ''});
}

class MaterialRequestScreen extends StatefulWidget {
  const MaterialRequestScreen({super.key});

  @override
  State<MaterialRequestScreen> createState() => _MaterialRequestScreenState();
}

class _MaterialRequestScreenState extends State<MaterialRequestScreen> {
  final _formKey = GlobalKey<FormState>();
  String? _selectedLocation;
  bool _isSubmitting = false;

  final List<MaterialItem> _availableMaterials = [];
  bool _isLoadingMaterials = false;
  final ApiService _apiService = ApiService();
  final TextEditingController _searchController = TextEditingController();
  String _searchQuery = '';

  final List<RequestItem> _requestItems = [];

  @override
  void initState() {
    super.initState();
    // Start with one empty item
    _requestItems.add(RequestItem());
    _fetchMaterials();
    _searchController.addListener(() {
      setState(() {
        _searchQuery = _searchController.text.toLowerCase();
      });
    });
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  List<MaterialItem> get _filteredMaterials {
    if (_searchQuery.isEmpty) return _availableMaterials;
    return _availableMaterials.where((item) {
      return item.name.toLowerCase().contains(_searchQuery);
    }).toList();
  }

  Future<void> _fetchMaterials() async {
    setState(() => _isLoadingMaterials = true);
    try {
      final res = await _apiService.fetchMaterialItems();
      if (res['success'] == true && res['items'] != null) {
        final List<dynamic> items = res['items'];
        setState(() {
          _availableMaterials.clear();
          for (var item in items) {
            _availableMaterials.add(
              MaterialItem(
                id: item['id'],
                name: item['item_name'],
                stock: item['quantity'],
                icon: _getIconForCategory(item['category'] ?? ''),
              ),
            );
          }
        });
      }
    } catch (e) {
      debugPrint('Error fetching materials: $e');
    } finally {
      setState(() => _isLoadingMaterials = false);
    }
  }

  String _getIconForCategory(String category) {
    category = category.toLowerCase();
    if (category.contains('paper') || category.contains('office')) return '📄';
    if (category.contains('drink') || category.contains('milk')) return '🥛';
    if (category.contains('tool') || category.contains('hardware')) {
      return '🛠️';
    }
    if (category.contains('stationery')) return '📎';
    if (category.contains('it') || category.contains('computer')) return '💻';
    return '📦';
  }

  void _addMaterialRow() {
    setState(() {
      _requestItems.add(RequestItem());
    });
  }

  void _removeMaterialRow(int index) {
    if (_requestItems.length > 1) {
      setState(() {
        _requestItems.removeAt(index);
      });
    } else {
      // Clear the single item if it's the only one
      setState(() {
        _requestItems[0] = RequestItem();
      });
    }
  }

  Future<void> _submitRequest() async {
    if (!_formKey.currentState!.validate()) return;

    // Check if any material is selected
    final List<RequestItem> validItems = _requestItems
        .where((item) => item.material != null)
        .toList();
    if (validItems.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('សូមជ្រើសរើសសម្ភារៈយ៉ាងហោចណាស់មួយ!')),
      );
      return;
    }

    setState(() => _isSubmitting = true);

    try {
      final List<Map<String, dynamic>> submitItems = validItems.map((item) {
        return {
          'id': item.material!.id,
          'name': item.material!.name,
          'quantity': item.quantity,
          'notes': item.note,
        };
      }).toList();

      final res = await _apiService.submitMaterialRequest({
        'location': _selectedLocation ?? 'N/A',
        'items': submitItems,
      });

      if (res['success'] == true) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                'សំណើសុំសម្ភារៈលេខ ${res['request_no']} ត្រូវបានបញ្ជូនដោយជោគជ័យ!',
              ),
            ),
          );
          Navigator.pop(context);
        }
      } else {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('មានបញ្ហា: ${res['message']}')),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('កំហុសការភ្ជាប់: $e')));
      }
    } finally {
      if (mounted) setState(() => _isSubmitting = false);
    }
  }

  void _openLocationPicker(List<String> locations) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (context) {
        return Container(
          height: MediaQuery.of(context).size.height * 0.6,
          decoration: BoxDecoration(
            color: AppTheme.bgDark,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.5),
                blurRadius: 20,
                offset: const Offset(0, -5),
              ),
            ],
          ),
          child: Column(
            children: [
              const SizedBox(height: 12),
              Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: Colors.white24,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'ជ្រើសរើសទីតាំង',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 16),
              Divider(height: 1, color: AppTheme.borderColor),
              Expanded(
                child: ListView.separated(
                  physics: const BouncingScrollPhysics(),
                  padding: const EdgeInsets.symmetric(
                    horizontal: 20,
                    vertical: 16,
                  ),
                  itemCount: locations.length,
                  separatorBuilder: (context, index) =>
                      const SizedBox(height: 10),
                  itemBuilder: (context, index) {
                    final loc = locations[index];
                    final isSelected = _selectedLocation == loc;
                    return InkWell(
                      onTap: () {
                        setState(() => _selectedLocation = loc);
                        Navigator.pop(context);
                      },
                      borderRadius: BorderRadius.circular(16),
                      child: Container(
                        padding: const EdgeInsets.all(16),
                        decoration: BoxDecoration(
                          color: isSelected
                              ? const Color(0xFF6366F1).withValues(alpha: 0.15)
                              : AppTheme.bgCardLight.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(16),
                          border: Border.all(
                            color: isSelected
                                ? const Color(0xFF6366F1)
                                : AppTheme.borderColor,
                          ),
                        ),
                        child: Row(
                          children: [
                            Icon(
                              Icons.storefront_rounded,
                              color: isSelected
                                  ? const Color(0xFF6366F1)
                                  : AppTheme.textMuted,
                              size: 24,
                            ),
                            const SizedBox(width: 16),
                            Expanded(
                              child: Text(
                                loc,
                                style: GoogleFonts.kantumruyPro(
                                  color: isSelected
                                      ? Colors.white
                                      : AppTheme.textSecondary,
                                  fontWeight: isSelected
                                      ? FontWeight.bold
                                      : FontWeight.w500,
                                  fontSize: 14,
                                ),
                              ),
                            ),
                            if (isSelected)
                              const Icon(
                                Icons.check_circle_rounded,
                                color: Color(0xFF6366F1),
                                size: 20,
                              ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  void _openMaterialPicker(int itemIndex) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (context) {
        return Container(
          height: MediaQuery.of(context).size.height * 0.7,
          decoration: BoxDecoration(
            color: AppTheme.bgDark,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.5),
                blurRadius: 20,
                offset: const Offset(0, -5),
              ),
            ],
          ),
          child: Column(
            children: [
              const SizedBox(height: 12),
              Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: Colors.white24,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'ជ្រើសរើសសម្ភារៈ',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 16),
              Divider(height: 1, color: AppTheme.borderColor),
              Expanded(
                child: ListView.separated(
                  physics: const BouncingScrollPhysics(),
                  padding: const EdgeInsets.symmetric(
                    horizontal: 20,
                    vertical: 16,
                  ),
                  itemCount: _availableMaterials.length,
                  separatorBuilder: (context, index) =>
                      const SizedBox(height: 10),
                  itemBuilder: (context, index) {
                    final mat = _availableMaterials[index];
                    final currentSelection = _requestItems[itemIndex].material;
                    final isSelected = currentSelection?.id == mat.id;
                    return InkWell(
                      onTap: () {
                        setState(() {
                          _requestItems[itemIndex].material = mat;
                        });
                        Navigator.pop(context);
                      },
                      borderRadius: BorderRadius.circular(16),
                      child: Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: isSelected
                              ? const Color(0xFF6366F1).withValues(alpha: 0.15)
                              : AppTheme.bgCardLight.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(16),
                          border: Border.all(
                            color: isSelected
                                ? const Color(0xFF6366F1)
                                : AppTheme.borderColor,
                          ),
                        ),
                        child: Row(
                          children: [
                            Container(
                              width: 44,
                              height: 44,
                              decoration: BoxDecoration(
                                color: AppTheme.bgDark,
                                borderRadius: BorderRadius.circular(12),
                              ),
                              alignment: Alignment.center,
                              child: Text(
                                mat.icon,
                                style: const TextStyle(fontSize: 20),
                              ),
                            ),
                            const SizedBox(width: 16),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    mat.name,
                                    maxLines: 2,
                                    overflow: TextOverflow.ellipsis,
                                    style: GoogleFonts.kantumruyPro(
                                      color: isSelected
                                          ? Colors.white
                                          : AppTheme.textSecondary,
                                      fontWeight: isSelected
                                          ? FontWeight.bold
                                          : FontWeight.w500,
                                      fontSize: 14,
                                    ),
                                  ),
                                  const SizedBox(height: 4),
                                  Text(
                                    'ស្តុកមាន: ${mat.stock}',
                                    style: GoogleFonts.kantumruyPro(
                                      color: mat.stock <= 5
                                          ? Colors.redAccent
                                          : Colors.tealAccent,
                                      fontSize: 12,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            if (isSelected)
                              const Icon(
                                Icons.check_circle_rounded,
                                color: Color(0xFF6366F1),
                                size: 22,
                              ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final user = Provider.of<UserProvider>(context);
    final isDesktop = MediaQuery.of(context).size.width > 800;

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        title: Text(
          'សុំសម្ភារៈប្រើប្រាស់',
          style: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.bold,
            fontSize: 20,
            color: Colors.white,
          ),
        ),
        elevation: 0,
        backgroundColor: AppTheme.bgDark.withValues(alpha: 0.8),
        foregroundColor: Colors.white,
        centerTitle: true,
      ),
      body: SafeArea(
        child: isDesktop ? _buildDesktopLayout(user) : _buildMobileLayout(user),
      ),
    );
  }

  Widget _buildDesktopLayout(UserProvider user) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          flex: 5,
          child: SingleChildScrollView(
            physics: const BouncingScrollPhysics(),
            padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 30),
            child: _buildFormContent(user),
          ),
        ),
        Container(width: 1, color: AppTheme.borderColor),
        Expanded(flex: 3, child: _buildStockContent()),
      ],
    );
  }

  Widget _buildMobileLayout(UserProvider user) {
    final stockHeight = (MediaQuery.sizeOf(context).height * 0.38).clamp(
      280.0,
      360.0,
    );
    return Column(
      children: [
        Expanded(
          child: SingleChildScrollView(
            physics: const BouncingScrollPhysics(),
            padding: EdgeInsets.fromLTRB(
              AppResponsive.horizontalPadding(context),
              16,
              AppResponsive.horizontalPadding(context),
              AppResponsive.bottomPadding(context, extra: 12),
            ),
            child: AppResponsive.maxWidth(
              context: context,
              child: _buildFormContent(user),
            ),
          ),
        ),
        // A mini expandable or simple persistent bottom bar to view stock could be placed here,
        // but for now we just append it smoothly at the bottom or make it a tab.
        // Putting it inline with a clear separator makes it scrollable easily.
        Container(
          width: double.infinity,
          height: 1,
          color: AppTheme.borderColor,
          margin: const EdgeInsets.symmetric(vertical: 8),
        ),
        SizedBox(height: stockHeight.toDouble(), child: _buildStockContent()),
      ],
    );
  }

  // Ultra-Clean Custom TextField
  Widget _buildCleanTextField({
    required String hint,
    required IconData icon,
    String? initialValue,
    Function(String)? onChanged,
    TextInputType keyboardType = TextInputType.text,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 15),
      decoration: BoxDecoration(
        color: AppTheme.fieldFill,
        borderRadius: BorderRadius.circular(AppTheme.radiusMd),
        border: Border.all(color: AppTheme.fieldBorder),
      ),
      child: Row(
        children: [
          Icon(icon, color: AppTheme.fieldIconColor, size: 20),
          const SizedBox(width: 12),
          Expanded(
            child: TextFormField(
              initialValue: initialValue,
              onChanged: onChanged,
              keyboardType: keyboardType,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 14,
              ),
              decoration: InputDecoration.collapsed(
                hintText: hint,
                hintStyle: GoogleFonts.kantumruyPro(
                  color: AppTheme.fieldHintColor,
                  fontSize: 13,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFormContent(UserProvider user) {
    return Form(
      key: _formKey,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Elegant Header Profile
          Container(
            padding: const EdgeInsets.all(16),
            decoration: AppTheme.cardDecoration(
              color: AppTheme.primary.withValues(alpha: 0.08),
              radius: AppTheme.radiusLg,
              borderColor: AppTheme.primary.withValues(alpha: 0.18),
            ),
            child: Row(
              children: [
                CircleAvatar(
                  radius: 26,
                  backgroundColor: AppTheme.primary,
                  backgroundImage:
                      user.avatarUrl != null && user.avatarUrl!.isNotEmpty
                      ? NetworkImage(user.avatarUrl!)
                      : null,
                  child: (user.avatarUrl == null || user.avatarUrl!.isEmpty)
                      ? const Icon(Icons.person, color: Colors.white)
                      : null,
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        user.name ?? 'អ្នកប្រើប្រាស់',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      Text(
                        'អ្នកស្នើសុំ',
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.primaryLight,
                          fontSize: 13,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 32),

          // Location Selection
          Text(
            'ទីតាំងស្នើសុំ',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontSize: 16,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 12),
          InkWell(
            onTap: () => _openLocationPicker(user.materialLocations),
            borderRadius: BorderRadius.circular(16),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 18),
              decoration: BoxDecoration(
                color: AppTheme.fieldFill,
                borderRadius: BorderRadius.circular(AppTheme.radiusMd),
                border: Border.all(color: AppTheme.fieldBorder),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.location_on_rounded,
                    color: AppTheme.primaryLight,
                    size: 20,
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Text(
                      _selectedLocation ?? '-- ជ្រើសរើសទីតាំង --',
                      style: GoogleFonts.kantumruyPro(
                        color: _selectedLocation == null
                            ? AppTheme.textMuted
                            : Colors.white,
                        fontSize: 14,
                        fontWeight: _selectedLocation == null
                            ? FontWeight.normal
                            : FontWeight.w500,
                      ),
                    ),
                  ),
                  const Icon(
                    Icons.keyboard_arrow_down_rounded,
                    color: Colors.grey,
                  ),
                ],
              ),
            ),
          ),

          const SizedBox(height: 32),
          Text(
            'បញ្ជីសម្ភារៈ',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontSize: 16,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 16),

          // Items List using Animated List style
          ListView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: _requestItems.length,
            itemBuilder: (context, index) {
              final item = _requestItems[index];
              return Container(
                margin: const EdgeInsets.only(bottom: 16),
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: AppTheme.bgCard,
                  borderRadius: BorderRadius.circular(AppTheme.radiusLg),
                  border: Border.all(color: AppTheme.cardBorder),
                ),
                child: Column(
                  children: [
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.center,
                      children: [
                        // Number circle
                        Container(
                          width: 28,
                          height: 28,
                          decoration: BoxDecoration(
                            color: AppTheme.bgDark,
                            shape: BoxShape.circle,
                          ),
                          child: Center(
                            child: Text(
                              '${index + 1}',
                              style: GoogleFonts.inter(
                                color: AppTheme.textMuted,
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        // Dropdown Replaced by BottomSheet trigger Box
                        Expanded(
                          child: InkWell(
                            onTap: () => _openMaterialPicker(index),
                            borderRadius: BorderRadius.circular(12),
                            child: Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                                vertical: 12,
                              ),
                              decoration: BoxDecoration(
                                color: AppTheme.bgCardLight.withValues(
                                  alpha: 0.15,
                                ),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: AppTheme.borderColor),
                              ),
                              child: Row(
                                children: [
                                  if (item.material != null) ...[
                                    Container(
                                      padding: const EdgeInsets.all(4),
                                      decoration: BoxDecoration(
                                        color: Colors.white.withValues(
                                          alpha: 0.05,
                                        ),
                                        borderRadius: BorderRadius.circular(8),
                                      ),
                                      child: Text(
                                        item.material!.icon,
                                        style: const TextStyle(fontSize: 16),
                                      ),
                                    ),
                                    const SizedBox(width: 10),
                                  ],
                                  Expanded(
                                    child: Text(
                                      item.material?.name ?? 'ជ្រើសរើសមុខទំនិញ',
                                      maxLines: 1,
                                      overflow: TextOverflow.ellipsis,
                                      style: GoogleFonts.kantumruyPro(
                                        color: item.material == null
                                            ? AppTheme.textMuted
                                            : Colors.white,
                                        fontWeight: item.material == null
                                            ? FontWeight.normal
                                            : FontWeight.w600,
                                        fontSize: 13,
                                      ),
                                    ),
                                  ),
                                  const Icon(
                                    Icons.expand_more_rounded,
                                    color: Colors.white54,
                                    size: 20,
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                        // Delete Button
                        IconButton(
                          icon: const Icon(
                            Icons.close_rounded,
                            color: Colors.redAccent,
                            size: 20,
                          ),
                          onPressed: () => _removeMaterialRow(index),
                          padding: EdgeInsets.zero,
                          constraints: const BoxConstraints(),
                        ),
                      ],
                    ),
                    const Padding(
                      padding: EdgeInsets.symmetric(vertical: 8),
                      child: Divider(color: Colors.white10),
                    ),
                    Row(
                      children: [
                        Expanded(
                          flex: 2,
                          child: _buildCleanTextField(
                            hint: 'កំណត់ចំណាំផ្សេងៗ',
                            icon: Icons.edit_note_rounded,
                            initialValue: item.note,
                            onChanged: (val) => item.note = val,
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          flex: 1,
                          child: _buildCleanTextField(
                            hint: 'ចំនួន',
                            icon: Icons.shopping_bag_outlined,
                            initialValue: item.quantity.toString(),
                            keyboardType: TextInputType.number,
                            onChanged: (val) =>
                                item.quantity = int.tryParse(val) ?? 1,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              );
            },
          ),

          // Ultra-modern Dashed Add Button
          GestureDetector(
            onTap: _addMaterialRow,
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(vertical: 16),
              decoration: BoxDecoration(
                color: Colors.cyanAccent.withValues(alpha: 0.05),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(
                  color: Colors.cyanAccent.withValues(alpha: 0.3),
                  style: BorderStyle.solid,
                ), // In a real app we might use dotted border package, but solid light is very clean too
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(
                    Icons.add_circle_rounded,
                    color: Colors.cyanAccent,
                    size: 20,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'បន្ថែមជួរថ្មី',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.cyanAccent,
                      fontWeight: FontWeight.bold,
                      fontSize: 14,
                    ),
                  ),
                ],
              ),
            ),
          ),

          const SizedBox(height: 40),

          // Submit Button
          SizedBox(
            width: double.infinity,
            height: 56,
            child: ElevatedButton(
              onPressed: _isSubmitting ? null : _submitRequest,
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.primary,
                foregroundColor: AppTheme.textPrimary,
                elevation: 8,
                shadowColor: AppTheme.primary.withValues(alpha: 0.35),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(AppTheme.radiusLg),
                ),
              ),
              child: _isSubmitting
                  ? const SizedBox(
                      width: 24,
                      height: 24,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: Colors.white,
                      ),
                    )
                  : Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.send_rounded, size: 20),
                        const SizedBox(width: 10),
                        Text(
                          'បញ្ជូនសំណើ',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
            ),
          ),
          const SizedBox(height: 20),
        ],
      ),
    );
  }

  Widget _buildStockContent() {
    return Container(
      color: AppTheme.bgDark.withValues(alpha: 0.5),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.all(20),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: AppTheme.borderColor),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.search_rounded,
                    color: AppTheme.textMuted,
                    size: 20,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: TextField(
                      controller: _searchController,
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontSize: 14,
                      ),
                      decoration: InputDecoration.collapsed(
                        hintText: 'ស្វែងរកស្តុកទំនិញ...',
                        hintStyle: GoogleFonts.kantumruyPro(
                          color: AppTheme.textMuted,
                          fontSize: 13,
                        ),
                      ),
                    ),
                  ),
                  if (_searchQuery.isNotEmpty)
                    InkWell(
                      borderRadius: BorderRadius.circular(999),
                      onTap: _searchController.clear,
                      child: Padding(
                        padding: const EdgeInsets.all(4),
                        child: Icon(
                          Icons.cancel_rounded,
                          color: AppTheme.textMuted,
                          size: 16,
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
          Expanded(
            child: _isLoadingMaterials
                ? const Center(
                    child: CircularProgressIndicator(color: Colors.cyanAccent),
                  )
                : _filteredMaterials.isEmpty
                ? Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          Icons.inventory_2_outlined,
                          size: 40,
                          color: AppTheme.textMuted.withValues(alpha: 0.4),
                        ),
                        const SizedBox(height: 12),
                        Text(
                          'គ្មានទិន្នន័យ',
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textSecondary,
                          ),
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 20,
                      vertical: 8,
                    ),
                    physics: const BouncingScrollPhysics(),
                    itemCount: _filteredMaterials.length,
                    itemBuilder: (context, index) {
                      final mat = _filteredMaterials[index];
                      // Use an elegant mini card
                      return Container(
                        margin: const EdgeInsets.only(bottom: 12),
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: AppTheme.bgCardLight.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(16),
                        ),
                        child: Row(
                          children: [
                            Container(
                              width: 40,
                              height: 40,
                              decoration: BoxDecoration(
                                color: AppTheme.bgDark,
                                borderRadius: BorderRadius.circular(10),
                              ),
                              alignment: Alignment.center,
                              child: Text(
                                mat.icon,
                                style: const TextStyle(fontSize: 18),
                              ),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    mat.name,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.white,
                                      fontWeight: FontWeight.w600,
                                      fontSize: 13,
                                    ),
                                  ),
                                  const SizedBox(height: 4),
                                  Text(
                                    'នៅសល់ស្តុក: ${mat.stock}',
                                    style: GoogleFonts.kantumruyPro(
                                      color: mat.stock <= 5
                                          ? Colors.redAccent
                                          : Colors.tealAccent,
                                      fontSize: 11,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}
