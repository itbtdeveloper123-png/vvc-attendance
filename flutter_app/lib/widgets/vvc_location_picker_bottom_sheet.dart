import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Reusable VVC Dark Theme "Location" Picker Modal Bottom Sheet Component
class VvcLocationPickerBottomSheet extends StatefulWidget {
  final Function(Map<String, dynamic> locationData)? onSendLocation;
  final Function(String category)? onTabChanged;

  const VvcLocationPickerBottomSheet({
    super.key,
    this.onSendLocation,
    this.onTabChanged,
  });

  static Future<T?> show<T>({
    required BuildContext context,
    Function(Map<String, dynamic> locationData)? onSendLocation,
    Function(String category)? onTabChanged,
  }) {
    return showModalBottomSheet<T>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => VvcLocationPickerBottomSheet(
        onSendLocation: onSendLocation,
        onTabChanged: onTabChanged,
      ),
    );
  }

  @override
  State<VvcLocationPickerBottomSheet> createState() => _VvcLocationPickerBottomSheetState();
}

class _VvcLocationPickerBottomSheetState extends State<VvcLocationPickerBottomSheet> {
  String _activeTab = 'Location';
  final TextEditingController _searchController = TextEditingController();
  bool _isSearchActive = false;

  // Theme Colors
  static const Color _bgColor = Color(0xFF1C1C1E);
  static const Color _cardColor = Color(0xFF2C2C2E);
  static const Color _accentColor = Color(0xFF3388FF);
  static const Color _dividerColor = Color(0x1FFFFFFF);
  static const Color _mutedColor = Color(0xFF8E8E93);

  // Mockup Nearby Places Data
  final List<Map<String, dynamic>> _nearbyPlaces = [
    {
      'name': 'Brown Coffee & Bakery',
      'address': 'Monivong Blvd, Phnom Penh',
      'icon': Icons.local_cafe_rounded,
      'color': const Color(0xFFFF9F0A),
      'latitude': 11.5564,
      'longitude': 104.9282,
    },
    {
      'name': 'Major Cineplex AEON Mall 1',
      'address': 'Samdech Sothearos Blvd, Phnom Penh',
      'icon': Icons.movie_rounded,
      'color': const Color(0xFFBF5AF2),
      'latitude': 11.5478,
      'longitude': 104.9351,
    },
    {
      'name': 'ABA Bank Head Office',
      'address': 'Preah Sihanouk Blvd, Phnom Penh',
      'icon': Icons.account_balance_rounded,
      'color': const Color(0xFF0A84FF),
      'latitude': 11.5532,
      'longitude': 104.9214,
    },
    {
      'name': 'Central Market (Phsar Thmei)',
      'address': 'St 128 (Kampuchea Krom), Phnom Penh',
      'icon': Icons.shopping_bag_rounded,
      'color': const Color(0xFF30D158),
      'latitude': 11.5696,
      'longitude': 104.9210,
    },
    {
      'name': 'Malu Restaurant BKK1',
      'address': 'St 310, Boeung Keng Kang 1',
      'icon': Icons.restaurant_rounded,
      'color': const Color(0xFFFF375F),
      'latitude': 11.5499,
      'longitude': 104.9255,
    },
  ];

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _sendCurrentLocation() {
    final locationData = {
      'type': 'current_location',
      'name': 'Current Location',
      'address': 'Accurate to 10 metres',
      'latitude': 11.5564,
      'longitude': 104.9282,
      'timestamp': DateTime.now().toIso8601String(),
    };

    Navigator.pop(context);
    widget.onSendLocation?.call(locationData);
  }

  void _sendSelectedPlace(Map<String, dynamic> place) {
    final locationData = {
      'type': 'place',
      'name': place['name'],
      'address': place['address'],
      'latitude': place['latitude'],
      'longitude': place['longitude'],
      'timestamp': DateTime.now().toIso8601String(),
    };

    Navigator.pop(context);
    widget.onSendLocation?.call(locationData);
  }

  @override
  Widget build(BuildContext context) {
    final double maxSheetHeight = MediaQuery.of(context).size.height * 0.90;

    return Container(
      constraints: BoxConstraints(maxHeight: maxSheetHeight),
      decoration: const BoxDecoration(
        color: _bgColor,
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: 10),
          Center(
            child: Container(
              width: 36,
              height: 4.5,
              decoration: BoxDecoration(
                color: const Color(0xFF48484A),
                borderRadius: BorderRadius.circular(2.5),
              ),
            ),
          ),
          const SizedBox(height: 8),

          _buildMapViewHeaderSection(),
          const SizedBox(height: 12),

          Expanded(
            child: SingleChildScrollView(
              physics: const BouncingScrollPhysics(),
              padding: const EdgeInsets.symmetric(horizontal: 16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildCurrentLocationCard(),
                  const SizedBox(height: 24),

                  Text(
                    'OR CHOOSE A PLACE',
                    style: GoogleFonts.inter(
                      color: _mutedColor,
                      fontSize: 12.0,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 0.5,
                    ),
                  ),
                  const SizedBox(height: 8),

                  _buildNearbyPlacesCard(),
                  const SizedBox(height: 20),
                ],
              ),
            ),
          ),

          _buildBottomNavBar(),
        ],
      ),
    );
  }

  Widget _buildMapViewHeaderSection() {
    return Container(
      height: 220,
      width: double.infinity,
      margin: const EdgeInsets.symmetric(horizontal: 16),
      decoration: BoxDecoration(
        color: const Color(0xFF151D2A),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08), width: 0.8),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(16),
        child: Stack(
          children: [
            CustomPaint(
              size: Size.infinite,
              painter: _DarkMapPainter(),
            ),

            Center(
              child: Padding(
                padding: const EdgeInsets.only(bottom: 24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      padding: const EdgeInsets.all(3),
                      decoration: const BoxDecoration(
                        color: Colors.white,
                        shape: BoxShape.circle,
                        boxShadow: [
                          BoxShadow(color: Colors.black45, blurRadius: 10, offset: Offset(0, 4)),
                        ],
                      ),
                      child: const CircleAvatar(
                        radius: 18,
                        backgroundColor: _accentColor,
                        child: Icon(Icons.person_rounded, color: Colors.white, size: 20),
                      ),
                    ),
                    const Icon(Icons.arrow_drop_down_rounded, color: Colors.white, size: 24),
                  ],
                ),
              ),
            ),

            Positioned(
              top: 8,
              left: 12,
              right: 12,
              child: _isSearchActive ? _buildMapSearchBar() : _buildMapHeaderRow(),
            ),

            Positioned(
              bottom: 12,
              right: 12,
              child: Column(
                children: [
                  _buildFloatingMapButton(
                    icon: Icons.layers_rounded,
                    onTap: () {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text('Switched Map Style', style: GoogleFonts.inter()),
                          duration: const Duration(seconds: 1),
                        ),
                      );
                    },
                  ),
                  const SizedBox(height: 8),
                  _buildFloatingMapButton(
                    icon: Icons.my_location_rounded,
                    iconColor: _accentColor,
                    onTap: () {},
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildMapHeaderRow() {
    return Container(
      height: 38,
      padding: const EdgeInsets.symmetric(horizontal: 8),
      decoration: BoxDecoration(
        color: Colors.black.withValues(alpha: 0.45),
        borderRadius: BorderRadius.circular(19),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          IconButton(
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
            icon: const Icon(Icons.close_rounded, color: Colors.white, size: 20),
            onPressed: () => Navigator.pop(context),
          ),
          Text(
            'Location',
            style: GoogleFonts.inter(
              color: Colors.white,
              fontSize: 15,
              fontWeight: FontWeight.bold,
            ),
          ),
          IconButton(
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
            icon: const Icon(Icons.search_rounded, color: Colors.white, size: 20),
            onPressed: () {
              setState(() {
                _isSearchActive = true;
              });
            },
          ),
        ],
      ),
    );
  }

  Widget _buildMapSearchBar() {
    return Container(
      height: 38,
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(19),
      ),
      padding: const EdgeInsets.symmetric(horizontal: 10),
      child: Row(
        children: [
          const Icon(Icons.search_rounded, color: _mutedColor, size: 18),
          const SizedBox(width: 8),
          Expanded(
            child: TextField(
              controller: _searchController,
              autofocus: true,
              style: GoogleFonts.inter(color: Colors.white, fontSize: 13.5),
              cursorColor: _accentColor,
              decoration: InputDecoration(
                hintText: 'Search location or place',
                hintStyle: GoogleFonts.inter(color: _mutedColor, fontSize: 13.5),
                border: InputBorder.none,
                isDense: true,
              ),
              onChanged: (_) => setState(() {}),
            ),
          ),
          InkWell(
            onTap: () {
              _searchController.clear();
              setState(() {
                _isSearchActive = false;
              });
            },
            child: const Icon(Icons.cancel_rounded, color: _mutedColor, size: 16),
          ),
        ],
      ),
    );
  }

  Widget _buildFloatingMapButton({
    required IconData icon,
    Color iconColor = Colors.white,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(20),
      child: Container(
        width: 36,
        height: 36,
        decoration: BoxDecoration(
          color: _cardColor.withValues(alpha: 0.90),
          shape: BoxShape.circle,
          border: Border.all(color: Colors.white.withValues(alpha: 0.12), width: 0.8),
        ),
        child: Icon(icon, color: iconColor, size: 18),
      ),
    );
  }

  Widget _buildCurrentLocationCard() {
    return Container(
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(16),
      ),
      child: InkWell(
        onTap: _sendCurrentLocation,
        borderRadius: BorderRadius.circular(16),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 14.0),
          child: Row(
            children: [
              Container(
                width: 42,
                height: 42,
                decoration: const BoxDecoration(
                  color: _accentColor,
                  shape: BoxShape.circle,
                ),
                child: const Icon(Icons.navigation_rounded, color: Colors.white, size: 22),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Send My Current Location',
                      style: GoogleFonts.inter(
                        color: Colors.white,
                        fontSize: 15.5,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      'Accurate to 10 metres',
                      style: GoogleFonts.inter(
                        color: _mutedColor,
                        fontSize: 12.5,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildNearbyPlacesCard() {
    final filteredPlaces = _nearbyPlaces.where((place) {
      if (_searchController.text.isEmpty) return true;
      final q = _searchController.text.toLowerCase();
      return place['name'].toString().toLowerCase().contains(q) ||
          place['address'].toString().toLowerCase().contains(q);
    }).toList();

    if (filteredPlaces.isEmpty) {
      return Container(
        width: double.infinity,
        padding: const EdgeInsets.all(24),
        decoration: BoxDecoration(
          color: _cardColor,
          borderRadius: BorderRadius.circular(16),
        ),
        child: Center(
          child: Text(
            'No nearby places found',
            style: GoogleFonts.inter(color: _mutedColor, fontSize: 14),
          ),
        ),
      );
    }

    return Container(
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(16),
      ),
      child: ListView.separated(
        shrinkWrap: true,
        physics: const NeverScrollableScrollPhysics(),
        itemCount: filteredPlaces.length,
        separatorBuilder: (context, index) => const Divider(
          height: 1,
          color: _dividerColor,
          indent: 62,
        ),
        itemBuilder: (context, index) {
          final place = filteredPlaces[index];
          return InkWell(
            onTap: () => _sendSelectedPlace(place),
            borderRadius: BorderRadius.circular(16),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 12.0),
              child: Row(
                children: [
                  Container(
                    width: 40,
                    height: 40,
                    decoration: BoxDecoration(
                      color: place['color'] as Color,
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      place['icon'] as IconData,
                      color: Colors.white,
                      size: 20,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          place['name'].toString(),
                          style: GoogleFonts.inter(
                            color: Colors.white,
                            fontSize: 15,
                            fontWeight: FontWeight.w500,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 2),
                        Text(
                          place['address'].toString(),
                          style: GoogleFonts.inter(
                            color: _mutedColor,
                            fontSize: 12.5,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _buildBottomNavBar() {
    final categories = [
      {'label': 'Gallery', 'icon': Icons.photo_library_outlined, 'selectedIcon': Icons.photo_library_rounded},
      {'label': 'File', 'icon': Icons.insert_drive_file_outlined, 'selectedIcon': Icons.insert_drive_file_rounded},
      {'label': 'Location', 'icon': Icons.location_on_outlined, 'selectedIcon': Icons.location_on_rounded},
      {'label': 'Poll', 'icon': Icons.poll_outlined, 'selectedIcon': Icons.poll_rounded},
      {'label': 'Contact', 'icon': Icons.person_outline_rounded, 'selectedIcon': Icons.person_rounded},
    ];

    return Container(
      decoration: const BoxDecoration(
        color: Color(0xFF141416),
        border: Border(top: BorderSide(color: Color(0x1AFFFFFF), width: 0.5)),
      ),
      padding: EdgeInsets.only(
        top: 8,
        bottom: MediaQuery.of(context).padding.bottom > 0
            ? MediaQuery.of(context).padding.bottom + 4
            : 10,
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: categories.map((cat) {
          final String label = cat['label'] as String;
          final bool isSelected = _activeTab == label;

          return InkWell(
            onTap: () {
              setState(() {
                _activeTab = label;
              });
              widget.onTabChanged?.call(label);
            },
            borderRadius: BorderRadius.circular(16),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    padding: const EdgeInsets.all(6),
                    decoration: BoxDecoration(
                      color: isSelected ? _accentColor.withValues(alpha: 0.2) : Colors.transparent,
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      isSelected ? (cat['selectedIcon'] as IconData) : (cat['icon'] as IconData),
                      color: isSelected ? _accentColor : _mutedColor,
                      size: 22,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    label,
                    style: GoogleFonts.inter(
                      color: isSelected ? _accentColor : _mutedColor,
                      fontSize: 11,
                      fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                    ),
                  ),
                ],
              ),
            ),
          );
        }).toList(),
      ),
    );
  }
}

class _DarkMapPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final bgPaint = Paint()..color = const Color(0xFF151D2A);
    canvas.drawRect(Rect.fromLTWH(0, 0, size.width, size.height), bgPaint);

    final roadPaint = Paint()
      ..color = const Color(0xFF263248)
      ..strokeWidth = 4.0
      ..style = PaintingStyle.stroke;

    final mainRoadPaint = Paint()
      ..color = const Color(0xFF334155)
      ..strokeWidth = 7.0
      ..style = PaintingStyle.stroke;

    final riverPaint = Paint()
      ..color = const Color(0xFF0F2B48)
      ..strokeWidth = 14.0
      ..style = PaintingStyle.stroke;

    final riverPath = Path()
      ..moveTo(0, size.height * 0.2)
      ..quadraticBezierTo(size.width * 0.4, size.height * 0.5, size.width, size.height * 0.3);
    canvas.drawPath(riverPath, riverPaint);

    final roadPath1 = Path()
      ..moveTo(0, size.height * 0.6)
      ..lineTo(size.width, size.height * 0.4);
    canvas.drawPath(roadPath1, mainRoadPaint);

    final roadPath2 = Path()
      ..moveTo(size.width * 0.5, 0)
      ..lineTo(size.width * 0.4, size.height);
    canvas.drawPath(roadPath2, mainRoadPaint);

    for (double i = 20; i < size.width; i += 40) {
      canvas.drawLine(Offset(i, 0), Offset(i + 30, size.height), roadPaint);
    }
    for (double i = 20; i < size.height; i += 40) {
      canvas.drawLine(Offset(0, i), Offset(size.width, i + 20), roadPaint);
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
