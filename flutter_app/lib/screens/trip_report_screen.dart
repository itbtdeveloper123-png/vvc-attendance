import 'dart:async';
import 'dart:ui' as ui;
import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import 'package:google_maps_flutter/google_maps_flutter.dart';
import 'package:http/http.dart' as http;
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import 'trip_tracking_screen.dart';

class TripReportScreen extends StatefulWidget {
  const TripReportScreen({super.key});

  @override
  State<TripReportScreen> createState() => _TripReportScreenState();
}

class _TripReportScreenState extends State<TripReportScreen>
    with SingleTickerProviderStateMixin {
  final ApiService _api = ApiService();
  List<dynamic> _allTrips = [];
  bool _isLoading = true;
  late TabController _tabController;
  Timer? _pollingTimer;

  bool _isSidebarOpen = true;
  GoogleMapController? _combinedMapController;
  final Map<String, BitmapDescriptor> _profileBitmaps = {};

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    _loadTrips();
    _pollingTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (mounted) _loadTripsSilently();
    });
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadTripsSilently() async {
    try {
      final res = await _api.fetchAllTrips();
      if (res['success'] == true && mounted) {
        final data = res['data'] ?? [];
        setState(() {
          _allTrips = data;
        });
        final activeTrips = data.where((t) => t['status'] == 'active').toList();
        _loadProfileMarkerBitmaps(activeTrips);
      }
    } catch (_) {}
  }

  Future<void> _loadTrips() async {
    if (!mounted) return;
    setState(() => _isLoading = true);
    try {
      final res = await _api.fetchAllTrips();
      if (res['success'] == true) {
        final data = res['data'] ?? [];
        setState(() {
          _allTrips = data;
          _isLoading = false;
        });
        final activeTrips = data.where((t) => t['status'] == 'active').toList();
        _loadProfileMarkerBitmaps(activeTrips);
      } else {
        setState(() {
          _isLoading = false;
        });
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('បរាជ័យ: ${res['message'] ?? "មិនត្រឹមត្រូវ"}'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    } catch (e) {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _loadProfileMarkerBitmaps(List<dynamic> activeTrips) async {
    for (final trip in activeTrips) {
      final eid = (trip['employee_id'] ?? '').toString();
      final avatarUrl = trip['avatar_url']?.toString() ?? '';
      if (eid.isEmpty || avatarUrl.isEmpty || _profileBitmaps.containsKey(eid)) {
        continue;
      }
      try {
        final response = await http
            .get(Uri.parse(avatarUrl))
            .timeout(const Duration(seconds: 8));
        if (response.statusCode == 200) {
          final codec = await ui.instantiateImageCodec(
            response.bodyBytes,
            targetWidth: 36,
            targetHeight: 36,
          );
          final frame = await codec.getNextFrame();
          final image = frame.image;

          final recorder = ui.PictureRecorder();
          final canvas = Canvas(recorder);
          const size = 36.0;
          const half = size / 2;
          const borderWidth = 2.0;

          final borderPaint = Paint()..color = const Color(0xFF10b981);
          canvas.drawCircle(const Offset(half, half), half, borderPaint);

          final clipPath = Path()
            ..addOval(
              Rect.fromCircle(
                center: const Offset(half, half),
                radius: half - borderWidth,
              ),
            );
          canvas.clipPath(clipPath);

          final srcRect = Rect.fromLTWH(
            0,
            0,
            image.width.toDouble(),
            image.height.toDouble(),
          );
          final dstRect = Rect.fromLTWH(
            borderWidth,
            borderWidth,
            size - borderWidth * 2,
            size - borderWidth * 2,
          );
          canvas.drawImageRect(image, srcRect, dstRect, Paint());

          final picture = recorder.endRecording();
          final img = await picture.toImage(size.toInt(), size.toInt());
          final byteData = await img.toByteData(format: ui.ImageByteFormat.png);
          if (byteData != null) {
            final Uint8List bytes = byteData.buffer.asUint8List();
            final bitmap = BitmapDescriptor.bytes(bytes);
            if (mounted) {
              setState(() {
                _profileBitmaps[eid] = bitmap;
              });
            }
          }
        }
      } catch (e) {
        debugPrint('Failed to load profile marker bitmap for $eid: $e');
      }
    }
  }

  List<dynamic> _getFilteredTrips(String role) {
    if (role == 'Skills') {
      return _allTrips.where((t) {
        final r = t['system_role']?.toString().toLowerCase().trim() ?? '';
        return r != 'worker';
      }).toList();
    } else {
      return _allTrips.where((t) {
        final r = t['system_role']?.toString().toLowerCase().trim() ?? '';
        return r == 'worker';
      }).toList();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        title: Text(
          "របាយការណ៍ការធ្វើដំណើរ",
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        centerTitle: true,
        backgroundColor: Colors.transparent,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _loadTrips,
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppTheme.primary,
          labelStyle: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
          unselectedLabelStyle: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.normal,
          ),
          tabs: const [
            Tab(text: "ជំនាញ (Skills)"),
            Tab(text: "កម្មករ (Workers)"),
            Tab(text: "មើលរួម"),
          ],
        ),
      ),
      body: AppBackgroundShell(
        child: _isLoading
            ? const Center(child: CircularProgressIndicator())
            : TabBarView(
                controller: _tabController,
                children: [
                  _buildTripList(_getFilteredTrips('Skills')),
                  _buildTripList(_getFilteredTrips('Workers')),
                  _buildCombinedView(),
                ],
              ),
      ),
    );
  }

  // ─── Combined View ─────────────────────────────────────────────────────────

  Widget _buildCombinedView() {
    final activeTrips = _allTrips.where((t) => t['status'] == 'active').toList();
    final activeCount = activeTrips.length;

    if (activeTrips.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.directions_car_outlined,
              size: 64,
              color: Colors.white24,
            ),
            const SizedBox(height: 12),
            Text(
              "មិនមានអ្នកបើកសកម្ម",
              style: GoogleFonts.kantumruyPro(
                color: Colors.white54,
                fontSize: 16,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              "សូមធ្វើការកែប្រែ និង Refresh ដើម្បីពិនិត្យទិន្នន័យ។",
              style: GoogleFonts.kantumruyPro(
                color: Colors.white38,
                fontSize: 12,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }

    return Stack(
      children: [
        Positioned.fill(
          child: ClipRRect(
            borderRadius: BorderRadius.circular(24),
            child: _buildActiveTripsMapScreen(context, activeTrips),
          ),
        ),
        Positioned(
          top: 16,
          left: 16,
          right: _isSidebarOpen ? 300 : 80,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            decoration: BoxDecoration(
              color: AppTheme.bgCard.withValues(alpha: 0.88),
              borderRadius: BorderRadius.circular(18),
              border: Border.all(
                color: Colors.white12,
              ),
            ),
            child: Row(
              children: [
                const Icon(
                  Icons.satellite_alt_rounded,
                  color: Colors.greenAccent,
                  size: 18,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Active map: $activeCount នាក់',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                      fontSize: 14,
                    ),
                  ),
                ),
                Text(
                  'Satellite',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white70,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ),
        Positioned(
          top: 16,
          right: 16,
          child: Material(
            color: AppTheme.bgCard.withValues(alpha: 0.88),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(14),
              side: const BorderSide(color: Colors.white12),
            ),
            child: InkWell(
              borderRadius: BorderRadius.circular(14),
              onTap: () {
                setState(() {
                  _isSidebarOpen = !_isSidebarOpen;
                });
              },
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Icon(
                  _isSidebarOpen ? Icons.chevron_right : Icons.menu_open_rounded,
                  color: Colors.white,
                  size: 20,
                ),
              ),
            ),
          ),
        ),
        if (_isSidebarOpen)
          Positioned(
            top: 80,
            bottom: 16,
            right: 16,
            width: 270,
            child: SlideInRight(
              duration: const Duration(milliseconds: 250),
              child: Container(
                decoration: BoxDecoration(
                  color: AppTheme.bgCard.withValues(alpha: 0.95),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: Colors.white12),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: 0.4),
                      blurRadius: 10,
                      offset: const Offset(-2, 2),
                    ),
                  ],
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 16, 16, 12),
                      child: Text(
                        "អ្នកបើកបរលោតសកម្ម",
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                          fontSize: 14,
                        ),
                      ),
                    ),
                    const Divider(color: Colors.white10, height: 1),
                    Expanded(
                      child: ListView.builder(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
                        itemCount: activeTrips.length,
                        itemBuilder: (context, index) {
                          final trip = activeTrips[index];
                          return _buildSidebarActiveCard(trip);
                        },
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
      ],
    );
  }





  LatLng? _extractTripLatLng(dynamic trip) {
    if (trip == null) return null;

    double? parseValue(dynamic value) {
      if (value == null) return null;
      if (value is double) return value;
      if (value is int) return value.toDouble();
      return double.tryParse(value.toString());
    }

    final lat = parseValue(trip['latitude'] ?? trip['lat'] ?? trip['current_lat'] ?? trip['target_lat'] ?? trip['customer_lat'] ?? trip['origin_lat'] ?? trip['start_lat']);
    final lng = parseValue(trip['longitude'] ?? trip['lng'] ?? trip['current_lng'] ?? trip['target_lng'] ?? trip['customer_lng'] ?? trip['origin_lng'] ?? trip['start_lng']);

    if (lat != null && lng != null) {
      return LatLng(lat, lng);
    }
    return null;
  }

  Widget _buildActiveTripsMapScreen(BuildContext context, List<dynamic> activeTrips) {
    final markers = <Marker>{};
    for (final trip in activeTrips) {
      final point = _extractTripLatLng(trip);
      if (point == null) continue;

      final name = trip['user_name'] ?? trip['employee_name'] ?? trip['employee_id'] ?? 'N/A';
      final eid = (trip['employee_id'] ?? '').toString();
      final customIcon = _profileBitmaps[eid];

      markers.add(
        Marker(
          markerId: MarkerId('trip_${eid}_${point.latitude}_${point.longitude}'),
          position: point,
          infoWindow: InfoWindow(
            title: name,
            snippet: eid.isNotEmpty ? 'ID: $eid' : null,
          ),
          icon: customIcon ?? BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueRed),
        ),
      );
    }

    if (markers.isEmpty) {
      return Center(
        child: Text(
          'មិនមានទីតាំងអ្នកបើកសកម្មទេ។ សូមធ្វើ refresh និងពិនិត្យទិន្នន័យ active trip។',
          style: GoogleFonts.kantumruyPro(
            color: Colors.white54,
            fontSize: 14,
          ),
          textAlign: TextAlign.center,
        ),
      );
    }

    final firstMarker = markers.first.position;
    return GoogleMap(
      initialCameraPosition: CameraPosition(target: firstMarker, zoom: 13),
      markers: markers,
      mapType: MapType.satellite,
      myLocationButtonEnabled: false,
      zoomControlsEnabled: true,
      zoomGesturesEnabled: true,
      scrollGesturesEnabled: true,
      rotateGesturesEnabled: true,
      tiltGesturesEnabled: true,
      mapToolbarEnabled: false,
      compassEnabled: true,
      onMapCreated: (controller) {
        _combinedMapController = controller;
      },
      gestureRecognizers: <Factory<OneSequenceGestureRecognizer>>{
        Factory<OneSequenceGestureRecognizer>(
          () => EagerGestureRecognizer(),
        ),
      },
    );
  }

  void _focusOnUser(LatLng point) {
    if (_combinedMapController != null) {
      _combinedMapController!.animateCamera(
        CameraUpdate.newLatLngZoom(point, 15),
      );
    }
  }

  Widget _buildInitialsAvatarSmall(String initials) {
    return Container(
      color: AppTheme.primary.withValues(alpha: 0.1),
      alignment: Alignment.center,
      child: Text(
        initials,
        style: TextStyle(
          color: AppTheme.primary,
          fontWeight: FontWeight.bold,
          fontSize: 12,
        ),
      ),
    );
  }

  Widget _buildSidebarActiveCard(dynamic trip) {
    final name = trip['user_name'] ?? trip['employee_name'] ?? trip['employee_id'] ?? 'N/A';
    final eid = trip['employee_id'] ?? '';
    final customer = trip['customer_name'] ?? 'N/A';
    final duration = trip['duration_minutes'] ?? 0;
    final double dist = double.tryParse((trip['distance_km'] ?? trip['total_distance_km'] ?? '0').toString()) ?? 0.0;
    final avatarUrl = trip['avatar_url']?.toString() ?? '';
    final initials = name.trim().isEmpty
        ? '?'
        : name.trim().split(RegExp(r'\s+')).take(2).map((w) => w[0].toUpperCase()).join();

    final point = _extractTripLatLng(trip);

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTheme.bgDark.withValues(alpha: 0.6),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.primary.withValues(alpha: 0.25)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              // Avatar
              Stack(
                children: [
                  Container(
                    width: 36,
                    height: 36,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      border: Border.all(color: AppTheme.primary.withValues(alpha: 0.5), width: 1.5),
                    ),
                    child: ClipOval(
                      child: avatarUrl.isNotEmpty
                          ? Image.network(
                              avatarUrl,
                              fit: BoxFit.cover,
                              errorBuilder: (ctx, err, stack) => _buildInitialsAvatarSmall(initials),
                            )
                          : _buildInitialsAvatarSmall(initials),
                    ),
                  ),
                  Positioned(
                    top: 0,
                    right: 0,
                    child: Container(
                      width: 8,
                      height: 8,
                      decoration: const BoxDecoration(
                        color: Colors.greenAccent,
                        shape: BoxShape.circle,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      name,
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 12,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                    Text(
                      eid.isNotEmpty ? 'ID: $eid' : '',
                      style: GoogleFonts.inter(
                        color: Colors.white54,
                        fontSize: 10,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            '📍 $customer',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white70,
              fontSize: 11,
            ),
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 6),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                '⏱ $duration នាទី',
                style: GoogleFonts.kantumruyPro(color: Colors.amber, fontSize: 10),
              ),
              Text(
                '🛣 ${dist.toStringAsFixed(1)} គម',
                style: GoogleFonts.kantumruyPro(color: AppTheme.primary, fontSize: 10),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              // Locate Button
              if (point != null)
                Expanded(
                  child: OutlinedButton(
                    onPressed: () => _focusOnUser(point),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: Colors.white,
                      side: const BorderSide(color: Colors.white24),
                      padding: const EdgeInsets.symmetric(vertical: 4),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    child: const Icon(Icons.location_searching, size: 14),
                  ),
                ),
              if (point != null) const SizedBox(width: 6),
              // Track detail Button
              Expanded(
                child: ElevatedButton(
                  onPressed: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (context) => TripTrackingScreen(
                          tripId: int.parse(trip['id'].toString()),
                        ),
                      ),
                    );
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.primary,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    elevation: 0,
                  ),
                  child: Text(
                    "តាមដាន",
                    style: GoogleFonts.kantumruyPro(fontSize: 10, fontWeight: FontWeight.bold),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // ─── Skills / Workers Tab List ─────────────────────────────────────────────

  Widget _buildTripList(List<dynamic> trips) {
    if (trips.isEmpty) {
      return const Center(
        child: Text(
          "មិនទាន់មានទិន្នន័យ",
          style: TextStyle(color: Colors.white54),
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: trips.length,
      itemBuilder: (context, index) {
        final trip = trips[index];
        final name =
            trip['user_name'] ??
            trip['employee_name'] ??
            trip['employee_id'] ??
            'N/A';
        final eid = trip['employee_id'] ?? '';
        final customer = trip['customer_name'] ?? 'N/A';
        final status = trip['status'] ?? 'unknown';
        final duration = trip['duration_minutes'] ?? 0;
        final double dist =
            double.tryParse(
              (trip['distance_km'] ?? trip['total_distance_km'] ?? '0')
                  .toString(),
            ) ??
            0.0;
        final started = trip['started_at'] ?? '';
        final finished = trip['finished_at'] ?? trip['ended_at'] ?? '';
        final avatarUrl = trip['avatar_url']?.toString() ?? '';
        final initials = name.trim().isEmpty
            ? '?'
            : name
                  .trim()
                  .split(RegExp(r'\s+'))
                  .take(2)
                  .map((w) => w[0].toUpperCase())
                  .join();

        final isActive = status == 'active';

        return FadeInUp(
          duration: Duration(milliseconds: 300 + (index * 20)),
          child: Container(
            margin: const EdgeInsets.only(bottom: 12),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(24),
              border: Border.all(
                color: isActive
                    ? AppTheme.primary.withValues(alpha: 0.3)
                    : AppTheme.textPrimary.withValues(alpha: 0.05),
              ),
              boxShadow: isActive
                  ? [
                      BoxShadow(
                        color: AppTheme.primary.withValues(alpha: 0.1),
                        blurRadius: 10,
                        offset: const Offset(0, 4),
                      ),
                    ]
                  : null,
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    // Avatar with profile image
                    Stack(
                      children: [
                        Container(
                          width: 48,
                          height: 48,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: isActive
                                  ? AppTheme.primary.withValues(alpha: 0.4)
                                  : Colors.white12,
                              width: 2,
                            ),
                          ),
                          child: ClipOval(
                            child: avatarUrl.isNotEmpty
                                ? Image.network(
                                    avatarUrl,
                                    fit: BoxFit.cover,
                                    errorBuilder:
                                        (
                                          context,
                                          error,
                                          stackTrace,
                                        ) => Container(
                                          color:
                                              (isActive
                                                      ? AppTheme.primary
                                                      : AppTheme.textSecondary)
                                                  .withValues(alpha: 0.1),
                                          alignment: Alignment.center,
                                          child: Icon(
                                            isActive
                                                ? Icons.directions_car_rounded
                                                : Icons.person_rounded,
                                            color: isActive
                                                ? AppTheme.primary
                                                : AppTheme.textSecondary,
                                            size: 24,
                                          ),
                                        ),
                                  )
                                : Container(
                                    color:
                                        (isActive
                                                ? AppTheme.primary
                                                : AppTheme.textSecondary)
                                            .withValues(alpha: 0.1),
                                    alignment: Alignment.center,
                                    child: initials.length == 1
                                        ? Text(
                                            initials,
                                            style: TextStyle(
                                              color: isActive
                                                  ? AppTheme.primary
                                                  : AppTheme.textSecondary,
                                              fontWeight: FontWeight.bold,
                                              fontSize: 18,
                                            ),
                                          )
                                        : Icon(
                                            isActive
                                                ? Icons.directions_car_rounded
                                                : Icons.person_rounded,
                                            color: isActive
                                                ? AppTheme.primary
                                                : AppTheme.textSecondary,
                                            size: 24,
                                          ),
                                  ),
                          ),
                        ),
                        if (isActive)
                          Positioned(
                            top: 0,
                            right: 0,
                            child: Pulse(
                              infinite: true,
                              child: Container(
                                width: 12,
                                height: 12,
                                decoration: const BoxDecoration(
                                  color: Colors.greenAccent,
                                  shape: BoxShape.circle,
                                ),
                              ),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Text(
                                name,
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white,
                                  fontWeight: FontWeight.bold,
                                  fontSize: 15,
                                ),
                              ),
                              const SizedBox(width: 8),
                              Text(
                                "($eid)",
                                style: GoogleFonts.inter(
                                  color: Colors.white54,
                                  fontSize: 11,
                                ),
                              ),
                            ],
                          ),
                          Text(
                            customer,
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white70,
                              fontSize: 13,
                            ),
                          ),
                        ],
                      ),
                    ),
                    if (isActive)
                      ElevatedButton(
                        onPressed: () {
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (context) => TripTrackingScreen(
                                tripId: int.parse(trip['id'].toString()),
                              ),
                            ),
                          );
                        },
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppTheme.primary,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(
                            horizontal: 12,
                            vertical: 8,
                          ),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12),
                          ),
                          elevation: 0,
                        ),
                        child: Text(
                          "តាមដាន",
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 12,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                  ],
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppTheme.bgDark.withValues(alpha: 0.3),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Row(
                    children: [
                      Expanded(child: _buildInfoItem("ចាប់ផ្ដម", started)),
                      Container(width: 1, height: 24, color: Colors.white10),
                      Expanded(
                        child: _buildInfoItem(
                          "បញ្ចប់",
                          finished.isEmpty ? "កំពុងធ្វើដំណើរ" : finished,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    _buildMetric(
                      Icons.straighten_rounded,
                      "ចំងាយ",
                      "${dist.toStringAsFixed(1)} KM",
                    ),
                    _buildMetric(
                      Icons.timer_outlined,
                      "រយៈពេល",
                      "$duration នាទី",
                    ),
                    _buildStatusBadge(status),
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildInfoItem(String label, String val) {
    return Column(
      children: [
        Text(
          label,
          style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 10),
        ),
        const SizedBox(height: 2),
        Text(
          val,
          style: GoogleFonts.inter(
            color: Colors.white,
            fontSize: 11,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }

  Widget _buildMetric(IconData icon, String label, String val) {
    return Row(
      children: [
        Icon(icon, size: 14, color: AppTheme.primary.withValues(alpha: 0.6)),
        const SizedBox(width: 4),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white38,
                fontSize: 9,
              ),
            ),
            Text(
              val,
              style: GoogleFonts.inter(
                color: Colors.white70,
                fontSize: 11,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildStatusBadge(String status) {
    final bool isActive = status == 'active';
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: (isActive ? Colors.greenAccent : Colors.white12).withValues(
          alpha: 0.1,
        ),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(
        isActive ? "កំពុងដំណើរការ" : "បានបញ្ចប់",
        style: GoogleFonts.kantumruyPro(
          color: isActive ? Colors.greenAccent : Colors.white38,
          fontSize: 10,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}
