import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import 'package:google_maps_flutter/google_maps_flutter.dart';
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
        setState(() {
          _allTrips = res['data'] ?? [];
        });
      }
    } catch (_) {}
  }

  Future<void> _loadTrips() async {
    if (!mounted) return;
    setState(() => _isLoading = true);
    try {
      final res = await _api.fetchAllTrips();
      if (res['success'] == true) {
        setState(() {
          _allTrips = res['data'] ?? [];
          _isLoading = false;
        });
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

  /// Combined view: all employees, only those with active trips shown prominently
  List<dynamic> _getCombinedActiveTrips() {
    // Show active trips first, then recently finished
    final active = _allTrips.where((t) => t['status'] == 'active').toList();
    final finished = _allTrips.where((t) => t['status'] != 'active').toList();
    return [...active, ...finished];
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

    return Column(
      children: [
        // ── Summary header ──
        Container(
          margin: const EdgeInsets.fromLTRB(16, 12, 16, 0),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: [
                AppTheme.primary.withValues(alpha: 0.2),
                AppTheme.primary.withValues(alpha: 0.05),
              ],
            ),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: AppTheme.primary.withValues(alpha: 0.3)),
          ),
          child: Row(
            children: [
              const Icon(
                Icons.satellite_alt_rounded,
                color: Colors.greenAccent,
                size: 16,
              ),
              const SizedBox(width: 8),
              Text(
                'Active map: $activeCount នាក់',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.greenAccent,
                  fontWeight: FontWeight.bold,
                  fontSize: 13,
                ),
              ),
              const Spacer(),
              Text(
                'ផែនទី Satellite',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white54,
                  fontSize: 12,
                ),
              ),
            ],
          ),
        ),
        Expanded(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(24),
              child: _buildActiveTripsMapScreen(context, activeTrips),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildCombinedCard(dynamic trip, bool isActive) {
    final name =
        trip['user_name'] ??
        trip['employee_name'] ??
        trip['employee_id'] ??
        'N/A';
    final eid = trip['employee_id'] ?? '';
    final customer = trip['customer_name'] ?? 'N/A';
    final duration = trip['duration_minutes'] ?? 0;
    final double dist =
        double.tryParse(
          (trip['distance_km'] ?? trip['total_distance_km'] ?? '0').toString(),
        ) ??
        0.0;
    final started = trip['started_at'] ?? '';
    final avatarUrl = trip['avatar_url']?.toString() ?? '';
    final initials = name.trim().isEmpty
        ? '?'
        : name
              .trim()
              .split(RegExp(r'\s+'))
              .take(2)
              .map((w) => w[0].toUpperCase())
              .join();

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: isActive
              ? Colors.greenAccent.withValues(alpha: 0.35)
              : Colors.white.withValues(alpha: 0.05),
        ),
        boxShadow: isActive
            ? [
                BoxShadow(
                  color: Colors.greenAccent.withValues(alpha: 0.08),
                  blurRadius: 12,
                  offset: const Offset(0, 4),
                ),
              ]
            : null,
      ),
      child: Row(
        children: [
          // ── Side-left stats panel ──────────────────────────────────────────
          Container(
            width: 72,
            padding: const EdgeInsets.symmetric(vertical: 12),
            decoration: BoxDecoration(
              color: isActive
                  ? Colors.greenAccent.withValues(alpha: 0.08)
                  : Colors.white.withValues(alpha: 0.03),
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(20),
                bottomLeft: Radius.circular(20),
              ),
            ),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                _sideStatItem(
                  Icons.straighten_rounded,
                  dist.toStringAsFixed(1),
                  'km',
                  AppTheme.primary,
                ),
                const SizedBox(height: 8),
                _sideStatItem(
                  Icons.timer_outlined,
                  '$duration',
                  'min',
                  const Color(0xFFf59e0b),
                ),
                const SizedBox(height: 8),
                _sideStatItem(
                  isActive ? Icons.circle : Icons.check_circle_outline,
                  isActive ? 'Live' : 'Done',
                  '',
                  isActive ? Colors.greenAccent : Colors.white38,
                ),
              ],
            ),
          ),
          // ── Main content ───────────────────────────────────────────────────
          Expanded(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      // Avatar
                      Stack(
                        children: [
                          Container(
                            width: 40,
                            height: 40,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              border: Border.all(
                                color: isActive
                                    ? Colors.greenAccent.withValues(alpha: 0.5)
                                    : Colors.white24,
                                width: 2,
                              ),
                            ),
                            child: ClipOval(
                              child: avatarUrl.isNotEmpty
                                  ? Image.network(
                                      avatarUrl,
                                      fit: BoxFit.cover,
                                      errorBuilder:
                                          (context, error, stackTrace) =>
                                              _buildInitialsAvatar(
                                                initials,
                                                isActive,
                                              ),
                                    )
                                  : _buildInitialsAvatar(initials, isActive),
                            ),
                          ),
                          if (isActive)
                            Positioned(
                              bottom: 0,
                              right: 0,
                              child: Pulse(
                                infinite: true,
                                child: Container(
                                  width: 10,
                                  height: 10,
                                  decoration: const BoxDecoration(
                                    color: Colors.greenAccent,
                                    shape: BoxShape.circle,
                                  ),
                                ),
                              ),
                            ),
                        ],
                      ),
                      const SizedBox(width: 10),
                      // Name + employee ID
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              name,
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white,
                                fontWeight: FontWeight.bold,
                                fontSize: 13,
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                            Text(
                              '($eid)',
                              style: GoogleFonts.inter(
                                color: Colors.white54,
                                fontSize: 10,
                              ),
                            ),
                          ],
                        ),
                      ),
                      // Track button (active only)
                      if (isActive)
                        GestureDetector(
                          onTap: () {
                            Navigator.push(
                              context,
                              MaterialPageRoute(
                                builder: (context) => TripTrackingScreen(
                                  tripId: int.parse(trip['id'].toString()),
                                ),
                              ),
                            );
                          },
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 6,
                            ),
                            decoration: BoxDecoration(
                              color: AppTheme.primary,
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: Text(
                              'តាមដាន',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white,
                                fontSize: 11,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  // Destination
                  Row(
                    children: [
                      Icon(
                        Icons.location_on,
                        size: 12,
                        color: AppTheme.primary.withValues(alpha: 0.7),
                      ),
                      const SizedBox(width: 4),
                      Expanded(
                        child: Text(
                          customer,
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white70,
                            fontSize: 12,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                  if (started.isNotEmpty) ...[
                    const SizedBox(height: 4),
                    Row(
                      children: [
                        Icon(
                          Icons.access_time,
                          size: 11,
                          color: Colors.white38,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          started,
                          style: GoogleFonts.inter(
                            color: Colors.white38,
                            fontSize: 10,
                          ),
                        ),
                      ],
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _sideStatItem(IconData icon, String value, String label, Color color) {
    return Column(
      children: [
        Icon(icon, size: 13, color: color),
        const SizedBox(height: 2),
        Text(
          value,
          style: GoogleFonts.inter(
            color: color,
            fontSize: 11,
            fontWeight: FontWeight.bold,
          ),
        ),
        if (label.isNotEmpty)
          Text(
            label,
            style: const TextStyle(color: Colors.white38, fontSize: 9),
          ),
      ],
    );
  }

  Widget _buildInitialsAvatar(String initials, bool isActive) {
    return Container(
      color: isActive
          ? Colors.greenAccent.withValues(alpha: 0.15)
          : AppTheme.bgCard,
      alignment: Alignment.center,
      child: Text(
        initials,
        style: TextStyle(
          color: isActive ? Colors.greenAccent : Colors.white54,
          fontWeight: FontWeight.bold,
          fontSize: 13,
        ),
      ),
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
      final eid = trip['employee_id'] ?? '';

      markers.add(
        Marker(
          markerId: MarkerId('trip_${eid}_${point.latitude}_${point.longitude}'),
          position: point,
          infoWindow: InfoWindow(
            title: name,
            snippet: eid.isNotEmpty ? 'ID: $eid' : null,
          ),
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
