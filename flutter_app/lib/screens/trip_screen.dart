import 'dart:async';

import 'package:flutter/foundation.dart' show kIsWeb, defaultTargetPlatform;
import 'package:flutter/material.dart';
import 'package:geolocator/geolocator.dart';
import 'package:google_maps_flutter/google_maps_flutter.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:vvc_hrm/services/api_service.dart';
import 'package:vvc_hrm/services/background_location_service.dart';

class TripScreen extends StatefulWidget {
  const TripScreen({super.key});

  @override
  State<TripScreen> createState() => _TripScreenState();
}

class _TripScreenState extends State<TripScreen>
    with TickerProviderStateMixin, WidgetsBindingObserver {
  final ApiService _api = ApiService();

  List<Map<String, dynamic>> _customers = [];
  bool _isLoading = true;
  bool _isTripActive = false;
  int? _activeTripId;
  int? _activeCustomerId;
  String _activeTripCustomer = '';
  StreamSubscription<Position>? _positionSubscription;
  Position? _currentPosition;
  double _tripDistance = 0;
  int _tripDuration = 0;
  DateTime? _tripStartTime;
  int _locationPointsSent = 0;
  String _routeSource = 'raw';
  String? _routeMessage;
  bool _isMapExpanded = false;

  double? _targetLat;
  double? _targetLng;

  // OSRM navigation route (from current → customer destination)
  List<LatLng> _navRoutePoints = [];
  bool _isLoadingNavRoute = false;

  GoogleMapController? _mapController;
  final Set<Marker> _markers = {};
  final Set<Polyline> _polylines = {};
  final List<LatLng> _routePoints = [];

  late AnimationController _pulseController;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
    _loadData();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _positionSubscription?.cancel();
    _mapController?.dispose();
    _pulseController.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (!_isTripActive || _activeTripId == null || kIsWeb) return;
    if (state == AppLifecycleState.resumed) {
      if (_positionSubscription == null) {
        _startLocationTracking();
      }
    }
  }

  LocationSettings _buildLocationSettings({
    LocationAccuracy accuracy = LocationAccuracy.bestForNavigation,
    int distanceFilter = 5,
  }) {
    if (defaultTargetPlatform == TargetPlatform.android) {
      return AndroidSettings(
        accuracy: accuracy,
        distanceFilter: distanceFilter,
        intervalDuration: const Duration(seconds: 10),
        forceLocationManager: false,
      );
    }
    if (defaultTargetPlatform == TargetPlatform.iOS) {
      return AppleSettings(
        accuracy: accuracy,
        activityType: ActivityType.automotiveNavigation,
        distanceFilter: distanceFilter,
        pauseLocationUpdatesAutomatically: false,
        showBackgroundLocationIndicator: true,
      );
    }
    return LocationSettings(accuracy: accuracy, distanceFilter: distanceFilter);
  }

  Future<bool> _ensureTripLocationPermissions() async {
    final serviceEnabled = await Geolocator.isLocationServiceEnabled();
    if (!serviceEnabled) {
      _showSnack('សូមបើក GPS ជាមុនសិន។', isError: true);
      return false;
    }

    var permission = await Geolocator.checkPermission();
    if (permission == LocationPermission.denied) {
      permission = await Geolocator.requestPermission();
    }
    if (permission == LocationPermission.denied) {
      _showSnack('ត្រូវការការអនុញ្ញាត Location ដើម្បីចាប់ផ្តើមដំណើរ។', isError: true);
      return false;
    }
    if (permission == LocationPermission.deniedForever) {
      _showSnack('Location ត្រូវបានបិទ។ សូមបើកវិញក្នុង Settings។', isError: true);
      await openAppSettings();
      return false;
    }
    if (permission == LocationPermission.always) return true;
    if (!kIsWeb && defaultTargetPlatform == TargetPlatform.android) {
      final backgroundStatus = await Permission.locationAlways.status;
      if (!backgroundStatus.isGranted) {
        final requested = await Permission.locationAlways.request();
        if (!requested.isGranted) {
          _showSnack('សូមអនុញ្ញាត background location ដើម្បីឲ្យ app តាមដានបានពេលចេញពីកម្មវិធី។',
              isError: true);
          await openAppSettings();
          return false;
        }
      }
      final notificationStatus = await Permission.notification.status;
      if (!notificationStatus.isGranted) {
        await Permission.notification.request();
      }
    }
    return true;
  }

  Future<Position?> _getBestCurrentPosition() async {
    try {
      return await Geolocator.getCurrentPosition(
        locationSettings: _buildLocationSettings(),
      );
    } catch (e) {
      debugPrint('Current GPS lookup failed: $e');
      return Geolocator.getLastKnownPosition();
    }
  }

  Future<void> _loadData() async {
    if (!mounted) return;
    setState(() => _isLoading = true);
    try {
      final results = await Future.wait([
        _api.getTrackingCustomers(),
        _api.getActiveTrip(),
      ]);
      final customersRes = results[0];
      final activeTripRes = results[1];

      if (customersRes['success'] == true) {
        _customers = List<Map<String, dynamic>>.from(customersRes['data'] ?? []);
      }

      if (activeTripRes['success'] == true && activeTripRes['trip'] != null) {
        final trip = activeTripRes['trip'] as Map<String, dynamic>;
        _isTripActive = true;
        _activeTripId = int.tryParse(trip['id'].toString());
        _activeCustomerId = int.tryParse(trip['customer_id']?.toString() ?? '');
        _activeTripCustomer = trip['customer_name']?.toString() ?? '';
        _tripStartTime = DateTime.tryParse(trip['started_at']?.toString() ?? '');
        _targetLat = double.tryParse(trip['target_lat']?.toString() ?? '');
        _targetLng = double.tryParse(trip['target_lng']?.toString() ?? '');
        _tripDistance = double.tryParse(trip['total_distance_km']?.toString() ?? '0') ?? 0;
        _tripDuration = int.tryParse(trip['duration_minutes']?.toString() ?? '0') ?? 0;

        if (_activeTripId != null) {
          final prefs = await SharedPreferences.getInstance();
          await prefs.setString('current_active_trip_id', _activeTripId.toString());
          await _ensureBackgroundTrackingService();
          await _loadActiveTripRoute();
          _startLocationTracking();
          // Fetch nav route if target exists
          if (_targetLat != null && _targetLng != null && _currentPosition != null) {
            _fetchNavRoute();
          }
        }
      }
    } catch (e) {
      debugPrint('Error loading trip data: $e');
    }
    if (mounted) setState(() => _isLoading = false);
  }

  Future<void> _loadActiveTripRoute() async {
    if (_activeTripId == null) return;
    try {
      final res = await _api.getTripDetails(_activeTripId!);
      if (res['success'] != true) return;

      final routeData = (res['snapped_points'] as List?)?.isNotEmpty == true
          ? (res['snapped_points'] as List)
          : ((res['points'] as List?) ?? const []);

      final points = routeData
          .map((p) => LatLng(
                double.tryParse((p['latitude'] ?? p['lat']).toString()) ?? 0,
                double.tryParse((p['longitude'] ?? p['lng']).toString()) ?? 0,
              ))
          .where((point) => point.latitude != 0 || point.longitude != 0)
          .toList();

      final trip = res['trip'] as Map<String, dynamic>?;
      if (!mounted) return;
      setState(() {
        _routePoints..clear()..addAll(points);
        _locationPointsSent = points.length;
        if (trip != null) {
          _tripDistance = double.tryParse(trip['total_distance_km']?.toString() ?? '0') ?? _tripDistance;
          _tripDuration = int.tryParse(trip['duration_minutes']?.toString() ?? '0') ?? _tripDuration;
        }
        _routeSource = res['route_source']?.toString() ?? 'raw';
        _routeMessage = res['route_message']?.toString();
        _updateMapOverlays();
      });
    } catch (e) {
      debugPrint('Failed to load trip route: $e');
    }
  }

  /// Fetch OSRM navigation route from current position to customer destination
  Future<void> _fetchNavRoute() async {
    if (_currentPosition == null || _targetLat == null || _targetLng == null) return;
    if (mounted) setState(() => _isLoadingNavRoute = true);
    try {
      final coords = await ApiService.getOsrmRoute(
        startLat: _currentPosition!.latitude,
        startLng: _currentPosition!.longitude,
        endLat: _targetLat!,
        endLng: _targetLng!,
      );
      if (coords != null && mounted) {
        setState(() {
          _navRoutePoints = coords.map((c) => LatLng(c['lat']!, c['lng']!)).toList();
          _updateMapOverlays();
        });
      }
    } finally {
      if (mounted) setState(() => _isLoadingNavRoute = false);
    }
  }

  Future<void> _startTrip(Map<String, dynamic> customer) async {
    final hasPermission = await _ensureTripLocationPermissions();
    if (!hasPermission) return;
    _showSnack('កំពុងយកទីតាំង GPS...');
    try {
      final position = await _getBestCurrentPosition();
      if (position == null) {
        _showSnack('មិនអាចយកទីតាំង GPS បានទេ។', isError: true);
        return;
      }
      final customerId = int.tryParse(customer['id'].toString()) ?? 0;
      final customerName = customer['name']?.toString() ?? '';
      final res = await _api.startTrip(
        customerId: customerId,
        customerName: customerName,
        latitude: position.latitude,
        longitude: position.longitude,
      );
      if (res['success'] != true) {
        _showSnack(res['message']?.toString() ?? 'មិនអាចចាប់ផ្តើមដំណើរបានទេ។', isError: true);
        return;
      }
      final tripIdInt = res['trip_id'] is int
          ? res['trip_id'] as int
          : int.tryParse(res['trip_id'].toString());
      if (tripIdInt == null) {
        _showSnack('បានចាប់ផ្តើមដំណើរ ប៉ុន្តែមិនទទួលបានលេខសម្គាល់ Trip។', isError: true);
        return;
      }
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('current_active_trip_id', tripIdInt.toString());
      await _ensureBackgroundTrackingService();

      final custLat = double.tryParse(customer['latitude']?.toString() ?? '');
      final custLng = double.tryParse(customer['longitude']?.toString() ?? '');

      if (!mounted) return;
      setState(() {
        _isTripActive = true;
        _activeTripId = tripIdInt;
        _activeCustomerId = customerId;
        _activeTripCustomer = customerName;
        _tripStartTime = DateTime.now();
        _currentPosition = position;
        _tripDistance = 0;
        _tripDuration = 0;
        _targetLat = custLat;
        _targetLng = custLng;
        _routePoints.clear();
        _routePoints.add(LatLng(position.latitude, position.longitude));
        _navRoutePoints.clear();
        _locationPointsSent = _routePoints.length;
        _routeSource = 'raw';
        _routeMessage = null;
        _updateMapOverlays();
      });
      _startLocationTracking();
      _showSnack('បានចាប់ផ្តើមដំណើរទៅ $customerName។');

      // Fetch OSRM nav route if customer has lat/lng
      if (custLat != null && custLng != null) {
        _fetchNavRoute();
      }
    } catch (e) {
      _showSnack('ចាប់ផ្តើមដំណើរមិនបាន: $e', isError: true);
    }
  }

  void _startLocationTracking() {
    _positionSubscription?.cancel();
    _positionSubscription = Geolocator.getPositionStream(
      locationSettings: _buildLocationSettings(),
    ).listen((Position position) async {
      if (!_isTripActive || _activeTripId == null) return;

      if (mounted) {
        setState(() {
          _currentPosition = position;
          if (_tripStartTime != null) {
            _tripDuration = DateTime.now().difference(_tripStartTime!).inMinutes;
          }
          _appendRoutePoint(LatLng(position.latitude, position.longitude));
          _updateMapOverlays();
        });
      }

      // On iOS, sync to the server from the main isolate stream
      if (defaultTargetPlatform == TargetPlatform.iOS) {
        await _syncCurrentPositionToServer(position: position);
      }

      if (_mapController != null && mounted) {
        await _mapController!.animateCamera(
          CameraUpdate.newLatLng(LatLng(position.latitude, position.longitude)),
        );
      }
    }, onError: (dynamic error) {
      debugPrint('Location stream error: $error');
    });
  }

  void _appendRoutePoint(LatLng point) {
    if (_routePoints.isNotEmpty) {
      final lastPoint = _routePoints.last;
      final distanceMeters = Geolocator.distanceBetween(
        lastPoint.latitude, lastPoint.longitude,
        point.latitude, point.longitude,
      );
      if (distanceMeters < 3) return;
      _tripDistance += distanceMeters / 1000;
    }
    _routePoints.add(point);
    _locationPointsSent = _routePoints.length;
  }

  Future<void> _syncCurrentPositionToServer({Position? position}) async {
    if (_activeTripId == null) return;
    final gps = position ?? await _getBestCurrentPosition();
    if (gps == null) return;
    try {
      await _api.updateTripLocation(
        tripId: _activeTripId!,
        latitude: gps.latitude,
        longitude: gps.longitude,
        speed: gps.speed * 3.6,
        accuracy: gps.accuracy,
      );
    } catch (e) {
      debugPrint('Final trip sync failed: $e');
    }
  }

  Future<void> _endTrip() async {
    if (_activeTripId == null) return;

    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: const Row(
          children: [
            Icon(Icons.flag, color: Colors.red),
            SizedBox(width: 10),
            Text('បញ្ចប់ដំណើរ?'),
          ],
        ),
        content: Text('តើចង់បញ្ចប់ដំណើរទៅកាន់ $_activeTripCustomer មែនទេ?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('បោះបង់'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
              foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            ),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('បញ្ចប់'),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    await _syncCurrentPositionToServer(position: _currentPosition);

    final tripId = _activeTripId!;
    final endCustomerId = _activeCustomerId;
    final endPosition = _currentPosition;
    final res = await _api.endTrip(tripId);

    if (res['success'] != true) {
      _showSnack(res['message']?.toString() ?? 'មិនអាចបញ្ចប់ដំណើរបានទេ។', isError: true);
      return;
    }

    // Auto-save customer location if they don't have one yet
    if (endCustomerId != null && endCustomerId > 0 && endPosition != null) {
      try {
        await _api.updateCustomerLocation(
          customerId: endCustomerId,
          latitude: endPosition.latitude,
          longitude: endPosition.longitude,
        );
        debugPrint('Auto-saved customer location: $endCustomerId');
      } catch (e) {
        debugPrint('Auto-save customer location failed: $e');
      }
    }

    _positionSubscription?.cancel();
    _positionSubscription = null;

    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('current_active_trip_id');
    await _stopBackgroundTrackingService();

    final trip = res['trip'] as Map<String, dynamic>?;
    final finalDistance = double.tryParse(trip?['total_distance_km']?.toString() ?? '0') ?? _tripDistance;
    final finalDuration = int.tryParse(trip?['duration_minutes']?.toString() ?? '0') ?? _tripDuration;

    if (!mounted) return;
    setState(() {
      _isTripActive = false;
      _activeTripId = null;
      _activeCustomerId = null;
      _activeTripCustomer = '';
      _tripDistance = finalDistance;
      _tripDuration = finalDuration;
      _locationPointsSent = 0;
      _targetLat = null;
      _targetLng = null;
      _routePoints.clear();
      _navRoutePoints.clear();
      _markers.clear();
      _polylines.clear();
      _currentPosition = null;
      _routeSource = 'raw';
      _routeMessage = null;
    });

    // Reload customers (in case auto-save updated a customer)
    await _loadData();

    // Show "Continue to next customer?" dialog
    if (mounted) {
      _showContinueDialog(finalDistance, finalDuration);
    }
  }

  void _showContinueDialog(double distance, int duration) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: const Row(
          children: [
            Icon(Icons.check_circle, color: Color(0xFF10b981)),
            SizedBox(width: 10),
            Text('ដំណើរបានបញ្ចប់!', style: TextStyle(fontFamily: 'KhmerFont')),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '📍 ចម្ងាយ: ${distance.toStringAsFixed(2)} គម\n⏱ រយៈពេល: $duration នាទី',
              style: const TextStyle(fontFamily: 'KhmerFont', fontSize: 15),
            ),
            const SizedBox(height: 16),
            const Text(
              'តើចង់ធ្វើដំណើរទៅអតិថិជនមួយទៀតដែរអត់?',
              style: TextStyle(fontFamily: 'KhmerFont', fontWeight: FontWeight.w600),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('ចប់ហើយ', style: TextStyle(fontFamily: 'KhmerFont')),
          ),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF6366f1),
              foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            ),
            icon: const Icon(Icons.directions_car, size: 18),
            label: const Text('ដំណើរទៅបន្ត', style: TextStyle(fontFamily: 'KhmerFont')),
            onPressed: () {
              Navigator.pop(ctx);
              _showNextCustomerSelector();
            },
          ),
        ],
      ),
    );
  }

  void _showNextCustomerSelector() {
    if (_customers.isEmpty) {
      _showSnack('មិនមានអតិថិជនដើម្បីជ្រើសរើស', isError: true);
      return;
    }
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (ctx) => DraggableScrollableSheet(
        expand: false,
        initialChildSize: 0.6,
        maxChildSize: 0.9,
        builder: (_, scrollController) => Column(
          children: [
            const SizedBox(height: 12),
            Container(
              width: 40, height: 4,
              decoration: BoxDecoration(color: Colors.grey.shade300, borderRadius: BorderRadius.circular(4)),
            ),
            const SizedBox(height: 16),
            const Text(
              'ជ្រើសរើសអតិថិជនបន្ត',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w700, fontFamily: 'KhmerFont'),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: ListView.builder(
                controller: scrollController,
                padding: const EdgeInsets.symmetric(horizontal: 16),
                itemCount: _customers.length,
                itemBuilder: (_, index) {
                  final customer = _customers[index];
                  final name = customer['name']?.toString() ?? '';
                  final hasLoc = (customer['latitude'] != null &&
                      double.tryParse(customer['latitude'].toString()) != 0);
                  return ListTile(
                    leading: CircleAvatar(
                      backgroundColor: const Color(0xFF6366f1).withOpacity(0.12),
                      child: Text(
                        name.isEmpty ? '?' : name[0].toUpperCase(),
                        style: const TextStyle(color: Color(0xFF6366f1), fontWeight: FontWeight.w700),
                      ),
                    ),
                    title: Text(name, style: const TextStyle(fontFamily: 'KhmerFont', fontWeight: FontWeight.w600)),
                    subtitle: Text(
                      hasLoc ? '📍 មានទីតាំង' : '📍 គ្មានទីតាំង',
                      style: TextStyle(
                        fontSize: 12,
                        fontFamily: 'KhmerFont',
                        color: hasLoc ? const Color(0xFF10b981) : Colors.grey.shade500,
                      ),
                    ),
                    trailing: ElevatedButton(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF10b981),
                        foregroundColor: Colors.white,
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                      ),
                      onPressed: () {
                        Navigator.pop(ctx);
                        _startTrip(customer);
                      },
                      child: const Text('ធ្វើដំណើរ', style: TextStyle(fontFamily: 'KhmerFont')),
                    ),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _updateMapOverlays() {
    _markers.clear();
    _polylines.clear();

    if (_routePoints.isNotEmpty) {
      _markers.add(Marker(
        markerId: const MarkerId('start'),
        position: _routePoints.first,
        infoWindow: const InfoWindow(title: 'ចំណុចចាប់ផ្តើម'),
        icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueAzure),
      ));
      _markers.add(Marker(
        markerId: const MarkerId('current'),
        position: _routePoints.last,
        infoWindow: InfoWindow(
          title: 'ទីតាំងបច្ចុប្បន្ន',
          snippet: 'ល្បឿន ${((_currentPosition?.speed ?? 0) * 3.6).toStringAsFixed(1)} km/h',
        ),
        icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueGreen),
      ));
      // Traveled route polyline (purple)
      _polylines.add(Polyline(
        polylineId: const PolylineId('route'),
        points: List<LatLng>.from(_routePoints),
        color: const Color(0xFF6366f1),
        width: 5,
      ));
    }

    // Navigation route line from current position → destination (blue)
    if (_navRoutePoints.isNotEmpty) {
      _polylines.add(Polyline(
        polylineId: const PolylineId('nav_route'),
        points: List<LatLng>.from(_navRoutePoints),
        color: const Color(0xFF3b82f6),
        width: 4,
        patterns: [PatternItem.dash(20), PatternItem.gap(10)],
      ));
    }

    // Destination marker (red pin)
    if (_targetLat != null && _targetLng != null) {
      _markers.add(Marker(
        markerId: const MarkerId('target'),
        position: LatLng(_targetLat!, _targetLng!),
        infoWindow: InfoWindow(title: 'គោលដៅ: $_activeTripCustomer'),
        icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueRed),
      ));
    }
  }

  Future<void> _ensureBackgroundTrackingService() async {
    await BackgroundLocationService.startTracking();
  }

  Future<void> _stopBackgroundTrackingService() async {
    BackgroundLocationService.stopTracking();
  }

  void _showSnack(String msg, {bool isError = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg),
      backgroundColor: isError ? Colors.red.shade700 : const Color(0xFF10b981),
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      margin: const EdgeInsets.all(16),
    ));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Theme.of(context).scaffoldBackgroundColor,
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : _isTripActive
          ? _buildActiveTripMapView()
          : _buildCustomerList(),
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Full-Screen Map Active Trip View
  // ─────────────────────────────────────────────────────────────────────────────
  Widget _buildActiveTripMapView() {
    final speedKmh = (_currentPosition?.speed ?? 0) * 3.6;

    return Stack(
      children: [
        // ── Full-screen Google Map ──
        Positioned.fill(child: _buildMapWidget()),

        // ── Top AppBar overlay ──
        Positioned(
          top: 0, left: 0, right: 0,
          child: SafeArea(
            child: Container(
              margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.70),
                borderRadius: BorderRadius.circular(18),
              ),
              child: Row(
                children: [
                  GestureDetector(
                    onTap: () => Navigator.maybePop(context),
                    child: const Icon(Icons.arrow_back_ios_new, color: Colors.white, size: 20),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text('ការធ្វើដំណើរ',
                            style: TextStyle(color: Colors.white70, fontSize: 11, fontFamily: 'KhmerFont')),
                        Text(_activeTripCustomer,
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 16,
                              fontWeight: FontWeight.w700,
                              fontFamily: 'KhmerFont',
                            ),
                            overflow: TextOverflow.ellipsis),
                      ],
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.refresh_rounded, color: Colors.white),
                    onPressed: () {
                      _loadActiveTripRoute();
                      if (_targetLat != null && _targetLng != null && _currentPosition != null) {
                        _fetchNavRoute();
                      }
                    },
                  ),
                ],
              ),
            ),
          ),
        ),

        // ── Stats overlay cards (bottom left, above end button) ──
        Positioned(
          left: 12, right: 12,
          bottom: 100,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Nav route chip
              if (_targetLat != null)
                Container(
                  margin: const EdgeInsets.only(bottom: 8),
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  decoration: BoxDecoration(
                    color: Colors.black.withOpacity(0.65),
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        _isLoadingNavRoute ? Icons.hourglass_empty : Icons.directions,
                        color: const Color(0xFF3b82f6), size: 14,
                      ),
                      const SizedBox(width: 6),
                      Text(
                        _isLoadingNavRoute
                            ? 'កំពុងគណនា Route...'
                            : _navRoutePoints.isNotEmpty
                                ? 'Route OSRM: ${_navRoutePoints.length} ចំណុច'
                                : 'គ្មាន Route ទៅ Customer',
                        style: const TextStyle(
                          color: Colors.white, fontSize: 12, fontFamily: 'KhmerFont',
                        ),
                      ),
                    ],
                  ),
                ),
              // Stats row
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: Colors.black.withOpacity(0.70),
                  borderRadius: BorderRadius.circular(18),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceAround,
                  children: [
                    _miniStat(Icons.timer, '$_tripDuration', 'នាទី', const Color(0xFF6366f1)),
                    _divider(),
                    _miniStat(Icons.route, _tripDistance.toStringAsFixed(2), 'គម', const Color(0xFF10b981)),
                    _divider(),
                    _miniStat(Icons.speed, '${speedKmh.toStringAsFixed(1)}', 'km/h', const Color(0xFFf59e0b)),
                    _divider(),
                    _miniStat(Icons.location_on, '$_locationPointsSent', 'GPS', const Color(0xFF3b82f6)),
                  ],
                ),
              ),
            ],
          ),
        ),

        // ── END TRIP button ──
        Positioned(
          left: 16, right: 16, bottom: 32,
          child: SafeArea(
            child: SizedBox(
              height: 56,
              child: ElevatedButton.icon(
                onPressed: _endTrip,
                icon: const Icon(Icons.flag, size: 24),
                label: const Text(
                  'បញ្ចប់ដំណើរ',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.w700, fontFamily: 'KhmerFont'),
                ),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.red.shade600,
                  foregroundColor: Colors.white,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                  elevation: 6,
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _miniStat(IconData icon, String value, String label, Color color) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, color: color, size: 18),
        const SizedBox(height: 4),
        Text(value,
            style: TextStyle(color: color, fontWeight: FontWeight.w800, fontSize: 16)),
        Text(label,
            style: const TextStyle(color: Colors.white54, fontSize: 10, fontFamily: 'KhmerFont')),
      ],
    );
  }

  Widget _divider() => Container(
        width: 1, height: 40,
        color: Colors.white.withOpacity(0.15),
        margin: const EdgeInsets.symmetric(horizontal: 4),
      );

  Widget _buildMapWidget() {
    final isSupported =
        kIsWeb ||
        defaultTargetPlatform == TargetPlatform.android ||
        defaultTargetPlatform == TargetPlatform.iOS;

    if (!isSupported) {
      return const Center(child: Text('Map មិនទាន់គាំទ្រ', style: TextStyle(fontFamily: 'KhmerFont')));
    }

    return GoogleMap(
      initialCameraPosition: CameraPosition(
        target: LatLng(
          _currentPosition?.latitude ?? 11.5564,
          _currentPosition?.longitude ?? 104.9282,
        ),
        zoom: 16,
      ),
      onMapCreated: (controller) {
        _mapController = controller;
        if (_routePoints.isNotEmpty) _updateMapOverlays();
      },
      markers: _markers,
      polylines: _polylines,
      myLocationEnabled: !kIsWeb,
      myLocationButtonEnabled: true,
      zoomControlsEnabled: true,
      zoomGesturesEnabled: true,
      scrollGesturesEnabled: true,
      rotateGesturesEnabled: true,
      tiltGesturesEnabled: true,
      mapToolbarEnabled: false,
      compassEnabled: true,
      mapType: MapType.normal,
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Customer List
  // ─────────────────────────────────────────────────────────────────────────────
  Widget _buildCustomerList() {
    return Scaffold(
      appBar: AppBar(
        title: const Text(
          'ការធ្វើដំណើរ',
          style: TextStyle(fontWeight: FontWeight.w700, fontFamily: 'KhmerFont'),
        ),
        centerTitle: true,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _loadData,
          ),
        ],
      ),
      body: _customers.isEmpty
          ? Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.people_outline, size: 80, color: Colors.grey.shade300),
                  const SizedBox(height: 16),
                  Text('មិនមានអតិថិជនសម្រាប់តាមដានទេ។',
                      style: TextStyle(fontSize: 18, color: Colors.grey.shade500, fontFamily: 'KhmerFont')),
                ],
              ),
            )
          : RefreshIndicator(
              onRefresh: _loadData,
              child: ListView.builder(
                padding: const EdgeInsets.all(16),
                itemCount: _customers.length,
                itemBuilder: (context, index) => _customerCard(_customers[index]),
              ),
            ),
    );
  }

  Widget _customerCard(Map<String, dynamic> customer) {
    final name = customer['name']?.toString() ?? 'N/A';
    final phone = customer['phone']?.toString() ?? '';
    final image = customer['profile_image']?.toString();
    final hasImage = image != null && image.isNotEmpty;
    final hasLoc = (customer['latitude'] != null &&
        double.tryParse(customer['latitude'].toString()) != 0);

    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      decoration: BoxDecoration(
        color: Theme.of(context).cardColor,
        borderRadius: BorderRadius.circular(20),
        boxShadow: [
          BoxShadow(color: Colors.black.withOpacity(0.06), blurRadius: 12, offset: const Offset(0, 4)),
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            CircleAvatar(
              radius: 30,
              backgroundColor: const Color(0xFF6366f1).withOpacity(0.1),
              backgroundImage: hasImage ? NetworkImage(ApiService.getFullImageUrl(image)) : null,
              child: !hasImage
                  ? Text(name.isEmpty ? '?' : name[0].toUpperCase(),
                      style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w700, color: Color(0xFF6366f1)))
                  : null,
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(name,
                      style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
                  if (phone.isNotEmpty) ...[
                    const SizedBox(height: 4),
                    Row(children: [
                      Icon(Icons.phone, size: 14, color: Colors.grey.shade500),
                      const SizedBox(width: 4),
                      Text(phone, style: TextStyle(fontSize: 13, color: Colors.grey.shade600)),
                    ]),
                  ],
                  const SizedBox(height: 4),
                  Row(children: [
                    Icon(
                      hasLoc ? Icons.location_on : Icons.location_off,
                      size: 13,
                      color: hasLoc ? const Color(0xFF10b981) : Colors.grey.shade400,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      hasLoc ? 'មានទីតាំង GPS' : 'គ្មានទីតាំង GPS',
                      style: TextStyle(
                        fontSize: 12,
                        fontFamily: 'KhmerFont',
                        color: hasLoc ? const Color(0xFF10b981) : Colors.grey.shade400,
                      ),
                    ),
                  ]),
                ],
              ),
            ),
            ElevatedButton.icon(
              onPressed: () => _startTrip(customer),
              icon: const Icon(Icons.directions_car, size: 18),
              label: const Text('ធ្វើដំណើរ',
                  style: TextStyle(fontWeight: FontWeight.w600, fontSize: 13, fontFamily: 'KhmerFont')),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF10b981),
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                elevation: 2,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
