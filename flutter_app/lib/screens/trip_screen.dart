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
  String _activeTripCustomer = '';
  Timer? _locationTimer;
  Position? _currentPosition;
  double _tripDistance = 0;
  int _tripDuration = 0;
  DateTime? _tripStartTime;
  int _locationPointsSent = 0;
  String _routeSource = 'raw';
  String? _routeMessage;

  double? _targetLat;
  double? _targetLng;

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
    _locationTimer?.cancel();
    _mapController?.dispose();
    _pulseController.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (!_isTripActive || _activeTripId == null || kIsWeb) return;

    if (state == AppLifecycleState.resumed) {
      if (_locationTimer == null || !(_locationTimer?.isActive ?? false)) {
        _startLocationTracking();
      }
    } else if (state == AppLifecycleState.inactive ||
        state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      _locationTimer?.cancel();
      _locationTimer = null;
    }
  }

  LocationSettings _buildLocationSettings({
    LocationAccuracy accuracy = LocationAccuracy.bestForNavigation,
    int distanceFilter = 5,
    Duration timeLimit = const Duration(seconds: 15),
  }) {
    if (defaultTargetPlatform == TargetPlatform.android) {
      return AndroidSettings(
        accuracy: accuracy,
        distanceFilter: distanceFilter,
        intervalDuration: const Duration(seconds: 10),
        forceLocationManager: false,
        timeLimit: timeLimit,
      );
    }

    if (defaultTargetPlatform == TargetPlatform.iOS) {
      return AppleSettings(
        accuracy: accuracy,
        activityType: ActivityType.automotiveNavigation,
        distanceFilter: distanceFilter,
        pauseLocationUpdatesAutomatically: false,
        showBackgroundLocationIndicator: true,
        timeLimit: timeLimit,
      );
    }

    return LocationSettings(
      accuracy: accuracy,
      distanceFilter: distanceFilter,
      timeLimit: timeLimit,
    );
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
      _showSnack(
        'ត្រូវការការអនុញ្ញាត Location ដើម្បីចាប់ផ្តើមដំណើរ។',
        isError: true,
      );
      return false;
    }

    if (permission == LocationPermission.deniedForever) {
      _showSnack(
        'Location ត្រូវបានបិទ។ សូមបើកវិញក្នុង Settings។',
        isError: true,
      );
      await openAppSettings();
      return false;
    }

    // If permission is already 'always', we are fully authorized for background tracking!
    if (permission == LocationPermission.always) {
      return true;
    }

    if (!kIsWeb) {
      if (defaultTargetPlatform == TargetPlatform.android) {
        final backgroundStatus = await Permission.locationAlways.status;
        if (!backgroundStatus.isGranted) {
          final requested = await Permission.locationAlways.request();
          if (!requested.isGranted) {
            _showSnack(
              'សូមអនុញ្ញាត background location ដើម្បីឲ្យ app តាមដានបានពេលចេញពីកម្មវិធី។',
              isError: true,
            );
            await openAppSettings();
            return false;
          }
        }

        final notificationStatus = await Permission.notification.status;
        if (!notificationStatus.isGranted) {
          await Permission.notification.request();
        }
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
      debugPrint('Current GPS lookup failed, using last known position: $e');
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
        _customers = List<Map<String, dynamic>>.from(
          customersRes['data'] ?? [],
        );
      }

      if (activeTripRes['success'] == true && activeTripRes['trip'] != null) {
        final trip = activeTripRes['trip'] as Map<String, dynamic>;
        _isTripActive = true;
        _activeTripId = int.tryParse(trip['id'].toString());
        _activeTripCustomer = trip['customer_name']?.toString() ?? '';
        _tripStartTime = DateTime.tryParse(
          trip['started_at']?.toString() ?? '',
        );
        _targetLat = double.tryParse(trip['target_lat']?.toString() ?? '');
        _targetLng = double.tryParse(trip['target_lng']?.toString() ?? '');
        _tripDistance =
            double.tryParse(trip['total_distance_km']?.toString() ?? '0') ?? 0;
        _tripDuration =
            int.tryParse(trip['duration_minutes']?.toString() ?? '0') ?? 0;

        if (_activeTripId != null) {
          final prefs = await SharedPreferences.getInstance();
          await prefs.setString(
            'current_active_trip_id',
            _activeTripId.toString(),
          );
          await _ensureBackgroundTrackingService();
          await _loadActiveTripRoute();
          _startLocationTracking();
        }
      }
    } catch (e) {
      debugPrint('Error loading trip data: $e');
    }

    if (mounted) {
      setState(() => _isLoading = false);
    }
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
          .map(
            (p) => LatLng(
              double.tryParse((p['latitude'] ?? p['lat']).toString()) ?? 0,
              double.tryParse((p['longitude'] ?? p['lng']).toString()) ?? 0,
            ),
          )
          .where((point) => point.latitude != 0 || point.longitude != 0)
          .toList();

      final trip = res['trip'] as Map<String, dynamic>?;

      if (!mounted) return;
      setState(() {
        _routePoints
          ..clear()
          ..addAll(points);
        _locationPointsSent = points.length;

        if (trip != null) {
          _tripDistance =
              double.tryParse(trip['total_distance_km']?.toString() ?? '0') ??
              _tripDistance;
          _tripDuration =
              int.tryParse(trip['duration_minutes']?.toString() ?? '0') ??
              _tripDuration;
        }
        _routeSource = res['route_source']?.toString() ?? 'raw';
        _routeMessage = res['route_message']?.toString();

        _updateMapOverlays();
      });
    } catch (e) {
      debugPrint('Failed to load trip route: $e');
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
        _showSnack(
          res['message']?.toString() ?? 'មិនអាចចាប់ផ្តើមដំណើរបានទេ។',
          isError: true,
        );
        return;
      }

      final tripIdInt = res['trip_id'] is int
          ? res['trip_id'] as int
          : int.tryParse(res['trip_id'].toString());

      if (tripIdInt == null) {
        _showSnack(
          'បានចាប់ផ្តើមដំណើរ ប៉ុន្តែមិនទទួលបានលេខសម្គាល់ Trip។',
          isError: true,
        );
        return;
      }

      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('current_active_trip_id', tripIdInt.toString());
      await _ensureBackgroundTrackingService();

      if (!mounted) return;
      setState(() {
        _isTripActive = true;
        _activeTripId = tripIdInt;
        _activeTripCustomer = customerName;
        _tripStartTime = DateTime.now();
        _currentPosition = position;
        _tripDistance = 0;
        _tripDuration = 0;
        _targetLat = double.tryParse(customer['latitude']?.toString() ?? '');
        _targetLng = double.tryParse(customer['longitude']?.toString() ?? '');
        _routePoints.clear();
        _routePoints.add(LatLng(position.latitude, position.longitude));
        _locationPointsSent = _routePoints.length;
        _routeSource = 'raw';
        _routeMessage = null;
        _updateMapOverlays();
      });

      _startLocationTracking();
      _showSnack('បានចាប់ផ្តើមដំណើរទៅ $customerName។');
    } catch (e) {
      _showSnack('ចាប់ផ្តើមដំណើរមិនបាន: $e', isError: true);
    }
  }

  void _startLocationTracking() {
    _locationTimer?.cancel();
    _locationTimer = Timer.periodic(const Duration(seconds: 5), (_) async {
      if (!_isTripActive || _activeTripId == null) return;

      try {
        final position = await _getBestCurrentPosition();
        if (position == null || !mounted) return;

        setState(() {
          _currentPosition = position;
          if (_tripStartTime != null) {
            _tripDuration = DateTime.now()
                .difference(_tripStartTime!)
                .inMinutes;
          }

          _appendRoutePoint(LatLng(position.latitude, position.longitude));
          _updateMapOverlays();
        });

        if (_mapController != null) {
          await _mapController!.animateCamera(
            CameraUpdate.newLatLng(
              LatLng(position.latitude, position.longitude),
            ),
          );
        }
      } catch (e) {
        debugPrint('Location update error: $e');
      }
    });
  }

  void _appendRoutePoint(LatLng point) {
    if (_routePoints.isNotEmpty) {
      final lastPoint = _routePoints.last;
      final distanceMeters = Geolocator.distanceBetween(
        lastPoint.latitude,
        lastPoint.longitude,
        point.latitude,
        point.longitude,
      );

      if (distanceMeters < 3) {
        return;
      }

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
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
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
    final res = await _api.endTrip(tripId);
    if (res['success'] != true) {
      _showSnack(
        res['message']?.toString() ?? 'មិនអាចបញ្ចប់ដំណើរបានទេ។',
        isError: true,
      );
      return;
    }

    _locationTimer?.cancel();
    _locationTimer = null;

    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('current_active_trip_id');
    await _stopBackgroundTrackingService();

    final trip = res['trip'] as Map<String, dynamic>?;

    if (!mounted) return;
    setState(() {
      _isTripActive = false;
      _activeTripId = null;
      _activeTripCustomer = '';
      _tripDistance =
          double.tryParse(trip?['total_distance_km']?.toString() ?? '0') ?? 0;
      _tripDuration =
          int.tryParse(trip?['duration_minutes']?.toString() ?? '0') ?? 0;
      _locationPointsSent = 0;
      _targetLat = null;
      _targetLng = null;
      _routePoints.clear();
      _markers.clear();
      _polylines.clear();
      _currentPosition = null;
      _routeSource = 'raw';
      _routeMessage = null;
    });

    _showSnack(
      'បានបញ្ចប់ដំណើរ។ ចម្ងាយ ${_tripDistance.toStringAsFixed(2)} គម និងរយៈពេល $_tripDuration នាទី',
    );
  }

  void _updateMapOverlays() {
    _markers.clear();
    _polylines.clear();

    if (_routePoints.isEmpty) return;

    _markers.add(
      Marker(
        markerId: const MarkerId('start'),
        position: _routePoints.first,
        infoWindow: const InfoWindow(title: 'ចំណុចចាប់ផ្តើម'),
        icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueAzure),
      ),
    );

    _markers.add(
      Marker(
        markerId: const MarkerId('current'),
        position: _routePoints.last,
        infoWindow: InfoWindow(
          title: 'ទីតាំងបច្ចុប្បន្ន',
          snippet:
              'ល្បឿន ${((_currentPosition?.speed ?? 0) * 3.6).toStringAsFixed(1)} km/h',
        ),
        icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueGreen),
      ),
    );

    _polylines.add(
      Polyline(
        polylineId: const PolylineId('route'),
        points: List<LatLng>.from(_routePoints),
        color: const Color(0xFF6366f1),
        width: 6,
      ),
    );

    if (_targetLat != null && _targetLng != null) {
      _markers.add(
        Marker(
          markerId: const MarkerId('target'),
          position: LatLng(_targetLat!, _targetLng!),
          infoWindow: InfoWindow(title: 'គោលដៅ: $_activeTripCustomer'),
          icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueRed),
        ),
      );
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
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg),
        backgroundColor: isError
            ? Colors.red.shade700
            : const Color(0xFF10b981),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        margin: const EdgeInsets.all(16),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      backgroundColor: theme.scaffoldBackgroundColor,
      appBar: AppBar(
        title: const Text(
          'ការធ្វើដំណើរ',
          style: TextStyle(
            fontWeight: FontWeight.w700,
            fontFamily: 'KhmerFont',
          ),
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
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : _isTripActive
          ? _buildActiveTripView()
          : _buildCustomerList(),
    );
  }

  Widget _buildActiveTripView() {
    final speedKmh = (_currentPosition?.speed ?? 0) * 3.6;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        children: [
          AnimatedBuilder(
            animation: _pulseController,
            builder: (context, child) {
              return Container(
                width: double.infinity,
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  color: const Color(0xFF10B981),
                  borderRadius: BorderRadius.circular(24),
                  boxShadow: [
                    BoxShadow(
                      color: const Color(0xFF10b981).withValues(alpha: 0.3),
                      blurRadius: 20,
                      offset: const Offset(0, 8),
                    ),
                  ],
                ),
                child: Column(
                  children: [
                    const Icon(
                      Icons.directions_car,
                      color: Colors.white,
                      size: 48,
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'កំពុងធ្វើដំណើរ',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 22,
                        fontWeight: FontWeight.w800,
                        fontFamily: 'KhmerFont',
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      _activeTripCustomer,
                      style: const TextStyle(
                        color: Colors.white70,
                        fontSize: 16,
                        fontFamily: 'KhmerFont',
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
          const SizedBox(height: 24),
          Row(
            children: [
              _statCard(
                Icons.timer,
                'រយៈពេល',
                '$_tripDuration នាទី',
                const Color(0xFF6366f1),
              ),
              const SizedBox(width: 12),
              _statCard(
                Icons.route,
                'ចម្ងាយ',
                '${_tripDistance.toStringAsFixed(2)} គម',
                const Color(0xFF10b981),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              _statCard(
                Icons.speed,
                'ល្បឿន',
                '${speedKmh.toStringAsFixed(1)} km/h',
                const Color(0xFFf59e0b),
              ),
              const SizedBox(width: 12),
              _statCard(
                Icons.location_searching,
                'ចំណុច GPS',
                _locationPointsSent.toString(),
                const Color(0xFF3b82f6),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Align(
            alignment: Alignment.centerLeft,
            child: _buildRouteSourceChip(),
          ),
          const SizedBox(height: 24),
          Container(
            height: 360,
            width: double.infinity,
            decoration: BoxDecoration(
              color: Colors.grey.shade200,
              borderRadius: BorderRadius.circular(24),
              border: Border.all(color: Colors.grey.shade300),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.05),
                  blurRadius: 10,
                  offset: const Offset(0, 4),
                ),
              ],
            ),
            clipBehavior: Clip.antiAlias,
            child: _buildMapWidget(),
          ),
          const SizedBox(height: 24),
          SizedBox(
            width: double.infinity,
            height: 56,
            child: ElevatedButton.icon(
              onPressed: _endTrip,
              icon: const Icon(Icons.flag, size: 24),
              label: const Text(
                'បញ្ចប់ដំណើរ',
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                  fontFamily: 'KhmerFont',
                ),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.red.shade600,
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(16),
                ),
                elevation: 4,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMapWidget() {
    final isSupported =
        kIsWeb ||
        defaultTargetPlatform == TargetPlatform.android ||
        defaultTargetPlatform == TargetPlatform.iOS;

    if (!isSupported) {
      return Center(
        child: Text(
          'Map មិនទាន់គាំទ្រលើ ${defaultTargetPlatform.name} ទេ។',
          style: TextStyle(
            color: Colors.grey.shade600,
            fontFamily: 'KhmerFont',
          ),
        ),
      );
    }

    return GoogleMap(
      initialCameraPosition: CameraPosition(
        target: LatLng(
          _currentPosition?.latitude ?? 11.5564,
          _currentPosition?.longitude ?? 104.9282,
        ),
        zoom: 15,
      ),
      onMapCreated: (controller) {
        _mapController = controller;
        if (_routePoints.isNotEmpty) {
          _updateMapOverlays();
        }
      },
      markers: _markers,
      polylines: _polylines,
      myLocationEnabled: !kIsWeb,
      myLocationButtonEnabled: !kIsWeb,
      zoomControlsEnabled: true,
      zoomGesturesEnabled: true,
      mapToolbarEnabled: true,
    );
  }

  Widget _statCard(IconData icon, String label, String value, Color color) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: color.withValues(alpha: 0.2)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, color: color, size: 24),
            const SizedBox(height: 8),
            Text(
              value,
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.w800,
                color: color,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              label,
              style: TextStyle(
                fontSize: 12,
                color: Colors.grey.shade600,
                fontFamily: 'KhmerFont',
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildRouteSourceChip() {
    final isSnapped = _routeSource != 'raw';
    final background = isSnapped
        ? const Color(0xFF10b981).withValues(alpha: 0.14)
        : const Color(0xFFf59e0b).withValues(alpha: 0.14);
    final foreground = isSnapped
        ? const Color(0xFF10b981)
        : const Color(0xFFf59e0b);
    final label = isSnapped ? 'ផ្លូវជាប់ផ្លូវពិត' : 'GPS ដើម';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: background,
            borderRadius: BorderRadius.circular(999),
            border: Border.all(color: foreground.withValues(alpha: 0.25)),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                isSnapped ? Icons.route : Icons.my_location,
                size: 16,
                color: foreground,
              ),
              const SizedBox(width: 8),
              Text(
                label,
                style: TextStyle(
                  color: foreground,
                  fontWeight: FontWeight.w700,
                  fontFamily: 'KhmerFont',
                ),
              ),
            ],
          ),
        ),
        if ((_routeMessage ?? '').isNotEmpty) ...[
          const SizedBox(height: 6),
          Text(
            'បង្ហាញ GPS ដើម ព្រោះ route snap មិនទាន់ពេញលេញ។',
            style: TextStyle(
              color: Colors.grey.shade600,
              fontSize: 12,
              fontFamily: 'KhmerFont',
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildCustomerList() {
    if (_customers.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.people_outline, size: 80, color: Colors.grey.shade300),
            const SizedBox(height: 16),
            Text(
              'មិនមានអតិថិជនសម្រាប់តាមដានទេ។',
              style: TextStyle(
                fontSize: 18,
                color: Colors.grey.shade500,
                fontFamily: 'KhmerFont',
              ),
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _loadData,
      child: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: _customers.length,
        itemBuilder: (context, index) {
          final customer = _customers[index];
          return _customerCard(customer);
        },
      ),
    );
  }

  Widget _customerCard(Map<String, dynamic> customer) {
    final name = customer['name']?.toString() ?? 'N/A';
    final phone = customer['phone']?.toString() ?? '';
    final image = customer['profile_image']?.toString();
    final hasImage = image != null && image.isNotEmpty;

    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      decoration: BoxDecoration(
        color: Theme.of(context).cardColor,
        borderRadius: BorderRadius.circular(20),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.06),
            blurRadius: 12,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            CircleAvatar(
              radius: 30,
              backgroundColor: const Color(0xFF6366f1).withValues(alpha: 0.1),
              backgroundImage: hasImage
                  ? NetworkImage(ApiService.getFullImageUrl(image))
                  : null,
              child: !hasImage
                  ? Text(
                      name.isEmpty ? '?' : name[0].toUpperCase(),
                      style: const TextStyle(
                        fontSize: 22,
                        fontWeight: FontWeight.w700,
                        color: Color(0xFF6366f1),
                      ),
                    )
                  : null,
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    name,
                    style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  if (phone.isNotEmpty) ...[
                    const SizedBox(height: 4),
                    Row(
                      children: [
                        Icon(
                          Icons.phone,
                          size: 14,
                          color: Colors.grey.shade500,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          phone,
                          style: TextStyle(
                            fontSize: 13,
                            color: Colors.grey.shade600,
                          ),
                        ),
                      ],
                    ),
                  ],
                ],
              ),
            ),
            ElevatedButton.icon(
              onPressed: () => _startTrip(customer),
              icon: const Icon(Icons.directions_car, size: 18),
              label: const Text(
                'ធ្វើដំណើរ',
                style: TextStyle(
                  fontWeight: FontWeight.w600,
                  fontSize: 13,
                  fontFamily: 'KhmerFont',
                ),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF10b981),
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                ),
                padding: const EdgeInsets.symmetric(
                  horizontal: 14,
                  vertical: 10,
                ),
                elevation: 2,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
