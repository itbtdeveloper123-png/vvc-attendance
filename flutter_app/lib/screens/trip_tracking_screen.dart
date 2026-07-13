import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:google_maps_flutter/google_maps_flutter.dart';

import '../services/api_service.dart';
import '../utils/app_theme.dart';

class TripTrackingScreen extends StatefulWidget {
  final int tripId;

  const TripTrackingScreen({super.key, required this.tripId});

  @override
  State<TripTrackingScreen> createState() => _TripTrackingScreenState();
}

class _TripTrackingScreenState extends State<TripTrackingScreen> {
  final ApiService _api = ApiService();

  GoogleMapController? _mapController;
  Map<String, dynamic>? _trip;
  List<LatLng> _points = [];
  bool _isLoading = true;
  Set<Marker> _markers = {};
  Set<Polyline> _polylines = {};
  String _routeSource = 'raw';
  String? _routeMessage;

  Timer? _pollingTimer;
  bool _isFirstLoad = true;

  @override
  void initState() {
    super.initState();
    _loadTripDetails();
    _startPolling();
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    super.dispose();
  }

  void _startPolling() {
    _pollingTimer = Timer.periodic(const Duration(seconds: 10), (timer) {
      if (!mounted) return;
      if (_trip == null || _trip?['status'] == 'active') {
        _loadTripDetailsSilently();
      } else {
        _pollingTimer?.cancel();
      }
    });
  }

  Future<void> _loadTripDetails() async {
    try {
      _isFirstLoad = true;
      final res = await _api.getTripDetails(widget.tripId);
      if (res['success'] == true) {
        final routeData = (res['snapped_points'] as List?)?.isNotEmpty == true
            ? res['snapped_points'] as List
            : (res['points'] as List? ?? const []);

        setState(() {
          _trip = res['trip'];
          _routeSource = res['route_source']?.toString() ?? 'raw';
          _routeMessage = res['route_message']?.toString();
          _points = routeData
              .map(
                (p) => LatLng(
                  double.parse((p['latitude'] ?? p['lat']).toString()),
                  double.parse((p['longitude'] ?? p['lng']).toString()),
                ),
              )
              .toList();
          _isLoading = false;
        });
        _updateMap();
      } else {
        setState(() => _isLoading = false);
      }
    } catch (e) {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _loadTripDetailsSilently() async {
    try {
      final res = await _api.getTripDetails(widget.tripId);
      if (res['success'] == true && mounted) {
        final routeData = (res['snapped_points'] as List?)?.isNotEmpty == true
            ? res['snapped_points'] as List
            : (res['points'] as List? ?? const []);

        setState(() {
          _trip = res['trip'];
          _routeSource = res['route_source']?.toString() ?? 'raw';
          _routeMessage = res['route_message']?.toString();
          _points = routeData
              .map(
                (p) => LatLng(
                  double.parse((p['latitude'] ?? p['lat']).toString()),
                  double.parse((p['longitude'] ?? p['lng']).toString()),
                ),
              )
              .toList();
        });
        _updateMap();
      }
    } catch (_) {
      // Ignore background errors
    }
  }

  void _updateMap() {
    if (_points.isEmpty) return;

    final start = _points.first;
    final last = _points.last;

    _markers = {
      Marker(
        markerId: const MarkerId('start'),
        position: start,
        infoWindow: const InfoWindow(title: 'ចំណុចចាប់ផ្តើម'),
        icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueGreen),
      ),
      Marker(
        markerId: const MarkerId('current'),
        position: last,
        infoWindow: InfoWindow(
          title: _trip?['user_name'] ?? 'ទីតាំងបច្ចុប្បន្ន',
        ),
        icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueAzure),
      ),
    };

    _polylines = {
      Polyline(
        polylineId: const PolylineId('route'),
        points: _points,
        color: AppTheme.primary,
        width: 5,
      ),
    };

    if (_mapController != null && _isFirstLoad) {
      _mapController?.animateCamera(CameraUpdate.newLatLngZoom(last, 15));
      _isFirstLoad = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        title: Text(
          _trip?['user_name'] ?? 'តាមដានការធ្វើដំណើរ',
          style: GoogleFonts.kantumruyPro(),
        ),
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : Stack(
              children: [
                GoogleMap(
                  style: AppTheme.isDarkMode
                      ? '''[{"elementType":"geometry","stylers":[{"color":"#242f3e"}]},{"elementType":"labels.text.fill","stylers":[{"color":"#746855"}]},{"elementType":"labels.text.stroke","stylers":[{"color":"#242f3e"}]},{"featureType":"administrative.locality","elementType":"labels.text.fill","stylers":[{"color":"#d59563"}]},{"featureType":"poi","elementType":"labels.text.fill","stylers":[{"color":"#d59563"}]},{"featureType":"poi.park","elementType":"geometry","stylers":[{"color":"#263c3f"}]},{"featureType":"poi.park","elementType":"labels.text.fill","stylers":[{"color":"#6b9a76"}]},{"featureType":"road","elementType":"geometry","stylers":[{"color":"#38414e"}]},{"featureType":"road","elementType":"geometry.stroke","stylers":[{"color":"#212a37"}]},{"featureType":"road","elementType":"labels.text.fill","stylers":[{"color":"#9ca5b3"}]},{"featureType":"road.highway","elementType":"geometry","stylers":[{"color":"#746855"}]},{"featureType":"road.highway","elementType":"geometry.stroke","stylers":[{"color":"#1f2835"}]},{"featureType":"road.highway","elementType":"labels.text.fill","stylers":[{"color":"#f3d19c"}]},{"featureType":"transit","elementType":"geometry","stylers":[{"color":"#2f3948"}]},{"featureType":"transit.station","elementType":"labels.text.fill","stylers":[{"color":"#d59563"}]},{"featureType":"water","elementType":"geometry","stylers":[{"color":"#17263c"}]},{"featureType":"water","elementType":"labels.text.fill","stylers":[{"color":"#515c6d"}]},{"featureType":"water","elementType":"labels.text.stroke","stylers":[{"color":"#17263c"}]}]'''
                      : null,
                  initialCameraPosition: CameraPosition(
                    target: _points.isNotEmpty
                        ? _points.last
                        : const LatLng(11.5564, 104.9282),
                    zoom: 15,
                  ),
                  onMapCreated: (c) {
                    _mapController = c;
                    if (_points.isNotEmpty) _updateMap();
                  },
                  markers: _markers,
                  polylines: _polylines,
                  myLocationButtonEnabled: false,
                ),
                Positioned(
                  bottom: 20,
                  left: 20,
                  right: 20,
                  child: Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: AppTheme.bgCard.withValues(alpha: 0.9),
                      borderRadius: BorderRadius.circular(20),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.3),
                          blurRadius: 10,
                        ),
                      ],
                    ),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Row(
                          children: [
                            CircleAvatar(
                              backgroundColor: AppTheme.primary.withValues(alpha: 0.1),
                              child: Icon(
                                Icons.directions_car,
                                color: AppTheme.primary,
                              ),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    _trip?['customer_name'] ?? 'N/A',
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.white,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  Text(
                                    'កំពុងធ្វើដំណើរ...',
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.greenAccent,
                                      fontSize: 12,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            _buildInfo(
                              'ចម្ងាយ',
                              '${_trip?['total_distance_km'] ?? '0'} KM',
                            ),
                            _buildInfo(
                              'រយៈពេល',
                              '${_trip?['duration_minutes'] ?? '0'} នាទី',
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        Align(
                          alignment: Alignment.centerLeft,
                          child: _buildRouteBadge(),
                        ),
                      ],
                    ),
                  ),
                ),
                Positioned(
                  top: 10,
                  right: 10,
                  child: FloatingActionButton(
                    mini: true,
                    backgroundColor: AppTheme.primary,
                    onPressed: _loadTripDetails,
                    child: const Icon(Icons.refresh, color: Colors.white),
                  ),
                ),
              ],
            ),
    );
  }

  Widget _buildInfo(String label, String val) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 10),
        ),
        Text(
          val,
          style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold),
        ),
      ],
    );
  }

  Widget _buildRouteBadge() {
    final isSnapped = _routeSource != 'raw';
    final bg = isSnapped
        ? AppTheme.primary.withValues(alpha: 0.18)
        : Colors.orange.withValues(alpha: 0.18);
    final fg = isSnapped ? Colors.greenAccent : Colors.orangeAccent;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: bg,
            borderRadius: BorderRadius.circular(999),
            border: Border.all(color: fg.withValues(alpha: 0.25)),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                isSnapped ? Icons.route : Icons.my_location,
                size: 15,
                color: fg,
              ),
              const SizedBox(width: 8),
              Text(
                isSnapped ? 'ផ្លូវជាប់ផ្លូវពិត' : 'GPS ដើម',
                style: GoogleFonts.kantumruyPro(
                  color: fg,
                  fontWeight: FontWeight.w700,
                  fontSize: 12,
                ),
              ),
            ],
          ),
        ),
        if ((_routeMessage ?? '').isNotEmpty) ...[
          const SizedBox(height: 6),
          Text(
            'កំពុងបង្ហាញ GPS ដើម ព្រោះការជាប់ផ្លូវមិនទាន់ពេញលេញ។',
            style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 11),
          ),
        ],
      ],
    );
  }
}
