import 'dart:io';
import 'dart:convert';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:geolocator/geolocator.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:google_maps_flutter/google_maps_flutter.dart';
import 'package:image_picker/image_picker.dart';
import 'package:flutter/foundation.dart' show kIsWeb, defaultTargetPlatform;
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../services/notification_service.dart';
import '../utils/app_theme.dart';

class OutsideAttendanceScreen extends StatefulWidget {
  const OutsideAttendanceScreen({super.key});

  @override
  State<OutsideAttendanceScreen> createState() => _OutsideAttendanceScreenState();
}

class _OutsideAttendanceScreenState extends State<OutsideAttendanceScreen> {
  final ApiService _apiService = ApiService();
  final TextEditingController _locationController = TextEditingController();
  
  bool _isLoading = false;
  Position? _currentPosition;
  GoogleMapController? _mapController;
  final Set<Marker> _markers = {};
  XFile? _capturedImage;
  Future<void> _captureImage() async {
    final picker = ImagePicker();
    final pickedFile = await picker.pickImage(
      source: ImageSource.camera,
      imageQuality: 50,
      maxWidth: 800,
    );
    if (pickedFile != null) {
      setState(() {
        _capturedImage = pickedFile;
      });
    }
  }

  @override
  void initState() {
    super.initState();
    _determinePosition();
  }

  @override
  void dispose() {
    _locationController.dispose();
    super.dispose();
  }

  Future<void> _determinePosition() async {
    setState(() => _isLoading = true);
    try {
      bool serviceEnabled = await Geolocator.isLocationServiceEnabled();
      if (!serviceEnabled) {
        throw 'សេវាទីតាំង (GPS) ត្រូវបានបិទ។ សូមបើកវាសិន។';
      }

      LocationPermission permission = await Geolocator.checkPermission();
      if (permission == LocationPermission.denied) {
        permission = await Geolocator.requestPermission();
        if (permission == LocationPermission.denied) {
          throw 'ការអនុញ្ញាតចូលប្រើទីតាំងត្រូវបានបដិសេធ';
        }
      }

      if (permission == LocationPermission.deniedForever) {
        throw 'ការអនុញ្ញាតទីតាំងត្រូវបានបដិសេធជាអចិន្ត្រៃយ៍។';
      }

      Position position = await Geolocator.getCurrentPosition(
        locationSettings: const LocationSettings(
          accuracy: LocationAccuracy.high,
          timeLimit: Duration(seconds: 15),
        ),
      );

      setState(() {
        _currentPosition = position;
        _markers.add(Marker(
          markerId: const MarkerId('current'),
          position: LatLng(position.latitude, position.longitude),
          infoWindow: const InfoWindow(title: 'ទីតាំងរបស់អ្នក'),
          icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueRed),
        ));
      });

      if (_mapController != null) {
        _mapController!.animateCamera(
          CameraUpdate.newLatLngZoom(
            LatLng(position.latitude, position.longitude), 
            16.0
          ),
        );
      }
    } catch (e) {
      _showError(e.toString());
    } finally {
      setState(() => _isLoading = false);
    }
  }

  void _submitAttendance(String action) async {
    if (_currentPosition == null) {
      _showError("កំពុងស្វែងរកទីតាំង GPS សូមរង់ចាំ...");
      return;
    }

    if (_capturedImage == null) {
      _showError("សូមថតរូបទីតាំងរបស់អ្នកជាមុនសិន");
      return;
    }

    if (_locationController.text.trim().isEmpty) {
      _showError("សូមបញ្ចូលឈ្មោះអតិថិជន ឬ ទីតាំង");
      return;
    }

    setState(() => _isLoading = true);

    try {
      String locationRaw = "${_currentPosition!.latitude},${_currentPosition!.longitude}";
      final userProvider = Provider.of<UserProvider>(context, listen: false);
      
      String photoBase64 = base64Encode(await _capturedImage!.readAsBytes());

      final result = await _apiService.submitAttendance(
        action: action,
        employeeId: userProvider.employeeId!,
        workplace: "Outside",
        branch: "Outside",
        locationRaw: locationRaw,
        qrSecret: "outside_scan",
        qrLocationId: 0,
        manualLocationName: _locationController.text.trim(),
        photoBase64: photoBase64,
      );

      if (result['success'] == true) {
        NotificationService().showNotification(
          id: DateTime.now().millisecondsSinceEpoch.remainder(100000),
          title: "ជោគជ័យ",
          body: "អ្នកបាន $action (ក្រៅការិយាល័យ) ដោយជោគជ័យ!",
        );
        _showSuccess(result['message']);
      } else {
        _showError(result['message']);
      }
    } catch (e) {
      _showError("កំហុស៖ $e");
    } finally {
      setState(() => _isLoading = false);
    }
  }

  void _showError(String message) {
    _showResultPopup(message, Icons.error_outline_rounded, Colors.redAccent);
  }

  void _showSuccess(String message) {
    _showResultPopup(message, Icons.check_circle_outline_rounded, Colors.cyanAccent, isSuccess: true);
  }

  void _showResultPopup(String message, IconData icon, Color color, {bool isSuccess = false}) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => FadeInScale(
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 10, sigmaY: 10),
          child: AlertDialog(
            backgroundColor: const Color(0xFF1E293B).withValues(alpha: 0.9),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(24),
              side: BorderSide(color: color.withValues(alpha: 0.3)),
            ),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(icon, color: color, size: 64),
                const SizedBox(height: 20),
                Text(
                  message,
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontSize: 16,
                  ),
                ),
                const SizedBox(height: 24),
                ElevatedButton(
                  onPressed: () {
                    Navigator.pop(context);
                    if (isSuccess) Navigator.pop(context);
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: color.withValues(alpha: 0.2),
                    foregroundColor: color,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  child: Text(
                    "យល់ព្រម",
                    style: GoogleFonts.kantumruyPro(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildMapWidget() {
    bool isSupported = kIsWeb || 
                       defaultTargetPlatform == TargetPlatform.android || 
                       defaultTargetPlatform == TargetPlatform.iOS;

    if (!isSupported) {
      return Container(
        color: AppTheme.bgCard,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.location_off_rounded, size: 64, color: AppTheme.textMuted),
            const SizedBox(height: 16),
            Text(
              'ផែនទីមិនទាន់គាំទ្រលើប្រព័ន្ធនេះទេ',
              style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.w600, color: AppTheme.textSecondary),
            ),
          ],
        ),
      );
    }

    return GoogleMap(
      initialCameraPosition: CameraPosition(
        target: _currentPosition != null 
            ? LatLng(_currentPosition!.latitude, _currentPosition!.longitude)
            : const LatLng(11.5564, 104.9282), // Default Phnom Penh
        zoom: 15,
      ),
      onMapCreated: (controller) => _mapController = controller,
      markers: _markers,
      myLocationEnabled: true,
      myLocationButtonEnabled: true,
      zoomControlsEnabled: false,
      mapToolbarEnabled: false,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        title: Text(
          "Check-In ខាងក្រៅ",
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        backgroundColor: AppTheme.bgCard,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _determinePosition,
          ),
        ],
      ),
      body: Stack(
        children: [
          Column(
            children: [
              // Map View
              Expanded(
                flex: 4,
                child: Container(
                  width: double.infinity,
                  decoration: BoxDecoration(
                    border: Border(bottom: BorderSide(color: AppTheme.textPrimary.withValues(alpha: 0.1))),
                  ),
                  child: _buildMapWidget(),
                ),
              ),

              // Controls View
              Expanded(
                flex: 6,
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
                  decoration: BoxDecoration(
                    color: AppTheme.bgCard,
                    borderRadius: const BorderRadius.vertical(top: Radius.circular(30)),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: 0.2),
                        blurRadius: 20,
                        offset: const Offset(0, -5),
                      ),
                    ],
                  ),
                  child: SingleChildScrollView(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        // Camera Section
                        Center(
                          child: GestureDetector(
                            onTap: _captureImage,
                            child: Container(
                              height: 120,
                              width: 120,
                              margin: const EdgeInsets.only(bottom: 20),
                              decoration: BoxDecoration(
                                color: AppTheme.bgDark,
                                borderRadius: BorderRadius.circular(16),
                                border: Border.all(color: AppTheme.primary.withValues(alpha: 0.5), width: 1),
                                image: _capturedImage != null
                                    ? DecorationImage(
                                        image: kIsWeb ? NetworkImage(_capturedImage!.path) as ImageProvider : FileImage(File(_capturedImage!.path)),
                                        fit: BoxFit.cover,
                                      )
                                    : null,
                              ),
                              child: _capturedImage == null
                                  ? Column(
                                      mainAxisAlignment: MainAxisAlignment.center,
                                      children: [
                                        Icon(Icons.camera_alt_rounded, size: 40, color: AppTheme.primary),
                                        const SizedBox(height: 8),
                                        Text(
                                          "ថតរូបទីតាំង",
                                          style: GoogleFonts.kantumruyPro(
                                            color: AppTheme.primary,
                                            fontSize: 12,
                                            fontWeight: FontWeight.w600,
                                          ),
                                        )
                                      ],
                                    )
                                  : Align(
                                      alignment: Alignment.bottomRight,
                                      child: Container(
                                        padding: const EdgeInsets.all(4),
                                        margin: const EdgeInsets.all(8),
                                        decoration: BoxDecoration(color: Colors.black54, borderRadius: BorderRadius.circular(8)),
                                        child: const Icon(Icons.edit, size: 16, color: Colors.white),
                                      ),
                                    ),
                            ),
                          ),
                        ),

                        Text(
                          "ទីតាំងអតិថិជន ឬ គោលដៅ",
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textSecondary,
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 10),
                        TextField(
                          controller: _locationController,
                          style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary),
                          decoration: InputDecoration(
                            hintText: "ឧទាហរណ៍: ការដ្ឋានបុរី ឬ ឈ្មោះអតិថិជន...",
                            hintStyle: GoogleFonts.kantumruyPro(color: AppTheme.textMuted),
                            filled: true,
                            fillColor: AppTheme.bgDark,
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(16),
                              borderSide: BorderSide.none,
                            ),
                            prefixIcon: Icon(Icons.business_rounded, color: AppTheme.primary),
                          ),
                        ),
                        const SizedBox(height: 24),
                        Row(
                          children: [
                            Expanded(
                              child: _buildActionButton(
                                "Check-In",
                                Colors.cyanAccent,
                                Icons.login_rounded,
                                () => _submitAttendance("Check-In"),
                              ),
                            ),
                            const SizedBox(width: 16),
                            Expanded(
                              child: _buildActionButton(
                                "Check-Out",
                                Colors.orangeAccent,
                                Icons.logout_rounded,
                                () => _submitAttendance("Check-Out"),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ],
          ),

          if (_isLoading)
            Container(
              color: Colors.black.withValues(alpha: 0.6),
              child: const Center(
                child: CircularProgressIndicator(color: Colors.cyanAccent),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildActionButton(String label, Color color, IconData icon, VoidCallback onTap) {
    return ElevatedButton(
      onPressed: onTap,
      style: ElevatedButton.styleFrom(
        backgroundColor: color.withValues(alpha: 0.15),
        foregroundColor: color,
        padding: const EdgeInsets.symmetric(vertical: 16),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: color.withValues(alpha: 0.5), width: 1.5),
        ),
        elevation: 0,
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, size: 22),
          const SizedBox(width: 8),
          Text(
            label,
            style: GoogleFonts.inter(
              fontWeight: FontWeight.w800,
              fontSize: 16,
              letterSpacing: 0.5,
            ),
          ),
        ],
      ),
    );
  }
}

class FadeInScale extends StatefulWidget {
  final Widget child;
  const FadeInScale({super.key, required this.child});
  @override
  State<FadeInScale> createState() => _FadeInScaleState();
}

class _FadeInScaleState extends State<FadeInScale> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _opacity;
  late Animation<double> _scale;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: const Duration(milliseconds: 300));
    _opacity = Tween<double>(begin: 0.0, end: 1.0).animate(CurvedAnimation(parent: _controller, curve: Curves.easeOut));
    _scale = Tween<double>(begin: 0.8, end: 1.0).animate(CurvedAnimation(parent: _controller, curve: Curves.easeOutBack));
    _controller.forward();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return FadeTransition(opacity: _opacity, child: ScaleTransition(scale: _scale, child: widget.child));
  }
}
