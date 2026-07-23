import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:geolocator/geolocator.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:google_maps_flutter/google_maps_flutter.dart';
import 'package:image_picker/image_picker.dart';
import 'package:local_auth/local_auth.dart';
import 'package:flutter/foundation.dart' show kIsWeb, defaultTargetPlatform;
import 'package:http/http.dart' as http;
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../services/notification_service.dart';
import '../utils/app_theme.dart';
import '../utils/image_compress.dart';

class OutsideAttendanceScreen extends StatefulWidget {
  const OutsideAttendanceScreen({super.key});

  @override
  State<OutsideAttendanceScreen> createState() => _OutsideAttendanceScreenState();
}

class _OutsideAttendanceScreenState extends State<OutsideAttendanceScreen> {
  final ApiService _apiService = ApiService();
  final TextEditingController _locationController = TextEditingController();

  bool _isLoading = false;
  bool _isMapSatellite = false;
  Position? _currentPosition;
  GoogleMapController? _mapController;
  final Set<Marker> _markers = {};
  XFile? _capturedImage;
  BitmapDescriptor? _profileMarkerBitmap;

  Future<void> _loadProfileMarkerBitmap() async {
    try {
      final user = context.read<UserProvider>();
      final avatarUrl = user.avatarUrl ?? '';
      if (avatarUrl.isEmpty) return;

      final response = await http
          .get(Uri.parse(avatarUrl))
          .timeout(const Duration(seconds: 8));
      if (response.statusCode != 200) return;

      final codec = await ui.instantiateImageCodec(
        response.bodyBytes,
        targetWidth: 48,
        targetHeight: 48,
      );
      final frame = await codec.getNextFrame();
      final image = frame.image;

      final recorder = ui.PictureRecorder();
      final canvas = Canvas(recorder);
      const size = 48.0;
      const half = size / 2;
      const borderWidth = 3.0;

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
      if (byteData == null) return;

      final Uint8List bytes = byteData.buffer.asUint8List();
      final bitmap = BitmapDescriptor.bytes(bytes);

      if (mounted) {
        setState(() {
          _profileMarkerBitmap = bitmap;
          _updateProfileMarker();
        });
      }
    } catch (e) {
      debugPrint('Failed to load profile marker bitmap: $e');
    }
  }

  void _updateProfileMarker() {
    if (_currentPosition == null) return;
    _markers.removeWhere((m) => m.markerId.value == 'profile');
    if (_profileMarkerBitmap != null) {
      _markers.add(
        Marker(
          markerId: const MarkerId('profile'),
          position: LatLng(_currentPosition!.latitude, _currentPosition!.longitude),
          icon: _profileMarkerBitmap!,
          anchor: const Offset(0.5, 0.5),
        ),
      );
    }
    setState(() {});
  }

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
        _markers.add(
          Marker(
            markerId: const MarkerId('current'),
            position: LatLng(position.latitude, position.longitude),
            infoWindow: const InfoWindow(title: 'ទីតាំងរបស់អ្នក'),
            icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueRed),
          ),
        );
      });

      if (_mapController != null) {
        _mapController!.animateCamera(
          CameraUpdate.newLatLngZoom(
            LatLng(position.latitude, position.longitude),
            16.0,
          ),
        );
      }

      _loadProfileMarkerBitmap();

      _apiService.reverseGeocode(position.latitude, position.longitude).then((res) {
        if (res['success'] == true && res['address'] != null) {
          if (_locationController.text.trim().isEmpty) {
            setState(() {
              _locationController.text = res['address'];
            });
          }
        }
      }).catchError((e) {
        // Fail silently to prevent interrupting GPS flow
      });
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

      String photoBase64 = await compressAndEncodeImage(await _capturedImage!.readAsBytes());

      // Local Biometric Authentication
      final LocalAuthentication localAuth = LocalAuthentication();
      final bool canCheckBiometrics = await localAuth.canCheckBiometrics;
      final bool isDeviceSupported = await localAuth.isDeviceSupported();
      bool deviceAuthenticated = false;

      if (canCheckBiometrics || isDeviceSupported) {
        deviceAuthenticated = await localAuth.authenticate(
          localizedReason: "សូមស្កេន Face ID/Fingerprint ដើម្បីបញ្ជាក់អត្តសញ្ញាណស្កេនវត្តមាន",
          biometricOnly: false,
          persistAcrossBackgrounding: true,
        );

        if (!deviceAuthenticated) {
          _showError("ការផ្ទៀងផ្ទាត់ជីវមាត្រត្រូវបានបដិសេធ។");
          setState(() => _isLoading = false);
          return;
        }
      }

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
        biometricVerified: deviceAuthenticated,
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
          filter: ui.ImageFilter.blur(sigmaX: 10, sigmaY: 10),
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
            : const LatLng(11.5564, 104.9282),
        zoom: 16,
      ),
      onMapCreated: (controller) => _mapController = controller,
      markers: _markers,
      myLocationEnabled: true,
      myLocationButtonEnabled: true,
      zoomControlsEnabled: false,
      mapToolbarEnabled: false,
      mapType: _isMapSatellite ? MapType.satellite : MapType.normal,
    );
  }

  Widget _buildMapTypeToggle() {
    return Positioned(
      top: 12,
      right: 12,
      child: GestureDetector(
        onTap: () {
          setState(() => _isMapSatellite = !_isMapSatellite);
        },
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: Colors.black.withValues(alpha: 0.70),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                _isMapSatellite ? Icons.map_outlined : Icons.satellite_alt_outlined,
                color: Colors.white,
                size: 18,
              ),
              const SizedBox(width: 6),
              Text(
                _isMapSatellite ? 'Normal' : 'Satellite',
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 12,
                  fontFamily: 'KhmerFont',
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: Stack(
        children: [
          // Full-screen map
          Positioned.fill(child: _buildMapWidget()),

          // Map type toggle
          _buildMapTypeToggle(),

          // Top AppBar overlay
          Positioned(
            top: 0,
            left: 0,
            right: 0,
            child: SafeArea(
              child: Container(
                margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.70),
                  borderRadius: BorderRadius.circular(18),
                ),
                child: Row(
                  children: [
                    GestureDetector(
                      onTap: () => Navigator.maybePop(context),
                      child: const Icon(
                        Icons.arrow_back_ios_new,
                        color: Colors.white,
                        size: 20,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        "Check-In ខាងក្រៅ",
                        style: GoogleFonts.kantumruyPro(
                          fontWeight: FontWeight.bold,
                          color: Colors.white,
                          fontSize: 16,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    IconButton(
                      icon: const Icon(
                        Icons.refresh_rounded,
                        color: Colors.white,
                      ),
                      onPressed: _determinePosition,
                    ),
                  ],
                ),
              ),
            ),
          ),

          // Bottom controls overlay
          Positioned(
            left: 12,
            right: 12,
            bottom: 16,
            child: SafeArea(
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 18),
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.75),
                  borderRadius: BorderRadius.circular(24),
                ),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    // Camera Section
                    Center(
                      child: GestureDetector(
                        onTap: _captureImage,
                        child: Container(
                          height: 80,
                          width: 80,
                          margin: const EdgeInsets.only(bottom: 14),
                          decoration: BoxDecoration(
                            color: AppTheme.bgDark,
                            borderRadius: BorderRadius.circular(14),
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
                                    Icon(Icons.camera_alt_rounded, size: 28, color: AppTheme.primary),
                                    const SizedBox(height: 4),
                                    Text(
                                      "ថតរូបទីតាំង",
                                      style: GoogleFonts.kantumruyPro(
                                        color: AppTheme.primary,
                                        fontSize: 10,
                                        fontWeight: FontWeight.w600,
                                      ),
                                    ),
                                  ],
                                )
                              : Align(
                                  alignment: Alignment.bottomRight,
                                  child: Container(
                                    padding: const EdgeInsets.all(3),
                                    margin: const EdgeInsets.all(6),
                                    decoration: BoxDecoration(color: Colors.black54, borderRadius: BorderRadius.circular(6)),
                                    child: const Icon(Icons.edit, size: 14, color: Colors.white),
                                  ),
                                ),
                        ),
                      ),
                    ),

                    TextField(
                      controller: _locationController,
                      style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary),
                      decoration: InputDecoration(
                        hintText: "ឧទាហរណ៍: ការដ្ឋានបុរី ឬ ឈ្មោះអតិថិជន...",
                        hintStyle: GoogleFonts.kantumruyPro(color: AppTheme.textMuted),
                        filled: true,
                        fillColor: AppTheme.bgDark,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(14),
                          borderSide: BorderSide.none,
                        ),
                        prefixIcon: Icon(Icons.business_rounded, color: AppTheme.primary),
                      ),
                    ),
                    const SizedBox(height: 12),
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
                        const SizedBox(width: 12),
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
        padding: const EdgeInsets.symmetric(vertical: 14),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(14),
          side: BorderSide(color: color.withValues(alpha: 0.5), width: 1.5),
        ),
        elevation: 0,
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, size: 20),
          const SizedBox(width: 8),
          Text(
            label,
            style: GoogleFonts.inter(
              fontWeight: FontWeight.w800,
              fontSize: 15,
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
