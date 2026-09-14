import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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
import '../services/face_recognizer_service.dart';
import '../services/notification_service.dart';
import '../utils/app_theme.dart';
import '../utils/image_compress.dart';
import '../widgets/vvc_liquid_glass_scaffold.dart';

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
      const dstRect = Rect.fromLTWH(
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
      preferredCameraDevice: CameraDevice.front,
      imageQuality: 60,
      maxWidth: 800,
    );
    if (pickedFile != null) {
      try {
        final liveness = await FaceRecognizerService().checkImageLiveness(pickedFile.path);
        if (!liveness.isLive) {
          if (mounted) _showError(liveness.feedbackMessage ?? 'រូបថតមិនឆ្លងកាត់ការត្រួតពិនិត្យផ្ទៃមុខទេ សូមថតសារជាថ្មី');
          return;
        }
        setState(() {
          _capturedImage = pickedFile;
        });
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(liveness.feedbackMessage ?? 'បានផ្ទៀងផ្ទាត់ផ្ទៃមុខជោគជ័យ ✅'),
              backgroundColor: const Color(0xFF10B981),
              behavior: SnackBarBehavior.floating,
              duration: const Duration(seconds: 2),
            ),
          );
        }
      } catch (_) {
        setState(() {
          _capturedImage = pickedFile;
        });
      }
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
    if (!mounted) return;
    setState(() => _isLoading = true);
    try {
      bool serviceEnabled = await Geolocator.isLocationServiceEnabled();
      if (!serviceEnabled) {
        if (mounted) _showError('សេវាទីតាំង (GPS) ត្រូវបានបិទ។ សូមបើកវាសិន។');
        return;
      }

      LocationPermission permission = await Geolocator.checkPermission();
      if (permission == LocationPermission.denied) {
        permission = await Geolocator.requestPermission();
        if (permission == LocationPermission.denied) {
          if (mounted) _showError('ការអនុញ្ញាតចូលប្រើទីតាំងត្រូវបានបដិសេធ');
          return;
        }
      }

      if (permission == LocationPermission.deniedForever) {
        if (mounted) _showError('ការអនុញ្ញាតទីតាំងត្រូវបានបដិសេធជាអចិន្ត្រៃយ៍។');
        return;
      }

      Position position = await Geolocator.getCurrentPosition(
        locationSettings: const LocationSettings(
          accuracy: LocationAccuracy.high,
          timeLimit: Duration(seconds: 15),
        ),
      );

      if (position.isMocked) {
        if (mounted) _showError('⚠️ រកឃើញការក្លែងបន្លំទីតាំង (Fake GPS)! សូមបិទ Mock Location មុនពេលស្កេនវត្តមាន។');
        return;
      }

      if (!mounted) return;
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

      if (_mapController != null && mounted) {
        try {
          _mapController!.animateCamera(
            CameraUpdate.newLatLngZoom(
              LatLng(position.latitude, position.longitude),
              16.0,
            ),
          );
        } catch (e) {
          debugPrint('Map camera animation error: $e');
        }
      }

      if (mounted) {
        _loadProfileMarkerBitmap();
      }

      _apiService.reverseGeocode(position.latitude, position.longitude).then((res) {
        if (mounted && res['success'] == true && res['address'] != null) {
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
      if (mounted) _showError(e.toString());
    } finally {
      if (mounted) setState(() => _isLoading = false);
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
          options: const AuthenticationOptions(
            biometricOnly: false,
            stickyAuth: true,
          ),
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
    if (mounted) {
      _showResultPopup(message, Icons.error_outline_rounded, Colors.redAccent);
    }
  }

  void _showSuccess(String message) {
    if (mounted) {
      _showResultPopup(message, Icons.check_circle_outline_rounded, Colors.cyanAccent, isSuccess: true);
    }
  }

  void _showResultPopup(String message, IconData icon, Color color, {bool isSuccess = false}) {
    if (!mounted) return;
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
                    Navigator.pop(context); // Close dialog
                    if (isSuccess && Navigator.canPop(context)) {
                      Navigator.pop(context); // Close screen if successful and can pop
                    }
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

    try {
      return GoogleMap(
        initialCameraPosition: CameraPosition(
          target: _currentPosition != null
              ? LatLng(_currentPosition!.latitude, _currentPosition!.longitude)
              : const LatLng(11.5564, 104.9282),
          zoom: 16,
        ),
        onMapCreated: (controller) {
          if (mounted) {
            _mapController = controller;
          }
        },
        markers: _markers,
        myLocationEnabled: true,
        myLocationButtonEnabled: false,
        zoomControlsEnabled: false,
        mapToolbarEnabled: false,
        compassEnabled: false,
        mapType: _isMapSatellite ? MapType.satellite : MapType.normal,
      );
    } catch (e) {
      debugPrint('Google Map initialization error: $e');
      return Container(
        color: AppTheme.bgCard,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.map_outlined, size: 64, color: AppTheme.textMuted),
            const SizedBox(height: 16),
            Text(
              'មានបញ្ហាក្នុងការផ្ទុកផែនទី',
              style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.w600, color: AppTheme.textSecondary),
            ),
            const SizedBox(height: 8),
            Text(
              'សូមព្យាយាមម្តងទៀត',
              style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted),
            ),
          ],
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      backgroundColor: isDark ? const Color(0xFF0B0F19) : const Color(0xFFF8FAFC),
      body: Stack(
        children: [
          // 1. Full-screen Google Map
          Positioned.fill(child: _buildMapWidget()),

          // 2. Top Floating Liquid Glass Pods Header
          Positioned(
            top: MediaQuery.paddingOf(context).top + 6.0,
            left: 14.0,
            right: 14.0,
            child: VvcFloatingHeaderPods(
              height: 42.0,
              alwaysShowTitle: true,
              alwaysShowGlass: true,
              backgroundColor: isDark
                  ? const Color(0xFF131B2A).withValues(alpha: 0.92)
                  : Colors.white.withValues(alpha: 0.95),
              leading: IconButton(
                icon: const Icon(CupertinoIcons.chevron_back, size: 19),
                onPressed: () {
                  HapticFeedback.lightImpact();
                  Navigator.maybePop(context);
                },
              ),
              titleWidget: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 6.5,
                        height: 6.5,
                        margin: const EdgeInsets.only(right: 6),
                        decoration: BoxDecoration(
                          color: _currentPosition != null
                              ? const Color(0xFF10B981)
                              : const Color(0xFFF59E0B),
                          shape: BoxShape.circle,
                          boxShadow: [
                            BoxShadow(
                              color: (_currentPosition != null
                                      ? const Color(0xFF10B981)
                                      : const Color(0xFFF59E0B))
                                  .withValues(alpha: 0.50),
                              blurRadius: 4,
                            ),
                          ],
                        ),
                      ),
                      Text(
                        'Check-In ខាងក្រៅ',
                        style: GoogleFonts.kantumruyPro(
                          color: isDark ? Colors.white : const Color(0xFF0F172A),
                          fontWeight: FontWeight.bold,
                          fontSize: 13.5,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 1),
                  Text(
                    _currentPosition != null
                        ? 'GPS ភ្ជាប់ត្រឹមត្រូវ (High Accuracy)'
                        : 'កំពុងស្វែងរក GPS...',
                    style: GoogleFonts.kantumruyPro(
                      color: isDark
                          ? const Color(0xFF94A3B8)
                          : const Color(0xFF64748B),
                      fontSize: 10,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
              actions: [
                IconButton(
                  tooltip: _isMapSatellite ? 'ផែនទីធម្មតា' : 'ផែនទីផ្កាយរណប',
                  icon: Icon(
                    _isMapSatellite ? Icons.map_rounded : Icons.satellite_alt_rounded,
                    color: isDark
                        ? (_isMapSatellite ? const Color(0xFF38BDF8) : Colors.white)
                        : const Color(0xFF0F172A),
                    size: 19,
                  ),
                  onPressed: () {
                    HapticFeedback.lightImpact();
                    setState(() => _isMapSatellite = !_isMapSatellite);
                  },
                ),
                IconButton(
                  tooltip: 'ស្វែងរកទីតាំងឡើងវិញ',
                  icon: Icon(
                    Icons.refresh_rounded,
                    color: isDark ? Colors.white : const Color(0xFF0F172A),
                    size: 19,
                  ),
                  onPressed: () {
                    HapticFeedback.lightImpact();
                    _determinePosition();
                  },
                ),
              ],
            ),
          ),

          // 3. Recenter My Location FAB
          Positioned(
            right: 18,
            bottom: 215,
            child: _buildRecenterButton(isDark),
          ),

          // 4. Bottom Floating Liquid Glass Panel
          Positioned(
            left: 14,
            right: 14,
            bottom: 16,
            child: SafeArea(
              top: false,
              child: Container(
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(26),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: isDark ? 0.45 : 0.12),
                      blurRadius: 24,
                      offset: const Offset(0, 8),
                    ),
                  ],
                ),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(26),
                  child: BackdropFilter(
                    filter: ui.ImageFilter.blur(sigmaX: 20, sigmaY: 20),
                    child: Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: isDark
                            ? const Color(0xFF0F1523).withValues(alpha: 0.92)
                            : Colors.white.withValues(alpha: 0.95),
                        borderRadius: BorderRadius.circular(26),
                        border: Border.all(
                          color: isDark
                              ? const Color(0xFF2E384D)
                              : const Color(0xFFE2E8F0),
                          width: 1.0,
                        ),
                      ),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          // Top Row: Photo Preview/Capture + Location Info
                          Row(
                            crossAxisAlignment: CrossAxisAlignment.center,
                            children: [
                              _buildPhotoPickerTile(isDark),
                              const SizedBox(width: 12),
                              Expanded(
                                child: _buildLocationInputBox(isDark),
                              ),
                            ],
                          ),
                          const SizedBox(height: 14),
                          // Action Buttons: Check-In & Check-Out
                          Row(
                            children: [
                              Expanded(
                                child: _buildActionButton(
                                  label: "Check-In",
                                  khmerSub: "ចូលធ្វើការ",
                                  icon: Icons.login_rounded,
                                  gradient: const LinearGradient(
                                    colors: [Color(0xFF059669), Color(0xFF10B981)],
                                    begin: Alignment.topLeft,
                                    end: Alignment.bottomRight,
                                  ),
                                  shadowColor: const Color(0xFF10B981).withValues(alpha: 0.35),
                                  onTap: () => _submitAttendance("Check-In"),
                                ),
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: _buildActionButton(
                                  label: "Check-Out",
                                  khmerSub: "ចេញពីការងារ",
                                  icon: Icons.logout_rounded,
                                  gradient: const LinearGradient(
                                    colors: [Color(0xFFD97706), Color(0xFFF59E0B)],
                                    begin: Alignment.topLeft,
                                    end: Alignment.bottomRight,
                                  ),
                                  shadowColor: const Color(0xFFF59E0B).withValues(alpha: 0.35),
                                  onTap: () => _submitAttendance("Check-Out"),
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),

          // 5. Loading Overlay
          if (_isLoading)
            Positioned.fill(
              child: Container(
                color: Colors.black.withValues(alpha: 0.50),
                child: Center(
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 18),
                    decoration: BoxDecoration(
                      color: isDark ? const Color(0xFF131B2A) : Colors.white,
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(
                        color: isDark ? const Color(0xFF334155) : const Color(0xFFE2E8F0),
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.25),
                          blurRadius: 16,
                        ),
                      ],
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(
                            strokeWidth: 2.2,
                            color: Color(0xFF10B981),
                          ),
                        ),
                        const SizedBox(width: 14),
                        Text(
                          'កំពុងដំណើរការ...',
                          style: GoogleFonts.kantumruyPro(
                            color: isDark ? Colors.white : const Color(0xFF0F172A),
                            fontWeight: FontWeight.w600,
                            fontSize: 14,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildRecenterButton(bool isDark) {
    return FloatingActionButton.small(
      heroTag: 'recenter_gps_button',
      backgroundColor: isDark ? const Color(0xFF131B2A) : Colors.white,
      foregroundColor: isDark ? const Color(0xFFFCD34D) : const Color(0xFF0F172A),
      elevation: 4,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(
          color: isDark ? const Color(0xFF334155) : const Color(0xFFE2E8F0),
          width: 1.0,
        ),
      ),
      tooltip: 'តម្រង់ទៅទីតាំងខ្ញុំ',
      onPressed: () {
        if (_currentPosition != null && _mapController != null) {
          HapticFeedback.lightImpact();
          _mapController!.animateCamera(
            CameraUpdate.newLatLngZoom(
              LatLng(_currentPosition!.latitude, _currentPosition!.longitude),
              16.5,
            ),
          );
        } else {
          _determinePosition();
        }
      },
      child: const Icon(Icons.my_location_rounded, size: 20),
    );
  }

  Widget _buildPhotoPickerTile(bool isDark) {
    final hasPhoto = _capturedImage != null;
    return GestureDetector(
      onTap: () {
        HapticFeedback.lightImpact();
        _captureImage();
      },
      child: Container(
        width: 76,
        height: 76,
        decoration: BoxDecoration(
          color: isDark ? const Color(0xFF182032) : const Color(0xFFF8FAFC),
          borderRadius: BorderRadius.circular(18),
          border: Border.all(
            color: hasPhoto
                ? const Color(0xFF10B981)
                : (isDark ? const Color(0xFF334155) : const Color(0xFFE2E8F0)),
            width: hasPhoto ? 1.5 : 1.0,
          ),
          image: hasPhoto
              ? DecorationImage(
                  image: kIsWeb
                      ? NetworkImage(_capturedImage!.path) as ImageProvider
                      : FileImage(File(_capturedImage!.path)),
                  fit: BoxFit.cover,
                )
              : null,
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: isDark ? 0.20 : 0.04),
              blurRadius: 6,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: hasPhoto
            ? Align(
                alignment: Alignment.bottomRight,
                child: Container(
                  padding: const EdgeInsets.all(4),
                  margin: const EdgeInsets.all(4),
                  decoration: const BoxDecoration(
                    color: Color(0xFF10B981),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(Icons.check_rounded, size: 12, color: Colors.white),
                ),
              )
            : Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: isDark
                          ? const Color(0xFFF59E0B).withValues(alpha: 0.18)
                          : const Color(0xFFFFFBEB),
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      Icons.camera_alt_rounded,
                      size: 20,
                      color: isDark ? const Color(0xFFFCD34D) : const Color(0xFFD97706),
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    "ថតរូបទីតាំង",
                    style: GoogleFonts.kantumruyPro(
                      color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
                      fontSize: 10,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
      ),
    );
  }

  Widget _buildLocationInputBox(bool isDark) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: isDark ? const Color(0xFF182032) : const Color(0xFFF8FAFC),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: isDark ? const Color(0xFF2C354A) : const Color(0xFFE2E8F0),
          width: 1.0,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                Icons.location_on_rounded,
                size: 14,
                color: isDark ? const Color(0xFFFCD34D) : const Color(0xFFD97706),
              ),
              const SizedBox(width: 4),
              Text(
                'ទីតាំងបច្ចុប្បន្ន',
                style: GoogleFonts.kantumruyPro(
                  color: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
                  fontSize: 10.5,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const Spacer(),
              if (_currentPosition != null)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1.5),
                  decoration: BoxDecoration(
                    color: const Color(0xFF10B981).withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    'GPS ត្រឹមត្រូវ',
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFF10B981),
                      fontSize: 9,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 4),
          TextField(
            controller: _locationController,
            maxLines: 2,
            minLines: 1,
            style: GoogleFonts.kantumruyPro(
              color: isDark ? Colors.white : const Color(0xFF0F172A),
              fontSize: 12.5,
              fontWeight: FontWeight.w500,
            ),
            decoration: InputDecoration(
              filled: false,
              fillColor: Colors.transparent,
              isDense: true,
              contentPadding: EdgeInsets.zero,
              hintText: "ឧ. ឈ្មោះអតិថិជន ឬការដ្ឋាន...",
              hintStyle: GoogleFonts.kantumruyPro(
                color: isDark ? const Color(0xFF64748B) : const Color(0xFF94A3B8),
                fontSize: 12,
              ),
              border: InputBorder.none,
              enabledBorder: InputBorder.none,
              focusedBorder: InputBorder.none,
              disabledBorder: InputBorder.none,
              errorBorder: InputBorder.none,
              focusedErrorBorder: InputBorder.none,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildActionButton({
    required String label,
    required String khmerSub,
    required IconData icon,
    required Gradient gradient,
    required Color shadowColor,
    required VoidCallback onTap,
  }) {
    return Container(
      height: 52,
      decoration: BoxDecoration(
        gradient: gradient,
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: shadowColor,
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: () {
            HapticFeedback.mediumImpact();
            onTap();
          },
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 10),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(icon, size: 20, color: Colors.white),
                const SizedBox(width: 8),
                Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      label,
                      style: GoogleFonts.inter(
                        fontWeight: FontWeight.w800,
                        fontSize: 13.5,
                        color: Colors.white,
                        letterSpacing: 0.3,
                      ),
                    ),
                    Text(
                      khmerSub,
                      style: GoogleFonts.kantumruyPro(
                        fontWeight: FontWeight.w600,
                        fontSize: 9.5,
                        color: Colors.white.withValues(alpha: 0.85),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
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
