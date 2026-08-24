import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui';
import 'package:camera/camera.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:google_mlkit_face_detection/google_mlkit_face_detection.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:geolocator/geolocator.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:provider/provider.dart';
import 'package:animate_do/animate_do.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../services/face_recognizer_service.dart';
import '../services/notification_service.dart';
import '../utils/app_theme.dart';
import '../utils/image_compress.dart';
import 'face_setup_screen.dart';
import '../widgets/vvc_global_alert.dart';
import '../services/local_db_service.dart';

class AttendanceScreen extends StatefulWidget {
  /// If set, auto-submits with this action (skips dialog).
  final String? presetAction;
  const AttendanceScreen({super.key, this.presetAction});

  @override
  State<AttendanceScreen> createState() => _AttendanceScreenState();
}

class _AttendanceScreenState extends State<AttendanceScreen>
    with SingleTickerProviderStateMixin {
  late final MobileScannerController controller = MobileScannerController(
    formats: [BarcodeFormat.qrCode],
    detectionTimeoutMs: 1000,
    autoStart: false,
  );
  CameraController? _cameraController;
  FaceDetector? _faceDetector;
  final ApiService _apiService = ApiService();
  final FaceRecognizerService _faceRecognizer = FaceRecognizerService();

  bool _isScanning = false;
  bool _isLoading = false;
  bool _useQrScanner = false;
  bool _faceScanAttempted = false;
  bool _faceCaptured = false;
  bool _faceProcessing = false;
  bool _isFaceDetected = false;
  bool _isFaceRegistered = false; // true = user already completed face setup before
  int _consecutiveFaceFrames = 0;
  int _consecutiveErrorFrames = 0;
  Timer? _faceScanTimeout;
  DateTime _lastFaceProcessTime = DateTime.now();

  late AnimationController _laserController;
  late Animation<double> _laserAnimation;

  bool _isOfflineOrNetworkError(dynamic result, [Object? error]) {
    final str = '${result is Map ? result['message'] ?? '' : ''} ${error?.toString() ?? ''}'.toLowerCase();
    return str.contains('socket') ||
        str.contains('connection') ||
        str.contains('timed out') ||
        str.contains('timeout') ||
        str.contains('offline') ||
        str.contains('failed host lookup') ||
        str.contains('network') ||
        str.contains('handshake');
  }

  Future<void> _saveOfflinePunch({
    required String action,
    required String employeeId,
    required String workplace,
    required String branch,
    required String locationRaw,
    required String qrSecret,
    required int qrLocationId,
    String? lateReason,
  }) async {
    try {
      final punchData = {
        'action': action,
        'employee_id': employeeId,
        'workplace': workplace,
        'branch': branch,
        'location_raw': locationRaw,
        'qr_secret': qrSecret,
        'qr_location_id': qrLocationId,
        'late_reason': lateReason ?? '',
        'manual_distance': 0.0,
        'manual_location_name': workplace,
        'timestamp': DateTime.now().toIso8601String(),
        'synced': 0,
      };

      await LocalDbService().insertPunch(punchData);

      NotificationService().showNotification(
        id: DateTime.now().millisecondsSinceEpoch.remainder(100000),
        title: 'បានរក្សាទុក Offline',
        body: 'វត្តមាន $action ត្រូវបានរក្សាទុកក្នុងទូរស័ព្ទ!',
      );

      if (mounted) {
        _showSuccess(
          'បានរក្សាទុកវត្តមានក្នុងទូរស័ព្ទ (Offline) ដោយសារគ្មានអ៊ីនធឺណិត។\nប្រព័ន្ធនឹងផ្ញើទៅ Server ដោយស្វ័យប្រវត្តពេលមានអ៊ីនធឺណិតឡើងវិញ។',
          action: action,
        );
      }
    } catch (e) {
      debugPrint('Failed to save offline punch: $e');
      if (mounted) {
        _showError('មិនអាចរក្សាទុក Offline បានទេ៖ $e');
      }
    }
  }

  Future<void> _syncOfflinePunches() async {
    try {
      final unsynced = await LocalDbService().getUnsyncedPunches();
      if (unsynced.isEmpty) return;

      debugPrint('[OfflineSync] Found ${unsynced.length} pending offline punches');
      for (final p in unsynced) {
        final int id = p['id'] as int;
        final res = await _apiService.submitAttendance(
          action: p['action']?.toString() ?? 'Check-In',
          employeeId: p['employee_id']?.toString() ?? '',
          workplace: p['workplace']?.toString() ?? 'Offline',
          branch: p['branch']?.toString() ?? 'Offline',
          locationRaw: p['location_raw']?.toString() ?? '0.0,0.0',
          qrSecret: p['qr_secret']?.toString() ?? '',
          qrLocationId: (p['qr_location_id'] as num?)?.toInt() ?? 0,
          lateReason: p['late_reason']?.toString(),
        );
        if (res['success'] == true) {
          await LocalDbService().markAsSynced(id);
          debugPrint('[OfflineSync] Synced punch ID: $id successfully');
        }
      }
    } catch (e) {
      debugPrint('[OfflineSync] Sync failed (will retry next time): $e');
    }
  }

  /// Load whether this user has already registered their face
  Future<void> _loadFaceRegistrationStatus() async {
    // Biometrics are native to device, so we treat it as always registered
    _isFaceRegistered = true;
  }

  @override
  void initState() {
    super.initState();
    _laserController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1800),
    )..repeat(reverse: true);
    _laserAnimation = Tween<double>(begin: 0.05, end: 0.95).animate(
      CurvedAnimation(parent: _laserController, curve: Curves.easeInOut),
    );

    WidgetsBinding.instance.addPostFrameCallback((_) async {
      await _loadFaceRegistrationStatus();
      _tryFaceScanOrFallback();
      _syncOfflinePunches();
    });
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // NOTE: Do NOT re-trigger _tryFaceScanOrFallback here —
    // It is already called from initState's postFrameCallback.
    // Re-triggering it here causes the face scanner to re-initialise
    // on every rebuild, which creates the "always shows setup" bug.
  }

  @override
  void dispose() {
    _laserController.dispose();
    controller.dispose();
    _faceScanTimeout?.cancel();
    _cameraController?.dispose();
    _faceDetector?.close();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) async {
    final List<Barcode> barcodes = capture.barcodes;
    if (barcodes.isEmpty) return;

    final String? code = barcodes.first.rawValue;
    if (code == null) return;

    if (!_isScanning) return;
    _processQR(code);
  }

  Future<void> _tryFaceScanOrFallback() async {
    if (_faceScanAttempted || _useQrScanner || _isLoading) return;
    setState(() => _isLoading = true);

    final userProvider = Provider.of<UserProvider>(context, listen: false);
    if (!userProvider.faceScanEnabled) {
      if (!mounted) return;
      setState(() {
        _useQrScanner = true;
        _isScanning = true;
        _isLoading = false;
      });
      await Future.delayed(const Duration(milliseconds: 100));
      if (mounted) { try { await controller.start(); } catch (_) {} }
      return;
    }

    // Face scan enabled ប៉ុន្តែ face មិនទាន់ register → ណែនាំ Setup
    if (!_isFaceRegistered) {
      if (!mounted) return;
      setState(() { _isLoading = false; });
      final registered = await Navigator.push<bool>(
        context,
        MaterialPageRoute(
          builder: (_) => const FaceSetupScreen(isFirstTime: true),
          fullscreenDialog: true,
        ),
      );
      if (!mounted) return;
      if (registered == true) {
        _isFaceRegistered = true;
        // ចាប់ face scan ភ្លាមៗ ក្រោយ setup — ប្រើ postFrameCallback ដើម្បីជៀសវាង re-entrance
        _faceScanAttempted = false;
        // NOTE: Do NOT set _isLoading=true here! _tryFaceScanOrFallback() uses it as a guard.
        // Calling it directly after setting _isLoading=true causes permanent stuck loading.
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (mounted) _tryFaceScanOrFallback();
        });
      } else {
        // User បែកបង្ច setup → ប្តូរតូ QR
        setState(() {
          _useQrScanner = true;
          _isScanning = true;
          _isLoading = false;
        });
        await Future.delayed(const Duration(milliseconds: 100));
        if (mounted) { try { await controller.start(); } catch (_) {} }
      }
      return;
    }
    _faceScanAttempted = true;

    // បិទ QR Scanner មុនចាប់ Face camera ដើម្បីកុំអ្នកំរិកាមេរ៉ាផ្តើមួយតែមួយ
    try { await controller.stop(); } catch (_) {}

    try {
      // ត្រួតពិនិត្យ permission ដំបូង មុននឹងស្នើសុំ
      var cameraPermission = await Permission.camera.status;
      if (!mounted) return;

      if (cameraPermission.isPermanentlyDenied) {
        // អ្នកប្រើបដិសេធជានិច្ច — ត្រូវបង្ហាញ Dialog ឱ្យទៅបើក Settings
        await _showOpenSettingsDialog();
        if (!mounted) return;
        throw Exception('Camera permission permanently denied');
      }

      if (!cameraPermission.isGranted && !cameraPermission.isLimited) {
        // ស្នើសុំ permission (ករណីដំបូង ឬ denied)
        cameraPermission = await Permission.camera.request();
        if (!mounted) return;
      }

      if (cameraPermission.isPermanentlyDenied) {
        // អ្នកប្រើបដិសេធ ក្រោយការស្នើ
        await _showOpenSettingsDialog();
        if (!mounted) return;
        throw Exception('Camera permission permanently denied');
      }

      if (!cameraPermission.isGranted && !cameraPermission.isLimited) {
        throw Exception('Camera permission denied');
      }


      final cameras = await availableCameras();
      if (!mounted) return;
      if (cameras.isEmpty) {
        throw Exception('មិនមានកាមេរ៉ាណាមួយ');
      }

      CameraDescription? frontCamera;
      for (final camera in cameras) {
        if (camera.lensDirection == CameraLensDirection.front) {
          frontCamera = camera;
          break;
        }
      }
      if (frontCamera == null) {
        throw Exception('ទូរស័ព្ទនេះមិនមានកាមេរ៉ាមុខសម្រាប់ស្កេនមុខ');
      }

      _cameraController = CameraController(
        frontCamera,
        ResolutionPreset.medium,
        enableAudio: false,
        imageFormatGroup: Platform.isAndroid
            ? ImageFormatGroup.yuv420
            : ImageFormatGroup.bgra8888,
      );

      await _cameraController!.initialize();
      if (!mounted) return;

      _faceDetector = FaceDetector(
        options: FaceDetectorOptions(
          performanceMode: FaceDetectorMode.fast,
          enableLandmarks: false,
          enableClassification: false,
          enableContours: false,
          enableTracking: false,
        ),
      );

      await _cameraController!.startImageStream(_processCameraImage);
      if (!mounted) return;

      _faceScanTimeout?.cancel();
      _faceScanTimeout = Timer(const Duration(seconds: 10), () {
        if (!_faceCaptured && mounted) {
          _switchToQrScanner();
        }
      });

      setState(() {
        _useQrScanner = false;
        _isScanning = true;
        _isLoading = false;
      });
    } catch (e) {
      try {
        if (_cameraController != null &&
            _cameraController!.value.isStreamingImages) {
          await _cameraController!.stopImageStream();
        }
      } catch (_) {}
      try {
        await _cameraController?.dispose();
      } catch (_) {}
      _cameraController = null;

      try {
        await _faceDetector?.close();
      } catch (_) {}
      _faceDetector = null;

      if (!mounted) return;
      debugPrint('Face scan setup failed: $e');
      final errStr = e.toString().toLowerCase();
      if (userProvider.faceScanEnabled) {
        // ករណី permanentlyDenied — Dialog ត្រូវបានបង្ហាញរួចហើយ មិនចាំបាច់ SnackBar
        if (!errStr.contains('permanently denied')) {
          final errorMessage = errStr.contains('camera permission denied')
              ? 'ការអនុញ្ញាតកាមេរ៉ាត្រូវការ — សូម Restart កម្មវិធី ឬចូល Settings ហើយបើកការអនុញ្ញាត។'
              : 'មិនអាចចាប់ផ្តើមស្កេនមុខបាន។ កំពុងប្ដូរទៅ QR Code ជំនួស។';
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(errorMessage),
              duration: const Duration(seconds: 4),
            ),
          );
        }
      }
      setState(() {
        _useQrScanner = true;
        _isScanning = true;
        _isLoading = false;
      });
      // បើក QR Scanner ក្រោយឯកសារកែល Face Scan បានបរាជ័យ
      await Future.delayed(const Duration(milliseconds: 200));
      if (mounted) {
        try { await controller.start(); } catch (_) {}
      }
    }
  }

  Future<void> _switchToQrScanner() async {
    _faceScanTimeout?.cancel();
    _faceProcessing = false;
    _faceCaptured = false;
    _consecutiveFaceFrames = 0;
    _consecutiveErrorFrames = 0;

    // បិទ Face camera stream ដំបូងសិន
    try {
      if (_cameraController != null &&
          _cameraController!.value.isStreamingImages) {
        await _cameraController!.stopImageStream();
      }
    } catch (_) {}

    try {
      await _cameraController?.dispose();
    } catch (_) {}
    _cameraController = null;

    try {
      await _faceDetector?.close();
    } catch (_) {}
    _faceDetector = null;

    if (!mounted) return;
    setState(() {
      _useQrScanner = true;
      _isScanning = true;
      _isLoading = false;
      _isFaceDetected = false;
    });

    // បើក QR Scanner ក្រោយ Face camera ត្រូវបានទម្លាក់ចោលរួច
    await Future.delayed(const Duration(milliseconds: 200));
    if (mounted) {
      try {
        await controller.start();
      } catch (e) {
        debugPrint('QR Scanner start error: $e');
      }
    }
  }

  /// បង្ហាញ Dialog ណែនាំអ្នកប្រើប្រាស់ ទៅបើក Settings ពេល permission ត្រូវបានបដិសេធជានិច្ច
  Future<void> _showOpenSettingsDialog() async {
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 10, sigmaY: 10),
        child: AlertDialog(
          backgroundColor: const Color(0xFF1E293B).withValues(alpha: 0.95),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(24),
            side: BorderSide(color: Colors.orangeAccent.withValues(alpha: 0.4)),
          ),
          title: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.videocam_off_rounded, color: Colors.orangeAccent, size: 52),
              const SizedBox(height: 12),
              Text(
                'ការអនុញ្ញាតកាមេរ៉ាត្រូវការ',
                textAlign: TextAlign.center,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontWeight: FontWeight.bold,
                  fontSize: 17,
                ),
              ),
            ],
          ),
          content: Text(
            'កម្មវិធីនេះត្រូវការការអនុញ្ញាតកាមេរ៉ា ដើម្បីស្កេនមុខ។\n\nសូមទៅកាន់ Settings → ${Platform.isIOS ? "Privacy & Security → Camera" : "Apps → VVC HRM → Permissions → Camera"} ហើយបើកការអនុញ្ញាតឱ្យ Allow.',
            textAlign: TextAlign.center,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textPrimary.withValues(alpha: 0.8),
              fontSize: 13,
              height: 1.6,
            ),
          ),
          actionsAlignment: MainAxisAlignment.center,
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: Text(
                'ប្រើ QR Code ជំនួស',
                style: GoogleFonts.kantumruyPro(color: Colors.white54),
              ),
            ),
            ElevatedButton.icon(
              onPressed: () async {
                Navigator.pop(ctx);
                await openAppSettings();
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.orangeAccent.withValues(alpha: 0.2),
                foregroundColor: Colors.orangeAccent,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
              ),
              icon: const Icon(Icons.settings_rounded, size: 16),
              label: Text(
                'បើក Settings',
                style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _switchToFaceScanner() async {
    if (!mounted) return;

    // បិទ QR Scanner ដំបូងសិន មុនចាប់ Face camera
    try {
      await controller.stop();
    } catch (e) {
      debugPrint('QR Scanner stop error: $e');
    }

    setState(() {
      _faceScanAttempted = false;
      _useQrScanner = false;
      _isLoading = false;
      _isScanning = false;
      _isFaceDetected = false;
    });
    await _tryFaceScanOrFallback();
  }


  void _processCameraImage(CameraImage image) async {
    final now = DateTime.now();
    // Throttle to 120ms to eliminate CPU lag and battery drain
    if (now.difference(_lastFaceProcessTime).inMilliseconds < 120) {
      return;
    }
    if (_faceProcessing ||
        _faceCaptured ||
        _useQrScanner ||
        _cameraController == null ||
        !mounted) {
      return;
    }
    _faceProcessing = true;
    _lastFaceProcessTime = now;

    try {
      final inputImage = _convertCameraImage(
        image,
        _cameraController!.description.sensorOrientation,
      );
      if (inputImage == null) return;
      final faces = await _faceDetector?.processImage(inputImage) ?? [];
      _consecutiveErrorFrames = 0;

      final bool detected = faces.isNotEmpty;
      if (detected != _isFaceDetected && mounted) {
        setState(() => _isFaceDetected = detected);
      }

      if (faces.isNotEmpty) {
        _consecutiveFaceFrames += 1;
      } else {
        _consecutiveFaceFrames = 0;
      }

      if (_consecutiveFaceFrames >= 2 && !_faceCaptured) {
        _faceCaptured = true;
        _faceScanTimeout?.cancel();
        await _submitFaceAttendance();
      }
    } catch (e) {
      debugPrint('Face frame detection error: $e');
      _consecutiveErrorFrames += 1;
      if (_consecutiveErrorFrames >= 5) {
        _faceScanTimeout?.cancel();
        if (mounted) {
          await _switchToQrScanner();
          if (!mounted) return;
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('មិនអាចស្កេនផ្ទៃមុខបានទេ។ កំពុងប្ដូរទៅ QR Code ជំនួស។'),
              duration: Duration(seconds: 3),
            ),
          );
        }
      }
    } finally {
      _faceProcessing = false;
    }
  }

  Widget _buildFaceScannerPreview() {
    if (_cameraController == null || !_cameraController!.value.isInitialized) {
      return Container(
        color: const Color(0xFF0A0F1D),
        child: const Center(
          child: CircularProgressIndicator(color: Color(0xFF00E5FF)),
        ),
      );
    }

    final size = MediaQuery.of(context).size;
    final double reticleWidth = (size.width * 0.72).clamp(240.0, 300.0);
    final double reticleHeight = reticleWidth * 1.32;
    final double topOffset = (size.height * 0.20).clamp(110.0, 190.0);
    final double leftOffset = (size.width - reticleWidth) / 2;
    final Rect cutoutRect = Rect.fromLTWH(leftOffset, topOffset, reticleWidth, reticleHeight);

    final activeColor = _isFaceDetected ? const Color(0xFF10B981) : const Color(0xFF00E5FF);

    return Stack(
      fit: StackFit.expand,
      children: [
        // 1. Full-bleed Camera Preview (No distortion, fills screen smoothly)
        SizedBox.expand(
          child: FittedBox(
            fit: BoxFit.cover,
            child: SizedBox(
              width: _cameraController!.value.previewSize?.height ?? size.width,
              height: _cameraController!.value.previewSize?.width ?? size.height,
              child: CameraPreview(_cameraController!),
            ),
          ),
        ),

        // 2. Custom Mask & Biometric Viewfinder Painter
        CustomPaint(
          size: size,
          painter: FaceScannerOverlayPainter(
            cutoutRect: cutoutRect,
            borderRadius: 36.0,
            borderColor: activeColor,
            isFaceDetected: _isFaceDetected,
          ),
        ),

        // 3. Subtle Center Watermark Icon inside cutout
        Positioned(
          left: cutoutRect.left,
          top: cutoutRect.top,
          width: cutoutRect.width,
          height: cutoutRect.height,
          child: Center(
            child: Icon(
              Icons.face_unlock_rounded,
              color: Colors.white.withValues(alpha: _isFaceDetected ? 0.08 : 0.16),
              size: 90,
            ),
          ),
        ),

        // 4. Animated Laser Beam with Soft Glow
        AnimatedBuilder(
          animation: _laserAnimation,
          builder: (context, child) {
            return Positioned(
              top: cutoutRect.top + 12 + _laserAnimation.value * (cutoutRect.height - 24),
              left: cutoutRect.left + 16,
              width: cutoutRect.width - 32,
              child: Container(
                height: 3,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(2),
                  gradient: LinearGradient(
                    colors: [
                      Colors.transparent,
                      activeColor,
                      Colors.white,
                      activeColor,
                      Colors.transparent,
                    ],
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: activeColor.withValues(alpha: 0.8),
                      blurRadius: 14,
                      spreadRadius: 2,
                    ),
                  ],
                ),
              ),
            );
          },
        ),

        // 5. High-Tech Glassmorphic Guidance Card (Positioned Cleanly Below Reticle)
        Positioned(
          top: cutoutRect.bottom + 22,
          left: 24,
          right: 24,
          child: Center(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(24),
              child: BackdropFilter(
                filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 300),
                  padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
                  decoration: BoxDecoration(
                    color: Colors.black.withValues(alpha: 0.45),
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(
                      color: activeColor.withValues(alpha: _isFaceDetected ? 0.5 : 0.2),
                      width: 1.2,
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: activeColor.withValues(alpha: _isFaceDetected ? 0.15 : 0.05),
                        blurRadius: 16,
                      ),
                    ],
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            _isFaceDetected
                                ? Icons.check_circle_rounded
                                : Icons.face_retouching_natural_rounded,
                            color: activeColor,
                            size: 20,
                          ),
                          const SizedBox(width: 8),
                          Text(
                            _isFaceDetected
                                ? 'រកឃើញផ្ទៃមុខហើយ កំពុងផ្ទៀងផ្ទាត់...'
                                : 'សូមដាក់ផ្ទៃមុខឱ្យចំកណ្តាលក្របខ័ណ្ឌ',
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 14,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'សូមរក្សាផ្ទៃមុខឱ្យត្រង់ និងស្ថិតក្នុងពន្លឺគ្រប់គ្រាន់',
                        textAlign: TextAlign.center,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white.withValues(alpha: 0.65),
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  InputImage? _convertCameraImage(CameraImage image, int rotation) {
    try {
      final imageRotation =
          InputImageRotationValue.fromRawValue(rotation) ??
          InputImageRotation.rotation0deg;

      if (Platform.isIOS) {
        return InputImage.fromBytes(
          bytes: image.planes.first.bytes,
          metadata: InputImageMetadata(
            size: Size(image.width.toDouble(), image.height.toDouble()),
            rotation: imageRotation,
            format: InputImageFormat.bgra8888,
            bytesPerRow: image.planes.first.bytesPerRow,
          ),
        );
      } else {
        final WriteBuffer allBytes = WriteBuffer();
        for (final Plane plane in image.planes) {
          allBytes.putUint8List(plane.bytes);
        }
        final bytes = allBytes.done().buffer.asUint8List();
        final fmt = InputImageFormatValue.fromRawValue(image.format.raw) ??
            InputImageFormat.nv21;

        return InputImage.fromBytes(
          bytes: bytes,
          metadata: InputImageMetadata(
            size: Size(image.width.toDouble(), image.height.toDouble()),
            rotation: imageRotation,
            format: fmt,
            bytesPerRow: image.planes.first.bytesPerRow,
          ),
        );
      }
    } catch (e) {
      return null;
    }
  }

  Future<void> _submitFaceAttendance() async {
    if (!mounted) return;

    setState(() {
      _isScanning = false;
      _isLoading = true;
    });

    try {
      if (_cameraController != null &&
          _cameraController!.value.isStreamingImages) {
        await _cameraController!.stopImageStream();
        await Future.delayed(const Duration(milliseconds: 300));
      }

      final XFile photo = await _cameraController!.takePicture();
      final String photoBase64 = await compressAndEncodeImage(await photo.readAsBytes());

      // === AI FACE VERIFICATION (On-Device FaceNet) ===
      if (!mounted) return;
      final userProvider = Provider.of<UserProvider>(context, listen: false);
      final userId = userProvider.employeeId ?? '';

      bool faceVerified = false;
      String? faceError;

      if (userId.isNotEmpty) {
        // Check if user has registered face locally
        final isRegistered = await _faceRecognizer.isFaceRegistered(userId);
        if (isRegistered) {
          // Compare live face vs registered face
          final result = await _faceRecognizer.verifyFace(
            imagePath: photo.path,
            userId: userId,
            threshold: 0.65,
          );
          faceVerified = result.matched;
          faceError = result.error;
          debugPrint('[FaceAttendance] AI verify: ${result.matched} | ${result.error}');
        } else {
          faceVerified = false;
          faceError = 'អ្នកមិនទាន់បានចុះឈ្មោះផ្ទៃមុខទេ។ សូមចូលទៅកាន់ការកំណត់ដើម្បីចុះឈ្មោះជាមុនសិន።';
        }
      } else {
        faceVerified = true; // No user ID — skip
      }

      if (!faceVerified) {
        if (mounted) {
          _showError(
            'ការផ្ទៀងផ្ទាត់ផ្ទៃមុខមិនជោគជ័យ\n\n${faceError ?? "សូមព្យាយាមស្កេនម្ដងទៀត"}',
          );
          await _switchToQrScanner();
        }
        return;
      }

      Position position = await _determinePosition();
      String locationRaw = '${position.latitude},${position.longitude}';

      String? action = widget.presetAction;
      if (action == null) {
        final lastActionData = await _apiService.fetchLastAction();
        String suggestion = 'Check-In';
        if (lastActionData['success'] == true) {
          String last = lastActionData['last_action'] ?? 'Check-Out';
          suggestion = (last == 'Check-In') ? 'Check-Out' : 'Check-In';
        }
        action = suggestion; // Automatically check-in or check-out
      }

      if (!mounted) return;

      final String resolvedAction = action;

      Future<void> submit(String? reason) async {
        final result = await _apiService.submitAttendance(
          action: resolvedAction,
          employeeId: userProvider.employeeId!,
          workplace: 'Face Scan',
          branch: 'Face Scan',
          locationRaw: locationRaw,
          qrSecret: 'outside_scan',
          qrLocationId: 0,
          lateReason: reason,
          photoBase64: photoBase64,
          biometricVerified: true,
        );

        if (result['success'] == true) {
          NotificationService().showNotification(
            id: DateTime.now().millisecondsSinceEpoch.remainder(100000),
            title: 'ជោគជ័យ',
            body: 'អ្នកបាន $resolvedAction ដោយជោគជ័យ!',
          );
          _showSuccess(result['message'], action: resolvedAction);
        } else if (result['require_late_reason'] == true) {
          if (!mounted) return;
          setState(() => _isLoading = false);
          String? inputReason = await _showLateReasonDialog(result['message']);
          if (inputReason != null && inputReason.trim().isNotEmpty) {
            setState(() => _isLoading = true);
            await submit(inputReason.trim());
          } else {
            await _switchToQrScanner();
          }
        } else if (_isOfflineOrNetworkError(result)) {
          await _saveOfflinePunch(
            action: resolvedAction,
            employeeId: userProvider.employeeId!,
            workplace: 'Face Scan',
            branch: 'Face Scan',
            locationRaw: locationRaw,
            qrSecret: 'outside_scan',
            qrLocationId: 0,
            lateReason: reason,
          );
        } else {
          _showError(result['message'] ?? 'បរាជ័យ');
        }
      }

      await submit(null);
    } catch (e) {
      if (mounted) {
        if (_isOfflineOrNetworkError(null, e)) {
          final userProvider =
              Provider.of<UserProvider>(context, listen: false);
          await _saveOfflinePunch(
            action: widget.presetAction ?? 'Check-In',
            employeeId: userProvider.employeeId ?? '',
            workplace: 'Face Scan',
            branch: 'Face Scan',
            locationRaw: '0.0,0.0',
            qrSecret: 'outside_scan',
            qrLocationId: 0,
          );
        } else {
          _showError('កំហុស៖ $e');
          await _switchToQrScanner();
        }
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  void _processQR(String code) async {
    setState(() {
      _isScanning = false;
      _isLoading = true;
    });

    try {
      // 0. Clean the raw code
      final rawCode = code.trim();

      // 1. Get GPS Location
      Position position = await _determinePosition();
      String locationRaw = "${position.latitude},${position.longitude}";

      // 2. Parse QR Code
      int locationId = 0;
      String secret = "";

      try {
        final decoded = jsonDecode(rawCode);
        if (decoded is Map<String, dynamic>) {
          // Robust parsing of location_id (handle both String "13" and int 13)
          final locIdRaw = decoded['location_id'];
          if (locIdRaw is String) {
            locationId = int.tryParse(locIdRaw) ?? 0;
          } else if (locIdRaw is num) {
            locationId = locIdRaw.toInt();
          }

          secret = decoded['secret']?.toString() ?? "";
        }
      } catch (_) {
        // Fallback for plain text format: "id|secret"
        List<String> parts = rawCode.split('|');
        if (parts.length >= 2) {
          locationId = int.tryParse(parts[0]) ?? 0;
          secret = parts[1];
        } else {
          debugPrint("Raw QR Code failed parsing: $rawCode");
        }
      }

      if (locationId == 0 || secret.isEmpty) {
        _showError(
          "QR Code មិនត្រឹមត្រូវ\n(Data: ${rawCode.length > 20 ? "${rawCode.substring(0, 20)}..." : rawCode})",
        );
        return;
      }

      // 3. Action Dialog (Automatic Detection)
      String? action;
      if (widget.presetAction != null) {
        // Auto-submit with preset action — no dialog needed
        action = widget.presetAction;
      } else {
        final lastActionData = await _apiService.fetchLastAction();
        String suggestion = "Check-In";
        if (lastActionData['success'] == true) {
          String last = lastActionData['last_action'] ?? "Check-Out";
          suggestion = (last == "Check-In") ? "Check-Out" : "Check-In";
        }
        action = await _showActionDialog(suggested: suggestion);
      }
      if (action == null) {
        if (!mounted) return;
        setState(() {
          _isScanning = true;
          _isLoading = false;
        });
        return;
      }

      if (!mounted) return;

      final String resolvedAction = action;

      // 4. Submit Flow
      final userProvider = Provider.of<UserProvider>(context, listen: false);

      Future<void> submit(String? reason) async {
        final result = await _apiService.submitAttendance(
          action: resolvedAction,
          employeeId: userProvider.employeeId!,
          workplace: "N/A",
          branch: "N/A",
          locationRaw: locationRaw,
          qrSecret: secret,
          qrLocationId: locationId,
          lateReason: reason,
        );

        if (result['success'] == true) {
          NotificationService().showNotification(
            id: DateTime.now().millisecondsSinceEpoch.remainder(100000),
            title: "ជោគជ័យ",
            body: "អ្នកបាន $resolvedAction ដោយជោគជ័យ!",
          );
          _showSuccess(result['message'], action: resolvedAction);
        } else if (result['require_late_reason'] == true) {
          if (!mounted) return;
          setState(() => _isLoading = false);
          String? inputReason = await _showLateReasonDialog(result['message']);
          if (inputReason != null && inputReason.trim().isNotEmpty) {
            setState(() => _isLoading = true);
            await submit(inputReason.trim());
          } else {
            if (mounted) setState(() => _isScanning = true);
          }
        } else if (_isOfflineOrNetworkError(result)) {
          await _saveOfflinePunch(
            action: resolvedAction,
            employeeId: userProvider.employeeId!,
            workplace: "N/A",
            branch: "N/A",
            locationRaw: locationRaw,
            qrSecret: secret,
            qrLocationId: locationId,
            lateReason: reason,
          );
        } else {
          _showError(result['message'] ?? 'បរាជ័យ');
        }
      }

      await submit(null);
    } catch (e) {
      if (_isOfflineOrNetworkError(null, e)) {
        if (mounted) {
          final userProvider =
              Provider.of<UserProvider>(context, listen: false);
          await _saveOfflinePunch(
            action: widget.presetAction ?? 'Check-In',
            employeeId: userProvider.employeeId ?? '',
            workplace: "N/A",
            branch: "N/A",
            locationRaw: '0.0,0.0',
            qrSecret: '',
            qrLocationId: 0,
          );
        }
      } else {
        _showError("កំហុស៖ $e");
      }
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  Future<Position> _determinePosition() async {
    bool serviceEnabled = await Geolocator.isLocationServiceEnabled();
    if (!serviceEnabled) {
      return Future.error('សេវាទីតាំង (GPS) ត្រូវបានបិទ។ សូមបើកវាសិន។');
    }

    LocationPermission permission = await Geolocator.checkPermission();
    if (permission == LocationPermission.denied) {
      permission = await Geolocator.requestPermission();
      if (permission == LocationPermission.denied) {
        return Future.error('ការអនុញ្ញាតចូលប្រើទីតាំងត្រូវបានបដិសេធ');
      }
    }

    if (permission == LocationPermission.deniedForever) {
      return Future.error('ការអនុញ្ញាតទីតាំងត្រូវបានបដិសេធជាអចិន្ត្រៃយ៍។');
    }

    try {
      return await Geolocator.getCurrentPosition(
        locationSettings: const LocationSettings(
          accuracy: LocationAccuracy.high,
          timeLimit: Duration(seconds: 10),
        ),
      );
    } catch (e) {
      Position? lastPosition = await Geolocator.getLastKnownPosition();
      if (lastPosition != null) return lastPosition;
      return Future.error('មិនអាចទាញយកទីតាំងបានទេ');
    }
  }

  Future<String?> _showActionDialog({String suggested = "Check-In"}) async {
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) => BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 10, sigmaY: 10),
        child: FadeInScale(
          child: AlertDialog(
            backgroundColor: const Color(0xFF1E293B).withValues(alpha: 0.9),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(24),
              side: BorderSide(
                color: AppTheme.textPrimary.withValues(alpha: 0.1),
              ),
            ),
            title: Text(
              "ជ្រើសរើសសកម្មភាព",
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
              ),
            ),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  "តើអ្នកចង់ Check-In ឬ Check-Out?",
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary.withValues(alpha: 0.70),
                  ),
                ),
                const SizedBox(height: 10),
                Text(
                  "សំណើបន្ទាប់៖ $suggested",
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.cyanAccent.withValues(alpha: 0.8),
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
            actionsAlignment: MainAxisAlignment.center,
            actions: [
              _buildDialogButton(
                "Check-In",
                Colors.cyanAccent,
                () => Navigator.pop(context, "Check-In"),
                isSuggested: suggested == "Check-In",
              ),
              _buildDialogButton(
                "Check-Out",
                Colors.orangeAccent,
                () => Navigator.pop(context, "Check-Out"),
                isSuggested: suggested == "Check-Out",
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<String?> _showLateReasonDialog(String message) async {
    TextEditingController reasonController = TextEditingController();
    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (context) => BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 10, sigmaY: 10),
        child: FadeInScale(
          child: AlertDialog(
            backgroundColor: const Color(0xFF1E293B).withValues(alpha: 0.9),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(24),
              side: BorderSide(
                color: Colors.orangeAccent.withValues(alpha: 0.3),
              ),
            ),
            title: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(
                  Icons.access_time_rounded,
                  color: Colors.orangeAccent,
                  size: 48,
                ),
                const SizedBox(height: 12),
                Text(
                  "ស្កេនចូលយឺត",
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  message,
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary.withValues(alpha: 0.8),
                    fontSize: 14,
                  ),
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: reasonController,
                  maxLines: 3,
                  style: GoogleFonts.kantumruyPro(color: Colors.white),
                  decoration: InputDecoration(
                    hintText: "សូមសរសេរមូលហេតុនៅទីនេះ...",
                    hintStyle: GoogleFonts.kantumruyPro(color: Colors.white38),
                    filled: true,
                    fillColor: Colors.black12,
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(color: Colors.white24),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(color: Colors.orangeAccent),
                    ),
                  ),
                ),
              ],
            ),
            actionsAlignment: MainAxisAlignment.center,
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, null),
                child: Text(
                  "បោះបង់",
                  style: GoogleFonts.kantumruyPro(color: Colors.white54),
                ),
              ),
              ElevatedButton(
                onPressed: () {
                  final reason = reasonController.text.trim();
                  if (reason.isEmpty) return; // Prevent empty submit
                  Navigator.pop(context, reason);
                },
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.orangeAccent.withValues(alpha: 0.2),
                  foregroundColor: Colors.orangeAccent,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                child: Text(
                  "បញ្ជូន",
                  style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDialogButton(
    String label,
    Color color,
    VoidCallback onTap, {
    bool isSuggested = false,
  }) {
    return TextButton(
      onPressed: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
        decoration: BoxDecoration(
          color: isSuggested
              ? color.withValues(alpha: 0.2)
              : color.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: color.withValues(alpha: isSuggested ? 0.8 : 0.2),
            width: isSuggested ? 2 : 1,
          ),
          boxShadow: isSuggested
              ? [
                  BoxShadow(
                    color: color.withValues(alpha: 0.2),
                    blurRadius: 10,
                    spreadRadius: 1,
                  ),
                ]
              : null,
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (isSuggested) ...[
              Icon(Icons.star_rounded, color: color, size: 16),
              const SizedBox(width: 4),
            ],
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: color,
                fontWeight: isSuggested ? FontWeight.w900 : FontWeight.bold,
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showError(String message) {
    _showResultPopup(
      message,
      Icons.error_outline_rounded,
      Colors.redAccent,
      isError: true,
    );
  }

  void _showSuccess(String message, {String? action}) {
    String? result;
    if (action != null) {
      if (action == 'Check-In') {
        result = 'checked_in';
      } else if (action == 'Check-Out') {
        result = 'checked_out';
      }
    }
    _showResultPopup(
      message,
      Icons.check_circle_outline_rounded,
      Colors.cyanAccent,
      result: result,
    );
  }

  void _showResultPopup(
    String message,
    IconData icon,
    Color color, {
    bool isError = false,
    String? result,
  }) {
    VvcAlert.showAlertDialog(
      context,
      title: isError ? 'ការផ្ទៀងផ្ទាត់ផ្ទៃមុខមិនជោគជ័យ' : 'ស្កេនវត្តមានជោគជ័យ',
      message: message,
      type: isError ? VvcAlertType.error : VvcAlertType.success,
      buttonText: 'យល់ព្រម',
      onPressed: () {
        if (!isError && result != null && Navigator.canPop(context)) {
          Navigator.pop(context, result);
        } else {
          setState(() => _isScanning = true);
        }
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final bool faceScanEnabled = Provider.of<UserProvider>(context).faceScanEnabled;
    return Scaffold(
      backgroundColor: const Color(0xFF0A0F1D),
      body: Stack(
        children: [
          // 1. Background Scanner (QR or Face)
          if (_isScanning)
            _useQrScanner
                ? MobileScanner(
                    controller: controller,
                    onDetect: _onDetect,
                    errorBuilder: (context, error) {
                      return Center(
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.videocam_off_rounded,
                              color: AppTheme.textPrimary.withValues(alpha: 0.24),
                              size: 80,
                            ),
                            const SizedBox(height: 20),
                            Text(
                              "កំហុសកាមេរ៉ា៖ ${error.errorCode}",
                              style: GoogleFonts.kantumruyPro(
                                color: AppTheme.textPrimary,
                              ),
                            ),
                          ],
                        ),
                      );
                    },
                  )
                : _buildFaceScannerPreview(),

          // 2. QR Scanner Overlay (When in QR mode only)
          if (_isScanning && _useQrScanner)
            Container(
              decoration: ShapeDecoration(
                shape: QrScannerOverlayShape(
                  borderColor: Colors.cyanAccent.withValues(alpha: 0.8),
                  borderRadius: 24,
                  borderLength: 40,
                  borderWidth: 4,
                  cutOutSide: 280,
                  overlayColor: Colors.black.withValues(alpha: 0.6),
                ),
              ),
            ),

          // 3. Unified Top Navigation Bar (Single Layer, Zero Overlap!)
          SafeArea(
            child: Align(
              alignment: Alignment.topCenter,
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                child: FadeInDown(
                  duration: const Duration(milliseconds: 500),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      // Back Button
                      ClipOval(
                        child: BackdropFilter(
                          filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
                          child: Container(
                            width: 42,
                            height: 42,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: Colors.black.withValues(alpha: 0.35),
                              border: Border.all(
                                color: Colors.white.withValues(alpha: 0.15),
                              ),
                            ),
                            child: IconButton(
                              icon: const Icon(
                                Icons.arrow_back_ios_new_rounded,
                                color: Colors.white,
                                size: 18,
                              ),
                              onPressed: () => Navigator.pop(context),
                              tooltip: "ត្រឡប់ក្រោយ",
                            ),
                          ),
                        ),
                      ),

                      // Mode Badge Pill
                      ClipRRect(
                        borderRadius: BorderRadius.circular(30),
                        child: BackdropFilter(
                          filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 18,
                              vertical: 9,
                            ),
                            decoration: BoxDecoration(
                              color: Colors.black.withValues(alpha: 0.4),
                              borderRadius: BorderRadius.circular(30),
                              border: Border.all(
                                color: (_useQrScanner
                                        ? Colors.cyanAccent
                                        : const Color(0xFF10B981))
                                    .withValues(alpha: 0.35),
                              ),
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Container(
                                  width: 8,
                                  height: 8,
                                  decoration: BoxDecoration(
                                    shape: BoxShape.circle,
                                    color: _useQrScanner
                                        ? Colors.cyanAccent
                                        : const Color(0xFF10B981),
                                    boxShadow: [
                                      BoxShadow(
                                        color: (_useQrScanner
                                                ? Colors.cyanAccent
                                                : const Color(0xFF10B981))
                                            .withValues(alpha: 0.7),
                                        blurRadius: 8,
                                        spreadRadius: 1,
                                      ),
                                    ],
                                  ),
                                ),
                                const SizedBox(width: 8),
                                Text(
                                  _useQrScanner
                                      ? "QR CODE SCANNER"
                                      : "AI FACE SCAN",
                                  style: GoogleFonts.inter(
                                    color: Colors.white,
                                    fontWeight: FontWeight.w800,
                                    letterSpacing: 1.2,
                                    fontSize: 12,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ),

                      // Quick Switch Icon Button
                      ClipOval(
                        child: BackdropFilter(
                          filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
                          child: Container(
                            width: 42,
                            height: 42,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: Colors.black.withValues(alpha: 0.35),
                              border: Border.all(
                                color: Colors.white.withValues(alpha: 0.15),
                              ),
                            ),
                            child: IconButton(
                              icon: Icon(
                                _useQrScanner
                                    ? Icons.face_rounded
                                    : Icons.qr_code_2_rounded,
                                color: Colors.white,
                                size: 20,
                              ),
                              onPressed: () {
                                if (_useQrScanner) {
                                  _switchToFaceScanner();
                                } else {
                                  _switchToQrScanner();
                                }
                              },
                              tooltip: _useQrScanner
                                  ? "ប្ដូរទៅ Face Scan"
                                  : "ប្ដូរទៅ QR Code",
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),

          // 4. Modern Bottom Mode Switcher Dock
          if (_isScanning && !_isLoading)
            SafeArea(
              child: Align(
                alignment: Alignment.bottomCenter,
                child: Padding(
                  padding: const EdgeInsets.only(bottom: 28, left: 24, right: 24),
                  child: FadeInUp(
                    duration: const Duration(milliseconds: 600),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(28),
                      child: BackdropFilter(
                        filter: ImageFilter.blur(sigmaX: 14, sigmaY: 14),
                        child: Material(
                          color: Colors.transparent,
                          child: (_useQrScanner && !faceScanEnabled)
                              ? Container(
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 20,
                                    vertical: 12,
                                  ),
                                  decoration: BoxDecoration(
                                    color: Colors.black.withValues(alpha: 0.5),
                                    borderRadius: BorderRadius.circular(28),
                                    border: Border.all(
                                      color: Colors.white.withValues(alpha: 0.15),
                                    ),
                                  ),
                                  child: Row(
                                    mainAxisSize: MainAxisSize.min,
                                    children: [
                                      const Icon(
                                        Icons.qr_code_2_rounded,
                                        color: Colors.cyanAccent,
                                        size: 18,
                                      ),
                                      const SizedBox(width: 8),
                                      Text(
                                        'គណនីនេះកំណត់ប្រើប្រាស់ QR Code',
                                        style: GoogleFonts.kantumruyPro(
                                          color: Colors.white70,
                                          fontSize: 13,
                                        ),
                                      ),
                                    ],
                                  ),
                                )
                              : InkWell(
                                  onTap: () {
                                    if (_useQrScanner) {
                                      _switchToFaceScanner();
                                    } else {
                                      _switchToQrScanner();
                                    }
                                  },
                                  borderRadius: BorderRadius.circular(28),
                                  child: Container(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 24,
                                      vertical: 14,
                                    ),
                                    decoration: BoxDecoration(
                                      color: Colors.black.withValues(alpha: 0.5),
                                      borderRadius: BorderRadius.circular(28),
                                      border: Border.all(
                                        color: Colors.white.withValues(alpha: 0.18),
                                      ),
                                      boxShadow: [
                                        BoxShadow(
                                          color: Colors.black.withValues(alpha: 0.3),
                                          blurRadius: 20,
                                          offset: const Offset(0, 8),
                                        ),
                                      ],
                                    ),
                                    child: Row(
                                      mainAxisSize: MainAxisSize.min,
                                      children: [
                                        Icon(
                                          _useQrScanner
                                              ? Icons.face_retouching_natural_rounded
                                              : Icons.qr_code_scanner_rounded,
                                          color: _useQrScanner
                                              ? const Color(0xFF10B981)
                                              : Colors.cyanAccent,
                                          size: 22,
                                        ),
                                        const SizedBox(width: 10),
                                        Text(
                                          _useQrScanner
                                              ? 'ប្ដូរទៅស្កេនផ្ទៃមុខ (Face Scan)'
                                              : 'ប្ដូរទៅស្កេន QR Code',
                                          style: GoogleFonts.kantumruyPro(
                                            color: Colors.white,
                                            fontWeight: FontWeight.bold,
                                            fontSize: 14,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ),

          // 5. Setup guide: visible ONLY for first-time users (NOT yet registered)
          if (!_useQrScanner && !_isLoading && !_isFaceRegistered)
            Positioned(
              bottom: 110,
              left: 24,
              right: 24,
              child: FadeInUp(
                duration: const Duration(milliseconds: 600),
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    vertical: 18,
                    horizontal: 20,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.black.withValues(alpha: 0.6),
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(
                      color: Colors.cyanAccent.withValues(alpha: 0.35),
                    ),
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          const Icon(Icons.face_retouching_natural_rounded,
                              color: Colors.cyanAccent, size: 20),
                          const SizedBox(width: 8),
                          Text(
                            'ការដំឡើង Face ID លើកដំបូង',
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.cyanAccent,
                              fontWeight: FontWeight.bold,
                              fontSize: 14,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 10),
                      Text(
                        'សូមបញ្ចូលមុខរបស់អ្នក ដើម្បីដំឡើង Face ID ជាលើកដំបូង',
                        textAlign: TextAlign.center,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                          fontSize: 15,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'ប្រសិនបើទូរស័ព្ទនេះមិនគាំទ្រ ឬអ្នកមិនចង់ប្រើ Face Scan សូម​ប្ដូរទៅ QR Code',
                        textAlign: TextAlign.center,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary.withValues(alpha: 0.8),
                          fontSize: 13,
                        ),
                      ),
                      const SizedBox(height: 16),
                      ElevatedButton(
                        onPressed: () {
                          _switchToQrScanner();
                        },
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.cyanAccent,
                          foregroundColor: Colors.black,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(16),
                          ),
                          padding: const EdgeInsets.symmetric(
                            vertical: 12,
                            horizontal: 24,
                          ),
                        ),
                        child: Text(
                          'ប្រើ QR Code ទៅវិញ',
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

          // 6. Loading / Processing Glass Overlay
          if (_isLoading)
            BackdropFilter(
              filter: ImageFilter.blur(sigmaX: 8, sigmaY: 8),
              child: Container(
                color: Colors.black.withValues(alpha: 0.65),
                child: Center(
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(24),
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 32,
                        vertical: 28,
                      ),
                      decoration: BoxDecoration(
                        color: const Color(0xFF1E293B).withValues(alpha: 0.85),
                        borderRadius: BorderRadius.circular(24),
                        border: Border.all(
                          color: Colors.cyanAccent.withValues(alpha: 0.3),
                        ),
                      ),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const SizedBox(
                            width: 46,
                            height: 46,
                            child: CircularProgressIndicator(
                              color: Colors.cyanAccent,
                              strokeWidth: 3.5,
                            ),
                          ),
                          const SizedBox(height: 20),
                          Text(
                            "កំពុងដំណើរការ...",
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            "សូមរង់ចាំការចាប់យកទីតាំង GPS",
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white60,
                              fontSize: 12,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class QrScannerOverlayShape extends ShapeBorder {
  final Color borderColor;
  final double borderWidth;
  final Color overlayColor;
  final double borderRadius;
  final double borderLength;
  final double cutOutSide;

  const QrScannerOverlayShape({
    this.borderColor = Colors.white,
    this.borderWidth = 1.0,
    this.overlayColor = const Color(0x88000000),
    this.borderRadius = 0,
    this.borderLength = 40,
    this.cutOutSide = 250,
  });

  @override
  EdgeInsetsGeometry get dimensions => const EdgeInsets.all(10);

  @override
  Path getInnerPath(Rect rect, {TextDirection? textDirection}) {
    return Path()..addRRect(
      RRect.fromRectAndRadius(
        Rect.fromCenter(
          center: rect.center,
          width: cutOutSide,
          height: cutOutSide,
        ),
        Radius.circular(borderRadius),
      ),
    );
  }

  @override
  Path getOuterPath(Rect rect, {TextDirection? textDirection}) {
    return Path()..addRect(rect);
  }

  @override
  void paint(Canvas canvas, Rect rect, {TextDirection? textDirection}) {
    final width = rect.width;
    final height = rect.height;
    final topOffset = (height - cutOutSide) / 2;
    final leftOffset = (width - cutOutSide) / 2;

    final backgroundPaint = Paint()..color = overlayColor;

    final cutOutRect = Rect.fromLTWH(
      leftOffset,
      topOffset,
      cutOutSide,
      cutOutSide,
    );

    // Draw background with cutout using evenOdd fill type (more reliable across platforms)
    final backgroundPath = Path()
      ..addRect(rect)
      ..addRRect(
        RRect.fromRectAndRadius(cutOutRect, Radius.circular(borderRadius)),
      )
      ..fillType = PathFillType.evenOdd;

    canvas.drawPath(backgroundPath, backgroundPaint);

    final borderPaint = Paint()
      ..color = borderColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = borderWidth;

    final path = Path();
    // Top Left
    path.moveTo(leftOffset, topOffset + borderLength);
    path.lineTo(leftOffset, topOffset + borderRadius);
    path.arcToPoint(
      Offset(leftOffset + borderRadius, topOffset),
      radius: Radius.circular(borderRadius),
    );
    path.lineTo(leftOffset + borderLength, topOffset);

    // Top Right
    path.moveTo(leftOffset + cutOutSide - borderLength, topOffset);
    path.lineTo(leftOffset + cutOutSide - borderRadius, topOffset);
    path.arcToPoint(
      Offset(leftOffset + cutOutSide, topOffset + borderRadius),
      radius: Radius.circular(borderRadius),
    );
    path.lineTo(leftOffset + cutOutSide, topOffset + borderLength);

    // Bottom Right
    path.moveTo(leftOffset + cutOutSide, topOffset + cutOutSide - borderLength);
    path.lineTo(leftOffset + cutOutSide, topOffset + cutOutSide - borderRadius);
    path.arcToPoint(
      Offset(leftOffset + cutOutSide - borderRadius, topOffset + cutOutSide),
      radius: Radius.circular(borderRadius),
    );
    path.lineTo(leftOffset + cutOutSide - borderLength, topOffset + cutOutSide);

    // Bottom Left
    path.moveTo(leftOffset + borderLength, topOffset + cutOutSide);
    path.lineTo(leftOffset + borderRadius, topOffset + cutOutSide);
    path.arcToPoint(
      Offset(leftOffset, topOffset + cutOutSide - borderRadius),
      radius: Radius.circular(borderRadius),
    );
    path.lineTo(leftOffset, topOffset + cutOutSide - borderLength);

    canvas.drawPath(path, borderPaint);
  }

  @override
  ShapeBorder scale(double t) => this;
}

class FadeInScale extends StatefulWidget {
  final Widget child;
  const FadeInScale({super.key, required this.child});
  @override
  State<FadeInScale> createState() => _FadeInScaleState();
}

class _FadeInScaleState extends State<FadeInScale>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _opacity;
  late Animation<double> _scale;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 400),
    );
    _opacity = Tween<double>(
      begin: 0.0,
      end: 1.0,
    ).animate(CurvedAnimation(parent: _controller, curve: Curves.easeOut));
    _scale = Tween<double>(
      begin: 0.8,
      end: 1.0,
    ).animate(CurvedAnimation(parent: _controller, curve: Curves.easeOutBack));
    _controller.forward();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return FadeTransition(
      opacity: _opacity,
      child: ScaleTransition(scale: _scale, child: widget.child),
    );
  }
}

/// Custom Face Scanner Overlay Painter with Cutout and Glowing Biometric Frame
class FaceScannerOverlayPainter extends CustomPainter {
  final Rect cutoutRect;
  final double borderRadius;
  final Color borderColor;
  final bool isFaceDetected;

  FaceScannerOverlayPainter({
    required this.cutoutRect,
    this.borderRadius = 36.0,
    required this.borderColor,
    this.isFaceDetected = false,
  });

  @override
  void paint(Canvas canvas, Size size) {
    // 1. Dark Vignette Background with Cutout
    final backgroundPaint = Paint()
      ..color = Colors.black.withValues(alpha: 0.65)
      ..style = PaintingStyle.fill;

    final rrect = RRect.fromRectAndRadius(cutoutRect, Radius.circular(borderRadius));
    final backgroundPath = Path()
      ..addRect(Rect.fromLTWH(0, 0, size.width, size.height))
      ..addRRect(rrect)
      ..fillType = PathFillType.evenOdd;

    canvas.drawPath(backgroundPath, backgroundPaint);

    // 2. Soft Outer Glowing Border
    final borderGlowPaint = Paint()
      ..color = borderColor.withValues(alpha: isFaceDetected ? 0.40 : 0.22)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 6.0
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 8);
    canvas.drawRRect(rrect, borderGlowPaint);

    // 3. Crisp Inner Border
    final borderPaint = Paint()
      ..color = borderColor.withValues(alpha: 0.85)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.0;
    canvas.drawRRect(rrect, borderPaint);

    // 4. Cyberpunk Corner Brackets
    final bracketPaint = Paint()
      ..color = isFaceDetected ? const Color(0xFF10B981) : const Color(0xFF00E5FF)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 4.0
      ..strokeCap = StrokeCap.round;

    const double cornerLen = 28.0;
    final double rad = borderRadius;

    // Top-Left Corner
    final tlPath = Path()
      ..moveTo(cutoutRect.left, cutoutRect.top + cornerLen)
      ..lineTo(cutoutRect.left, cutoutRect.top + rad)
      ..arcToPoint(
        Offset(cutoutRect.left + rad, cutoutRect.top),
        radius: Radius.circular(rad),
      )
      ..lineTo(cutoutRect.left + cornerLen, cutoutRect.top);
    canvas.drawPath(tlPath, bracketPaint);

    // Top-Right Corner
    final trPath = Path()
      ..moveTo(cutoutRect.right - cornerLen, cutoutRect.top)
      ..lineTo(cutoutRect.right - rad, cutoutRect.top)
      ..arcToPoint(
        Offset(cutoutRect.right, cutoutRect.top + rad),
        radius: Radius.circular(rad),
      )
      ..lineTo(cutoutRect.right, cutoutRect.top + cornerLen);
    canvas.drawPath(trPath, bracketPaint);

    // Bottom-Left Corner
    final blPath = Path()
      ..moveTo(cutoutRect.left, cutoutRect.bottom - cornerLen)
      ..lineTo(cutoutRect.left, cutoutRect.bottom - rad)
      ..arcToPoint(
        Offset(cutoutRect.left + rad, cutoutRect.bottom),
        radius: Radius.circular(rad),
      )
      ..lineTo(cutoutRect.left + cornerLen, cutoutRect.bottom);
    canvas.drawPath(blPath, bracketPaint);

    // Bottom-Right Corner
    final brPath = Path()
      ..moveTo(cutoutRect.right - cornerLen, cutoutRect.bottom)
      ..lineTo(cutoutRect.right - rad, cutoutRect.bottom)
      ..arcToPoint(
        Offset(cutoutRect.right, cutoutRect.bottom - rad),
        radius: Radius.circular(rad),
      )
      ..lineTo(cutoutRect.right, cutoutRect.bottom - cornerLen);
    canvas.drawPath(brPath, bracketPaint);
  }

  @override
  bool shouldRepaint(covariant FaceScannerOverlayPainter oldDelegate) {
    return oldDelegate.cutoutRect != cutoutRect ||
        oldDelegate.borderColor != borderColor ||
        oldDelegate.isFaceDetected != isFaceDetected;
  }
}
