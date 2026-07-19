import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui';
import 'package:camera/camera.dart';
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
import '../services/notification_service.dart';
import '../utils/app_theme.dart';

class AttendanceScreen extends StatefulWidget {
  /// If set, auto-submits with this action (skips dialog).
  final String? presetAction;
  const AttendanceScreen({super.key, this.presetAction});

  @override
  State<AttendanceScreen> createState() => _AttendanceScreenState();
}

class _AttendanceScreenState extends State<AttendanceScreen> {
  final MobileScannerController controller = MobileScannerController(
    formats: [BarcodeFormat.qrCode],
    detectionTimeoutMs: 1000,
  );
  CameraController? _cameraController;
  FaceDetector? _faceDetector;
  final ApiService _apiService = ApiService();

  bool _isScanning = false;
  bool _isLoading = false;
  bool _useQrScanner = false;
  bool _faceScanAttempted = false;
  bool _faceCaptured = false;
  bool _faceProcessing = false;
  int _consecutiveFaceFrames = 0;
  Timer? _faceScanTimeout;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _tryFaceScanOrFallback();
    });
  }

  @override
  void dispose() {
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
    if (_faceScanAttempted || _useQrScanner) return;
    _faceScanAttempted = true;
    setState(() => _isLoading = true);
 
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    if (!userProvider.faceScanEnabled) {
      if (!mounted) return;
      setState(() {
        _useQrScanner = true;
        _isScanning = true;
        _isLoading = false;
      });
      return;
    }
 
    try {
      final permission = await Permission.camera.request();
      if (!permission.isGranted) {
        throw Exception('Camera permission denied');
      }

      final cameras = await availableCameras();
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
      );

      await _cameraController!.initialize();
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
      _faceScanTimeout?.cancel();
      _faceScanTimeout = Timer(const Duration(seconds: 10), () {
        if (!_faceCaptured && mounted) {
          _switchToQrScanner();
        }
      });

      if (!mounted) return;
      setState(() {
        _useQrScanner = false;
        _isScanning = true;
        _isLoading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _useQrScanner = true;
        _isScanning = true;
        _isLoading = false;
      });
    }
  }

  Future<void> _switchToQrScanner() async {
    _faceScanTimeout?.cancel();
    _faceProcessing = false;
    _faceCaptured = false;
    _consecutiveFaceFrames = 0;

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
    });
  }

  Future<void> _switchToFaceScanner() async {
    _faceScanAttempted = false;
    if (!mounted) return;
    setState(() {
      _isLoading = true;
      _isScanning = false;
    });
    await _tryFaceScanOrFallback();
  }

  void _processCameraImage(CameraImage image) async {
    if (_faceProcessing ||
        _faceCaptured ||
        _useQrScanner ||
        _cameraController == null) {
      return;
    }
    _faceProcessing = true;

    try {
      final inputImage = _convertCameraImage(
        image,
        _cameraController!.description.sensorOrientation,
      );
      final faces = await _faceDetector?.processImage(inputImage) ?? [];

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
    } catch (_) {
      // Ignore detection errors and allow fallback timer to trigger.
    } finally {
      _faceProcessing = false;
    }
  }

  Widget _buildFaceScannerPreview() {
    if (_cameraController == null || !_cameraController!.value.isInitialized) {
      return Container(color: Colors.black);
    }

    return Stack(
      fit: StackFit.expand,
      children: [
        CameraPreview(_cameraController!),
        Container(color: Colors.black.withValues(alpha: 0.2)),
        Align(
          alignment: Alignment.topCenter,
          child: Padding(
            padding: const EdgeInsets.only(top: 40, left: 24, right: 24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  'FACE SCAN',
                  style: GoogleFonts.inter(
                    color: Colors.white,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 1.5,
                    fontSize: 16,
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  'សូមកាន់កាមេរ៉ាមុខអ្នកជិតមុខ និងមិនដកពីផ្ទៃមុខ',
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white.withValues(alpha: 0.85),
                    fontSize: 13,
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  InputImage _convertCameraImage(CameraImage image, int rotation) {
    final BytesBuilder allBytes = BytesBuilder();
    for (final Plane plane in image.planes) {
      allBytes.add(plane.bytes);
    }
    final bytes = allBytes.takeBytes();

    final Size imageSize = Size(
      image.width.toDouble(),
      image.height.toDouble(),
    );
    final inputImageFormat =
        InputImageFormatValue.fromRawValue(image.format.raw) ??
        InputImageFormat.nv21;
    final imageRotation =
        InputImageRotationValue.fromRawValue(rotation) ??
        InputImageRotation.rotation0deg;

    final planeData = image.planes
        .map(
          (Plane plane) => InputImagePlaneMetadata(
            bytesPerRow: plane.bytesPerRow,
            height: plane.height,
            width: plane.width,
          ),
        )
        .toList();

    final inputImageData = InputImageData(
      size: imageSize,
      imageRotation: imageRotation,
      inputImageFormat: inputImageFormat,
      planeData: planeData,
    );

    return InputImage.fromBytes(bytes: bytes, inputImageData: inputImageData);
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
      }

      final XFile photo = await _cameraController!.takePicture();
      final String photoBase64 = base64Encode(await photo.readAsBytes());

      Position position = await _determinePosition();
      String locationRaw = "${position.latitude},${position.longitude}";

      String? action = widget.presetAction;
      if (action == null) {
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
          _useQrScanner = true;
          _isScanning = true;
          _isLoading = false;
        });
        return;
      }

      if (!mounted) return;
      final userProvider = Provider.of<UserProvider>(context, listen: false);

      Future<void> submit(String? reason) async {
        final result = await _apiService.submitAttendance(
          action: action!,
          employeeId: userProvider.employeeId!,
          workplace: "Face Scan",
          branch: "Face Scan",
          locationRaw: locationRaw,
          qrSecret: "outside_scan",
          qrLocationId: 0,
          lateReason: reason,
          photoBase64: photoBase64,
        );

        if (result['success'] == true) {
          NotificationService().showNotification(
            id: DateTime.now().millisecondsSinceEpoch.remainder(100000),
            title: "ជោគជ័យ",
            body: "អ្នកបាន $action ដោយជោគជ័យ!",
          );
          _showSuccess(result['message'], action: action);
        } else if (result['require_late_reason'] == true) {
          if (!mounted) return;
          setState(() => _isLoading = false);
          String? inputReason = await _showLateReasonDialog(result['message']);
          if (inputReason != null && inputReason.trim().isNotEmpty) {
            setState(() => _isLoading = true);
            await submit(inputReason.trim());
          } else {
            if (mounted) {
              setState(() {
                _useQrScanner = true;
                _isScanning = true;
                _isLoading = false;
              });
            }
          }
        } else {
          _showError(result['message'] ?? 'បរាជ័យ');
        }
      }

      await submit(null);
    } catch (e) {
      if (mounted) {
        _showError("កំហុស៖ $e");
        setState(() {
          _useQrScanner = true;
          _isScanning = true;
        });
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

      // 4. Submit Flow
      final userProvider = Provider.of<UserProvider>(context, listen: false);

      Future<void> submit(String? reason) async {
        final result = await _apiService.submitAttendance(
          action: action!,
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
            body: "អ្នកបាន $action ដោយជោគជ័យ!",
          );
          _showSuccess(result['message'], action: action);
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
        } else {
          _showError(result['message'] ?? 'បរាជ័យ');
        }
      }

      await submit(null);
    } catch (e) {
      _showError("កំហុស៖ $e");
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
                SizedBox(height: 10),
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
                Icon(
                  Icons.access_time_rounded,
                  color: Colors.orangeAccent,
                  size: 48,
                ),
                SizedBox(height: 12),
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
                SizedBox(height: 16),
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
                      borderSide: BorderSide(color: Colors.white24),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: BorderSide(color: Colors.orangeAccent),
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
        padding: EdgeInsets.symmetric(horizontal: 24, vertical: 12),
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
              SizedBox(width: 4),
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
                SizedBox(height: 20),
                Text(
                  message,
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontSize: 16,
                  ),
                ),
                SizedBox(height: 24),
                ElevatedButton(
                  onPressed: () {
                    Navigator.pop(context); // close dialog
                    if (!isError && result != null) {
                      // Return result to caller (Feature #1, #2, #5)
                      Navigator.pop(context, result);
                    } else {
                      setState(() => _isScanning = true);
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

  @override
  Widget build(BuildContext context) {
    final bool faceScanEnabled = Provider.of<UserProvider>(context).faceScanEnabled;
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      body: Stack(
        children: [
          // 1. Background Scanner
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
                              color: AppTheme.textPrimary.withValues(
                                alpha: 0.24,
                              ),
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

          // 2. Scanner Overlay Mask with Corner Borders
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

          // 4. Top Info Panel (Clean & Minimal)
          SafeArea(
            bottom: false,
            child: Align(
              alignment: Alignment.topCenter,
              child: Padding(
                padding: const EdgeInsets.only(top: 32),
                child: FadeInDown(
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(30),
                    child: BackdropFilter(
                      filter: ImageFilter.blur(sigmaX: 10, sigmaY: 10),
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 24,
                          vertical: 12,
                        ),
                        decoration: BoxDecoration(
                          color: Colors.black.withValues(alpha: 0.3),
                          borderRadius: BorderRadius.circular(30),
                          border: Border.all(
                            color: Colors.white.withValues(alpha: 0.15),
                          ),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              _useQrScanner
                                  ? Icons.qr_code_scanner_rounded
                                  : Icons.face_retouching_natural_rounded,
                              color: Colors.cyanAccent,
                              size: 18,
                            ),
                            const SizedBox(width: 8),
                            Text(
                              _useQrScanner ? "SCAN QR CODE" : "FACE SCAN",
                              style: GoogleFonts.inter(
                                color: Colors.white,
                                fontWeight: FontWeight.w800,
                                letterSpacing: 1.5,
                                fontSize: 13,
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

          // 5. Minimal Bottom Icon (Optional visual cue)
          if (_isScanning)
            Positioned(
              bottom: 40,
              left: 0,
              right: 0,
              child: Center(
                child: FadeInUp(
                  duration: const Duration(milliseconds: 1000),
                  child: Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: Colors.black.withValues(alpha: 0.3),
                      border: Border.all(
                        color: Colors.white.withValues(alpha: 0.1),
                      ),
                    ),
                    child: Icon(
                      Icons.camera_alt_outlined,
                      color: Colors.white.withValues(alpha: 0.6),
                      size: 28,
                    ),
                  ),
                ),
              ),
            ),

          if (_isScanning && _useQrScanner && !_isLoading)
            Positioned(
              bottom: 110,
              left: 24,
              right: 24,
              child: faceScanEnabled
                  ? FadeInUp(
                      duration: const Duration(milliseconds: 600),
                      child: ElevatedButton(
                        onPressed: _switchToFaceScanner,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.black.withValues(alpha: 0.5),
                          foregroundColor: Colors.white,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(16),
                            side: BorderSide(
                              color: Colors.cyanAccent.withValues(alpha: 0.3),
                            ),
                          ),
                          padding: const EdgeInsets.symmetric(vertical: 14),
                        ),
                        child: Text(
                          'សាកល្បងស្កេនមុខម្ដងទៀត',
                          style: GoogleFonts.kantumruyPro(
                            fontWeight: FontWeight.bold,
                            fontSize: 14,
                          ),
                        ),
                      ),
                    )
                  : FadeInUp(
                      duration: const Duration(milliseconds: 600),
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                          vertical: 16,
                          horizontal: 20,
                        ),
                        decoration: BoxDecoration(
                          color: Colors.black.withValues(alpha: 0.6),
                          borderRadius: BorderRadius.circular(16),
                          border: Border.all(
                            color: Colors.white.withValues(alpha: 0.12),
                          ),
                        ),
                        child: Text(
                          'Face Scan មិនត្រូវបានកំណត់សម្រាប់គណនីនេះទេ។ សូមប្រើ QR Code ដើម្បីបញ្ចូលវត្តមាន។',
                          textAlign: TextAlign.center,
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontSize: 13,
                          ),
                        ),
                      ),
                    ),
            ),

          if (!_useQrScanner && !_isLoading)
            Positioned(
              bottom: 140,
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
                    color: Colors.black.withValues(alpha: 0.55),
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(
                      color: Colors.white.withValues(alpha: 0.12),
                    ),
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        'សូមបញ្ចូលមុខរបស់អ្នក ដើម្បីស្កេនវត្តមាន',
                        textAlign: TextAlign.center,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                          fontSize: 15,
                        ),
                      ),
                      const SizedBox(height: 10),
                      Text(
                        'ប្រសិនបើទូរសព្ទនេះមិនគាំទ្រការស្កេនមុខ ឬអ្នកមិនចង់ប្រើមុខ សូម​ប្ដូរទៅ QR code',
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

          // 7. Loading Overlay
          if (_isLoading)
            Container(
              color: Colors.black.withValues(alpha: 0.7),
              child: Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const CircularProgressIndicator(color: Colors.cyanAccent),
                    const SizedBox(height: 20),
                    Text(
                      "កំពុងដំណើរការ...",
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary,
                        fontSize: 16,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      "សូមរង់ចាំការចាប់យកទីតាំង GPS",
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary.withValues(alpha: 0.54),
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
              ),
            ),

          // 8. Back Button (Crucial for routing back correctly)
          SafeArea(
            child: Align(
              alignment: Alignment.topLeft,
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: FadeInDown(
                  child: Container(
                    decoration: BoxDecoration(
                      color: Colors.black.withValues(alpha: 0.4),
                      shape: BoxShape.circle,
                      border: Border.all(
                        color: Colors.white.withValues(alpha: 0.1),
                      ),
                    ),
                    child: IconButton(
                      icon: const Icon(
                        Icons.arrow_back_ios_new_rounded,
                        color: Colors.white,
                        size: 20,
                      ),
                      onPressed: () => Navigator.pop(context),
                      tooltip: "ត្រឡប់ក្រោយ",
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
      duration: Duration(milliseconds: 400),
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
