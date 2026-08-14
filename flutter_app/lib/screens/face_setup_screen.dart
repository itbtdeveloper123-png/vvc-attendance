import 'dart:async';
import 'dart:io';
import 'dart:math' as math;
import 'package:camera/camera.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:google_mlkit_face_detection/google_mlkit_face_detection.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../services/face_recognizer_service.dart';
import '../utils/image_compress.dart';
import '../widgets/vvc_global_alert.dart';

// ========================
// FaceSetupScreen (iOS Style Face ID Setup)
// ========================

class FaceSetupScreen extends StatefulWidget {
  final bool isFirstTime;
  const FaceSetupScreen({super.key, this.isFirstTime = false});

  @override
  State<FaceSetupScreen> createState() => _FaceSetupScreenState();
}

class _FaceSetupScreenState extends State<FaceSetupScreen>
    with TickerProviderStateMixin {
  CameraController? _cameraController;
  FaceDetector? _faceDetector;
  final ApiService _apiService = ApiService();
  final FaceRecognizerService _faceRecognizer = FaceRecognizerService();

  bool _isInitializing = true;
  bool _isFaceDetected = false;
  bool _isCaptured = false;
  bool _isSubmitting = false;
  bool _cameraError = false;

  int _currentStep = 0; // 0: Straight, 1: Left, 2: Right
  final List<String> _capturedPhotoPaths = [];
  final List<String> _capturedPhotos = [];

  final List<String> _stepTitles = [
    'មើលចំត្រង់ (Center)',
    'ងាកក្បាលទៅឆ្វេង (Slight Left)',
    'ងាកក្បាលទៅស្តាំ (Slight Right)',
  ];

  final List<String> _stepSubtitles = [
    'សូមដាក់ផ្ទៃមុខរបស់អ្នកឱ្យចំកណ្តាលរង្វង់',
    'សូមងាកក្បាលយឺតៗទៅខាងឆ្វេងបន្តិច',
    'សូមងាកក្បាលយឺតៗទៅខាងស្តាំបន្តិច',
  ];

  late AnimationController _rotationController;
  late AnimationController _successController;
  late Animation<double> _successScaleAnim;
  late AnimationController _pulseController;
  late Animation<double> _pulseAnim;

  bool _faceProcessing = false;
  DateTime _lastFrameProcessed = DateTime.now();
  int _consecutiveFaceFrames = 0;
  String _poseFeedback = 'ដាក់ផ្ទៃមុខរបស់អ្នកក្នុងរង្វង់';

  @override
  void initState() {
    super.initState();
    _rotationController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 8),
    )..repeat();

    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1400),
    )..repeat(reverse: true);
    _pulseAnim = Tween<double>(begin: 0.98, end: 1.03).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );

    _successController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 600),
    );
    _successScaleAnim = CurvedAnimation(
      parent: _successController,
      curve: Curves.elasticOut,
    );

    WidgetsBinding.instance.addPostFrameCallback((_) => _initCamera());
  }

  Future<void> _initCamera() async {
    setState(() => _isInitializing = true);
    try {
      var status = await Permission.camera.status;
      if (!status.isGranted) {
        status = await Permission.camera.request();
      }
      if (!status.isGranted) {
        if (mounted) {
          setState(() {
            _cameraError = true;
            _isInitializing = false;
          });
        }
        return;
      }

      final cameras = await availableCameras();
      final front = cameras.firstWhere(
        (c) => c.lensDirection == CameraLensDirection.front,
        orElse: () => cameras.first,
      );

      _cameraController = CameraController(
        front,
        ResolutionPreset.medium,
        enableAudio: false,
        imageFormatGroup: Platform.isIOS ? ImageFormatGroup.bgra8888 : ImageFormatGroup.yuv420,
      );
      await _cameraController!.initialize();

      _faceDetector = FaceDetector(
        options: FaceDetectorOptions(
          performanceMode: FaceDetectorMode.fast,
          enableLandmarks: false,
          enableContours: false,
          enableClassification: false,
        ),
      );

      await _cameraController!.startImageStream(_processFrame);
      if (mounted) setState(() => _isInitializing = false);
    } catch (e) {
      debugPrint('FaceSetup init error: $e');
      if (mounted) {
        setState(() {
          _cameraError = true;
          _isInitializing = false;
        });
      }
    }
  }

  void _processFrame(CameraImage image) async {
    // Throttle to 120ms to eliminate CPU lag and battery drain
    final now = DateTime.now();
    if (now.difference(_lastFrameProcessed).inMilliseconds < 120) return;
    if (_faceProcessing || _isCaptured || _isSubmitting || !mounted) return;
    _faceProcessing = true;
    _lastFrameProcessed = now;

    try {
      final inputImage = _buildInputImage(image);
      if (inputImage == null) return;

      final faces = await _faceDetector?.processImage(inputImage) ?? [];
      if (!mounted) return;

      if (faces.isNotEmpty) {
        final face = faces.first;
        final angleY = face.headEulerAngleY ?? 0;

        bool isCorrectPose = false;
        String feedback = '';

        if (_currentStep == 0) {
          if (angleY.abs() <= 12) {
            isCorrectPose = true;
            feedback = 'ទីតាំងត្រឹមត្រូវ! កំពុងចាប់យក...';
          } else {
            feedback = 'សូមមើលចំកាមេរ៉ាត្រង់';
          }
        } else if (_currentStep == 1) {
          if (angleY <= -12) {
            isCorrectPose = true;
            feedback = 'ងាកឆ្វេងត្រឹមត្រូវ! កំពុងចាប់យក...';
          } else {
            feedback = 'សូមងាកក្បាលទៅខាងឆ្វេងបន្តិច';
          }
        } else if (_currentStep == 2) {
          if (angleY >= 12) {
            isCorrectPose = true;
            feedback = 'ងាកស្តាំត្រឹមត្រូវ! កំពុងចាប់យក...';
          } else {
            feedback = 'សូមងាកក្បាលទៅខាងស្តាំបន្តិច';
          }
        }

        if (mounted) {
          setState(() {
            _poseFeedback = feedback;
            _isFaceDetected = true;
          });
        }

        if (isCorrectPose) {
          _consecutiveFaceFrames++;
          if (_consecutiveFaceFrames >= 4 && !_isCaptured) {
            _capturePhoto();
          }
        } else {
          _consecutiveFaceFrames = 0;
        }
      } else {
        if (mounted) {
          setState(() {
            _consecutiveFaceFrames = 0;
            _isFaceDetected = false;
            _poseFeedback = 'សូមដាក់ផ្ទៃមុខឱ្យចំកណ្តាលរង្វង់';
          });
        }
      }
    } catch (_) {
      _consecutiveFaceFrames = 0;
    } finally {
      _faceProcessing = false;
    }
  }

  InputImage? _buildInputImage(CameraImage image) {
    try {
      final camera = _cameraController?.description;
      if (camera == null) return null;

      final sensorOrientation = camera.sensorOrientation;
      final rot = InputImageRotationValue.fromRawValue(sensorOrientation) ??
          InputImageRotation.rotation0deg;

      if (Platform.isIOS) {
        // Fast path on iOS: single plane
        return InputImage.fromBytes(
          bytes: image.planes.first.bytes,
          metadata: InputImageMetadata(
            size: Size(image.width.toDouble(), image.height.toDouble()),
            rotation: rot,
            format: InputImageFormat.bgra8888,
            bytesPerRow: image.planes.first.bytesPerRow,
          ),
        );
      } else {
        // Fast buffer concatenation on Android
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
            rotation: rot,
            format: fmt,
            bytesPerRow: image.planes.first.bytesPerRow,
          ),
        );
      }
    } catch (e) {
      return null;
    }
  }

  Future<void> _capturePhoto() async {
    if (_isCaptured || _cameraController == null) return;
    setState(() => _isCaptured = true);

    try {
      await _cameraController!.stopImageStream();
      await Future.delayed(const Duration(milliseconds: 150));
      final photo = await _cameraController!.takePicture();

      _capturedPhotoPaths.add(photo.path);
      final b64 = await compressAndEncodeImage(await photo.readAsBytes());
      _capturedPhotos.add(b64);

      _successController.forward(from: 0);
      await Future.delayed(const Duration(milliseconds: 700));

      if (_currentStep < 2) {
        if (mounted) {
          setState(() {
            _currentStep++;
            _isCaptured = false;
            _isFaceDetected = false;
            _consecutiveFaceFrames = 0;
            _poseFeedback = 'សូមដាក់ផ្ទៃមុខឱ្យចំកណ្តាលរង្វង់';
          });
        }
        await _cameraController!.startImageStream(_processFrame);
      } else {
        await _submitRegistration();
      }
    } catch (e) {
      debugPrint('Capture error: $e');
      if (mounted) {
        setState(() => _isCaptured = false);
      }
      await _cameraController?.startImageStream(_processFrame);
    }
  }

  Future<void> _submitRegistration() async {
    setState(() => _isSubmitting = true);
    try {
      final userProvider = Provider.of<UserProvider>(context, listen: false);
      final userId = userProvider.employeeId ?? 'user';

      // 1. On-device AI Face Registration (FaceNet TFLite)
      bool aiRegistrationOk = false;
      try {
        await _faceRecognizer.deleteAllFaces(userId);
        final labels = ['front', 'left', 'right'];
        int registered = 0;
        for (int i = 0; i < _capturedPhotoPaths.length; i++) {
          final ok = await _faceRecognizer.registerFace(
            userId: userId,
            imagePath: _capturedPhotoPaths[i],
            imageId: labels[i],
          );
          if (ok) registered++;
        }
        aiRegistrationOk = registered > 0;
      } catch (e) {
        debugPrint('[FaceSetup] AI registration warning: $e');
      }

      // 2. Server-side Face Registration
      final result = await _apiService.registerFace(_capturedPhotos);
      if (!mounted) return;

      if (result['success'] == true || aiRegistrationOk) {
        userProvider.setFaceRegistered(true);
        _showSuccessDialog();
      } else {
        _showError(result['message'] ?? 'ចុះឈ្មោះបានបរាជ័យ');
        setState(() {
          _currentStep = 0;
          _capturedPhotos.clear();
          _capturedPhotoPaths.clear();
          _isCaptured = false;
          _isFaceDetected = false;
          _isSubmitting = false;
          _consecutiveFaceFrames = 0;
          _poseFeedback = 'សូមដាក់ផ្ទៃមុខឱ្យចំកណ្តាលរង្វង់';
        });
        await _cameraController?.startImageStream(_processFrame);
      }
    } catch (e) {
      _showError('$e');
      setState(() => _isSubmitting = false);
    }
  }

  void _showSuccessDialog() {
    VvcAlert.showSuccessDialog(
      context,
      title: 'ចុះឈ្មោះជោគជ័យ!',
      message: 'Face ID របស់អ្នកត្រូវបានចុះឈ្មោះដោយជោគជ័យ!\nឥឡូវ អ្នកអាចស្កេនវត្តមានដោយផ្ទៃមុខបានយ៉ាងរហ័ស។',
      buttonText: 'រួចរាល់',
      onPressed: () => Navigator.pop(context, true),
    );
  }

  void _showError(String msg) {
    if (!mounted) return;
    VvcAlert.showError(
      context,
      title: 'ការចុះឈ្មោះបរាជ័យ',
      message: msg,
    );
  }

  @override
  void dispose() {
    _rotationController.dispose();
    _pulseController.dispose();
    _successController.dispose();
    try {
      _cameraController?.stopImageStream();
    } catch (_) {}
    _cameraController?.dispose();
    _faceDetector?.close();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final double viewportSize = math.min(size.width * 0.72, 280.0);

    return Scaffold(
      backgroundColor: const Color(0xFF000000),
      body: SafeArea(
        child: Stack(
          children: [
            // Main Content Layout
            Column(
              children: [
                _buildTopHeader(),
                const SizedBox(height: 8),
                _buildStepPillIndicator(),

                const Spacer(flex: 1),

                // Apple-style Circular Camera Viewport + Animated Ticks
                Center(
                  child: SizedBox(
                    width: viewportSize + 40,
                    height: viewportSize + 40,
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        // Background Glow
                        Container(
                          width: viewportSize,
                          height: viewportSize,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            boxShadow: [
                              BoxShadow(
                                color: _isCaptured
                                    ? const Color(0xFF10B981).withAlpha(120)
                                    : (_isFaceDetected
                                        ? const Color(0xFF00E5FF).withAlpha(80)
                                        : Colors.white.withAlpha(20)),
                                blurRadius: 36,
                                spreadRadius: 4,
                              ),
                            ],
                          ),
                        ),

                        // Authentic iOS Circular Ticks (Segmented Ring Gauge)
                        CustomPaint(
                          size: Size(viewportSize + 36, viewportSize + 36),
                          painter: IosFaceIdTickPainter(
                            currentStep: _currentStep,
                            isCaptured: _isCaptured,
                            isFaceDetected: _isFaceDetected,
                            rotationValue: _rotationController.value,
                          ),
                        ),

                        // Center Circular Camera Preview
                        ScaleTransition(
                          scale: _isFaceDetected && !_isCaptured
                              ? _pulseAnim
                              : const AlwaysStoppedAnimation(1.0),
                          child: Container(
                            width: viewportSize,
                            height: viewportSize,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: const Color(0xFF151D2A),
                              border: Border.all(
                                color: _isCaptured
                                    ? const Color(0xFF10B981)
                                    : (_isFaceDetected
                                        ? const Color(0xFF00E5FF)
                                        : Colors.white24),
                                width: 3,
                              ),
                            ),
                            clipBehavior: Clip.antiAlias,
                            child: Stack(
                              fit: StackFit.expand,
                              children: [
                                if (!_isInitializing &&
                                    !_cameraError &&
                                    _cameraController != null &&
                                    _cameraController!.value.isInitialized)
                                  FittedBox(
                                    fit: BoxFit.cover,
                                    child: SizedBox(
                                      width: _cameraController!.value.previewSize?.height ?? viewportSize,
                                      height: _cameraController!.value.previewSize?.width ?? viewportSize,
                                      child: CameraPreview(_cameraController!),
                                    ),
                                  )
                                else
                                  const Center(
                                    child: CircularProgressIndicator(
                                      color: Color(0xFF00E5FF),
                                    ),
                                  ),

                                // Subtle inner vignette
                                Container(
                                  decoration: BoxDecoration(
                                    shape: BoxShape.circle,
                                    gradient: RadialGradient(
                                      radius: 0.85,
                                      colors: [
                                        Colors.transparent,
                                        Colors.black.withAlpha(60),
                                      ],
                                    ),
                                  ),
                                ),

                                // Checkmark on step captured
                                if (_isCaptured)
                                  Container(
                                    color: Colors.black.withAlpha(90),
                                    child: Center(
                                      child: ScaleTransition(
                                        scale: _successScaleAnim,
                                        child: Container(
                                          padding: const EdgeInsets.all(16),
                                          decoration: const BoxDecoration(
                                            color: Color(0xFF10B981),
                                            shape: BoxShape.circle,
                                          ),
                                          child: const Icon(
                                            Icons.check_rounded,
                                            color: Colors.white,
                                            size: 48,
                                          ),
                                        ),
                                      ),
                                    ),
                                  ),
                              ],
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),

                const Spacer(flex: 1),

                // Live Pose Instruction & Dynamic Guidance
                _buildInstructionCard(),

                const SizedBox(height: 16),

                // Bottom Status Pill
                _buildBottomStatusPill(),

                const SizedBox(height: 28),
              ],
            ),

            // Loading / Submitting Overlay
            if (_isSubmitting || _isInitializing)
              Container(
                color: Colors.black.withAlpha(200),
                child: Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const CircularProgressIndicator(
                        color: Color(0xFF00E5FF),
                        strokeWidth: 3,
                      ),
                      const SizedBox(height: 20),
                      Text(
                        _isSubmitting
                            ? 'កំពុងរក្សាទុកទិន្នន័យ Face ID...'
                            : 'កំពុងបើកដំណើរការកាមេរ៉ា...',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 15,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ),

            // Camera Error Overlay
            if (_cameraError)
              Container(
                color: Colors.black,
                padding: const EdgeInsets.all(32),
                child: Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(
                        Icons.videocam_off_rounded,
                        color: Colors.orangeAccent,
                        size: 64,
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'មិនអាចចូលប្រើកាមេរ៉ាបានទេ',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'សូមបើកការអនុញ្ញាត Camera នៅក្នុង Settings របស់ឧបករណ៍។',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white60,
                          fontSize: 13,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 24),
                      ElevatedButton.icon(
                        onPressed: () => Navigator.pop(context),
                        icon: const Icon(Icons.arrow_back_rounded),
                        label: Text(
                          'ត្រឡប់ក្រោយ',
                          style: GoogleFonts.kantumruyPro(),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.white12,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(
                            horizontal: 24,
                            vertical: 12,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildTopHeader() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      child: Row(
        children: [
          GestureDetector(
            onTap: () => Navigator.pop(context),
            child: Container(
              width: 38,
              height: 38,
              decoration: BoxDecoration(
                color: Colors.white.withAlpha(25),
                shape: BoxShape.circle,
              ),
              child: const Icon(
                Icons.close_rounded,
                color: Colors.white,
                size: 20,
              ),
            ),
          ),
          const Spacer(),
          Text(
            'ចុះឈ្មោះ Face ID',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 18,
            ),
          ),
          const Spacer(),
          const SizedBox(width: 38), // Balancer
        ],
      ),
    );
  }

  Widget _buildStepPillIndicator() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 6),
      child: Row(
        children: List.generate(3, (i) {
          final done = i < _currentStep;
          final active = i == _currentStep;

          return Expanded(
            child: Container(
              margin: const EdgeInsets.symmetric(horizontal: 4),
              height: 4,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(2),
                color: done
                    ? const Color(0xFF10B981)
                    : (active ? const Color(0xFF00E5FF) : Colors.white24),
                boxShadow: active
                    ? [
                        BoxShadow(
                          color: const Color(0xFF00E5FF).withAlpha(160),
                          blurRadius: 6,
                        ),
                      ]
                    : null,
              ),
            ),
          );
        }),
      ),
    );
  }

  Widget _buildInstructionCard() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 32),
      child: Column(
        children: [
          Text(
            _stepTitles[_currentStep],
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 20,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 6),
          Text(
            _stepSubtitles[_currentStep],
            style: GoogleFonts.kantumruyPro(
              color: Colors.white60,
              fontSize: 14,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildBottomStatusPill() {
    if (_isSubmitting) return const SizedBox.shrink();

    if (_isCaptured) {
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 10),
        decoration: BoxDecoration(
          color: const Color(0xFF10B981).withAlpha(40),
          borderRadius: BorderRadius.circular(30),
          border: Border.all(color: const Color(0xFF10B981).withAlpha(140)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(
              Icons.check_circle_rounded,
              color: Color(0xFF10B981),
              size: 18,
            ),
            const SizedBox(width: 8),
            Text(
              'ចាប់យកបានជោគជ័យ!',
              style: GoogleFonts.kantumruyPro(
                color: const Color(0xFF10B981),
                fontWeight: FontWeight.bold,
                fontSize: 13,
              ),
            ),
          ],
        ),
      );
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 10),
      decoration: BoxDecoration(
        color: _isFaceDetected
            ? const Color(0xFF00E5FF).withAlpha(35)
            : Colors.white.withAlpha(15),
        borderRadius: BorderRadius.circular(30),
        border: Border.all(
          color: _isFaceDetected
              ? const Color(0xFF00E5FF).withAlpha(120)
              : Colors.white.withAlpha(30),
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (_isFaceDetected)
            const SizedBox(
              width: 14,
              height: 14,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: Color(0xFF00E5FF),
              ),
            )
          else
            const Icon(
              Icons.face_retouching_natural_rounded,
              color: Colors.white60,
              size: 16,
            ),
          const SizedBox(width: 8),
          Text(
            _poseFeedback,
            style: GoogleFonts.kantumruyPro(
              color: _isFaceDetected ? const Color(0xFF00E5FF) : Colors.white70,
              fontWeight: FontWeight.w600,
              fontSize: 13,
            ),
          ),
        ],
      ),
    );
  }
}

// ==========================================
// iOS Face ID Segmented Circular Tick Painter
// ==========================================
class IosFaceIdTickPainter extends CustomPainter {
  final int currentStep;
  final bool isCaptured;
  final bool isFaceDetected;
  final double rotationValue;

  IosFaceIdTickPainter({
    required this.currentStep,
    required this.isCaptured,
    required this.isFaceDetected,
    required this.rotationValue,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = (size.width / 2) - 4;
    const int totalTicks = 42;
    const double tickLength = 10.0;
    const double tickWidth = 3.2;

    for (int i = 0; i < totalTicks; i++) {
      final angle = (i * 2 * math.pi / totalTicks) - (math.pi / 2);

      // Determine tick status based on step & head orientation
      bool isTickActive = false;

      if (isCaptured) {
        isTickActive = true;
      } else {
        if (currentStep == 0) {
          // Top & Center arc active
          isTickActive = (i >= 0 && i <= 8) || (i >= 34 && i < 42);
        } else if (currentStep == 1) {
          // Left arc active
          isTickActive = (i >= 24 && i <= 40);
        } else if (currentStep == 2) {
          // Right arc active
          isTickActive = (i >= 2 && i <= 18);
        }
      }

      Color tickColor;
      if (isCaptured) {
        tickColor = const Color(0xFF10B981);
      } else if (isFaceDetected && isTickActive) {
        tickColor = const Color(0xFF00E5FF);
      } else if (isFaceDetected) {
        tickColor = const Color(0xFF00E5FF).withAlpha(90);
      } else {
        tickColor = Colors.white.withAlpha(45);
      }

      final p1 = Offset(
        center.dx + (radius - tickLength) * math.cos(angle),
        center.dy + (radius - tickLength) * math.sin(angle),
      );
      final p2 = Offset(
        center.dx + radius * math.cos(angle),
        center.dy + radius * math.sin(angle),
      );

      final paint = Paint()
        ..color = tickColor
        ..strokeWidth = tickWidth
        ..strokeCap = StrokeCap.round;

      canvas.drawLine(p1, p2, paint);
    }
  }

  @override
  bool shouldRepaint(covariant IosFaceIdTickPainter oldDelegate) {
    return oldDelegate.currentStep != currentStep ||
        oldDelegate.isCaptured != isCaptured ||
        oldDelegate.isFaceDetected != isFaceDetected ||
        oldDelegate.rotationValue != rotationValue;
  }
}
