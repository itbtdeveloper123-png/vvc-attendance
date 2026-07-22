import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui';
import 'package:camera/camera.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:google_mlkit_face_detection/google_mlkit_face_detection.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';

// ========================
// FaceSetupScreen
// ========================
// អ្នកប្រើប្រាស់ថតរូបមុខ ៣ ដង ពី ៣ ទិស ដើម្បីចុះឈ្មោះ Face ID
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

  bool _isInitializing = true;
  bool _isFaceDetected = false;
  bool _isCaptured = false;
  bool _isSubmitting = false;
  bool _cameraError = false;

  int _currentStep = 0;
  final List<String> _capturedPhotos = [];
  final List<String> _stepTitles = [
    'ស្ថានភាពទី ១ — ត្រង់ (Straight)',
    'ស្ថានភាពទី ២ — ក្បាលទំអែតឆ្វេង (Slight Left)',
    'ស្ថានភាពទី ៣ — ក្បាលទំអែតស្ដាំ (Slight Right)',
  ];
  final List<String> _stepIcons = ['😐', '🙂', '🙃'];
  final List<String> _stepHints = [
    'សូមមើលត្រង់ទៅកាន់កាមេរ៉ា',
    'សូមងាក​ក្បាលបន្ដិចទៅខាងឆ្វេង',
    'សូមងាក​ក្បាលបន្ដិចទៅខាងស្ដាំ',
  ];

  late AnimationController _pulseController;
  late Animation<double> _pulseAnim;
  late AnimationController _successController;
  late Animation<double> _successAnim;

  Timer? _captureTimer;
  Timer? _countdownTimer;
  bool _faceProcessing = false;
  int _consecutiveFaceFrames = 0;
  int _captureCountdown = 3;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    )..repeat(reverse: true);
    _pulseAnim = Tween<double>(begin: 0.95, end: 1.05).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );
    _successController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 500),
    );
    _successAnim = CurvedAnimation(
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
        front, ResolutionPreset.medium, enableAudio: false,
        imageFormatGroup: Platform.isIOS ? ImageFormatGroup.bgra8888 : ImageFormatGroup.yuv420,
      );
      await _cameraController!.initialize();

      _faceDetector = FaceDetector(
        options: FaceDetectorOptions(performanceMode: FaceDetectorMode.fast),
      );
      await _cameraController!.startImageStream(_processFrame);
      if (mounted) setState(() => _isInitializing = false);
    } catch (e) {
      debugPrint('FaceSetup init error: $e');
      if (mounted) setState(() { _cameraError = true; _isInitializing = false; });
    }
  }

  void _processFrame(CameraImage image) async {
    if (_faceProcessing || _isCaptured || _isSubmitting) return;
    _faceProcessing = true;
    try {
      final fmt = Platform.isIOS
          ? InputImageFormat.bgra8888
          : (InputImageFormatValue.fromRawValue(image.format.raw) ?? InputImageFormat.nv21);
      final rot = InputImageRotationValue.fromRawValue(
              _cameraController!.description.sensorOrientation) ??
          InputImageRotation.rotation0deg;
      
      final inputImage = InputImage.fromBytes(
        bytes: image.planes.map((plane) => plane.bytes).expand((x) => x).toList(),
        metadata: InputImageMetadata(
          size: Size(image.width.toDouble(), image.height.toDouble()),
          rotation: rot,
          format: fmt,
          bytesPerRow: image.planes.first.bytesPerRow,
        ),
      );

      final faces = await _faceDetector?.processImage(inputImage) ?? [];
      if (!mounted) return;

      if (faces.isNotEmpty) {
        _consecutiveFaceFrames++;
        if (!_isFaceDetected) setState(() => _isFaceDetected = true);
        if (_consecutiveFaceFrames >= 10 && !_isCaptured && _captureTimer == null) {
          _startCaptureCountdown();
        }
      } else {
        _consecutiveFaceFrames = 0;
        if (_isFaceDetected) {
          setState(() => _isFaceDetected = false);
          _cancelCountdown();
        }
      }
    } catch (_) {
      _consecutiveFaceFrames = 0;
    } finally {
      _faceProcessing = false;
    }
  }

  void _startCaptureCountdown() {
    if (_captureTimer != null) return;
    _captureCountdown = 3;
    setState(() {});
    _countdownTimer = Timer.periodic(const Duration(seconds: 1), (t) {
      if (!mounted) { t.cancel(); return; }
      _captureCountdown--;
      setState(() {});
      if (_captureCountdown <= 0) { t.cancel(); _capturePhoto(); }
    });
    _captureTimer = Timer(const Duration(seconds: 4), () {});
  }

  void _cancelCountdown() {
    _countdownTimer?.cancel(); _countdownTimer = null;
    _captureTimer?.cancel(); _captureTimer = null;
    _captureCountdown = 3;
  }

  Future<void> _capturePhoto() async {
    if (_isCaptured || _cameraController == null) return;
    setState(() => _isCaptured = true);
    try {
      await _cameraController!.stopImageStream();
      await Future.delayed(const Duration(milliseconds: 200));
      final photo = await _cameraController!.takePicture();
      final b64 = base64Encode(await photo.readAsBytes());
      _capturedPhotos.add(b64);
      _successController.forward(from: 0);
      await Future.delayed(const Duration(milliseconds: 800));

      if (_currentStep < 2) {
        if (mounted) {
          setState(() {
            _currentStep++;
            _isCaptured = false;
            _isFaceDetected = false;
            _consecutiveFaceFrames = 0;
            _captureTimer = null;
            _countdownTimer = null;
            _captureCountdown = 3;
          });
        }
        await _cameraController!.startImageStream(_processFrame);
      } else {
        await _submitRegistration();
      }
    } catch (e) {
      debugPrint('Capture error: $e');
      if (mounted) { setState(() => _isCaptured = false); }
      await _cameraController?.startImageStream(_processFrame);
    }
  }

  Future<void> _submitRegistration() async {
    setState(() => _isSubmitting = true);
    try {
      final result = await _apiService.registerFace(_capturedPhotos);
      if (!mounted) return;
      if (result['success'] == true) {
        final userProvider = Provider.of<UserProvider>(context, listen: false);
        userProvider.setFaceRegistered(true);
        _showSuccessDialog();
      } else {
        _showError(result['message'] ?? 'ចុះឈ្មោះបានបរាជ័យ');
        setState(() {
          _currentStep = 0; _capturedPhotos.clear();
          _isCaptured = false; _isFaceDetected = false;
          _isSubmitting = false; _consecutiveFaceFrames = 0;
        });
        await _cameraController?.startImageStream(_processFrame);
      }
    } catch (e) {
      _showError('$e');
      setState(() => _isSubmitting = false);
    }
  }

  void _showSuccessDialog() {
    _successController.forward(from: 0);
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
        child: Dialog(
          backgroundColor: Colors.transparent,
          child: Container(
            padding: const EdgeInsets.all(32),
            decoration: BoxDecoration(
              color: const Color(0xFF0F1E35).withValues(alpha: 0.95),
              borderRadius: BorderRadius.circular(28),
              border: Border.all(color: Colors.greenAccent.withValues(alpha: 0.5)),
              boxShadow: [BoxShadow(color: Colors.greenAccent.withValues(alpha: 0.3), blurRadius: 40, spreadRadius: 5)],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                ScaleTransition(
                  scale: _successAnim,
                  child: Container(
                    width: 80, height: 80,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: Colors.greenAccent.withValues(alpha: 0.15),
                      border: Border.all(color: Colors.greenAccent, width: 2),
                    ),
                    child: const Icon(Icons.check_rounded, color: Colors.greenAccent, size: 44),
                  ),
                ),
                const SizedBox(height: 20),
                Text('ចុះឈ្មោះជោគជ័យ!', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 20)),
                const SizedBox(height: 12),
                Text(
                  'មុខរបស់អ្នកត្រូវបានចុះឈ្មោះដោយជោគជ័យ!\nឥឡូវ អ្នកអាចប្រើ Face Scan ដើម្បីចូលវត្តមានបាន។',
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13, height: 1.6),
                ),
                const SizedBox(height: 24),
                ElevatedButton(
                  onPressed: () { Navigator.pop(ctx); Navigator.pop(context, true); },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.greenAccent.withValues(alpha: 0.2),
                    foregroundColor: Colors.greenAccent,
                    padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 14),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                  ),
                  child: Text('បន្ត', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, fontSize: 16)),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  void _showError(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(msg, style: GoogleFonts.kantumruyPro()), backgroundColor: Colors.redAccent),
    );
  }

  @override
  void dispose() {
    _captureTimer?.cancel(); _countdownTimer?.cancel();
    _pulseController.dispose(); _successController.dispose();
    try { _cameraController?.stopImageStream(); } catch (_) {}
    _cameraController?.dispose();
    _faceDetector?.close();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Stack(
        fit: StackFit.expand,
        children: [
          if (!_isInitializing && !_cameraError && _cameraController != null)
            CameraPreview(_cameraController!),
          Container(color: Colors.black.withValues(alpha: _isInitializing ? 1.0 : 0.35)),
          SafeArea(
            child: Column(
              children: [
                _buildTopBar(),
                _buildStepProgress(),
                const Spacer(),
                _buildFaceFrame(),
                const SizedBox(height: 16),
                _buildHintText(),
                const Spacer(),
                _buildBottomStatus(),
                const SizedBox(height: 32),
              ],
            ),
          ),
          if (_isSubmitting || _isInitializing)
            Container(
              color: Colors.black.withValues(alpha: 0.7),
              child: Center(
                child: Column(mainAxisSize: MainAxisSize.min, children: [
                  const CircularProgressIndicator(color: Colors.cyanAccent),
                  const SizedBox(height: 20),
                  Text(
                    _isSubmitting ? 'កំពុងបញ្ជូនទិន្នន័យ...' : 'កំពុងចាប់ផ្ដើមកាមេរ៉ា...',
                    style: GoogleFonts.kantumruyPro(color: Colors.white),
                  ),
                ]),
              ),
            ),
          if (_cameraError)
            Container(
              color: Colors.black87,
              child: Center(
                child: Column(mainAxisSize: MainAxisSize.min, children: [
                  const Icon(Icons.videocam_off_rounded, color: Colors.orangeAccent, size: 64),
                  const SizedBox(height: 16),
                  Text('មិនអាចចូលប្រើកាមេរ៉ាបានទេ', style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16)),
                  const SizedBox(height: 8),
                  Text('សូមបើកការអនុញ្ញាតកាមេរ៉ានៅក្នុង Settings', style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 13)),
                  const SizedBox(height: 24),
                  ElevatedButton.icon(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.arrow_back_rounded),
                    label: Text('ត្រឡប់ក្រោយ', style: GoogleFonts.kantumruyPro()),
                    style: ElevatedButton.styleFrom(backgroundColor: Colors.orangeAccent.withValues(alpha: 0.2), foregroundColor: Colors.orangeAccent),
                  ),
                ]),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildTopBar() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Row(children: [
        GestureDetector(
          onTap: () => Navigator.pop(context),
          child: Container(
            width: 40, height: 40,
            decoration: BoxDecoration(color: Colors.white.withValues(alpha: 0.1), shape: BoxShape.circle),
            child: const Icon(Icons.close_rounded, color: Colors.white, size: 20),
          ),
        ),
        const Spacer(),
        Text('ចុះឈ្មោះ Face ID', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 17)),
        const Spacer(),
        const SizedBox(width: 40),
      ]),
    );
  }

  Widget _buildStepProgress() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 8),
      child: Row(
        children: List.generate(3, (i) {
          final done = i < _currentStep;
          final active = i == _currentStep;
          return Expanded(
            child: Row(children: [
              Expanded(
                child: Column(children: [
                  AnimatedContainer(
                    duration: const Duration(milliseconds: 300),
                    height: 4,
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(2),
                      color: done ? Colors.greenAccent : (active ? Colors.cyanAccent : Colors.white24),
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    'ស្ថានភាព ${i + 1}',
                    style: GoogleFonts.kantumruyPro(
                      color: done ? Colors.greenAccent : (active ? Colors.cyanAccent : Colors.white38),
                      fontSize: 10,
                      fontWeight: active ? FontWeight.bold : FontWeight.normal,
                    ),
                  ),
                ]),
              ),
              if (i < 2) const SizedBox(width: 8),
            ]),
          );
        }),
      ),
    );
  }

  Widget _buildFaceFrame() {
    final color = _isCaptured ? Colors.greenAccent : (_isFaceDetected ? Colors.cyanAccent : Colors.white38);
    return AnimatedBuilder(
      animation: _pulseAnim,
      builder: (context, child) => Transform.scale(
        scale: _isFaceDetected && !_isCaptured ? _pulseAnim.value : 1.0,
        child: child,
      ),
      child: Container(
        width: 220, height: 270,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(130),
          border: Border.all(color: color, width: 3),
          boxShadow: [BoxShadow(color: color.withValues(alpha: 0.35), blurRadius: 24, spreadRadius: 4)],
        ),
        child: _isCaptured
            ? Center(child: ScaleTransition(scale: _successAnim, child: const Icon(Icons.check_circle_rounded, color: Colors.greenAccent, size: 72)))
            : null,
      ),
    );
  }

  Widget _buildHintText() {
    return Column(children: [
      Text(_stepIcons[_currentStep], style: const TextStyle(fontSize: 36)),
      const SizedBox(height: 8),
      Text(_stepTitles[_currentStep], style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 15)),
      const SizedBox(height: 6),
      Text(_stepHints[_currentStep], textAlign: TextAlign.center, style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 13)),
    ]);
  }

  Widget _buildBottomStatus() {
    if (_isSubmitting) return const SizedBox.shrink();
    if (_isCaptured) {
      return _statusPill(Colors.greenAccent, Icons.check_rounded, 'ថតបានជោគជ័យ!');
    }
    if (_isFaceDetected && _captureCountdown < 3) {
      return _statusPill(Colors.cyanAccent, Icons.camera_alt_rounded, 'ថតក្នុង $_captureCountdown វិនាទី...');
    }
    if (_isFaceDetected) {
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 14),
        decoration: BoxDecoration(
          color: Colors.cyanAccent.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(50),
          border: Border.all(color: Colors.cyanAccent.withValues(alpha: 0.4)),
        ),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.cyanAccent)),
          const SizedBox(width: 10),
          Text('ផ្ទៀងផ្ទាត់...', style: GoogleFonts.kantumruyPro(color: Colors.cyanAccent, fontWeight: FontWeight.bold)),
        ]),
      );
    }
    return _statusPill(Colors.white38, Icons.face_rounded, 'ដំឡើងមុខទៅក្នុងក្របខ័ណ្ឌ');
  }

  Widget _statusPill(Color color, IconData icon, String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 14),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(50),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, color: color, size: 18),
        const SizedBox(width: 8),
        Text(label, style: GoogleFonts.kantumruyPro(color: color, fontWeight: FontWeight.bold)),
      ]),
    );
  }
}
