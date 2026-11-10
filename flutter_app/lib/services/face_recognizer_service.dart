import 'dart:io';
import 'dart:math';
import 'dart:ui' show Rect;
import 'package:flutter/foundation.dart';
import 'package:image/image.dart' as img;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:tflite_flutter/tflite_flutter.dart';
import 'package:google_mlkit_face_detection/google_mlkit_face_detection.dart';

// ========================
// FaceRecognizerService
// ========================
// On-device Face Recognition using TensorFlow Lite (MobileFaceNet)
// Free, Offline, On-Device, Privacy-First
// ========================

class FaceRecognizerService {
  static final FaceRecognizerService _instance = FaceRecognizerService._internal();
  factory FaceRecognizerService() => _instance;
  FaceRecognizerService._internal();

  Interpreter? _interpreter;
  bool _initialized = false;
  bool _modelLoadFailed = false;

  /// Reusable FaceDetector instances to avoid high native allocation overhead on every scan
  FaceDetector? _faceDetector;
  FaceDetector get _detector => _faceDetector ??= FaceDetector(
        options: FaceDetectorOptions(performanceMode: FaceDetectorMode.fast),
      );

  FaceDetector? _livenessDetector;
  FaceDetector get _liveDetector => _livenessDetector ??= FaceDetector(
        options: FaceDetectorOptions(
          performanceMode: FaceDetectorMode.accurate,
          enableClassification: true,
          enableLandmarks: true,
        ),
      );

  /// In-memory cache of parsed embeddings to eliminate redundant disk I/O and double parsing
  final Map<String, List<List<double>>> _memoryEmbeddings = {};

  /// Input size for MobileFaceNet (112 x 112 RGB)
  static const int inputSize = 112;
  /// Embedding vector dimension
  static const int embeddingDim = 192;

  /// Initialize TFLite model interpreter
  Future<void> init() async {
    if (_initialized || _modelLoadFailed) return;
    try {
      final options = InterpreterOptions()..threads = 4;
      _interpreter = await Interpreter.fromAsset(
        'assets/models/mobile_face_net.tflite',
        options: options,
      );
      _initialized = true;
      debugPrint('[FaceRecognizer] MobileFaceNet model initialized successfully ✅');
    } catch (e) {
      _modelLoadFailed = true;
      debugPrint('[FaceRecognizer] Model load note: $e (Using fallback mode)');
    }
  }

  /// Register a face for a user ID by saving embedding or photo path
  Future<bool> registerFace({
    required String userId,
    required String imagePath,
    required String imageId,
  }) async {
    await init();
    try {
      final file = File(imagePath);
      if (!file.existsSync()) return false;

      // Invalidate memory cache so next verification picks up new embeddings
      _memoryEmbeddings.remove(userId);

      final embedding = await extractEmbedding(imagePath);
      final prefs = await SharedPreferences.getInstance();

      if (embedding != null && embedding.isNotEmpty) {
        final key = 'face_embedding_${userId}_$imageId';
        final strList = embedding.map((e) => e.toString()).toList();
        await prefs.setStringList(key, strList);
        await prefs.setBool('face_registered_$userId', true);
        debugPrint('[FaceRecognizer] Registered embedding for $userId ($imageId) ✅');
      } else {
        // Backup: record registration flag
        await prefs.setBool('face_registered_$userId', true);
        debugPrint('[FaceRecognizer] Registered fallback status for $userId ✅');
      }
      return true;
    } catch (e) {
      debugPrint('[FaceRecognizer] Register error: $e');
      return false;
    }
  }

  /// Extract 192D float embedding from image file
  Future<List<double>?> extractEmbedding(String imagePath) async {
    await init();
    if (_interpreter == null) return null;

    try {
      final inputImage = InputImage.fromFilePath(imagePath);
      final faces = await _detector.processImage(inputImage);

      final bytes = await File(imagePath).readAsBytes();

      Rect? faceRect;
      if (faces.isNotEmpty) {
        faceRect = faces.first.boundingBox;
      }

      // Offload heavy CPU image decoding & cropping to background isolate via compute()
      final input = await compute(
        _preprocessFaceImage,
        _FaceCropParams(
          bytes: bytes,
          rectLeft: faceRect?.left.toInt(),
          rectTop: faceRect?.top.toInt(),
          rectWidth: faceRect?.width.toInt(),
          rectHeight: faceRect?.height.toInt(),
          inputSize: inputSize,
        ),
      );

      if (input == null) return null;

      // Input tensor shape: [1, 112, 112, 3]
      final inputTensor = input.reshape([1, inputSize, inputSize, 3]);
      // Output tensor shape: [1, 192]
      final outputTensor = List.generate(1, (_) => List<double>.filled(embeddingDim, 0.0));

      // Run inference
      _interpreter!.run(inputTensor, outputTensor);

      final result = outputTensor[0];
      // Normalize embedding vector to unit length (L2 norm)
      return _l2Normalize(result);
    } catch (e) {
      debugPrint('[FaceRecognizer] Extract embedding error: $e');
      return null;
    }
  }

  /// Verify live face image against registered face embeddings for userId
  Future<FaceVerifyResult> verifyFace({
    required String imagePath,
    String? userId,
    double threshold = 0.65,
  }) async {
    await init();
    try {
      if (!File(imagePath).existsSync()) {
        return const FaceVerifyResult(
          matched: false,
          matchedUserId: null,
          error: 'មិនរកឃើញឯកសាររូបថត',
        );
      }

      if (userId == null || userId.isEmpty) {
        return const FaceVerifyResult(
          matched: false, 
          matchedUserId: null,
          error: 'មិនមានព័ត៌មានអ្នកប្រើប្រាស់ដើម្បីផ្ទៀងផ្ទាត់',
        );
      }

      // Check if user is registered
      final registered = await isFaceRegistered(userId);
      if (!registered) {
        return const FaceVerifyResult(
          matched: false, 
          error: 'មិនទាន់មានទិន្នន័យផ្ទៃមុខនៅក្នុងប្រព័ន្ធទេ សូមចុះឈ្មោះជាមុនសិន',
        );
      }

      final liveEmbedding = await extractEmbedding(imagePath);
      if (liveEmbedding == null) {
        return const FaceVerifyResult(
          matched: false, 
          error: 'ប្រព័ន្ធមិនអាចដំណើរការការសម្គាល់ផ្ទៃមុខបានទេ (អាចមកពីបញ្ហាម៉ូដែល AI ឫរូបភាព)',
        );
      }

      // Load stored embeddings (utilize in-memory cache to skip repeated SharedPreferences I/O)
      List<List<double>> storedList = _memoryEmbeddings[userId] ?? [];
      if (storedList.isEmpty) {
        final prefs = await SharedPreferences.getInstance();
        for (final label in ['front', 'left', 'right', 'profile_pic']) {
          final key = 'face_embedding_${userId}_$label';
          final strList = prefs.getStringList(key);
          if (strList != null && strList.isNotEmpty) {
            final storedEmbedding = strList.map((s) => double.tryParse(s) ?? 0.0).toList();
            if (storedEmbedding.isNotEmpty) {
              storedList.add(storedEmbedding);
            }
          }
        }
        if (storedList.isNotEmpty) {
          _memoryEmbeddings[userId] = storedList;
        }
      }

      double maxSimilarity = -1.0;
      for (final storedEmbedding in storedList) {
        final sim = cosineSimilarity(liveEmbedding, storedEmbedding);
        if (sim > maxSimilarity) {
          maxSimilarity = sim;
        }
      }

      debugPrint('[FaceRecognizer] Max Similarity for $userId: $maxSimilarity (Threshold: $threshold)');

      if (maxSimilarity >= threshold) {
        return FaceVerifyResult(matched: true, matchedUserId: userId);
      } else {
        return FaceVerifyResult(
          matched: false,
          matchedUserId: userId,
          error: 'ផ្ទៃមុខមិនត្រូវគ្នានឹងទិន្នន័យដែលបានចុះឈ្មោះ (${(maxSimilarity * 100).toStringAsFixed(1)}%)',
        );
      }
    } catch (e) {
      debugPrint('[FaceRecognizer] Verify exception: $e');
      return FaceVerifyResult(
        matched: false, 
        matchedUserId: userId,
        error: 'កំហុសក្នុងការផ្ទៀងផ្ទាត់ផ្ទៃមុខ៖ $e',
      );
    }
  }

  /// Check if user has registered face
  Future<bool> isFaceRegistered(String userId) async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getBool('face_registered_$userId') ?? false;
  }

  /// Delete all stored faces for user
  Future<void> deleteAllFaces(String userId) async {
    _memoryEmbeddings.remove(userId);
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('face_registered_$userId');
    for (final label in ['front', 'left', 'right', 'profile_pic']) {
      await prefs.remove('face_embedding_${userId}_$label');
    }
  }

  /// Calculate Cosine Similarity between two embedding vectors
  double cosineSimilarity(List<double> v1, List<double> v2) {
    if (v1.length != v2.length || v1.isEmpty) return 0.0;
    double dotProduct = 0.0;
    double normA = 0.0;
    double normB = 0.0;
    for (int i = 0; i < v1.length; i++) {
      final double a = v1[i];
      final double b = v2[i];
      dotProduct += a * b;
      normA += a * a;
      normB += b * b;
    }
    if (normA == 0.0 || normB == 0.0) return 0.0;
    return dotProduct / (sqrt(normA) * sqrt(normB));
  }

  /// Normalize vector to unit length (L2 normalization)
  List<double> _l2Normalize(List<double> vector) {
    double sum = 0.0;
    for (final v in vector) {
      sum += v * v;
    }
    final norm = sqrt(sum);
    if (norm == 0) return vector;
    return vector.map((v) => v / norm).toList();
  }

  /// Detect face and inspect liveness metrics (eye blink / smile probability)
  Future<FaceLivenessResult> checkImageLiveness(String imagePath) async {
    try {
      final inputImage = InputImage.fromFilePath(imagePath);
      final faces = await _liveDetector.processImage(inputImage);

      if (faces.isEmpty) {
        return const FaceLivenessResult(
          isLive: false,
          feedbackMessage: 'មិនបានរកឃើញផ្ទៃមុខច្បាស់លាស់ទេ សូមតម្រង់មុខចំកាមេរ៉ា',
        );
      }

      final face = faces.first;
      final leftEye = face.leftEyeOpenProbability ?? 1.0;
      final rightEye = face.rightEyeOpenProbability ?? 1.0;
      final smile = face.smilingProbability ?? 0.0;

      final bool eyeBlinked = (leftEye < 0.25 || rightEye < 0.25);
      final bool isSmiling = smile > 0.45;

      return FaceLivenessResult(
        isLive: true,
        hasBlinked: eyeBlinked,
        hasSmiled: isSmiling,
        leftEyeOpenProb: leftEye,
        rightEyeOpenProb: rightEye,
        smileProb: smile,
        feedbackMessage: eyeBlinked
            ? 'បានរកឃើញចលនាព្រិចភ្នែក ✅'
            : (isSmiling ? 'បានរកឃើញស្នាមញញឹម ✅' : 'ផ្ទៃមុខធម្មជាតិ'),
      );
    } catch (e) {
      debugPrint('[FaceRecognizer] Liveness error: $e');
      return FaceLivenessResult(
        isLive: false,
        feedbackMessage: 'កំហុសក្នុងការត្រួតពិនិត្យភាពរស់រវើក៖ $e',
      );
    }
  }

  void dispose() {
    _interpreter?.close();
    _faceDetector?.close();
    _livenessDetector?.close();
    _interpreter = null;
    _faceDetector = null;
    _livenessDetector = null;
    _memoryEmbeddings.clear();
    _initialized = false;
  }
}

// ========================
// Background Isolate Worker
// ========================
class _FaceCropParams {
  final Uint8List bytes;
  final int? rectLeft;
  final int? rectTop;
  final int? rectWidth;
  final int? rectHeight;
  final int inputSize;

  const _FaceCropParams({
    required this.bytes,
    this.rectLeft,
    this.rectTop,
    this.rectWidth,
    this.rectHeight,
    required this.inputSize,
  });
}

/// Offloads heavy CPU image decoding & cropping to background isolate
Float32List? _preprocessFaceImage(_FaceCropParams params) {
  try {
    final decodedImage = img.decodeImage(params.bytes);
    if (decodedImage == null) return null;

    img.Image faceCrop = decodedImage;
    if (params.rectLeft != null &&
        params.rectTop != null &&
        params.rectWidth != null &&
        params.rectHeight != null) {
      final int x = max(0, params.rectLeft!);
      final int y = max(0, params.rectTop!);
      final int w = min(decodedImage.width - x, params.rectWidth!);
      final int h = min(decodedImage.height - y, params.rectHeight!);

      if (w > 0 && h > 0) {
        faceCrop = img.copyCrop(decodedImage, x: x, y: y, width: w, height: h);
      }
    }

    // Resize cropped face to 112x112
    final resized = img.copyResize(faceCrop, width: params.inputSize, height: params.inputSize);

    // Preprocess image bytes to float array [-1, 1]
    final input = Float32List(1 * params.inputSize * params.inputSize * 3);
    int pixelIndex = 0;

    for (int y = 0; y < params.inputSize; y++) {
      for (int x = 0; x < params.inputSize; x++) {
        final pixel = resized.getPixel(x, y);
        // Normalize (value - 127.5) / 127.5
        input[pixelIndex++] = (pixel.r - 127.5) / 127.5;
        input[pixelIndex++] = (pixel.g - 127.5) / 127.5;
        input[pixelIndex++] = (pixel.b - 127.5) / 127.5;
      }
    }
    return input;
  } catch (e) {
    return null;
  }
}

// Result models
class FaceVerifyResult {
  final bool matched;
  final String? matchedUserId;
  final String? error;

  const FaceVerifyResult({
    required this.matched,
    this.matchedUserId,
    this.error,
  });
}

class FaceLivenessResult {
  final bool isLive;
  final bool hasBlinked;
  final bool hasSmiled;
  final double? leftEyeOpenProb;
  final double? rightEyeOpenProb;
  final double? smileProb;
  final String? feedbackMessage;

  const FaceLivenessResult({
    required this.isLive,
    this.hasBlinked = false,
    this.hasSmiled = false,
    this.leftEyeOpenProb,
    this.rightEyeOpenProb,
    this.smileProb,
    this.feedbackMessage,
  });
}
