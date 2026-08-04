import 'package:flutter/foundation.dart';
import 'package:google_mlkit_digital_ink_recognition/google_mlkit_digital_ink_recognition.dart';

/// Digital Ink Recognition Service (Handwriting & Shape recognition in 300+ languages)
class DigitalInkService {
  final DigitalInkRecognizerModelManager _modelManager = DigitalInkRecognizerModelManager();
  
  DigitalInkRecognizer? _recognizer;
  String _currentLanguageCode = 'en-US';

  DigitalInkService() {
    _initRecognizer('en-US');
  }

  Future<void> _initRecognizer(String languageCode) async {
    try {
      await _recognizer?.close();
      _currentLanguageCode = languageCode;
      _recognizer = DigitalInkRecognizer(languageCode: languageCode);
    } catch (e) {
      debugPrint('Error initializing Digital Ink Recognizer: $e');
    }
  }

  /// Download model if needed
  Future<bool> downloadModel(String languageCode) async {
    try {
      final isDownloaded = await _modelManager.isModelDownloaded(languageCode);
      if (!isDownloaded) {
        final downloaded = await _modelManager.downloadModel(languageCode);
        return downloaded;
      }
      return true;
    } catch (e) {
      debugPrint('Error downloading model $languageCode: $e');
      return false;
    }
  }

  /// Switch language model (e.g. 'km-KH', 'en-US', 'zxx-x-autodraw')
  Future<void> switchLanguage(String languageCode) async {
    await downloadModel(languageCode);
    await _initRecognizer(languageCode);
  }

  /// Recognize strokes drawn on canvas
  Future<List<RecognitionCandidate>> recognizeInk(Ink ink) async {
    if (_recognizer == null) {
      await _initRecognizer(_currentLanguageCode);
    }
    try {
      final candidates = await _recognizer!.recognize(ink);
      return candidates;
    } catch (e) {
      debugPrint('Digital Ink Recognition error: $e');
      return [];
    }
  }

  void dispose() {
    try {
      _recognizer?.close();
    } catch (_) {}
  }
}
