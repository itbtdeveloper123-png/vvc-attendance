import 'dart:ui' as ui;
import 'package:google_mlkit_text_recognition/google_mlkit_text_recognition.dart';

/// OCR Service using Google ML Kit for text recognition
/// Extracts text from scanned document images
class OCRService {
  late final TextRecognizer _textRecognizer;

  /// Initialize the OCR service
  OCRService() {
    // Initialize text recognizer with Latin script (default)
    // For Khmer text support, you would need to use a different script
    _textRecognizer = TextRecognizer(script: TextRecognitionScript.latin);
  }

  /// Extract text from an image file
  /// 
  /// Algorithm:
  /// 1. Create InputImage from the file path
  /// 2. Process the image with ML Kit Text Recognizer
  /// 3. Extract all recognized text blocks
  /// 4. Return formatted text with confidence scores
  Future<OCRResult> extractText(String imagePath) async {
    try {
      // Create InputImage from file
      final inputImage = InputImage.fromFilePath(imagePath);

      // Process the image
      final RecognizedText recognizedText = await _textRecognizer.processImage(inputImage);

      // Extract text blocks with their positions and confidence
      final textBlocks = <TextBlockData>[];
      String fullText = '';

      for (final block in recognizedText.blocks) {
        final blockText = block.text;
        fullText += '$blockText\n';

        // Extract lines within the block
        final lines = <TextLineData>[];
        for (final line in block.lines) {
          final lineText = line.text;
          final lineElements = <TextElementData>[];

          // Extract elements (words) within the line
          for (final element in line.elements) {
            lineElements.add(TextElementData(
              text: element.text,
              boundingBox: _convertRect(element.boundingBox),
              confidence: element.confidence ?? 0.0,
            ));
          }

          lines.add(TextLineData(
            text: lineText,
            boundingBox: _convertRect(line.boundingBox),
            confidence: line.confidence ?? 0.0,
            elements: lineElements,
          ));
        }

        textBlocks.add(TextBlockData(
          text: blockText,
          boundingBox: _convertRect(block.boundingBox),
          confidence: 0.0, // ML Kit doesn't provide block-level confidence
          lines: lines,
        ));
      }

      return OCRResult(
        fullText: fullText.trim(),
        textBlocks: textBlocks,
        success: true,
      );
    } catch (e) {
      return OCRResult(
        fullText: '',
        textBlocks: [],
        success: false,
        error: 'OCR failed: $e',
      );
    }
  }

  /// Extract text with specific language support
  /// 
  /// Parameters:
  /// - imagePath: Path to the image file
  /// - script: Text recognition script (latin, chinese, japanese, korean, etc.)
  Future<OCRResult> extractTextWithScript(
    String imagePath,
    TextRecognitionScript script,
  ) async {
    try {
      // Recreate recognizer with specified script
      await _textRecognizer.close();
      _textRecognizer = TextRecognizer(script: script);

      return await extractText(imagePath);
    } catch (e) {
      return OCRResult(
        fullText: '',
        textBlocks: [],
        success: false,
        error: 'OCR with script failed: $e',
      );
    }
  }

  /// Release resources when done
  Future<void> dispose() async {
    await _textRecognizer.close();
  }

  /// Convert ML Kit Rect to ui.Rect
  ui.Rect _convertRect(dynamic rect) {
    if (rect is ui.Rect) {
      return rect;
    }
    // Handle different rect formats from ML Kit
    return ui.Rect.fromLTRB(
      rect.left.toDouble(),
      rect.top.toDouble(),
      rect.right.toDouble(),
      rect.bottom.toDouble(),
    );
  }
}

/// Data class for OCR result
class OCRResult {
  final String fullText;
  final List<TextBlockData> textBlocks;
  final bool success;
  final String? error;

  OCRResult({
    required this.fullText,
    required this.textBlocks,
    required this.success,
    this.error,
  });

  /// Get text blocks sorted by vertical position (top to bottom)
  List<TextBlockData> get sortedTextBlocks {
    final sorted = List<TextBlockData>.from(textBlocks);
    sorted.sort((a, b) => a.boundingBox.top.compareTo(b.boundingBox.top));
    return sorted;
  }

  /// Get all text as a single string without newlines
  String get compactText => fullText.replaceAll('\n', ' ');

  /// Get word count
  int get wordCount => fullText.split(RegExp(r'\s+')).where((w) => w.isNotEmpty).length;

  /// Get character count (excluding spaces)
  int get charCount => fullText.replaceAll(' ', '').length;
}

/// Data class for a text block (paragraph)
class TextBlockData {
  final String text;
  final ui.Rect boundingBox;
  final double confidence;
  final List<TextLineData> lines;

  TextBlockData({
    required this.text,
    required this.boundingBox,
    required this.confidence,
    required this.lines,
  });

  /// Get lines sorted by horizontal position (left to right)
  List<TextLineData> get sortedLines {
    final sorted = List<TextLineData>.from(lines);
    sorted.sort((a, b) => a.boundingBox.left.compareTo(b.boundingBox.left));
    return sorted;
  }
}

/// Data class for a text line
class TextLineData {
  final String text;
  final ui.Rect boundingBox;
  final double confidence;
  final List<TextElementData> elements;

  TextLineData({
    required this.text,
    required this.boundingBox,
    required this.confidence,
    required this.elements,
  });

  /// Get elements sorted by horizontal position
  List<TextElementData> get sortedElements {
    final sorted = List<TextElementData>.from(elements);
    sorted.sort((a, b) => a.boundingBox.left.compareTo(b.boundingBox.left));
    return sorted;
  }
}

/// Data class for a text element (word)
class TextElementData {
  final String text;
  final ui.Rect boundingBox;
  final double confidence;

  TextElementData({
    required this.text,
    required this.boundingBox,
    required this.confidence,
  });
}
