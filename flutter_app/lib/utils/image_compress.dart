import 'dart:convert';
import 'dart:typed_data';
import 'package:image/image.dart' as img;

/// Compresses image bytes to a max dimension of 600px and 70% quality,
/// returning the base64 encoded string.
Future<String> compressAndEncodeImage(Uint8List imageBytes) async {
  try {
    final img.Image? original = img.decodeImage(imageBytes);
    if (original == null) {
      return base64Encode(imageBytes);
    }

    int width = original.width;
    int height = original.height;
    const int maxDimension = 600;

    if (width > maxDimension || height > maxDimension) {
      if (width > height) {
        height = (height * maxDimension / width).round();
        width = maxDimension;
      } else {
        width = (width * maxDimension / height).round();
        height = maxDimension;
      }
      // Resize the image
      final img.Image resized = img.copyResize(original, width: width, height: height);
      final List<int> compressedBytes = img.encodeJpg(resized, quality: 70);
      return base64Encode(compressedBytes);
    }

    final List<int> compressedBytes = img.encodeJpg(original, quality: 70);
    return base64Encode(compressedBytes);
  } catch (e) {
    // Fallback to raw base64 if decoding or resizing fails
    return base64Encode(imageBytes);
  }
}
