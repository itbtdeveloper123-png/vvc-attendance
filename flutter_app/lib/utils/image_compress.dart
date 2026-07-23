import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui' as ui;

/// Compresses and resizes image bytes natively using Flutter's C++ engine (dart:ui).
/// If the image dimensions are already small (<= 600px), it returns the original base64 bytes
/// directly without any processing, preserving 100% of the original quality.
Future<String> compressAndEncodeImage(Uint8List imageBytes) async {
  try {
    // 1. Get original image dimensions without full raw allocation
    final ui.Codec codecMeta = await ui.instantiateImageCodec(imageBytes);
    final ui.FrameInfo frameMeta = await codecMeta.getNextFrame();
    final ui.Image origImage = frameMeta.image;

    final int origWidth = origImage.width;
    final int origHeight = origImage.height;

    // Dispose metadata objects immediately to free C++ memory
    origImage.dispose();
    codecMeta.dispose();

    const int maxDimension = 600;

    // Security & Quality check: If image is already small, return original bytes directly
    if (origWidth <= maxDimension && origHeight <= maxDimension) {
      return base64Encode(imageBytes);
    }

    // 2. Calculate target width preserving aspect ratio
    int targetWidth;
    if (origWidth > origHeight) {
      targetWidth = maxDimension;
    } else {
      targetWidth = (origWidth * maxDimension / origHeight).round();
    }

    // 3. Resize natively using Flutter engine
    final ui.Codec codec = await ui.instantiateImageCodec(
      imageBytes,
      targetWidth: targetWidth,
    );
    final ui.FrameInfo frame = await codec.getNextFrame();
    final ui.Image resizedImage = frame.image;

    final ByteData? byteData = await resizedImage.toByteData(format: ui.ImageByteFormat.png);
    
    // Clean up C++ resources
    resizedImage.dispose();
    codec.dispose();

    if (byteData == null) {
      return base64Encode(imageBytes);
    }

    return base64Encode(byteData.buffer.asUint8List());
  } catch (e) {
    // Fallback to original base64 on any exception
    return base64Encode(imageBytes);
  }
}
