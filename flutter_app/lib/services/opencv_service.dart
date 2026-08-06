/// OpenCV Service - Deprecated
/// 
/// This service has been deprecated in favor of native document scanning.
/// The app now uses cunning_document_scanner which provides:
/// - ML Kit Document Scanner API on Android
/// - Apple VisionKit Document Camera on iOS
/// 
/// For document scanning functionality, use the native scanner directly
/// through the DocumentScannerScreen.
class OpenCVService {
  /// This service is deprecated and should not be used
  /// Use cunning_document_scanner instead
  @Deprecated('Use cunning_document_scanner package for native document scanning')
  factory OpenCVService() {
    throw UnimplementedError(
      'OpenCVService is deprecated. Use cunning_document_scanner package for native document scanning instead.',
    );
  }
}
