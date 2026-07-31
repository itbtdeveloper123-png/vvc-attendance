# Document Scanner Module - CamScanner Clone

A comprehensive Flutter module for document scanning with OpenCV edge detection, image enhancement, and ML Kit OCR functionality.

## 📋 Features

- **Auto-Edge Detection & Perspective Crop**: Automatically detects document boundaries and straightens images
- **Image Enhancement Filters**: Magic Color, B&W, and Enhanced filters for document optimization
- **High-Accuracy OCR**: Text extraction using Google ML Kit
- **PDF Export**: Export scanned documents as PDF files
- **Clean Workflow UI**: Step-by-step scanning process with preview and editing

## 🔧 Required Dependencies

Add these to your `pubspec.yaml`:

```yaml
dependencies:
  opencv_dart: ^1.0.0
  google_mlkit_text_recognition: ^0.11.0
  image_picker: ^1.2.3
  pdf: ^3.10.0
  printing: ^5.10.0
  path_provider: ^2.1.6
  path: ^1.9.0
```

## 📁 File Structure

```
lib/
├── screens/
│   └── document_scanner_screen.dart    # Main scanner screen with workflow
├── services/
│   ├── opencv_service.dart             # OpenCV processing logic
│   └── ocr_service.dart                # ML Kit OCR service
└── widgets/
    ├── document_preview_widget.dart     # Image preview components
    └── filter_selection_widget.dart   # Filter selection UI
```

## 🚀 Usage

### Basic Integration

```dart
import 'package:flutter/material.dart';
import 'screens/document_scanner_screen.dart';

// Navigate to the scanner
Navigator.push(
  context,
  MaterialPageRoute(
    builder: (context) => const DocumentScannerScreen(),
  ),
);
```

### Using Individual Components

#### 1. OpenCV Service

```dart
import 'services/opencv_service.dart';

// Detect document edges
final corners = await OpenCVService.detectDocumentEdges(imagePath);

// Apply perspective transform
final croppedPath = await OpenCVService.perspectiveTransform(
  imagePath,
  corners,
  outputPath,
);

// Apply Magic Color filter
final enhancedPath = await OpenCVService.applyMagicColorFilter(
  imagePath,
  outputPath,
);

// Apply B&W filter
final bwPath = await OpenCVService.applyBWFilter(imagePath, outputPath);

// Adjust contrast and brightness
final adjustedPath = await OpenCVService.adjustContrastBrightness(
  imagePath,
  outputPath,
  alpha: 1.3,  // Contrast factor
  beta: 50,     // Brightness offset
);
```

#### 2. OCR Service

```dart
import 'services/ocr_service.dart';

final ocrService = OCRService();

// Extract text from image
final result = await ocrService.extractText(imagePath);

if (result.success) {
  print('Extracted text: ${result.fullText}');
  print('Word count: ${result.wordCount}');
  print('Character count: ${result.charCount}');
  
  // Access individual text blocks
  for (final block in result.sortedTextBlocks) {
    print('Block: ${block.text}');
    for (final line in block.lines) {
      print('Line: ${line.text}');
    }
  }
}

// Don't forget to dispose
await ocrService.dispose();
```

#### 3. Preview Widgets

```dart
import 'widgets/document_preview_widget.dart';

DocumentPreviewWidget(
  imagePath: processedImagePath,
  isLoading: isProcessing,
  errorMessage: error,
  onRetry: () => retryProcessing(),
  loadingMessage: 'Detecting edges...',
)
```

#### 4. Filter Selection

```dart
import 'widgets/filter_selection_widget.dart';

FilterSelectionWidget(
  baseImagePath: originalPath,
  selectedFilter: currentFilter,
  filters: FilterOption.documentFilters,
  onFilterSelected: (filterId) {
    // Apply selected filter
    applyFilter(filterId);
  },
  isLoading: isProcessing,
)
```

## 🔍 Algorithm Explanations

### Edge Detection Algorithm

1. **Grayscale Conversion**: Convert image to grayscale for edge detection
2. **Gaussian Blur**: Apply 5x5 Gaussian kernel to reduce noise
3. **Canny Edge Detection**: Use thresholds (50, 150) to detect edges
4. **Contour Detection**: Find contours using RETR_EXTERNAL method
5. **Largest Contour**: Select the largest quadrilateral contour
6. **Corner Approximation**: Use Douglas-Peucker algorithm with 2% epsilon to approximate to 4 corners

### Perspective Transform Algorithm

1. **Corner Ordering**: Sort corners to consistent order (TL, TR, BR, BL)
2. **Dimension Calculation**: Calculate max width and height from corner distances
3. **Transform Matrix**: Create perspective transform matrix using source and destination points
4. **Warp Perspective**: Apply transformation to straighten the document

### Magic Color Filter Algorithm

1. **Grayscale Conversion**: Convert to grayscale
2. **Adaptive Thresholding**: Use Gaussian-weighted adaptive thresholding (block size 11, C=2)
3. **CLAHE Enhancement**: Apply Contrast Limited Adaptive Histogram Equalization (clip limit 2.0, tile grid 8x8)
4. **Color Conversion**: Convert back to BGR for display

### B&W Filter Algorithm

1. **Grayscale Conversion**: Convert to grayscale
2. **Otsu's Thresholding**: Automatically calculate optimal threshold using Otsu's method
3. **Binary Conversion**: Apply threshold to create pure black and white image

## 📱 Scanner Workflow

The scanner follows this step-by-step workflow:

1. **Select Image**: User captures or selects a document image
2. **Edge Detection**: OpenCV automatically detects document boundaries
3. **Perspective Crop**: Image is cropped and straightened
4. **Filter Selection**: User selects enhancement filter (Original, Magic Color, B&W, Enhanced)
5. **OCR Processing**: Extract text using ML Kit (optional)
6. **PDF Export**: Export processed document as PDF

## 🎨 Customization

### Adding Custom Filters

```dart
// In FilterOption class
static const List<FilterOption> customFilters = [
  FilterOption(
    id: 'custom',
    label: 'Custom',
    description: 'Your custom filter',
    overlayColor: Colors.blue.withOpacity(0.1),
    icon: Icons.tune,
  ),
];
```

### Custom OpenCV Processing

```dart
// Add your custom processing method to OpenCVService
static Future<String> applyCustomFilter(
  String inputPath,
  String outputPath,
) async {
  // Your custom OpenCV processing
  // ...
  return outputPath;
}
```

## 🐛 Error Handling

The module includes comprehensive error handling:

- **Image Loading Errors**: Caught and displayed with retry option
- **Edge Detection Failures**: Falls back to original image if no document detected
- **OCR Errors**: Gracefully handles OCR failures without crashing
- **Memory Management**: Proper disposal of OpenCV Mat objects

## 🔐 Permissions

Add these permissions to your `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
```

Add to your `Info.plist` for iOS:

```xml
<key>NSCameraUsageDescription</key>
<string>We need camera access to scan documents</string>
<key>NSPhotoLibraryUsageDescription</key>
<string>We need photo library access to select documents</string>
```

## 📊 Performance Considerations

- **Image Resolution**: Images are resized to max 2000px width for performance
- **Memory Management**: OpenCV Mat objects are properly disposed
- **Async Processing**: All image processing runs asynchronously to avoid UI blocking
- **Temporary Files**: Temporary files are cleaned up on disposal

## 🧪 Testing

Test the module with different document types:

- **Text Documents**: Contracts, letters, forms
- **ID Cards**: Driver's licenses, passports
- **Receipts**: Various lighting conditions
- **Multi-page Documents**: Test OCR accuracy

## 🔄 Future Enhancements

Potential improvements for the module:

- **Multi-page PDF Support**: Scan multiple pages into single PDF
- **Batch Processing**: Process multiple images at once
- **Khmer OCR Support**: Add Khmer language recognition
- **Cloud Storage Integration**: Save scanned documents to cloud
- **Document Organization**: Folder and tag system
- **Search**: Full-text search across scanned documents

## 📝 Notes

- The module uses `opencv_dart` which is a Dart wrapper around OpenCV
- ML Kit OCR works best with clear, high-contrast text
- Edge detection works best with documents against contrasting backgrounds
- For best results, ensure good lighting when capturing documents

## 🆘 Troubleshooting

**Edge detection not working:**
- Ensure document has clear edges
- Improve lighting conditions
- Use contrasting background

**OCR accuracy low:**
- Apply Magic Color filter first
- Ensure text is sharp and clear
- Check image resolution

**Memory issues:**
- Reduce image resolution before processing
- Dispose of OCR service when not needed
- Clean up temporary files regularly

## 📞 Support

For issues or questions about this module, please refer to:
- OpenCV documentation: https://docs.opencv.org/
- ML Kit documentation: https://developers.google.com/ml-kit
- Flutter documentation: https://flutter.dev/docs
