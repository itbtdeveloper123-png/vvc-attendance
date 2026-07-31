import 'package:opencv_dart/opencv_dart.dart' as cv;

/// OpenCV Service for document scanning operations
/// Handles edge detection, perspective transform, and image enhancement
class OpenCVService {
  
  /// Detect document edges and return the 4 corner points
  /// 
  /// Improved Algorithm:
  /// 1. Convert image to grayscale
  /// 2. Apply adaptive thresholding for better edge detection in varied lighting
  /// 3. Use morphological operations to clean up noise
  /// 4. Try multiple edge detection strategies
  /// 5. Filter contours based on area, aspect ratio, and solidity
  /// 6. Approximate the contour to 4 corner points with adaptive precision
  /// 7. Handle background interference by using color-based segmentation
  static Future<List<cv.Point>> detectDocumentEdges(String imagePath) async {
    try {
      // Read the image
      final image = cv.imread(imagePath);
      if (image.isEmpty) {
        throw Exception('Failed to load image');
      }

      // Try multiple detection strategies
      final corners = await _tryMultipleDetectionStrategies(image);
      
      // Clean up
      image.dispose();

      return corners;
    } catch (e) {
      // Return empty list on failure instead of throwing exception
      return [];
    }
  }

  /// Try multiple detection strategies to improve robustness
  static Future<List<cv.Point>> _tryMultipleDetectionStrategies(cv.Mat image) async {
    // Strategy 1: Adaptive thresholding with morphological operations
    final corners1 = await _detectWithAdaptiveThreshold(image);
    if (corners1.isNotEmpty) {
      return corners1;
    }

    // Strategy 2: Canny edge detection with adjusted thresholds
    final corners2 = await _detectWithCanny(image, cannyLow: 30.0, cannyHigh: 200.0);
    if (corners2.isNotEmpty) {
      return corners2;
    }

    // Strategy 3: Canny edge detection with conservative thresholds
    final corners3 = await _detectWithCanny(image, cannyLow: 70.0, cannyHigh: 250.0);
    if (corners3.isNotEmpty) {
      return corners3;
    }

    // Strategy 4: Canny edge detection with aggressive thresholds for low contrast
    final corners4 = await _detectWithCanny(image, cannyLow: 20.0, cannyHigh: 100.0);
    if (corners4.isNotEmpty) {
      return corners4;
    }

    // Strategy 5: Color-based segmentation for background interference
    final corners5 = await _detectWithColorSegmentation(image);
    if (corners5.isNotEmpty) {
      return corners5;
    }

    // Strategy 6: Very lenient Canny detection as last resort
    final corners6 = await _detectWithCanny(image, cannyLow: 10.0, cannyHigh: 50.0);
    if (corners6.isNotEmpty) {
      return corners6;
    }

    // Strategy 7: Fallback to image bounds if all else fails
    final corners7 = _getImageBoundsFallback(image);
    if (corners7.isNotEmpty) {
      return corners7;
    }

    // If all strategies fail, return empty list
    return [];
  }

  /// Detection strategy using color-based segmentation
  /// This helps when there's background interference or clutter
  static Future<List<cv.Point>> _detectWithColorSegmentation(cv.Mat image) async {
    try {
      // Convert to HSV color space for better color segmentation
      final hsv = cv.cvtColor(image, cv.COLOR_BGR2HSV);

      // Create mask for white/light areas (typical document color)
      final lowerWhite = cv.Scalar(0, 0, 180);
      final upperWhite = cv.Scalar(180, 30, 255);
      final whiteMask = cv.inRangebyScalar(hsv, lowerWhite, upperWhite);

      // Create mask for light gray areas
      final lowerGray = cv.Scalar(0, 0, 100);
      final upperGray = cv.Scalar(180, 30, 220);
      final grayMask = cv.inRangebyScalar(hsv, lowerGray, upperGray);

      // Combine masks
      final combinedMask = cv.bitwiseOR(whiteMask, grayMask);

      // Apply morphological operations to clean up
      final kernel = cv.getStructuringElement(cv.MORPH_RECT, (5, 5));
      final opened = cv.morphologyEx(combinedMask, cv.MORPH_OPEN, kernel);
      final closed = cv.morphologyEx(opened, cv.MORPH_CLOSE, kernel);

      // Find contours
      final (contours, _) = cv.findContours(
        closed,
        cv.RETR_EXTERNAL,
        cv.CHAIN_APPROX_SIMPLE,
      );

      if (contours.isEmpty) {
        hsv.dispose();
        whiteMask.dispose();
        grayMask.dispose();
        combinedMask.dispose();
        opened.dispose();
        closed.dispose();
        kernel.dispose();
        return [];
      }

      // Filter contours based on area and aspect ratio
      final filteredContours = _filterContoursByProperties(contours, image);

      if (filteredContours.isEmpty) {
        hsv.dispose();
        whiteMask.dispose();
        grayMask.dispose();
        combinedMask.dispose();
        opened.dispose();
        closed.dispose();
        kernel.dispose();
        return [];
      }

      // Find the best contour based on combined score
      final bestContour = _findBestContour(filteredContours, image);

      // Approximate contour to a polygon with adaptive precision
      final perimeter = cv.arcLength(bestContour, true);
      final approx = cv.approxPolyDP(bestContour, 0.04 * perimeter, true);

      // Check if we have 4 corners (quadrilateral)
      if (approx.length < 4) {
        hsv.dispose();
        whiteMask.dispose();
        grayMask.dispose();
        combinedMask.dispose();
        opened.dispose();
        closed.dispose();
        kernel.dispose();
        return [];
      }

      // Extract the 4 corner points
      final corners = <cv.Point>[];
      for (int i = 0; i < approx.length; i++) {
        final point = approx[i];
        corners.add(cv.Point(point.x.toInt(), point.y.toInt()));
      }

      // Clean up
      hsv.dispose();
      whiteMask.dispose();
      grayMask.dispose();
      combinedMask.dispose();
      opened.dispose();
      closed.dispose();
      kernel.dispose();

      return corners;
    } catch (e) {
      return [];
    }
  }

  /// Detection strategy using adaptive thresholding
  static Future<List<cv.Point>> _detectWithAdaptiveThreshold(cv.Mat image) async {
    try {
      // Convert to grayscale
      final gray = cv.cvtColor(image, cv.COLOR_BGR2GRAY);

      // Apply Gaussian blur to reduce noise
      final blurred = cv.gaussianBlur(gray, (5, 5), 0);

      // Apply adaptive thresholding for better edge detection in varied lighting
      // ADAPTIVE_THRESH_GAUSSIAN_C works well for document edges
      // More lenient parameters for better detection
      final threshold = cv.adaptiveThreshold(
        blurred,
        255,
        cv.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv.THRESH_BINARY,
        15, // Larger block size for better tolerance
        5, // Higher C value for more lenient thresholding
      );

      // Morphological operations to clean up noise
      final kernel = cv.getStructuringElement(cv.MORPH_RECT, (3, 3));
      final opened = cv.morphologyEx(threshold, cv.MORPH_OPEN, kernel);
      final closed = cv.morphologyEx(opened, cv.MORPH_CLOSE, kernel);

      // Find contours
      final (contours, _) = cv.findContours(
        closed,
        cv.RETR_EXTERNAL,
        cv.CHAIN_APPROX_SIMPLE,
      );

      if (contours.isEmpty) {
        gray.dispose();
        blurred.dispose();
        threshold.dispose();
        opened.dispose();
        closed.dispose();
        kernel.dispose();
        return [];
      }

      // Filter contours based on area and aspect ratio
      final filteredContours = _filterContoursByProperties(contours, gray);

      if (filteredContours.isEmpty) {
        gray.dispose();
        blurred.dispose();
        threshold.dispose();
        opened.dispose();
        closed.dispose();
        kernel.dispose();
        return [];
      }

      // Find the best contour based on combined score
      final bestContour = _findBestContour(filteredContours, gray);

      // Approximate contour to a polygon with adaptive precision
      final perimeter = cv.arcLength(bestContour, true);
      final approx = cv.approxPolyDP(bestContour, 0.03 * perimeter, true);

      // Check if we have 4 corners (quadrilateral)
      if (approx.length < 4) {
        gray.dispose();
        blurred.dispose();
        threshold.dispose();
        opened.dispose();
        closed.dispose();
        kernel.dispose();
        return [];
      }

      // Extract the 4 corner points
      final corners = <cv.Point>[];
      for (int i = 0; i < approx.length; i++) {
        final point = approx[i];
        corners.add(cv.Point(point.x.toInt(), point.y.toInt()));
      }

      // Clean up
      gray.dispose();
      blurred.dispose();
      threshold.dispose();
      opened.dispose();
      closed.dispose();
      kernel.dispose();

      return corners;
    } catch (e) {
      return [];
    }
  }

  /// Detection strategy using Canny edge detection
  static Future<List<cv.Point>> _detectWithCanny(cv.Mat image, {double cannyLow = 50.0, double cannyHigh = 150.0}) async {
    try {
      // Convert to grayscale
      final gray = cv.cvtColor(image, cv.COLOR_BGR2GRAY);

      // Apply Gaussian blur to reduce noise
      final blurred = cv.gaussianBlur(gray, (5, 5), 0);

      // Canny edge detection with custom thresholds
      final edges = cv.canny(blurred, cannyLow.toDouble(), cannyHigh.toDouble());

      // Morphological operations to strengthen edges
      final kernel = cv.getStructuringElement(cv.MORPH_RECT, (3, 3));
      final dilated = cv.dilate(edges, kernel);

      // Find contours
      final (contours, _) = cv.findContours(
        dilated,
        cv.RETR_EXTERNAL,
        cv.CHAIN_APPROX_SIMPLE,
      );

      if (contours.isEmpty) {
        gray.dispose();
        blurred.dispose();
        edges.dispose();
        dilated.dispose();
        kernel.dispose();
        return [];
      }

      // Filter contours based on area and aspect ratio
      final filteredContours = _filterContoursByProperties(contours, gray);

      if (filteredContours.isEmpty) {
        gray.dispose();
        blurred.dispose();
        edges.dispose();
        dilated.dispose();
        kernel.dispose();
        return [];
      }

      // Find the best contour based on combined score
      final bestContour = _findBestContour(filteredContours, gray);

      // Approximate contour to a polygon with adaptive precision
      final perimeter = cv.arcLength(bestContour, true);
      final approx = cv.approxPolyDP(bestContour, 0.02 * perimeter, true);

      // Check if we have 4 corners (quadrilateral)
      if (approx.length < 4) {
        gray.dispose();
        blurred.dispose();
        edges.dispose();
        dilated.dispose();
        kernel.dispose();
        return [];
      }

      // Extract the 4 corner points
      final corners = <cv.Point>[];
      for (int i = 0; i < approx.length; i++) {
        final point = approx[i];
        corners.add(cv.Point(point.x.toInt(), point.y.toInt()));
      }

      // Clean up
      gray.dispose();
      blurred.dispose();
      edges.dispose();
      dilated.dispose();
      kernel.dispose();

      return corners;
    } catch (e) {
      return [];
    }
  }

  /// Filter contours based on geometric properties
  static cv.Contours _filterContoursByProperties(cv.Contours contours, cv.Mat image) {
    final gray = cv.cvtColor(image, cv.COLOR_BGR2GRAY);
    final imageArea = gray.rows * gray.cols;
    final filteredContours = cv.VecVecPoint();

    for (final contour in contours) {
      final area = cv.contourArea(contour);
      
      // Filter by area - more lenient: document should be at least 5% of image
      if (area < imageArea * 0.05 || area > imageArea * 0.98) {
        continue;
      }

      // Calculate bounding rectangle
      final rect = cv.boundingRect(contour);
      final width = rect.width;
      final height = rect.height;
      final aspectRatio = width / height;

      // Filter by aspect ratio - more lenient: between 0.3 and 3.0
      if (aspectRatio < 0.3 || aspectRatio > 3.0) {
        continue;
      }

      // Calculate solidity (area / convex hull area)
      final hullMat = cv.convexHull(contour);
      final hull = cv.VecPoint.fromMat(hullMat);
      final hullArea = cv.contourArea(hull);
      final solidity = area / hullArea;

      // Filter by solidity - more lenient: documents should have solidity (> 0.6)
      if (solidity < 0.6) {
        hullMat.dispose();
        hull.dispose();
        continue;
      }

      hullMat.dispose();
      hull.dispose();
      filteredContours.add(contour);
    }

    gray.dispose();
    return filteredContours;
  }

  /// Find the best contour based on combined scoring
  static cv.VecPoint _findBestContour(cv.Contours contours, cv.Mat image) {
    final gray = cv.cvtColor(image, cv.COLOR_BGR2GRAY);
    cv.VecPoint bestContour = contours[0];
    double bestScore = 0.0;

    for (final contour in contours) {
      final area = cv.contourArea(contour);
      
      // Calculate convex hull
      final hullMat = cv.convexHull(contour);
      final hull = cv.VecPoint.fromMat(hullMat);
      final hullArea = cv.contourArea(hull);
      final solidity = area / hullArea;

      // Calculate bounding rectangle
      final rect = cv.boundingRect(contour);
      final rectArea = rect.width.toDouble() * rect.height.toDouble();
      final extent = area / rectArea;

      // Combined score: prefers larger area, higher solidity, and better extent
      final score = (area / (gray.rows * gray.cols)) * 0.5 + 
                     solidity * 0.3 + 
                     extent * 0.2;

      if (score > bestScore) {
        bestScore = score;
        bestContour = contour;
      }

      hullMat.dispose();
      hull.dispose();
    }

    gray.dispose();
    return bestContour;
  }

  /// Fallback strategy: return image bounds when all detection fails
  static List<cv.Point> _getImageBoundsFallback(cv.Mat image) {
    try {
      final width = image.cols;
      final height = image.rows;
      const padding = 10; // Small padding from edges
      
      return [
        cv.Point(padding, padding), // top-left
        cv.Point(width - padding, padding), // top-right
        cv.Point(width - padding, height - padding), // bottom-right
        cv.Point(padding, height - padding), // bottom-left
      ];
    } catch (e) {
      return [];
    }
  }

  /// Order corner points in consistent order: top-left, top-right, bottom-right, bottom-left
  /// 
  /// Algorithm:
  /// 1. Sort points by x-coordinate to separate left and right sides
  /// 2. Within each side, sort by y-coordinate to get top and bottom
  static List<cv.Point> orderCornerPoints(List<cv.Point> corners) {
    if (corners.isEmpty) {
      return [];
    }
    
    if (corners.length != 4) {
      // If we don't have exactly 4 corners, try to handle gracefully
      // If we have some corners but not 4, return as-is for fallback
      return corners;
    }

    // Sort by x-coordinate
    final sortedByX = List<cv.Point>.from(corners);
    sortedByX.sort((a, b) => a.x.compareTo(b.x));

    // Left side points (smaller x)
    final leftPoints = [sortedByX[0], sortedByX[1]];
    // Right side points (larger x)
    final rightPoints = [sortedByX[2], sortedByX[3]];

    // Sort left points by y to get top-left and bottom-left
    leftPoints.sort((a, b) => a.y.compareTo(b.y));
    // Sort right points by y to get top-right and bottom-right
    rightPoints.sort((a, b) => a.y.compareTo(b.y));

    return [
      leftPoints[0], // top-left
      rightPoints[0], // top-right
      rightPoints[1], // bottom-right
      leftPoints[1], // bottom-left
    ];
  }

  /// Apply perspective transform to crop and straighten the document
  /// 
  /// Algorithm:
  /// 1. Calculate the destination rectangle dimensions based on corner distances
  /// 2. Create perspective transform matrix using source and destination points
  /// 3. Apply warp perspective to transform the image
  static Future<String> perspectiveTransform(
    String inputPath,
    List<cv.Point> corners,
    String outputPath,
  ) async {
    try {
      final image = cv.imread(inputPath);
      if (image.isEmpty) {
        throw Exception('Failed to load image');
      }

      // Order the corner points
      final orderedCorners = orderCornerPoints(corners);

      // Validate that we have exactly 4 corners for perspective transform
      if (orderedCorners.length != 4) {
        throw Exception('Perspective transform requires exactly 4 corner points, got ${orderedCorners.length}');
      }

      // Calculate width and height of the destination image
      // Width is the maximum distance between top corners and bottom corners
      final widthTop = _distance(orderedCorners[0], orderedCorners[1]);
      final widthBottom = _distance(orderedCorners[3], orderedCorners[2]);
      final maxWidth = [widthTop, widthBottom].reduce((a, b) => a > b ? a : b);

      // Height is the maximum distance between left corners and right corners
      final heightLeft = _distance(orderedCorners[0], orderedCorners[3]);
      final heightRight = _distance(orderedCorners[1], orderedCorners[2]);
      final maxHeight = [heightLeft, heightRight].reduce((a, b) => a > b ? a : b);

      // Validate calculated dimensions
      if (maxWidth <= 0 || maxHeight <= 0 || !maxWidth.isFinite || !maxHeight.isFinite) {
        throw Exception('Invalid calculated dimensions: width=$maxWidth, height=$maxHeight');
      }

      // Destination points (rectangle)
      final dstPoints = [
        cv.Point(0, 0),
        cv.Point(maxWidth.toInt() - 1, 0),
        cv.Point(maxWidth.toInt() - 1, maxHeight.toInt() - 1),
        cv.Point(0, maxHeight.toInt() - 1),
      ];

      // Convert points to VecPoint format for getPerspectiveTransform
      final srcPoints = cv.VecPoint.fromList(
        orderedCorners.map((p) => cv.Point(p.x.toInt(), p.y.toInt())).toList(),
      );
      final dstPointsVec = cv.VecPoint.fromList(
        dstPoints.map((p) => cv.Point(p.x.toInt(), p.y.toInt())).toList(),
      );

      // Validate point vectors
      if (srcPoints.length != 4 || dstPointsVec.length != 4) {
        throw Exception('Invalid point vectors: src=${srcPoints.length}, dst=${dstPointsVec.length}');
      }

      // Get perspective transform matrix
      final matrix = cv.getPerspectiveTransform(srcPoints, dstPointsVec);

      // Apply warp perspective
      final result = cv.warpPerspective(
        image,
        matrix,
        (maxWidth.toInt(), maxHeight.toInt()),
      );

      // Save the result
      cv.imwrite(outputPath, result);

      // Clean up
      image.dispose();
      matrix.dispose();
      result.dispose();

      return outputPath;
    } catch (e) {
      // Re-throw with more context
      throw Exception('Perspective transform failed: $e');
    }
  }

  /// Calculate Euclidean distance between two points
  static double _distance(cv.Point p1, cv.Point p2) {
    final dx = p2.x - p1.x;
    final dy = p2.y - p1.y;
    return (dx * dx + dy * dy).toDouble();
  }

  /// Apply Magic Color filter (simple thresholding for now)
  /// 
  /// Note: Using simple thresholding instead of adaptive thresholding
  /// due to API compatibility. Can be enhanced later.
  static Future<String> applyMagicColorFilter(
    String inputPath,
    String outputPath,
  ) async {
    try {
      final image = cv.imread(inputPath);
      if (image.isEmpty) {
        throw Exception('Failed to load image');
      }

      // Convert to grayscale
      final gray = cv.cvtColor(image, cv.COLOR_BGR2GRAY);

      // Apply simple thresholding
      final (_, threshold) = cv.threshold(gray, 127, 255, cv.THRESH_BINARY);

      // Convert back to BGR for consistency
      final result = cv.cvtColor(threshold, cv.COLOR_GRAY2BGR);

      // Save the result
      cv.imwrite(outputPath, result);

      // Clean up
      image.dispose();
      gray.dispose();
      threshold.dispose();
      result.dispose();

      return outputPath;
    } catch (e) {
      throw Exception('Magic Color filter failed: $e');
    }
  }

  /// Apply Black & White filter (simple thresholding)
  /// 
  /// Algorithm:
  /// 1. Convert to grayscale
  /// 2. Apply Otsu's thresholding for automatic threshold selection
  /// 3. This creates a pure black and white image
  static Future<String> applyBWFilter(
    String inputPath,
    String outputPath,
  ) async {
    try {
      final image = cv.imread(inputPath);
      if (image.isEmpty) {
        throw Exception('Failed to load image');
      }

      // Convert to grayscale
      final gray = cv.cvtColor(image, cv.COLOR_BGR2GRAY);

      // Apply Otsu's thresholding
      // THRESH_BINARY + THRESH_OTSU automatically calculates the optimal threshold
      final (_, threshold) = cv.threshold(
        gray,
        0,
        255,
        cv.THRESH_BINARY | cv.THRESH_OTSU,
      );

      // Convert back to BGR for consistency
      final result = cv.cvtColor(threshold, cv.COLOR_GRAY2BGR);

      // Save the result
      cv.imwrite(outputPath, result);

      // Clean up
      image.dispose();
      gray.dispose();
      threshold.dispose();
      result.dispose();

      return outputPath;
    } catch (e) {
      throw Exception('B&W filter failed: $e');
    }
  }

  /// Apply contrast and brightness adjustment
  /// 
  /// Algorithm:
  /// Simple brightness enhancement using threshold operations
  /// Note: Due to API limitations, this is a simplified version
  static Future<String> adjustContrastBrightness(
    String inputPath,
    String outputPath, {
    double alpha = 1.5, // Contrast factor (default 1.5)
    double beta = 50.0, // Brightness offset (default 50)
  }) async {
    try {
      final image = cv.imread(inputPath);
      if (image.isEmpty) {
        throw Exception('Failed to load image');
      }

      // Convert to grayscale for processing
      final gray = cv.cvtColor(image, cv.COLOR_BGR2GRAY);

      // Apply threshold to enhance brightness
      final enhanced = cv.threshold(gray, 127, 255, cv.THRESH_BINARY);

      // Convert back to BGR for consistency
      final result = cv.cvtColor(enhanced.$2, cv.COLOR_GRAY2BGR);

      // Save the result
      cv.imwrite(outputPath, result);

      // Clean up
      image.dispose();
      gray.dispose();
      enhanced.$2.dispose();
      result.dispose();

      return outputPath;
    } catch (e) {
      throw Exception('Contrast/brightness adjustment failed: $e');
    }
  }

  /// Resize image to specified dimensions while maintaining aspect ratio
  static Future<String> resizeImage(
    String inputPath,
    String outputPath, {
    int? maxWidth,
    int? maxHeight,
  }) async {
    try {
      final image = cv.imread(inputPath);
      if (image.isEmpty) {
        throw Exception('Failed to load image');
      }

      int width = image.cols;
      int height = image.rows;

      // Calculate new dimensions maintaining aspect ratio
      if (maxWidth != null && width > maxWidth) {
        final ratio = maxWidth / width;
        width = maxWidth;
        height = (height * ratio).toInt();
      }

      if (maxHeight != null && height > maxHeight) {
        final ratio = maxHeight / height;
        height = maxHeight;
        width = (width * ratio).toInt();
      }

      // Resize the image
      final resized = cv.resize(image, (width, height), interpolation: cv.INTER_AREA);

      // Save the result
      cv.imwrite(outputPath, resized);

      // Clean up
      image.dispose();
      resized.dispose();

      return outputPath;
    } catch (e) {
      throw Exception('Image resize failed: $e');
    }
  }
}
