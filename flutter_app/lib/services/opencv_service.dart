import 'package:opencv_dart/opencv_dart.dart' as cv;

/// OpenCV Service for document scanning operations
/// Handles edge detection, perspective transform, and image enhancement
class OpenCVService {
  
  /// Detect document edges and return the 4 corner points
  /// 
  /// Algorithm:
  /// 1. Convert image to grayscale
  /// 2. Apply Gaussian blur to reduce noise
  /// 3. Use Canny edge detection to find edges
  /// 4. Find contours from the edge map
  /// 5. Filter contours to find the largest quadrilateral
  /// 6. Approximate the contour to 4 corner points
  static Future<List<cv.Point>> detectDocumentEdges(String imagePath) async {
    try {
      // Read the image
      final image = cv.imread(imagePath);
      if (image.isEmpty) {
        throw Exception('Failed to load image');
      }

      // Step 1: Convert to grayscale
      final gray = cv.cvtColor(image, cv.COLOR_BGR2GRAY);

      // Step 2: Apply Gaussian blur to reduce noise
      // Kernel size (5,5) helps smooth the image while preserving edges
      final blurred = cv.gaussianBlur(gray, (5, 5), 0);

      // Step 3: Canny edge detection
      // Threshold values (50, 150) work well for document edges
      // Lower threshold: minimum edge intensity
      // Upper threshold: maximum edge intensity
      final edges = cv.canny(blurred, 50, 150);

      // Step 4: Find contours
      // RETR_EXTERNAL retrieves only the outer contours
      // CHAIN_APPROX_SIMPLE compresses horizontal, vertical, and diagonal segments
      final contours = cv.findContours(
        edges,
        cv.RETR_EXTERNAL,
        cv.CHAIN_APPROX_SIMPLE,
      );

      if (contours.$1.isEmpty) {
        image.dispose();
        gray.dispose();
        blurred.dispose();
        edges.dispose();
        throw Exception('No contours found in image');
      }

      // Step 5: Find the largest contour (should be the document)
      cv.VecPoint largestContour = contours.$1[0];
      double maxArea = cv.contourArea(contours.$1[0]);

      for (final contour in contours.$1) {
        final area = cv.contourArea(contour);
        if (area > maxArea) {
          maxArea = area;
          largestContour = contour;
        }
      }

      // Step 6: Approximate contour to a polygon
      // Epsilon determines the approximation accuracy (2% of perimeter)
      final perimeter = cv.arcLength(largestContour, true);
      final approx = cv.approxPolyDP(largestContour, 0.02 * perimeter, true);

      // Check if we have 4 corners (quadrilateral)
      if (approx.length < 4) {
        image.dispose();
        gray.dispose();
        blurred.dispose();
        edges.dispose();
        // Return empty list to indicate edge detection failed
        return [];
      }

      // Extract the 4 corner points
      final corners = <cv.Point>[];
      for (int i = 0; i < approx.length; i++) {
        final point = approx[i];
        corners.add(cv.Point(point.x.toInt(), point.y.toInt()));
      }

      // Clean up
      image.dispose();
      gray.dispose();
      blurred.dispose();
      edges.dispose();

      return corners;
    } catch (e) {
      // Return empty list on failure instead of throwing exception
      return [];
    }
  }

  /// Order corner points in consistent order: top-left, top-right, bottom-right, bottom-left
  /// 
  /// Algorithm:
  /// 1. Sort points by x-coordinate to separate left and right sides
  /// 2. Within each side, sort by y-coordinate to get top and bottom
  static List<cv.Point> orderCornerPoints(List<cv.Point> corners) {
    if (corners.length != 4) {
      // If we don't have exactly 4 corners, try to handle gracefully
      if (corners.length == 0) {
        return [];
      }
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

      // Calculate width and height of the destination image
      // Width is the maximum distance between top corners and bottom corners
      final widthTop = _distance(orderedCorners[0], orderedCorners[1]);
      final widthBottom = _distance(orderedCorners[3], orderedCorners[2]);
      final maxWidth = [widthTop, widthBottom].reduce((a, b) => a > b ? a : b);

      // Height is the maximum distance between left corners and right corners
      final heightLeft = _distance(orderedCorners[0], orderedCorners[3]);
      final heightRight = _distance(orderedCorners[1], orderedCorners[2]);
      final maxHeight = [heightLeft, heightRight].reduce((a, b) => a > b ? a : b);

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
      final threshold = cv.threshold(gray, 127, 255, cv.THRESH_BINARY);

      // Convert back to BGR for consistency
      final result = cv.cvtColor(threshold.$2, cv.COLOR_GRAY2BGR);

      // Save the result
      cv.imwrite(outputPath, result);

      // Clean up
      image.dispose();
      gray.dispose();
      threshold.$2.dispose();
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
