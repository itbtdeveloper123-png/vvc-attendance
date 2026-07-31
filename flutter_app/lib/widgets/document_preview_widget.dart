import 'dart:io';
import 'package:flutter/material.dart';

/// Widget for displaying document preview with loading states
/// 
/// Features:
/// - Displays original and processed images
/// - Shows loading spinner during processing
/// - Error handling with retry option
/// - Zoom and pan support
class DocumentPreviewWidget extends StatelessWidget {
  final String? imagePath;
  final bool isLoading;
  final String? errorMessage;
  final VoidCallback? onRetry;
  final String? loadingMessage;

  const DocumentPreviewWidget({
    Key? key,
    this.imagePath,
    this.isLoading = false,
    this.errorMessage,
    this.onRetry,
    this.loadingMessage,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    if (isLoading) {
      return _buildLoadingState();
    }

    if (errorMessage != null) {
      return _buildErrorState();
    }

    if (imagePath == null) {
      return _buildEmptyState();
    }

    return _buildImagePreview();
  }

  /// Loading state with spinner and message
  Widget _buildLoadingState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const CircularProgressIndicator(),
          if (loadingMessage != null) ...[
            const SizedBox(height: 16),
            Text(
              loadingMessage!,
              style: const TextStyle(color: Colors.grey),
            ),
          ],
        ],
      ),
    );
  }

  /// Error state with retry button
  Widget _buildErrorState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(
              Icons.error_outline,
              size: 48,
              color: Colors.red,
            ),
            const SizedBox(height: 16),
            Text(
              errorMessage!,
              textAlign: TextAlign.center,
              style: const TextStyle(color: Colors.red),
            ),
            if (onRetry != null) ...[
              const SizedBox(height: 16),
              ElevatedButton(
                onPressed: onRetry,
                child: const Text('Retry'),
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// Empty state when no image is available
  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.document_scanner_outlined,
            size: 100,
            color: Colors.grey[300],
          ),
          const SizedBox(height: 16),
          Text(
            'No image selected',
            style: TextStyle(
              color: Colors.grey[600],
              fontSize: 16,
            ),
          ),
        ],
      ),
    );
  }

  /// Image preview with zoom support
  Widget _buildImagePreview() {
    return InteractiveViewer(
      minScale: 0.5,
      maxScale: 4.0,
      child: Image.file(
        File(imagePath!),
        fit: BoxFit.contain,
        errorBuilder: (context, error, stackTrace) {
          return _buildErrorState();
        },
      ),
    );
  }
}

/// Side-by-side comparison widget for before/after
class DocumentComparisonWidget extends StatelessWidget {
  final String? beforePath;
  final String? afterPath;
  final String beforeLabel;
  final String afterLabel;

  const DocumentComparisonWidget({
    Key? key,
    this.beforePath,
    this.afterPath,
    this.beforeLabel = 'Original',
    this.afterLabel = 'Processed',
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Before image
        Expanded(
          child: Container(
            margin: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              border: Border.all(color: Colors.grey[300]!),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Column(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Colors.grey[200],
                    borderRadius: const BorderRadius.only(
                      topLeft: Radius.circular(8),
                      topRight: Radius.circular(8),
                    ),
                  ),
                  child: Text(
                    beforeLabel,
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                ),
                Expanded(
                  child: beforePath != null
                      ? Image.file(
                          File(beforePath!),
                          fit: BoxFit.contain,
                        )
                      : const Center(child: Text('No image')),
                ),
              ],
            ),
          ),
        ),
        // After image
        Expanded(
          child: Container(
            margin: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              border: Border.all(color: Colors.grey[300]!),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Column(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Colors.grey[200],
                    borderRadius: const BorderRadius.only(
                      topLeft: Radius.circular(8),
                      topRight: Radius.circular(8),
                    ),
                  ),
                  child: Text(
                    afterLabel,
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                ),
                Expanded(
                  child: afterPath != null
                      ? Image.file(
                          File(afterPath!),
                          fit: BoxFit.contain,
                        )
                      : const Center(child: Text('No image')),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}
