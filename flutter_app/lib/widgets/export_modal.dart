import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';

/// Export Modal
/// Allows users to customize file name and choose export format
class ExportModal extends StatefulWidget {
  final List<String> imagePaths;
  final String? ocrText;
  final Function(String fileName, ExportFormat format, {bool includeWatermark, String watermarkText}) onExport;

  const ExportModal({
    super.key,
    required this.imagePaths,
    this.ocrText,
    required this.onExport,
  });

  @override
  State<ExportModal> createState() => _ExportModalState();
}

class _ExportModalState extends State<ExportModal> {
  late TextEditingController _nameController;
  late TextEditingController _watermarkController;
  ExportFormat _selectedFormat = ExportFormat.pdf;
  bool _includeWatermark = true;

  @override
  void initState() {
    super.initState();
    _nameController = TextEditingController(
      text: _generateDefaultName(),
    );
    _watermarkController = TextEditingController(
      text: 'VVC OFFICIAL DOCUMENT',
    );
  }

  @override
  void dispose() {
    _nameController.dispose();
    _watermarkController.dispose();
    super.dispose();
  }

  String _generateDefaultName() {
    final now = DateTime.now();
    final formatter = DateFormat('dd-MM-yyyy_HHmm');
    return 'Scan_${formatter.format(now)}';
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        color: Color(0xFF1E1E1E),
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Handle
          Container(
            width: 40,
            height: 4,
            margin: const EdgeInsets.only(top: 12, bottom: 20),
            decoration: BoxDecoration(
              color: Colors.grey.withValues(alpha: 0.3),
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          // Header
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20),
            child: Row(
              children: [
                Text(
                  'Export Document',
                  style: GoogleFonts.inter(
                    color: Colors.white,
                    fontSize: 20,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.close, color: Colors.white),
                  onPressed: () => Navigator.pop(context),
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),
          // File name input
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'File Name',
                  style: GoogleFonts.inter(
                    color: Colors.white.withValues(alpha: 0.7),
                    fontSize: 14,
                  ),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _nameController,
                  style: GoogleFonts.inter(
                    color: Colors.white,
                    fontSize: 16,
                  ),
                  decoration: InputDecoration(
                    hintText: 'Enter file name',
                    hintStyle: GoogleFonts.inter(
                      color: Colors.grey,
                      fontSize: 16,
                    ),
                    filled: true,
                    fillColor: Colors.white.withValues(alpha: 0.05),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: BorderSide(
                        color: Colors.white.withValues(alpha: 0.1),
                      ),
                    ),
                    enabledBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: BorderSide(
                        color: Colors.white.withValues(alpha: 0.1),
                      ),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(
                        color: Colors.orange,
                        width: 2,
                      ),
                    ),
                    suffixText: _getFileExtension(),
                    suffixStyle: GoogleFonts.inter(
                      color: Colors.grey,
                      fontSize: 14,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          // Export format options
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Export Format',
                  style: GoogleFonts.inter(
                    color: Colors.white.withValues(alpha: 0.7),
                    fontSize: 14,
                  ),
                ),
                const SizedBox(height: 12),
                _buildFormatOption(
                  format: ExportFormat.pdf,
                  icon: Icons.picture_as_pdf,
                  label: 'Multi-page PDF',
                  description: 'Merge all pages into a single PDF document',
                ),
                const SizedBox(height: 8),
                _buildFormatOption(
                  format: ExportFormat.images,
                  icon: Icons.image,
                  label: 'High-Quality Images',
                  description: 'Export as individual JPG files',
                ),
                const SizedBox(height: 8),
                if (widget.ocrText != null && widget.ocrText!.isNotEmpty)
                  _buildFormatOption(
                    format: ExportFormat.text,
                    icon: Icons.text_fields,
                    label: 'Extracted Text',
                    description: 'Export OCR results as TXT file',
                  ),
              ],
            ),
          ),
          // Watermark Option (for PDF)
          if (_selectedFormat == ExportFormat.pdf) ...[
            const SizedBox(height: 16),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.05),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(
                    color: _includeWatermark
                        ? Colors.orange.withValues(alpha: 0.5)
                        : Colors.white.withValues(alpha: 0.1),
                  ),
                ),
                child: Column(
                  children: [
                    Row(
                      children: [
                        const Icon(
                          Icons.verified_user_outlined,
                          color: Colors.orange,
                          size: 20,
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'Official Watermark (ត្រាទឹកផ្លូវការ)',
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white,
                                  fontWeight: FontWeight.w600,
                                  fontSize: 13,
                                ),
                              ),
                              Text(
                                'បោះត្រាទឹកសម្គាល់ភាពស្របច្បាប់លើក្រដាស PDF',
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white54,
                                  fontSize: 11,
                                ),
                              ),
                            ],
                          ),
                        ),
                        Switch(
                          value: _includeWatermark,
                          activeThumbColor: Colors.orange,
                          onChanged: (v) => setState(() => _includeWatermark = v),
                        ),
                      ],
                    ),
                    if (_includeWatermark) ...[
                      const SizedBox(height: 10),
                      TextField(
                        controller: _watermarkController,
                        style: GoogleFonts.inter(
                          color: Colors.white,
                          fontSize: 13,
                          fontWeight: FontWeight.bold,
                        ),
                        decoration: InputDecoration(
                          hintText: 'Watermark Text',
                          hintStyle: GoogleFonts.inter(color: Colors.grey, fontSize: 13),
                          isDense: true,
                          filled: true,
                          fillColor: Colors.black26,
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(8),
                            borderSide: BorderSide(
                              color: Colors.white.withValues(alpha: 0.1),
                            ),
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ],
          const SizedBox(height: 20),
          // Page count info
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20),
            child: Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.orange.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: Colors.orange.withValues(alpha: 0.3),
                  width: 1,
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.info_outline, color: Colors.orange, size: 18),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      '${widget.imagePaths.length} page${widget.imagePaths.length > 1 ? 's' : ''} ready for export',
                      style: GoogleFonts.inter(
                        color: Colors.white.withValues(alpha: 0.8),
                        fontSize: 13,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 24),
          // Export button
          Padding(
            padding: EdgeInsets.only(
              left: 20,
              right: 20,
              bottom: MediaQuery.of(context).padding.bottom + 20,
            ),
            child: SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: _handleExport,
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.orange,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                child: Text(
                  'Export ${_getFormatLabel()}',
                  style: GoogleFonts.inter(
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFormatOption({
    required ExportFormat format,
    required IconData icon,
    required String label,
    required String description,
  }) {
    final isSelected = _selectedFormat == format;

    return GestureDetector(
      onTap: () {
        setState(() {
          _selectedFormat = format;
        });
      },
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: isSelected
              ? Colors.orange.withValues(alpha: 0.2)
              : Colors.white.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: isSelected
                ? Colors.orange
                : Colors.white.withValues(alpha: 0.1),
            width: isSelected ? 2 : 1,
          ),
        ),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: isSelected
                    ? Colors.orange
                    : Colors.white.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Icon(
                icon,
                color: isSelected ? Colors.white : Colors.white.withValues(alpha: 0.7),
                size: 24,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: GoogleFonts.inter(
                      color: Colors.white,
                      fontSize: 15,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    description,
                    style: GoogleFonts.inter(
                      color: Colors.white.withValues(alpha: 0.5),
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),
            if (isSelected)
              const Icon(
                Icons.check_circle,
                color: Colors.orange,
                size: 24,
              ),
          ],
        ),
      ),
    );
  }

  String _getFileExtension() {
    switch (_selectedFormat) {
      case ExportFormat.pdf:
        return '.pdf';
      case ExportFormat.images:
        return '';
      case ExportFormat.text:
        return '.txt';
    }
  }

  String _getFormatLabel() {
    switch (_selectedFormat) {
      case ExportFormat.pdf:
        return 'PDF';
      case ExportFormat.images:
        return 'Images';
      case ExportFormat.text:
        return 'Text';
    }
  }

  void _handleExport() {
    final fileName = _nameController.text.trim();
    if (fileName.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please enter a file name'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    final watermarkText = _watermarkController.text.trim().isNotEmpty
        ? _watermarkController.text.trim()
        : 'VVC OFFICIAL DOCUMENT';

    widget.onExport(
      fileName,
      _selectedFormat,
      includeWatermark: _selectedFormat == ExportFormat.pdf && _includeWatermark,
      watermarkText: watermarkText,
    );
    Navigator.pop(context);
  }
}

enum ExportFormat {
  pdf,
  images,
  text,
}
