import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';

/// PDF Page Size Options
enum PdfPageSize {
  a4Full,    // ពេញក្រដាស A4 (Full Bleed - គ្មានគែមស)
  autoFit,   // សមាមាត្ររូបភាពជាក់ស្តែង (100% Exact Image Size - គ្មានគែមស)
  a4Margin,  // A4 មានគែមស្តើង (8pt Margin)
}

/// Export Formats
enum ExportFormat {
  pdf,
  images,
  text,
}

/// Export Modal
/// Allows users to customize file name, choose export format, and paper layout
class ExportModal extends StatefulWidget {
  final List<String> imagePaths;
  final String? ocrText;
  final Function(
    String fileName,
    ExportFormat format, {
    bool includeWatermark,
    String watermarkText,
    PdfPageSize pageSize,
  }) onExport;
  final Function(
    String fileName,
    ExportFormat format,
    List<String> imagePaths, {
    bool includeWatermark,
    String watermarkText,
    PdfPageSize pageSize,
  })? onSaveToPhone;

  const ExportModal({
    super.key,
    required this.imagePaths,
    this.ocrText,
    required this.onExport,
    this.onSaveToPhone,
  });

  @override
  State<ExportModal> createState() => _ExportModalState();
}

class _ExportModalState extends State<ExportModal> {
  late TextEditingController _nameController;
  late TextEditingController _watermarkController;
  ExportFormat _selectedFormat = ExportFormat.pdf;
  PdfPageSize _selectedPageSize = PdfPageSize.a4Full;
  bool _includeWatermark = false;

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
        color: Color(0xFF0F172A),
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Handle bar
            Center(
              child: Container(
                width: 42,
                height: 4.5,
                margin: const EdgeInsets.only(top: 12, bottom: 16),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.25),
                  borderRadius: BorderRadius.circular(3),
                ),
              ),
            ),

            // Header
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0284C7).withValues(alpha: 0.15),
                      shape: BoxShape.circle,
                    ),
                    child: const Icon(
                      Icons.ios_share_rounded,
                      color: Color(0xFF0284C7),
                      size: 20,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Text(
                    'នាំចេញឯកសារ',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const Spacer(),
                  IconButton(
                    icon: const Icon(Icons.close_rounded, color: Colors.white70),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 16),

            // File Name Input
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'ឈ្មោះឯកសារ',
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFF94A3B8),
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _nameController,
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 14.5,
                    ),
                    cursorColor: const Color(0xFF0284C7),
                    decoration: InputDecoration(
                      hintText: 'បញ្ចូលឈ្មោះឯកសារ',
                      hintStyle: GoogleFonts.kantumruyPro(
                        color: Colors.white38,
                        fontSize: 14,
                      ),
                      filled: true,
                      fillColor: const Color(0xFF1E293B),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 16,
                        vertical: 13,
                      ),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(14),
                        borderSide: const BorderSide(color: Color(0xFF334155)),
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(14),
                        borderSide: const BorderSide(color: Color(0xFF334155)),
                      ),
                      focusedBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(14),
                        borderSide: const BorderSide(
                          color: Color(0xFF0284C7),
                          width: 1.5,
                        ),
                      ),
                      suffixText: _getFileExtension(),
                      suffixStyle: GoogleFonts.kantumruyPro(
                        color: const Color(0xFF0284C7),
                        fontWeight: FontWeight.bold,
                        fontSize: 14,
                      ),
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 20),

            // Export format options
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'ទម្រង់ឯកសារនាំចេញ',
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFF94A3B8),
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 10),
                  _buildFormatOption(
                    format: ExportFormat.pdf,
                    icon: Icons.picture_as_pdf_rounded,
                    label: 'ឯកសារ PDF ច្រើនទំព័រ',
                    description: 'បញ្ចូលទំព័រទាំងអស់ជាឯកសារ PDF តែមួយ',
                  ),
                  const SizedBox(height: 8),
                  _buildFormatOption(
                    format: ExportFormat.images,
                    icon: Icons.photo_library_rounded,
                    label: 'រូបភាពគុណភាពខ្ពស់',
                    description: 'នាំចេញជារូបភាព JPG ដាច់ដោយឡែក',
                  ),
                  if (widget.ocrText != null && widget.ocrText!.isNotEmpty) ...[
                    const SizedBox(height: 8),
                    _buildFormatOption(
                      format: ExportFormat.text,
                      icon: Icons.text_snippet_rounded,
                      label: 'អត្ថបទ OCR',
                      description: 'ទាញយកអត្ថបទដែលបានស្កេនជាឯកសារ TXT',
                    ),
                  ],
                ],
              ),
            ),

            // Paper Size & Layout Options (when PDF is selected)
            if (_selectedFormat == ExportFormat.pdf) ...[
              const SizedBox(height: 20),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(
                          Icons.aspect_ratio_rounded,
                          color: Color(0xFF0284C7),
                          size: 16,
                        ),
                        const SizedBox(width: 6),
                        Text(
                          'ទំហំ និងប្លង់ក្រដាស PDF',
                          style: GoogleFonts.kantumruyPro(
                            color: const Color(0xFF94A3B8),
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    _buildPageSizeOption(
                      size: PdfPageSize.a4Full,
                      icon: Icons.fullscreen_rounded,
                      label: 'ពេញក្រដាស A4 (ណែនាំ)',
                      description: 'លាតសន្ធឹងពេញក្រដាស A4 ស្អាត គ្មានចន្លោះគែមសរំខាន',
                    ),
                    const SizedBox(height: 8),
                    _buildPageSizeOption(
                      size: PdfPageSize.autoFit,
                      icon: Icons.fit_screen_rounded,
                      label: 'សមាមាត្ររូបភាពដើម (Auto-Fit)',
                      description: 'ទំហំ PDF ផ្គូផ្គងតាមរូបភាពស្កេន ១០០% គ្មានគែមសលើក្រោម',
                    ),
                    const SizedBox(height: 8),
                    _buildPageSizeOption(
                      size: PdfPageSize.a4Margin,
                      icon: Icons.crop_free_rounded,
                      label: 'ក្រដាស A4 (មានគែមស្ដើង)',
                      description: 'សមស្របសម្រាប់ការព្រីនលើម៉ាស៊ីនបោះពុម្ពទូទៅ',
                    ),
                  ],
                ),
              ),

              // Official Watermark Option
              const SizedBox(height: 16),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: const Color(0xFF1E293B),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(
                      color: _includeWatermark
                          ? const Color(0xFF0284C7).withValues(alpha: 0.6)
                          : const Color(0xFF334155),
                    ),
                  ),
                  child: Column(
                    children: [
                      Row(
                        children: [
                          const Icon(
                            Icons.verified_rounded,
                            color: Color(0xFF0284C7),
                            size: 20,
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'ត្រាទឹកផ្លូវការ (Official Watermark)',
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
                            activeThumbColor: const Color(0xFF0284C7),
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
                            hintStyle: GoogleFonts.inter(color: Colors.white38, fontSize: 13),
                            isDense: true,
                            filled: true,
                            fillColor: const Color(0xFF0F172A),
                            contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(8),
                              borderSide: const BorderSide(color: Color(0xFF334155)),
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ],

            const SizedBox(height: 16),

            // Page count info
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  color: const Color(0xFF0284C7).withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                    color: const Color(0xFF0284C7).withValues(alpha: 0.25),
                  ),
                ),
                child: Row(
                  children: [
                    const Icon(
                      Icons.description_outlined,
                      color: Color(0xFF0284C7),
                      size: 18,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'ឯកសារសរុបមានចំនួន ${widget.imagePaths.length} ទំព័រ ត្រៀមរួចរាល់',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white.withValues(alpha: 0.9),
                          fontSize: 12.5,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),

            const SizedBox(height: 24),

            // Action buttons (Save to phone & Share)
            Padding(
              padding: EdgeInsets.only(
                left: 20,
                right: 20,
                bottom: MediaQuery.of(context).padding.bottom + 20,
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (_selectedFormat == ExportFormat.images) ...[
                    // Primary Action: Save directly to phone (Photos/Gallery)
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _handleSaveToPhone,
                        icon: const Icon(Icons.download_rounded, size: 22),
                        label: Text(
                          'រក្សាទុកក្នុងទូរស័ព្ទ (Save to Phone)',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 15,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF059669), // Emerald Green
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          elevation: 3,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(14),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(height: 10),
                    // Secondary Action: Share actual images
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _handleExport,
                        icon: const Icon(Icons.share_rounded, size: 20),
                        label: Text(
                          'ចែករំលែករូបភាព (Share Images)',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 14.5,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF0284C7),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 13),
                          elevation: 2,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(14),
                          ),
                        ),
                      ),
                    ),
                  ] else if (_selectedFormat == ExportFormat.pdf) ...[
                    // Primary Action: Export & Share PDF
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _handleExport,
                        icon: const Icon(Icons.share_rounded, size: 20),
                        label: Text(
                          'នាំចេញ និងចែករំលែក PDF',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 15,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF0284C7),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          elevation: 3,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(14),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(height: 10),
                    // Secondary Action: Save PDF to Device
                    SizedBox(
                      width: double.infinity,
                      child: OutlinedButton.icon(
                        onPressed: _handleSaveToPhone,
                        icon: const Icon(Icons.download_rounded, size: 20, color: Color(0xFF38BDF8)),
                        label: Text(
                          'រក្សាទុក PDF ក្នុងទូរស័ព្ទ (Save to Device)',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                            color: const Color(0xFF38BDF8),
                          ),
                        ),
                        style: OutlinedButton.styleFrom(
                          side: const BorderSide(color: Color(0xFF0284C7), width: 1.2),
                          backgroundColor: const Color(0xFF1E293B),
                          padding: const EdgeInsets.symmetric(vertical: 13),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(14),
                          ),
                        ),
                      ),
                    ),
                  ] else ...[
                    // OCR Text Export
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _handleExport,
                        icon: const Icon(Icons.text_snippet_rounded, size: 20),
                        label: Text(
                          'នាំចេញអត្ថបទ (Export Text)',
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 15,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF0284C7),
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(vertical: 14),
                          elevation: 3,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(14),
                          ),
                        ),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
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
      onTap: () => setState(() => _selectedFormat = format),
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: isSelected
              ? const Color(0xFF0284C7).withValues(alpha: 0.15)
              : const Color(0xFF1E293B),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: isSelected ? const Color(0xFF0284C7) : const Color(0xFF334155),
            width: isSelected ? 1.8 : 1,
          ),
        ),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(9),
              decoration: BoxDecoration(
                color: isSelected
                    ? const Color(0xFF0284C7)
                    : Colors.white.withValues(alpha: 0.06),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Icon(
                icon,
                color: isSelected ? Colors.white : Colors.white70,
                size: 22,
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 3),
                  Text(
                    description,
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFF94A3B8),
                      fontSize: 11.5,
                    ),
                  ),
                ],
              ),
            ),
            if (isSelected)
              const Icon(
                Icons.check_circle_rounded,
                color: Color(0xFF0284C7),
                size: 22,
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildPageSizeOption({
    required PdfPageSize size,
    required IconData icon,
    required String label,
    required String description,
  }) {
    final isSelected = _selectedPageSize == size;

    return GestureDetector(
      onTap: () => setState(() => _selectedPageSize = size),
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: isSelected
              ? const Color(0xFF0284C7).withValues(alpha: 0.12)
              : const Color(0xFF1E293B).withValues(alpha: 0.6),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: isSelected ? const Color(0xFF0284C7) : const Color(0xFF334155),
            width: isSelected ? 1.6 : 1,
          ),
        ),
        child: Row(
          children: [
            Icon(
              icon,
              color: isSelected ? const Color(0xFF0284C7) : Colors.white60,
              size: 20,
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: GoogleFonts.kantumruyPro(
                      color: isSelected ? Colors.white : Colors.white70,
                      fontSize: 13,
                      fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    description,
                    style: GoogleFonts.kantumruyPro(
                      color: const Color(0xFF94A3B8),
                      fontSize: 11,
                    ),
                  ),
                ],
              ),
            ),
            if (isSelected)
              const Icon(
                Icons.check_circle_rounded,
                color: Color(0xFF0284C7),
                size: 18,
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

  void _handleExport() {
    final fileName = _nameController.text.trim();
    if (fileName.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('សូមបញ្ចូលឈ្មោះឯកសារជាមុនសិន'),
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
      pageSize: _selectedPageSize,
    );
    Navigator.pop(context);
  }

  void _handleSaveToPhone() {
    final fileName = _nameController.text.trim();
    if (fileName.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'សូមបញ្ចូលឈ្មោះឯកសារជាមុនសិន',
            style: GoogleFonts.kantumruyPro(),
          ),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    final watermarkText = _watermarkController.text.trim().isNotEmpty
        ? _watermarkController.text.trim()
        : 'VVC OFFICIAL DOCUMENT';

    widget.onSaveToPhone?.call(
      fileName,
      _selectedFormat,
      widget.imagePaths,
      includeWatermark: _selectedFormat == ExportFormat.pdf && _includeWatermark,
      watermarkText: watermarkText,
      pageSize: _selectedPageSize,
    );
    Navigator.pop(context);
  }
}
