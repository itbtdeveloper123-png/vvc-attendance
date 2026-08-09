import 'dart:io';
import 'dart:typed_data';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:path_provider/path_provider.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import 'package:share_plus/share_plus.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/vvc_global_alert.dart';

class CertificateEditorScreen extends StatefulWidget {
  final String recipientName;
  final String recipientGender;
  final String recipientDept;
  final String recipientLocation;
  final String quarterPeriod;
  final String? recipientAvatarUrl;

  const CertificateEditorScreen({
    super.key,
    this.recipientName = 'លី ស៊ាងអ៊ី',
    this.recipientGender = 'ស្រី',
    this.recipientDept = 'គណនេយ្យករ',
    this.recipientLocation = 'ការិយាល័យកណ្តាល',
    this.quarterPeriod = 'ត្រីមាសទី ២ នៃឆ្នាំ ២០២៦',
    this.recipientAvatarUrl,
  });

  @override
  State<CertificateEditorScreen> createState() => _CertificateEditorScreenState();
}

class _CertificateEditorScreenState extends State<CertificateEditorScreen> {
  final GlobalKey _previewContainerKey = GlobalKey();

  late TextEditingController _nameController;
  late TextEditingController _genderController;
  late TextEditingController _deptController;
  late TextEditingController _locationController;
  late TextEditingController _quarterController;
  late TextEditingController _issueDateController;
  late TextEditingController _signatoryController;
  late TextEditingController _titleController;
  late TextEditingController _companyController;

  String _selectedTemplateAsset = 'assets/certificate_template/frame_quarter1.jpg';
  String _employeeCategory = 'skilled'; // 'skilled' (បុគ្គលិកជំនាញ) or 'worker' (កម្មករ)
  bool _isGeneratingPdf = false;
  bool _showInlineControls = true;

  final List<Map<String, String>> _templates = [
    {'name': 'ទម្រង់ទី ១ (Classic Gold)', 'path': 'assets/certificate_template/frame_quarter1.jpg'},
    {'name': 'ទម្រង់ទី ២ (Royal Blue)', 'path': 'assets/certificate_template/frame_quarter2.jpg'},
    {'name': 'ទម្រង់ទី ៣ (Modern Silver)', 'path': 'assets/certificate_template/frame_quarter3.jpg'},
    {'name': 'ទម្រង់ទី ៤ (Elegant Gold)', 'path': 'assets/certificate_template/frame_quarter4.jpg'},
    {'name': 'ទម្រង់ទី ៥ (Platinum Grey)', 'path': 'assets/certificate_template/frame_quarter5.jpg'},
    {'name': 'ទម្រង់ទី ៦ (Premium Diamond)', 'path': 'assets/certificate_template/frame_quarter6.jpg'},
  ];

  @override
  void initState() {
    super.initState();
    _nameController = TextEditingController(text: widget.recipientName);
    _genderController = TextEditingController(text: widget.recipientGender);
    _deptController = TextEditingController(text: widget.recipientDept);
    _locationController = TextEditingController(text: widget.recipientLocation);
    _quarterController = TextEditingController(text: widget.quarterPeriod);
    _issueDateController = TextEditingController(text: 'រាជធានីភ្នំពេញ, ថ្ងៃទី ០៩ ខែ សីហា ឆ្នាំ ២០២៦');
    _signatoryController = TextEditingController(text: 'នាត សុវណ្ណ');
    _titleController = TextEditingController(text: 'លិខិតសរសើរ');
    _companyController = TextEditingController(text: 'អគ្គនាយិកាក្រុមហ៊ុន វណ្ណ វណ្ណ ខេមបូឌា');
  }

  @override
  void dispose() {
    _nameController.dispose();
    _genderController.dispose();
    _deptController.dispose();
    _locationController.dispose();
    _quarterController.dispose();
    _issueDateController.dispose();
    _signatoryController.dispose();
    _titleController.dispose();
    _companyController.dispose();
    super.dispose();
  }

  Future<Uint8List?> _capturePngBytes() async {
    try {
      final RenderRepaintBoundary boundary =
          _previewContainerKey.currentContext!.findRenderObject() as RenderRepaintBoundary;
      final ui.Image image = await boundary.toImage(pixelRatio: 3.0);
      final ByteData? byteData = await image.toByteData(format: ui.ImageByteFormat.png);
      return byteData?.buffer.asUint8List();
    } catch (e) {
      debugPrint('Error capturing certificate PNG: $e');
      return null;
    }
  }

  Future<void> _printCertificate() async {
    setState(() => _isGeneratingPdf = true);
    try {
      final pngBytes = await _capturePngBytes();
      if (pngBytes == null) {
        if (mounted) {
          VvcAlert.showError(context, title: 'បរាជ័យ', message: 'មិនអាចទាញយករូបភាព Certificate បានទេ');
        }
        return;
      }

      final doc = pw.Document();
      final image = pw.MemoryImage(pngBytes);

      doc.addPage(
        pw.Page(
          pageFormat: PdfPageFormat.a4.landscape,
          margin: pw.EdgeInsets.zero,
          build: (pw.Context context) {
            return pw.FullPage(
              ignoreMargins: true,
              child: pw.Image(image, fit: pw.BoxFit.cover),
            );
          },
        ),
      );

      await Printing.layoutPdf(
        onLayout: (PdfPageFormat format) async => doc.save(),
        name: 'Certificate_${_nameController.text.replaceAll(' ', '_')}.pdf',
      );
    } catch (e) {
      if (mounted) {
        VvcAlert.showError(context, title: 'កំហុសបោះពុម្ព', message: '$e');
      }
    } finally {
      if (mounted) setState(() => _isGeneratingPdf = false);
    }
  }

  Future<void> _shareCertificate() async {
    setState(() => _isGeneratingPdf = true);
    try {
      final pngBytes = await _capturePngBytes();
      if (pngBytes == null) return;

      final tempDir = await getTemporaryDirectory();
      final file = File('${tempDir.path}/Certificate_${DateTime.now().millisecondsSinceEpoch}.png');
      await file.writeAsBytes(pngBytes);

      await Share.shareXFiles(
        [XFile(file.path)],
        text: 'ប័ណ្ណសរសើរសម្រាប់ ${_nameController.text}',
      );
    } catch (e) {
      if (mounted) {
        VvcAlert.showError(context, title: 'កំហុសក្នុងការ Share', message: '$e');
      }
    } finally {
      if (mounted) setState(() => _isGeneratingPdf = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: const Color(0xFF111E33),
        title: Text(
          'រចនា & បោះពុម្ពលិខិតសរសើរ (A4 Certificate)',
          style: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.bold,
            color: Colors.white,
            fontSize: 16,
          ),
        ),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          IconButton(
            tooltip: 'បិទ/បើកប្រអប់កែប្រែ',
            icon: Icon(
              _showInlineControls ? Icons.tune_rounded : Icons.tune_outlined,
              color: Colors.amberAccent,
            ),
            onPressed: () => setState(() => _showInlineControls = !_showInlineControls),
          ),
          IconButton(
            tooltip: 'Share',
            icon: const Icon(Icons.share_rounded, color: Colors.cyanAccent),
            onPressed: _isGeneratingPdf ? null : _shareCertificate,
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            // Employee Type Tabs: បុគ្គលិកជំនាញ vs កម្មករ
            Container(
              padding: const EdgeInsets.fromLTRB(14, 10, 14, 10),
              color: const Color(0xFF111E33),
              child: Row(
                children: [
                  Expanded(
                    child: GestureDetector(
                      onTap: () => setState(() => _employeeCategory = 'skilled'),
                      child: AnimatedContainer(
                        duration: const Duration(milliseconds: 200),
                        padding: const EdgeInsets.symmetric(vertical: 10),
                        decoration: BoxDecoration(
                          color: _employeeCategory == 'skilled'
                              ? Colors.amberAccent
                              : Colors.white.withValues(alpha: 0.05),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: _employeeCategory == 'skilled'
                                ? Colors.amberAccent
                                : Colors.white.withValues(alpha: 0.1),
                          ),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.badge_rounded,
                              size: 18,
                              color: _employeeCategory == 'skilled' ? Colors.black : Colors.white70,
                            ),
                            const SizedBox(width: 6),
                            Text(
                              '👔 បុគ្គលិកជំនាញ',
                              style: GoogleFonts.kantumruyPro(
                                color: _employeeCategory == 'skilled' ? Colors.black : Colors.white70,
                                fontWeight: FontWeight.bold,
                                fontSize: 13.5,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: GestureDetector(
                      onTap: () => setState(() => _employeeCategory = 'worker'),
                      child: AnimatedContainer(
                        duration: const Duration(milliseconds: 200),
                        padding: const EdgeInsets.symmetric(vertical: 10),
                        decoration: BoxDecoration(
                          color: _employeeCategory == 'worker'
                              ? Colors.cyanAccent
                              : Colors.white.withValues(alpha: 0.05),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: _employeeCategory == 'worker'
                                ? Colors.cyanAccent
                                : Colors.white.withValues(alpha: 0.1),
                          ),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.engineering_rounded,
                              size: 18,
                              color: _employeeCategory == 'worker' ? Colors.black : Colors.white70,
                            ),
                            const SizedBox(width: 6),
                            Text(
                              '👷‍♂️ កម្មករ / ប្រតិបត្តិការ',
                              style: GoogleFonts.kantumruyPro(
                                color: _employeeCategory == 'worker' ? Colors.black : Colors.white70,
                                fontWeight: FontWeight.bold,
                                fontSize: 13.5,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),

            // Visual Template Selector Gallery
            Container(
              height: 70,
              padding: const EdgeInsets.symmetric(vertical: 6),
              color: const Color(0xFF0D1627),
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 14),
                itemCount: _templates.length,
                itemBuilder: (context, idx) {
                  final t = _templates[idx];
                  final isSelected = _selectedTemplateAsset == t['path'];
                  return GestureDetector(
                    onTap: () => setState(() => _selectedTemplateAsset = t['path']!),
                    child: Container(
                      margin: const EdgeInsets.only(right: 10),
                      padding: const EdgeInsets.all(4),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(
                          color: isSelected ? Colors.amberAccent : Colors.white.withValues(alpha: 0.1),
                          width: isSelected ? 2 : 1,
                        ),
                      ),
                      child: Row(
                        children: [
                          ClipRRect(
                            borderRadius: BorderRadius.circular(6),
                            child: Image.asset(
                              t['path']!,
                              width: 60,
                              height: 48,
                              fit: BoxFit.cover,
                            ),
                          ),
                          const SizedBox(width: 8),
                          Text(
                            t['name']!,
                            style: GoogleFonts.kantumruyPro(
                              color: isSelected ? Colors.amberAccent : Colors.white70,
                              fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                              fontSize: 11.5,
                            ),
                          ),
                          if (isSelected) ...[
                            const SizedBox(width: 6),
                            const Icon(Icons.check_circle_rounded, color: Colors.amberAccent, size: 16),
                          ],
                        ],
                      ),
                    ),
                  );
                },
              ),
            ),

            const SizedBox(height: 12),

            // Certificate Preview Container (A4 Landscape ratio: 297mm x 210mm ~ 1.414)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: Column(
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        '🔍 មើលគំរូផ្សាយផ្ទាល់ (Live A4 Preview)',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white70,
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      Text(
                        'ចុចលើអត្ថបទដើម្បីកែប្រែដោយផ្ទាល់ (Inline Edit)',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.amberAccent,
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),

                  RepaintBoundary(
                    key: _previewContainerKey,
                    child: AspectRatio(
                      aspectRatio: 1.414,
                      child: Container(
                        decoration: BoxDecoration(
                          color: Colors.white,
                          borderRadius: BorderRadius.circular(8),
                          boxShadow: [
                            BoxShadow(
                              color: Colors.black.withValues(alpha: 0.5),
                              blurRadius: 20,
                              offset: const Offset(0, 8),
                            ),
                          ],
                        ),
                        child: Stack(
                          fit: StackFit.expand,
                          children: [
                            // 1. Background Template Image
                            ClipRRect(
                              borderRadius: BorderRadius.circular(8),
                              child: Image.asset(
                                _selectedTemplateAsset,
                                fit: BoxFit.fill,
                                errorBuilder: (ctx, err, stack) => Container(
                                  color: Colors.white,
                                  child: const Center(
                                    child: Icon(Icons.workspace_premium_rounded, size: 80, color: Colors.amber),
                                  ),
                                ),
                              ),
                            ),

                            // 2. Certificate Content Layer
                            Padding(
                              padding: const EdgeInsets.fromLTRB(40, 36, 40, 24),
                              child: LayoutBuilder(
                                builder: (context, constraints) {
                                  final baseWidth = constraints.maxWidth;
                                  final scale = baseWidth / 700;

                                  return Column(
                                    crossAxisAlignment: CrossAxisAlignment.center,
                                    children: [
                                      // Top Header & Recipient Photo Box
                                      Stack(
                                        children: [
                                          Align(
                                            alignment: Alignment.topCenter,
                                            child: Column(
                                              children: [
                                                const SizedBox(height: 8),
                                                Text(
                                                  _titleController.text,
                                                  textAlign: TextAlign.center,
                                                  style: GoogleFonts.kantumruyPro(
                                                    color: const Color(0xFF1E3A8A),
                                                    fontSize: 28 * scale,
                                                    fontWeight: FontWeight.bold,
                                                    letterSpacing: 1.2,
                                                  ),
                                                ),
                                                SizedBox(height: 4 * scale),
                                                Container(
                                                  width: 140 * scale,
                                                  height: 2,
                                                  color: const Color(0xFF1E3A8A),
                                                ),
                                              ],
                                            ),
                                          ),
                                          // Recipient Photo Placeholder Top Right (Matching user screenshot!)
                                          Align(
                                            alignment: Alignment.topRight,
                                            child: Container(
                                              width: 75 * scale,
                                              height: 95 * scale,
                                              decoration: BoxDecoration(
                                                color: Colors.white,
                                                borderRadius: BorderRadius.circular(6),
                                                border: Border.all(
                                                  color: const Color(0xFFD97706),
                                                  width: 2,
                                                ),
                                                boxShadow: [
                                                  BoxShadow(
                                                    color: Colors.black.withValues(alpha: 0.15),
                                                    blurRadius: 6,
                                                  ),
                                                ],
                                              ),
                                              child: ClipRRect(
                                                borderRadius: BorderRadius.circular(4),
                                                child: widget.recipientAvatarUrl != null &&
                                                        widget.recipientAvatarUrl!.isNotEmpty
                                                    ? Image.network(
                                                        ApiService.getFullImageUrl(widget.recipientAvatarUrl!),
                                                        fit: BoxFit.cover,
                                                        errorBuilder: (_, __, ___) => _buildAvatarPlaceholder(scale),
                                                      )
                                                    : _buildAvatarPlaceholder(scale),
                                              ),
                                            ),
                                          ),
                                        ],
                                      ),

                                      SizedBox(height: 14 * scale),

                                      // Subtitle / Company Title
                                      Text(
                                        _companyController.text,
                                        style: GoogleFonts.kantumruyPro(
                                          color: const Color(0xFF1E293B),
                                          fontSize: 16 * scale,
                                          fontWeight: FontWeight.bold,
                                        ),
                                      ),
                                      SizedBox(height: 4 * scale),
                                      Text(
                                        'សូមសរសើរចំពោះ',
                                        style: GoogleFonts.kantumruyPro(
                                          color: const Color(0xFFD97706),
                                          fontSize: 17 * scale,
                                          fontWeight: FontWeight.bold,
                                        ),
                                      ),
                                      SizedBox(height: 14 * scale),

                                      // Paragraph Main Body Text
                                      RichText(
                                        textAlign: TextAlign.center,
                                        text: TextSpan(
                                          style: GoogleFonts.kantumruyPro(
                                            color: const Color(0xFF1E293B),
                                            fontSize: 13.5 * scale,
                                            height: 1.6,
                                          ),
                                          children: [
                                            TextSpan(
                                              text: _employeeCategory == 'worker'
                                                  ? 'កម្មករ/បុគ្គលិកប្រតិបត្តិការ ឈ្មោះ ៖ '
                                                  : 'បុគ្គលិកឈ្មោះ ៖ ',
                                            ),
                                            TextSpan(
                                              text: _nameController.text,
                                              style: GoogleFonts.kantumruyPro(
                                                color: const Color(0xFF2563EB),
                                                fontWeight: FontWeight.bold,
                                                fontSize: 15 * scale,
                                              ),
                                            ),
                                            const TextSpan(text: ' ភេទ '),
                                            TextSpan(
                                              text: _genderController.text,
                                              style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
                                            ),
                                            TextSpan(
                                              text: _employeeCategory == 'worker'
                                                  ? ' ផ្នែក '
                                                  : ' ជាបុគ្គលិកផ្នែក ',
                                            ),
                                            TextSpan(
                                              text: _deptController.text,
                                              style: GoogleFonts.kantumruyPro(
                                                color: const Color(0xFF2563EB),
                                                fontWeight: FontWeight.bold,
                                                fontSize: 14 * scale,
                                              ),
                                            ),
                                            TextSpan(
                                              text: _employeeCategory == 'worker'
                                                  ? '\nដែលបានខិតខំប្រឹងប្រែងធ្វើការងារយ៉ាងសកម្ម និងមានភាពស្មោះត្រង់ក្នុងការបំពេញភារកិច្ចជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិក/កម្មករឆ្នើមផ្នែក '
                                                  : '\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើមផ្នែក ',
                                            ),
                                            TextSpan(
                                              text: _locationController.text,
                                              style: GoogleFonts.kantumruyPro(
                                                color: const Color(0xFF2563EB),
                                                fontWeight: FontWeight.bold,
                                                fontSize: 14 * scale,
                                              ),
                                            ),
                                            const TextSpan(text: ' ប្រចាំ '),
                                            TextSpan(
                                              text: _quarterController.text,
                                              style: GoogleFonts.kantumruyPro(
                                                color: const Color(0xFF2563EB),
                                                fontWeight: FontWeight.bold,
                                                fontSize: 14 * scale,
                                              ),
                                            ),
                                            const TextSpan(text: ' ៕'),
                                          ],
                                        ),
                                      ),

                                      const Spacer(),

                                      // Footer Section: Date, Title, Signature & Gold Ribbon Seal
                                      Row(
                                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                        crossAxisAlignment: CrossAxisAlignment.end,
                                        children: [
                                          // Bottom Left: Gold Medal Ribbon Icon (Matching Screenshot!)
                                          Container(
                                            width: 60 * scale,
                                            height: 60 * scale,
                                            decoration: const BoxDecoration(
                                              shape: BoxShape.circle,
                                            ),
                                            child: Icon(
                                              Icons.workspace_premium_rounded,
                                              size: 58 * scale,
                                              color: const Color(0xFFD97706),
                                            ),
                                          ),

                                          // Bottom Right: Signatory & Date
                                          Column(
                                            crossAxisAlignment: CrossAxisAlignment.center,
                                            children: [
                                              Text(
                                                _issueDateController.text,
                                                style: GoogleFonts.kantumruyPro(
                                                  color: const Color(0xFF475569),
                                                  fontSize: 11 * scale,
                                                ),
                                              ),
                                              SizedBox(height: 4 * scale),
                                              Text(
                                                'អគ្គនាយិកា',
                                                style: GoogleFonts.kantumruyPro(
                                                  color: const Color(0xFF0F172A),
                                                  fontSize: 14 * scale,
                                                  fontWeight: FontWeight.bold,
                                                ),
                                              ),
                                              SizedBox(height: 4 * scale),
                                              // Signature Image from Assets
                                              Image.asset(
                                                'assets/certificate_template/sign.png',
                                                height: 38 * scale,
                                                errorBuilder: (_, __, ___) => SizedBox(height: 38 * scale),
                                              ),
                                              SizedBox(height: 2 * scale),
                                              Text(
                                                _signatoryController.text,
                                                style: GoogleFonts.kantumruyPro(
                                                  color: const Color(0xFF0F172A),
                                                  fontSize: 14 * scale,
                                                  fontWeight: FontWeight.bold,
                                                ),
                                              ),
                                            ],
                                          ),
                                        ],
                                      ),
                                    ],
                                  );
                                },
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 16),

            // Inline Editor Form Controls
            if (_showInlineControls)
              Container(
                margin: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(
                  color: const Color(0xFF111E33),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.edit_note_rounded, color: Colors.amberAccent),
                        const SizedBox(width: 8),
                        Text(
                          'កែសម្រួលព័ត៌មានលិខិតសរសើរ (Inline Editor)',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontSize: 15,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 14),
                    Row(
                      children: [
                        Expanded(
                          child: _buildEditorField('ឈ្មោះបុគ្គលិក', _nameController),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: _buildEditorField('ភេទ (ស្រី/ប្រុស)', _genderController),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Row(
                      children: [
                        Expanded(
                          child: _buildEditorField('ផ្នែក/តួនាទី', _deptController),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: _buildEditorField('ទីតាំង/សាខា', _locationController),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Row(
                      children: [
                        Expanded(
                          child: _buildEditorField('ត្រីមាស / ឆ្នាំ', _quarterController),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: _buildEditorField('ឈ្មោះអ្នកចុះហត្ថលេខា', _signatoryController),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    _buildEditorField('កាលបរិច្ឆេទ & ទីតាំងចេញ', _issueDateController),
                  ],
                ),
              ),

            const SizedBox(height: 20),

            // Print / Save PDF Button
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: SizedBox(
                width: double.infinity,
                height: 52,
                child: Container(
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [Color(0xFFF59E0B), Color(0xFFD97706)],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    borderRadius: BorderRadius.circular(16),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.amber.withValues(alpha: 0.35),
                        blurRadius: 14,
                        offset: const Offset(0, 4),
                      ),
                    ],
                  ),
                  child: ElevatedButton.icon(
                    onPressed: _isGeneratingPdf ? null : _printCertificate,
                    icon: _isGeneratingPdf
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black),
                          )
                        : const Icon(Icons.print_rounded, color: Colors.black),
                    label: Text(
                      _isGeneratingPdf ? 'កំពុងរៀបចំ PDF...' : '🖨️ បោះពុម្ព Certificate (A4 Print)',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.black,
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.transparent,
                      shadowColor: Colors.transparent,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                    ),
                  ),
                ),
              ),
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  Widget _buildAvatarPlaceholder(double scale) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.person_rounded, size: 36 * scale, color: Colors.black38),
          Text(
            'Photo',
            style: GoogleFonts.inter(fontSize: 10 * scale, color: Colors.black45),
          ),
        ],
      ),
    );
  }

  Widget _buildEditorField(String label, TextEditingController controller) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12),
        ),
        const SizedBox(height: 4),
        TextField(
          controller: controller,
          onChanged: (_) => setState(() {}),
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13),
          decoration: InputDecoration(
            filled: true,
            fillColor: Colors.white.withValues(alpha: 0.05),
            contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(12),
              borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.1)),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(12),
              borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.1)),
            ),
          ),
        ),
      ],
    );
  }
}
