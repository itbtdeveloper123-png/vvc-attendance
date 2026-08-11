import 'dart:io';
import 'dart:typed_data';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_khmer_chankitec/flutter_khmer_chankitec.dart';
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
  final int rankNumber;

  final String initialCategory;

  const CertificateEditorScreen({
    super.key,
    this.recipientName = 'លី ស៊ាងអ៊ី',
    this.recipientGender = 'ស្រី',
    this.recipientDept = 'គណនេយ្យករ',
    this.recipientLocation = 'ការិយាល័យកណ្តាល',
    this.quarterPeriod = 'ត្រីមាសទី ២ នៃឆ្នាំ ២០២៦',
    this.recipientAvatarUrl,
    this.rankNumber = 1,
    this.initialCategory = 'skilled',
  });

  @override
  State<CertificateEditorScreen> createState() => _CertificateEditorScreenState();
}

class _CertificateEditorScreenState extends State<CertificateEditorScreen> {
  final GlobalKey _previewContainerKey = GlobalKey();
  late PageController _pageController;

  late TextEditingController _nameController;
  late TextEditingController _genderController;
  late TextEditingController _deptController;
  late TextEditingController _locationController;
  late TextEditingController _quarterController;
  late TextEditingController _solarDateController;
  late TextEditingController _lunarDateController;
  late TextEditingController _signatoryController;
  late TextEditingController _titleController;
  late TextEditingController _companyController;

  String _selectedTemplateAsset = 'assets/certificate_template/frame_quarter1.jpg';
  String _employeeCategory = 'skilled'; // 'skilled' (បុគ្គលិកជំនាញ) or 'worker' (កម្មករ)
  int _workerRank = 1; // 1, 2, 3
  int _activePageIndex = 0; // Page 0 or Page 1 for Skilled 2-page swipe

  DateTime _selectedDate = DateTime(2026, 8, 5);
  bool _isGeneratingPdf = false;
  bool _showInlineControls = true;
  String? _activeAvatarUrl;

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
    _pageController = PageController();
    _workerRank = widget.rankNumber;
    _employeeCategory = widget.initialCategory;

    _nameController = TextEditingController(text: widget.recipientName);
    _genderController = TextEditingController(text: widget.recipientGender);
    _deptController = TextEditingController(text: widget.recipientDept);
    _locationController = TextEditingController(text: widget.recipientLocation);
    String qText = widget.quarterPeriod;
    if (qText == 'Q1') {
      qText = 'ត្រីមាសទី ១';
    } else if (qText == 'Q2') {
      qText = 'ត្រីមាសទី ២';
    } else if (qText == 'Q3') {
      qText = 'ត្រីមាសទី ៣';
    } else if (qText == 'Q4') {
      qText = 'ត្រីមាសទី ៤';
    }
    _quarterController = TextEditingController(text: qText);
    _signatoryController = TextEditingController(text: 'នាត សុវណ្ណ');
    _titleController = TextEditingController(text: 'លិខិតសរសើរ');
    _companyController = TextEditingController(text: 'អគ្គនាយិកាក្រុមហ៊ុន វណ្ណ វណ្ណ ខេមបូឌា');

    _solarDateController = TextEditingController();
    _lunarDateController = TextEditingController();
    _activeAvatarUrl = widget.recipientAvatarUrl;

    _updateKhmerDates(_selectedDate);
  }

  @override
  void dispose() {
    _pageController.dispose();
    _nameController.dispose();
    _genderController.dispose();
    _deptController.dispose();
    _locationController.dispose();
    _quarterController.dispose();
    _solarDateController.dispose();
    _lunarDateController.dispose();
    _signatoryController.dispose();
    _titleController.dispose();
    _companyController.dispose();
    super.dispose();
  }

  String _toKhmerDigits(String input) {
    const english = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
    const khmer = ['០', '១', '២', '៣', '៤', '៥', '៦', '៧', '៨', '៩'];
    for (int i = 0; i < english.length; i++) {
      input = input.replaceAll(english[i], khmer[i]);
    }
    return input;
  }

  String _getKhmerMonthName(int month) {
    const months = [
      'មករា', 'កុម្ភៈ', 'មីនា', 'មេសា', 'ឧសភា', 'មិថុនា',
      'កក្កដា', 'សីហា', 'កញ្ញា', 'តុលា', 'វិច្ឆិកា', 'ធ្នូ'
    ];
    return months[month - 1];
  }

  void _updateKhmerDates(DateTime date) {
    _selectedDate = date;
    final lunar = Chhankitek.fromDate(date);

    final dayOfWeek = lunar.format("ថ្ងៃW");
    final lunarDay = lunar.lunarDay.toString();
    final lunarMonth = "ខែ${lunar.format("m")}";
    final lunarYear = "ឆ្នាំ${lunar.format("a")}";
    final era = lunar.format("e");
    final buddhistEra = "ពុទ្ធសករាជ ${lunar.format("b")}";

    setState(() {
      _lunarDateController.text = "$dayOfWeek $lunarDay $lunarMonth $lunarYear $era $buddhistEra";
      _solarDateController.text = "រាជធានីភ្នំពេញ, ថ្ងៃទី${_toKhmerDigits(date.day.toString())} ខែ${_getKhmerMonthName(date.month)} ឆ្នាំ${_toKhmerDigits(date.year.toString())}";
    });
  }

  Future<void> _pickDate() async {
    final picked = await showDatePicker(
      context: context,
      initialDate: _selectedDate,
      firstDate: DateTime(2020),
      lastDate: DateTime(2035),
    );
    if (picked != null) {
      _updateKhmerDates(picked);
    }
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
    final bool isSkilled = _employeeCategory == 'skilled';

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
            // Employee Type Tabs: បុគ្គលិកជំនាញ vs កម្មករ / ប្រតិបត្តិការ
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
                          color: isSkilled ? Colors.amberAccent : Colors.white.withValues(alpha: 0.05),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: isSkilled ? Colors.amberAccent : Colors.white.withValues(alpha: 0.1),
                          ),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.badge_rounded,
                              size: 18,
                              color: isSkilled ? Colors.black : Colors.white70,
                            ),
                            const SizedBox(width: 6),
                            Text(
                              '👔 បុគ្គលិកជំនាញ (២ សន្លឹក)',
                              style: GoogleFonts.kantumruyPro(
                                color: isSkilled ? Colors.black : Colors.white70,
                                fontWeight: FontWeight.bold,
                                fontSize: 13,
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
                          color: !isSkilled ? Colors.cyanAccent : Colors.white.withValues(alpha: 0.05),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: !isSkilled ? Colors.cyanAccent : Colors.white.withValues(alpha: 0.1),
                          ),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.engineering_rounded,
                              size: 18,
                              color: !isSkilled ? Colors.black : Colors.white70,
                            ),
                            const SizedBox(width: 6),
                            Text(
                              '👷‍♂️ កម្មករ (លេខ ១,២,៣)',
                              style: GoogleFonts.kantumruyPro(
                                color: !isSkilled ? Colors.black : Colors.white70,
                                fontWeight: FontWeight.bold,
                                fontSize: 13,
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
              height: 68,
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
                              width: 56,
                              height: 44,
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

            const SizedBox(height: 10),

            // Preview Title & Swipe Navigation Indicator
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 14),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    isSkilled ? '🔍 មើលគំរូ (២ សន្លឹក - Swipe Scroll ↔️)' : '🔍 មើលគំរូ (A4 Preview)',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white70,
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  if (isSkilled)
                    Row(
                      children: [
                        GestureDetector(
                          onTap: () {
                            _pageController.animateToPage(0, duration: const Duration(milliseconds: 300), curve: Curves.easeInOut);
                          },
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                            decoration: BoxDecoration(
                              color: _activePageIndex == 0 ? Colors.amberAccent : Colors.white10,
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Text(
                              'សន្លឹកទី ១',
                              style: GoogleFonts.kantumruyPro(
                                color: _activePageIndex == 0 ? Colors.black : Colors.white70,
                                fontSize: 11,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 6),
                        GestureDetector(
                          onTap: () {
                            _pageController.animateToPage(1, duration: const Duration(milliseconds: 300), curve: Curves.easeInOut);
                          },
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                            decoration: BoxDecoration(
                              color: _activePageIndex == 1 ? Colors.amberAccent : Colors.white10,
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Text(
                              'សន្លឹកទី ២',
                              style: GoogleFonts.kantumruyPro(
                                color: _activePageIndex == 1 ? Colors.black : Colors.white70,
                                fontSize: 11,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                ],
              ),
            ),
            const SizedBox(height: 8),

            // Certificate Preview Stack (Swipeable if Skilled 2-page)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: AspectRatio(
                aspectRatio: 1.414,
                child: isSkilled
                    ? PageView(
                        controller: _pageController,
                        onPageChanged: (idx) => setState(() => _activePageIndex = idx),
                        children: [
                          _buildSingleCertificateView(pageIndex: 0),
                          _buildSingleCertificateView(pageIndex: 1),
                        ],
                      )
                    : _buildSingleCertificateView(pageIndex: 0),
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

                    // Rank Selection Dropdown (Only for Worker Tab)
                    if (!isSkilled) ...[
                      Text('ជ័យលាភី (Award Rank)', style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 12, fontWeight: FontWeight.bold)),
                      const SizedBox(height: 4),
                      DropdownButtonFormField<int>(
                        initialValue: _workerRank,
                        dropdownColor: const Color(0xFF1E293B),
                        style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                        items: const [
                          DropdownMenuItem(value: 1, child: Text('🥇 លេខ ១ (ជ័យលាភីលេខ ១)')),
                          DropdownMenuItem(value: 2, child: Text('🥈 លេខ ២ (ជ័យលាភីលេខ ២)')),
                          DropdownMenuItem(value: 3, child: Text('🥉 លេខ ៣ (ជ័យលាភីលេខ ៣)')),
                        ],
                        onChanged: (val) {
                          if (val != null) setState(() => _workerRank = val);
                        },
                        decoration: InputDecoration(
                          filled: true,
                          fillColor: Colors.white.withValues(alpha: 0.05),
                          contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                          border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                        ),
                      ),
                      const SizedBox(height: 10),
                    ],

                    // DatePicker Selection Controls (Khmer Solar & Lunar Dates)
                    _buildFormLabel('កាលបរិច្ឆេទចេញ (ចន្ទគតិ & សុរិយគតិ)'),
                    const SizedBox(height: 6),
                    Row(
                      children: [
                        Expanded(
                          child: InkWell(
                            onTap: _pickDate,
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
                              decoration: BoxDecoration(
                                color: Colors.white.withValues(alpha: 0.05),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.4)),
                              ),
                              child: Row(
                                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                children: [
                                  Text(
                                    '📅 ជ្រើសរើសថ្ងៃខែឆ្នាំ: ${_selectedDate.year}-${_selectedDate.month.toString().padLeft(2, '0')}-${_selectedDate.day.toString().padLeft(2, '0')}',
                                    style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 12.5, fontWeight: FontWeight.bold),
                                  ),
                                  const Icon(Icons.edit_calendar_rounded, color: Colors.amberAccent, size: 18),
                                ],
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    _buildEditorField('ថ្ងៃខែឆ្នាំ (ចន្ទគតិ - ស្វ័យប្រវត្តិ)', _lunarDateController),
                    const SizedBox(height: 8),
                    _buildEditorField('ទីតាំង & ថ្ងៃខែឆ្នាំ (សុរិយគតិ - ស្វ័យប្រវត្តិ)', _solarDateController),
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

  Widget _buildSingleCertificateView({required int pageIndex}) {
    final bool isSkilled = _employeeCategory == 'skilled';

    return RepaintBoundary(
      key: pageIndex == 0 ? _previewContainerKey : null,
      child: Container(
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(8),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.5),
              blurRadius: 18,
              offset: const Offset(0, 6),
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
              padding: const EdgeInsets.fromLTRB(40, 32, 40, 20),
              child: LayoutBuilder(
                builder: (context, constraints) {
                  final baseWidth = constraints.maxWidth;
                  final scale = baseWidth / 700;

                  return Stack(
                    children: [
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.center,
                        children: [
                          // Top Header & Recipient Photo Box
                          Stack(
                            children: [
                              Align(
                                alignment: Alignment.topCenter,
                                child: Column(
                                  children: [
                                    const SizedBox(height: 6),
                                    Text(
                                      pageIndex == 1 ? 'លិខិតសរសើរ & វាយតម្លៃ' : _titleController.text,
                                      textAlign: TextAlign.center,
                                      style: GoogleFonts.moul(
                                        color: const Color(0xFF1E3A8A),
                                        fontSize: 26 * scale,
                                        fontWeight: FontWeight.bold,
                                        letterSpacing: 1.2,
                                      ),
                                    ),
                                    SizedBox(height: 4 * scale),
                                    // Tacteing Ornate Divider Symbol Line (Tacteing Symbol #3 Style)
                                    Row(
                                      mainAxisAlignment: MainAxisAlignment.center,
                                      children: [
                                        Container(
                                          width: 36 * scale,
                                          height: 1,
                                          color: const Color(0xFF1E3A8A).withValues(alpha: 0.4),
                                        ),
                                        Padding(
                                          padding: EdgeInsets.symmetric(horizontal: 6 * scale),
                                          child: Text(
                                            '— ❖ ❖ ❖ —',
                                            style: GoogleFonts.moul(
                                              color: const Color(0xFF1E3A8A),
                                              fontSize: 10 * scale,
                                            ),
                                          ),
                                        ),
                                        Container(
                                          width: 36 * scale,
                                          height: 1,
                                          color: const Color(0xFF1E3A8A).withValues(alpha: 0.4),
                                        ),
                                      ],
                                    ),
                                  ],
                                ),
                              ),
                              // Recipient Photo Placeholder Top Right
                              Align(
                                alignment: Alignment.topRight,
                                child: Container(
                                  width: 72 * scale,
                                  height: 90 * scale,
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
                                    child: _activeAvatarUrl != null &&
                                            _activeAvatarUrl!.trim().isNotEmpty
                                        ? Image.network(
                                            ApiService.getFullImageUrl(_activeAvatarUrl!),
                                            fit: BoxFit.cover,
                                            errorBuilder: (_, __, ___) => _buildAvatarPlaceholder(scale),
                                          )
                                        : _buildAvatarPlaceholder(scale),
                                  ),
                                ),
                              ),
                            ],
                          ),

                          SizedBox(height: 12 * scale),

                          // Subtitle / Company Title (Khmer OS Muol Light Font)
                          Text(
                            _companyController.text,
                            style: GoogleFonts.moul(
                              color: const Color(0xFF1E293B),
                              fontSize: 15 * scale,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          SizedBox(height: 4 * scale),
                          Text(
                            pageIndex == 1 ? 'លទ្ធផលការងារឆ្នើម' : 'សូមសរសើរចំពោះ ៖',
                            style: GoogleFonts.moul(
                              color: const Color(0xFF1E293B),
                              fontSize: 15.5 * scale,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          SizedBox(height: 12 * scale),

                          // Paragraph Main Body Text (Battambang Font)
                          if (pageIndex == 0)
                            RichText(
                              textAlign: TextAlign.center,
                              text: TextSpan(
                                style: GoogleFonts.battambang(
                                  color: const Color(0xFF1E293B),
                                  fontSize: 13 * scale,
                                  height: 1.6,
                                ),
                                children: [
                                  TextSpan(
                                    text: isSkilled
                                        ? 'បុគ្គលិកឈ្មោះ ៖ '
                                        : 'កម្មករ/បុគ្គលិកប្រតិបត្តិការ ឈ្មោះ ៖ ',
                                  ),
                                  TextSpan(
                                    text: _nameController.text,
                                    style: GoogleFonts.battambang(
                                      color: const Color(0xFF2563EB),
                                      fontWeight: FontWeight.bold,
                                      fontSize: 14.5 * scale,
                                    ),
                                  ),
                                  const TextSpan(text: ' ភេទ '),
                                  TextSpan(
                                    text: _genderController.text,
                                    style: GoogleFonts.battambang(fontWeight: FontWeight.bold),
                                  ),
                                  TextSpan(
                                    text: isSkilled ? ' ជាបុគ្គលិកផ្នែក ' : ' ផ្នែក ',
                                  ),
                                  TextSpan(
                                    text: _deptController.text,
                                    style: GoogleFonts.battambang(
                                      color: const Color(0xFF2563EB),
                                      fontWeight: FontWeight.bold,
                                      fontSize: 13.5 * scale,
                                    ),
                                  ),
                                  TextSpan(
                                    text: isSkilled
                                        ? '\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើមផ្នែក '
                                        : '\nដែលបានខិតខំប្រឹងប្រែងធ្វើការងារយ៉ាងសកម្ម និងមានភាពស្មោះត្រង់ក្នុងការបំពេញភារកិច្ចជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិក/កម្មករឆ្នើមផ្នែក ',
                                  ),
                                  TextSpan(
                                    text: _locationController.text,
                                    style: GoogleFonts.battambang(
                                      color: const Color(0xFF2563EB),
                                      fontWeight: FontWeight.bold,
                                      fontSize: 13.5 * scale,
                                    ),
                                  ),
                                  const TextSpan(text: ' ប្រចាំ '),
                                  TextSpan(
                                    text: _quarterController.text,
                                    style: GoogleFonts.battambang(
                                      color: const Color(0xFF2563EB),
                                      fontWeight: FontWeight.bold,
                                      fontSize: 13.5 * scale,
                                    ),
                                  ),
                                  const TextSpan(text: ' ៕'),
                                ],
                              ),
                            )
                          else
                            RichText(
                              textAlign: TextAlign.center,
                              text: TextSpan(
                                style: GoogleFonts.battambang(
                                  color: const Color(0xFF1E293B),
                                  fontSize: 13 * scale,
                                  height: 1.6,
                                ),
                                children: [
                                  const TextSpan(text: 'សម្រាប់ការខិតខំប្រឹងប្រែង និងលទ្ធផលការងារដ៏ឆ្នើមរបស់ '),
                                  TextSpan(
                                    text: _nameController.text,
                                    style: GoogleFonts.battambang(
                                      color: const Color(0xFF2563EB),
                                      fontWeight: FontWeight.bold,
                                      fontSize: 14 * scale,
                                    ),
                                  ),
                                  TextSpan(
                                    text: ' ក្នុងការដឹកនាំ និងការសម្រេចបាននូវ KPI ខ្ពស់បំផុតប្រចាំ ${_quarterController.text} ជូនក្រុមហ៊ុន វណ្ណ វណ្ណ ខេមបូឌា ៕',
                                  ),
                                ],
                              ),
                            ),

                          const Spacer(),

                          // Footer Section: Khmer Dates & Signatory block
                          Row(
                            mainAxisAlignment: MainAxisAlignment.end,
                            crossAxisAlignment: CrossAxisAlignment.end,
                            children: [
                              // Bottom Right: Dual Dates (Lunar & Solar) and Signatory
                              Column(
                                crossAxisAlignment: CrossAxisAlignment.center,
                                children: [
                                  // Line 1: Khmer Lunar Date (Battambang Font)
                                  Text(
                                    _lunarDateController.text,
                                    style: GoogleFonts.battambang(
                                      color: const Color(0xFF334155),
                                      fontSize: 10 * scale,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                  SizedBox(height: 2 * scale),
                                  // Line 2: Khmer Solar Date (Battambang Font)
                                  Text(
                                    _solarDateController.text,
                                    style: GoogleFonts.battambang(
                                      color: const Color(0xFF475569),
                                      fontSize: 10.5 * scale,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  SizedBox(height: 4 * scale),
                                  Text(
                                    'អគ្គនាយិកា',
                                    style: GoogleFonts.moul(
                                      color: const Color(0xFF0F172A),
                                      fontSize: 13.5 * scale,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  SizedBox(height: 3 * scale),
                                  // Signature Image from Assets
                                  Image.asset(
                                    'assets/certificate_template/sign.png',
                                    height: 36 * scale,
                                    errorBuilder: (_, __, ___) => SizedBox(height: 36 * scale),
                                  ),
                                  SizedBox(height: 2 * scale),
                                  Text(
                                    _signatoryController.text,
                                    style: GoogleFonts.moul(
                                      color: const Color(0xFF0F172A),
                                      fontSize: 13.5 * scale,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ],
                      ),

                      // Center Award Seal (Trophy Icon / Rank Number centered directly on top of the award ribbon background)
                      Positioned(
                        bottom: 44 * scale,
                        left: 0,
                        right: 0,
                        child: Center(
                          child: Container(
                            width: 56 * scale,
                            height: 56 * scale,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              gradient: const LinearGradient(
                                colors: [Color(0xFFF59E0B), Color(0xFFB45309)],
                                begin: Alignment.topLeft,
                                end: Alignment.bottomRight,
                              ),
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.amber.withValues(alpha: 0.4),
                                  blurRadius: 8,
                                  offset: const Offset(0, 3),
                                ),
                              ],
                            ),
                            child: isSkilled
                                ? Icon(
                                    Icons.emoji_events_rounded,
                                    size: 32 * scale,
                                    color: Colors.white,
                                  )
                                : Center(
                                    child: Text(
                                      _toKhmerDigits('$_workerRank'),
                                      style: GoogleFonts.moul(
                                        color: Colors.white,
                                        fontSize: 24 * scale,
                                        fontWeight: FontWeight.bold,
                                      ),
                                    ),
                                  ),
                          ),
                        ),
                      ),
                    ],
                  );
                },
              ),
            ),
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
          Icon(Icons.person_rounded, size: 34 * scale, color: Colors.black38),
          Text(
            'Photo',
            style: GoogleFonts.inter(fontSize: 9.5 * scale, color: Colors.black45),
          ),
        ],
      ),
    );
  }

  Widget _buildFormLabel(String label) {
    return Text(
      label,
      style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12),
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
