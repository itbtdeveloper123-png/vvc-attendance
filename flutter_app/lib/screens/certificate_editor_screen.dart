import 'dart:io';
import 'dart:typed_data';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_khmer_chankitec/flutter_khmer_chankitec.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:image_picker/image_picker.dart';
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
  final String initialCategory; // 'head_office', 'warehouse', 'worker', 'skilled'

  const CertificateEditorScreen({
    super.key,
    this.recipientName = 'លី ស៊ាងអ៊ី',
    this.recipientGender = 'ស្រី',
    this.recipientDept = 'គណនេយ្យករ',
    this.recipientLocation = 'ការិយាល័យកណ្តាល',
    this.quarterPeriod = 'ត្រីមាសទី ២',
    this.recipientAvatarUrl,
    this.rankNumber = 1,
    this.initialCategory = 'head_office',
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
  late TextEditingController _yearController;
  late TextEditingController _solarDateController;
  late TextEditingController _lunarDateController;
  late TextEditingController _signatoryController;
  late TextEditingController _signatoryRoleController;
  late TextEditingController _titleController;
  late TextEditingController _companyController;
  late TextEditingController _praiseTitleController;
  late TextEditingController _customBodyTextController;

  // Mode / Category: 'head_office' (ការិយាល័យកណ្តាល), 'warehouse' (ឃ្លាំង), 'worker' (កម្មករ)
  String _selectedCategory = 'head_office';
  int _workerRank = 1; // 1, 2, 3
  int _activePageIndex = 0; // Page 0 or Page 1

  String _selectedTemplateAsset = 'assets/certificate_template/frame_quarter1.jpg';
  DateTime _selectedDate = DateTime(2026, 8, 5);
  bool _isGeneratingPdf = false;
  bool _showInlineControls = true;
  String _activeTab = 'info'; // 'info', 'style', 'text', 'photo'

  // Photo state
  String? _activeAvatarUrl;
  File? _pickedAvatarFile;

  // Custom Full Text Toggle
  bool _isCustomBodyTextEnabled = false;

  // Typography Settings
  String _titleFontFamily = 'Moul';
  String _bodyFontFamily = 'Battambang';
  String _companyFontFamily = 'Moul';
  String _footerFontFamily = 'Battambang';

  double _titleFontSize = 26.0;
  double _companyFontSize = 15.0;
  double _bodyFontSize = 13.5;
  double _bodyLineHeight = 1.6;
  double _footerFontSize = 10.5;
  double _signatoryFontSize = 13.5;
  double _sealSize = 56.0;

  // Text Color highlights
  Color _highlightColor = const Color(0xFF2563EB); // Royal Blue
  Color _titleColor = const Color(0xFF1E3A8A); // Deep Navy

  final List<String> _availableFonts = [
    'Moul',
    'Battambang',
    'Kantumruy Pro',
    'Siemreap',
    'Bayon',
    'Hanuman',
    'Koulen',
    'Bokor',
    'Dangrek',
    'Suwannaphum',
    'Chenla',
    'Preahvihear',
    'KhmerFont',
  ];

  final List<Map<String, String>> _templates = [
    {'name': 'ទម្រង់ទី ១ (Classic Gold)', 'path': 'assets/certificate_template/frame_quarter1.jpg'},
    {'name': 'ទម្រង់ទី ២ (Royal Blue)', 'path': 'assets/certificate_template/frame_quarter2.jpg'},
    {'name': 'ទម្រង់ទី ៣ (Modern Silver)', 'path': 'assets/certificate_template/frame_quarter3.jpg'},
    {'name': 'ទម្រង់ទី ៤ (Elegant Gold)', 'path': 'assets/certificate_template/frame_quarter4.jpg'},
    {'name': 'ទម្រង់ទី ៥ (Platinum Grey)', 'path': 'assets/certificate_template/frame_quarter5.jpg'},
    {'name': 'ទម្រង់ទី ៦ (Premium Diamond)', 'path': 'assets/certificate_template/frame_quarter6.jpg'},
  ];

  final List<Map<String, String>> _standardLocations = [
    {'key': 'head_office', 'name': 'ការិយាល័យកណ្តាល', 'type': 'head_office'},
    {'key': 'warehouse', 'name': 'ឃ្លាំង', 'type': 'warehouse'},
    {'key': 'warehouse_prv', 'name': 'ឃ្លាំង PRV', 'type': 'worker'},
    {'key': 'warehouse_psp', 'name': 'ឃ្លាំង PSP', 'type': 'worker'},
  ];

  @override
  void initState() {
    super.initState();
    _pageController = PageController();
    _workerRank = widget.rankNumber;

    // Detect category from initial parameters
    final initCat = widget.initialCategory.toLowerCase();
    final initLoc = widget.recipientLocation.toLowerCase();

    if (initCat.contains('worker') || initCat.contains('កម្មករ') || initLoc.contains('psp') || initLoc.contains('prv')) {
      _selectedCategory = 'worker';
    } else if (initCat.contains('warehouse') || initCat.contains('ឃ្លាំង') || initLoc.contains('ឃ្លាំង')) {
      _selectedCategory = 'warehouse';
    } else {
      _selectedCategory = 'head_office';
    }

    _nameController = TextEditingController(text: widget.recipientName);
    _genderController = TextEditingController(text: widget.recipientGender);
    _deptController = TextEditingController(text: widget.recipientDept);

    String locText = widget.recipientLocation;
    if (_selectedCategory == 'head_office' && (locText.isEmpty || locText == 'Head Office')) {
      locText = 'ការិយាល័យកណ្តាល';
    } else if (_selectedCategory == 'warehouse' && (locText.isEmpty || locText == 'Warehouse')) {
      locText = 'ឃ្លាំង';
    } else if (_selectedCategory == 'worker') {
      if (locText.toLowerCase().contains('prv')) {
        locText = 'ឃ្លាំង PRV';
      } else {
        locText = 'ព្រៃស្ពឺ(PSP)';
      }
    }
    _locationController = TextEditingController(text: locText);

    String qText = widget.quarterPeriod;
    if (qText.contains('Q1') || qText.contains('១')) {
      qText = 'ត្រីមាសទី ១';
    } else if (qText.contains('Q2') || qText.contains('២')) {
      qText = 'ត្រីមាសទី ២';
    } else if (qText.contains('Q3') || qText.contains('៣')) {
      qText = 'ត្រីមាសទី ៣';
    } else if (qText.contains('Q4') || qText.contains('៤')) {
      qText = 'ត្រីមាសទី ៤';
    } else if (qText.trim().isEmpty) {
      qText = 'ត្រីមាសទី ២';
    }

    _quarterController = TextEditingController(text: qText);
    _yearController = TextEditingController(text: '២០២៦');
    _signatoryController = TextEditingController(text: 'នាត សុវណ្ណ');
    _signatoryRoleController = TextEditingController(text: 'អគ្គនាយិកា');
    _titleController = TextEditingController(text: 'លិខិតសរសើរ');
    _companyController = TextEditingController(text: 'អគ្គនាយិកាក្រុមហ៊ុន វណ្ណ វណ្ណ ខេមបូឌា');
    _praiseTitleController = TextEditingController(text: 'សូមសរសើរចំពោះ ៖');
    _customBodyTextController = TextEditingController();

    _solarDateController = TextEditingController();
    _lunarDateController = TextEditingController();
    _activeAvatarUrl = widget.recipientAvatarUrl;

    _updateKhmerDates(_selectedDate);
    _syncCustomBodyText();
  }

  @override
  void dispose() {
    _pageController.dispose();
    _nameController.dispose();
    _genderController.dispose();
    _deptController.dispose();
    _locationController.dispose();
    _quarterController.dispose();
    _yearController.dispose();
    _solarDateController.dispose();
    _lunarDateController.dispose();
    _signatoryController.dispose();
    _signatoryRoleController.dispose();
    _titleController.dispose();
    _companyController.dispose();
    _praiseTitleController.dispose();
    _customBodyTextController.dispose();
    super.dispose();
  }

  void _onCategoryChanged(String newCat) {
    setState(() {
      _selectedCategory = newCat;
      if (newCat == 'head_office') {
        _locationController.text = 'ការិយាល័យកណ្តាល';
      } else if (newCat == 'warehouse') {
        _locationController.text = 'ឃ្លាំង';
      } else if (newCat == 'worker') {
        if (!_locationController.text.contains('PSP') && !_locationController.text.contains('PRV')) {
          _locationController.text = 'ព្រៃស្ពឺ(PSP)';
        }
      }
      _syncCustomBodyText();
    });
  }

  void _selectStandardLocation(Map<String, String> loc) {
    setState(() {
      _selectedCategory = loc['type']!;
      _locationController.text = loc['name']!;
      if (loc['name'] == 'ឃ្លាំង PSP') {
        _locationController.text = 'ព្រៃស្ពឺ(PSP)';
      }
      _syncCustomBodyText();
    });
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
      _solarDateController.text =
          "រាជធានីភ្នំពេញ, ថ្ងៃទី${_toKhmerDigits(date.day.toString())} ខែ${_getKhmerMonthName(date.month)} ឆ្នាំ${_toKhmerDigits(date.year.toString())}";
    });
  }

  void _syncCustomBodyText() {
    final name = _nameController.text;
    final gender = _genderController.text.trim().isNotEmpty ? ' ភេទ ${_genderController.text}' : '';
    final dept = _deptController.text;
    final quarter = _quarterController.text;
    final year = _yearController.text;
    final location = _locationController.text;

    if (_selectedCategory == 'head_office') {
      _customBodyTextController.text =
          'បុគ្គលិកឈ្មោះ $name$gender ជាបុគ្គលិកផ្នែក $dept\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើមផ្នែក ការិយាល័យកណ្តាល ប្រចាំ $quarter នៃឆ្នាំ $year ៕';
    } else if (_selectedCategory == 'warehouse') {
      _customBodyTextController.text =
          'បុគ្គលិកឈ្មោះ $name$gender ជាបុគ្គលិកផ្នែក $dept\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើមផ្នែក ឃ្លាំង ប្រចាំ $quarter នៃឆ្នាំ $year ៕';
    } else {
      final rankStr = _toKhmerDigits('$_workerRank');
      _customBodyTextController.text =
          'បុគ្គលិកឈ្មោះ $name$gender ជាបុគ្គលិកផ្នែក $dept\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើម លេខ $rankStr នៅឃ្លាំង $location ប្រចាំ $quarter នៃឆ្នាំ $year ៕';
    }
  }

  Future<void> _pickDate() async {
    final picked = await showDatePicker(
      context: context,
      initialDate: _selectedDate,
      firstDate: DateTime(2020),
      lastDate: DateTime(2035),
      builder: (context, child) {
        return Theme(
          data: ThemeData.dark().copyWith(
            colorScheme: const ColorScheme.dark(
              primary: Colors.amberAccent,
              onPrimary: Colors.black,
              surface: Color(0xFF1E293B),
              onSurface: Colors.white,
            ),
          ),
          child: child!,
        );
      },
    );
    if (picked != null) {
      _updateKhmerDates(picked);
    }
  }

  Future<void> _pickAvatarImage() async {
    try {
      final ImagePicker picker = ImagePicker();
      final XFile? image = await picker.pickImage(
        source: ImageSource.gallery,
        maxWidth: 1024,
        maxHeight: 1024,
        imageQuality: 90,
      );
      if (image != null) {
        setState(() {
          _pickedAvatarFile = File(image.path);
        });
      }
    } catch (e) {
      if (mounted) {
        VvcAlert.showError(context, title: 'កំហុសជ្រើសរើសរូបភាព', message: '$e');
      }
    }
  }

  TextStyle _getKhmerTextStyle({
    required String fontFamily,
    double fontSize = 14,
    FontWeight fontWeight = FontWeight.normal,
    Color color = Colors.black,
    double height = 1.4,
    double? letterSpacing,
  }) {
    switch (fontFamily.toLowerCase()) {
      case 'moul':
        return GoogleFonts.moul(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'kantumruy pro':
      case 'kantumruypro':
        return GoogleFonts.kantumruyPro(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'siemreap':
        return GoogleFonts.siemreap(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'bayon':
        return GoogleFonts.bayon(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'hanuman':
        return GoogleFonts.hanuman(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'koulen':
        return GoogleFonts.koulen(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'bokor':
        return GoogleFonts.bokor(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'dangrek':
        return GoogleFonts.dangrek(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'suwannaphum':
        return GoogleFonts.suwannaphum(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'chenla':
        return GoogleFonts.chenla(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'preahvihear':
        return GoogleFonts.preahvihear(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'khmerfont':
        return TextStyle(
          fontFamily: 'KhmerFont',
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
      case 'battambang':
      default:
        return GoogleFonts.battambang(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
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
    final bool isSkilled = _selectedCategory == 'head_office' || _selectedCategory == 'warehouse';

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: const Color(0xFF111E33),
        title: Text(
          'រចនា & បោះពុម្ពលិខិតសរសើរ (A4)',
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
            // Category Tabs: 🏢 ការិយាល័យកណ្តាល | 🏬 ឃ្លាំង | 👷‍♂️ កម្មករ
            Container(
              padding: const EdgeInsets.fromLTRB(12, 10, 12, 8),
              color: const Color(0xFF111E33),
              child: Row(
                children: [
                  Expanded(
                    child: _buildCategoryHeaderTab(
                      key: 'head_office',
                      label: '🏢 ការិយាល័យកណ្តាល',
                      isSelected: _selectedCategory == 'head_office',
                    ),
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: _buildCategoryHeaderTab(
                      key: 'warehouse',
                      label: '🏬 ឃ្លាំង',
                      isSelected: _selectedCategory == 'warehouse',
                    ),
                  ),
                  const SizedBox(width: 6),
                  Expanded(
                    child: _buildCategoryHeaderTab(
                      key: 'worker',
                      label: '👷‍♂️ កម្មករ (PSP/PRV)',
                      isSelected: _selectedCategory == 'worker',
                    ),
                  ),
                ],
              ),
            ),

            // Quick Location Chips Row (ការិយាល័យកណ្តាល, ឃ្លាំង, ឃ្លាំង PRV, ឃ្លាំង PSP)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              color: const Color(0xFF0F1A2E),
              child: Row(
                children: [
                  Text(
                    'ទីតាំង/ឃ្លាំង: ',
                    style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 11.5, fontWeight: FontWeight.bold),
                  ),
                  Expanded(
                    child: SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      child: Row(
                        children: _standardLocations.map((loc) {
                          final bool isLocActive = _locationController.text == loc['name'] ||
                              (_locationController.text == 'ព្រៃស្ពឺ(PSP)' && loc['name'] == 'ឃ្លាំង PSP') ||
                              (_locationController.text == 'ការិយាល័យកណ្តាល' && loc['name'] == 'ការិយាល័យកណ្តាល');
                          return Padding(
                            padding: const EdgeInsets.only(right: 6),
                            child: FilterChip(
                              label: Text(
                                loc['name']!,
                                style: GoogleFonts.kantumruyPro(
                                  color: isLocActive ? Colors.black : Colors.white,
                                  fontSize: 11,
                                  fontWeight: isLocActive ? FontWeight.bold : FontWeight.normal,
                                ),
                              ),
                              selected: isLocActive,
                              selectedColor: Colors.amberAccent,
                              backgroundColor: Colors.white.withValues(alpha: 0.07),
                              checkmarkColor: Colors.black,
                              padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
                              visualDensity: VisualDensity.compact,
                              onSelected: (_) => _selectStandardLocation(loc),
                            ),
                          );
                        }).toList(),
                      ),
                    ),
                  ),
                ],
              ),
            ),

            // Visual Frame Template Selector Gallery
            Container(
              height: 64,
              padding: const EdgeInsets.symmetric(vertical: 6),
              color: const Color(0xFF0A1220),
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 12),
                itemCount: _templates.length,
                itemBuilder: (context, idx) {
                  final t = _templates[idx];
                  final isSelected = _selectedTemplateAsset == t['path'];
                  return GestureDetector(
                    onTap: () => setState(() => _selectedTemplateAsset = t['path']!),
                    child: Container(
                      margin: const EdgeInsets.only(right: 8),
                      padding: const EdgeInsets.all(3),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                          color: isSelected ? Colors.amberAccent : Colors.white.withValues(alpha: 0.1),
                          width: isSelected ? 2 : 1,
                        ),
                      ),
                      child: Row(
                        children: [
                          ClipRRect(
                            borderRadius: BorderRadius.circular(5),
                            child: Image.asset(
                              t['path']!,
                              width: 50,
                              height: 38,
                              fit: BoxFit.cover,
                            ),
                          ),
                          const SizedBox(width: 6),
                          Text(
                            t['name']!,
                            style: GoogleFonts.kantumruyPro(
                              color: isSelected ? Colors.amberAccent : Colors.white70,
                              fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                              fontSize: 11,
                            ),
                          ),
                          if (isSelected) ...[
                            const SizedBox(width: 4),
                            const Icon(Icons.check_circle_rounded, color: Colors.amberAccent, size: 14),
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
                    isSkilled ? '🔍 មើលគំរូ (A4 Certificate Preview)' : '🔍 មើលគំរូ (A4 Certificate Preview)',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white70,
                      fontSize: 12.5,
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

            // Certificate Preview Box (A4 Aspect Ratio: 1.414)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 10),
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

            const SizedBox(height: 14),

            // Customization Control Center (Inline Tabs: Info, Style, Text, Photo)
            if (_showInlineControls)
              Container(
                margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFF111E33),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Sub-navigation tabs
                    Container(
                      padding: const EdgeInsets.all(3),
                      decoration: BoxDecoration(
                        color: Colors.black.withValues(alpha: 0.25),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: Row(
                        children: [
                          _buildSubNavTab('info', '📝 ទិន្នន័យ', Icons.badge_outlined),
                          _buildSubNavTab('style', '🎨 Font & ទំហំ', Icons.text_fields_rounded),
                          _buildSubNavTab('text', '✍️ អត្ថបទសេរី', Icons.edit_note_rounded),
                          _buildSubNavTab('photo', '🖼️ រូបថត', Icons.photo_library_outlined),
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),

                    if (_activeTab == 'info') _buildInfoTabContent(),
                    if (_activeTab == 'style') _buildStyleTabContent(),
                    if (_activeTab == 'text') _buildTextTabContent(),
                    if (_activeTab == 'photo') _buildPhotoTabContent(),
                  ],
                ),
              ),

            const SizedBox(height: 14),

            // Print / Save PDF Button
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 14),
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
                      _isGeneratingPdf ? 'កំពុងរៀបចំ PDF...' : '🖨️ បោះពុម្ពលិខិតសរសើរ (A4 Print / PDF)',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.black,
                        fontWeight: FontWeight.bold,
                        fontSize: 15.5,
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

  Widget _buildCategoryHeaderTab({
    required String key,
    required String label,
    required bool isSelected,
  }) {
    return GestureDetector(
      onTap: () => _onCategoryChanged(key),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 4),
        decoration: BoxDecoration(
          color: isSelected ? Colors.amberAccent : Colors.white.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: isSelected ? Colors.amberAccent : Colors.white.withValues(alpha: 0.1),
          ),
        ),
        child: Center(
          child: Text(
            label,
            textAlign: TextAlign.center,
            style: GoogleFonts.kantumruyPro(
              color: isSelected ? Colors.black : Colors.white70,
              fontWeight: isSelected ? FontWeight.bold : FontWeight.w600,
              fontSize: 11.5,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildSubNavTab(String tabKey, String label, IconData icon) {
    final bool isSelected = _activeTab == tabKey;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _activeTab = tabKey),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          padding: const EdgeInsets.symmetric(vertical: 8),
          decoration: BoxDecoration(
            color: isSelected ? const Color(0xFF1E293B) : Colors.transparent,
            borderRadius: BorderRadius.circular(10),
            border: isSelected ? Border.all(color: Colors.amberAccent.withValues(alpha: 0.4)) : null,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                icon,
                size: 16,
                color: isSelected ? Colors.amberAccent : Colors.white60,
              ),
              const SizedBox(height: 3),
              Text(
                label,
                style: GoogleFonts.kantumruyPro(
                  color: isSelected ? Colors.amberAccent : Colors.white60,
                  fontSize: 10.5,
                  fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildInfoTabContent() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(child: _buildEditorField('ឈ្មោះបុគ្គលិក', _nameController)),
            const SizedBox(width: 10),
            Expanded(child: _buildEditorField('ភេទ (ស្រី/ប្រុស)', _genderController)),
          ],
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(child: _buildEditorField('ផ្នែក/តួនាទី', _deptController)),
            const SizedBox(width: 10),
            Expanded(child: _buildEditorField('ទីតាំង/សាខា/ឃ្លាំង', _locationController)),
          ],
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(child: _buildEditorField('ត្រីមាស (ឧ. ត្រីមាសទី ២)', _quarterController)),
            const SizedBox(width: 10),
            Expanded(child: _buildEditorField('ឆ្នាំ (ឧ. ២០២៦)', _yearController)),
          ],
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(child: _buildEditorField('ឈ្មោះអ្នកចុះហត្ថលេខា', _signatoryController)),
            const SizedBox(width: 10),
            Expanded(child: _buildEditorField('តួនាទីអ្នកចុះហត្ថលេខា', _signatoryRoleController)),
          ],
        ),
        const SizedBox(height: 10),

        // Rank Selection Dropdown (For Worker Tab)
        if (_selectedCategory == 'worker') ...[
          Text('ជ័យលាភីចំណាត់ថ្នាក់ (Rank Selection)',
              style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 12, fontWeight: FontWeight.bold)),
          const SizedBox(height: 4),
          DropdownButtonFormField<int>(
            initialValue: _workerRank,
            dropdownColor: const Color(0xFF1E293B),
            style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13),
            items: const [
              DropdownMenuItem(value: 1, child: Text('🥇 លេខ ១ (ជ័យលាភីលេខ ១)')),
              DropdownMenuItem(value: 2, child: Text('🥈 លេខ ២ (ជ័យលាភីលេខ ២)')),
              DropdownMenuItem(value: 3, child: Text('🥉 លេខ ៣ (ជ័យលាភីលេខ ៣)')),
            ],
            onChanged: (val) {
              if (val != null) {
                setState(() {
                  _workerRank = val;
                  _syncCustomBodyText();
                });
              }
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

        // DatePicker Selection Controls
        _buildFormLabel('កាលបរិច្ឆេទចេញ (ចន្ទគតិ & សុរិយគតិ)'),
        const SizedBox(height: 6),
        InkWell(
          onTap: _pickDate,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 11),
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
                  style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 12, fontWeight: FontWeight.bold),
                ),
                const Icon(Icons.edit_calendar_rounded, color: Colors.amberAccent, size: 18),
              ],
            ),
          ),
        ),
        const SizedBox(height: 8),
        _buildEditorField('ថ្ងៃខែឆ្នាំ (ចន្ទគតិ - ស្វ័យប្រវត្តិ)', _lunarDateController),
        const SizedBox(height: 8),
        _buildEditorField('ទីតាំង & ថ្ងៃខែឆ្នាំ (សុរិយគតិ - ស្វ័យប្រវត្តិ)', _solarDateController),
      ],
    );
  }

  Widget _buildStyleTabContent() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text('🎨 កំណត់ម៉ូតអក្សរ (Font Family)',
                style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold)),
            TextButton.icon(
              onPressed: () {
                setState(() {
                  _titleFontFamily = 'Moul';
                  _bodyFontFamily = 'Battambang';
                  _companyFontFamily = 'Moul';
                  _titleFontSize = 26.0;
                  _bodyFontSize = 13.5;
                  _companyFontSize = 15.0;
                  _footerFontSize = 10.5;
                  _bodyLineHeight = 1.6;
                  _sealSize = 56.0;
                });
              },
              icon: const Icon(Icons.restart_alt_rounded, size: 16, color: Colors.white70),
              label: Text('កំណត់ឡើងវិញ', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 11)),
            ),
          ],
        ),
        const SizedBox(height: 8),

        // Title Font Picker Dropdown
        _buildFontPickerDropdown(
          label: 'Font ចំណងជើងធំ (Title Font)',
          currentFont: _titleFontFamily,
          onSelected: (font) => setState(() => _titleFontFamily = font),
        ),
        const SizedBox(height: 10),

        // Body Font Picker Dropdown
        _buildFontPickerDropdown(
          label: 'Font អត្ថបទតួសេចក្តី (Body Font)',
          currentFont: _bodyFontFamily,
          onSelected: (font) => setState(() => _bodyFontFamily = font),
        ),
        // Footer Font Picker Dropdown
        _buildFontPickerDropdown(
          label: 'Font កាលបរិច្ឆេទ & ហត្ថលេខា (Footer Font)',
          currentFont: _footerFontFamily,
          onSelected: (font) => setState(() => _footerFontFamily = font),
        ),
        const SizedBox(height: 16),

        const Divider(color: Colors.white12),
        const SizedBox(height: 10),

        Text('📏 ទំហំអក្សរ & គម្លាត (Font Sizes & Spacing)',
            style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold)),
        const SizedBox(height: 10),

        _buildSizeSlider(
          label: 'ទំហំចំណងជើងធំ (Title Size)',
          value: _titleFontSize,
          min: 18.0,
          max: 38.0,
          onChanged: (val) => setState(() => _titleFontSize = val),
        ),

        _buildSizeSlider(
          label: 'ទំហំតួសេចក្តី (Body Text Size)',
          value: _bodyFontSize,
          min: 10.0,
          max: 20.0,
          onChanged: (val) => setState(() => _bodyFontSize = val),
        ),

        _buildSizeSlider(
          label: 'គម្លាតបន្ទាត់ (Line Height)',
          value: _bodyLineHeight,
          min: 1.2,
          max: 2.4,
          divisions: 12,
          onChanged: (val) => setState(() => _bodyLineHeight = val),
        ),

        _buildSizeSlider(
          label: 'ទំហំកាលបរិច្ឆេទ (Date/Footer Size)',
          value: _footerFontSize,
          min: 8.0,
          max: 16.0,
          onChanged: (val) => setState(() => _footerFontSize = val),
        ),

        _buildSizeSlider(
          label: 'ទំហំឈ្មោះអ្នកចុះហត្ថលេខា (Signatory Size)',
          value: _signatoryFontSize,
          min: 9.0,
          max: 20.0,
          onChanged: (val) => setState(() => _signatoryFontSize = val),
        ),

        _buildSizeSlider(
          label: 'ទំហំមេដាយ/Seal (Center Seal Size)',
          value: _sealSize,
          min: 36.0,
          max: 80.0,
          onChanged: (val) => setState(() => _sealSize = val),
        ),

        const SizedBox(height: 10),
        const Divider(color: Colors.white12),
        const SizedBox(height: 10),

        Text('🌈 ពណ៌ចំណងជើងធំ (Title Color)',
            style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold)),
        const SizedBox(height: 8),
        Row(
          children: [
            _buildTitleColorOption(const Color(0xFF1E3A8A), 'Navy'),
            _buildTitleColorOption(const Color(0xFF2563EB), 'Blue'),
            _buildTitleColorOption(const Color(0xFFB45309), 'Gold'),
            _buildTitleColorOption(const Color(0xFF047857), 'Green'),
            _buildTitleColorOption(const Color(0xFF991B1B), 'Crimson'),
            _buildTitleColorOption(const Color(0xFF5B21B6), 'Purple'),
            _buildTitleColorOption(const Color(0xFF0F172A), 'Dark'),
          ],
        ),
        const SizedBox(height: 12),

        Text('✨ ពណ៌ Highlight ឈ្មោះ & ផ្នែក (Highlight Color)',
            style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold)),
        const SizedBox(height: 8),
        Row(
          children: [
            _buildColorOption(const Color(0xFF2563EB), 'Blue'),
            _buildColorOption(const Color(0xFF1E3A8A), 'Navy'),
            _buildColorOption(const Color(0xFFD97706), 'Gold'),
            _buildColorOption(const Color(0xFF059669), 'Green'),
            _buildColorOption(const Color(0xFFDC2626), 'Crimson'),
            _buildColorOption(const Color(0xFF7C3AED), 'Purple'),
            _buildColorOption(const Color(0xFF0F172A), 'Dark'),
          ],
        ),
      ],
    );
  }

  Widget _buildTitleColorOption(Color color, String name) {
    final bool isSelected = _titleColor == color;
    return GestureDetector(
      onTap: () => setState(() => _titleColor = color),
      child: Container(
        margin: const EdgeInsets.only(right: 10),
        width: 32,
        height: 32,
        decoration: BoxDecoration(
          color: color,
          shape: BoxShape.circle,
          border: Border.all(
            color: isSelected ? Colors.white : Colors.white24,
            width: isSelected ? 3 : 1,
          ),
          boxShadow: isSelected
              ? [
                  BoxShadow(
                    color: color.withValues(alpha: 0.6),
                    blurRadius: 8,
                    offset: const Offset(0, 2),
                  ),
                ]
              : null,
        ),
        child: isSelected ? const Icon(Icons.check, color: Colors.white, size: 16) : null,
      ),
    );
  }

  Widget _buildColorOption(Color color, String name) {
    final bool isSelected = _highlightColor == color;
    return GestureDetector(
      onTap: () => setState(() => _highlightColor = color),
      child: Container(
        margin: const EdgeInsets.only(right: 10),
        width: 32,
        height: 32,
        decoration: BoxDecoration(
          color: color,
          shape: BoxShape.circle,
          border: Border.all(
            color: isSelected ? Colors.white : Colors.white24,
            width: isSelected ? 3 : 1,
          ),
          boxShadow: isSelected
              ? [
                  BoxShadow(
                    color: color.withValues(alpha: 0.6),
                    blurRadius: 8,
                    offset: const Offset(0, 2),
                  ),
                ]
              : null,
        ),
        child: isSelected ? const Icon(Icons.check, color: Colors.white, size: 16) : null,
      ),
    );
  }

  Widget _buildFontPickerDropdown({
    required String label,
    required String currentFont,
    required ValueChanged<String> onSelected,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 11.5)),
        const SizedBox(height: 4),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12),
          decoration: BoxDecoration(
            color: Colors.white.withValues(alpha: 0.05),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
          ),
          child: DropdownButtonHideUnderline(
            child: DropdownButton<String>(
              value: _availableFonts.contains(currentFont) ? currentFont : 'Battambang',
              isExpanded: true,
              dropdownColor: const Color(0xFF1E293B),
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13),
              icon: const Icon(Icons.arrow_drop_down_rounded, color: Colors.amberAccent),
              items: _availableFonts.map((font) {
                return DropdownMenuItem<String>(
                  value: font,
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        font,
                        style: _getKhmerTextStyle(
                          fontFamily: font,
                          fontSize: 13,
                          color: Colors.white,
                        ),
                      ),
                      Text('គំរូអក្សរ', style: _getKhmerTextStyle(fontFamily: font, fontSize: 11, color: Colors.amberAccent)),
                    ],
                  ),
                );
              }).toList(),
              onChanged: (val) {
                if (val != null) onSelected(val);
              },
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildSizeSlider({
    required String label,
    required double value,
    required double min,
    required double max,
    int? divisions,
    required ValueChanged<double> onChanged,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(label, style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 11.5)),
            Text(
              value.toStringAsFixed(1),
              style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 12, fontWeight: FontWeight.bold),
            ),
          ],
        ),
        SliderTheme(
          data: SliderTheme.of(context).copyWith(
            activeTrackColor: Colors.amberAccent,
            inactiveTrackColor: Colors.white12,
            thumbColor: Colors.amberAccent,
            trackHeight: 3,
            thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 6),
          ),
          child: Slider(
            value: value,
            min: min,
            max: max,
            divisions: divisions,
            onChanged: onChanged,
          ),
        ),
      ],
    );
  }

  Widget _buildTextTabContent() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text('✍️ កែប្រែអត្ថបទពេញលេញ (Custom Body Text)',
                style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold)),
            Switch(
              value: _isCustomBodyTextEnabled,
              activeTrackColor: Colors.amberAccent.withValues(alpha: 0.5),
              activeThumbColor: Colors.amberAccent,
              onChanged: (val) {
                setState(() {
                  _isCustomBodyTextEnabled = val;
                  if (val && _customBodyTextController.text.trim().isEmpty) {
                    _syncCustomBodyText();
                  }
                });
              },
            ),
          ],
        ),
        const SizedBox(height: 6),
        Text(
          'បើក Switch ខាងលើដើម្បីសរសេរ ឬកែសម្រួលពាក្យពេចន៍ក្នុងលិខិតសរសើរដោយសេរីតាមចិត្ត។',
          style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 11.5),
        ),
        const SizedBox(height: 10),
        _buildEditorField('ចំណងជើងលិខិតសរសើរ', _titleController),
        const SizedBox(height: 8),
        _buildEditorField('ចំណងជើងក្រុមហ៊ុន', _companyController),
        const SizedBox(height: 8),
        _buildEditorField('ពាក្យលើកសរសើរ (ឧ. សូមសរសើរចំពោះ ៖)', _praiseTitleController),
        const SizedBox(height: 10),
        Text('អត្ថបទតួសេចក្តីពេញលេញ (Full Body Text):',
            style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
        const SizedBox(height: 4),
        TextField(
          controller: _customBodyTextController,
          enabled: _isCustomBodyTextEnabled,
          maxLines: 5,
          style: _getKhmerTextStyle(
            fontFamily: _bodyFontFamily,
            fontSize: 13,
            color: _isCustomBodyTextEnabled ? Colors.white : Colors.white54,
            height: 1.5,
          ),
          onChanged: (_) => setState(() {}),
          decoration: InputDecoration(
            filled: true,
            fillColor: Colors.white.withValues(alpha: 0.05),
            contentPadding: const EdgeInsets.all(12),
            hintText: 'វាយបញ្ចូលអត្ថបទលិខិតសរសើរនៅទីនេះ...',
            hintStyle: GoogleFonts.kantumruyPro(color: Colors.white30),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(12),
              borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.1)),
            ),
          ),
        ),
        const SizedBox(height: 8),
        Align(
          alignment: Alignment.centerRight,
          child: TextButton.icon(
            onPressed: () {
              setState(() {
                _syncCustomBodyText();
              });
            },
            icon: const Icon(Icons.sync_rounded, size: 16, color: Colors.amberAccent),
            label: Text('បង្កើតតាមទម្រង់ដើមឡើងវិញ', style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 11.5)),
          ),
        ),
      ],
    );
  }

  Widget _buildPhotoTabContent() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('🖼️ រូបថតបុគ្គលិក (Recipient Photo)',
            style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold)),
        const SizedBox(height: 10),
        Row(
          children: [
            Container(
              width: 72,
              height: 90,
              decoration: BoxDecoration(
                color: Colors.white10,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.amberAccent, width: 1.5),
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(6),
                child: _pickedAvatarFile != null
                    ? Image.file(_pickedAvatarFile!, fit: BoxFit.cover)
                    : (_activeAvatarUrl != null && _activeAvatarUrl!.trim().isNotEmpty
                        ? Image.network(
                            ApiService.getFullImageUrl(_activeAvatarUrl!),
                            fit: BoxFit.cover,
                            errorBuilder: (_, __, ___) => const Icon(Icons.person, color: Colors.white54),
                          )
                        : const Icon(Icons.person, color: Colors.white54)),
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  ElevatedButton.icon(
                    onPressed: _pickAvatarImage,
                    icon: const Icon(Icons.photo_camera_rounded, size: 16, color: Colors.black),
                    label: Text('ជ្រើសរើសរូបភាពពីទូរស័ព្ទ',
                        style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 12)),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.amberAccent,
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                    ),
                  ),
                  const SizedBox(height: 6),
                  if (_pickedAvatarFile != null || _activeAvatarUrl != null)
                    TextButton.icon(
                      onPressed: () {
                        setState(() {
                          _pickedAvatarFile = null;
                          _activeAvatarUrl = null;
                        });
                      },
                      icon: const Icon(Icons.delete_outline_rounded, size: 16, color: Colors.redAccent),
                      label: Text('លុបរូបភាពចេញ', style: GoogleFonts.kantumruyPro(color: Colors.redAccent, fontSize: 11.5)),
                    ),
                ],
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildSingleCertificateView({required int pageIndex}) {
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
            // 1. Background Frame Template Image
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
              padding: const EdgeInsets.fromLTRB(36, 28, 36, 18),
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
                                    const SizedBox(height: 4),
                                    Text(
                                      pageIndex == 1 ? 'លិខិតសរសើរ & វាយតម្លៃ' : _titleController.text,
                                      textAlign: TextAlign.center,
                                      style: _getKhmerTextStyle(
                                        fontFamily: _titleFontFamily,
                                        color: _titleColor,
                                        fontSize: _titleFontSize * scale,
                                        fontWeight: FontWeight.bold,
                                        letterSpacing: 1.2,
                                      ),
                                    ),
                                    SizedBox(height: 3 * scale),
                                    // Tacteing Ornate Divider Symbol Line
                                    Row(
                                      mainAxisAlignment: MainAxisAlignment.center,
                                      children: [
                                        Container(
                                          width: 36 * scale,
                                          height: 1,
                                          color: _titleColor.withValues(alpha: 0.4),
                                        ),
                                        Padding(
                                          padding: EdgeInsets.symmetric(horizontal: 6 * scale),
                                          child: Text(
                                            '— ❖ ❖ ❖ —',
                                            style: _getKhmerTextStyle(
                                              fontFamily: _titleFontFamily,
                                              color: _titleColor,
                                              fontSize: 10 * scale,
                                            ),
                                          ),
                                        ),
                                        Container(
                                          width: 36 * scale,
                                          height: 1,
                                          color: _titleColor.withValues(alpha: 0.4),
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
                                    child: _pickedAvatarFile != null
                                        ? Image.file(_pickedAvatarFile!, fit: BoxFit.cover)
                                        : (_activeAvatarUrl != null && _activeAvatarUrl!.trim().isNotEmpty
                                            ? Image.network(
                                                ApiService.getFullImageUrl(_activeAvatarUrl!),
                                                fit: BoxFit.cover,
                                                errorBuilder: (_, __, ___) => _buildAvatarPlaceholder(scale),
                                              )
                                            : _buildAvatarPlaceholder(scale)),
                                  ),
                                ),
                              ),
                            ],
                          ),

                          SizedBox(height: 8 * scale),

                          // Subtitle / Company Title
                          Text(
                            _companyController.text,
                            style: _getKhmerTextStyle(
                              fontFamily: _companyFontFamily,
                              color: const Color(0xFF1E293B),
                              fontSize: _companyFontSize * scale,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          SizedBox(height: 3 * scale),
                          Text(
                            pageIndex == 1 ? 'លទ្ធផលការងារឆ្នើម' : _praiseTitleController.text,
                            style: _getKhmerTextStyle(
                              fontFamily: _companyFontFamily,
                              color: const Color(0xFF1E293B),
                              fontSize: (_companyFontSize + 0.5) * scale,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          SizedBox(height: 10 * scale),

                          // Paragraph Main Body Text
                          if (pageIndex == 0)
                            _buildBodyParagraph(scale)
                          else
                            _buildEvaluationParagraph(scale),

                          const Spacer(),

                          // Footer Section: Dual Dates (Lunar & Solar) and Signatory
                          Row(
                            mainAxisAlignment: MainAxisAlignment.end,
                            crossAxisAlignment: CrossAxisAlignment.end,
                            children: [
                              Column(
                                crossAxisAlignment: CrossAxisAlignment.center,
                                children: [
                                  // Line 1: Khmer Lunar Date
                                  Text(
                                    _lunarDateController.text,
                                    style: _getKhmerTextStyle(
                                      fontFamily: _footerFontFamily,
                                      color: const Color(0xFF334155),
                                      fontSize: _footerFontSize * scale,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                  SizedBox(height: 2 * scale),
                                  // Line 2: Khmer Solar Date
                                  Text(
                                    _solarDateController.text,
                                    style: _getKhmerTextStyle(
                                      fontFamily: _footerFontFamily,
                                      color: const Color(0xFF475569),
                                      fontSize: (_footerFontSize + 0.5) * scale,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  SizedBox(height: 3 * scale),
                                  Text(
                                    _signatoryRoleController.text,
                                    style: _getKhmerTextStyle(
                                      fontFamily: _companyFontFamily,
                                      color: const Color(0xFF0F172A),
                                      fontSize: _signatoryFontSize * scale,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  SizedBox(height: 2 * scale),
                                  // Signature Image from Assets
                                  Image.asset(
                                    'assets/certificate_template/sign.png',
                                    height: 34 * scale,
                                    errorBuilder: (_, __, ___) => SizedBox(height: 34 * scale),
                                  ),
                                  SizedBox(height: 2 * scale),
                                  Text(
                                    _signatoryController.text,
                                    style: _getKhmerTextStyle(
                                      fontFamily: _companyFontFamily,
                                      color: const Color(0xFF0F172A),
                                      fontSize: _signatoryFontSize * scale,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ],
                      ),

                      // Center Award Seal (Medal / Rank / Trophy)
                      Positioned(
                        bottom: 40 * scale,
                        left: 0,
                        right: 0,
                        child: Center(
                          child: Container(
                            width: _sealSize * scale,
                            height: _sealSize * scale,
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
                            child: Center(
                              child: _selectedCategory == 'worker'
                                  ? Text(
                                      _toKhmerDigits('$_workerRank'),
                                      style: _getKhmerTextStyle(
                                        fontFamily: 'Moul',
                                        color: Colors.white,
                                        fontSize: (_sealSize * 0.43) * scale,
                                        fontWeight: FontWeight.bold,
                                      ),
                                    )
                                  : Text(
                                      '១',
                                      style: _getKhmerTextStyle(
                                        fontFamily: 'Moul',
                                        color: Colors.white,
                                        fontSize: (_sealSize * 0.43) * scale,
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

  Widget _buildBodyParagraph(double scale) {
    if (_isCustomBodyTextEnabled && _customBodyTextController.text.trim().isNotEmpty) {
      return Text(
        _customBodyTextController.text,
        textAlign: TextAlign.center,
        style: _getKhmerTextStyle(
          fontFamily: _bodyFontFamily,
          color: const Color(0xFF1E293B),
          fontSize: _bodyFontSize * scale,
          height: _bodyLineHeight,
        ),
      );
    }

    final String name = _nameController.text;
    final String gender = _genderController.text.trim();
    final String dept = _deptController.text;
    final String quarter = _quarterController.text;
    final String year = _yearController.text;
    final String location = _locationController.text;

    if (_selectedCategory == 'head_office') {
      return RichText(
        textAlign: TextAlign.center,
        text: TextSpan(
          style: _getKhmerTextStyle(
            fontFamily: _bodyFontFamily,
            color: const Color(0xFF1E293B),
            fontSize: _bodyFontSize * scale,
            height: _bodyLineHeight,
          ),
          children: [
            const TextSpan(text: 'បុគ្គលិកឈ្មោះ: '),
            TextSpan(
              text: name,
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 1.2) * scale,
              ),
            ),
            if (gender.isNotEmpty) ...[
              const TextSpan(text: ' ភេទ '),
              TextSpan(
                text: gender,
                style: _getKhmerTextStyle(
                  fontFamily: _bodyFontFamily,
                  color: const Color(0xFF1E293B),
                  fontWeight: FontWeight.bold,
                  fontSize: _bodyFontSize * scale,
                ),
              ),
            ],
            const TextSpan(text: ' ជាបុគ្គលិកផ្នែក '),
            TextSpan(
              text: dept,
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(
              text:
                  '\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើមផ្នែក ',
            ),
            TextSpan(
              text: 'ការិយាល័យកណ្តាល',
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(text: ' ប្រចាំ '),
            TextSpan(
              text: quarter,
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 0.5) * scale,
              ),
            ),
            TextSpan(text: ' នៃឆ្នាំ $year ៕'),
          ],
        ),
      );
    } else if (_selectedCategory == 'warehouse') {
      return RichText(
        textAlign: TextAlign.center,
        text: TextSpan(
          style: _getKhmerTextStyle(
            fontFamily: _bodyFontFamily,
            color: const Color(0xFF1E293B),
            fontSize: _bodyFontSize * scale,
            height: _bodyLineHeight,
          ),
          children: [
            const TextSpan(text: 'បុគ្គលិកឈ្មោះ: '),
            TextSpan(
              text: name,
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 1.2) * scale,
              ),
            ),
            if (gender.isNotEmpty) ...[
              const TextSpan(text: ' ភេទ '),
              TextSpan(
                text: gender,
                style: _getKhmerTextStyle(
                  fontFamily: _bodyFontFamily,
                  color: const Color(0xFF1E293B),
                  fontWeight: FontWeight.bold,
                  fontSize: _bodyFontSize * scale,
                ),
              ),
            ],
            const TextSpan(text: ' ជាបុគ្គលិកផ្នែក '),
            TextSpan(
              text: dept,
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(
              text:
                  '\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើមផ្នែក ',
            ),
            TextSpan(
              text: 'ឃ្លាំង',
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(text: ' ប្រចាំ '),
            TextSpan(
              text: quarter,
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 0.5) * scale,
              ),
            ),
            TextSpan(text: ' នៃឆ្នាំ $year ៕'),
          ],
        ),
      );
    } else {
      // Worker Template
      final rankStr = _toKhmerDigits('$_workerRank');
      return RichText(
        textAlign: TextAlign.center,
        text: TextSpan(
          style: _getKhmerTextStyle(
            fontFamily: _bodyFontFamily,
            color: const Color(0xFF1E293B),
            fontSize: _bodyFontSize * scale,
            height: _bodyLineHeight,
          ),
          children: [
            const TextSpan(text: 'បុគ្គលិកឈ្មោះ: '),
            TextSpan(
              text: name,
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 1.2) * scale,
              ),
            ),
            if (gender.isNotEmpty) ...[
              const TextSpan(text: ' ភេទ '),
              TextSpan(
                text: gender,
                style: _getKhmerTextStyle(
                  fontFamily: _bodyFontFamily,
                  color: const Color(0xFF1E293B),
                  fontWeight: FontWeight.bold,
                  fontSize: _bodyFontSize * scale,
                ),
              ),
            ],
            const TextSpan(text: ' ជាបុគ្គលិកផ្នែក '),
            TextSpan(
              text: dept,
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(
              text:
                  '\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើម ',
            ),
            TextSpan(
              text: 'លេខ $rankStr',
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(text: ' នៅឃ្លាំង '),
            TextSpan(
              text: location,
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(text: ' ប្រចាំ '),
            TextSpan(
              text: quarter,
              style: _getKhmerTextStyle(
                fontFamily: _bodyFontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (_bodyFontSize + 0.5) * scale,
              ),
            ),
            TextSpan(text: ' នៃឆ្នាំ $year ៕'),
          ],
        ),
      );
    }
  }

  Widget _buildEvaluationParagraph(double scale) {
    return RichText(
      textAlign: TextAlign.center,
      text: TextSpan(
        style: _getKhmerTextStyle(
          fontFamily: _bodyFontFamily,
          color: const Color(0xFF1E293B),
          fontSize: _bodyFontSize * scale,
          height: _bodyLineHeight,
        ),
        children: [
          const TextSpan(text: 'សម្រាប់ការខិតខំប្រឹងប្រែង និងលទ្ធផលការងារដ៏ឆ្នើមរបស់ '),
          TextSpan(
            text: _nameController.text,
            style: _getKhmerTextStyle(
              fontFamily: _bodyFontFamily,
              color: _highlightColor,
              fontWeight: FontWeight.bold,
              fontSize: (_bodyFontSize + 1) * scale,
            ),
          ),
          TextSpan(
            text: ' ក្នុងការបំពេញភារកិច្ច និងការសម្រេចបាននូវ KPI ខ្ពស់បំផុតប្រចាំ ${_quarterController.text} ជូនក្រុមហ៊ុន វណ្ណ វណ្ណ ខេមបូឌា ៕',
          ),
        ],
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
          onChanged: (_) => setState(() {
            _syncCustomBodyText();
          }),
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
