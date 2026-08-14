import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_khmer_chankitec/flutter_khmer_chankitec.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:image_picker/image_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import 'package:share_plus/share_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/responsive_layout.dart';
import '../widgets/vvc_global_alert.dart';

/// Class representing an individually editable, styleable, and draggable element on the Certificate Canvas.
class CertItem {
  final String id;
  final String type; // 'text', 'symbol', 'body', 'seal', 'photo', 'signature'
  String title; // Human readable label
  String text;
  String fontFamily;
  double fontSize;
  FontWeight fontWeight;
  Color color;
  double x; // Center X in 700x495 coordinate system
  double y; // Center Y in 700x495 coordinate system
  double width;
  double height;
  TextAlign textAlign;
  bool isVisible;

  CertItem({
    required this.id,
    required this.type,
    required this.title,
    required this.text,
    this.fontFamily = 'Moul',
    this.fontSize = 16.0,
    this.fontWeight = FontWeight.normal,
    this.color = const Color(0xFF1E293B),
    this.x = 350.0,
    this.y = 200.0,
    this.width = 560.0,
    this.height = 40.0,
    this.textAlign = TextAlign.center,
    this.isVisible = true,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'type': type,
    'title': title,
    'text': text,
    'fontFamily': fontFamily,
    'fontSize': fontSize,
    'fontWeight': fontWeight.value,
    'color': color.toARGB32(),
    'x': x,
    'y': y,
    'width': width,
    'height': height,
    'textAlign': textAlign.index,
    'isVisible': isVisible,
  };

  factory CertItem.fromJson(Map<String, dynamic> json) => CertItem(
    id: json['id'] ?? '',
    type: json['type'] ?? 'text',
    title: json['title'] ?? '',
    text: json['text'] ?? '',
    fontFamily: json['fontFamily'] ?? 'Battambang',
    fontSize: (json['fontSize'] as num?)?.toDouble() ?? 14.0,
    fontWeight: FontWeight.values.firstWhere(
      (w) => w.value == json['fontWeight'],
      orElse: () => FontWeight.normal,
    ),
    color: Color(json['color'] ?? 0xFF000000),
    x: (json['x'] as num?)?.toDouble() ?? 350.0,
    y: (json['y'] as num?)?.toDouble() ?? 200.0,
    width: (json['width'] as num?)?.toDouble() ?? 300.0,
    height: (json['height'] as num?)?.toDouble() ?? 40.0,
    textAlign: (json['textAlign'] != null && json['textAlign'] < TextAlign.values.length)
        ? TextAlign.values[json['textAlign']]
        : TextAlign.center,
    isVisible: json['isVisible'] ?? true,
  );

  CertItem copyWith({
    String? text,
    String? fontFamily,
    double? fontSize,
    FontWeight? fontWeight,
    Color? color,
    double? x,
    double? y,
    double? width,
    double? height,
    TextAlign? textAlign,
    bool? isVisible,
  }) {
    return CertItem(
      id: id,
      type: type,
      title: title,
      text: text ?? this.text,
      fontFamily: fontFamily ?? this.fontFamily,
      fontSize: fontSize ?? this.fontSize,
      fontWeight: fontWeight ?? this.fontWeight,
      color: color ?? this.color,
      x: x ?? this.x,
      y: y ?? this.y,
      width: width ?? this.width,
      height: height ?? this.height,
      textAlign: textAlign ?? this.textAlign,
      isVisible: isVisible ?? this.isVisible,
    );
  }
}

/// Canvas State Controller for 120 FPS high-performance isolated rendering & Photoshop-style Layers
class CertCanvasController extends ChangeNotifier {
  final Map<String, CertItem> items = {};
  final List<String> layerOrder = [];
  String? selectedItemId;
  double nudgeStep = 2.0; // 1.0, 2.0, 5.0, 10.0

  void selectItem(String? id) {
    if (selectedItemId != id) {
      selectedItemId = id;
      notifyListeners();
    }
  }

  void moveItem(String id, double deltaDx, double deltaDy) {
    final item = items[id];
    if (item != null) {
      item.x += deltaDx;
      item.y += deltaDy;
      notifyListeners();
    }
  }

  void nudge(String id, double dx, double dy) {
    final item = items[id];
    if (item != null) {
      item.x += dx;
      item.y += dy;
      notifyListeners();
    }
  }

  void toggleVisibility(String id) {
    final item = items[id];
    if (item != null) {
      item.isVisible = !item.isVisible;
      notifyListeners();
    }
  }

  void reorderLayers(int oldIndex, int newIndex) {
    if (oldIndex < newIndex) {
      newIndex -= 1;
    }
    final id = layerOrder.removeAt(oldIndex);
    layerOrder.insert(newIndex, id);
    notifyListeners();
  }

  void updateItem(String id, CertItem updated) {
    items[id] = updated;
    notifyListeners();
  }

  void setItems(Map<String, CertItem> newItems) {
    items.clear();
    items.addAll(newItems);
    layerOrder.clear();
    layerOrder.addAll(newItems.keys);
    notifyListeners();
  }

  void requestRebuild() {
    notifyListeners();
  }
}

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
  final CertCanvasController _canvasController = CertCanvasController();
  final FocusNode _keyboardFocusNode = FocusNode();
  Timer? _autoSaveDebounceTimer;
  bool _isInitialLoading = true;

  // Basic Info Form Controllers
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

  // Category Mode: 'head_office' (ការិយាល័យកណ្តាល), 'warehouse' (ឃ្លាំង), 'worker' (កម្មករ)
  String _selectedCategory = 'head_office';
  int _workerRank = 1;

  String _selectedTemplateAsset = 'assets/certificate_template/frame_quarter1.jpg';
  DateTime _selectedDate = DateTime(2026, 8, 5);
  bool _isGeneratingPdf = false;
  bool _showInlineControls = true;
  String _activeTab = 'layers'; // 'layers', 'nudge', 'info', 'style', 'text', 'photo'

  // Photo state
  String? _activeAvatarUrl;
  File? _pickedAvatarFile;

  // Custom Full Text Toggle
  bool _isCustomBodyTextEnabled = false;

  // Highlight color for structured body spans
  Color _highlightColor = const Color(0xFF2563EB);

  // Cached TextStyle map for ultra-smooth rendering
  final Map<String, TextStyle> _textStyleCache = {};

  final List<String> _availableFonts = [
    'Tacteing',
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

  final List<Color> _availableColors = [
    const Color(0xFF1E3A8A), // Navy
    const Color(0xFF2563EB), // Blue
    const Color(0xFF0F172A), // Dark Slate
    const Color(0xFFD97706), // Gold Amber
    const Color(0xFF047857), // Emerald Green
    const Color(0xFFDC2626), // Crimson Red
    const Color(0xFF7C3AED), // Purple
    const Color(0xFF475569), // Grey Slate
    Colors.black,
    Colors.white,
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

  void _onCanvasChanged() {
    if (_isInitialLoading) return;
    _scheduleAutoSave();
  }

  void _scheduleAutoSave() {
    _autoSaveDebounceTimer?.cancel();
    _autoSaveDebounceTimer = Timer(const Duration(milliseconds: 500), () {
      _saveCertificateToStorage(showToast: false);
    });
  }

  KeyEventResult _handleKeyEvent(FocusNode node, KeyEvent event) {
    if (event is KeyDownEvent || event is KeyRepeatEvent) {
      final bool isShiftPressed = HardwareKeyboard.instance.isShiftPressed;
      final double step = isShiftPressed ? 10.0 : 2.0;
      final selectedId = _canvasController.selectedItemId;

      if (event.logicalKey == LogicalKeyboardKey.arrowUp) {
        if (selectedId != null) {
          _canvasController.nudge(selectedId, 0, -step);
          return KeyEventResult.handled;
        } else if (_canvasController.layerOrder.isNotEmpty) {
          _canvasController.selectItem(_canvasController.layerOrder.last);
          return KeyEventResult.handled;
        }
      } else if (event.logicalKey == LogicalKeyboardKey.arrowDown) {
        if (selectedId != null) {
          _canvasController.nudge(selectedId, 0, step);
          return KeyEventResult.handled;
        } else if (_canvasController.layerOrder.isNotEmpty) {
          _canvasController.selectItem(_canvasController.layerOrder.first);
          return KeyEventResult.handled;
        }
      } else if (event.logicalKey == LogicalKeyboardKey.arrowLeft) {
        if (selectedId != null) {
          _canvasController.nudge(selectedId, -step, 0);
          return KeyEventResult.handled;
        }
      } else if (event.logicalKey == LogicalKeyboardKey.arrowRight) {
        if (selectedId != null) {
          _canvasController.nudge(selectedId, step, 0);
          return KeyEventResult.handled;
        }
      } else if (event.logicalKey == LogicalKeyboardKey.tab) {
        if (_canvasController.layerOrder.isNotEmpty) {
          final currentIdx = selectedId == null ? -1 : _canvasController.layerOrder.indexOf(selectedId);
          final nextIdx = (currentIdx + 1) % _canvasController.layerOrder.length;
          _canvasController.selectItem(_canvasController.layerOrder[nextIdx]);
          return KeyEventResult.handled;
        }
      } else if (event.logicalKey == LogicalKeyboardKey.escape) {
        _canvasController.selectItem(null);
        return KeyEventResult.handled;
      }
    }
    return KeyEventResult.ignored;
  }

  @override
  void initState() {
    super.initState();
    _canvasController.addListener(_onCanvasChanged);
    _workerRank = widget.rankNumber;

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
    _loadCertificateFromStorage();
  }

  @override
  void dispose() {
    _autoSaveDebounceTimer?.cancel();
    _canvasController.removeListener(_onCanvasChanged);
    _keyboardFocusNode.dispose();
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
    _canvasController.dispose();
    super.dispose();
  }

  /// Initialize all individually styleable, draggable elements on the 700x495 canvas.
  void _initCanvasElements() {
    final Map<String, CertItem> items = {};

    items['title'] = CertItem(
      id: 'title',
      type: 'text',
      title: 'ចំណងជើងធំ',
      text: _titleController.text,
      fontFamily: 'Moul',
      fontSize: 28.0,
      fontWeight: FontWeight.bold,
      color: const Color(0xFF1E3A8A),
      x: 350.0,
      y: 48.0,
      width: 400.0,
    );

    items['symbol'] = CertItem(
      id: 'symbol',
      type: 'symbol',
      title: 'ក្បាច់ Divider',
      text: '— ❖ ❖ ❖ —',
      fontFamily: 'Tacteing',
      fontSize: 12.0,
      color: const Color(0xFF1E3A8A),
      x: 350.0,
      y: 74.0,
      width: 200.0,
    );

    items['company'] = CertItem(
      id: 'company',
      type: 'text',
      title: 'ចំណងជើងក្រុមហ៊ុន',
      text: _companyController.text,
      fontFamily: 'Moul',
      fontSize: 15.5,
      fontWeight: FontWeight.bold,
      color: const Color(0xFF1E293B),
      x: 350.0,
      y: 98.0,
      width: 520.0,
    );

    items['praise'] = CertItem(
      id: 'praise',
      type: 'text',
      title: 'ពាក្យលើកសរសើរ',
      text: _praiseTitleController.text,
      fontFamily: 'Moul',
      fontSize: 16.0,
      fontWeight: FontWeight.bold,
      color: const Color(0xFF1E293B),
      x: 350.0,
      y: 122.0,
      width: 400.0,
    );

    items['body'] = CertItem(
      id: 'body',
      type: 'body',
      title: 'អត្ថបទតួសេចក្តី',
      text: _customBodyTextController.text,
      fontFamily: 'Battambang',
      fontSize: 15.0,
      color: const Color(0xFF1E293B),
      x: 350.0,
      y: 192.0,
      width: 580.0,
      height: 85.0,
    );

    items['lunar_date'] = CertItem(
      id: 'lunar_date',
      type: 'text',
      title: 'កាលបរិច្ឆេទចន្ទគតិ',
      text: _lunarDateController.text,
      fontFamily: 'Battambang',
      fontSize: 11.5,
      fontWeight: FontWeight.w600,
      color: const Color(0xFF334155),
      x: 535.0,
      y: 318.0,
      width: 280.0,
    );

    items['solar_date'] = CertItem(
      id: 'solar_date',
      type: 'text',
      title: 'កាលបរិច្ឆេទសុរិយគតិ',
      text: _solarDateController.text,
      fontFamily: 'Battambang',
      fontSize: 12.0,
      fontWeight: FontWeight.bold,
      color: const Color(0xFF475569),
      x: 535.0,
      y: 338.0,
      width: 280.0,
    );

    items['sign_role'] = CertItem(
      id: 'sign_role',
      type: 'text',
      title: 'តួនាទីអ្នកចុះហត្ថលេខា',
      text: _signatoryRoleController.text,
      fontFamily: 'Moul',
      fontSize: 14.5,
      fontWeight: FontWeight.bold,
      color: const Color(0xFF0F172A),
      x: 535.0,
      y: 360.0,
      width: 200.0,
    );

    items['signature'] = CertItem(
      id: 'signature',
      type: 'signature',
      title: 'រូបហត្ថលេខា',
      text: 'assets/certificate_template/sign.png',
      x: 535.0,
      y: 396.0,
      width: 85.0,
      height: 38.0,
    );

    items['sign_name'] = CertItem(
      id: 'sign_name',
      type: 'text',
      title: 'ឈ្មោះអ្នកចុះហត្ថលេខា',
      text: _signatoryController.text,
      fontFamily: 'Moul',
      fontSize: 14.5,
      fontWeight: FontWeight.bold,
      color: const Color(0xFF0F172A),
      x: 535.0,
      y: 432.0,
      width: 200.0,
    );

    items['seal'] = CertItem(
      id: 'seal',
      type: 'seal',
      title: 'មេដាយ/Seal កណ្តាល',
      text: _toKhmerDigits('$_workerRank'),
      fontFamily: 'Moul',
      fontSize: 27.0,
      x: 350.0,
      y: 382.0,
      width: 62.0,
      height: 62.0,
    );

    items['photo'] = CertItem(
      id: 'photo',
      type: 'photo',
      title: 'រូបថតបុគ្គលិក',
      text: '',
      x: 605.0,
      y: 88.0,
      width: 68.0,
      height: 86.0,
    );

    _canvasController.setItems(items);
  }

  void _syncControllersToItems() {
    if (_canvasController.items.containsKey('title')) _canvasController.items['title']!.text = _titleController.text;
    if (_canvasController.items.containsKey('company')) _canvasController.items['company']!.text = _companyController.text;
    if (_canvasController.items.containsKey('praise')) _canvasController.items['praise']!.text = _praiseTitleController.text;
    if (_canvasController.items.containsKey('body') && !_isCustomBodyTextEnabled) _canvasController.items['body']!.text = _customBodyTextController.text;
    if (_canvasController.items.containsKey('lunar_date')) _canvasController.items['lunar_date']!.text = _lunarDateController.text;
    if (_canvasController.items.containsKey('solar_date')) _canvasController.items['solar_date']!.text = _solarDateController.text;
    if (_canvasController.items.containsKey('sign_role')) _canvasController.items['sign_role']!.text = _signatoryRoleController.text;
    if (_canvasController.items.containsKey('sign_name')) _canvasController.items['sign_name']!.text = _signatoryController.text;
    if (_canvasController.items.containsKey('seal')) _canvasController.items['seal']!.text = _toKhmerDigits('$_workerRank');
    _canvasController.requestRebuild();
  }

  void _onCategoryChanged(String newCat) {
    if (_selectedCategory == newCat) return;
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
    _loadCertificateFromStorage();
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
    _loadCertificateFromStorage();
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
      _syncControllersToItems();
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
    if (_canvasController.items.containsKey('body')) {
      _canvasController.items['body']!.text = _customBodyTextController.text;
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
    final cacheKey = '$fontFamily-$fontSize-${fontWeight.value}-${color.toARGB32()}-$height-$letterSpacing';
    if (_textStyleCache.containsKey(cacheKey)) {
      return _textStyleCache[cacheKey]!;
    }

    TextStyle style;
    switch (fontFamily.toLowerCase()) {
      case 'moul':
        style = GoogleFonts.moul(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'kantumruy pro':
      case 'kantumruypro':
        style = GoogleFonts.kantumruyPro(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'siemreap':
        style = GoogleFonts.siemreap(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'bayon':
        style = GoogleFonts.bayon(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'hanuman':
        style = GoogleFonts.hanuman(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'koulen':
        style = GoogleFonts.koulen(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'bokor':
        style = GoogleFonts.bokor(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'dangrek':
        style = GoogleFonts.dangrek(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'suwannaphum':
        style = GoogleFonts.suwannaphum(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'chenla':
        style = GoogleFonts.chenla(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'preahvihear':
        style = GoogleFonts.preahvihear(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'tacteing':
        style = TextStyle(
          fontFamily: 'Tacteing',
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'khmerfont':
        style = TextStyle(
          fontFamily: 'KhmerFont',
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
      case 'battambang':
      default:
        style = GoogleFonts.battambang(
          fontSize: fontSize,
          fontWeight: fontWeight,
          color: color,
          height: height,
          letterSpacing: letterSpacing,
        );
        break;
    }

    _textStyleCache[cacheKey] = style;
    return style;
  }

  Color _parseHexColor(String hexString, {Color fallback = Colors.black}) {
    try {
      String hex = hexString.replaceAll('#', '').trim();
      if (hex.length == 6) {
        hex = 'FF$hex';
      }
      if (hex.length == 8) {
        return Color(int.parse('0x$hex'));
      }
    } catch (_) {}
    return fallback;
  }

  /// Parses rich formatting markup such as [font=Moul]...[/font], [b]...[/b], **...**, [color=#HEX]...[/color], [size=N]...[/size]
  List<InlineSpan> _parseRichTextSpans({
    required String rawText,
    required String baseFontFamily,
    required double baseFontSize,
    required Color baseColor,
    required FontWeight baseFontWeight,
    required double scale,
    double height = 1.5,
  }) {
    if (!rawText.contains('[') && !rawText.contains('*')) {
      return [
        TextSpan(
          text: rawText,
          style: _getKhmerTextStyle(
            fontFamily: baseFontFamily,
            fontSize: baseFontSize * scale,
            color: baseColor,
            fontWeight: baseFontWeight,
            height: height,
          ),
        ),
      ];
    }

    final List<InlineSpan> spans = [];
    final RegExp tagRegex = RegExp(
      r'\[font=([^\]]+)\](.*?)\[\/font\]|\[color=([^\]]+)\](.*?)\[\/color\]|\[size=([^\]]+)\](.*?)\[\/size\]|\[b\](.*?)\[\/b\]|\*\*(.*?)\*\*',
      dotAll: true,
      caseSensitive: false,
    );

    int lastIndex = 0;
    for (final Match match in tagRegex.allMatches(rawText)) {
      if (match.start > lastIndex) {
        final preText = rawText.substring(lastIndex, match.start);
        spans.add(TextSpan(
          text: preText,
          style: _getKhmerTextStyle(
            fontFamily: baseFontFamily,
            fontSize: baseFontSize * scale,
            color: baseColor,
            fontWeight: baseFontWeight,
            height: height,
          ),
        ));
      }

      String spanText = '';
      String currentFont = baseFontFamily;
      Color currentColor = baseColor;
      double currentSize = baseFontSize;
      FontWeight currentWeight = baseFontWeight;

      if (match.group(1) != null) {
        currentFont = match.group(1)!.trim();
        spanText = match.group(2) ?? '';
      } else if (match.group(3) != null) {
        currentColor = _parseHexColor(match.group(3)!.trim(), fallback: baseColor);
        spanText = match.group(4) ?? '';
      } else if (match.group(5) != null) {
        final sz = double.tryParse(match.group(5)!.trim());
        if (sz != null) currentSize = sz;
        spanText = match.group(6) ?? '';
      } else if (match.group(7) != null) {
        currentWeight = FontWeight.bold;
        spanText = match.group(7) ?? '';
      } else if (match.group(8) != null) {
        currentWeight = FontWeight.bold;
        spanText = match.group(8) ?? '';
      }

      spans.add(TextSpan(
        text: spanText,
        style: _getKhmerTextStyle(
          fontFamily: currentFont,
          fontSize: currentSize * scale,
          color: currentColor,
          fontWeight: currentWeight,
          height: height,
        ),
      ));

      lastIndex = match.end;
    }

    if (lastIndex < rawText.length) {
      final postText = rawText.substring(lastIndex);
      spans.add(TextSpan(
        text: postText,
        style: _getKhmerTextStyle(
          fontFamily: baseFontFamily,
          fontSize: baseFontSize * scale,
          color: baseColor,
          fontWeight: baseFontWeight,
          height: height,
        ),
      ));
    }

    return spans;
  }

  /// Persistent Database Save: saves all custom certificate items, template, and texts to SharedPreferences
  Future<void> _saveCertificateToStorage({bool showToast = true}) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final Map<String, dynamic> itemsJson = {};
      _canvasController.items.forEach((key, item) {
        itemsJson[key] = item.toJson();
      });

      final keyPrefix = 'vvc_cert_$_selectedCategory';
      await prefs.setString('${keyPrefix}_items', jsonEncode(itemsJson));
      await prefs.setStringList('${keyPrefix}_order', _canvasController.layerOrder);
      await prefs.setString('${keyPrefix}_template', _selectedTemplateAsset);
      await prefs.setBool('${keyPrefix}_custom_body_enabled', _isCustomBodyTextEnabled);

      // Save form controller texts
      final Map<String, String> formsMap = {
        'title': _titleController.text,
        'company': _companyController.text,
        'praise': _praiseTitleController.text,
        'custom_body': _customBodyTextController.text,
        'signatory': _signatoryController.text,
        'signatory_role': _signatoryRoleController.text,
        'location': _locationController.text,
        'quarter': _quarterController.text,
        'year': _yearController.text,
      };
      await prefs.setString('${keyPrefix}_forms', jsonEncode(formsMap));

      // Sync to Central Server Cloud Database (so other computers & devices can sync)
      try {
        final cloudPayload = {
          'items': itemsJson,
          'order': _canvasController.layerOrder,
          'template': _selectedTemplateAsset,
          'custom_body_enabled': _isCustomBodyTextEnabled,
          'forms': formsMap,
          'updated_at': DateTime.now().toIso8601String(),
        };
        await ApiService().saveCertificateTemplate(
          category: _selectedCategory,
          templateData: jsonEncode(cloudPayload),
        );
      } catch (cloudErr) {
        debugPrint('Cloud sync notice: $cloudErr');
      }

      if (showToast && mounted) {
        VvcAlert.showSuccess(
          context,
          title: 'ជោគជ័យ',
          message: 'បានរក្សាទុកទិន្នន័យក្នុង Server Database និង Local Storage រួចរាល់!',
        );
      }
    } catch (e) {
      debugPrint('Error saving certificate: $e');
      if (showToast && mounted) {
        VvcAlert.showError(context, title: 'កំហុស', message: 'មិនអាចរក្សាទុកទិន្នន័យបានទេ: $e');
      }
    }
  }

  /// Persistent Database Load: loads from local cache and syncs with Server Cloud Database
  Future<void> _loadCertificateFromStorage() async {
    _isInitialLoading = true;
    try {
      final prefs = await SharedPreferences.getInstance();
      final keyPrefix = 'vvc_cert_$_selectedCategory';
      final String? itemsRaw = prefs.getString('${keyPrefix}_items');

      bool loadedFromLocal = false;
      if (itemsRaw != null && itemsRaw.isNotEmpty) {
        final Map<String, dynamic> decoded = jsonDecode(itemsRaw);
        final Map<String, CertItem> loadedItems = {};
        decoded.forEach((key, val) {
          loadedItems[key] = CertItem.fromJson(Map<String, dynamic>.from(val));
        });

        final List<String>? savedOrder = prefs.getStringList('${keyPrefix}_order');
        final String? savedTemplate = prefs.getString('${keyPrefix}_template');
        final bool? savedBodyEnabled = prefs.getBool('${keyPrefix}_custom_body_enabled');
        final String? formsRaw = prefs.getString('${keyPrefix}_forms');

        if (formsRaw != null && formsRaw.isNotEmpty) {
          final Map<String, dynamic> formsDecoded = jsonDecode(formsRaw);
          if (formsDecoded['title'] != null) _titleController.text = formsDecoded['title'];
          if (formsDecoded['company'] != null) _companyController.text = formsDecoded['company'];
          if (formsDecoded['praise'] != null) _praiseTitleController.text = formsDecoded['praise'];
          if (formsDecoded['custom_body'] != null) _customBodyTextController.text = formsDecoded['custom_body'];
          if (formsDecoded['signatory'] != null) _signatoryController.text = formsDecoded['signatory'];
          if (formsDecoded['signatory_role'] != null) _signatoryRoleController.text = formsDecoded['signatory_role'];
          if (formsDecoded['location'] != null && _locationController.text.isEmpty) _locationController.text = formsDecoded['location'];
        }

        if (savedTemplate != null) _selectedTemplateAsset = savedTemplate;
        if (savedBodyEnabled != null) _isCustomBodyTextEnabled = savedBodyEnabled;

        _canvasController.setItems(loadedItems);
        if (savedOrder != null && savedOrder.isNotEmpty) {
          _canvasController.layerOrder.clear();
          _canvasController.layerOrder.addAll(savedOrder);
        }
        _canvasController.requestRebuild();
        if (mounted) setState(() {});
        loadedFromLocal = true;
      }

      if (!loadedFromLocal) {
        _initCanvasElements();
        await _syncFromCloudDatabase(forceApply: true);
      } else {
        _syncFromCloudDatabase(forceApply: false);
      }
    } catch (e) {
      debugPrint('Error loading saved certificate: $e');
      _initCanvasElements();
    } finally {
      _isInitialLoading = false;
    }
  }

  Future<void> _syncFromCloudDatabase({bool forceApply = false}) async {
    try {
      final res = await ApiService().getCertificateTemplate(_selectedCategory);
      if (res['success'] == true && res['data'] != null) {
        final Map<String, dynamic> cloudData = Map<String, dynamic>.from(res['data']);
        if (cloudData['items'] != null && (forceApply || _canvasController.items.isEmpty)) {
          final Map<String, dynamic> itemsMap = Map<String, dynamic>.from(cloudData['items']);
          final Map<String, CertItem> cloudItems = {};
          itemsMap.forEach((k, v) {
            cloudItems[k] = CertItem.fromJson(Map<String, dynamic>.from(v));
          });

          if (cloudData['forms'] != null) {
            final forms = Map<String, dynamic>.from(cloudData['forms']);
            if (forms['title'] != null) _titleController.text = forms['title'];
            if (forms['company'] != null) _companyController.text = forms['company'];
            if (forms['praise'] != null) _praiseTitleController.text = forms['praise'];
            if (forms['custom_body'] != null) _customBodyTextController.text = forms['custom_body'];
            if (forms['signatory'] != null) _signatoryController.text = forms['signatory'];
            if (forms['signatory_role'] != null) _signatoryRoleController.text = forms['signatory_role'];
            if (forms['location'] != null && _locationController.text.isEmpty) _locationController.text = forms['location'];
          }

          if (cloudData['template'] != null) _selectedTemplateAsset = cloudData['template'];
          if (cloudData['custom_body_enabled'] != null) _isCustomBodyTextEnabled = cloudData['custom_body_enabled'] == true;

          _canvasController.setItems(cloudItems);
          if (cloudData['order'] != null) {
            final List<dynamic> orderList = cloudData['order'];
            _canvasController.layerOrder.clear();
            _canvasController.layerOrder.addAll(orderList.map((e) => e.toString()));
          }
          _canvasController.requestRebuild();
          if (mounted) setState(() {});
        }
      }
    } catch (e) {
      debugPrint('Cloud fetch notice: $e');
    }
  }

  /// Reset to standard default template
  Future<void> _resetCertificateToDefault() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1E293B),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Row(
          children: [
            const Icon(Icons.refresh_rounded, color: Colors.amberAccent),
            const SizedBox(width: 8),
            Text('កំណត់ឡើងវិញ', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
          ],
        ),
        content: Text(
          'តើលោកអ្នកចង់កំណត់ទម្រង់ និងទីតាំងធាតុទាំងអស់ទៅជាលំនាំដើមវិញដែរឬទេ?',
          style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: Colors.white60)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.amberAccent),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text('កំណត់ឡើងវិញ', style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      final prefs = await SharedPreferences.getInstance();
      final keyPrefix = 'vvc_cert_$_selectedCategory';
      await prefs.remove('${keyPrefix}_items');
      await prefs.remove('${keyPrefix}_order');
      await prefs.remove('${keyPrefix}_template');
      await prefs.remove('${keyPrefix}_forms');
      await prefs.remove('${keyPrefix}_custom_body_enabled');

      setState(() {
        _isCustomBodyTextEnabled = false;
        _initCanvasElements();
        _syncCustomBodyText();
        _syncControllersToItems();
      });

      if (mounted) {
        VvcAlert.showSuccess(context, title: 'ជោគជ័យ', message: 'បានកំណត់ទម្រង់ទៅជាលំនាំដើមវិញរួចរាល់');
      }
    }
  }

  IconData _getLayerIcon(String type) {
    switch (type) {
      case 'title':
        return Icons.title_rounded;
      case 'symbol':
        return Icons.auto_awesome_rounded;
      case 'company':
        return Icons.business_rounded;
      case 'praise':
        return Icons.military_tech_rounded;
      case 'body':
        return Icons.article_rounded;
      case 'lunar_date':
        return Icons.nights_stay_rounded;
      case 'solar_date':
        return Icons.wb_sunny_rounded;
      case 'sign_role':
        return Icons.badge_rounded;
      case 'signature':
        return Icons.draw_rounded;
      case 'sign_name':
        return Icons.person_pin_rounded;
      case 'seal':
        return Icons.workspace_premium_rounded;
      case 'photo':
        return Icons.image_rounded;
      default:
        return Icons.layers_rounded;
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

  /// Opens the Quick Direct Text & Font Editing Form Modal for a single element
  void _openElementEditForm(CertItem item) {
    final textEditCtrl = TextEditingController(text: item.text);
    String selectedFont = item.fontFamily;
    double currentFontSize = item.fontSize;
    Color currentColor = item.color;
    FontWeight currentWeight = item.fontWeight;
    TextAlign currentAlign = item.textAlign;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF1E293B),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (ctx) {
        return StatefulBuilder(
          builder: (modalCtx, setModalState) {
            // Helper to apply formatting to selected text or whole element
            void applyFormattingToSelection({
              String? font,
              bool? bold,
              Color? color,
              double? size,
              bool clearTags = false,
            }) {
              final selection = textEditCtrl.selection;
              final text = textEditCtrl.text;

              if (clearTags) {
                final cleaned = text
                    .replaceAll(RegExp(r'\[\/?(font|color|size|b)[^\]]*\]'), '')
                    .replaceAll('**', '');
                textEditCtrl.text = cleaned;
                setModalState(() {});
                return;
              }

              if (!selection.isValid || selection.isCollapsed || selection.start == selection.end) {
                // No text selected -> Apply as default for the whole element
                if (font != null) setModalState(() => selectedFont = font);
                if (bold != null) setModalState(() => currentWeight = bold ? FontWeight.bold : FontWeight.normal);
                if (color != null) setModalState(() => currentColor = color);
                if (size != null) setModalState(() => currentFontSize = size);
                return;
              }

              final selectedText = text.substring(selection.start, selection.end);
              String formattedText = selectedText;

              if (font != null) {
                formattedText = '[font=$font]$formattedText[/font]';
              }
              if (bold == true) {
                formattedText = '[b]$formattedText[/b]';
              }
              if (color != null) {
                final hexStr = '#${color.toARGB32().toRadixString(16).padLeft(8, '0').substring(2).toUpperCase()}';
                formattedText = '[color=$hexStr]$formattedText[/color]';
              }
              if (size != null) {
                formattedText = '[size=${size.toInt()}]$formattedText[/size]';
              }

              final newText = text.replaceRange(selection.start, selection.end, formattedText);
              final newSelectionIndex = selection.start + formattedText.length;
              textEditCtrl.value = TextEditingValue(
                text: newText,
                selection: TextSelection.collapsed(offset: newSelectionIndex),
              );
              setModalState(() {});
            }

            return Padding(
              padding: EdgeInsets.only(
                left: 20,
                right: 20,
                top: 20,
                bottom: MediaQuery.of(ctx).viewInsets.bottom + 24,
              ),
              child: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Header Bar
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.edit_note_rounded, color: Colors.amberAccent, size: 24),
                            const SizedBox(width: 8),
                            Text(
                              'កែប្រែ៖ ${item.title}',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.amberAccent,
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ],
                        ),
                        IconButton(
                          icon: const Icon(Icons.close_rounded, color: Colors.white70),
                          onPressed: () => Navigator.pop(ctx),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),

                    // Rich Text Selection Formatting Bar
                    if (item.type != 'photo' && item.type != 'signature') ...[
                      Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: const Color(0xFF0F172A),
                          borderRadius: BorderRadius.circular(14),
                          border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.3)),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                const Icon(Icons.text_format_rounded, color: Colors.amberAccent, size: 16),
                                const SizedBox(width: 6),
                                Text(
                                  'Select ពាក្យ រួចចុច Font ដើម្បីប្តូរតែពាក្យនោះ ៖',
                                  style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 11.5, fontWeight: FontWeight.bold),
                                ),
                                const Spacer(),
                                InkWell(
                                  onTap: () => applyFormattingToSelection(clearTags: true),
                                  child: Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                    decoration: BoxDecoration(
                                      color: Colors.white10,
                                      borderRadius: BorderRadius.circular(6),
                                    ),
                                    child: Text('សម្អាត Tag', style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 10)),
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 8),
                            // Quick Font Selection Chips
                            SingleChildScrollView(
                              scrollDirection: Axis.horizontal,
                              physics: const BouncingScrollPhysics(),
                              child: Row(
                                children: _availableFonts.map((font) {
                                  return Padding(
                                    padding: const EdgeInsets.only(right: 6),
                                    child: ActionChip(
                                      backgroundColor: selectedFont == font ? Colors.amberAccent : const Color(0xFF1E293B),
                                      side: BorderSide(color: selectedFont == font ? Colors.amberAccent : Colors.white24),
                                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                      label: Text(
                                        font,
                                        style: _getKhmerTextStyle(
                                          fontFamily: font,
                                          fontSize: 11,
                                          color: selectedFont == font ? Colors.black : Colors.white,
                                          fontWeight: FontWeight.bold,
                                        ),
                                      ),
                                      onPressed: () => applyFormattingToSelection(font: font),
                                    ),
                                  );
                                }).toList(),
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 12),

                      // Text Input Field
                      Text(
                        'ខ្លឹមសារអត្ថបទ (Text Content):',
                        style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5),
                      ),
                      const SizedBox(height: 6),
                      TextField(
                        controller: textEditCtrl,
                        maxLines: item.type == 'body' ? 5 : 2,
                        onChanged: (_) => setModalState(() {}),
                        style: _getKhmerTextStyle(
                          fontFamily: selectedFont,
                          fontSize: 14,
                          color: Colors.white,
                        ),
                        decoration: InputDecoration(
                          filled: true,
                          fillColor: Colors.white.withValues(alpha: 0.06),
                          contentPadding: const EdgeInsets.all(12),
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(12),
                            borderSide: const BorderSide(color: Colors.white24),
                          ),
                          enabledBorder: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(12),
                            borderSide: const BorderSide(color: Colors.white24),
                          ),
                        ),
                      ),
                      const SizedBox(height: 10),

                      // Live Rendered Preview Card (White background like real certificate)
                      Container(
                        width: double.infinity,
                        decoration: BoxDecoration(
                          color: Colors.cyanAccent.withValues(alpha: 0.08),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: Colors.cyanAccent.withValues(alpha: 0.4)),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Padding(
                              padding: const EdgeInsets.fromLTRB(12, 10, 12, 6),
                              child: Row(
                                children: [
                                  const Icon(Icons.visibility_rounded, color: Colors.cyanAccent, size: 14),
                                  const SizedBox(width: 6),
                                  Text(
                                    'គំរូអត្ថបទជាក់ស្តែង (Live Preview on Certificate):',
                                    style: GoogleFonts.kantumruyPro(color: Colors.cyanAccent, fontSize: 11, fontWeight: FontWeight.bold),
                                  ),
                                ],
                              ),
                            ),
                            // White card simulating real certificate background
                            Container(
                              width: double.infinity,
                              margin: const EdgeInsets.fromLTRB(10, 0, 10, 10),
                              padding: const EdgeInsets.all(14),
                              decoration: BoxDecoration(
                                color: Colors.white,
                                borderRadius: BorderRadius.circular(8),
                                boxShadow: [
                                  BoxShadow(
                                    color: Colors.black.withValues(alpha: 0.2),
                                    blurRadius: 6,
                                    offset: const Offset(0, 2),
                                  ),
                                ],
                              ),
                              child: RichText(
                                textAlign: currentAlign,
                                text: TextSpan(
                                  children: _parseRichTextSpans(
                                    rawText: textEditCtrl.text,
                                    baseFontFamily: selectedFont,
                                    baseFontSize: currentFontSize.clamp(10.0, 18.0),
                                    baseColor: (currentColor == Colors.white || currentColor == const Color(0xFFFFFFFF))
                                        ? Colors.black87
                                        : currentColor,
                                    baseFontWeight: currentWeight,
                                    scale: 1.0,
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 14),
                    ],

                    // Font Selection Dropdown (Base Font)
                    if (item.type != 'photo' && item.type != 'signature') ...[
                      Text(
                        'ម៉ូតអក្សរគោលសម្រាប់ធាតុនេះ (Base Font Family):',
                        style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5),
                      ),
                      const SizedBox(height: 6),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 12),
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.06),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: Colors.white24),
                        ),
                        child: DropdownButtonHideUnderline(
                          child: DropdownButton<String>(
                            value: _availableFonts.contains(selectedFont) ? selectedFont : 'Battambang',
                            isExpanded: true,
                            dropdownColor: const Color(0xFF0F172A),
                            icon: const Icon(Icons.arrow_drop_down_rounded, color: Colors.amberAccent),
                            items: _availableFonts.map((font) {
                              return DropdownMenuItem<String>(
                                value: font,
                                child: Row(
                                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                  children: [
                                    Text(
                                      font,
                                      style: _getKhmerTextStyle(fontFamily: font, fontSize: 13, color: Colors.white),
                                    ),
                                    Text(
                                      'គំរូអក្សរ ខ្មែរ',
                                      style: _getKhmerTextStyle(fontFamily: font, fontSize: 11.5, color: Colors.amberAccent),
                                    ),
                                  ],
                                ),
                              );
                            }).toList(),
                            onChanged: (val) {
                              if (val != null) {
                                setModalState(() => selectedFont = val);
                              }
                            },
                          ),
                        ),
                      ),
                      const SizedBox(height: 14),

                      // Font Size Slider
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            'ទំហំអក្សរ (Font Size):',
                            style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5),
                          ),
                          Text(
                            currentFontSize.toStringAsFixed(1),
                            style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontWeight: FontWeight.bold, fontSize: 13),
                          ),
                        ],
                      ),
                      SliderTheme(
                        data: SliderTheme.of(context).copyWith(
                          activeTrackColor: Colors.amberAccent,
                          inactiveTrackColor: Colors.white12,
                          thumbColor: Colors.amberAccent,
                        ),
                        child: Slider(
                          value: currentFontSize,
                          min: 8.0,
                          max: 48.0,
                          onChanged: (v) => setModalState(() => currentFontSize = v),
                        ),
                      ),
                      const SizedBox(height: 10),

                      // Text Color Palette
                      Text(
                        'ពណ៌អក្សរ (Text Color / Apply to Selection):',
                        style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5),
                      ),
                      const SizedBox(height: 8),
                      SingleChildScrollView(
                        scrollDirection: Axis.horizontal,
                        child: Row(
                          children: _availableColors.map((c) {
                            final bool isSel = currentColor == c;
                            return GestureDetector(
                              onTap: () {
                                if (textEditCtrl.selection.isValid && !textEditCtrl.selection.isCollapsed) {
                                  applyFormattingToSelection(color: c);
                                } else {
                                  setModalState(() => currentColor = c);
                                }
                              },
                              child: Container(
                                margin: const EdgeInsets.only(right: 8),
                                width: 32,
                                height: 32,
                                decoration: BoxDecoration(
                                  color: c,
                                  shape: BoxShape.circle,
                                  border: Border.all(
                                    color: isSel ? Colors.white : Colors.white24,
                                    width: isSel ? 3 : 1,
                                  ),
                                ),
                                child: isSel ? const Icon(Icons.check, color: Colors.white, size: 16) : null,
                              ),
                            );
                          }).toList(),
                        ),
                      ),
                      const SizedBox(height: 14),

                      // Alignment and Bold Stepper
                      Row(
                        children: [
                          Text('ទម្រង់តម្រឹម:', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5)),
                          const SizedBox(width: 10),
                          IconButton(
                            icon: Icon(Icons.format_align_left_rounded, color: currentAlign == TextAlign.left ? Colors.amberAccent : Colors.white54),
                            onPressed: () => setModalState(() => currentAlign = TextAlign.left),
                          ),
                          IconButton(
                            icon: Icon(Icons.format_align_center_rounded, color: currentAlign == TextAlign.center ? Colors.amberAccent : Colors.white54),
                            onPressed: () => setModalState(() => currentAlign = TextAlign.center),
                          ),
                          IconButton(
                            icon: Icon(Icons.format_align_right_rounded, color: currentAlign == TextAlign.right ? Colors.amberAccent : Colors.white54),
                            onPressed: () => setModalState(() => currentAlign = TextAlign.right),
                          ),
                          const Spacer(),
                          TextButton.icon(
                            onPressed: () {
                              if (textEditCtrl.selection.isValid && !textEditCtrl.selection.isCollapsed) {
                                applyFormattingToSelection(bold: true);
                              } else {
                                setModalState(() {
                                  currentWeight = currentWeight == FontWeight.bold ? FontWeight.normal : FontWeight.bold;
                                });
                              }
                            },
                            icon: Icon(Icons.format_bold_rounded, color: currentWeight == FontWeight.bold ? Colors.amberAccent : Colors.white54),
                            label: Text(
                              currentWeight == FontWeight.bold ? 'ដិត (Bold)' : 'ធម្មតា',
                              style: GoogleFonts.kantumruyPro(color: currentWeight == FontWeight.bold ? Colors.amberAccent : Colors.white54, fontSize: 11),
                            ),
                          ),
                        ],
                      ),
                    ],

                    const SizedBox(height: 20),

                    // Save / Apply Button
                    SizedBox(
                      width: double.infinity,
                      height: 48,
                      child: ElevatedButton.icon(
                        onPressed: () async {
                          setState(() {
                            item.text = textEditCtrl.text;
                            item.fontFamily = selectedFont;
                            item.fontSize = currentFontSize;
                            item.color = currentColor;
                            item.fontWeight = currentWeight;
                            item.textAlign = currentAlign;

                            // Sync back to standard controllers if matching
                            if (item.id == 'title') _titleController.text = item.text;
                            if (item.id == 'company') _companyController.text = item.text;
                            if (item.id == 'praise') _praiseTitleController.text = item.text;
                            if (item.id == 'body') {
                              _customBodyTextController.text = item.text;
                              _isCustomBodyTextEnabled = true;
                            }
                            if (item.id == 'lunar_date') _lunarDateController.text = item.text;
                            if (item.id == 'solar_date') _solarDateController.text = item.text;
                            if (item.id == 'sign_role') _signatoryRoleController.text = item.text;
                            if (item.id == 'sign_name') _signatoryController.text = item.text;
                          });
                          _canvasController.updateItem(item.id, item);

                          // Persistent Auto-Save to Database
                          await _saveCertificateToStorage(showToast: false);

                          if (ctx.mounted) Navigator.pop(ctx);
                        },
                        icon: const Icon(Icons.check_circle_rounded, color: Colors.black),
                        label: Text(
                          'រក្សាទុកការកែប្រែ (Save Changes)',
                          style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 14),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.amberAccent,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            );
          },
        );
      },
    );
  }

  /// Opens the Font-Only Quick Selection Modal for an element
  void _openFontPickerOnly(CertItem item) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E293B),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) {
        return Container(
          padding: const EdgeInsets.all(16),
          height: 380,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                '🔤 ជ្រើសរើស Font សម្រាប់ «${item.title}»',
                style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 14, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 10),
              Expanded(
                child: ListView.builder(
                  itemCount: _availableFonts.length,
                  itemBuilder: (context, i) {
                    final f = _availableFonts[i];
                    final isSel = item.fontFamily == f;
                    return ListTile(
                      dense: true,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                      tileColor: isSel ? Colors.amberAccent.withValues(alpha: 0.15) : null,
                      title: Text(
                        f,
                        style: _getKhmerTextStyle(fontFamily: f, fontSize: 14, color: isSel ? Colors.amberAccent : Colors.white),
                      ),
                      trailing: Text(
                        'គំរូអក្សរ ខ្មែរ',
                        style: _getKhmerTextStyle(fontFamily: f, fontSize: 12, color: isSel ? Colors.amberAccent : Colors.white60),
                      ),
                      onTap: () {
                        setState(() {
                          item.fontFamily = f;
                        });
                        _canvasController.updateItem(item.id, item);
                        Navigator.pop(ctx);
                      },
                    );
                  },
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  // Open Full-Screen Interactive Editor Modal
  void _openFullScreenViewer() {
    showDialog(
      context: context,
      barrierColor: Colors.black87,
      builder: (ctx) {
        return Scaffold(
          backgroundColor: Colors.black,
          appBar: AppBar(
            backgroundColor: Colors.black,
            elevation: 0,
            title: Text(
              '🔍 កែប្រែពេញអេក្រង់ (Full-Screen Live Editor)',
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5, fontWeight: FontWeight.bold),
            ),
            leading: IconButton(
              icon: const Icon(Icons.close_rounded, color: Colors.white),
              onPressed: () => Navigator.pop(ctx),
            ),
            actions: [
              IconButton(
                tooltip: 'Share',
                icon: const Icon(Icons.share_rounded, color: Colors.cyanAccent),
                onPressed: _shareCertificate,
              ),
              IconButton(
                tooltip: 'Print',
                icon: const Icon(Icons.print_rounded, color: Colors.amberAccent),
                onPressed: _printCertificate,
              ),
            ],
          ),
          body: Column(
            children: [
              ListenableBuilder(
                listenable: _canvasController,
                builder: (context, _) {
                  if (_canvasController.selectedItemId != null &&
                      _canvasController.items.containsKey(_canvasController.selectedItemId)) {
                    return _buildFloatingToolbar(isFullScreen: true);
                  }
                  return const SizedBox.shrink();
                },
              ),
              Expanded(
                child: Center(
                  child: ListenableBuilder(
                    listenable: _canvasController,
                    builder: (context, _) {
                      return InteractiveViewer(
                        panEnabled: _canvasController.selectedItemId == null,
                        scaleEnabled: _canvasController.selectedItemId == null,
                        minScale: 0.7,
                        maxScale: 3.0,
                        child: Padding(
                          padding: const EdgeInsets.all(8),
                          child: AspectRatio(
                            aspectRatio: 1.414,
                            child: _buildInteractiveCanvas(isFullScreen: true),
                          ),
                        ),
                      );
                    },
                  ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: true,
      onPopInvokedWithResult: (didPop, result) async {
        await _saveCertificateToStorage(showToast: false);
      },
      child: Focus(
        focusNode: _keyboardFocusNode,
        autofocus: true,
        onKeyEvent: _handleKeyEvent,
        child: (Responsive.isDesktop(context) || Responsive.isTablet(context))
            ? _buildDesktopStudioLayout()
            : _buildMobileLayout(),
      ),
    );
  }

  Widget _buildDesktopStudioLayout() {
    return Scaffold(
      backgroundColor: const Color(0xFF090D16),
      appBar: AppBar(
        backgroundColor: const Color(0xFF0F172A),
        elevation: 1,
        title: Row(
          children: [
            const Icon(Icons.workspace_premium_rounded, color: Colors.amberAccent, size: 24),
            const SizedBox(width: 10),
            Text(
              'Certificate Studio Pro (Desktop Enterprise)',
              style: GoogleFonts.outfit(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 16),
            ),
            const SizedBox(width: 8),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                color: Colors.amberAccent.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.4)),
              ),
              child: Text(
                'A4 LANDSCAPE',
                style: GoogleFonts.outfit(color: Colors.amberAccent, fontSize: 10, fontWeight: FontWeight.bold),
              ),
            ),
          ],
        ),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white),
          onPressed: () async {
            await _saveCertificateToStorage(showToast: false);
            if (mounted) Navigator.pop(context);
          },
        ),
        actions: [
          IconButton(
            tooltip: 'រក្សាទុកក្នុង Database (Save Design)',
            icon: const Icon(Icons.save_rounded, color: Colors.greenAccent, size: 22),
            onPressed: () => _saveCertificateToStorage(showToast: true),
          ),
          IconButton(
            tooltip: 'កំណត់ឡើងវិញ (Reset to Default)',
            icon: const Icon(Icons.restore_rounded, color: Colors.orangeAccent, size: 22),
            onPressed: _resetCertificateToDefault,
          ),
          IconButton(
            tooltip: 'ពេញអេក្រង់ (Full Screen)',
            icon: const Icon(Icons.fullscreen_rounded, color: Colors.amberAccent, size: 24),
            onPressed: _openFullScreenViewer,
          ),
          IconButton(
            tooltip: 'ចែករំលែក (Share)',
            icon: const Icon(Icons.share_rounded, color: Colors.cyanAccent),
            onPressed: _isGeneratingPdf ? null : _shareCertificate,
          ),
          const SizedBox(width: 8),
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 10),
            child: ElevatedButton.icon(
              onPressed: _isGeneratingPdf ? null : _printCertificate,
              icon: _isGeneratingPdf
                  ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black))
                  : const Icon(Icons.print_rounded, size: 18, color: Colors.black),
              label: Text(
                _isGeneratingPdf ? 'កំពុងរៀបចំ...' : '🖨️ បោះពុម្ព A4 PDF',
                style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 13),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.amberAccent,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
            ),
          ),
          const SizedBox(width: 10),
        ],
      ),
      body: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Left Studio Stage (Canvas + Quick Bar + Template Bar)
          Expanded(
            flex: 3,
            child: Container(
              color: const Color(0xFF090D16),
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Top Category & Location Chips Row
                    Row(
                      children: [
                        Expanded(
                          child: Container(
                            padding: const EdgeInsets.all(4),
                            decoration: BoxDecoration(
                              color: const Color(0xFF111E33),
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(color: Colors.white10),
                            ),
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
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),

                    // Quick Location Filter Chips
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                      decoration: BoxDecoration(
                        color: const Color(0xFF0F1A2E),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: Colors.white10),
                      ),
                      child: Row(
                        children: [
                          Text('ទីតាំង/ឃ្លាំង: ', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.bold)),
                          const SizedBox(width: 10),
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
                                      label: Text(loc['name']!, style: GoogleFonts.kantumruyPro(color: isLocActive ? Colors.black : Colors.white, fontSize: 11.5, fontWeight: isLocActive ? FontWeight.bold : FontWeight.normal)),
                                      selected: isLocActive,
                                      selectedColor: Colors.amberAccent,
                                      backgroundColor: Colors.white.withValues(alpha: 0.07),
                                      checkmarkColor: Colors.black,
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
                    const SizedBox(height: 14),

                    // Floating Context Toolbar for Selected Element
                    ListenableBuilder(
                      listenable: _canvasController,
                      builder: (context, _) {
                        if (_canvasController.selectedItemId != null &&
                            _canvasController.items.containsKey(_canvasController.selectedItemId)) {
                          return _buildFloatingToolbar(isFullScreen: false);
                        }
                        return const SizedBox.shrink();
                      },
                    ),

                    // Live Certificate Canvas (A4 Aspect Ratio: 1.414)
                    Center(
                      child: Container(
                        constraints: const BoxConstraints(maxWidth: 820),
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(12),
                          boxShadow: [
                            BoxShadow(
                              color: Colors.black.withValues(alpha: 0.7),
                              blurRadius: 28,
                              offset: const Offset(0, 10),
                            ),
                          ],
                        ),
                        child: AspectRatio(
                          aspectRatio: 1.414,
                          child: _buildInteractiveCanvas(isFullScreen: false),
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),

                    // Frame Template Carousel at the bottom of the canvas stage
                    Text('🖼️ ជ្រើសរើសស៊ុមគំរូ (Certificate Frame Templates):', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5, fontWeight: FontWeight.bold)),
                    const SizedBox(height: 8),
                    SizedBox(
                      height: 72,
                      child: ListView.builder(
                        scrollDirection: Axis.horizontal,
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
                                color: const Color(0xFF111E33),
                                borderRadius: BorderRadius.circular(10),
                                border: Border.all(color: isSelected ? Colors.amberAccent : Colors.white12, width: isSelected ? 2 : 1),
                              ),
                              child: Row(
                                children: [
                                  ClipRRect(
                                    borderRadius: BorderRadius.circular(6),
                                    child: Image.asset(t['path']!, width: 62, height: 48, fit: BoxFit.cover),
                                  ),
                                  const SizedBox(width: 8),
                                  Text(t['name']!, style: GoogleFonts.kantumruyPro(color: isSelected ? Colors.amberAccent : Colors.white70, fontSize: 11.5, fontWeight: isSelected ? FontWeight.bold : FontWeight.normal)),
                                  if (isSelected) ...[
                                    const SizedBox(width: 6),
                                    const Icon(Icons.check_circle_rounded, color: Colors.amberAccent, size: 16),
                                  ],
                                  const SizedBox(width: 4),
                                ],
                              ),
                            ),
                          );
                        },
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),

          // Right Inspector Sidebar (Tools, Layers, D-Pad, Form)
          Expanded(
            flex: 2,
            child: Container(
              decoration: BoxDecoration(
                color: const Color(0xFF0F172A),
                border: Border(
                  left: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
                ),
              ),
              child: Column(
                children: [
                  // Tab Navigation Header
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0A101D),
                      border: Border(bottom: BorderSide(color: Colors.white.withValues(alpha: 0.06))),
                    ),
                    child: SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      child: Row(
                        children: [
                          _buildSubNavTab('layers', '📚 ស្រទាប់', Icons.layers_rounded),
                          _buildSubNavTab('nudge', '🕹️ D-Pad', Icons.control_camera_rounded),
                          _buildSubNavTab('info', '📝 ទិន្នន័យ', Icons.badge_outlined),
                          _buildSubNavTab('style', '🎨 Font & ពណ៌', Icons.text_fields_rounded),
                          _buildSubNavTab('text', '✍️ អត្ថបទ', Icons.edit_note_rounded),
                          _buildSubNavTab('photo', '🖼️ រូបថត', Icons.photo_library_outlined),
                        ],
                      ),
                    ),
                  ),

                  // Scrollable Inspector Body
                  Expanded(
                    child: SingleChildScrollView(
                      padding: const EdgeInsets.all(18),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          if (_activeTab == 'layers') _buildLayersTabContent(),
                          if (_activeTab == 'nudge') _buildNudgeTabContent(),
                          if (_activeTab == 'info') _buildInfoTabContent(),
                          if (_activeTab == 'style') _buildStyleTabContent(),
                          if (_activeTab == 'text') _buildTextTabContent(),
                          if (_activeTab == 'photo') _buildPhotoTabContent(),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMobileLayout() {
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
          onPressed: () async {
            await _saveCertificateToStorage(showToast: false);
            if (mounted) Navigator.pop(context);
          },
        ),
        actions: [
          IconButton(
            tooltip: 'មើល & កែប្រែពេញអេក្រង់',
            icon: const Icon(Icons.fullscreen_rounded, color: Colors.amberAccent, size: 24),
            onPressed: _openFullScreenViewer,
          ),
          IconButton(
            tooltip: 'បិទ/បើកផ្ទាំងកែប្រែ',
            icon: Icon(
              _showInlineControls ? Icons.tune_rounded : Icons.tune_outlined,
              color: Colors.white70,
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

            // Quick Location Chips Row
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

            // Frame Template Gallery
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

            // Preview Header Bar
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 14),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    '👆 ចុច ឬសារ៉េលើអក្សរផ្ទាល់ (Photoshop Canvas & Layers)',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white70,
                      fontSize: 12.0,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  InkWell(
                    onTap: _openFullScreenViewer,
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: Colors.amberAccent.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.4)),
                      ),
                      child: Row(
                        children: [
                          const Icon(Icons.fullscreen_rounded, color: Colors.amberAccent, size: 16),
                          const SizedBox(width: 4),
                          Text(
                            'ពេញអេក្រង់',
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.amberAccent,
                              fontSize: 11,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),

            // Floating Context Toolbar for Selected Element
            ListenableBuilder(
              listenable: _canvasController,
              builder: (context, _) {
                if (_canvasController.selectedItemId != null &&
                    _canvasController.items.containsKey(_canvasController.selectedItemId)) {
                  return _buildFloatingToolbar(isFullScreen: false);
                }
                return const SizedBox.shrink();
              },
            ),

            // Live Interactive Certificate Canvas Box (A4 Aspect Ratio: 1.414)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 10),
              child: AspectRatio(
                aspectRatio: 1.414,
                child: _buildInteractiveCanvas(isFullScreen: false),
              ),
            ),

            const SizedBox(height: 14),

            // Customization Control Center (Tabs: Layers, Nudge/D-Pad, Info, Style, Text, Photo)
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
                    Container(
                      padding: const EdgeInsets.all(3),
                      decoration: BoxDecoration(
                        color: Colors.black.withValues(alpha: 0.25),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: SingleChildScrollView(
                        scrollDirection: Axis.horizontal,
                        child: Row(
                          children: [
                            _buildSubNavTab('layers', '📚 ស្រទាប់ Layers', Icons.layers_rounded),
                            _buildSubNavTab('nudge', '🕹️ ប៊ូតុងសារ៉េ D-Pad', Icons.control_camera_rounded),
                            _buildSubNavTab('info', '📝 ទិន្នន័យ', Icons.badge_outlined),
                            _buildSubNavTab('style', '🎨 Font & ពណ៌', Icons.text_fields_rounded),
                            _buildSubNavTab('text', '✍️ អត្ថបទសេរី', Icons.edit_note_rounded),
                            _buildSubNavTab('photo', '🖼️ រូបថត', Icons.photo_library_outlined),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),

                    if (_activeTab == 'layers') _buildLayersTabContent(),
                    if (_activeTab == 'nudge') _buildNudgeTabContent(),
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

  /// Floating Context Toolbar displayed above the canvas when an element is selected
  Widget _buildFloatingToolbar({required bool isFullScreen}) {
    final selectedId = _canvasController.selectedItemId;
    final item = selectedId != null ? _canvasController.items[selectedId] : null;
    if (item == null) return const SizedBox.shrink();

    return Container(
      margin: const EdgeInsets.fromLTRB(12, 0, 12, 8),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: const Color(0xFF1E293B),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: Colors.amberAccent, width: 1.5),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.4),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          children: [
            // Selected Title Badge
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: Colors.amberAccent,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  Icon(_getLayerIcon(item.type), color: Colors.black, size: 14),
                  const SizedBox(width: 4),
                  Text(
                    item.title,
                    style: GoogleFonts.kantumruyPro(color: Colors.black, fontSize: 11, fontWeight: FontWeight.bold),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),

            // 1. [ ✏️ Edit text ] button
            if (item.type != 'photo' && item.type != 'signature')
              ElevatedButton.icon(
                onPressed: () => _openElementEditForm(item),
                icon: const Icon(Icons.edit_rounded, size: 14, color: Colors.black),
                label: Text('កែអត្ថបទ', style: GoogleFonts.kantumruyPro(fontSize: 11.5, color: Colors.black, fontWeight: FontWeight.bold)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.amberAccent,
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                ),
              ),
            if (item.type != 'photo' && item.type != 'signature') const SizedBox(width: 6),

            // 2. [ 🔤 Font ] button
            if (item.type != 'photo' && item.type != 'signature')
              OutlinedButton.icon(
                onPressed: () => _openFontPickerOnly(item),
                icon: const Icon(Icons.font_download_rounded, size: 14, color: Colors.white),
                label: Text(item.fontFamily, style: GoogleFonts.kantumruyPro(fontSize: 11, color: Colors.white)),
                style: OutlinedButton.styleFrom(
                  side: const BorderSide(color: Colors.white30),
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                ),
              ),
            if (item.type != 'photo' && item.type != 'signature') const SizedBox(width: 6),

            // 3. Size Steppers [ A- ] [ A+ ]
            if (item.type != 'photo' && item.type != 'signature') ...[
              InkWell(
                onTap: () {
                  if (item.fontSize > 7) {
                    item.fontSize -= 1;
                    _canvasController.updateItem(item.id, item);
                  }
                },
                child: Container(
                  padding: const EdgeInsets.all(6),
                  decoration: BoxDecoration(color: Colors.white10, borderRadius: BorderRadius.circular(8)),
                  child: const Text('A-', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
                ),
              ),
              const SizedBox(width: 4),
              InkWell(
                onTap: () {
                  if (item.fontSize < 50) {
                    item.fontSize += 1;
                    _canvasController.updateItem(item.id, item);
                  }
                },
                child: Container(
                  padding: const EdgeInsets.all(6),
                  decoration: BoxDecoration(color: Colors.white10, borderRadius: BorderRadius.circular(8)),
                  child: const Text('A+', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
                ),
              ),
              const SizedBox(width: 8),
            ],

            // 4. Directional D-Pad Navigation Buttons (⬅️ ⬆️ ⬇️ ➡️)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: Colors.white12),
              ),
              child: Row(
                children: [
                  IconButton(
                    tooltip: 'ទៅឆ្វេង (Left)',
                    icon: const Icon(Icons.arrow_left_rounded, color: Colors.amberAccent, size: 22),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(minWidth: 26, minHeight: 26),
                    onPressed: () => _canvasController.nudge(item.id, -_canvasController.nudgeStep, 0),
                  ),
                  IconButton(
                    tooltip: 'ឡើងលើ (Up)',
                    icon: const Icon(Icons.arrow_drop_up_rounded, color: Colors.amberAccent, size: 22),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(minWidth: 26, minHeight: 26),
                    onPressed: () => _canvasController.nudge(item.id, 0, -_canvasController.nudgeStep),
                  ),
                  IconButton(
                    tooltip: 'ចុះក្រោម (Down)',
                    icon: const Icon(Icons.arrow_drop_down_rounded, color: Colors.amberAccent, size: 22),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(minWidth: 26, minHeight: 26),
                    onPressed: () => _canvasController.nudge(item.id, 0, _canvasController.nudgeStep),
                  ),
                  IconButton(
                    tooltip: 'ទៅស្តាំ (Right)',
                    icon: const Icon(Icons.arrow_right_rounded, color: Colors.amberAccent, size: 22),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(minWidth: 26, minHeight: 26),
                    onPressed: () => _canvasController.nudge(item.id, _canvasController.nudgeStep, 0),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 6),

            // 5. Center Align Horizontal Button
            IconButton(
              tooltip: 'តម្រឹមចំកណ្តាល',
              icon: const Icon(Icons.align_horizontal_center_rounded, color: Colors.amberAccent, size: 18),
              onPressed: () {
                item.x = 350.0;
                _canvasController.updateItem(item.id, item);
              },
            ),

            // 6. Change photo button if item is photo
            if (item.type == 'photo')
              ElevatedButton.icon(
                onPressed: _pickAvatarImage,
                icon: const Icon(Icons.photo_camera, size: 14, color: Colors.black),
                label: Text('ប្តូររូបថត', style: GoogleFonts.kantumruyPro(fontSize: 11, color: Colors.black, fontWeight: FontWeight.bold)),
                style: ElevatedButton.styleFrom(backgroundColor: Colors.amberAccent),
              ),

            // Close Toolbar
            IconButton(
              tooltip: 'បិទ',
              icon: const Icon(Icons.close_rounded, color: Colors.white54, size: 16),
              onPressed: () => _canvasController.selectItem(null),
            ),
          ],
        ),
      ),
    );
  }

  /// Core Live Interactive Certificate Canvas Widget (700 x 495 reference space)
  Widget _buildInteractiveCanvas({required bool isFullScreen}) {
    return RepaintBoundary(
      key: isFullScreen ? null : _previewContainerKey,
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
            // 1. Background Frame Template (Cached in GPU layer)
            RepaintBoundary(
              child: ClipRRect(
                borderRadius: BorderRadius.circular(8),
                child: Image.asset(
                  _selectedTemplateAsset,
                  fit: BoxFit.fill,
                  gaplessPlayback: true,
                  errorBuilder: (ctx, err, stack) => Container(
                    color: Colors.white,
                    child: const Center(
                      child: Icon(Icons.workspace_premium_rounded, size: 80, color: Colors.amber),
                    ),
                  ),
                ),
              ),
            ),

            // 2. Isolated Canvas Layer - Renders items in exact Photoshop Layer Order
            LayoutBuilder(
              builder: (context, constraints) {
                final baseWidth = constraints.maxWidth;
                final scale = baseWidth / 700.0;

                return GestureDetector(
                  onTap: () {
                    _keyboardFocusNode.requestFocus();
                    _canvasController.selectItem(null);
                  },
                  behavior: HitTestBehavior.translucent,
                  child: ListenableBuilder(
                    listenable: _canvasController,
                    builder: (context, _) {
                      return Stack(
                        children: _canvasController.layerOrder.map((id) {
                          final item = _canvasController.items[id];
                          if (item == null || !item.isVisible) return const SizedBox.shrink();

                          final bool isSelected = _canvasController.selectedItemId == item.id;
                          final double renderX = item.x * scale;
                          final double renderY = item.y * scale;

                          Widget elementWidget;

                          switch (item.type) {
                            case 'body':
                              elementWidget = _buildBodyElementWidget(item, scale);
                              break;
                            case 'seal':
                              elementWidget = _buildSealElementWidget(item, scale, isSelected);
                              break;
                            case 'photo':
                              elementWidget = _buildPhotoElementWidget(item, scale, isSelected);
                              break;
                            case 'signature':
                              elementWidget = Image.asset(
                                item.text,
                                width: item.width * scale,
                                height: item.height * scale,
                                fit: BoxFit.contain,
                                gaplessPlayback: true,
                                errorBuilder: (_, __, ___) => SizedBox(width: item.width * scale, height: item.height * scale),
                              );
                              break;
                            case 'symbol':
                            case 'text':
                            default:
                              elementWidget = RichText(
                                textAlign: item.textAlign,
                                text: TextSpan(
                                  children: _parseRichTextSpans(
                                    rawText: item.text,
                                    baseFontFamily: item.fontFamily,
                                    baseFontSize: item.fontSize,
                                    baseColor: item.color,
                                    baseFontWeight: item.fontWeight,
                                    scale: scale,
                                  ),
                                ),
                              );
                              break;
                          }

                          return Positioned(
                            left: renderX - (item.width * scale) / 2,
                            top: renderY - (item.height * scale) / 2,
                            width: item.width * scale,
                            child: GestureDetector(
                              onTap: () {
                                _keyboardFocusNode.requestFocus();
                                _canvasController.selectItem(item.id);
                              },
                              onDoubleTap: () => _openElementEditForm(item),
                              onPanStart: (_) {
                                _keyboardFocusNode.requestFocus();
                                _canvasController.selectItem(item.id);
                              },
                              onPanUpdate: (details) {
                                _canvasController.moveItem(item.id, details.delta.dx / scale, details.delta.dy / scale);
                              },
                              child: Container(
                                alignment: item.textAlign == TextAlign.left
                                    ? Alignment.centerLeft
                                    : (item.textAlign == TextAlign.right ? Alignment.centerRight : Alignment.center),
                                decoration: isSelected
                                    ? BoxDecoration(
                                        border: Border.all(color: Colors.amberAccent, width: 2),
                                        borderRadius: BorderRadius.circular(6),
                                        color: Colors.amberAccent.withValues(alpha: 0.08),
                                      )
                                    : null,
                                child: elementWidget,
                              ),
                            ),
                          );
                        }).toList(),
                      );
                    },
                  ),
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildBodyElementWidget(CertItem item, double scale) {
    if (_isCustomBodyTextEnabled && item.text.trim().isNotEmpty) {
      return RichText(
        textAlign: item.textAlign,
        text: TextSpan(
          children: _parseRichTextSpans(
            rawText: item.text,
            baseFontFamily: item.fontFamily,
            baseFontSize: item.fontSize,
            baseColor: item.color,
            baseFontWeight: item.fontWeight,
            scale: scale,
            height: 1.6,
          ),
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
        textAlign: item.textAlign,
        text: TextSpan(
          style: _getKhmerTextStyle(
            fontFamily: item.fontFamily,
            color: item.color,
            fontSize: item.fontSize * scale,
            height: 1.6,
          ),
          children: [
            const TextSpan(text: 'បុគ្គលិកឈ្មោះ: '),
            TextSpan(
              text: name,
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 1.2) * scale,
              ),
            ),
            if (gender.isNotEmpty) ...[
              const TextSpan(text: ' ភេទ '),
              TextSpan(
                text: gender,
                style: _getKhmerTextStyle(
                  fontFamily: item.fontFamily,
                  color: item.color,
                  fontWeight: FontWeight.bold,
                  fontSize: item.fontSize * scale,
                ),
              ),
            ],
            const TextSpan(text: ' ជាបុគ្គលិកផ្នែក '),
            TextSpan(
              text: dept,
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(
              text:
                  '\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើមផ្នែក ',
            ),
            TextSpan(
              text: 'ការិយាល័យកណ្តាល',
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(text: ' ប្រចាំ '),
            TextSpan(
              text: quarter,
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 0.5) * scale,
              ),
            ),
            TextSpan(text: ' នៃឆ្នាំ $year ៕'),
          ],
        ),
      );
    } else if (_selectedCategory == 'warehouse') {
      return RichText(
        textAlign: item.textAlign,
        text: TextSpan(
          style: _getKhmerTextStyle(
            fontFamily: item.fontFamily,
            color: item.color,
            fontSize: item.fontSize * scale,
            height: 1.6,
          ),
          children: [
            const TextSpan(text: 'បុគ្គលិកឈ្មោះ: '),
            TextSpan(
              text: name,
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 1.2) * scale,
              ),
            ),
            if (gender.isNotEmpty) ...[
              const TextSpan(text: ' ភេទ '),
              TextSpan(
                text: gender,
                style: _getKhmerTextStyle(
                  fontFamily: item.fontFamily,
                  color: item.color,
                  fontWeight: FontWeight.bold,
                  fontSize: item.fontSize * scale,
                ),
              ),
            ],
            const TextSpan(text: ' ជាបុគ្គលិកផ្នែក '),
            TextSpan(
              text: dept,
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(
              text:
                  '\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើមផ្នែក ',
            ),
            TextSpan(
              text: 'ឃ្លាំង',
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(text: ' ប្រចាំ '),
            TextSpan(
              text: quarter,
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 0.5) * scale,
              ),
            ),
            TextSpan(text: ' នៃឆ្នាំ $year ៕'),
          ],
        ),
      );
    } else {
      final rankStr = _toKhmerDigits('$_workerRank');
      return RichText(
        textAlign: item.textAlign,
        text: TextSpan(
          style: _getKhmerTextStyle(
            fontFamily: item.fontFamily,
            color: item.color,
            fontSize: item.fontSize * scale,
            height: 1.6,
          ),
          children: [
            const TextSpan(text: 'បុគ្គលិកឈ្មោះ: '),
            TextSpan(
              text: name,
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 1.2) * scale,
              ),
            ),
            if (gender.isNotEmpty) ...[
              const TextSpan(text: ' ភេទ '),
              TextSpan(
                text: gender,
                style: _getKhmerTextStyle(
                  fontFamily: item.fontFamily,
                  color: item.color,
                  fontWeight: FontWeight.bold,
                  fontSize: item.fontSize * scale,
                ),
              ),
            ],
            const TextSpan(text: ' ជាបុគ្គលិកផ្នែក '),
            TextSpan(
              text: dept,
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(
              text:
                  '\nដែលបានខិតខំក្នុងតួនាទីរបស់ខ្លួនបានយ៉ាងល្អក្នុងការបំពេញការងារជូនក្រុមហ៊ុន និងបានជាប់\nជាបុគ្គលិកឆ្នើម ',
            ),
            TextSpan(
              text: 'លេខ $rankStr',
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(text: ' នៅឃ្លាំង '),
            TextSpan(
              text: location,
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 0.5) * scale,
              ),
            ),
            const TextSpan(text: ' ប្រចាំ '),
            TextSpan(
              text: quarter,
              style: _getKhmerTextStyle(
                fontFamily: item.fontFamily,
                color: _highlightColor,
                fontWeight: FontWeight.bold,
                fontSize: (item.fontSize + 0.5) * scale,
              ),
            ),
            TextSpan(text: ' នៃឆ្នាំ $year ៕'),
          ],
        ),
      );
    }
  }

  Widget _buildSealElementWidget(CertItem item, double scale, bool isSelected) {
    return Container(
      width: item.width * scale,
      height: item.height * scale,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: const LinearGradient(
          colors: [Color(0xFFF59E0B), Color(0xFFB45309)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        border: isSelected ? Border.all(color: Colors.white, width: 2.5) : null,
        boxShadow: [
          BoxShadow(
            color: Colors.amber.withValues(alpha: 0.45),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Center(
        child: Text(
          item.text,
          style: _getKhmerTextStyle(
            fontFamily: item.fontFamily,
            color: Colors.white,
            fontSize: item.fontSize * scale,
            fontWeight: FontWeight.bold,
          ),
        ),
      ),
    );
  }

  Widget _buildPhotoElementWidget(CertItem item, double scale, bool isSelected) {
    return Container(
      width: item.width * scale,
      height: item.height * scale,
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(
          color: isSelected ? Colors.amberAccent : const Color(0xFFD97706),
          width: isSelected ? 2.5 : 2,
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
    return GestureDetector(
      onTap: () => setState(() => _activeTab = tabKey),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 12),
        margin: const EdgeInsets.only(right: 4),
        decoration: BoxDecoration(
          color: isSelected ? const Color(0xFF1E293B) : Colors.transparent,
          borderRadius: BorderRadius.circular(10),
          border: isSelected ? Border.all(color: Colors.amberAccent.withValues(alpha: 0.5)) : null,
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              size: 15,
              color: isSelected ? Colors.amberAccent : Colors.white60,
            ),
            const SizedBox(width: 6),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: isSelected ? Colors.amberAccent : Colors.white60,
                fontSize: 11,
                fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Photoshop-Style Layers Panel with Visibility, Selection & Drag-to-Reorder
  Widget _buildLayersTabContent() {
    return ListenableBuilder(
      listenable: _canvasController,
      builder: (context, _) {
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  '📚 ស្រទាប់ (Photoshop Layers)',
                  style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold),
                ),
                Text(
                  'អូស ≡ ដើម្បីតម្រៀបលំដាប់ Z-Index',
                  style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 11),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Container(
              height: 280,
              decoration: BoxDecoration(
                color: const Color(0xFF0F172A),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: Colors.white12),
              ),
              child: ReorderableListView(
                padding: const EdgeInsets.symmetric(vertical: 4),
                onReorder: (oldIdx, newIdx) => _canvasController.reorderLayers(oldIdx, newIdx),
                children: _canvasController.layerOrder.map((id) {
                  final item = _canvasController.items[id];
                  if (item == null) return SizedBox.shrink(key: ValueKey(id));
                  final isSel = _canvasController.selectedItemId == id;

                  return Container(
                    key: ValueKey(id),
                    margin: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: isSel ? Colors.amberAccent.withValues(alpha: 0.18) : Colors.white.withValues(alpha: 0.04),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(
                        color: isSel ? Colors.amberAccent : Colors.white12,
                      ),
                    ),
                    child: Row(
                      children: [
                        // Drag Reorder Handle
                        const Icon(Icons.drag_handle_rounded, color: Colors.white38, size: 20),
                        const SizedBox(width: 4),
                        // Visibility Eye Toggle
                        IconButton(
                          icon: Icon(
                            item.isVisible ? Icons.visibility_rounded : Icons.visibility_off_rounded,
                            color: item.isVisible ? Colors.amberAccent : Colors.white24,
                            size: 18,
                          ),
                          onPressed: () => _canvasController.toggleVisibility(id),
                        ),
                        // Type Icon
                        Icon(_getLayerIcon(item.type), color: isSel ? Colors.amberAccent : Colors.white70, size: 16),
                        const SizedBox(width: 8),
                        // Item Title
                        Expanded(
                          child: GestureDetector(
                            onTap: () => _canvasController.selectItem(id),
                            child: Text(
                              item.title,
                              style: GoogleFonts.kantumruyPro(
                                color: isSel ? Colors.amberAccent : (item.isVisible ? Colors.white : Colors.white38),
                                fontSize: 12,
                                fontWeight: isSel ? FontWeight.bold : FontWeight.normal,
                              ),
                            ),
                          ),
                        ),
                        // Edit Button
                        IconButton(
                          icon: const Icon(Icons.edit_rounded, color: Colors.white70, size: 16),
                          onPressed: () {
                            _canvasController.selectItem(id);
                            _openElementEditForm(item);
                          },
                        ),
                      ],
                    ),
                  );
                }).toList(),
              ),
            ),
          ],
        );
      },
    );
  }

  /// Directional Nudge Pad Tab for pixel-precision adjustment without dragging
  Widget _buildNudgeTabContent() {
    return ListenableBuilder(
      listenable: _canvasController,
      builder: (context, _) {
        final selectedId = _canvasController.selectedItemId;
        final item = selectedId != null ? _canvasController.items[selectedId] : null;

        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  '🕹️ ប៊ូតុងសារ៉េទីតាំង (Precision D-Pad)',
                  style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold),
                ),
                if (item != null)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                    decoration: BoxDecoration(color: Colors.amberAccent, borderRadius: BorderRadius.circular(8)),
                    child: Text(
                      item.title,
                      style: GoogleFonts.kantumruyPro(color: Colors.black, fontSize: 11, fontWeight: FontWeight.bold),
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 10),

            if (item == null)
              Container(
                padding: const EdgeInsets.all(20),
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: Colors.black26,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.white12),
                ),
                child: Text(
                  'សូមចុចជ្រើសរើសអត្ថបទ ឬ Symbol ណាមួយនៅលើ Canvas ឬ Tab ស្រទាប់ជាមុនសិន!',
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 12),
                ),
              )
            else ...[
              // Step Size Chooser
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text('ចម្ងាយសារ៉េ (Step Size):', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
                  Row(
                    children: [1.0, 2.0, 5.0, 10.0].map((s) {
                      final isStep = _canvasController.nudgeStep == s;
                      return Padding(
                        padding: const EdgeInsets.only(left: 6),
                        child: ChoiceChip(
                          label: Text('${s.toInt()}px', style: TextStyle(color: isStep ? Colors.black : Colors.white, fontSize: 11)),
                          selected: isStep,
                          selectedColor: Colors.amberAccent,
                          backgroundColor: Colors.white10,
                          onSelected: (_) => setState(() => _canvasController.nudgeStep = s),
                        ),
                      );
                    }).toList(),
                  ),
                ],
              ),
              const SizedBox(height: 14),

              // Directional Cross Controller
              Center(
                child: Container(
                  width: 170,
                  height: 170,
                  decoration: BoxDecoration(
                    color: const Color(0xFF0F172A),
                    shape: BoxShape.circle,
                    border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.4), width: 2),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: 0.5),
                        blurRadius: 12,
                      ),
                    ],
                  ),
                  child: Stack(
                    alignment: Alignment.center,
                    children: [
                      // UP
                      Positioned(
                        top: 6,
                        child: IconButton(
                          tooltip: 'ឡើងលើ',
                          icon: const Icon(Icons.keyboard_arrow_up_rounded, color: Colors.amberAccent, size: 36),
                          onPressed: () => _canvasController.nudge(item.id, 0, -_canvasController.nudgeStep),
                        ),
                      ),
                      // DOWN
                      Positioned(
                        bottom: 6,
                        child: IconButton(
                          tooltip: 'ចុះក្រោម',
                          icon: const Icon(Icons.keyboard_arrow_down_rounded, color: Colors.amberAccent, size: 36),
                          onPressed: () => _canvasController.nudge(item.id, 0, _canvasController.nudgeStep),
                        ),
                      ),
                      // LEFT
                      Positioned(
                        left: 6,
                        child: IconButton(
                          tooltip: 'ទៅឆ្វេង',
                          icon: const Icon(Icons.keyboard_arrow_left_rounded, color: Colors.amberAccent, size: 36),
                          onPressed: () => _canvasController.nudge(item.id, -_canvasController.nudgeStep, 0),
                        ),
                      ),
                      // RIGHT
                      Positioned(
                        right: 6,
                        child: IconButton(
                          tooltip: 'ទៅស្តាំ',
                          icon: const Icon(Icons.keyboard_arrow_right_rounded, color: Colors.amberAccent, size: 36),
                          onPressed: () => _canvasController.nudge(item.id, _canvasController.nudgeStep, 0),
                        ),
                      ),
                      // CENTER HORIZONTALLY BUTTON
                      Center(
                        child: InkWell(
                          onTap: () {
                            item.x = 350.0;
                            _canvasController.updateItem(item.id, item);
                          },
                          child: Container(
                            width: 44,
                            height: 44,
                            decoration: const BoxDecoration(
                              color: Colors.amberAccent,
                              shape: BoxShape.circle,
                            ),
                            child: const Center(
                              child: Icon(Icons.align_horizontal_center_rounded, color: Colors.black, size: 20),
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 10),
              Center(
                child: Text(
                  'កូអរដោនេ: X = ${item.x.toStringAsFixed(1)}, Y = ${item.y.toStringAsFixed(1)}',
                  style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 12, fontWeight: FontWeight.bold),
                ),
              ),
            ],
          ],
        );
      },
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
                  _syncControllersToItems();
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

        Text('កាលបរិច្ឆេទចេញ (ចន្ទគតិ & សុរិយគតិ)', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
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
        Text(
          '🎨 ជ្រើសរើសធាតុណាមួយដើម្បីប្តូរ Font & ពណ៌ដោយផ្ទាល់',
          style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 10),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: _canvasController.items.values.map((item) {
            final isSel = _canvasController.selectedItemId == item.id;
            return ActionChip(
              avatar: Icon(_getLayerIcon(item.type), size: 14, color: isSel ? Colors.black : Colors.amberAccent),
              label: Text(item.title, style: GoogleFonts.kantumruyPro(fontSize: 11.5, color: isSel ? Colors.black : Colors.white)),
              backgroundColor: isSel ? Colors.amberAccent : Colors.white10,
              onPressed: () {
                _canvasController.selectItem(item.id);
                _openElementEditForm(item);
              },
            );
          }).toList(),
        ),
        const SizedBox(height: 16),
        const Divider(color: Colors.white12),
        const SizedBox(height: 10),
        Text('✨ ពណ៌ Highlight ឈ្មោះ & ផ្នែកក្នុងតួសេចក្តី:',
            style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
        const SizedBox(height: 8),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: Row(
            children: _availableColors.map((c) {
              final bool isSel = _highlightColor == c;
              return GestureDetector(
                onTap: () => setState(() => _highlightColor = c),
                child: Container(
                  margin: const EdgeInsets.only(right: 8),
                  width: 32,
                  height: 32,
                  decoration: BoxDecoration(
                    color: c,
                    shape: BoxShape.circle,
                    border: Border.all(
                      color: isSel ? Colors.white : Colors.white24,
                      width: isSel ? 3 : 1,
                    ),
                  ),
                  child: isSel ? const Icon(Icons.check, color: Colors.white, size: 16) : null,
                ),
              );
            }).toList(),
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
                  _syncControllersToItems();
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
          style: GoogleFonts.battambang(
            fontSize: 14,
            color: _isCustomBodyTextEnabled ? Colors.white : Colors.white54,
            height: 1.5,
          ),
          onChanged: (_) => setState(() {
            _syncControllersToItems();
          }),
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
                _syncControllersToItems();
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
            _syncControllersToItems();
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
