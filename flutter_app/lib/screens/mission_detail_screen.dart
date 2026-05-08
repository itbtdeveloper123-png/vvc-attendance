import 'dart:typed_data';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import '../utils/app_theme.dart';

class MissionDetailScreen extends StatefulWidget {
  final Map<String, dynamic> mission;

  const MissionDetailScreen({super.key, required this.mission});

  @override
  State<MissionDetailScreen> createState() => _MissionDetailScreenState();
}

class _MissionDetailScreenState extends State<MissionDetailScreen> {
  final GlobalKey _boundaryKey = GlobalKey();

  Future<void> _printDocument() async {
    try {
      final pdf = await _generatePdfFromScreenshot();
      await Printing.layoutPdf(
        onLayout: (PdfPageFormat format) async => pdf.save(),
        name: 'Mission_Letter_${widget.mission['id']}.pdf',
      );
    } catch (e) {
      if (!mounted) return;
      _showError('បោះពុម្ពមិនបានជោគជ័យ: $e');
    }
  }

  Future<void> _downloadPdf() async {
    try {
      final pdf = await _generatePdfFromScreenshot();
      await Printing.sharePdf(
        bytes: await pdf.save(),
        filename: 'Mission_Letter_${widget.mission['id']}.pdf',
      );
    } catch (e) {
      if (!mounted) return;
      _showError('មិនអាចទាញយក PDF បានទេ: $e');
    }
  }

  Future<void> _copyAsImage() async {
    try {
      final pngBytes = await _captureScreenshot();
      if (pngBytes == null) return;
      if (!mounted) return;

      await Printing.sharePdf(
        bytes: pngBytes,
        filename: 'Mission_Letter_${widget.mission['id']}.png',
      );
      
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('រូបភាពត្រូវបានរៀបចំរួចរាល់សម្រាប់ចែករំលែក')),
      );
    } catch (e) {
      if (!mounted) return;
      _showError('មិនអាចចម្លងរូបភាពបានទេ: $e');
    }
  }

  Future<Uint8List?> _captureScreenshot() async {
    try {
      RenderRepaintBoundary? boundary = _boundaryKey.currentContext?.findRenderObject() as RenderRepaintBoundary?;
      if (boundary == null) return null;

      ui.Image image = await boundary.toImage(pixelRatio: 4.0); // Ultra high quality
      ByteData? byteData = await image.toByteData(format: ui.ImageByteFormat.png);
      return byteData?.buffer.asUint8List();
    } catch (e) {
      return null;
    }
  }

  Future<pw.Document> _generatePdfFromScreenshot() async {
    final pdf = pw.Document();
    final pngBytes = await _captureScreenshot();
    
    if (pngBytes == null) throw Exception("Failed to capture screen");

    final image = pw.MemoryImage(pngBytes);
    
    pdf.addPage(
      pw.Page(
        pageFormat: PdfPageFormat.a4,
        margin: pw.EdgeInsets.zero,
        build: (pw.Context context) {
          return pw.FullPage(
            ignoreMargins: true,
            child: pw.Image(image, fit: pw.BoxFit.contain),
          );
        },
      ),
    );
    return pdf;
  }

  void _showError(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(msg), backgroundColor: AppTheme.danger),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        title: Text(
          "លិខិតបេសកកម្ម",
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.print_rounded),
            onPressed: _printDocument,
            tooltip: 'បោះពុម្ព',
          ),
          IconButton(
            icon: const Icon(Icons.picture_as_pdf_rounded),
            onPressed: _downloadPdf,
            tooltip: 'ទាញយក PDF',
          ),
          IconButton(
            icon: const Icon(Icons.copy_rounded),
            onPressed: _copyAsImage,
            tooltip: 'ចែករំលែកជារូបភាព',
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(vertical: 20),
        child: Center(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: FittedBox(
              fit: BoxFit.contain,
              child: RepaintBoundary(
                key: _boundaryKey,
                child: Container(
                  width: 595,
                  constraints: const BoxConstraints(minHeight: 842), // Standard A4 height pixels
                  padding: const EdgeInsets.symmetric(horizontal: 35, vertical: 40),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: 0.15),
                        blurRadius: 15,
                        spreadRadius: 2,
                      ),
                    ],
                  ),
                  child: _buildA4Content(),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildA4Content() {
    final mission = widget.mission;
    const bodyColor = Colors.black;
    
    return Column(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        // Header
        Text(
          "ព្រះរាជាណាចក្រកម្ពុជា",
          style: GoogleFonts.moul(color: const Color(0xFF0531AA), fontSize: 16),
        ),
        Text(
          "ជាតិ សាសនា ព្រះមហាក្សត្រ",
          style: GoogleFonts.moul(color: const Color(0xFF0531AA), fontSize: 16),
        ),
        const SizedBox(height: 5),
        const Text(
          "v?v",
          style: TextStyle(
            fontFamily: 'Tacteing', 
            color: Color(0xFFDAA520), 
            fontSize: 20,
          ),
        ),
        const SizedBox(height: 10),
        
        Row(
          mainAxisAlignment: MainAxisAlignment.start,
          children: [
            Image.network(
              "https://i.ibb.co/hdy8JSv/Logo-Van-Van-1.png",
              width: 130,
              errorBuilder: (c, e, s) => const Icon(Icons.business, size: 50, color: Colors.grey),
            ),
          ],
        ),
        
        const SizedBox(height: 15),
        Text(
          "លិខិតបញ្ជាបេសកកម្ម",
          style: GoogleFonts.koulen(fontSize: 20, fontWeight: FontWeight.bold, color: bodyColor),
        ),
        const Text(
          "3",
          style: TextStyle(
            fontFamily: 'Tacteing', 
            color: Color(0xFFDAA520), 
            fontSize: 20,
          ),
        ),
        const SizedBox(height: 30),
        
        // Body text
        Align(
          alignment: Alignment.centerLeft,
          child: RichText(
            textAlign: TextAlign.start,
            text: TextSpan(
              style: GoogleFonts.battambang(color: bodyColor, fontSize: 14, height: 1.6),
              children: [
                TextSpan(
                  text: "អគ្គនាយិកា ក្រុមហ៊ុន វណ្ណ វណ្ណ ខេមបូឌា",
                  style: GoogleFonts.moul(fontSize: 13, color: bodyColor),
                ),
                const TextSpan(text: " បានសម្រេចចាត់តាំងបុគ្គលិកដែលមានរាយនាមដូចខាងក្រោម ចុះបំពេញបេសកកម្មនៅ៖ "),
                TextSpan(
                  text: "${mission['location']} ",
                  style: const TextStyle(fontWeight: FontWeight.bold, decoration: TextDecoration.underline),
                ),
                const TextSpan(text: "ដើម្បី "),
                TextSpan(
                  text: "${mission['purpose']}",
                  style: const TextStyle(fontWeight: FontWeight.bold),
                ),
              ],
            ),
          ),
        ),
        
        const SizedBox(height: 25),
        
        // Personnel List
        ...List.generate(10, (index) {
          final i = index + 1;
          final person = mission['person$i']?.toString() ?? '';
          
          // Always show at least 3 rows. Beyond 3, show only if data exists.
          if (person.isEmpty && i > 3) return const SizedBox.shrink();
          
          final displayPerson = person.isEmpty ? '.......................' : person;
          final displayRole = (mission['role$i']?.toString() ?? '').isEmpty 
              ? '.......................' : mission['role$i'];
          
          return Padding(
            padding: const EdgeInsets.symmetric(vertical: 6),
            child: Row(
              children: [
                Expanded(
                  flex: 6,
                  child: Text(
                    "$i. លោក-លោកស្រី៖ $displayPerson",
                    style: GoogleFonts.battambang(fontSize: 14, color: bodyColor),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Expanded(
                  flex: 4,
                  child: Text(
                    "តួនាទី៖ $displayRole",
                    style: GoogleFonts.battambang(fontSize: 14, color: bodyColor),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          );
        }),
        
        const SizedBox(height: 25),
        
        // Dates
        _buildInfoRow("- ថ្ងៃចេញដំណើរ៖", mission['start_date_fmt'] ?? mission['start_date'] ?? '.......................', "- ម៉ោងចេញដំណើរ៖", mission['start_time'] ?? '.......................'),
        _buildInfoRow("- ថ្ងៃត្រឡប់មកវិញ៖", mission['end_date_fmt'] ?? mission['end_date'] ?? '.......................', "- ម៉ោងត្រឡប់មកវិញ៖", mission['end_time'] ?? '.......................'),
        
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 4),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                "- មធ្យោបាយធ្វើដំណើរ៖ ",
                style: GoogleFonts.battambang(fontSize: 14, fontWeight: FontWeight.bold, color: bodyColor),
              ),
              Expanded(
                child: Text(
                  "${mission['transport'] ?? '.......................'}",
                  style: GoogleFonts.battambang(fontSize: 14, color: bodyColor),
                ),
              ),
            ],
          ),
        ),
        
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 4),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                "- សម្ភារៈភ្ជាប់ជាមួយ៖ ",
                style: GoogleFonts.battambang(fontSize: 14, fontWeight: FontWeight.bold, color: bodyColor),
              ),
              Expanded(
                child: Text(
                  "${mission['materials'] ?? '.......................'}",
                  style: GoogleFonts.battambang(fontSize: 14, color: bodyColor),
                ),
              ),
            ],
          ),
        ),
        
        const SizedBox(height: 40),
        
        Align(
          alignment: Alignment.centerLeft,
          child: Text(
            "អាស្រ័យដូចបានជម្រាបមកខាងលើ សូមបុគ្គលិកដែលពាក់ព័ន្ធទាំងអស់ ជួយសម្រួលការចុះបេសកកម្មនេះ ដោយក្តីអនុគ្រោះ។",
            style: GoogleFonts.battambang(fontSize: 15, color: bodyColor),
            textAlign: TextAlign.start,
          ),
        ),
        
        const SizedBox(height: 30),
        
        // Signature
        Align(
          alignment: Alignment.centerRight,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.center,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                _formatKhmerDate(mission['date_khmer'] ?? ''),
                style: GoogleFonts.battambang(fontSize: 14, color: bodyColor),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              Text(
                "ជ.អគ្គនាយិក\nប្រធាននាយកដ្ឋានធនធានមនុស្ស និងរដ្ឋបាល",
                style: GoogleFonts.battambang(fontSize: 14, height: 1.6, color: bodyColor),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 50),
              Text(
                "ផល ស៊ាងឡេង",
                style: GoogleFonts.moul(fontSize: 17, color: bodyColor),
              ),
            ],
          ),
        ),
        
        const SizedBox(height: 30),
        
        // Footer
        const Divider(color: Colors.amber, thickness: 2),
        Text(
          "ផ្ទះលេខ 1 AEo ផ្លូវលេខ 318 សង្កាត់ ទួលស្វាយព្រៃ១ ខណ្ឌ បឹងកេងកង រាជធានីភ្នំពេញ ព្រះរាជាណាចក្រកម្ពុជា ទូរស័ព្ទលេខ 015 971 961-085 971 961",
          style: GoogleFonts.battambang(fontSize: 10, color: Colors.amber, fontWeight: FontWeight.bold),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 3),
        const Text(
          "No.IAEo, St.318, Sangkat Tuol Svay Prey!, Khan Beong Keng kong, Phnom Penh, Cambodia. Tell: 015 971 961-085 971 961",
          style: TextStyle(fontSize: 9, color: Colors.black, fontWeight: FontWeight.bold),
          textAlign: TextAlign.center,
        ),
      ],
    );
  }

  Widget _buildInfoRow(String label1, String value1, String label2, String value2) {
    const color = Colors.black;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Expanded(
            child: Row(
              children: [
                Text(label1, style: GoogleFonts.battambang(fontSize: 14, fontWeight: FontWeight.bold, color: color)),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(value1, 
                    style: GoogleFonts.battambang(fontSize: 14, color: color),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Row(
              children: [
                Text(label2, style: GoogleFonts.battambang(fontSize: 14, fontWeight: FontWeight.bold, color: color)),
                const SizedBox(width: 4),
                Expanded(
                  child: Text(value2, 
                    style: GoogleFonts.battambang(fontSize: 14, color: color),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _formatKhmerDate(String dateKhmer) {
    if (dateKhmer.isEmpty || dateKhmer == '.......................br.......................') {
       return '.......................';
    }
    // PHP uses 'br' as a line break separator
    return dateKhmer.replaceAll('br', '\n');
  }
}
