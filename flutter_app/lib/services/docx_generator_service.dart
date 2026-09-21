import 'dart:convert';
import 'dart:io';
import 'package:archive/archive.dart';

/// Supported standard paper sizes with dimensions in OpenXML dxa (1 pt = 20 dxa, 1 inch = 1440 dxa)
enum DocxPaperSize {
  a4('A4', '210 x 297 mm', 11906, 16838),
  letter('Letter', '8.5 x 11 in', 12240, 15840),
  legal('Legal', '8.5 x 14 in', 12240, 20160),
  a5('A5', '148 x 210 mm', 8390, 11906),
  a3('A3', '297 x 420 mm', 16838, 23811);

  final String name;
  final String dimensions;
  final int widthDxa; // portrait width
  final int heightDxa; // portrait height
  const DocxPaperSize(this.name, this.dimensions, this.widthDxa, this.heightDxa);
}

enum DocxPageOrientation {
  portrait('បញ្ឈរ (Portrait)'),
  landscape('ផ្តេក (Landscape)');

  final String label;
  const DocxPageOrientation(this.label);
}

enum DocxPageMargin {
  normal('ធម្មតា (Normal - 20mm)', 1134),
  narrow('ចង្អៀត (Narrow - 12.7mm)', 720),
  wide('ទូលាយ (Wide - 25.4mm)', 1440);

  final String label;
  final int marginDxa;
  const DocxPageMargin(this.label, this.marginDxa);
}

/// Result of auto-detecting paper size and orientation from a source document
class DetectedPageFormat {
  final DocxPaperSize paperSize;
  final DocxPageOrientation orientation;
  final double widthPt;
  final double heightPt;

  const DetectedPageFormat({
    required this.paperSize,
    required this.orientation,
    required this.widthPt,
    required this.heightPt,
  });

  String get summaryLabel => '${paperSize.name} • ${orientation == DocxPageOrientation.landscape ? "ផ្តេក (Landscape)" : "បញ្ឈរ (Portrait)"}';
}

/// Professional Docx Generator Service for Khmer & Multi-lingual Documents.
/// Produces genuine Microsoft Word (.docx) OpenXML archives.
/// Preserves Khmer typography (Khmer OS Battambang / Kantumruy Pro),
/// tables, alignments, headings, and dynamic paper dimensions.
class DocxGeneratorService {
  /// Detects closest standard paper format from physical dimensions in points or pixels
  static DetectedPageFormat detectFromDimensions(double width, double height) {
    if (width <= 0 || height <= 0) {
      return const DetectedPageFormat(
        paperSize: DocxPaperSize.a4,
        orientation: DocxPageOrientation.portrait,
        widthPt: 595.28,
        heightPt: 841.89,
      );
    }

    final isLandscape = width > height;
    final shortSide = isLandscape ? height : width;
    final longSide = isLandscape ? width : height;
    final aspect = longSide / shortSide;

    DocxPaperSize bestSize = DocxPaperSize.a4;
    double bestDiff = 999999.0;

    for (final size in DocxPaperSize.values) {
      final sizeAspect = size.heightDxa / size.widthDxa;
      final diff = (aspect - sizeAspect).abs();
      if (diff < bestDiff) {
        bestDiff = diff;
        bestSize = size;
      }
    }

    return DetectedPageFormat(
      paperSize: bestSize,
      orientation: isLandscape ? DocxPageOrientation.landscape : DocxPageOrientation.portrait,
      widthPt: width,
      heightPt: height,
    );
  }

  /// Generate a .docx file from structured text/markdown and save to [outputPath]
  /// Supports dynamic [pageSize], [orientation], and [margin]
  static Future<File> generateDocx({
    required String title,
    required String content,
    required String outputPath,
    List<String>? multiPageContents,
    DocxPaperSize pageSize = DocxPaperSize.a4,
    DocxPageOrientation orientation = DocxPageOrientation.portrait,
    DocxPageMargin margin = DocxPageMargin.normal,
  }) async {
    final archive = Archive();

    // 1. [Content_Types].xml
    const contentTypesXml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/fontTable.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"/>
</Types>''';
    archive.addFile(ArchiveFile('[Content_Types].xml', contentTypesXml.length, utf8.encode(contentTypesXml)));

    // 2. _rels/.rels
    const relsXml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>''';
    archive.addFile(ArchiveFile('_rels/.rels', relsXml.length, utf8.encode(relsXml)));

    // 3. word/_rels/document.xml.rels
    const docRelsXml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/>
</Relationships>''';
    archive.addFile(ArchiveFile('word/_rels/document.xml.rels', docRelsXml.length, utf8.encode(docRelsXml)));

    // 4. word/fontTable.xml
    const fontTableXml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:fonts xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:font w:name="Khmer OS Battambang">
    <w:panose1 w:val="02000503050603020002"/>
    <w:charset w:val="00"/>
    <w:family w:val="auto"/>
    <w:pitch w:val="variable"/>
  </w:font>
  <w:font w:name="Kantumruy Pro">
    <w:panose1 w:val="02000503050603020002"/>
    <w:charset w:val="00"/>
    <w:family w:val="auto"/>
    <w:pitch w:val="variable"/>
  </w:font>
  <w:font w:name="Khmer OS Muol Light">
    <w:panose1 w:val="02000503050603020002"/>
    <w:charset w:val="00"/>
    <w:family w:val="auto"/>
    <w:pitch w:val="variable"/>
  </w:font>
</w:fonts>''';
    archive.addFile(ArchiveFile('word/fontTable.xml', fontTableXml.length, utf8.encode(fontTableXml)));

    // 5. word/styles.xml
    const stylesXml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault>
      <w:rPr>
        <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>
        <w:sz w:val="23"/>
        <w:szCs w:val="23"/>
        <w:lang w:val="en-US" w:bidi="km-KH"/>
      </w:rPr>
    </w:rPrDefault>
    <w:pPrDefault>
      <w:pPr>
        <w:spacing w:line="320" w:lineRule="auto" w:after="120"/>
      </w:pPr>
    </w:pPrDefault>
  </w:docDefaults>
</w:styles>''';
    archive.addFile(ArchiveFile('word/styles.xml', stylesXml.length, utf8.encode(stylesXml)));

    // Compute dynamic paper dimensions and printable area in OpenXML dxa
    final isLandscape = orientation == DocxPageOrientation.landscape;
    final pageWidthDxa = isLandscape ? pageSize.heightDxa : pageSize.widthDxa;
    final pageHeightDxa = isLandscape ? pageSize.widthDxa : pageSize.heightDxa;
    final marginDxa = margin.marginDxa;
    final printableWidthDxa = pageWidthDxa - (marginDxa * 2);

    // 6. word/document.xml - Parse structured text / markdown into Word XML
    final documentXml = _buildDocumentXml(
      title: title,
      content: content,
      multiPageContents: multiPageContents,
      pageWidthDxa: pageWidthDxa,
      pageHeightDxa: pageHeightDxa,
      marginDxa: marginDxa,
      printableWidthDxa: printableWidthDxa,
      isLandscape: isLandscape,
    );
    archive.addFile(ArchiveFile('word/document.xml', documentXml.length, utf8.encode(documentXml)));

    // Zip and write to file
    final zipEncoder = ZipEncoder();
    final zipData = zipEncoder.encode(archive);

    final file = File(outputPath);
    await file.writeAsBytes(zipData);
    return file;
  }

  /// Builds the complete `word/document.xml` with dynamic page size and printable width
  static String _buildDocumentXml({
    required String title,
    required String content,
    List<String>? multiPageContents,
    required int pageWidthDxa,
    required int pageHeightDxa,
    required int marginDxa,
    required int printableWidthDxa,
    required bool isLandscape,
  }) {
    final buffer = StringBuffer();
    buffer.write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n');
    buffer.write('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n');
    buffer.write('<w:body>\n');

    if (multiPageContents != null && multiPageContents.length > 1) {
      for (int i = 0; i < multiPageContents.length; i++) {
        if (i > 0) {
          // Page Break
          buffer.write('<w:p><w:r><w:br w:type="page"/></w:r></w:p>\n');
        }
        _parseAndAppendBody(
          buffer,
          multiPageContents[i],
          isFirstPage: i == 0,
          docTitle: i == 0 ? title : null,
          printableWidthDxa: printableWidthDxa,
        );
      }
    } else {
      _parseAndAppendBody(
        buffer,
        content,
        isFirstPage: true,
        docTitle: title,
        printableWidthDxa: printableWidthDxa,
      );
    }

    // Dynamic Page & Margin settings
    final orientAttr = isLandscape ? ' w:orient="landscape"' : '';
    buffer.write('''
    <w:sectPr>
      <w:pgSz w:w="$pageWidthDxa" w:h="$pageHeightDxa"$orientAttr/>
      <w:pgMar w:top="$marginDxa" w:right="$marginDxa" w:bottom="$marginDxa" w:left="$marginDxa" w:header="708" w:footer="708" w:gutter="0"/>
      <w:cols w:space="708"/>
      <w:docGrid w:linePitch="360"/>
    </w:sectPr>
''');
    buffer.write('</w:body>\n');
    buffer.write('</w:document>');
    return buffer.toString();
  }

  /// Parses text lines, detects tables, headings, and alignments
  static void _parseAndAppendBody(
    StringBuffer buffer,
    String rawText, {
    bool isFirstPage = true,
    String? docTitle,
    int printableWidthDxa = 9500,
  }) {
    final lines = rawText.split(RegExp(r'\r?\n'));
    int i = 0;

    // Optional document title (only if genuine custom title and not already at start of document)
    if (docTitle != null &&
        docTitle.trim().isNotEmpty &&
        docTitle != 'ឯកសារស្កេន' &&
        docTitle != 'Khmer' &&
        docTitle != 'Scan') {
      final firstLines = rawText.split('\n').take(4).map((l) => l.trim().toLowerCase()).toList();
      if (!firstLines.contains(docTitle.trim().toLowerCase())) {
        buffer.write(_makeParagraph(
          text: docTitle.trim(),
          align: 'center',
          isBold: true,
          fontSizePt: 15,
          fontFamily: 'Khmer OS Muol Light',
        ));
      }
    }

    while (i < lines.length) {
      final line = lines[i];
      final trimmed = line.trim();

      if (trimmed.isEmpty) {
        i++;
        continue;
      }

      // 1. Detect Markdown Table (| col1 | col2 |)
      if (trimmed.startsWith('|') && trimmed.endsWith('|') && trimmed.contains('|')) {
        final tableLines = <String>[];
        while (i < lines.length && lines[i].trim().startsWith('|') && lines[i].trim().endsWith('|')) {
          tableLines.add(lines[i].trim());
          i++;
        }
        buffer.write(_buildTableXml(tableLines, totalWidth: printableWidthDxa));
        continue;
      }

      // 2. Headings (# Title or ## Subtitle)
      if (trimmed.startsWith('# ')) {
        buffer.write(_makeParagraph(
          text: trimmed.substring(2).trim(),
          align: 'center',
          isBold: true,
          fontSizePt: 15,
          fontFamily: 'Khmer OS Muol Light',
        ));
        i++;
        continue;
      } else if (trimmed.startsWith('## ')) {
        buffer.write(_makeParagraph(
          text: trimmed.substring(3).trim(),
          align: 'left',
          isBold: true,
          fontSizePt: 13,
          fontFamily: 'Khmer OS Battambang',
        ));
        i++;
        continue;
      } else if (trimmed.startsWith('### ')) {
        buffer.write(_makeParagraph(
          text: trimmed.substring(4).trim(),
          align: 'left',
          isBold: true,
          fontSizePt: 12,
          fontFamily: 'Khmer OS Battambang',
        ));
        i++;
        continue;
      }

      // 3. Centered Document Titles & Company names
      if (trimmed.contains('ព្រះរាជាណាចក្រកម្ពុជា') ||
          trimmed.contains('ជាតិ សាសនា ព្រះមហាក្សត្រ') ||
          trimmed.toUpperCase() == 'VAN VAN CAMBODIA' ||
          trimmed == 'វ៉ាន់ វ៉ាន់ ខេមបូឌា' ||
          trimmed.contains('APPLICATION FOR LEAVE') ||
          trimmed.contains('ពាក្យសុំច្បាប់ឈប់សម្រាក')) {
        buffer.write(_makeParagraph(
          text: trimmed,
          align: 'center',
          isBold: true,
          fontSizePt: trimmed.length < 30 ? 14 : 12.5,
          fontFamily: 'Khmer OS Muol Light',
        ));
        i++;
        continue;
      }

      // 4. Centered Titles (e.g. **ប័ណ្ណប្រកាសអាពាហ៍ពិពាហ៍** or **លិខិតបញ្ជាក់...**)
      if (trimmed.startsWith('**') && trimmed.endsWith('**')) {
        final inner = trimmed.substring(2, trimmed.length - 2).trim();
        buffer.write(_makeParagraph(
          text: inner,
          align: 'center',
          isBold: true,
          fontSizePt: 13.5,
          fontFamily: 'Khmer OS Muol Light',
        ));
        i++;
        continue;
      }

      // 5. Checkbox Items (e.g. [x] or [ ] or ☑ or ☐)
      if (RegExp(r'^\s*(\[[ xX]\]|[☑☐])\s*').hasMatch(trimmed)) {
        final isChecked = trimmed.contains('[x]') || trimmed.contains('[X]') || trimmed.contains('☑');
        final itemText = trimmed.replaceFirst(RegExp(r'^\s*(\[[ xX]\]|[☑☐])\s*'), '').trim();
        buffer.write(_makeCheckboxParagraph(
          text: itemText,
          isChecked: isChecked,
        ));
        i++;
        continue;
      }

      // 6. Multi-column lines (Signatures or wide spacing like \s{3,} or tabs)
      final multiCols = trimmed.split(RegExp(r'\s{3,}|\t+')).where((c) => c.trim().isNotEmpty).toList();
      if (multiCols.length >= 2 && !trimmed.startsWith('|')) {
        buffer.write(_buildBorderlessRowTableXml(multiCols, totalWidth: printableWidthDxa));
        i++;
        continue;
      }

      // 7. Bullet or Numbered items
      if (RegExp(r'^[-*•]\s+').hasMatch(trimmed)) {
        final bulletText = trimmed.replaceFirst(RegExp(r'^[-*•]\s+'), '');
        buffer.write(_makeParagraph(
          text: '•  $bulletText',
          align: 'left',
          leftIndent: 400,
        ));
        i++;
        continue;
      }

      // 8. Signature / Date lines at bottom
      if (trimmed.startsWith('ធ្វើនៅ') || trimmed.startsWith('ថ្ងៃទី') || trimmed.contains('ចៅសង្កាត់') || trimmed.contains('មេឃុំ')) {
        buffer.write(_makeParagraph(
          text: trimmed,
          align: 'right',
          fontSizePt: 11.5,
        ));
        i++;
        continue;
      }

      // 9. Regular paragraph with key-value detection
      buffer.write(_makeParagraph(
        text: trimmed,
        align: 'left',
      ));
      i++;
    }
  }

  /// Generates XML for a single Paragraph with smart key-value bolding
  static String _makeParagraph({
    required String text,
    String align = 'left',
    bool isBold = false,
    double fontSizePt = 11.5,
    String fontFamily = 'Khmer OS Battambang',
    int? leftIndent,
  }) {
    final cleanText = _escapeXml(text);
    final halfPt = (fontSizePt * 2).round();

    final buffer = StringBuffer();
    buffer.write('<w:p>\n');
    buffer.write('  <w:pPr>\n');
    if (align != 'left') {
      buffer.write('    <w:jc w:val="$align"/>\n');
    }
    if (leftIndent != null) {
      buffer.write('    <w:ind w:left="$leftIndent"/>\n');
    }
    buffer.write('    <w:spacing w:line="320" w:lineRule="auto" w:after="80"/>\n');
    buffer.write('  </w:pPr>\n');

    // Parse key-value format (Key: Value) to bold the Key
    if (cleanText.contains(': ') && !isBold) {
      final parts = cleanText.split(': ');
      for (int k = 0; k < parts.length; k++) {
        if (k == 0) {
          // First key
          buffer.write('  <w:r>\n');
          buffer.write('    <w:rPr>\n');
          buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
          buffer.write('      <w:b/>\n');
          buffer.write('      <w:sz w:val="$halfPt"/>\n');
          buffer.write('      <w:szCs w:val="$halfPt"/>\n');
          buffer.write('    </w:rPr>\n');
          buffer.write('    <w:t xml:space="preserve">${parts[0]}: </w:t>\n');
          buffer.write('  </w:r>\n');
        } else if (k < parts.length - 1) {
          // Middle value + next key
          final sub = parts[k];
          final lastSpace = sub.lastIndexOf(' ');
          if (lastSpace != -1) {
            final val = sub.substring(0, lastSpace);
            final nextKey = sub.substring(lastSpace + 1);
            // Value
            buffer.write('  <w:r>\n');
            buffer.write('    <w:rPr>\n');
            buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
            buffer.write('      <w:sz w:val="$halfPt"/>\n');
            buffer.write('      <w:szCs w:val="$halfPt"/>\n');
            buffer.write('    </w:rPr>\n');
            buffer.write('    <w:t xml:space="preserve">$val  </w:t>\n');
            buffer.write('  </w:r>\n');
            // Next Key
            buffer.write('  <w:r>\n');
            buffer.write('    <w:rPr>\n');
            buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
            buffer.write('      <w:b/>\n');
            buffer.write('      <w:sz w:val="$halfPt"/>\n');
            buffer.write('      <w:szCs w:val="$halfPt"/>\n');
            buffer.write('    </w:rPr>\n');
            buffer.write('    <w:t xml:space="preserve">$nextKey: </w:t>\n');
            buffer.write('  </w:r>\n');
          } else {
            buffer.write('  <w:r>\n');
            buffer.write('    <w:rPr>\n');
            buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
            buffer.write('      <w:sz w:val="$halfPt"/>\n');
            buffer.write('      <w:szCs w:val="$halfPt"/>\n');
            buffer.write('    </w:rPr>\n');
            buffer.write('    <w:t xml:space="preserve">${parts[k]}: </w:t>\n');
            buffer.write('  </w:r>\n');
          }
        } else {
          // Final value
          buffer.write('  <w:r>\n');
          buffer.write('    <w:rPr>\n');
          buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
          buffer.write('      <w:sz w:val="$halfPt"/>\n');
          buffer.write('      <w:szCs w:val="$halfPt"/>\n');
          buffer.write('    </w:rPr>\n');
          buffer.write('    <w:t>${parts[k]}</w:t>\n');
          buffer.write('  </w:r>\n');
        }
      }
    } else {
      buffer.write('  <w:r>\n');
      buffer.write('    <w:rPr>\n');
      buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
      if (isBold) buffer.write('      <w:b/>\n');
      buffer.write('      <w:sz w:val="$halfPt"/>\n');
      buffer.write('      <w:szCs w:val="$halfPt"/>\n');
      buffer.write('    </w:rPr>\n');
      buffer.write('    <w:t>$cleanText</w:t>\n');
      buffer.write('  </w:r>\n');
    }

    buffer.write('</w:p>\n');
    return buffer.toString();
  }

  /// Generates a clean checkbox paragraph with ballot box glyph
  static String _makeCheckboxParagraph({
    required String text,
    required bool isChecked,
    double fontSizePt = 11.5,
    String fontFamily = 'Khmer OS Battambang',
  }) {
    final halfPt = (fontSizePt * 2).round();
    final boxChar = isChecked ? '☑' : '☐';

    final buffer = StringBuffer();
    buffer.write('<w:p>\n');
    buffer.write('  <w:pPr>\n');
    buffer.write('    <w:ind w:left="400"/>\n');
    buffer.write('    <w:spacing w:line="300" w:lineRule="auto" w:after="70"/>\n');
    buffer.write('  </w:pPr>\n');

    // Checkbox Box Glyph
    buffer.write('  <w:r>\n');
    buffer.write('    <w:rPr>\n');
    buffer.write('      <w:rFonts w:ascii="Segoe UI Symbol" w:hAnsi="Segoe UI Symbol" w:cs="Segoe UI Symbol"/>\n');
    if (isChecked) {
      buffer.write('      <w:b/>\n');
      buffer.write('      <w:color w:val="2563EB"/>\n'); // Bold blue
    }
    buffer.write('      <w:sz w:val="${halfPt + 4}"/>\n');
    buffer.write('      <w:szCs w:val="${halfPt + 4}"/>\n');
    buffer.write('    </w:rPr>\n');
    buffer.write('    <w:t xml:space="preserve">$boxChar  </w:t>\n');
    buffer.write('  </w:r>\n');

    // Checkbox Label
    buffer.write('  <w:r>\n');
    buffer.write('    <w:rPr>\n');
    buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
    if (isChecked) buffer.write('      <w:b/>\n');
    buffer.write('      <w:sz w:val="$halfPt"/>\n');
    buffer.write('      <w:szCs w:val="$halfPt"/>\n');
    buffer.write('    </w:rPr>\n');
    buffer.write('    <w:t>${_escapeXml(text)}</w:t>\n');
    buffer.write('  </w:r>\n');

    buffer.write('</w:p>\n');
    return buffer.toString();
  }

  /// Builds a borderless table row for multi-column signature blocks or headers
  static String _buildBorderlessRowTableXml(List<String> cols, {int totalWidth = 9500}) {
    if (cols.isEmpty) return '';

    final colWidth = (totalWidth / cols.length).floor();

    final buffer = StringBuffer();
    buffer.write('<w:tbl>\n');
    buffer.write('  <w:tblPr>\n');
    buffer.write('    <w:tblW w:w="$totalWidth" w:type="dxa"/>\n');
    buffer.write('    <w:jc w:val="center"/>\n');
    buffer.write('    <w:tblBorders>\n');
    buffer.write('      <w:top w:val="none"/>\n');
    buffer.write('      <w:left w:val="none"/>\n');
    buffer.write('      <w:bottom w:val="none"/>\n');
    buffer.write('      <w:right w:val="none"/>\n');
    buffer.write('      <w:insideH w:val="none"/>\n');
    buffer.write('      <w:insideV w:val="none"/>\n');
    buffer.write('    </w:tblBorders>\n');
    buffer.write('  </w:tblPr>\n');

    buffer.write('  <w:tblGrid>\n');
    for (int c = 0; c < cols.length; c++) {
      buffer.write('    <w:gridCol w:w="$colWidth"/>\n');
    }
    buffer.write('  </w:tblGrid>\n');

    buffer.write('  <w:tr>\n');
    buffer.write('    <w:trPr><w:cantSplit/></w:trPr>\n');
    for (final col in cols) {
      buffer.write('    <w:tc>\n');
      buffer.write('      <w:tcPr>\n');
      buffer.write('        <w:tcW w:w="$colWidth" w:type="dxa"/>\n');
      buffer.write('        <w:tcMar>\n');
      buffer.write('          <w:top w:w="80" w:type="dxa"/>\n');
      buffer.write('          <w:bottom w:w="80" w:type="dxa"/>\n');
      buffer.write('          <w:left w:w="100" w:type="dxa"/>\n');
      buffer.write('          <w:right w:w="100" w:type="dxa"/>\n');
      buffer.write('        </w:tcMar>\n');
      buffer.write('        <w:vAlign w:val="center"/>\n');
      buffer.write('      </w:tcPr>\n');
      buffer.write('      <w:p>\n');
      buffer.write('        <w:pPr>\n');
      buffer.write('          <w:jc w:val="center"/>\n');
      buffer.write('          <w:spacing w:line="260" w:lineRule="auto" w:after="40"/>\n');
      buffer.write('        </w:pPr>\n');
      buffer.write('        <w:r>\n');
      buffer.write('          <w:rPr>\n');
      buffer.write('            <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
      if (col.contains('(') || col.contains('Verified') || col.contains('Requested')) {
        buffer.write('            <w:b/>\n');
      }
      buffer.write('            <w:sz w:val="21"/>\n');
      buffer.write('            <w:szCs w:val="21"/>\n');
      buffer.write('          </w:rPr>\n');
      buffer.write('          <w:t>${_escapeXml(col)}</w:t>\n');
      buffer.write('        </w:r>\n');
      buffer.write('      </w:p>\n');
      buffer.write('    </w:tc>\n');
    }
    buffer.write('  </w:tr>\n');
    buffer.write('</w:tbl>\n');

    return buffer.toString();
  }

  /// Builds a genuine OpenXML `<w:tbl>` from Markdown table rows
  static String _buildTableXml(List<String> tableLines, {int totalWidth = 9500}) {
    if (tableLines.isEmpty) return '';

    // Filter out divider lines like |---|---|
    final rows = <List<String>>[];
    for (final line in tableLines) {
      if (RegExp(r'^\|[\s\-:|]+\|$').hasMatch(line)) continue;
      final rawCells = line.split('|');
      if (rawCells.length >= 2) {
        final row = rawCells
            .sublist(1, rawCells.length - 1)
            .map((c) => c.trim())
            .toList();
        if (row.isNotEmpty) rows.add(row);
      }
    }

    if (rows.isEmpty) return '';

    final maxCols = rows.map((r) => r.length).reduce((a, b) => a > b ? a : b);
    final colWidth = (totalWidth / maxCols).floor();

    final buffer = StringBuffer();
    buffer.write('<w:tbl>\n');
    buffer.write('  <w:tblPr>\n');
    buffer.write('    <w:tblW w:w="$totalWidth" w:type="dxa"/>\n');
    buffer.write('    <w:jc w:val="center"/>\n');
    buffer.write('    <w:tblBorders>\n');
    buffer.write('      <w:top w:val="single" w:sz="8" w:space="0" w:color="000000"/>\n');
    buffer.write('      <w:left w:val="single" w:sz="8" w:space="0" w:color="000000"/>\n');
    buffer.write('      <w:bottom w:val="single" w:sz="8" w:space="0" w:color="000000"/>\n');
    buffer.write('      <w:right w:val="single" w:sz="8" w:space="0" w:color="000000"/>\n');
    buffer.write('      <w:insideH w:val="single" w:sz="4" w:space="0" w:color="000000"/>\n');
    buffer.write('      <w:insideV w:val="single" w:sz="4" w:space="0" w:color="000000"/>\n');
    buffer.write('    </w:tblBorders>\n');
    buffer.write('  </w:tblPr>\n');

    // Table grid
    buffer.write('  <w:tblGrid>\n');
    for (int c = 0; c < maxCols; c++) {
      buffer.write('    <w:gridCol w:w="$colWidth"/>\n');
    }
    buffer.write('  </w:tblGrid>\n');

    for (int r = 0; r < rows.length; r++) {
      final isHeader = r == 0;
      final row = rows[r];
      buffer.write('  <w:tr>\n');
      buffer.write('    <w:trPr>\n');
      if (isHeader) buffer.write('      <w:tblHeader/>\n');
      buffer.write('      <w:cantSplit/>\n');
      buffer.write('    </w:trPr>\n');

      for (int c = 0; c < maxCols; c++) {
        final cellText = c < row.length ? row[c] : '';
        final isKey = isHeader || cellText.contains('៖') || cellText.contains(':') || cellText.contains('ឈ្មោះ') || cellText.contains('ផ្នែក') || cellText.contains('ថ្ងៃ');
        buffer.write('    <w:tc>\n');
        buffer.write('      <w:tcPr>\n');
        buffer.write('        <w:tcW w:w="$colWidth" w:type="dxa"/>\n');
        if (isKey) {
          buffer.write('        <w:shd w:val="clear" w:color="auto" w:fill="FEF9C3"/>\n');
        }
        buffer.write('        <w:tcMar>\n');
        buffer.write('          <w:top w:w="120" w:type="dxa"/>\n');
        buffer.write('          <w:bottom w:w="120" w:type="dxa"/>\n');
        buffer.write('          <w:left w:w="160" w:type="dxa"/>\n');
        buffer.write('          <w:right w:w="160" w:type="dxa"/>\n');
        buffer.write('        </w:tcMar>\n');
        buffer.write('        <w:vAlign w:val="center"/>\n');
        buffer.write('      </w:tcPr>\n');

        // Paragraph inside cell
        buffer.write('      <w:p>\n');
        buffer.write('        <w:pPr>\n');
        if (isHeader) buffer.write('          <w:jc w:val="center"/>\n');
        buffer.write('          <w:spacing w:line="260" w:lineRule="auto" w:after="40"/>\n');
        buffer.write('        </w:pPr>\n');
        buffer.write('        <w:r>\n');
        buffer.write('          <w:rPr>\n');
        buffer.write('            <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
        buffer.write('            <w:cs/>\n');
        if (isKey) buffer.write('            <w:b/>\n');
        buffer.write('            <w:sz w:val="21"/>\n');
        buffer.write('            <w:szCs w:val="21"/>\n');
        buffer.write('          </w:rPr>\n');
        buffer.write('          <w:t>${_escapeXml(cellText)}</w:t>\n');
        buffer.write('        </w:r>\n');
        buffer.write('      </w:p>\n');
        buffer.write('    </w:tc>\n');
      }

      buffer.write('  </w:tr>\n');
    }

    buffer.write('</w:tbl>\n');
    return buffer.toString();
  }

  /// Escapes special XML characters
  static String _escapeXml(String input) {
    return input
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&apos;');
  }
}
