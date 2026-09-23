import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
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

    // 1. Check Legal first (Aspect ~1.647)
    if (aspect >= 1.55) {
      bestSize = DocxPaperSize.legal;
    }
    // 2. Check Letter (Aspect ~1.294)
    else if (aspect <= 1.34) {
      bestSize = DocxPaperSize.letter;
    }
    // 3. ISO 216 Family (Aspect ~1.414: A3, A4, A5)
    else {
      // In business documents, forms, and scanned papers, ISO ratio is overwhelmingly A4.
      // Only classify as A5 or A3 if physical point dimensions (e.g. from PDF DPI 72)
      // unambiguously indicate non-A4 paper:
      // A5 points: ~420 x ~595 pt
      // A3 points: ~842 x ~1191 pt
      if (shortSide < 450 && longSide < 620 && shortSide > 150) {
        bestSize = DocxPaperSize.a5;
      } else if (shortSide > 750 && longSide > 1050) {
        bestSize = DocxPaperSize.a3;
      } else {
        // Standard A4 (e.g. 595x842 pt, or scanned image resolutions like 560x794, 1080x1530)
        bestSize = DocxPaperSize.a4;
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
  /// Supports dynamic [pageSize], [orientation], and [margin], and real [photoFile] / [photoBytes] embedding.
  static Future<File> generateDocx({
    required String title,
    required String content,
    required String outputPath,
    List<String>? multiPageContents,
    File? photoFile,
    Uint8List? photoBytes,
    DocxPaperSize pageSize = DocxPaperSize.a4,
    DocxPageOrientation orientation = DocxPageOrientation.portrait,
    DocxPageMargin margin = DocxPageMargin.normal,
  }) async {
    final archive = Archive();

    // Check if photo is provided as file or bytes
    Uint8List? effectivePhotoBytes = photoBytes;
    if (effectivePhotoBytes == null && photoFile != null && photoFile.existsSync()) {
      try {
        effectivePhotoBytes = await photoFile.readAsBytes();
      } catch (_) {}
    }
    final hasPhoto = effectivePhotoBytes != null && effectivePhotoBytes.isNotEmpty;

    // 1. [Content_Types].xml
    const contentTypesXml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="jpg" ContentType="image/jpeg"/>
  <Default Extension="jpeg" ContentType="image/jpeg"/>
  <Default Extension="png" ContentType="image/png"/>
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
    final docRelsBuffer = StringBuffer();
    docRelsBuffer.write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n');
    docRelsBuffer.write('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n');
    docRelsBuffer.write('  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>\n');
    docRelsBuffer.write('  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/>\n');
    if (hasPhoto) {
      docRelsBuffer.write('  <Relationship Id="rIdPhoto1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/photo1.jpg"/>\n');
    }
    docRelsBuffer.write('</Relationships>');
    final docRelsXml = docRelsBuffer.toString();
    archive.addFile(ArchiveFile('word/_rels/document.xml.rels', docRelsXml.length, utf8.encode(docRelsXml)));

    // Add photo binary to media folder if present
    if (effectivePhotoBytes != null && effectivePhotoBytes.isNotEmpty) {
      archive.addFile(ArchiveFile('word/media/photo1.jpg', effectivePhotoBytes.length, effectivePhotoBytes));
    }

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
      hasPhoto: hasPhoto,
    );
    archive.addFile(ArchiveFile('word/document.xml', documentXml.length, utf8.encode(documentXml)));

    // Zip and write to file
    final zipEncoder = ZipEncoder();
    final zipData = zipEncoder.encode(archive);

    final file = File(outputPath);
    await file.writeAsBytes(zipData);
    return file;
  }

  /// Master document.xml generator with high-fidelity typography, sections, and tables
  static String _buildDocumentXml({
    required String title,
    required String content,
    List<String>? multiPageContents,
    required int pageWidthDxa,
    required int pageHeightDxa,
    required int marginDxa,
    required int printableWidthDxa,
    required bool isLandscape,
    bool hasPhoto = false,
  }) {
    final buffer = StringBuffer();
    buffer.write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n');
    buffer.write('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">\n');
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
          hasPhoto: hasPhoto,
        );
      }
    } else {
      _parseAndAppendBody(
        buffer,
        content,
        isFirstPage: true,
        docTitle: title,
        printableWidthDxa: printableWidthDxa,
        hasPhoto: hasPhoto,
      );
    }

    // Dynamic Page & Margin settings - Note: w:docGrid is intentionally omitted
    // to allow Microsoft Word to render Khmer complex text without line collision or squishing.
    final orientAttr = isLandscape ? ' w:orient="landscape"' : '';
    buffer.write('''
    <w:sectPr>
      <w:pgSz w:w="$pageWidthDxa" w:h="$pageHeightDxa"$orientAttr/>
      <w:pgMar w:top="$marginDxa" w:right="$marginDxa" w:bottom="$marginDxa" w:left="$marginDxa" w:header="708" w:footer="708" w:gutter="0"/>
      <w:cols w:space="708"/>
    </w:sectPr>
''');
    buffer.write('</w:body>\n');
    buffer.write('</w:document>');
    return buffer.toString();
  }

  /// Decorative solid colored bar (Header/Footer bars for CV and Certificates)
  static String _buildDecorativeSolidBarXml({int totalWidth = 9500, String color = '184E77', int heightDxa = 140}) {
    return '''<w:tbl>
  <w:tblPr>
    <w:tblW w:w="$totalWidth" w:type="dxa"/>
    <w:jc w:val="center"/>
    <w:tblBorders>
      <w:top w:val="none"/>
      <w:left w:val="none"/>
      <w:bottom w:val="none"/>
      <w:right w:val="none"/>
      <w:insideH w:val="none"/>
      <w:insideV w:val="none"/>
    </w:tblBorders>
  </w:tblPr>
  <w:tblGrid>
    <w:gridCol w:w="$totalWidth"/>
  </w:tblGrid>
  <w:tr>
    <w:trPr>
      <w:cantSplit/>
      <w:trHeight w:val="$heightDxa" w:hRule="exact"/>
    </w:trPr>
    <w:tc>
      <w:tcPr>
        <w:tcW w:w="$totalWidth" w:type="dxa"/>
        <w:shd w:val="clear" w:color="auto" w:fill="$color"/>
        <w:tcMar>
          <w:top w:w="0" w:type="dxa"/>
          <w:bottom w:w="0" w:type="dxa"/>
          <w:left w:w="0" w:type="dxa"/>
          <w:right w:w="0" w:type="dxa"/>
        </w:tcMar>
        <w:vAlign w:val="center"/>
      </w:tcPr>
      <w:p>
        <w:pPr>
          <w:spacing w:line="100" w:lineRule="auto" w:before="0" w:after="0"/>
        </w:pPr>
      </w:p>
    </w:tc>
  </w:tr>
</w:tbl>
''';
  }

  /// Decorative divider line OpenXML (1.0pt solid line)
  static String _makeDividerLineXml({String color = '184E77'}) {
    return '''<w:p>
  <w:pPr>
    <w:pBdr>
      <w:bottom w:val="single" w:sz="12" w:space="1" w:color="$color"/>
    </w:pBdr>
    <w:spacing w:line="80" w:lineRule="auto" w:before="20" w:after="30"/>
  </w:pPr>
</w:p>
''';
  }

  /// Check if a line is a Section Banner Heading (like in CVs or official sections)
  static bool _isSectionBanner(String trimmed) {
    if (trimmed.contains('[BANNER]')) return true;
    final clean = trimmed.replaceAll(RegExp(r'^#+\s*'), '').replaceAll('[BANNER]', '').trim();
    final lower = clean.toLowerCase();
    return lower == 'ព័ត៌មានផ្ទាល់ខ្លួននិងទីកន្លែងរស់នៅ' ||
        lower == 'ព័ត៌មានផ្ទាល់ខ្លួន និងទីកន្លែងរស់នៅ' ||
        lower == 'ព័ត៌មានផ្ទាល់ខ្លួន និងជីវប្រវត្តិ' ||
        lower == 'ព័ត៌មានផ្ទាល់ខ្លួន' ||
        lower.startsWith('ប្រវត្តិសិក្សា') ||
        lower.startsWith('ប្រវត្តិការងារ') ||
        lower.startsWith('បទពិសោធន៍ការងារ') ||
        lower.startsWith('ជំនាញផ្ទាល់ខ្លួន') ||
        lower.startsWith('ចំណេះដឹងទូទៅ') ||
        lower.startsWith('ចំណេះដឹង') ||
        lower == 'ភាសាបរទេស' ||
        lower == 'សេចក្តីបញ្ជាក់' ||
        lower == 'personal information' ||
        lower == 'education' ||
        lower == 'work experience' ||
        lower == 'skills' ||
        lower == 'languages' ||
        lower == 'references';
  }

  /// Solid colored Section Banner Bar OpenXML (White bold text on solid background)
  static String _buildSectionBannerXml(String titleText, {int totalWidth = 9500, String bgColor = '184E77'}) {
    final cleanText = _escapeXml(titleText.replaceAll(RegExp(r'^#+\s*'), '').replaceAll('[BANNER]', '').trim());
    return '''<w:tbl>
  <w:tblPr>
    <w:tblW w:w="$totalWidth" w:type="dxa"/>
    <w:jc w:val="center"/>
    <w:tblBorders>
      <w:top w:val="none"/>
      <w:left w:val="none"/>
      <w:bottom w:val="none"/>
      <w:right w:val="none"/>
      <w:insideH w:val="none"/>
      <w:insideV w:val="none"/>
    </w:tblBorders>
  </w:tblPr>
  <w:tblGrid>
    <w:gridCol w:w="$totalWidth"/>
  </w:tblGrid>
  <w:tr>
    <w:trPr>
      <w:cantSplit/>
    </w:trPr>
    <w:tc>
      <w:tcPr>
        <w:tcW w:w="$totalWidth" w:type="dxa"/>
        <w:shd w:val="clear" w:color="auto" w:fill="$bgColor"/>
        <w:tcMar>
          <w:top w:w="40" w:type="dxa"/>
          <w:bottom w:w="40" w:type="dxa"/>
          <w:left w:w="120" w:type="dxa"/>
          <w:right w:w="120" w:type="dxa"/>
        </w:tcMar>
        <w:vAlign w:val="center"/>
      </w:tcPr>
      <w:p>
        <w:pPr>
          <w:spacing w:line="240" w:lineRule="auto" w:before="20" w:after="0"/>
        </w:pPr>
        <w:r>
          <w:rPr>
            <w:rFonts w:ascii="Khmer OS Muol Light" w:hAnsi="Khmer OS Muol Light" w:cs="Khmer OS Muol Light"/>
            <w:b/>
            <w:color w:val="FFFFFF"/>
            <w:sz w:val="22"/>
            <w:szCs w:val="22"/>
          </w:rPr>
          <w:t>$cleanText</w:t>
        </w:r>
      </w:p>
    </w:tc>
  </w:tr>
</w:tbl>
''';
  }

  /// 2-Column CV Header Table (Left: Contact Info, Right: 3x4 Photo Frame with Embedded Photo)
  static String _buildCvHeaderTableXml(
    List<String> contactLines, {
    int totalWidth = 9500,
    bool hasPhoto = false,
  }) {
    final textWidth = (totalWidth * 0.74).floor();
    final photoWidth = totalWidth - textWidth;

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
    buffer.write('    <w:gridCol w:w="$textWidth"/>\n');
    buffer.write('    <w:gridCol w:w="$photoWidth"/>\n');
    buffer.write('  </w:tblGrid>\n');
    buffer.write('  <w:tr>\n');
    buffer.write('    <w:trPr><w:cantSplit/></w:trPr>\n');

    // Column 1: Contact Details (Aligned tab stops for colons)
    buffer.write('    <w:tc>\n');
    buffer.write('      <w:tcPr>\n');
    buffer.write('        <w:tcW w:w="$textWidth" w:type="dxa"/>\n');
    buffer.write('        <w:vAlign w:val="center"/>\n');
    buffer.write('      </w:tcPr>\n');
    for (final line in contactLines) {
      final clean = line.replaceAll('[PHOTO]', '').trim();
      if (clean.isEmpty) continue;
      final escaped = _escapeXml(clean);
      buffer.write('      <w:p>\n');
      buffer.write('        <w:pPr>\n');
      buffer.write('          <w:tabs><w:tab w:val="left" w:pos="2400"/></w:tabs>\n');
      buffer.write('          <w:spacing w:line="260" w:lineRule="auto" w:before="0" w:after="20"/>\n');
      buffer.write('        </w:pPr>\n');

      if (escaped.contains(' : ') || escaped.contains(': ')) {
        final delim = escaped.contains(' : ') ? ' : ' : ': ';
        final parts = escaped.split(delim);
        buffer.write('        <w:r>\n');
        buffer.write('          <w:rPr>\n');
        buffer.write('            <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
        buffer.write('            <w:b/>\n');
        buffer.write('            <w:sz w:val="21"/>\n');
        buffer.write('            <w:szCs w:val="21"/>\n');
        buffer.write('          </w:rPr>\n');
        buffer.write('          <w:t>${parts[0]}</w:t>\n');
        buffer.write('        </w:r>\n');
        buffer.write('        <w:r>\n');
        buffer.write('          <w:tab/>\n');
        buffer.write('          <w:rPr>\n');
        buffer.write('            <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
        buffer.write('            <w:sz w:val="20"/>\n');
        buffer.write('            <w:szCs w:val="20"/>\n');
        buffer.write('          </w:rPr>\n');
        buffer.write('          <w:t xml:space="preserve">: ${parts.sublist(1).join(delim)}</w:t>\n');
        buffer.write('        </w:r>\n');
      } else {
        buffer.write('        <w:r>\n');
        buffer.write('          <w:rPr>\n');
        buffer.write('            <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
        buffer.write('            <w:sz w:val="20"/>\n');
        buffer.write('            <w:szCs w:val="20"/>\n');
        buffer.write('          </w:rPr>\n');
        buffer.write('          <w:t>$escaped</w:t>\n');
        buffer.write('        </w:r>\n');
      }
      buffer.write('      </w:p>\n');
    }
    buffer.write('    </w:tc>\n');

    // Column 2: 3x4 Photo Frame (Crisp 1pt border with zero excess margin)
    buffer.write('    <w:tc>\n');
    buffer.write('      <w:tcPr>\n');
    buffer.write('        <w:tcW w:w="$photoWidth" w:type="dxa"/>\n');
    if (!hasPhoto) {
      buffer.write('        <w:tcBorders>\n');
      buffer.write('          <w:top w:val="single" w:sz="6" w:color="94A3B8"/>\n');
      buffer.write('          <w:left w:val="single" w:sz="6" w:color="94A3B8"/>\n');
      buffer.write('          <w:bottom w:val="single" w:sz="6" w:color="94A3B8"/>\n');
      buffer.write('          <w:right w:val="single" w:sz="6" w:color="94A3B8"/>\n');
      buffer.write('        </w:tcBorders>\n');
      buffer.write('        <w:shd w:val="clear" w:color="auto" w:fill="F1F5F9"/>\n');
    } else {
      buffer.write('        <w:tcBorders>\n');
      buffer.write('          <w:top w:val="none"/>\n');
      buffer.write('          <w:left w:val="none"/>\n');
      buffer.write('          <w:bottom w:val="none"/>\n');
      buffer.write('          <w:right w:val="none"/>\n');
      buffer.write('        </w:tcBorders>\n');
    }
    buffer.write('        <w:tcMar>\n');
    buffer.write('          <w:top w:w="0" w:type="dxa"/>\n');
    buffer.write('          <w:bottom w:w="0" w:type="dxa"/>\n');
    buffer.write('          <w:left w:w="0" w:type="dxa"/>\n');
    buffer.write('          <w:right w:w="0" w:type="dxa"/>\n');
    buffer.write('        </w:tcMar>\n');
    buffer.write('        <w:vAlign w:val="center"/>\n');
    buffer.write('      </w:tcPr>\n');
    buffer.write('      <w:p>\n');
    buffer.write('        <w:pPr>\n');
    buffer.write('          <w:spacing w:line="240" w:lineRule="auto" w:after="0"/>\n');
    buffer.write('          <w:jc w:val="center"/>\n');
    buffer.write('        </w:pPr>\n');

    if (hasPhoto) {
      // Real Embedded Photo DrawingML (Standard 3x4: 2.7cm x 3.6cm = 972000 x 1296000 EMUs)
      buffer.write('        <w:r>\n');
      buffer.write('          <w:drawing>\n');
      buffer.write('            <wp:inline distT="0" distB="0" distL="0" distR="0">\n');
      buffer.write('              <wp:extent cx="972000" cy="1296000"/>\n');
      buffer.write('              <wp:effectExtent l="0" t="0" r="0" b="0"/>\n');
      buffer.write('              <wp:docPr id="1" name="Candidate Photo"/>\n');
      buffer.write('              <wp:cNvGraphicFramePr>\n');
      buffer.write('                <a:graphicFrameLocks xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" noChangeAspect="1"/>\n');
      buffer.write('              </wp:cNvGraphicFramePr>\n');
      buffer.write('              <a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">\n');
      buffer.write('                <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">\n');
      buffer.write('                  <pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">\n');
      buffer.write('                    <pic:nvPicPr>\n');
      buffer.write('                      <pic:cNvPr id="1" name="photo1.jpg"/>\n');
      buffer.write('                      <pic:cNvPicPr/>\n');
      buffer.write('                    </pic:nvPicPr>\n');
      buffer.write('                    <pic:blipFill>\n');
      buffer.write('                      <a:blip r:embed="rIdPhoto1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>\n');
      buffer.write('                      <a:stretch><a:fillRect/></a:stretch>\n');
      buffer.write('                    </pic:blipFill>\n');
      buffer.write('                    <pic:spPr>\n');
      buffer.write('                      <a:xfrm><a:off x="0" y="0"/><a:ext cx="972000" cy="1296000"/></a:xfrm>\n');
      buffer.write('                      <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>\n');
      buffer.write('                      <a:ln w="9525"><a:solidFill><a:srgbClr val="184E77"/></a:solidFill></a:ln>\n');
      buffer.write('                    </pic:spPr>\n');
      buffer.write('                  </pic:pic>\n');
      buffer.write('                </a:graphicData>\n');
      buffer.write('              </a:graphic>\n');
      buffer.write('            </wp:inline>\n');
      buffer.write('          </w:drawing>\n');
      buffer.write('        </w:r>\n');
    } else {
      // Subtle Placeholder Frame
      buffer.write('        <w:r>\n');
      buffer.write('          <w:rPr>\n');
      buffer.write('            <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
      buffer.write('            <w:color w:val="64748B"/>\n');
      buffer.write('            <w:sz w:val="20"/>\n');
      buffer.write('            <w:szCs w:val="20"/>\n');
      buffer.write('          </w:rPr>\n');
      buffer.write('          <w:t>រូបថត 3x4</w:t>\n');
      buffer.write('        </w:r>\n');
    }
    buffer.write('      </w:p>\n');
    buffer.write('    </w:tc>\n');

    buffer.write('  </w:tr>\n');
    buffer.write('</w:tbl>\n');

    // Horizontal divider line in navy blue right under the header
    buffer.write(_makeDividerLineXml(color: '184E77'));

    return buffer.toString();
  }

  /// Bullet item OpenXML with navy bullet, bold key, and aligned colon
  static String _buildBulletItemXml({
    required String bulletText,
    int indentLeft = 360,
    int hanging = 180,
  }) {
    final buffer = StringBuffer();
    buffer.write('<w:p>\n');
    buffer.write('  <w:pPr>\n');
    buffer.write('    <w:tabs><w:tab w:val="left" w:pos="3100"/></w:tabs>\n');
    buffer.write('    <w:spacing w:line="250" w:lineRule="auto" w:before="0" w:after="15"/>\n');
    buffer.write('    <w:ind w:left="$indentLeft" w:hanging="$hanging"/>\n');
    buffer.write('  </w:pPr>\n');

    // Bullet glyph in Navy Blue
    buffer.write('  <w:r>\n');
    buffer.write('    <w:rPr>\n');
    buffer.write('      <w:rFonts w:ascii="Segoe UI Symbol" w:hAnsi="Segoe UI Symbol" w:cs="Segoe UI Symbol"/>\n');
    buffer.write('      <w:color w:val="184E77"/>\n');
    buffer.write('      <w:sz w:val="20"/>\n');
    buffer.write('      <w:szCs w:val="20"/>\n');
    buffer.write('    </w:rPr>\n');
    buffer.write('    <w:t xml:space="preserve">•  </w:t>\n');
    buffer.write('  </w:r>\n');

    if (bulletText.contains(' : ') || bulletText.contains(': ')) {
      final delim = bulletText.contains(' : ') ? ' : ' : ': ';
      final parts = bulletText.split(delim);
      final key = parts[0];
      final val = parts.sublist(1).join(delim);

      // Key in bold dark slate
      buffer.write('  <w:r>\n');
      buffer.write('    <w:rPr>\n');
      buffer.write('      <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
      buffer.write('      <w:b/>\n');
      buffer.write('      <w:sz w:val="20"/>\n');
      buffer.write('      <w:szCs w:val="20"/>\n');
      buffer.write('    </w:rPr>\n');
      buffer.write('    <w:t>${_escapeXml(key)}</w:t>\n');
      buffer.write('  </w:r>\n');

      // Value with aligned colon via tab stop
      buffer.write('  <w:r>\n');
      buffer.write('    <w:tab/>\n');
      buffer.write('    <w:rPr>\n');
      buffer.write('      <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
      buffer.write('      <w:sz w:val="20"/>\n');
      buffer.write('      <w:szCs w:val="20"/>\n');
      buffer.write('    </w:rPr>\n');
      buffer.write('    <w:t xml:space="preserve">: ${_escapeXml(val)}</w:t>\n');
      buffer.write('  </w:r>\n');
    } else {
      buffer.write('  <w:r>\n');
      buffer.write('    <w:rPr>\n');
      buffer.write('      <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
      buffer.write('      <w:sz w:val="20"/>\n');
      buffer.write('      <w:szCs w:val="20"/>\n');
      buffer.write('    </w:rPr>\n');
      buffer.write('    <w:t>${_escapeXml(bulletText)}</w:t>\n');
      buffer.write('  </w:r>\n');
    }

    buffer.write('</w:p>\n');
    return buffer.toString();
  }

  /// Parses text lines, detects tables, headings, banners, CV headers, and divider lines
  static void _parseAndAppendBody(
    StringBuffer buffer,
    String rawText, {
    bool isFirstPage = true,
    String? docTitle,
    int printableWidthDxa = 9500,
    bool hasPhoto = false,
  }) {
    final lines = rawText.split(RegExp(r'\r?\n'));
    int i = 0;
    bool hasEmittedFooterLine = false;

    final isCvDoc = lines.any((l) =>
        l.contains('ប្រវត្តិរូបសង្ខេប') ||
        l.toUpperCase().contains('CURRICULUM VITAE') ||
        l.toUpperCase() == 'RESUME' ||
        l.contains('[PHOTO]'));

    if (isCvDoc && isFirstPage) {
      buffer.write(_buildDecorativeSolidBarXml(totalWidth: printableWidthDxa, color: '184E77', heightDxa: 140));
    }

    // Document Title Deduplication:
    // If rawText already contains a main title heading (e.g. # ប្រវត្តិរូបសង្ខេប), do not print docTitle separately.
    final cleanDocTitle = docTitle?.replaceAll(RegExp(r'^[#*\s]+'), '').trim().toLowerCase() ?? '';
    final hasExplicitDocTitle = docTitle != null &&
        cleanDocTitle.isNotEmpty &&
        docTitle != 'ឯកសារស្កេន' &&
        docTitle != 'Khmer' &&
        docTitle != 'Scan' &&
        docTitle != 'ពាក្យសុំច្បាប់ឈប់សម្រាក';

    final firstFewLines = rawText
        .split('\n')
        .take(5)
        .map((l) => l.replaceAll(RegExp(r'^[#*\s]+'), '').trim().toLowerCase())
        .where((l) => l.isNotEmpty)
        .toList();

    final docAlreadyContainsTitle = firstFewLines.any((l) =>
        (hasExplicitDocTitle && (l == cleanDocTitle || l.contains(cleanDocTitle))) ||
        l.contains('ប្រវត្តិរូបសង្ខេប') ||
        l.contains('curriculum vitae') ||
        l == 'resume');

    if (hasExplicitDocTitle && !docAlreadyContainsTitle) {
      buffer.write(_makeParagraph(
        text: docTitle.trim(),
        align: 'center',
        isBold: true,
        fontSizePt: 14.5,
        fontFamily: 'Khmer OS Muol Light',
      ));
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

      // 2. Explicit divider lines (--- or ___)
      if (trimmed == '---' || trimmed == '___' || RegExp(r'^-{3,}$').hasMatch(trimmed)) {
        buffer.write(_makeDividerLineXml(color: '184E77'));
        i++;
        continue;
      }

      // 3. Section Banners (CV / Structured Document Category Bars like ព័ត៌មានផ្ទាល់ខ្លួន, ប្រវត្តិសិក្សា...)
      if (_isSectionBanner(trimmed)) {
        buffer.write(_buildSectionBannerXml(trimmed, totalWidth: printableWidthDxa));
        i++;
        continue;
      }

      // 4. CV / Resume Main Title & Header Profile
      if (trimmed.contains('ប្រវត្តិរូបសង្ខេប') ||
          trimmed.toUpperCase().contains('CURRICULUM VITAE') ||
          trimmed.toUpperCase() == 'RESUME') {
        final cleanTitle = trimmed.replaceAll(RegExp(r'^[#*\s]+'), '').trim();
        buffer.write(_makeParagraph(
          text: cleanTitle,
          align: 'center',
          isBold: true,
          fontSizePt: 16,
          fontFamily: 'Khmer OS Muol Light',
        ));
        i++;

        // Collect subsequent contact lines before first section banner
        final contactLines = <String>[];
        while (i < lines.length) {
          final nextTrimmed = lines[i].trim();
          if (nextTrimmed.isEmpty) {
            i++;
            continue;
          }
          if (_isSectionBanner(nextTrimmed) ||
              nextTrimmed.startsWith('|') ||
              nextTrimmed == '---' ||
              nextTrimmed == '___' ||
              RegExp(r'^[-*•]\s+').hasMatch(nextTrimmed)) {
            break;
          }
          contactLines.add(nextTrimmed);
          i++;
        }

        final headerContact = <String>[];
        final extraPersonal = <String>[];

        for (final line in contactLines) {
          final lTrim = line.replaceAll('[PHOTO]', '').trim();
          if (lTrim.isEmpty) continue;

          final isHeaderField = lTrim.contains('នាម-គោត្តនាម') ||
              lTrim.contains('អាសយដ្ឋាន') ||
              lTrim.contains('ទូរស័ព្ទ') ||
              lTrim.contains('Telegram') ||
              lTrim.contains('@') ||
              lTrim.contains('Email') ||
              (headerContact.length < 3 &&
                  !lTrim.contains('ភេទ') &&
                  !lTrim.contains('សញ្ជាតិ') &&
                  !lTrim.contains('កំណើត'));

          if (isHeaderField && extraPersonal.isEmpty) {
            headerContact.add(lTrim);
          } else {
            extraPersonal.add(lTrim);
          }
        }

        if (headerContact.isNotEmpty) {
          buffer.write(_buildCvHeaderTableXml(
            headerContact,
            totalWidth: printableWidthDxa,
            hasPhoto: hasPhoto,
          ));
        }

        if (extraPersonal.isNotEmpty) {
          buffer.write(_buildSectionBannerXml('ព័ត៌មានផ្ទាល់ខ្លួននិងទីកន្លែងរស់នៅ', totalWidth: printableWidthDxa));
          for (final item in extraPersonal) {
            buffer.write(_buildBulletItemXml(bulletText: item));
          }
        }
        continue;
      }

      // 5. Bullet or Numbered items (• or * or -)
      if (RegExp(r'^[-*•]\s+').hasMatch(trimmed)) {
        final bulletText = trimmed.replaceFirst(RegExp(r'^[-*•]\s+'), '');
        buffer.write(_buildBulletItemXml(bulletText: bulletText));
        i++;
        continue;
      }

      // 6. Headings (# Title or ## Subtitle)
      if (trimmed.startsWith('# ')) {
        buffer.write(_makeParagraph(
          text: trimmed.substring(2).trim(),
          align: 'center',
          isBold: true,
          fontSizePt: 14,
          fontFamily: 'Khmer OS Muol Light',
        ));
        i++;
        continue;
      } else if (trimmed.startsWith('## ')) {
        buffer.write(_makeParagraph(
          text: trimmed.substring(3).trim(),
          align: 'left',
          isBold: true,
          fontSizePt: 12.5,
          fontFamily: 'Khmer OS Battambang',
        ));
        i++;
        continue;
      } else if (trimmed.startsWith('### ')) {
        buffer.write(_makeParagraph(
          text: trimmed.substring(4).trim(),
          align: 'left',
          isBold: true,
          fontSizePt: 11.5,
          fontFamily: 'Khmer OS Battambang',
        ));
        i++;
        continue;
      }

      // 7. Centered Company Header with Golden Header Line (Forms like VAN VAN CAMBODIA)
      if (trimmed.toUpperCase().contains('VAN VAN CAMBODIA') ||
          trimmed.contains('វ៉ាន់ វ៉ាន់ ខេមបូឌា')) {
        buffer.write(_makeParagraph(
          text: trimmed,
          align: 'center',
          isBold: true,
          fontSizePt: 14,
          fontFamily: 'Khmer OS Muol Light',
        ));
        buffer.write(_makeDividerLineXml(color: 'D97706'));
        i++;
        continue;
      }

      // 8. Centered Document Titles
      if (trimmed.contains('ព្រះរាជាណាចក្រកម្ពុជា') ||
          trimmed.contains('ជាតិ សាសនា ព្រះមហាក្សត្រ') ||
          trimmed.contains('APPLICATION FOR LEAVE') ||
          trimmed.contains('ពាក្យសុំច្បាប់ឈប់សម្រាក') ||
          trimmed.contains('ពាក្យសុំច្បាប់របស់បុគ្គលិក')) {
        buffer.write(_makeParagraph(
          text: trimmed,
          align: 'center',
          isBold: true,
          fontSizePt: trimmed.length < 30 ? 14 : 12,
          fontFamily: 'Khmer OS Muol Light',
        ));
        i++;
        continue;
      }

      // 9. Centered Bold Section Titles (e.g. **ប័ណ្ណប្រកាស...**)
      if (trimmed.startsWith('**') && trimmed.endsWith('**')) {
        final inner = trimmed.substring(2, trimmed.length - 2).trim();
        buffer.write(_makeParagraph(
          text: inner,
          align: 'center',
          isBold: true,
          fontSizePt: 13,
          fontFamily: 'Khmer OS Muol Light',
        ));
        i++;
        continue;
      }

      // 10. Checkbox Items: Group consecutive items into a compact 3-column grid
      if (RegExp(r'^\s*(\[[ xX]\]|[☑☐])\s*').hasMatch(trimmed)) {
        final checkboxItems = <Map<String, dynamic>>[];
        while (i < lines.length && RegExp(r'^\s*(\[[ xX]\]|[☑☐])\s*').hasMatch(lines[i].trim())) {
          final cLine = lines[i].trim();
          final isChecked = cLine.contains('[x]') || cLine.contains('[X]') || cLine.contains('☑');
          final itemText = cLine.replaceFirst(RegExp(r'^\s*(\[[ xX]\]|[☑☐])\s*'), '').trim();
          checkboxItems.add({'text': itemText, 'isChecked': isChecked});
          i++;
        }
        buffer.write(_buildCompactCheckboxGridXml(checkboxItems, totalWidth: printableWidthDxa));
        continue;
      }

      // 11. Footer Address & Contact Info with Golden Footer Line
      if (trimmed.contains('ផ្ទះលេខ') ||
          trimmed.contains('No.1AEo') ||
          trimmed.contains('Sangkat Tuol Svay') ||
          trimmed.contains('សង្កាត់ទួលស្វាយព្រៃ') ||
          trimmed.contains('No.030') ||
          (trimmed.contains('ទូរស័ព្ទ:') && trimmed.length > 25)) {
        if (!hasEmittedFooterLine) {
          buffer.write(_makeDividerLineXml(color: 'D97706'));
          hasEmittedFooterLine = true;
        }
        buffer.write(_makeParagraph(
          text: trimmed,
          align: 'center',
          fontSizePt: 9.5,
          textColor: 'B45309',
        ));
        i++;
        continue;
      }

      // 12. Multi-column lines (Signatures or wide spacing like \s{3,} or tabs)
      final multiCols = trimmed.split(RegExp(r'\s{3,}|\t+')).where((c) => c.trim().isNotEmpty).toList();
      if (multiCols.length >= 2 && !trimmed.startsWith('|')) {
        buffer.write(_buildBorderlessRowTableXml(multiCols, totalWidth: printableWidthDxa));
        i++;
        continue;
      }

      // 13. Signature / Date lines at bottom
      if (trimmed.startsWith('ធ្វើនៅ') || trimmed.startsWith('ថ្ងៃទី') || trimmed.contains('ចៅសង្កាត់') || trimmed.contains('មេឃុំ')) {
        buffer.write(_makeParagraph(
          text: trimmed,
          align: 'right',
          fontSizePt: 11,
        ));
        i++;
        continue;
      }

      // 14. Regular paragraph with key-value detection
      final isCvDoc = lines.any((l) =>
          l.contains('ប្រវត្តិរូបសង្ខេប') ||
          l.toUpperCase().contains('CURRICULUM VITAE') ||
          l.toUpperCase() == 'RESUME');
      if (isCvDoc && (trimmed.contains(': ') || trimmed.contains(' : ') || trimmed.contains('៖ '))) {
        buffer.write(_buildBulletItemXml(bulletText: trimmed));
        i++;
        continue;
      }

      buffer.write(_makeParagraph(
        text: trimmed,
        align: 'left',
      ));
      i++;
    }

    if (isCvDoc) {
      buffer.write(_buildDecorativeSolidBarXml(totalWidth: printableWidthDxa, color: '184E77', heightDxa: 140));
    }
  }

  /// Generates XML for a single Paragraph with smart key-value bolding
  /// Strictly follows ECMA-376 CT_PPrBase sequence: spacing -> ind -> jc
  static String _makeParagraph({
    required String text,
    String align = 'left',
    bool isBold = false,
    double fontSizePt = 11.0,
    String fontFamily = 'Khmer OS Battambang',
    int? leftIndent,
    String? textColor,
  }) {
    final cleanText = _escapeXml(text);
    final halfPt = (fontSizePt * 2).round();

    final buffer = StringBuffer();
    buffer.write('<w:p>\n');
    buffer.write('  <w:pPr>\n');
    // ECMA-376: spacing MUST come before ind and jc
    buffer.write('    <w:spacing w:line="280" w:lineRule="auto" w:after="50"/>\n');
    if (leftIndent != null) {
      buffer.write('    <w:ind w:left="$leftIndent"/>\n');
    }
    if (align != 'left') {
      buffer.write('    <w:jc w:val="$align"/>\n');
    }
    buffer.write('  </w:pPr>\n');

    final colorTag = textColor != null ? '      <w:color w:val="$textColor"/>\n' : '';

    // Parse key-value format (Key: Value) to bold the Key
    if (cleanText.contains(': ') && !isBold) {
      final parts = cleanText.split(': ');
      for (int k = 0; k < parts.length; k++) {
        if (k == 0) {
          buffer.write('  <w:r>\n');
          buffer.write('    <w:rPr>\n');
          buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
          buffer.write('      <w:b/>\n');
          buffer.write(colorTag);
          buffer.write('      <w:sz w:val="$halfPt"/>\n');
          buffer.write('      <w:szCs w:val="$halfPt"/>\n');
          buffer.write('    </w:rPr>\n');
          buffer.write('    <w:t xml:space="preserve">${parts[0]}: </w:t>\n');
          buffer.write('  </w:r>\n');
        } else if (k < parts.length - 1) {
          final sub = parts[k];
          final lastSpace = sub.lastIndexOf(' ');
          if (lastSpace != -1) {
            final val = sub.substring(0, lastSpace);
            final nextKey = sub.substring(lastSpace + 1);
            buffer.write('  <w:r>\n');
            buffer.write('    <w:rPr>\n');
            buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
            buffer.write(colorTag);
            buffer.write('      <w:sz w:val="$halfPt"/>\n');
            buffer.write('      <w:szCs w:val="$halfPt"/>\n');
            buffer.write('    </w:rPr>\n');
            buffer.write('    <w:t xml:space="preserve">$val  </w:t>\n');
            buffer.write('  </w:r>\n');
            buffer.write('  <w:r>\n');
            buffer.write('    <w:rPr>\n');
            buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
            buffer.write('      <w:b/>\n');
            buffer.write(colorTag);
            buffer.write('      <w:sz w:val="$halfPt"/>\n');
            buffer.write('      <w:szCs w:val="$halfPt"/>\n');
            buffer.write('    </w:rPr>\n');
            buffer.write('    <w:t xml:space="preserve">$nextKey: </w:t>\n');
            buffer.write('  </w:r>\n');
          } else {
            buffer.write('  <w:r>\n');
            buffer.write('    <w:rPr>\n');
            buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
            buffer.write(colorTag);
            buffer.write('      <w:sz w:val="$halfPt"/>\n');
            buffer.write('      <w:szCs w:val="$halfPt"/>\n');
            buffer.write('    </w:rPr>\n');
            buffer.write('    <w:t xml:space="preserve">${parts[k]}: </w:t>\n');
            buffer.write('  </w:r>\n');
          }
        } else {
          buffer.write('  <w:r>\n');
          buffer.write('    <w:rPr>\n');
          buffer.write('      <w:rFonts w:ascii="$fontFamily" w:hAnsi="$fontFamily" w:cs="$fontFamily"/>\n');
          buffer.write(colorTag);
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
      buffer.write(colorTag);
      buffer.write('      <w:sz w:val="$halfPt"/>\n');
      buffer.write('      <w:szCs w:val="$halfPt"/>\n');
      buffer.write('    </w:rPr>\n');
      buffer.write('    <w:t>$cleanText</w:t>\n');
      buffer.write('  </w:r>\n');
    }

    buffer.write('</w:p>\n');
    return buffer.toString();
  }

  /// Compact 3-Column Checkbox Grid in Word OpenXML
  /// Keeps all leave options neatly packed on a single page
  static String _buildCompactCheckboxGridXml(List<Map<String, dynamic>> items, {int totalWidth = 9500}) {
    if (items.isEmpty) return '';

    const numCols = 3;
    final colWidth = (totalWidth / numCols).floor();
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
    for (int c = 0; c < numCols; c++) {
      buffer.write('    <w:gridCol w:w="$colWidth"/>\n');
    }
    buffer.write('  </w:tblGrid>\n');

    final numRows = (items.length / numCols).ceil();
    for (int r = 0; r < numRows; r++) {
      buffer.write('  <w:tr>\n');
      buffer.write('    <w:trPr><w:cantSplit/></w:trPr>\n');

      for (int c = 0; c < numCols; c++) {
        final itemIndex = r * numCols + c;
        if (itemIndex < items.length) {
          final item = items[itemIndex];
          final isChecked = item['isChecked'] as bool;
          final text = item['text'] as String;
          final boxChar = isChecked ? '☑' : '☐';

          buffer.write('    <w:tc>\n');
          buffer.write('      <w:tcPr>\n');
          buffer.write('        <w:tcW w:w="$colWidth" w:type="dxa"/>\n');
          if (isChecked) {
            buffer.write('        <w:shd w:val="clear" w:color="auto" w:fill="FEF3C7"/>\n');
          }
          buffer.write('        <w:tcMar>\n');
          buffer.write('          <w:top w:w="40" w:type="dxa"/>\n');
          buffer.write('          <w:bottom w:w="40" w:type="dxa"/>\n');
          buffer.write('          <w:left w:w="60" w:type="dxa"/>\n');
          buffer.write('          <w:right w:w="60" w:type="dxa"/>\n');
          buffer.write('        </w:tcMar>\n');
          buffer.write('        <w:vAlign w:val="center"/>\n');
          buffer.write('      </w:tcPr>\n');

          buffer.write('      <w:p>\n');
          buffer.write('        <w:pPr>\n');
          buffer.write('          <w:spacing w:line="240" w:lineRule="auto" w:after="20"/>\n');
          buffer.write('        </w:pPr>\n');

          // Box symbol
          buffer.write('        <w:r>\n');
          buffer.write('          <w:rPr>\n');
          buffer.write('            <w:rFonts w:ascii="Segoe UI Symbol" w:hAnsi="Segoe UI Symbol" w:cs="Segoe UI Symbol"/>\n');
          if (isChecked) {
            buffer.write('            <w:b/>\n');
            buffer.write('            <w:color w:val="D97706"/>\n');
          } else {
            buffer.write('            <w:color w:val="64748B"/>\n');
          }
          buffer.write('            <w:sz w:val="22"/>\n');
          buffer.write('            <w:szCs w:val="22"/>\n');
          buffer.write('          </w:rPr>\n');
          buffer.write('          <w:t xml:space="preserve">$boxChar  </w:t>\n');
          buffer.write('        </w:r>\n');

          // Label
          buffer.write('        <w:r>\n');
          buffer.write('          <w:rPr>\n');
          buffer.write('            <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
          if (isChecked) {
            buffer.write('            <w:b/>\n');
            buffer.write('            <w:color w:val="92400E"/>\n');
          }
          buffer.write('            <w:sz w:val="19"/>\n');
          buffer.write('            <w:szCs w:val="19"/>\n');
          buffer.write('          </w:rPr>\n');
          buffer.write('          <w:t>${_escapeXml(text)}</w:t>\n');
          buffer.write('        </w:r>\n');

          buffer.write('      </w:p>\n');
          buffer.write('    </w:tc>\n');
        } else {
          // Empty cell for grid balance
          buffer.write('    <w:tc>\n');
          buffer.write('      <w:tcPr><w:tcW w:w="$colWidth" w:type="dxa"/></w:tcPr>\n');
          buffer.write('      <w:p><w:pPr><w:spacing w:line="240" w:lineRule="auto" w:after="0"/></w:pPr></w:p>\n');
          buffer.write('    </w:tc>\n');
        }
      }

      buffer.write('  </w:tr>\n');
    }

    buffer.write('</w:tbl>\n');
    return buffer.toString();
  }

  /// Builds a borderless table row for multi-column signature blocks or headers
  /// Strictly follows ECMA-376 CT_PPrBase sequence: spacing -> jc
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
      buffer.write('          <w:top w:w="60" w:type="dxa"/>\n');
      buffer.write('          <w:bottom w:w="60" w:type="dxa"/>\n');
      buffer.write('          <w:left w:w="80" w:type="dxa"/>\n');
      buffer.write('          <w:right w:w="80" w:type="dxa"/>\n');
      buffer.write('        </w:tcMar>\n');
      buffer.write('        <w:vAlign w:val="center"/>\n');
      buffer.write('      </w:tcPr>\n');
      buffer.write('      <w:p>\n');
      buffer.write('        <w:pPr>\n');
      buffer.write('          <w:spacing w:line="240" w:lineRule="auto" w:after="30"/>\n');
      buffer.write('          <w:jc w:val="center"/>\n');
      buffer.write('        </w:pPr>\n');
      buffer.write('        <w:r>\n');
      buffer.write('          <w:rPr>\n');
      buffer.write('            <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
      if (col.contains('(') || col.contains('Verified') || col.contains('Requested')) {
        buffer.write('            <w:b/>\n');
      }
      buffer.write('            <w:sz w:val="20"/>\n');
      buffer.write('            <w:szCs w:val="20"/>\n');
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
  /// Strictly follows ECMA-376 schema sequence:
  /// - trPr: cantSplit before tblHeader
  /// - pPr: spacing before jc
  /// - rPr: rFonts -> b -> sz -> szCs (NO invalid cs tag)
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
      // ECMA-376: cantSplit MUST come BEFORE tblHeader
      buffer.write('      <w:cantSplit/>\n');
      if (isHeader) buffer.write('      <w:tblHeader/>\n');
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
        buffer.write('          <w:top w:w="80" w:type="dxa"/>\n');
        buffer.write('          <w:bottom w:w="80" w:type="dxa"/>\n');
        buffer.write('          <w:left w:w="120" w:type="dxa"/>\n');
        buffer.write('          <w:right w:w="120" w:type="dxa"/>\n');
        buffer.write('        </w:tcMar>\n');
        buffer.write('        <w:vAlign w:val="center"/>\n');
        buffer.write('      </w:tcPr>\n');

        // Paragraph inside cell: spacing MUST come before jc
        buffer.write('      <w:p>\n');
        buffer.write('        <w:pPr>\n');
        buffer.write('          <w:spacing w:line="240" w:lineRule="auto" w:after="20"/>\n');
        if (isHeader) buffer.write('          <w:jc w:val="center"/>\n');
        buffer.write('        </w:pPr>\n');
        buffer.write('        <w:r>\n');
        buffer.write('          <w:rPr>\n');
        buffer.write('            <w:rFonts w:ascii="Khmer OS Battambang" w:hAnsi="Khmer OS Battambang" w:cs="Khmer OS Battambang"/>\n');
        if (isKey) buffer.write('            <w:b/>\n');
        buffer.write('            <w:sz w:val="20"/>\n');
        buffer.write('            <w:szCs w:val="20"/>\n');
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
