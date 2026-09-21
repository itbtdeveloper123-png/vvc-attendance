import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:archive/archive.dart';
import 'package:vvc_hrm/services/docx_generator_service.dart';

void main() {
  group('Docx Page Setup & Auto-detection Tests', () {
    test('detectFromDimensions detects A4 Portrait and Landscape accurately', () {
      final portraitA4 = DocxGeneratorService.detectFromDimensions(595.28, 841.89);
      expect(portraitA4.paperSize, DocxPaperSize.a4);
      expect(portraitA4.orientation, DocxPageOrientation.portrait);

      final landscapeA4 = DocxGeneratorService.detectFromDimensions(841.89, 595.28);
      expect(landscapeA4.paperSize, DocxPaperSize.a4);
      expect(landscapeA4.orientation, DocxPageOrientation.landscape);
    });

    test('detectFromDimensions detects Letter and Legal formats', () {
      final letter = DocxGeneratorService.detectFromDimensions(612.0, 792.0);
      expect(letter.paperSize, DocxPaperSize.letter);
      expect(letter.orientation, DocxPageOrientation.portrait);

      final legal = DocxGeneratorService.detectFromDimensions(612.0, 1008.0);
      expect(legal.paperSize, DocxPaperSize.legal);
      expect(legal.orientation, DocxPageOrientation.portrait);
    });

    test('generateDocx produces valid OpenXML with dynamic page size, margins, and table width', () async {
      final tempDir = Directory.systemTemp.createTempSync('docx_test');
      final testFile = File('${tempDir.path}/test_landscape_letter.docx');

      const sampleTable = '''
| ឈ្មោះ | ភេទ | តួនាទី |
| អ៊ុក រ៉ា | ប្រុស | ប្រធានផ្នែក |
''';

      await DocxGeneratorService.generateDocx(
        title: 'លិខិតសាកល្បង',
        content: sampleTable,
        outputPath: testFile.path,
        pageSize: DocxPaperSize.letter,
        orientation: DocxPageOrientation.landscape,
        margin: DocxPageMargin.narrow,
      );

      expect(testFile.existsSync(), isTrue);

      // Unpack docx and inspect word/document.xml
      final bytes = await testFile.readAsBytes();
      final archive = ZipDecoder().decodeBytes(bytes);
      final docXmlFile = archive.findFile('word/document.xml');
      expect(docXmlFile, isNotNull);

      final docXml = utf8.decode(docXmlFile!.content as List<int>);

      // Letter dimensions: 12240 x 15840. In Landscape: w=15840, h=12240
      expect(docXml.contains('w:w="15840" w:h="12240" w:orient="landscape"'), isTrue);

      // Margin narrow = 720 dxa
      expect(docXml.contains('w:top="720" w:right="720" w:bottom="720" w:left="720"'), isTrue);

      // Printable width = 15840 - (720 * 2) = 14400
      expect(docXml.contains('w:tblW w:w="14400" w:type="dxa"'), isTrue);

      // Clean up
      tempDir.deleteSync(recursive: true);
    });

    test('detectFromDimensions classifies standard scanned image (560x794) as A4 Portrait', () {
      final scanned = DocxGeneratorService.detectFromDimensions(560.0, 794.0);
      expect(scanned.paperSize, DocxPaperSize.a4);
      expect(scanned.orientation, DocxPageOrientation.portrait);
    });

    test('generateDocx produces valid ECMA-376 XML with golden divider lines and compact checkboxes', () async {
      final tempDir = Directory.systemTemp.createTempSync('docx_schema_test');
      final testFile = File('${tempDir.path}/test_schema_valid.docx');

      const sampleDoc = '''
VAN VAN CAMBODIA
សំណុំបែបបទស្នើសុំច្បាប់របស់បុគ្គលិក ឬអវត្តមាន និងប្រែប្រួលម៉ោងធ្វើការ
[x] សម្រាកប្រចាំឆ្នាំ (Annual Leave)
[ ] សម្រាកដោយជំងឺ (Sick Leave)
[ ] ច្បាប់អវត្តមានបែប (Forgot FP)
| ឈ្មោះ | ផ្នែក |
| ធី រដ្ឋា | រដ្ឋបាល |
ផ្ទះលេខ 1 A Eo ផ្លូវលេខ 318 សង្កាត់ទួលស្វាយព្រៃ1
''';

      await DocxGeneratorService.generateDocx(
        title: 'ពាក្យសុំច្បាប់',
        content: sampleDoc,
        outputPath: testFile.path,
        pageSize: DocxPaperSize.a4,
        orientation: DocxPageOrientation.portrait,
      );

      expect(testFile.existsSync(), isTrue);

      final bytes = await testFile.readAsBytes();
      final archive = ZipDecoder().decodeBytes(bytes);
      final docXmlFile = archive.findFile('word/document.xml');
      expect(docXmlFile, isNotNull);

      final docXml = utf8.decode(docXmlFile!.content as List<int>);

      // 1. Check Golden Divider Lines (#D97706)
      expect(docXml.contains('w:color="D97706"'), isTrue);

      // 2. Check Compact Checkbox Grid with Ballot Boxes
      expect(docXml.contains('☑'), isTrue);
      expect(docXml.contains('☐'), isTrue);

      // 3. Check that invalid <w:cs/> is NOT present in cell runs
      expect(docXml.contains('<w:cs/>'), isFalse);

      // 4. Verify ECMA-376 schema order: cantSplit before tblHeader
      final cantSplitIdx = docXml.indexOf('<w:cantSplit/>');
      final tblHeaderIdx = docXml.indexOf('<w:tblHeader/>');
      if (cantSplitIdx != -1 && tblHeaderIdx != -1) {
        expect(cantSplitIdx < tblHeaderIdx, isTrue);
      }

      tempDir.deleteSync(recursive: true);
    });
  });
}
