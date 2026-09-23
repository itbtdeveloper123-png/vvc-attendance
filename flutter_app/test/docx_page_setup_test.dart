import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
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

    test('generateDocx formats CV / Resume with navy section banners, photo table, and bullets', () async {
      final tempDir = Directory.systemTemp.createTempSync('docx_cv_test');
      final testFile = File('${tempDir.path}/test_cv.docx');

      const cvContent = '''
# ប្រវត្តិរូបសង្ខេប
នាម-គោត្តនាម : វៃ រតនៈ
អាសយដ្ឋានបច្ចុប្បន្ន : ផ្លូវ សុភារុង ១០៧ សង្កាត់អូរឫស្សីទី២ ខណ្ឌ ៧មករា រាជធានីភ្នំពេញ
ទូរស័ព្ទទំនាក់ទំនង : 096 4677459 @vairothnak
[PHOTO]
---
## [BANNER] ព័ត៌មានផ្ទាល់ខ្លួននិងទីកន្លែងរស់នៅ
• ឈ្មោះ (ឡាតាំង) : VAI ROTHNAK
• ភេទ : ប្រុស
• សញ្ជាតិ : ខ្មែរ
• ថ្ងៃ ខែ ឆ្នាំកំណើត : ០៧ តុលា ២០០៤
• ទីកន្លែងកំណើត : ភូមិថ្មី ឃុំពាមមានជ័យ ស្រុកពាមរក៍ ខេត្តព្រៃវែង
• ស្ថានភាពគ្រួសារ : នៅលីវ
## [BANNER] ប្រវត្តិសិក្សានិងកម្រិតសិក្សា
• ២០២៣-២០២៤ : វិទ្យាល័យ ហាស ពាមរក៍ ( ត្រឹមថ្នាក់ទី ១០ )
• ២០២២-២០២៤ : TASSEL Cambodia ( English Level 3 )
## [BANNER] ប្រវត្តិការងារនិងបទពិសោធន៍ការងារ
• ២០២៤-២០២៦ : គ្មាន
• ២០២២-២០២៤ : គ្មាន
## [BANNER] ជំនាញផ្ទាល់ខ្លួននិងជំនាញផ្សេងៗ
• Microsoft word : ល្អបង្គួរ
• Microsoft excel : មធ្យម
• Computer : ល្អបង្គួរ
• Contact & Teamwork : ល្អ
• Designer Adobbe PS : មិនទាន់ល្អ
''';

      await DocxGeneratorService.generateDocx(
        title: 'ប្រវត្តិរូបសង្ខេប',
        content: cvContent,
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

      // 1. Verify Navy banner shading exists (w:fill="184E77")
      expect(docXml.contains('w:fill="184E77"'), isTrue);

      // 2. Verify white text for banner headings
      expect(docXml.contains('w:color w:val="FFFFFF"'), isTrue);

      // 3. Verify 2-column header profile table with photo frame
      expect(docXml.contains('រូបថត 3x4'), isTrue);
      expect(docXml.contains('វៃ រតនៈ'), isTrue);

      // 4. Verify bullet items generated with bullets
      expect(docXml.contains('•'), isTrue);
      // 5. Verify title deduplication (appears exactly ONCE in document.xml)
      final titleMatches = RegExp(r'<w:t[^>]*>ប្រវត្តិរូបសង្ខេប</w:t>').allMatches(docXml);
      expect(titleMatches.length, 1);

      // 6. Verify docGrid is NOT present
      expect(docXml.contains('<w:docGrid'), isFalse);

      tempDir.deleteSync(recursive: true);
    });

    test('generateDocx embeds real candidate photo into OpenXML archive and DrawingML', () async {
      final tempDir = Directory.systemTemp.createTempSync('docx_photo_test');
      final testFile = File('${tempDir.path}/test_cv_with_photo.docx');

      const cvContent = '''
# ប្រវត្តិរូបសង្ខេប
នាម-គោត្តនាម : វ៉ៃ រតនៈ
អាសយដ្ឋានបច្ចុប្បន្ន : ភ្នំពេញ
ទូរស័ព្ទទំនាក់ទំនង : 096 4677459
[PHOTO]
---
## [BANNER] ព័ត៌មានផ្ទាល់ខ្លួន
• ឈ្មោះ (ឡាតាំង) : VAI ROTHNAK
''';

      final dummyPhotoBytes = Uint8List.fromList(List.generate(100, (i) => i % 256));

      await DocxGeneratorService.generateDocx(
        title: 'ប្រវត្តិរូបសង្ខេប',
        content: cvContent,
        outputPath: testFile.path,
        photoBytes: dummyPhotoBytes,
        pageSize: DocxPaperSize.a4,
        orientation: DocxPageOrientation.portrait,
      );

      expect(testFile.existsSync(), isTrue);

      final bytes = await testFile.readAsBytes();
      final archive = ZipDecoder().decodeBytes(bytes);

      // 1. Verify photo media file exists inside the docx ZIP
      final photoMedia = archive.findFile('word/media/photo1.jpg');
      expect(photoMedia, isNotNull);
      expect(photoMedia!.content.length, dummyPhotoBytes.length);

      // 2. Verify relationships file links photo
      final relsFile = archive.findFile('word/_rels/document.xml.rels');
      expect(relsFile, isNotNull);
      final relsXml = utf8.decode(relsFile!.content as List<int>);
      expect(relsXml.contains('Id="rIdPhoto1"'), isTrue);
      expect(relsXml.contains('Target="media/photo1.jpg"'), isTrue);

      // 3. Verify document.xml contains DrawingML with rIdPhoto1 and no "រូបថត 3x4" placeholder
      final docXmlFile = archive.findFile('word/document.xml');
      expect(docXmlFile, isNotNull);
      final docXml = utf8.decode(docXmlFile!.content as List<int>);
      expect(docXml.contains('<w:drawing>'), isTrue);
      expect(docXml.contains('r:embed="rIdPhoto1"'), isTrue);
      expect(docXml.contains('រូបថត 3x4'), isFalse);

      tempDir.deleteSync(recursive: true);
    });
  });
}

