import 'dart:io';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import 'package:image/image.dart' as img;
import 'package:archive/archive.dart';

/// Document Conversion Service supporting Multi-Page Operations:
/// - JPG/PNG to PDF (Multi-page, Zero-margin auto-fit)
/// - PDF to JPG/PNG (Multi-page image rasterization)
/// - Word (.docx) to PDF (Multi-page formatted rendering)
/// - PDF Merge & Compress
class DocumentConversionService {
  /// Convert multiple images to a single high-quality PDF with 100% full bleed (zero white borders)
  static Future<File> convertImagesToPdf({
    required List<String> imagePaths,
    required String outputPath,
    void Function(int current, int total)? onProgress,
  }) async {
    final pdf = pw.Document();

    for (int i = 0; i < imagePaths.length; i++) {
      if (onProgress != null) onProgress(i + 1, imagePaths.length);

      final file = File(imagePaths[i]);
      if (!await file.exists()) continue;

      final bytes = await file.readAsBytes();
      final imageProvider = pw.MemoryImage(bytes);

      // Decode to inspect image dimensions for 100% aspect-ratio matching
      final decoded = img.decodeImage(bytes);
      final int imgW = decoded?.width ?? 1200;
      final int imgH = decoded?.height ?? 1600;
      final bool isLandscape = imgW > imgH;
      final double baseWidth = PdfPageFormat.a4.width;
      final double pageW = isLandscape ? (baseWidth * (imgW / imgH)) : baseWidth;
      final double pageH = isLandscape ? baseWidth : (baseWidth * (imgH / imgW));
      final pageFormat = PdfPageFormat(pageW, pageH, marginAll: 0);

      pdf.addPage(
        pw.Page(
          pageFormat: pageFormat,
          margin: pw.EdgeInsets.zero,
          build: (pw.Context context) {
            return pw.FullPage(
              ignoreMargins: true,
              child: pw.Image(
                imageProvider,
                fit: pw.BoxFit.fill,
                width: pageFormat.width,
                height: pageFormat.height,
              ),
            );
          },
        ),
      );
    }

    final pdfBytes = await pdf.save();
    final outputFile = File(outputPath);
    await outputFile.writeAsBytes(pdfBytes);
    return outputFile;
  }

  /// Convert PDF pages to separate high-definition JPG images (Multi-page)
  static Future<List<String>> convertPdfToImages({
    required String pdfPath,
    required String outputDir,
    void Function(int current, int total)? onProgress,
  }) async {
    final file = File(pdfPath);
    if (!await file.exists()) throw Exception('ឯកសារ PDF មិនមានឡើយ');

    final bytes = await file.readAsBytes();
    final outputImages = <String>[];

    int pageNum = 0;
    await for (final page in Printing.raster(bytes, dpi: 200)) {
      pageNum++;
      if (onProgress != null) onProgress(pageNum, pageNum);

      final imageBytes = await page.toPng();
      final outImagePath = '$outputDir/page_$pageNum.png';
      final outImageFile = File(outImagePath);
      await outImageFile.writeAsBytes(imageBytes);
      outputImages.add(outImagePath);
    }

    return outputImages;
  }

  /// Convert Word (.docx) or Text content to a beautiful multi-page PDF
  static Future<File> convertWordToPdf({
    required String docxOrTextPath,
    required String outputPath,
  }) async {
    final inputFile = File(docxOrTextPath);
    if (!await inputFile.exists()) throw Exception('ឯកសារមិនមានឡើយ');

    String rawText = '';
    if (docxOrTextPath.toLowerCase().endsWith('.docx')) {
      // Unpack docx and extract word/document.xml text
      final bytes = await inputFile.readAsBytes();
      try {
        final archive = ZipDecoder().decodeBytes(bytes);
        final docFile = archive.findFile('word/document.xml');
        if (docFile != null) {
          final xmlStr = String.fromCharCodes(docFile.content as List<int>);
          // Simple XML tag stripper to preserve paragraph text
          rawText = xmlStr
              .replaceAll(RegExp(r'</w:p>'), '\n\n')
              .replaceAll(RegExp(r'<[^>]*>'), ' ')
              .replaceAll(RegExp(r'&amp;'), '&')
              .replaceAll(RegExp(r'&lt;'), '<')
              .replaceAll(RegExp(r'&gt;'), '>')
              .replaceAll(RegExp(r'&quot;'), '"')
              .replaceAll(RegExp(r'&#39;'), "'")
              .replaceAll(RegExp(r' +'), ' ')
              .trim();
        }
      } catch (_) {
        rawText = await inputFile.readAsString();
      }
    } else {
      rawText = await inputFile.readAsString();
    }

    final pdf = pw.Document();
    final lines = rawText.split('\n');

    pdf.addPage(
      pw.MultiPage(
        pageFormat: PdfPageFormat.a4,
        margin: const pw.EdgeInsets.all(36),
        build: (pw.Context context) {
          return lines.map((line) {
            final trimmed = line.trim();
            if (trimmed.isEmpty) {
              return pw.SizedBox(height: 8);
            }
            final isHeading = trimmed.startsWith('#') || trimmed.contains('ព្រះរាជាណាចក្រកម្ពុជា');
            return pw.Padding(
              padding: const pw.EdgeInsets.only(bottom: 4),
              child: pw.Text(
                trimmed.replaceFirst(RegExp(r'^#+\s*'), ''),
                style: pw.TextStyle(
                  fontSize: isHeading ? 14 : 11,
                  fontWeight: isHeading ? pw.FontWeight.bold : pw.FontWeight.normal,
                ),
              ),
            );
          }).toList();
        },
      ),
    );

    final pdfBytes = await pdf.save();
    final outputFile = File(outputPath);
    await outputFile.writeAsBytes(pdfBytes);
    return outputFile;
  }

  /// Compress PDF by rasterizing pages with compressed JPEG quality
  static Future<File> compressPdf({
    required String inputPdfPath,
    required String outputPdfPath,
    int jpegQuality = 75,
    void Function(int current, int total)? onProgress,
  }) async {
    final file = File(inputPdfPath);
    if (!await file.exists()) throw Exception('ឯកសារ PDF មិនមានឡើយ');

    final bytes = await file.readAsBytes();
    final compressedDoc = pw.Document();

    int pageNum = 0;
    await for (final page in Printing.raster(bytes, dpi: 150)) {
      pageNum++;
      if (onProgress != null) onProgress(pageNum, pageNum);

      final pngBytes = await page.toPng();
      final decoded = img.decodeImage(pngBytes);
      if (decoded != null) {
        final compressedJpg = img.encodeJpg(decoded, quality: jpegQuality);
        final imageProvider = pw.MemoryImage(compressedJpg);
        compressedDoc.addPage(
          pw.Page(
            pageFormat: PdfPageFormat(page.width.toDouble(), page.height.toDouble(), marginAll: 0),
            margin: pw.EdgeInsets.zero,
            build: (pw.Context context) {
              return pw.FullPage(
                ignoreMargins: true,
                child: pw.Image(
                  imageProvider,
                  fit: pw.BoxFit.fill,
                ),
              );
            },
          ),
        );
      }
    }

    final compressedBytes = await compressedDoc.save();
    final outFile = File(outputPdfPath);
    await outFile.writeAsBytes(compressedBytes);
    return outFile;
  }

  /// Merge multiple PDF files into one single PDF
  static Future<File> mergePdfs({
    required List<String> pdfPaths,
    required String outputPdfPath,
    void Function(int current, int total)? onProgress,
  }) async {
    final mergedDoc = pw.Document();

    for (int docIdx = 0; docIdx < pdfPaths.length; docIdx++) {
      if (onProgress != null) onProgress(docIdx + 1, pdfPaths.length);

      final file = File(pdfPaths[docIdx]);
      if (!await file.exists()) continue;

      final bytes = await file.readAsBytes();
      await for (final page in Printing.raster(bytes, dpi: 180)) {
        final pngBytes = await page.toPng();
        final imageProvider = pw.MemoryImage(pngBytes);
        mergedDoc.addPage(
          pw.Page(
            pageFormat: PdfPageFormat(page.width.toDouble(), page.height.toDouble(), marginAll: 0),
            margin: pw.EdgeInsets.zero,
            build: (pw.Context context) {
              return pw.FullPage(
                ignoreMargins: true,
                child: pw.Image(imageProvider, fit: pw.BoxFit.fill),
              );
            },
          ),
        );
      }
    }

    final mergedBytes = await mergedDoc.save();
    final outFile = File(outputPdfPath);
    await outFile.writeAsBytes(mergedBytes);
    return outFile;
  }
}
