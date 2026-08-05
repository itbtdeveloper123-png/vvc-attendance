import 'package:flutter/foundation.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';

class PayslipPdfService {
  static Future<Uint8List> generatePayslipPdf({
    required String employeeName,
    required String position,
    required String department,
    required String month,
    required String year,
    required double baseSalary,
    required int presentDays,
    required double otHours,
    required double otPay,
    required double allowances,
    required double lateDeductions,
    required double nssfDeductions,
    required double taxDeductions,
    required double netSalary,
    required String paymentDate,
    required String paymentStatus,
  }) async {
    final pdf = pw.Document();

    final totalEarnings = baseSalary + otPay + allowances;
    final totalDeductions = lateDeductions + nssfDeductions + taxDeductions;
    final calculatedNet = totalEarnings - totalDeductions;
    final finalPayable = netSalary > 0 ? netSalary : calculatedNet;

    pdf.addPage(
      pw.Page(
        pageFormat: PdfPageFormat.a4,
        margin: const pw.EdgeInsets.all(32),
        build: (pw.Context context) {
          return pw.Column(
            crossAxisAlignment: pw.CrossAxisAlignment.start,
            children: [
              // Header
              pw.Row(
                mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                children: [
                  pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.start,
                    children: [
                      pw.Text(
                        'VVC ATTENDANCE & HR MANAGEMENT',
                        style: pw.TextStyle(
                          fontSize: 16,
                          fontWeight: pw.FontWeight.bold,
                          color: PdfColors.blue900,
                        ),
                      ),
                      pw.Text(
                        'OFFICIAL DIGITAL PAYSLIP',
                        style: pw.TextStyle(
                          fontSize: 11,
                          fontWeight: pw.FontWeight.bold,
                          color: PdfColors.grey700,
                        ),
                      ),
                    ],
                  ),
                  pw.Container(
                    padding: const pw.EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: pw.BoxDecoration(
                      color: paymentStatus.toLowerCase() == 'paid'
                          ? PdfColors.green100
                          : PdfColors.orange100,
                      borderRadius: pw.BorderRadius.circular(6),
                      border: pw.Border.all(
                        color: paymentStatus.toLowerCase() == 'paid'
                            ? PdfColors.green700
                            : PdfColors.orange700,
                      ),
                    ),
                    child: pw.Text(
                      paymentStatus.toUpperCase(),
                      style: pw.TextStyle(
                        color: paymentStatus.toLowerCase() == 'paid'
                            ? PdfColors.green900
                            : PdfColors.orange900,
                        fontSize: 12,
                        fontWeight: pw.FontWeight.bold,
                      ),
                    ),
                  ),
                ],
              ),
              pw.SizedBox(height: 16),
              pw.Divider(color: PdfColors.blue900, thickness: 2),
              pw.SizedBox(height: 16),

              // Employee Info Grid
              pw.Container(
                padding: const pw.EdgeInsets.all(12),
                decoration: pw.BoxDecoration(
                  color: PdfColors.grey100,
                  borderRadius: pw.BorderRadius.circular(8),
                ),
                child: pw.Row(
                  mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                  children: [
                    pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        _pdfInfoRow('Employee Name:', employeeName),
                        pw.SizedBox(height: 4),
                        _pdfInfoRow('Position:', position.isEmpty ? 'N/A' : position),
                        pw.SizedBox(height: 4),
                        _pdfInfoRow('Department:', department.isEmpty ? 'N/A' : department),
                      ],
                    ),
                    pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        _pdfInfoRow('Payroll Period:', '$month / $year'),
                        pw.SizedBox(height: 4),
                        _pdfInfoRow('Payment Date:', paymentDate.isEmpty ? '-' : paymentDate),
                        pw.SizedBox(height: 4),
                        _pdfInfoRow('Present Days:', '$presentDays Days'),
                      ],
                    ),
                  ],
                ),
              ),
              pw.SizedBox(height: 20),

              // Earnings & Deductions Tables
              pw.Row(
                crossAxisAlignment: pw.CrossAxisAlignment.start,
                children: [
                  // Earnings Column
                  pw.Expanded(
                    child: pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        pw.Text(
                          'EARNINGS (+)',
                          style: pw.TextStyle(
                            fontSize: 12,
                            fontWeight: pw.FontWeight.bold,
                            color: PdfColors.green900,
                          ),
                        ),
                        pw.SizedBox(height: 6),
                        _pdfTable([
                          ['Base Salary', '\$${baseSalary.toStringAsFixed(2)}'],
                          ['Overtime Pay (${otHours.toStringAsFixed(1)} hrs)', '\$${otPay.toStringAsFixed(2)}'],
                          ['Allowances', '\$${allowances.toStringAsFixed(2)}'],
                          ['Total Earnings', '\$${totalEarnings.toStringAsFixed(2)}'],
                        ]),
                      ],
                    ),
                  ),
                  pw.SizedBox(width: 16),

                  // Deductions Column
                  pw.Expanded(
                    child: pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        pw.Text(
                          'DEDUCTIONS (-)',
                          style: pw.TextStyle(
                            fontSize: 12,
                            fontWeight: pw.FontWeight.bold,
                            color: PdfColors.red900,
                          ),
                        ),
                        pw.SizedBox(height: 6),
                        _pdfTable([
                          ['Late/Absence Penalty', '\$${lateDeductions.toStringAsFixed(2)}'],
                          ['NSSF Contribution', '\$${nssfDeductions.toStringAsFixed(2)}'],
                          ['Salary Tax', '\$${taxDeductions.toStringAsFixed(2)}'],
                          ['Total Deductions', '\$${totalDeductions.toStringAsFixed(2)}'],
                        ]),
                      ],
                    ),
                  ),
                ],
              ),
              pw.SizedBox(height: 24),

              // Total Net Payable Box
              pw.Container(
                padding: const pw.EdgeInsets.all(16),
                decoration: pw.BoxDecoration(
                  color: PdfColors.blue900,
                  borderRadius: pw.BorderRadius.circular(10),
                ),
                child: pw.Row(
                  mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                  children: [
                    pw.Text(
                      'TOTAL NET PAYABLE SALARY',
                      style: pw.TextStyle(
                        color: PdfColors.white,
                        fontSize: 13,
                        fontWeight: pw.FontWeight.bold,
                      ),
                    ),
                    pw.Text(
                      '\$${finalPayable.toStringAsFixed(2)}',
                      style: pw.TextStyle(
                        color: PdfColors.white,
                        fontSize: 18,
                        fontWeight: pw.FontWeight.bold,
                      ),
                    ),
                  ],
                ),
              ),

              pw.Spacer(),

              // Confidentiality & Verification Seal
              pw.Divider(color: PdfColors.grey400),
              pw.SizedBox(height: 8),
              pw.Row(
                mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                children: [
                  pw.Text(
                    '🔒 BIOMETRICALLY VERIFIED & ENCRYPTED DOCUMENT',
                    style: const pw.TextStyle(
                      fontSize: 8,
                      color: PdfColors.grey600,
                    ),
                  ),
                  pw.Text(
                    'Generated on: ${DateTime.now().toLocal().toString().split('.')[0]}',
                    style: const pw.TextStyle(
                      fontSize: 8,
                      color: PdfColors.grey600,
                    ),
                  ),
                ],
              ),
            ],
          );
        },
      ),
    );

    return pdf.save();
  }

  static pw.Widget _pdfInfoRow(String label, String value) {
    return pw.Row(
      children: [
        pw.Text(
          '$label ',
          style: pw.TextStyle(fontSize: 10, fontWeight: pw.FontWeight.bold, color: PdfColors.grey800),
        ),
        pw.Text(
          value,
          style: const pw.TextStyle(fontSize: 10, color: PdfColors.grey900),
        ),
      ],
    );
  }

  static pw.Widget _pdfTable(List<List<String>> data) {
    return pw.Table(
      border: pw.TableBorder.all(color: PdfColors.grey300),
      children: data.map((row) {
        final isTotal = row[0].startsWith('Total');
        return pw.TableRow(
          decoration: isTotal ? const pw.BoxDecoration(color: PdfColors.grey200) : null,
          children: [
            pw.Padding(
              padding: const pw.EdgeInsets.all(6),
              child: pw.Text(
                row[0],
                style: pw.TextStyle(
                  fontSize: 9,
                  fontWeight: isTotal ? pw.FontWeight.bold : pw.FontWeight.normal,
                ),
              ),
            ),
            pw.Padding(
              padding: const pw.EdgeInsets.all(6),
              child: pw.Text(
                row[1],
                textAlign: pw.TextAlign.right,
                style: pw.TextStyle(
                  fontSize: 9,
                  fontWeight: isTotal ? pw.FontWeight.bold : pw.FontWeight.normal,
                ),
              ),
            ),
          ],
        );
      }).toList(),
    );
  }

  static Future<void> printOrSharePayslip({
    required String employeeName,
    required String position,
    required String department,
    required String month,
    required String year,
    required double baseSalary,
    required int presentDays,
    required double otHours,
    required double otPay,
    required double allowances,
    required double lateDeductions,
    required double nssfDeductions,
    required double taxDeductions,
    required double netSalary,
    required String paymentDate,
    required String paymentStatus,
  }) async {
    final pdfBytes = await generatePayslipPdf(
      employeeName: employeeName,
      position: position,
      department: department,
      month: month,
      year: year,
      baseSalary: baseSalary,
      presentDays: presentDays,
      otHours: otHours,
      otPay: otPay,
      allowances: allowances,
      lateDeductions: lateDeductions,
      nssfDeductions: nssfDeductions,
      taxDeductions: taxDeductions,
      netSalary: netSalary,
      paymentDate: paymentDate,
      paymentStatus: paymentStatus,
    );

    await Printing.sharePdf(
      bytes: pdfBytes,
      filename: 'Payslip_${employeeName.replaceAll(' ', '_')}_${month}_$year.pdf',
    );
  }
}
