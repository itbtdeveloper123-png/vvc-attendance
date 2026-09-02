import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';

/// Official Request Form Widget matching table_request.php 100%
/// Displays the full Van Van Cambodia / SK official request paper with header,
/// grid form, signatures, and gold footer address.
class OfficialRequestFormView extends StatelessWidget {
  final Map<String, dynamic> item;
  final double width;
  final bool isPrintMode;

  const OfficialRequestFormView({
    super.key,
    required this.item,
    this.width = 760,
    this.isPrintMode = false,
  });

  static const Color _goldColor = Color(0xFFC59B27);
  static const Color _greenSelected = Color(0xFF10B981);
  static const double _fontSizeLabel = 11.0;
  static const double _fontSizeValue = 11.5;

  @override
  Widget build(BuildContext context) {
    final requestType = (item['request_type'] ?? '').toString();

    final List<String> types = [
      'សម្រាកប្រចាំឆ្នាំ (Annual Leave)',
      'សម្រាកដោយជំងឺ (Sick Leave)',
      'ភ្លេចស្កេនមេដៃ (Forgot FP)',
      'សម្រាកលំហែមាតុភាព (Maternity Leave)',
      'ថែមម៉ោង (OT)',
      'ចេញមុនម៉ោង (Early)',
      'ប្តូរថ្ងៃសម្រាក (Changing day off)',
      'សម្រាកពិសេស (Special Leave)',
      'មកយឺត (Late)',
    ];

    bool isTypeSelected(String typeLabel) {
      final req = requestType.toLowerCase().trim();
      if (req.isEmpty) return false;

      if (req.contains('leave') || req.contains('ច្បាប់') || req.contains('សម្រាក')) {
        if (req.contains('annual') || req.contains('ប្រចាំឆ្នាំ')) return typeLabel.contains('Annual Leave');
        if (req.contains('sick') || req.contains('ជំងឺ')) return typeLabel.contains('Sick Leave');
        if (req.contains('maternity') || req.contains('បុត្រភាព') || req.contains('មាតុភាព')) return typeLabel.contains('Maternity Leave');
        if (req.contains('special') || req.contains('ពិសេស')) return typeLabel.contains('Special Leave');
      }
      if (req.contains('forgot') || req.contains('ស្កេន') || req.contains('មេដៃ') || req.contains('fp')) {
        return typeLabel.contains('Forgot FP');
      }
      if (req.contains('ot') || req.contains('ថែមម៉ោង')) {
        return typeLabel.contains('OT');
      }
      if (req.contains('early') || req.contains('ចេញមុន')) {
        return typeLabel.contains('Early');
      }
      if (req.contains('late') || req.contains('យឺត')) {
        return typeLabel.contains('Late');
      }
      if (req.contains('change') || req.contains('ប្តូរ')) {
        return typeLabel.contains('Changing day off');
      }
      final target = typeLabel.toLowerCase().trim();
      return target.contains(req) || req.contains(target);
    }

    String formatBranch(String? raw) {
      if (raw == null || raw.trim().isEmpty) return 'ការិយាល័យកណ្តាល';
      final s = raw.trim().toUpperCase();
      if (s == 'VVC_HQ' || s == 'VVC-HQ' || s == 'VVC HQ' || s == 'HQ' || s == 'HEAD OFFICE') {
        return 'ការិយាល័យកណ្តាល';
      }
      return raw;
    }

    String formatD(String? d) {
      if (d == null || d.isEmpty || d == 'N/A') return 'N/A';
      try {
        return DateFormat('dd-MM-yyyy').format(DateTime.parse(d));
      } catch (_) {
        return d;
      }
    }

    String formatT(String? t) {
      if (t == null || t.isEmpty || t == 'N/A') return 'N/A';
      try {
        DateTime? dt;
        if (t.contains('T') || t.contains('-')) {
          dt = DateTime.parse(t);
        } else if (t.contains(':')) {
          final parts = t.split(':');
          dt = DateTime(2000, 1, 1, int.parse(parts[0]), int.parse(parts[1]));
        }
        if (dt != null) {
          return DateFormat('HH:mm').format(dt);
        }
        return t;
      } catch (_) {
        return t;
      }
    }

    String formatP(String? p) {
      if (p == null || p.isEmpty || p == 'N/A') return 'N/A';
      String cleaned = p.replaceAll(RegExp(r'\D'), '');
      if (cleaned.length == 9) {
        return '${cleaned.substring(0, 3)} ${cleaned.substring(3, 6)} ${cleaned.substring(6)}';
      } else if (cleaned.length == 10) {
        return '${cleaned.substring(0, 3)} ${cleaned.substring(3, 7)} ${cleaned.substring(7)}';
      }
      return p;
    }

    // Process base64 signatures
    Uint8List? reqSigBytes;
    if (item['signature'] != null && item['signature'].toString().startsWith('data:image')) {
      try {
        reqSigBytes = base64.decode(item['signature'].split(',').last);
      } catch (_) {}
    }

    Uint8List? deptSigBytes;
    if (item['department_head_signature'] != null &&
        item['department_head_signature'].toString().startsWith('data:image')) {
      try {
        deptSigBytes = base64.decode(item['department_head_signature'].split(',').last);
      } catch (_) {}
    }

    return Container(
      width: width,
      color: Colors.white,
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        mainAxisSize: MainAxisSize.min,
        children: [
          // ================= 1. HEADER =================
          Center(
            child: Image.network(
              'https://i.ibb.co/r2JWnd2x/Logo-Van-Van-1.png',
              width: 210,
              height: 65,
              fit: BoxFit.contain,
              errorBuilder: (_, __, ___) => Column(
                children: [
                  const Icon(Icons.spa_rounded, color: _goldColor, size: 36),
                  Text(
                    'វ៉ាន់ វ៉ាន់ ខេមបូឌា',
                    style: GoogleFonts.kantumruyPro(
                      color: _goldColor,
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  Text(
                    'VAN VAN CAMBODIA',
                    style: GoogleFonts.outfit(
                      color: _goldColor,
                      fontSize: 11,
                      letterSpacing: 1.5,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 6),

          // Top Gold Line
          Container(
            height: 2.5,
            color: _goldColor,
            margin: const EdgeInsets.only(bottom: 8),
          ),

          // Title
          Text(
            'សំណើសុំច្បាប់ឈប់សម្រាក ប្តូរវេន ចេញមុនម៉ោង មកយឺត និងភ្លេចស្កេនមេដៃវត្តមាន',
            textAlign: TextAlign.center,
            style: GoogleFonts.kantumruyPro(
              fontSize: 14.5,
              fontWeight: FontWeight.bold,
              color: Colors.black,
              letterSpacing: 0.2,
            ),
          ),
          const SizedBox(height: 10),

          // ================= 2. MAIN FORM BOX =================
          Container(
            decoration: BoxDecoration(
              border: Border.all(color: Colors.black, width: 2.0),
              borderRadius: BorderRadius.circular(2),
            ),
            padding: const EdgeInsets.all(10),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Request Type Pills Box
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                  decoration: BoxDecoration(
                    color: const Color(0xFFF8FAFC),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: const Color(0xFFE2E8F0)),
                  ),
                  child: Center(
                    child: Wrap(
                      spacing: 8,
                      runSpacing: 6,
                      alignment: WrapAlignment.center,
                      children: types.map((t) {
                        final isSel = isTypeSelected(t);
                        return Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                          decoration: BoxDecoration(
                            color: isSel ? _greenSelected : Colors.white,
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(
                              color: isSel ? _greenSelected : const Color(0xFFCBD5E1),
                              width: 1,
                            ),
                            boxShadow: isSel
                                ? [BoxShadow(color: _greenSelected.withValues(alpha: 0.3), blurRadius: 4)]
                                : null,
                          ),
                          child: Text(
                            t,
                            style: GoogleFonts.kantumruyPro(
                              fontSize: 9.5,
                              color: isSel ? Colors.white : const Color(0xFF64748B),
                              fontWeight: isSel ? FontWeight.bold : FontWeight.normal,
                            ),
                          ),
                        );
                      }).toList(),
                    ),
                  ),
                ),
                const SizedBox(height: 12),

                // Details Grid Table
                Table(
                  border: TableBorder.all(color: Colors.black, width: 1.2),
                  columnWidths: const {
                    0: FlexColumnWidth(1.2), // Label 1
                    1: FlexColumnWidth(1.4), // Value 1
                    2: FlexColumnWidth(1.2), // Label 2
                    3: FlexColumnWidth(0.7), // Value 2a
                    4: FlexColumnWidth(0.7), // Value 2b
                  },
                  children: [
                    // Row 1: Name, Remaining days
                    _buildRow([
                      _cellText('ឈ្មោះអ្នកស្នើសុំ៖', isLabel: true),
                      _cellText(item['requester_name'] ?? 'N/A'),
                      _cellText('ចំនួនថ្ងៃ/ច្បាប់នៅសល់៖', isLabel: true),
                      _cellText('${item['number_of_days'] ?? '0'} ថ្ងៃ', align: TextAlign.center),
                      _cellText('${item['remaining_days'] ?? 'N/A'} ថ្ងៃ', align: TextAlign.center),
                    ]),

                    // Row 2: Department, Position, Branch
                    _buildRow([
                      _cellText('ផ្នែក/មុខតំណែង/សាខា៖', isLabel: true),
                      _cellText(item['department'] ?? 'N/A'),
                      _cellText(item['position'] ?? 'N/A'),
                      _cellText(formatBranch(item['branch']?.toString()), colSpan: 2, align: TextAlign.center),
                    ]),

                    // Row 3: Request Date, Late hours
                    _buildRow([
                      _cellText('ថ្ងៃខែឆ្នាំសុំឈប់៖', isLabel: true),
                      _cellText(formatD(item['request_date'])),
                      _cellText('ចំនួនម៉ោងយឺត/ចេញមុន៖', isLabel: true),
                      _cellText(item['late_hours']?.toString() ?? 'N/A', colSpan: 2, align: TextAlign.center),
                    ]),

                    // Row 4: Return Date, Forgot scan
                    _buildRow([
                      _cellText('ថ្ងៃចូលធ្វើការវិញ/ថ្ងៃសងវិញ៖', isLabel: true),
                      _cellText(formatD(item['return_date'])),
                      _cellText('ភ្លេចស្កេនមេដៃ៖', isLabel: true),
                      _cellText(item['forgot_scan_in']?.toString() ?? 'N/A', align: TextAlign.center),
                      _cellText(item['forgot_scan_out']?.toString() ?? 'N/A', align: TextAlign.center),
                    ]),

                    // Row 5: Work hours
                    _buildRow([
                      _cellText('ម៉ោងចេញចូល(ការងារ)៖', isLabel: true),
                      _cellText('ម៉ោងចូល៖  ${formatT(item['time_in'])}'),
                      _cellText('ម៉ោងចេញ៖  ${formatT(item['time_out'])}'),
                      _cellText('ម៉ោងសរុប៖  ${item['total_hours'] ?? 'N/A'}', colSpan: 2, align: TextAlign.center),
                    ]),

                    // Row 6: Repay work hours
                    _buildRow([
                      _cellText('ម៉ោងធ្វើការសងវិញ៖', isLabel: true),
                      _cellText('ម៉ោងចូលសង៖ ${formatT(item['repay_time_in'])}'),
                      _cellText('ម៉ោងចេញសង៖ ${formatT(item['repay_time_out'])}'),
                      _cellText('ម៉ោងសងសរុប៖ ${item['repay_total_hours'] ?? 'N/A'}', colSpan: 2, align: TextAlign.center),
                    ]),

                    // Row 7: Reason
                    _buildRow([
                      _cellText('មូលហេតុ៖', isLabel: true),
                      _cellText(item['reason'] ?? 'N/A', colSpan: 4),
                    ]),

                    // Row 8: Location
                    _buildRow([
                      _cellText('ទីកន្លែងអំឡុងពេលឈប់៖', isLabel: true),
                      _cellText(item['location'] ?? 'N/A', colSpan: 4),
                    ]),

                    // Row 9: Contact & Assignment
                    _buildRow([
                      _cellText('លេខទំនាក់ទំនងបន្ទាន់៖', isLabel: true),
                      _cellText(formatP(item['contact_number'])),
                      _cellText('ប្រគល់ការងារឱ្យ៖', isLabel: true),
                      _cellText(item['assigned_to'] ?? 'N/A', colSpan: 2, align: TextAlign.center),
                    ]),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 18),

          // ================= 3. SIGNATURES TABLE =================
          Table(
            border: TableBorder.all(color: Colors.black, width: 1.2),
            columnWidths: const {
              0: FlexColumnWidth(1.2), // Approver title
              1: FlexColumnWidth(1.2), // Name
              2: FlexColumnWidth(1.6), // Signature Image / Underline
              3: FlexColumnWidth(1.1), // Date
            },
            children: [
              // Header Row
              TableRow(
                decoration: const BoxDecoration(color: Color(0xFFF1F5F9)),
                children: [
                  _headerCell('បញ្ជាក់/អនុម័តដោយ'),
                  _headerCell('ឈ្មោះ (Name)'),
                  _headerCell('ហត្ថលេខា (Signature)'),
                  _headerCell('ថ្ងៃខែឆ្នាំ (Date)'),
                ],
              ),

              // 1. Requester
              _signatureTableRow(
                title: 'អ្នកស្នើសុំ',
                name: item['requester_name'] ?? '',
                sigBytes: reqSigBytes,
                date: formatD(item['signature_date'] ?? item['request_date']),
              ),

              // 2. Department Head
              _signatureTableRow(
                title: 'ប្រធានផ្នែក',
                name: item['department_head_name'] ?? '',
                sigBytes: deptSigBytes,
                date: formatD(item['department_head_signature_date']),
              ),

              // 3. HR Manager
              _signatureTableRow(
                title: 'ប្រធានធនធានមនុស្ស',
                name: '',
                sigBytes: null,
                date: '',
              ),

              // 4. General Manager
              _signatureTableRow(
                title: 'ប្រធានគ្រប់គ្រងទូទៅ',
                name: '',
                sigBytes: null,
                date: '',
              ),

              // 5. CEO / Directress
              _signatureTableRow(
                title: 'អគ្គនាយិកា',
                name: '',
                sigBytes: null,
                date: '',
              ),
            ],
          ),
          const SizedBox(height: 14),

          // ================= 4. FOOTER =================
          Container(
            height: 2.5,
            color: _goldColor,
            margin: const EdgeInsets.only(bottom: 6),
          ),
          Text(
            'ផ្ទះលេខ 1 AEo ផ្លូវលេខ 318 សង្កាត់ ទួលស្វាយព្រៃ១ ខណ្ឌ បឹងកេងកង រាជធានីភ្នំពេញ ព្រះរាជាណាចក្រកម្ពុជា ទូរស័ព្ទលេខ 015 971 961 - 085 971 961',
            textAlign: TextAlign.center,
            style: GoogleFonts.kantumruyPro(
              fontSize: 8.5,
              fontWeight: FontWeight.bold,
              color: const Color(0xFF996515),
              height: 1.3,
            ),
          ),
          Text(
            'No.1AEo, St.318, Sangkat Tuol Svay Prey1, Khan Boeng Keng Kang, Phnom Penh, Cambodia. Tel: 015 971 961 - 085 971 961',
            textAlign: TextAlign.center,
            style: GoogleFonts.outfit(
              fontSize: 8.5,
              color: const Color(0xFF996515),
              height: 1.3,
            ),
          ),
        ],
      ),
    );
  }

  static TableRow _buildRow(List<_TableCellData> cells) {
    List<Widget> rowChildren = [];
    for (final cell in cells) {
      if (cell.colSpan > 1) {
        // Expand width visually by adding container or flex
        rowChildren.add(
          TableCell(
            child: cell.widget,
          ),
        );
        for (int i = 1; i < cell.colSpan; i++) {
          rowChildren.add(const SizedBox.shrink());
        }
      } else {
        rowChildren.add(cell.widget);
      }
    }

    // Ensure row has exactly 5 children
    while (rowChildren.length < 5) {
      rowChildren.add(const SizedBox.shrink());
    }

    return TableRow(children: rowChildren.take(5).toList());
  }

  static _TableCellData _cellText(
    String text, {
    bool isLabel = false,
    int colSpan = 1,
    TextAlign align = TextAlign.left,
  }) {
    final widget = Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
      child: Text(
        text,
        textAlign: align,
        style: GoogleFonts.kantumruyPro(
          fontSize: isLabel ? _fontSizeLabel : _fontSizeValue,
          fontWeight: isLabel ? FontWeight.bold : FontWeight.normal,
          color: Colors.black,
        ),
      ),
    );
    return _TableCellData(widget: widget, colSpan: colSpan);
  }

  static Widget _headerCell(String text) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 8),
      child: Center(
        child: Text(
          text,
          textAlign: TextAlign.center,
          style: GoogleFonts.kantumruyPro(
            fontSize: _fontSizeLabel,
            fontWeight: FontWeight.bold,
            color: const Color(0xFF334155),
          ),
        ),
      ),
    );
  }

  static TableRow _signatureTableRow({
    required String title,
    required String name,
    required Uint8List? sigBytes,
    required String date,
  }) {
    return TableRow(
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
          child: Text(
            title,
            style: GoogleFonts.kantumruyPro(
              fontSize: _fontSizeLabel,
              fontWeight: FontWeight.bold,
              color: Colors.black,
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
          child: Center(
            child: Text(
              name,
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                fontSize: _fontSizeValue,
                color: Colors.black,
              ),
            ),
          ),
        ),
        Container(
          height: 52,
          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
          child: sigBytes != null
              ? Image.memory(sigBytes, fit: BoxFit.contain)
              : Center(
                  child: Container(
                    width: 100,
                    height: 1.0,
                    color: Colors.black26,
                  ),
                ),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
          child: Center(
            child: Text(
              date,
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(
                fontSize: _fontSizeValue,
                color: Colors.black,
              ),
            ),
          ),
        ),
      ],
    );
  }
}

class _TableCellData {
  final Widget widget;
  final int colSpan;

  const _TableCellData({
    required this.widget,
    this.colSpan = 1,
  });
}
