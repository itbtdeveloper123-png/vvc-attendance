import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';

/// Official A5 Request Form Widget matching table_request.php 100%
/// Formatted strictly for A5 Paper (148mm x 210mm) with complete header,
/// full 5-column request table, 4-column signature section, and gold footer address.
class OfficialRequestFormView extends StatelessWidget {
  final Map<String, dynamic> item;
  final double width;
  final bool isPrintMode;

  const OfficialRequestFormView({
    super.key,
    required this.item,
    this.width = 580, // Default width optimized for A5 ratio (1:1.414)
    this.isPrintMode = false,
  });

  static const Color _goldColor = Color(0xFFC59B27);
  static const Color _greenSelected = Color(0xFF059669);
  static const Color _greenSelectedBorder = Color(0xFF047857);
  static const double _fontSizeLabel = 10.0;
  static const double _fontSizeValue = 10.5;

  @override
  Widget build(BuildContext context) {
    final rawType = (item['request_type'] ?? item['type'] ?? '').toString().trim().toLowerCase();
    final rawReason = (item['reason'] ?? item['leave_reason'] ?? item['ot_reason'] ?? '').toString().trim().toLowerCase();

    final leaveType = (item['leave_type'] ?? '').toString().trim().toLowerCase();

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

    // Determine the single mutually exclusive canonical request type
    String determineCanonicalType() {
      // 1. Overtime (OT / ថែមម៉ោង) - Highest Priority
      if (rawType == 'overtime' ||
          rawType == 'ot' ||
          rawType == 'ថែមម៉ោង' ||
          rawType.contains('overtime') ||
          rawType.contains('ot') ||
          rawType.contains('ថែម') ||
          rawReason.contains('overtime') ||
          rawReason.contains('ថែមម៉ោង')) {
        return 'ថែមម៉ោង (OT)';
      }

      // 2. Changing day off (ប្តូរថ្ងៃសម្រាក / ប្តូរវេន)
      if (rawType.contains('change') ||
          rawType.contains('ប្តូរ') ||
          rawReason.contains('ប្តូរវេន') ||
          rawReason.contains('ប្តូរថ្ងៃ')) {
        return 'ប្តូរថ្ងៃសម្រាក (Changing day off)';
      }

      // 3. Late (មកយឺត)
      if (rawType == 'late' ||
          rawType.contains('late') ||
          rawType.contains('យឺត') ||
          rawReason.contains('មកយឺត')) {
        return 'មកយឺត (Late)';
      }

      // 4. Early (ចេញមុនម៉ោង)
      if (rawType == 'early' ||
          rawType.contains('early') ||
          rawType.contains('ចេញមុន') ||
          rawReason.contains('ចេញមុន')) {
        return 'ចេញមុនម៉ោង (Early)';
      }

      // 5. Forgot Scan / FP (ភ្លេចស្កេនមេដៃ)
      // Strictly checked ONLY if the request is genuinely about attendance/scan forgetfulness
      if (rawType.contains('forget') ||
          rawType.contains('forgot') ||
          rawType.contains('ភ្លេច') ||
          rawReason.contains('ភ្លេចស្កេន') ||
          rawReason.contains('ភ្លេចមេដៃ') ||
          ((item['forgot_scan_in']?.toString().toLowerCase() == 'yes' ||
            item['forgot_scan_out']?.toString().toLowerCase() == 'yes') &&
           !rawType.contains('leave') &&
           !rawType.contains('ច្បាប់'))) {
        return 'ភ្លេចស្កេនមេដៃ (Forgot FP)';
      }

      // 6. Sick Leave (សម្រាកដោយជំងឺ)
      if (rawType.contains('sick') ||
          leaveType.contains('sick') ||
          rawType.contains('ជំងឺ') ||
          rawReason.contains('ជំងឺ') ||
          rawReason.contains('ឈឺ')) {
        return 'សម្រាកដោយជំងឺ (Sick Leave)';
      }

      // 7. Maternity Leave (សម្រាកលំហែមាតុភាព)
      if (rawType.contains('maternity') ||
          leaveType.contains('maternity') ||
          rawType.contains('មាតុភាព') ||
          rawReason.contains('មាតុភាព') ||
          rawReason.contains('បុត្រ') ||
          rawReason.contains('សម្រាល')) {
        return 'សម្រាកលំហែមាតុភាព (Maternity Leave)';
      }

      // 8. Special Leave (សម្រាកពិសេស)
      if (rawType.contains('special') ||
          leaveType.contains('special') ||
          rawType.contains('ពិសេស') ||
          rawReason.contains('ពិសេស')) {
        return 'សម្រាកពិសេស (Special Leave)';
      }

      // 9. Annual Leave (សម្រាកប្រចាំឆ្នាំ)
      if (rawType.contains('annual') ||
          rawType.contains('ប្រចាំឆ្នាំ') ||
          rawType.contains('leave') ||
          rawType.contains('ច្បាប់') ||
          rawType.contains('សម្រាក')) {
        return 'សម្រាកប្រចាំឆ្នាំ (Annual Leave)';
      }

      // Fallback heuristics when rawType is blank or custom
      if (item['time_in'] != null &&
          item['time_in'].toString().isNotEmpty &&
          item['time_in'] != 'N/A' &&
          (item['number_of_days'] == null || item['number_of_days'].toString() == '0')) {
        return 'ថែមម៉ោង (OT)';
      }

      final days = double.tryParse((item['number_of_days'] ?? '0').toString()) ?? 0;
      if (days > 0) {
        return 'សម្រាកប្រចាំឆ្នាំ (Annual Leave)';
      }

      if (item['late_hours'] != null &&
          item['late_hours'].toString().isNotEmpty &&
          item['late_hours'].toString() != '0' &&
          item['late_hours'].toString() != 'N/A') {
        return 'មកយឺត (Late)';
      }

      if (item['repay_time_in'] != null &&
          item['repay_time_in'].toString().isNotEmpty &&
          item['repay_time_in'] != 'N/A') {
        return 'ប្តូរថ្ងៃសម្រាក (Changing day off)';
      }

      return 'ថែមម៉ោង (OT)';
    }

    final selectedCanonicalType = determineCanonicalType();

    bool isTypeSelected(String typeLabel) {
      return typeLabel == selectedCanonicalType;
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
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        mainAxisSize: MainAxisSize.min,
        children: [
          // ================= 1. A5 HEADER =================
          Center(
            child: Image.asset(
              'assets/images/logo_van_van.png',
              width: 300,
              height: 100,
              fit: BoxFit.contain,
              gaplessPlayback: true,
              errorBuilder: (_, __, ___) => Image.network(
                'https://i.ibb.co/r2JWnd2x/Logo-Van-Van-1.png',
                width: 300,
                height: 100,
                fit: BoxFit.contain,
                gaplessPlayback: true,
                errorBuilder: (_, __, ___) => Column(
                  children: [
                    const Icon(Icons.spa_rounded, color: _goldColor, size: 44),
                    Text(
                      'វ៉ាន់ វ៉ាន់ ខេមបូឌា',
                      style: GoogleFonts.kantumruyPro(
                        color: _goldColor,
                        fontSize: 17,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    Text(
                      'VAN VAN CAMBODIA',
                      style: GoogleFonts.outfit(
                        color: _goldColor,
                        fontSize: 11.5,
                        letterSpacing: 1.5,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
          const SizedBox(height: 6),

          // Top Gold Line
          Container(
            height: 2.2,
            color: _goldColor,
            margin: const EdgeInsets.only(bottom: 8),
          ),

          // Title
          Text(
            'សំណើសុំច្បាប់ឈប់សម្រាក ប្តូរវេន ចេញមុនម៉ោង មកយឺត និងភ្លេចស្កេនមេដៃវត្តមាន',
            textAlign: TextAlign.center,
            style: GoogleFonts.kantumruyPro(
              fontSize: 13.0,
              fontWeight: FontWeight.bold,
              color: Colors.black,
              letterSpacing: 0.1,
            ),
          ),
          const SizedBox(height: 10),

          // ================= 2. MAIN A5 FORM CONTAINER =================
          Container(
            decoration: BoxDecoration(
              border: Border.all(color: Colors.black, width: 1.5),
              borderRadius: BorderRadius.circular(2),
            ),
            padding: const EdgeInsets.all(8),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Request Type Pills Grid Box
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 7),
                  decoration: BoxDecoration(
                    color: const Color(0xFFF8FAFC),
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(color: const Color(0xFFE2E8F0), width: 0.8),
                  ),
                  child: Center(
                    child: Wrap(
                      spacing: 6,
                      runSpacing: 5,
                      alignment: WrapAlignment.center,
                      children: types.map((t) {
                        final isSel = isTypeSelected(t);
                        return Container(
                          padding: EdgeInsets.symmetric(
                            horizontal: isSel ? 9 : 8,
                            vertical: isSel ? 4 : 3.5,
                          ),
                          decoration: BoxDecoration(
                            color: isSel ? _greenSelected : Colors.white,
                            borderRadius: BorderRadius.circular(4.5),
                            border: Border.all(
                              color: isSel ? _greenSelectedBorder : const Color(0xFFCBD5E1),
                              width: isSel ? 1.4 : 0.8,
                            ),
                            boxShadow: isSel
                                ? [
                                    BoxShadow(
                                      color: _greenSelected.withValues(alpha: 0.28),
                                      blurRadius: 3,
                                      offset: const Offset(0, 1),
                                    ),
                                  ]
                                : null,
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              if (isSel) ...[
                                const Icon(
                                  Icons.check_circle_rounded,
                                  size: 11,
                                  color: Colors.white,
                                ),
                                const SizedBox(width: 4),
                              ],
                              Text(
                                t,
                                style: GoogleFonts.kantumruyPro(
                                  fontSize: isSel ? 9.0 : 8.8,
                                  color: isSel ? Colors.white : const Color(0xFF475569),
                                  fontWeight: isSel ? FontWeight.bold : FontWeight.normal,
                                ),
                              ),
                            ],
                          ),
                        );
                      }).toList(),
                    ),
                  ),
                ),
                const SizedBox(height: 10),

                // Pixel-Perfect A5 Grid Details Box (with exact borders & colspans)
                Container(
                  decoration: BoxDecoration(
                    border: Border.all(color: Colors.black, width: 1.0),
                  ),
                  child: Column(
                    children: [
                      // Row 1: Name, Remaining days (5 cols)
                      _buildGridRow([
                        const _GridCell(label: 'ឈ្មោះអ្នកស្នើសុំ៖', isHeader: true, flex: 25),
                        _GridCell(label: item['requester_name'] ?? 'N/A', flex: 25),
                        const _GridCell(label: 'ចំនួនថ្ងៃ/ច្បាប់នៅសល់៖', isHeader: true, flex: 25),
                        _GridCell(label: '${item['number_of_days'] ?? '0'} ថ្ងៃ', flex: 12, align: TextAlign.center),
                        _GridCell(label: '${item['remaining_days'] ?? 'N/A'} ថ្ងៃ', flex: 13, align: TextAlign.center, isLast: true),
                      ]),

                      // Row 2: Department, Position, Branch (4 cols)
                      _buildGridRow([
                        const _GridCell(label: 'ផ្នែក/មុខតំណែង/សាខា៖', isHeader: true, flex: 25),
                        _GridCell(label: item['department'] ?? 'N/A', flex: 25),
                        _GridCell(label: item['position'] ?? 'N/A', flex: 25),
                        _GridCell(label: formatBranch(item['branch']?.toString()), flex: 25, align: TextAlign.center, isLast: true),
                      ]),

                      // Row 3: Request Date, Late hours (4 cols)
                      _buildGridRow([
                        const _GridCell(label: 'ថ្ងៃខែឆ្នាំសុំឈប់៖', isHeader: true, flex: 25),
                        _GridCell(label: formatD(item['request_date']), flex: 25),
                        const _GridCell(label: 'ចំនួនម៉ោងយឺត/ចេញមុន៖', isHeader: true, flex: 25),
                        _GridCell(label: item['late_hours']?.toString() ?? 'N/A', flex: 25, align: TextAlign.center, isLast: true),
                      ]),

                      // Row 4: Return Date, Forgot scan (5 cols)
                      _buildGridRow([
                        const _GridCell(label: 'ថ្ងៃចូលធ្វើការវិញ/ថ្ងៃសងវិញ៖', isHeader: true, flex: 25),
                        _GridCell(label: formatD(item['return_date']), flex: 25),
                        const _GridCell(label: 'ភ្លេចស្កេនមេដៃ៖', isHeader: true, flex: 25),
                        _GridCell(label: item['forgot_scan_in']?.toString() ?? 'N/A', flex: 12, align: TextAlign.center),
                        _GridCell(label: item['forgot_scan_out']?.toString() ?? 'N/A', flex: 13, align: TextAlign.center, isLast: true),
                      ]),

                      // Row 5: Work hours (4 cols)
                      _buildGridRow([
                        const _GridCell(label: 'ម៉ោងចេញចូល(ការងារ)៖', isHeader: true, flex: 25),
                        _GridCell(label: 'ម៉ោងចូល៖ ${formatT(item['time_in'])}', flex: 25),
                        _GridCell(label: 'ម៉ោងចេញ៖ ${formatT(item['time_out'])}', flex: 25),
                        _GridCell(label: 'ម៉ោងសរុប៖ ${item['total_hours'] ?? 'N/A'}', flex: 25, align: TextAlign.center, isLast: true),
                      ]),

                      // Row 6: Repay work hours (4 cols)
                      _buildGridRow([
                        const _GridCell(label: 'ម៉ោងធ្វើការសងវិញ៖', isHeader: true, flex: 25),
                        _GridCell(label: 'ម៉ោងចូលសង៖ ${formatT(item['repay_time_in'])}', flex: 25),
                        _GridCell(label: 'ម៉ោងចេញសង៖ ${formatT(item['repay_time_out'])}', flex: 25),
                        _GridCell(label: 'ម៉ោងសងសរុប៖ ${item['repay_total_hours'] ?? 'N/A'}', flex: 25, align: TextAlign.center, isLast: true),
                      ]),

                      // Row 7: Reason (2 cols)
                      _buildGridRow([
                        const _GridCell(label: 'មូលហេតុ៖', isHeader: true, flex: 25),
                        _GridCell(label: item['reason'] ?? 'N/A', flex: 75, isLast: true),
                      ]),

                      // Row 8: Location (2 cols)
                      _buildGridRow([
                        const _GridCell(label: 'ទីកន្លែងអំឡុងពេលឈប់៖', isHeader: true, flex: 25),
                        _GridCell(label: item['location'] ?? 'N/A', flex: 75, isLast: true),
                      ]),

                      // Row 9: Contact & Assignment (4 cols)
                      _buildGridRow([
                        const _GridCell(label: 'លេខទំនាក់ទំនងបន្ទាន់៖', isHeader: true, flex: 25),
                        _GridCell(label: formatP(item['contact_number']), flex: 25),
                        const _GridCell(label: 'ប្រគល់ការងារឱ្យ៖', isHeader: true, flex: 25),
                        _GridCell(label: item['assigned_to'] ?? 'N/A', flex: 25, align: TextAlign.center, isLast: true),
                      ], isBottom: true),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),

          // ================= 3. A5 SIGNATURES TABLE =================
          Container(
            decoration: BoxDecoration(
              border: Border.all(color: Colors.black, width: 1.0),
            ),
            child: Column(
              children: [
                // Header Row
                Container(
                  color: const Color(0xFFF1F5F9),
                  child: _buildGridRow([
                    const _GridCell(label: 'បញ្ជាក់/អនុម័តដោយ', isHeader: true, flex: 25, align: TextAlign.center),
                    const _GridCell(label: 'ឈ្មោះ (Name)', isHeader: true, flex: 25, align: TextAlign.center),
                    const _GridCell(label: 'ហត្ថលេខា (Signature)', isHeader: true, flex: 28, align: TextAlign.center),
                    const _GridCell(label: 'ថ្ងៃខែឆ្នាំ (Date)', isHeader: true, flex: 22, align: TextAlign.center, isLast: true),
                  ]),
                ),

                // 1. Requester
                _buildSignatureRow(
                  title: 'អ្នកស្នើសុំ',
                  name: item['requester_name'] ?? '',
                  sigBytes: reqSigBytes,
                  date: formatD(item['signature_date'] ?? item['request_date']),
                ),

                // 2. Department Head
                _buildSignatureRow(
                  title: 'ប្រធានផ្នែក',
                  name: item['department_head_name'] ?? '',
                  sigBytes: deptSigBytes,
                  date: formatD(item['department_head_signature_date']),
                ),

                // 3. HR Manager
                _buildSignatureRow(
                  title: 'ប្រធានធនធានមនុស្ស',
                  name: '',
                  sigBytes: null,
                  date: '',
                ),

                // 4. General Manager
                _buildSignatureRow(
                  title: 'ប្រធានគ្រប់គ្រងទូទៅ',
                  name: '',
                  sigBytes: null,
                  date: '',
                ),

                // 5. CEO / Directress
                _buildSignatureRow(
                  title: 'អគ្គនាយិកា',
                  name: '',
                  sigBytes: null,
                  date: '',
                  isBottom: true,
                ),
              ],
            ),
          ),
          const SizedBox(height: 10),

          // ================= 4. A5 FOOTER =================
          Container(
            height: 2.2,
            color: _goldColor,
            margin: const EdgeInsets.only(bottom: 5),
          ),
          Text(
            'ផ្ទះលេខ 1 AEo ផ្លូវលេខ 318 សង្កាត់ ទួលស្វាយព្រៃ១ ខណ្ឌ បឹងកេងកង រាជធានីភ្នំពេញ ព្រះរាជាណាចក្រកម្ពុជា ទូរស័ព្ទលេខ 015 971 961 - 085 971 961',
            textAlign: TextAlign.center,
            style: GoogleFonts.kantumruyPro(
              fontSize: 7.8,
              fontWeight: FontWeight.bold,
              color: const Color(0xFF996515),
              height: 1.25,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            'No.1AEo, St.318, Sangkat Tuol Svay Prey1, Khan Boeng Keng Kang, Phnom Penh, Cambodia. Tel: 015 971 961 - 085 971 961',
            textAlign: TextAlign.center,
            style: GoogleFonts.outfit(
              fontSize: 7.6,
              color: const Color(0xFF996515),
              height: 1.25,
            ),
          ),
        ],
      ),
    );
  }

  // Row builder with bottom border
  static Widget _buildGridRow(List<_GridCell> cells, {bool isBottom = false}) {
    return Container(
      decoration: BoxDecoration(
        border: Border(
          bottom: isBottom ? BorderSide.none : const BorderSide(color: Colors.black, width: 1.0),
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: cells.map((c) {
          return Expanded(
            flex: c.flex,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 5.5, vertical: 5.0),
              decoration: BoxDecoration(
                border: Border(
                  right: c.isLast ? BorderSide.none : const BorderSide(color: Colors.black, width: 1.0),
                ),
              ),
              child: Text(
                c.label,
                textAlign: c.align,
                style: GoogleFonts.kantumruyPro(
                  fontSize: c.isHeader ? _fontSizeLabel : _fontSizeValue,
                  fontWeight: c.isHeader ? FontWeight.bold : FontWeight.normal,
                  color: Colors.black,
                  height: 1.2,
                ),
              ),
            ),
          );
        }).toList(),
      ),
    );
  }

  // Signature row builder
  static Widget _buildSignatureRow({
    required String title,
    required String name,
    required Uint8List? sigBytes,
    required String date,
    bool isBottom = false,
  }) {
    return Container(
      decoration: BoxDecoration(
        border: Border(
          bottom: isBottom ? BorderSide.none : const BorderSide(color: Colors.black, width: 1.0),
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          // Title
          Expanded(
            flex: 25,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 5.5, vertical: 7.0),
              decoration: const BoxDecoration(
                border: Border(right: BorderSide(color: Colors.black, width: 1.0)),
              ),
              child: Text(
                title,
                style: GoogleFonts.kantumruyPro(
                  fontSize: _fontSizeLabel,
                  fontWeight: FontWeight.bold,
                  color: Colors.black,
                ),
              ),
            ),
          ),

          // Name
          Expanded(
            flex: 25,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 5.5, vertical: 7.0),
              decoration: const BoxDecoration(
                border: Border(right: BorderSide(color: Colors.black, width: 1.0)),
              ),
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
          ),

          // Signature Image / Line
          Expanded(
            flex: 28,
            child: Container(
              height: 44,
              padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
              decoration: const BoxDecoration(
                border: Border(right: BorderSide(color: Colors.black, width: 1.0)),
              ),
              child: sigBytes != null
                  ? Image.memory(sigBytes, fit: BoxFit.contain)
                  : Center(
                      child: Container(
                        width: 70,
                        height: 1.0,
                        color: Colors.black26,
                      ),
                    ),
            ),
          ),

          // Date
          Expanded(
            flex: 22,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 5.5, vertical: 7.0),
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
          ),
        ],
      ),
    );
  }
}

class _GridCell {
  final String label;
  final bool isHeader;
  final int flex;
  final TextAlign align;
  final bool isLast;

  const _GridCell({
    required this.label,
    this.isHeader = false,
    this.flex = 1,
    this.align = TextAlign.left,
    this.isLast = false,
  });
}
