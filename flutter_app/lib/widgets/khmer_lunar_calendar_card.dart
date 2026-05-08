import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_khmer_chankitec/flutter_khmer_chankitec.dart';
import 'package:google_fonts/google_fonts.dart';
import '../utils/app_theme.dart';

class KhmerLunarCalendarCard extends StatefulWidget {
  final DateTime? initialDate;
  final bool isModal;
  const KhmerLunarCalendarCard({super.key, this.initialDate, this.isModal = false});

  @override
  State<KhmerLunarCalendarCard> createState() => _KhmerLunarCalendarCardState();
}

class _KhmerHoliday {
  final String name;
  final bool isMajor;
  _KhmerHoliday(this.name, this.isMajor);
}

class _KhmerLunarCalendarCardState extends State<KhmerLunarCalendarCard> {
  late DateTime _viewDate;
  late DateTime _today;
  final String _silaImageUrl = "https://i.ibb.co/gMwK57Bv/Chat-GPT-Image-May-4-2026-07-06-32-PM.png";

  @override
  void initState() {
    super.initState();
    _today = DateTime.now();
    _viewDate = widget.initialDate ?? DateTime(_today.year, _today.month, 1);
  }

  void _nextMonth() {
    setState(() {
      _viewDate = DateTime(_viewDate.year, _viewDate.month + 1, 1);
    });
  }

  void _prevMonth() {
    setState(() {
      _viewDate = DateTime(_viewDate.year, _viewDate.month - 1, 1);
    });
  }

  _KhmerHoliday? _getHoliday(DateTime date, KhmerLunarDate lunar) {
    if (date.month == 1 && date.day == 7) return _KhmerHoliday("ជ័យជម្នះ ៧មករា", true);
    if (date.month == 4 && date.day >= 13 && date.day <= 16) return _KhmerHoliday("ចូលឆ្នាំខ្មែរ", true);
    if (date.month == 5 && date.day == 14) return _KhmerHoliday("បុណ្យចម្រើនព្រះជន្ម", true);
    if (date.month == 9 && date.day == 24) return _KhmerHoliday("ទិវាប្រកាសរដ្ឋធម្មនុញ្ញ", true);
    if (date.month == 11 && date.day == 9) return _KhmerHoliday("បុណ្យឯករាជ្យជាតិ", true);

    if (date.month == 1 && date.day == 1) return _KhmerHoliday("ចូលឆ្នាំសកល", false);
    if (date.month == 3 && date.day == 8) return _KhmerHoliday("ទិវានារី", false);
    if (date.month == 5 && date.day == 1) return _KhmerHoliday("ទិវាពលកម្ម", false);
    if (date.month == 6 && date.day == 18) return _KhmerHoliday("បុណ្យចម្រើនព្រះជន្ម", false);
    if (date.month == 10 && date.day == 15) return _KhmerHoliday("ទិវាគោរពព្រះវិញ្ញាណក្ខន្ធ", false);
    if (date.month == 10 && date.day == 29) return _KhmerHoliday("បុណ្យគ្រងរាជ្យ", false);
    if (date.month == 12 && date.day == 29) return _KhmerHoliday("ទិវាសន្តិភាព", false);

    final m = lunar.format("m");
    final d = lunar.lunarDay.toString();
    if (m == "ភទ្របទ" && d.contains("១៥ រោច")) return _KhmerHoliday("ភ្ជុំបិណ្ឌ", true);
    if (m == "ភទ្របទ" && (d.contains("១៤ រោច") || d.contains("១៣ រោច"))) return _KhmerHoliday("កាន់បិណ្ឌ", true);
    if (m == "កត្តិក" && (d.contains("១៤ កើត") || d.contains("១៥ កើត"))) return _KhmerHoliday("បុណ្យអុំទូក", true);

    return null;
  }

  void _showDayDetails(DateTime date) {
    final lunar = Chhankitek.fromDate(date);
    final holiday = _getHoliday(date, lunar);
    
    final dayOfWeek = lunar.format("ថ្ងៃW");
    final lunarDay = lunar.lunarDay.toString();
    final lunarMonth = "ខែ${lunar.format("m")}";
    final lunarYear = "ឆ្នាំ${lunar.format("a")}";
    final era = lunar.format("e");
    final buddhistEra = "ពុទ្ធសករាជ ${lunar.format("b")}";
    final gregorianDay = date.day.toString().padLeft(2, '0');
    final gregorianMonthYear = "ខែ ${_getMonthName(date.month)} ${date.year}";

    final fullCopyText = "$dayOfWeek $lunarDay $lunarMonth $lunarYear $era $buddhistEra\nត្រូវនឹងថ្ងៃទី ${date.day} $gregorianMonthYear${holiday != null ? '\n(${holiday.name})' : ''}";

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        insetPadding: const EdgeInsets.symmetric(horizontal: 16),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        contentPadding: EdgeInsets.zero,
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              margin: const EdgeInsets.all(16),
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: const Color(0xFFFFF9E6),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: const Color(0xFFD4AF37).withValues(alpha: 0.3), width: 1),
                boxShadow: [
                  BoxShadow(color: Colors.black.withValues(alpha: 0.1), blurRadius: 10, offset: const Offset(0, 4)),
                ],
              ),
              child: IntrinsicHeight(
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: [
                    Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text(
                          gregorianDay,
                          style: GoogleFonts.inter(
                            fontSize: 50,
                            fontWeight: FontWeight.w900,
                            color: const Color(0xFF333333),
                            height: 1,
                          ),
                        ),
                        Text(
                          _getMonthName(date.month),
                          style: GoogleFonts.kantumruyPro(fontSize: 12, color: AppTheme.textMuted),
                        ),
                        Text(
                          date.year.toString(),
                          style: GoogleFonts.inter(fontSize: 12, color: AppTheme.textMuted),
                        ),
                      ],
                    ),
                    const VerticalDivider(width: 30, thickness: 1, color: Color(0xFFD4AF37)),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Text(
                            dayOfWeek,
                            style: GoogleFonts.kantumruyPro(color: Colors.redAccent, fontWeight: FontWeight.bold, fontSize: 18),
                          ),
                          const SizedBox(height: 4),
                          RichText(
                            text: TextSpan(
                              style: GoogleFonts.kantumruyPro(fontSize: 15, height: 1.5),
                              children: [
                                TextSpan(text: "$lunarDay ", style: const TextStyle(color: Color(0xFF003399), fontWeight: FontWeight.bold)),
                                TextSpan(text: lunarMonth, style: const TextStyle(color: Color(0xFF8B4513), fontWeight: FontWeight.bold)),
                              ],
                            ),
                          ),
                          RichText(
                            text: TextSpan(
                              style: GoogleFonts.kantumruyPro(fontSize: 15, height: 1.5),
                              children: [
                                TextSpan(text: "$lunarYear ", style: const TextStyle(color: Color(0xFF006400), fontWeight: FontWeight.bold)),
                                TextSpan(text: era, style: const TextStyle(color: Color(0xFF003399), fontWeight: FontWeight.bold)),
                              ],
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            buddhistEra,
                            style: GoogleFonts.kantumruyPro(color: const Color(0xFF555555), fontSize: 13),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
            
            if (holiday != null || lunar.isSilaDay)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Column(
                  children: [
                    if (holiday != null)
                      Container(
                        width: double.infinity,
                        margin: const EdgeInsets.only(bottom: 8),
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: (holiday.isMajor ? Colors.redAccent : Colors.blueAccent).withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: (holiday.isMajor ? Colors.redAccent : Colors.blueAccent).withValues(alpha: 0.2)),
                        ),
                        child: Text(
                          holiday.name,
                          style: GoogleFonts.kantumruyPro(
                            color: holiday.isMajor ? Colors.redAccent : Colors.blueAccent,
                            fontWeight: FontWeight.bold,
                            fontSize: 14,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ),
                    if (lunar.isSilaDay)
                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Image.network(_silaImageUrl, width: 20, height: 20, fit: BoxFit.contain),
                          const SizedBox(width: 8),
                          Text(
                            "ថ្ងៃសីល",
                            style: GoogleFonts.kantumruyPro(color: Colors.orange, fontWeight: FontWeight.bold, fontSize: 14),
                          ),
                        ],
                      ),
                  ],
                ),
              ),
              
            const SizedBox(height: 16),
            
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
              child: Row(
                children: [
                  Expanded(
                    child: TextButton(
                      onPressed: () => Navigator.pop(context),
                      style: TextButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 12),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                      child: Text("បិទ", style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted)),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    flex: 2,
                    child: ElevatedButton.icon(
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: fullCopyText));
                        Navigator.pop(context);
                        ScaffoldMessenger.of(this.context).showSnackBar(
                          SnackBar(
                            content: Text("ចម្លងកាលបរិច្ឆេទរួចរាល់", style: GoogleFonts.kantumruyPro()),
                            behavior: SnackBarBehavior.floating,
                            backgroundColor: AppTheme.accent,
                            margin: const EdgeInsets.all(20),
                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                          ),
                        );
                      },
                      icon: const Icon(Icons.copy_rounded, size: 18),
                      label: Text("ចម្លងអត្ថបទ", style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppTheme.primary,
                        foregroundColor: Colors.white,
                        elevation: 0,
                        padding: const EdgeInsets.symmetric(vertical: 12),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final firstDayOfMonth = DateTime(_viewDate.year, _viewDate.month, 1);
    final lastDayOfMonth = DateTime(_viewDate.year, _viewDate.month + 1, 0);
    final daysInMonth = lastDayOfMonth.day;
    final startWeekday = firstDayOfMonth.weekday % 7;

    final midMonthLunar = Chhankitek.fromDate(DateTime(_viewDate.year, _viewDate.month, 15));
    
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: widget.isModal ? Colors.transparent : AppTheme.bgCard,
        borderRadius: BorderRadius.circular(24),
        border: widget.isModal ? null : Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.08)),
      ),
      child: Column(
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              IconButton(
                onPressed: _prevMonth,
                icon: Icon(Icons.chevron_left_rounded, color: AppTheme.primaryLight),
              ),
              Expanded(
                child: Column(
                  children: [
                    Text(
                      "${_getMonthName(_viewDate.month)} ${_viewDate.year}",
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary,
                        fontWeight: FontWeight.bold,
                        fontSize: 18,
                      ),
                    ),
                    Text(
                      midMonthLunar.format("ខែm ឆ្នាំa e"),
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.primaryLight,
                        fontSize: 13,
                      ),
                    ),
                  ],
                ),
              ),
              IconButton(
                onPressed: _nextMonth,
                icon: Icon(Icons.chevron_right_rounded, color: AppTheme.primaryLight),
              ),
            ],
          ),
          const SizedBox(height: 20),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceAround,
            children: ['អា', 'ច', 'អ', 'ព', 'ព្រ', 'សុ', 'ស'].map((d) {
              return Expanded(
                child: Center(
                  child: Text(
                    d,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textMuted,
                      fontSize: 13,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              );
            }).toList(),
          ),
          const SizedBox(height: 12),
          GridView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 7,
              mainAxisSpacing: 1, // Minimal spacing for tight grid like web
              crossAxisSpacing: 1,
              childAspectRatio: 0.75, // Taller cells for text
            ),
            itemCount: daysInMonth + startWeekday,
            itemBuilder: (context, index) {
              if (index < startWeekday) return const SizedBox.shrink();
              
              final day = index - startWeekday + 1;
              final date = DateTime(_viewDate.year, _viewDate.month, day);
              final isToday = date.year == _today.year && date.month == _today.month && date.day == _today.day;
              final isSunday = date.weekday == DateTime.sunday;
              
              final lunar = Chhankitek.fromDate(date);
              final holiday = _getHoliday(date, lunar);
              final holidayColor = holiday != null ? (holiday.isMajor ? Colors.redAccent : Colors.blueAccent) : null;
              
              return InkWell(
                onTap: () => _showDayDetails(date),
                child: Container(
                  decoration: BoxDecoration(
                    color: isToday ? AppTheme.primary.withValues(alpha: 0.1) : Colors.transparent,
                    border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.03), width: 0.5),
                  ),
                  child: Stack(
                    clipBehavior: Clip.none,
                    children: [
                      // Indicators Row (Sila & Celebration)
                      Positioned(
                        top: 4,
                        left: 4,
                        right: 4,
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            if (holiday != null)
                              Icon(Icons.celebration_rounded, color: holidayColor, size: 9),
                            if (lunar.isSilaDay)
                              Image.network(_silaImageUrl, width: 10, height: 10, fit: BoxFit.contain),
                          ],
                        ),
                      ),
                      // Center Content
                      Align(
                        alignment: Alignment.center,
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              "$day",
                              style: GoogleFonts.inter(
                                color: isToday ? AppTheme.primaryLight : (isSunday ? Colors.redAccent : AppTheme.textPrimary),
                                fontWeight: (isToday || holiday != null) ? FontWeight.bold : FontWeight.normal,
                                fontSize: 15,
                              ),
                            ),
                            Text(
                              lunar.lunarDay.toString(),
                              style: GoogleFonts.kantumruyPro(
                                color: isToday ? AppTheme.primaryLight : AppTheme.textMuted,
                                fontSize: 8,
                              ),
                            ),
                            if (holiday != null)
                              Padding(
                                padding: const EdgeInsets.symmetric(horizontal: 2),
                                child: Text(
                                  holiday.name,
                                  style: GoogleFonts.kantumruyPro(
                                    color: holidayColor,
                                    fontSize: 6.5,
                                    fontWeight: FontWeight.bold,
                                  ),
                                  textAlign: TextAlign.center,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              );
            },
          ),
          const SizedBox(height: 20),
          Wrap(
            spacing: 15,
            runSpacing: 8,
            alignment: WrapAlignment.center,
            children: [
              _buildLegendItemWithImage(_silaImageUrl, "ថ្ងៃសីល"),
              _buildLegendItem(Icons.celebration_rounded, Colors.redAccent, "បុណ្យធំ"),
              _buildLegendItem(Icons.celebration_rounded, Colors.blueAccent, "បុណ្យតូច/ទិវា"),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildLegendItemWithImage(String imageUrl, String label) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Image.network(imageUrl, width: 14, height: 14, fit: BoxFit.contain),
        const SizedBox(width: 6),
        Text(
          label,
          style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 11),
        ),
      ],
    );
  }

  Widget _buildLegendItem(IconData icon, Color color, String label) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, color: color, size: 14),
        const SizedBox(width: 6),
        Text(
          label,
          style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 11),
        ),
      ],
    );
  }

  String _getMonthName(int month) {
    const months = [
      'មករា', 'កុម្ភៈ', 'មីនា', 'មេសា', 'ឧសភា', 'មិថុនា',
      'កក្កដា', 'សីហា', 'កញ្ញា', 'តុលា', 'វិច្ឆិកា', 'ធ្នូ'
    ];
    return months[month - 1];
  }
}
