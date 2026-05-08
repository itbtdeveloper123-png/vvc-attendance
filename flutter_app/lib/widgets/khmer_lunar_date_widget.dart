import 'package:flutter/material.dart';
import 'package:flutter_khmer_chankitec/flutter_khmer_chankitec.dart';
import 'package:google_fonts/google_fonts.dart';

class KhmerLunarDateWidget extends StatelessWidget {
  final DateTime date;
  final TextStyle? style;
  final TextAlign textAlign;

  const KhmerLunarDateWidget({
    super.key,
    required this.date,
    this.style,
    this.textAlign = TextAlign.center,
  });

  @override
  Widget build(BuildContext context) {
    // Convert from Gregorian Date using Chhankitek
    final lunarDate = Chhankitek.fromDate(date);
    
    // Get full date string: ថ្ងៃW d ខែm ឆ្នាំa e ព.ស. b
    // Format tokens: W=DayOfWeek, d=Day, m=Month, a=Zodiac, e=Era, b=BuddhistYear
    String lunarString = lunarDate.toString();

    return Text(
      lunarString,
      style: style ?? GoogleFonts.kantumruyPro(
        fontSize: 16,
        fontWeight: FontWeight.w500,
        height: 1.5,
        color: Theme.of(context).colorScheme.onSurface,
      ),
      textAlign: textAlign,
    );
  }
}
