import 'package:flutter/foundation.dart';
import 'package:flutter_khmer_chankitec/flutter_khmer_chankitec.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'notification_service.dart';

/// Service for scheduling Khmer Calendar holiday & Sila day notifications.
///
/// Rules:
///  - **Day before** (at 20:00): "ថ្ងៃស្អែកជា [name]! 🎉"
///  - **Day of**     (at 07:00): "ថ្ងៃនេះជា [name]! 🎊"
class KhmerCalendarNotificationService {
  static final KhmerCalendarNotificationService _instance =
      KhmerCalendarNotificationService._internal();

  factory KhmerCalendarNotificationService() => _instance;
  KhmerCalendarNotificationService._internal();

  static const String _channelId = 'vvc_khmer_calendar';
  static const String _channelName = 'ការជូនដំណឹងប្រតិទិនខ្មែរ';
  static const String _channelDesc = 'ជូនដំណឹងថ្ងៃបុណ្យ និង ថ្ងៃសីល';
  static const String _prefKey = 'khmer_cal_notif_scheduled_year';

  // Notification IDs: use offsets to avoid collision
  // Day-before notifications: 8000 + day_of_year
  // Day-of  notifications: 9000 + day_of_year
  static const int _dayBeforeOffset = 8000;
  static const int _dayOfOffset = 9000;

  /// Call this once per app start (or when user logs in).
  /// It will schedule notifications for the next 365 days, once per year.
  Future<void> scheduleForYear() async {
    if (kIsWeb) return;

    try {
      final prefs = await SharedPreferences.getInstance();
      final currentYear = DateTime.now().year;
      final lastScheduledYear = prefs.getInt(_prefKey) ?? 0;

      // Only re-schedule if we haven't scheduled for this year yet
      if (lastScheduledYear >= currentYear) return;

      await _ensureChannel();
      await _cancelAllCalendarNotifications();
      await _scheduleAllDays(currentYear);

      // Also schedule for next year so January notifications work
      await _scheduleAllDays(currentYear + 1);

      await prefs.setInt(_prefKey, currentYear);
      debugPrint('[KhmerCalendarNotif] Scheduled holidays for $currentYear & ${currentYear + 1}');
    } catch (e) {
      debugPrint('[KhmerCalendarNotif] Error scheduling: $e');
    }
  }

  /// Force reschedule (call when user toggles setting)
  Future<void> reschedule() async {
    if (kIsWeb) return;
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.remove(_prefKey);
      await scheduleForYear();
    } catch (e) {
      debugPrint('[KhmerCalendarNotif] reschedule error: $e');
    }
  }

  /// Cancel all calendar-related scheduled notifications
  Future<void> cancelAll() async {
    if (kIsWeb) return;
    await _cancelAllCalendarNotifications();
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_prefKey);
  }

  // ─── Private helpers ─────────────────────────────────────────────────────

  Future<void> _ensureChannel() async {
    final androidPlugin = NotificationService()
        .flutterLocalNotificationsPlugin
        .resolvePlatformSpecificImplementation<
          AndroidFlutterLocalNotificationsPlugin
        >();
    if (androidPlugin != null) {
      await androidPlugin.createNotificationChannel(
        const AndroidNotificationChannel(
          _channelId,
          _channelName,
          description: _channelDesc,
          importance: Importance.max,
          playSound: true,
        ),
      );
    }
  }

  Future<void> _cancelAllCalendarNotifications() async {
    final plugin = NotificationService().flutterLocalNotificationsPlugin;
    // Cancel IDs in range 8000-8366 (day-before) and 9000-9366 (day-of)
    for (int i = 0; i <= 366; i++) {
      await plugin.cancel(_dayBeforeOffset + i);
      await plugin.cancel(_dayOfOffset + i);
    }
  }

  Future<void> _scheduleAllDays(int year) async {
    final today = DateTime.now();
    final startDate = DateTime(year, 1, 1);
    final endDate = DateTime(year, 12, 31);

    for (DateTime d = startDate;
        d.isBefore(endDate.add(const Duration(days: 1)));
        d = d.add(const Duration(days: 1))) {
      final info = _getSpecialDayInfo(d);
      if (info == null) continue;

      final dayOfYear = _dayOfYear(d);

      // 1) Notification the day BEFORE at 20:00
      final dayBefore = d.subtract(const Duration(days: 1));
      final dayBeforeTime = DateTime(
        dayBefore.year,
        dayBefore.month,
        dayBefore.day,
        20, 0, 0,
      );
      if (dayBeforeTime.isAfter(today)) {
        await _schedule(
          id: _dayBeforeOffset + dayOfYear,
          title: '📅 ការរំឭក: ${info.name}',
          body: 'ថ្ងៃស្អែក (ថ្ងៃទី ${d.day}) គឺជា${info.typeLabel}! ${info.emoji}',
          scheduledDate: dayBeforeTime,
        );
      }

      // 2) Notification ON THE DAY at 07:00
      final dayOfTime = DateTime(d.year, d.month, d.day, 7, 0, 0);
      if (dayOfTime.isAfter(today)) {
        await _schedule(
          id: _dayOfOffset + dayOfYear,
          title: '🎊 ${info.name}',
          body: 'ថ្ងៃនេះគឺជា${info.typeLabel}! ${info.emoji} សូមឱ្យអ្នកទាំងអស់គ្នាអបអរ!',
          scheduledDate: dayOfTime,
        );
      }
    }
  }

  Future<void> _schedule({
    required int id,
    required String title,
    required String body,
    required DateTime scheduledDate,
  }) async {
    try {
      await NotificationService().scheduleNotificationOnChannel(
        id: id,
        title: title,
        body: body,
        scheduledDate: scheduledDate,
        channelId: _channelId,
        channelName: _channelName,
      );
    } on PlatformException catch (e) {
      debugPrint('[KhmerCalendarNotif] PlatformException scheduling id=$id: $e');
    } catch (e) {
      debugPrint('[KhmerCalendarNotif] Error scheduling id=$id: $e');
    }
  }

  int _dayOfYear(DateTime date) {
    return date.difference(DateTime(date.year, 1, 1)).inDays;
  }

  // ─── Special day detection ────────────────────────────────────────────────

  _SpecialDayInfo? _getSpecialDayInfo(DateTime date) {
    // Check fixed Gregorian holidays
    final gregorianHoliday = _getGregorianHoliday(date);
    if (gregorianHoliday != null) return gregorianHoliday;

    // Check lunar-based days (requires Chhankitek computation)
    try {
      final lunar = Chhankitek.fromDate(date);

      // Check lunar holidays
      final lunarHoliday = _getLunarHoliday(date, lunar);
      if (lunarHoliday != null) return lunarHoliday;

      // Check Sila day
      if (lunar.isSilaDay) {
        return _SpecialDayInfo(
          name: 'ថ្ងៃសីល',
          typeLabel: 'ថ្ងៃសីល',
          emoji: '🙏',
          isMajor: false,
        );
      }
    } catch (e) {
      debugPrint('[KhmerCalendarNotif] Chhankitek error for $date: $e');
    }

    return null;
  }

  _SpecialDayInfo? _getGregorianHoliday(DateTime date) {
    final m = date.month;
    final d = date.day;

    // Major public holidays
    if (m == 1 && d == 7) return _SpecialDayInfo(name: 'ជ័យជម្នះ ៧មករា', typeLabel: 'ថ្ងៃបុណ្យជាតិ', emoji: '🎉', isMajor: true);
    if (m == 4 && d >= 13 && d <= 16) return _SpecialDayInfo(name: 'ចូលឆ្នាំខ្មែរ', typeLabel: 'ថ្ងៃបុណ្យ', emoji: '🎊', isMajor: true);
    if (m == 5 && d == 14) return _SpecialDayInfo(name: 'បុណ្យចម្រើនព្រះជន្ម', typeLabel: 'ថ្ងៃបុណ្យ', emoji: '👑', isMajor: true);
    if (m == 9 && d == 24) return _SpecialDayInfo(name: 'ទិវាប្រកាសរដ្ឋធម្មនុញ្ញ', typeLabel: 'ថ្ងៃបុណ្យ', emoji: '📜', isMajor: true);
    if (m == 11 && d == 9) return _SpecialDayInfo(name: 'បុណ្យឯករាជ្យជាតិ', typeLabel: 'ថ្ងៃបុណ្យជាតិ', emoji: '🇰🇭', isMajor: true);

    // Other notable days
    if (m == 1 && d == 1) return _SpecialDayInfo(name: 'ចូលឆ្នាំសកល', typeLabel: 'ថ្ងៃបុណ្យ', emoji: '🎆', isMajor: false);
    if (m == 3 && d == 8) return _SpecialDayInfo(name: 'ទិវានារី', typeLabel: 'ទិវា', emoji: '💐', isMajor: false);
    if (m == 5 && d == 1) return _SpecialDayInfo(name: 'ទិវាពលកម្ម', typeLabel: 'ទិវា', emoji: '⚒️', isMajor: false);
    if (m == 6 && d == 18) return _SpecialDayInfo(name: 'ចម្រើនព្រះជន្ម សម្ដេចម៉ែ', typeLabel: 'ថ្ងៃបុណ្យ', emoji: '👑', isMajor: false);
    if (m == 10 && d == 15) return _SpecialDayInfo(name: 'ទិវាគោរពព្រះវិញ្ញាណក្ខន្ធ', typeLabel: 'ទិវា', emoji: '🕯️', isMajor: false);
    if (m == 10 && d == 29) return _SpecialDayInfo(name: 'បុណ្យគ្រងរាជ្យ', typeLabel: 'ថ្ងៃបុណ្យ', emoji: '👑', isMajor: false);
    if (m == 12 && d == 29) return _SpecialDayInfo(name: 'ទិវាសន្តិភាព', typeLabel: 'ទិវា', emoji: '🕊️', isMajor: false);

    return null;
  }

  _SpecialDayInfo? _getLunarHoliday(DateTime date, KhmerLunarDate lunar) {
    final m = lunar.format('m');
    final d = lunar.lunarDay.toString();

    if (m == 'ភទ្របទ' && d.contains('១៥ រោច')) {
      return _SpecialDayInfo(name: 'ភ្ជុំបិណ្ឌ', typeLabel: 'ថ្ងៃបុណ្យ', emoji: '🙏', isMajor: true);
    }
    if (m == 'ភទ្របទ' && (d.contains('១៤ រោច') || d.contains('១៣ រោច'))) {
      return _SpecialDayInfo(name: 'កាន់បិណ្ឌ', typeLabel: 'ថ្ងៃបុណ្យ', emoji: '🙏', isMajor: true);
    }
    if (m == 'កត្តិក' && (d.contains('១៤ កើត') || d.contains('១៥ កើត'))) {
      return _SpecialDayInfo(name: 'បុណ្យអុំទូក', typeLabel: 'ថ្ងៃបុណ្យ', emoji: '🚣', isMajor: true);
    }
    return null;
  }
}

class _SpecialDayInfo {
  final String name;
  final String typeLabel;
  final String emoji;
  final bool isMajor;

  const _SpecialDayInfo({
    required this.name,
    required this.typeLabel,
    required this.emoji,
    required this.isMajor,
  });
}
