import 'package:flutter/foundation.dart';
import 'package:speech_to_text/speech_to_text.dart';

/// A recognized voice command with its action type.
enum VoiceCommandType {
  scanIn,
  scanOut,
  outside,
  home,
  requests,
  notifications,
  chat,
  meetings,
  checklist,
  profile,
  mission,
  dailyReport,
  calendar,
  training,
  productAnalyzer,
  trip,
  payroll,
  unknown,
}

class VoiceCommand {
  final VoiceCommandType type;
  final String recognizedText;
  final double confidence;

  const VoiceCommand({
    required this.type,
    required this.recognizedText,
    required this.confidence,
  });
}

/// Service that manages speech-to-text and command matching.
class VoiceCommandService {
  static final VoiceCommandService _instance = VoiceCommandService._internal();
  factory VoiceCommandService() => _instance;
  VoiceCommandService._internal();

  final SpeechToText _speechToText = SpeechToText();
  bool _isInitialized = false;
  bool _isListening = false;

  bool get isListening => _isListening;

  // ─── Keyword maps ──────────────────────────────────────────────────────────
  // Each entry: list of keyword aliases for a command.
  static const Map<VoiceCommandType, List<String>> _commandKeywords = {
    VoiceCommandType.scanIn: [
      'ស្កេនចូល',
      'ចូល',
      'check in',
      'scan in',
      'check-in',
      'checkin',
      'clock in',
      'clock-in',
      'ចុះឈ្មោះចូល',
      'ចុះឈ្មោះ',
      'in',
    ],
    VoiceCommandType.scanOut: [
      'ស្កេនចេញ',
      'ចេញ',
      'check out',
      'scan out',
      'check-out',
      'checkout',
      'clock out',
      'clock-out',
      'ចុះឈ្មោះចេញ',
      'out',
    ],
    VoiceCommandType.outside: [
      'ក្រៅ',
      'វត្តមានក្រៅ',
      'outside',
      'outdoor',
      'outside attendance',
      'outside scan',
      'ស្កេនក្រៅ',
      'ចូលក្រៅ',
    ],
    VoiceCommandType.home: [
      'ទំព័រដើម',
      'ទំព័រ',
      'home',
      'main',
      'dashboard',
      'ត្រលប់',
      'back',
    ],
    VoiceCommandType.requests: [
      'ការស្នើ',
      'ស្នើ',
      'ការស្នើ',
      'ច្បាប់',
      'request',
      'requests',
      'leave',
      'leave request',
      'ឈប់សំរាក',
      'ឈប់',
    ],
    VoiceCommandType.notifications: [
      'ការជូនដំណឹង',
      'ជូនដំណឹង',
      'ការជូន',
      'notification',
      'notifications',
      'alerts',
      'news',
      'ព័ត៌មាន',
    ],
    VoiceCommandType.chat: [
      'ផ្ញើសារ',
      'សារ',
      'ជជែក',
      'chat',
      'message',
      'messages',
      'inbox',
      'conversation',
      'talk',
    ],
    VoiceCommandType.meetings: [
      'ប្រជុំ',
      'ការប្រជុំ',
      'meeting',
      'meetings',
      'conference',
      'schedule',
      'ពេលវេលា',
    ],
    VoiceCommandType.checklist: [
      'ចែករំលែក',
      'checklist',
      'tasks',
      'task',
      'todo',
      'to-do',
      'កិច្ចការ',
      'ការងារ',
      'work list',
    ],
    VoiceCommandType.profile: [
      'ព័ត៌មានខ្ញុំ',
      'ប្រវត្តិ',
      'profile',
      'account',
      'me',
      'settings',
      'setting',
      'ការកំណត់',
      'ផ្ទាល់ខ្លួន',
    ],
    VoiceCommandType.mission: [
      'បេសកកម្ម',
      'ភារកិច្ច',
      'mission',
      'task mission',
      'assignment',
    ],
    VoiceCommandType.dailyReport: [
      'របាយការណ៍ប្រចាំថ្ងៃ',
      'របាយការណ៍',
      'report',
      'daily report',
      'daily',
      'ប្រចាំថ្ងៃ',
    ],
    VoiceCommandType.calendar: [
      'ប្រតិទិន',
      'ប្រតិទិនខ្មែរ',
      'calendar',
      'khmer calendar',
      'lunar',
      'ថ្ងៃ',
    ],
    VoiceCommandType.training: [
      'ការហ្វឹកហ្វឺន',
      'ហ្វឹកហ្វឺន',
      'quiz',
      'training',
      'test',
      'learning',
      'ចំណេះ',
    ],
    VoiceCommandType.productAnalyzer: [
      'វិភាគផលិតផល',
      'ផលិតផល',
      'ស្កេនផលិតផល',
      'បាកូដ',
      'barcode',
      'product analyzer',
      'analyze product',
      'scan product',
      'product',
      'ai product',
    ],
    VoiceCommandType.trip: [
      'ដំណើរ',
      'ការដំណើរ',
      'trip',
      'travel',
      'tracking',
      'ការតាមដាន',
      'route',
    ],
    VoiceCommandType.payroll: [
      'ប្រាក់ខែ',
      'ប្រាក់',
      'payroll',
      'salary',
      'pay',
      'wage',
      'income',
      'ការបង់ប្រាក់',
    ],
  };

  // ─── Initialize ────────────────────────────────────────────────────────────

  Future<bool> initialize() async {
    if (_isInitialized) return true;
    if (kIsWeb) return false;

    try {
      _isInitialized = await _speechToText.initialize(
        onError: (error) => debugPrint('[Voice] STT Error: ${error.errorMsg}'),
        onStatus: (status) => debugPrint('[Voice] STT Status: $status'),
      );
      debugPrint('[Voice] Initialized: $_isInitialized');
    } catch (e) {
      debugPrint('[Voice] Init error: $e');
      _isInitialized = false;
    }
    return _isInitialized;
  }

  bool get isAvailable => _isInitialized && _speechToText.isAvailable;

  // ─── Listen ────────────────────────────────────────────────────────────────

  /// Start listening. Calls [onResult] when text is recognized.
  /// Calls [onListeningChanged] whenever the listening state changes.
  Future<void> startListening({
    required void Function(VoiceCommand command) onResult,
    void Function(bool isListening)? onListeningChanged,
    String localeId = 'km-KH', // Default to Khmer; falls back if unavailable
  }) async {
    if (!_isInitialized) {
      final ok = await initialize();
      if (!ok) return;
    }

    // Try Khmer first; fall back to system default if not supported
    final locales = await _speechToText.locales();
    final hasKhmer = locales.any((l) => l.localeId.startsWith('km'));
    final finalLocale = hasKhmer ? 'km-KH' : '';

    _isListening = true;
    onListeningChanged?.call(true);

    await _speechToText.listen(
      listenOptions: SpeechListenOptions(
        localeId: finalLocale.isEmpty ? null : finalLocale,
        listenFor: const Duration(seconds: 10),
        pauseFor: const Duration(seconds: 2),
        listenMode: ListenMode.confirmation,
        cancelOnError: true,
      ),
      onResult: (result) {
        if (result.finalResult) {
          _isListening = false;
          onListeningChanged?.call(false);
          final text = result.recognizedWords.toLowerCase().trim();
          final command = _matchCommand(text, result.confidence);
          onResult(command);
        }
      },
    );
  }

  Future<void> stopListening() async {
    if (_isListening) {
      await _speechToText.stop();
      _isListening = false;
    }
  }

  Future<void> cancelListening() async {
    await _speechToText.cancel();
    _isListening = false;
  }

  // ─── Command matching ──────────────────────────────────────────────────────

  VoiceCommand _matchCommand(String text, double confidence) {
    if (text.isEmpty) {
      return VoiceCommand(
        type: VoiceCommandType.unknown,
        recognizedText: text,
        confidence: confidence,
      );
    }

    // Score each command type by keyword overlap
    VoiceCommandType bestType = VoiceCommandType.unknown;
    int bestScore = 0;

    for (final entry in _commandKeywords.entries) {
      for (final keyword in entry.value) {
        final k = keyword.toLowerCase();
        // Check if the recognized text contains this keyword
        if (text.contains(k)) {
          // Longer match = better score
          if (k.length > bestScore) {
            bestScore = k.length;
            bestType = entry.key;
          }
        }
      }
    }

    return VoiceCommand(
      type: bestType,
      recognizedText: text,
      confidence: confidence,
    );
  }

  /// Get human-readable label for a command type
  static String commandLabel(VoiceCommandType type) {
    switch (type) {
      case VoiceCommandType.scanIn:
        return 'ស្កេនចូល (Check-In)';
      case VoiceCommandType.scanOut:
        return 'ស្កេនចេញ (Check-Out)';
      case VoiceCommandType.outside:
        return 'វត្តមានក្រៅ (Outside)';
      case VoiceCommandType.home:
        return 'ទំព័រដើម (Home)';
      case VoiceCommandType.requests:
        return 'ការស្នើ (Requests)';
      case VoiceCommandType.notifications:
        return 'ការជូនដំណឹង (Notifications)';
      case VoiceCommandType.chat:
        return 'ជជែក (Chat)';
      case VoiceCommandType.meetings:
        return 'ប្រជុំ (Meetings)';
      case VoiceCommandType.checklist:
        return 'កិច្ចការ (Checklist)';
      case VoiceCommandType.profile:
        return 'ព័ត៌មានខ្ញុំ (Profile)';
      case VoiceCommandType.mission:
        return 'បេសកកម្ម (Mission)';
      case VoiceCommandType.dailyReport:
        return 'របាយការណ៍ (Report)';
      case VoiceCommandType.calendar:
        return 'ប្រតិទិន (Calendar)';
      case VoiceCommandType.training:
        return 'ហ្វឹកហ្វឺន (Training)';
      case VoiceCommandType.productAnalyzer:
        return 'វិភាគផលិតផល (Product Analyzer)';
      case VoiceCommandType.trip:
        return 'ដំណើរ (Trip)';
      case VoiceCommandType.payroll:
        return 'ប្រាក់ខែ (Payroll)';
      case VoiceCommandType.unknown:
        return 'មិនស្គាល់';
    }
  }

  /// All supported commands shown in the hint list
  static const List<Map<String, String>> commandHints = [
    {'km': 'ស្កេនចូល', 'en': 'Scan In / Check-In'},
    {'km': 'ស្កេនចេញ', 'en': 'Scan Out / Check-Out'},
    {'km': 'វត្តមានក្រៅ', 'en': 'Outside Attendance'},
    {'km': 'ការស្នើ', 'en': 'Requests / Leave'},
    {'km': 'ជជែក / សារ', 'en': 'Chat / Messages'},
    {'km': 'ការប្រជុំ', 'en': 'Meetings'},
    {'km': 'វិភាគផលិតផល', 'en': 'Product Analyzer'},
    {'km': 'ប្រតិទិន', 'en': 'Khmer Calendar'},
    {'km': 'ប្រាក់ខែ', 'en': 'Payroll / Salary'},
    {'km': 'ព័ត៌មានខ្ញុំ', 'en': 'Profile / Settings'},
    {'km': 'ការជូនដំណឹង', 'en': 'Notifications'},
  ];
}
