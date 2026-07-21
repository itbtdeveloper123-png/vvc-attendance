import 'dart:async';

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
  bool _continuousMode = false;
  bool _manualStopRequested = false;
  bool _sessionStarting = false;
  Timer? _restartTimer;
  String? _resolvedLocaleId;
  String _requestedLocaleId = 'km-KH';

  void Function(VoiceCommand command)? _activeResultHandler;
  void Function(bool isListening)? _activeListeningHandler;

  bool get isInitialized => _isInitialized;
  bool get isListening => _isListening;
  bool get isContinuousMode => _continuousMode;
  bool get isAvailable => _isInitialized && _speechToText.isAvailable;
  String get lastRecognizedWords => _speechToText.lastRecognizedWords;

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
        onError: _handleSpeechError,
        onStatus: _handleSpeechStatus,
        finalTimeout: const Duration(milliseconds: 900),
      );
      debugPrint('[Voice] Initialized: $_isInitialized');
    } catch (e) {
      debugPrint('[Voice] Init error: $e');
      _isInitialized = false;
    }
    return _isInitialized;
  }

  void _setListening(bool value) {
    if (_isListening == value) return;
    _isListening = value;
    _activeListeningHandler?.call(value);
  }

  void _handleSpeechStatus(String status) {
    debugPrint('[Voice] STT Status: $status');
    if (status == SpeechToText.listeningStatus) {
      _setListening(true);
      return;
    }

    if (status == SpeechToText.notListeningStatus ||
        status == SpeechToText.doneStatus) {
      _setListening(false);
      if (_continuousMode && !_manualStopRequested) {
        _scheduleContinuousRestart(delay: const Duration(milliseconds: 450));
      }
    }
  }

  void _handleSpeechError(dynamic error) {
    final errorMsg = (error.errorMsg ?? '').toString();
    final permanent = error.permanent == true;
    debugPrint('[Voice] STT Error: $errorMsg');
    _setListening(false);

    if (_shouldRetryAfterError(errorMsg, permanent)) {
      _scheduleContinuousRestart(delay: const Duration(milliseconds: 900));
    }
  }

  bool _shouldRetryAfterError(String errorMsg, bool permanent) {
    if (!_continuousMode || _manualStopRequested) return false;
    if (!permanent) return true;

    const retryablePermanentErrors = [
      'error_no_match',
      'error_speech_timeout',
      'error_retry',
      'error_network_timeout',
      'error_server_disconnected',
      'error_busy',
    ];
    return retryablePermanentErrors.any(errorMsg.contains);
  }

  void _scheduleContinuousRestart({
    Duration delay = const Duration(milliseconds: 650),
  }) {
    if (!_continuousMode || _manualStopRequested || _sessionStarting) return;

    _restartTimer?.cancel();
    _restartTimer = Timer(delay, () {
      if (!_continuousMode || _manualStopRequested) return;
      _beginListenCycle();
    });
  }

  Future<String?> _resolveLocaleId(String localeId) async {
    if (_resolvedLocaleId != null) return _resolvedLocaleId;

    try {
      final locales = await _speechToText.locales();
      if (locales.isEmpty) return null;

      String normalize(String value) => value.replaceAll('_', '-').toLowerCase();
      final requested = normalize(localeId);

      for (final locale in locales) {
        if (normalize(locale.localeId) == requested) {
          _resolvedLocaleId = locale.localeId;
          return _resolvedLocaleId;
        }
      }

      for (final locale in locales) {
        if (normalize(locale.localeId).startsWith('km')) {
          _resolvedLocaleId = locale.localeId;
          return _resolvedLocaleId;
        }
      }
    } catch (e) {
      debugPrint('[Voice] Locale resolution error: $e');
    }

    return null;
  }

  // ─── Listen Methods ────────────────────────────────────────────────────────

  /// Single-shot listen. Calls [onResult] when text is recognized and finalized.
  /// Calls [onListeningChanged] whenever the listening state changes.
  Future<void> startListening({
    required void Function(VoiceCommand command) onResult,
    void Function(bool isListening)? onListeningChanged,
    String localeId = 'km-KH',
  }) async {
    if (!_isInitialized) {
      final ok = await initialize();
      if (!ok) return;
    }

    _continuousMode = false;
    _manualStopRequested = false;
    _activeResultHandler = onResult;
    _activeListeningHandler = onListeningChanged;
    _requestedLocaleId = localeId;

    final targetLocale = await _resolveLocaleId(localeId);

    _setListening(true);

    try {
      await _speechToText.listen(
        listenOptions: SpeechListenOptions(
          localeId: targetLocale,
          listenFor: const Duration(seconds: 10),
          pauseFor: const Duration(seconds: 2),
          listenMode: ListenMode.confirmation,
          cancelOnError: true,
        ),
        onResult: (result) {
          final text = result.recognizedWords.toLowerCase().trim();
          final command = _matchCommand(text, result.confidence);

          if (result.finalResult) {
            _setListening(false);
            _activeResultHandler?.call(command);
          }
        },
      );
    } catch (e) {
      debugPrint('[Voice] startListening error: $e');
      _setListening(false);
    }
  }

  /// Continuous listening mode. Automatically restarts after pause or error.
  Future<void> startContinuousListening({
    required void Function(VoiceCommand command) onResult,
    void Function(bool isListening)? onListeningChanged,
    String localeId = 'km-KH',
  }) async {
    if (!_isInitialized) {
      final ok = await initialize();
      if (!ok) return;
    }

    _continuousMode = true;
    _manualStopRequested = false;
    _activeResultHandler = onResult;
    _activeListeningHandler = onListeningChanged;
    _requestedLocaleId = localeId;

    await _beginListenCycle();
  }

  /// Internal worker method for continuous listening cycles
  Future<void> _beginListenCycle() async {
    if (!_continuousMode || _manualStopRequested || _sessionStarting) return;
    if (_speechToText.isListening) return;

    _sessionStarting = true;
    final targetLocale = await _resolveLocaleId(_requestedLocaleId);

    try {
      await _speechToText.listen(
        listenOptions: SpeechListenOptions(
          localeId: targetLocale,
          listenFor: const Duration(seconds: 30),
          pauseFor: const Duration(seconds: 3),
          listenMode: ListenMode.dictation,
          cancelOnError: false,
          partialResults: true,
        ),
        onResult: (result) {
          final text = result.recognizedWords.toLowerCase().trim();
          final command = _matchCommand(text, result.confidence);

          if (command.type != VoiceCommandType.unknown || result.finalResult) {
            _activeResultHandler?.call(command);
          }
        },
      );
    } catch (e) {
      debugPrint('[Voice] _beginListenCycle error: $e');
      _scheduleContinuousRestart(delay: const Duration(seconds: 1));
    } finally {
      _sessionStarting = false;
    }
  }

  Future<void> stopListening() async {
    _continuousMode = false;
    _manualStopRequested = true;
    _restartTimer?.cancel();

    if (_isListening || _speechToText.isListening) {
      await _speechToText.stop();
      _setListening(false);
    }
  }

  Future<void> cancelListening() async {
    _continuousMode = false;
    _manualStopRequested = true;
    _restartTimer?.cancel();

    await _speechToText.cancel();
    _setListening(false);
  }

  void dispose() {
    _continuousMode = false;
    _manualStopRequested = true;
    _restartTimer?.cancel();
    _speechToText.stop();
    _activeResultHandler = null;
    _activeListeningHandler = null;
    _setListening(false);
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

    // Clean text: strip special punctuation while keeping Khmer and English characters
    final cleanedText = text.replaceAll(RegExp(r'[^\w\s\u1780-\u17FF]'), ' ').toLowerCase().trim();

    VoiceCommandType bestType = VoiceCommandType.unknown;
    int bestScore = 0;

    for (final entry in _commandKeywords.entries) {
      for (final keyword in entry.value) {
        final k = keyword.toLowerCase().trim();
        // Check if the recognized text contains this keyword
        if (cleanedText.contains(k) || text.contains(k)) {
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
