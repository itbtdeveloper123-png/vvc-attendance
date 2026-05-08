import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

class MeetingRecordingState {
  const MeetingRecordingState({
    this.active = false,
    this.isRecording = false,
    this.isPaused = false,
    this.activePath,
    this.elapsedMs = 0,
    this.lastCompletedPath,
    this.lastCompletedDurationMs = 0,
  });

  final bool active;
  final bool isRecording;
  final bool isPaused;
  final String? activePath;
  final int elapsedMs;
  final String? lastCompletedPath;
  final int lastCompletedDurationMs;

  bool get hasCompletedRecording =>
      (lastCompletedPath != null && lastCompletedPath!.isNotEmpty);

  static const empty = MeetingRecordingState();

  factory MeetingRecordingState.fromMap(Map<dynamic, dynamic>? map) {
    if (map == null) {
      return empty;
    }

    int asInt(dynamic value) {
      if (value is int) return value;
      if (value is num) return value.toInt();
      return int.tryParse(value?.toString() ?? '') ?? 0;
    }

    bool asBool(dynamic value) {
      if (value is bool) return value;
      if (value is num) return value != 0;
      final text = (value?.toString() ?? '').toLowerCase();
      return text == 'true' || text == '1';
    }

    String? asString(dynamic value) {
      final text = value?.toString().trim() ?? '';
      return text.isEmpty ? null : text;
    }

    return MeetingRecordingState(
      active: asBool(map['active']),
      isRecording: asBool(map['isRecording']),
      isPaused: asBool(map['isPaused']),
      activePath: asString(map['activePath']),
      elapsedMs: asInt(map['elapsedMs']),
      lastCompletedPath: asString(map['lastCompletedPath']),
      lastCompletedDurationMs: asInt(map['lastCompletedDurationMs']),
    );
  }
}

class MeetingRecordingService {
  static const MethodChannel _channel = MethodChannel(
    'app.vvc/meeting_recording',
  );

  static bool get isSupported => !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  static Future<MeetingRecordingState> getState() async {
    if (!isSupported) {
      return MeetingRecordingState.empty;
    }
    final result = await _channel.invokeMethod<dynamic>('getState');
    if (result is Map) {
      return MeetingRecordingState.fromMap(result);
    }
    return MeetingRecordingState.empty;
  }

  static Future<MeetingRecordingState> startRecording(String path) async {
    if (!isSupported) {
      return MeetingRecordingState.empty;
    }
    await _channel.invokeMethod<void>('startRecording', {'path': path});
    await Future<void>.delayed(const Duration(milliseconds: 250));
    return getState();
  }

  static Future<MeetingRecordingState> pauseRecording() async {
    if (!isSupported) {
      return MeetingRecordingState.empty;
    }
    await _channel.invokeMethod<void>('pauseRecording');
    await Future<void>.delayed(const Duration(milliseconds: 150));
    return getState();
  }

  static Future<MeetingRecordingState> resumeRecording() async {
    if (!isSupported) {
      return MeetingRecordingState.empty;
    }
    await _channel.invokeMethod<void>('resumeRecording');
    await Future<void>.delayed(const Duration(milliseconds: 150));
    return getState();
  }

  static Future<MeetingRecordingState> stopRecording() async {
    if (!isSupported) {
      return MeetingRecordingState.empty;
    }
    await _channel.invokeMethod<void>('stopRecording');
    await Future<void>.delayed(const Duration(milliseconds: 250));
    return getState();
  }

  static Future<void> clearLastCompleted() async {
    if (!isSupported) {
      return;
    }
    await _channel.invokeMethod<void>('clearLastCompleted');
  }

  static Future<void> discardLastCompleted({String? path}) async {
    if (!isSupported) {
      return;
    }
    await _channel.invokeMethod<void>('discardLastCompleted', {'path': path});
  }
}
