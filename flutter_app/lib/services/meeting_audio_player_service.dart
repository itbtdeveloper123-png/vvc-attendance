import 'dart:async';

import 'package:audioplayers/audioplayers.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

class MeetingAudioPlayerService extends ChangeNotifier {
  MeetingAudioPlayerService._internal();

  static final MeetingAudioPlayerService instance =
      MeetingAudioPlayerService._internal();

  static const MethodChannel _channel = MethodChannel(
    'app.vvc/meeting_playback',
  );

  final AudioPlayer player = AudioPlayer();

  bool _initialized = false;
  bool _isLoading = false;
  bool _isPlaying = false;
  bool _isActive = false;
  String? _currentPath;
  String? _currentTitle;
  double _playbackSpeed = 1.0;
  Duration _duration = Duration.zero;
  Duration _position = Duration.zero;
  Timer? _androidPollTimer;

  bool get isLoading => _isLoading;
  bool get isPlaying => _isPlaying;
  bool get isActive => _isActive;
  String? get currentPath => _currentPath;
  String? get currentTitle => _currentTitle;
  double get playbackSpeed => _playbackSpeed;
  Duration get duration => _duration;
  Duration get position => _position;

  bool get _useNativeAndroid =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  Future<void> initialize() async {
    if (_initialized) {
      return;
    }

    if (_useNativeAndroid) {
      await _syncAndroidState();
      _initialized = true;
      return;
    }

    await player.setPlayerMode(PlayerMode.mediaPlayer);
    await player.setReleaseMode(ReleaseMode.stop);
    await player.setAudioContext(
      AudioContextConfig(
        stayAwake: true,
        focus: AudioContextConfigFocus.gain,
      ).build(),
    );

    player.onPlayerComplete.listen((_) {
      _isPlaying = false;
      _isActive = false;
      _position = Duration.zero;
      notifyListeners();
    });
    player.onPlayerStateChanged.listen((state) {
      _isPlaying = state == PlayerState.playing;
      if (state == PlayerState.playing || state == PlayerState.paused) {
        _isActive = _currentPath != null;
      } else if (state == PlayerState.stopped ||
          state == PlayerState.completed) {
        _isActive = false;
      }
      notifyListeners();
    });
    player.onDurationChanged.listen((duration) {
      _duration = duration;
      notifyListeners();
    });
    player.onPositionChanged.listen((position) {
      _position = position;
      notifyListeners();
    });

    _initialized = true;
  }

  Future<void> playPath(
    String path, {
    String? title,
    bool forceRemote = false,
    String? displayPath,
  }) async {
    await initialize();

    _isLoading = true;
    _currentPath = displayPath ?? path;
    _currentTitle = title;
    _position = Duration.zero;
    _duration = Duration.zero;
    _isActive = true;
    notifyListeners();

    try {
      if (_useNativeAndroid) {
        await _channel.invokeMethod<void>('play', {
          'path': path,
          'title': title ?? '',
          'displayPath': displayPath ?? path,
          'forceRemote': forceRemote,
        });
        _startAndroidPolling();
        await _syncAndroidState();
        return;
      }

      final source = _resolveSource(path, forceRemote: forceRemote);
      await player.setSource(source);
      await player.setPlaybackRate(_playbackSpeed);
      await player.resume();
      _isPlaying = true;
      _isActive = true;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  Future<void> pause() async {
    await initialize();
    if (_useNativeAndroid) {
      await _channel.invokeMethod<void>('pause');
      await _syncAndroidState();
      return;
    }
    await player.pause();
    _isPlaying = false;
    notifyListeners();
  }

  Future<void> resume() async {
    await initialize();
    if (_useNativeAndroid) {
      await _channel.invokeMethod<void>('resume');
      _startAndroidPolling();
      await _syncAndroidState();
      return;
    }
    await player.resume();
    _isPlaying = true;
    notifyListeners();
  }

  Future<void> stop() async {
    await initialize();
    if (_useNativeAndroid) {
      await _channel.invokeMethod<void>('stop');
      await _syncAndroidState();
      _stopAndroidPolling();
      return;
    }

    await player.stop();
    _resetState(clearSpeed: false);
    notifyListeners();
  }

  Future<void> seek(Duration position) async {
    await initialize();
    if (_useNativeAndroid) {
      await _channel.invokeMethod<void>('seek', {
        'positionMs': position.inMilliseconds,
      });
      await _syncAndroidState();
      return;
    }
    await player.seek(position);
    _position = position;
    notifyListeners();
  }

  Future<void> setPlaybackSpeed(double speed) async {
    await initialize();
    _playbackSpeed = speed;
    if (_useNativeAndroid) {
      await _channel.invokeMethod<void>('setSpeed', {'speed': speed});
      await _syncAndroidState();
      return;
    }
    await player.setPlaybackRate(speed);
    notifyListeners();
  }

  void _startAndroidPolling() {
    _androidPollTimer?.cancel();
    _androidPollTimer = Timer.periodic(const Duration(milliseconds: 500), (_) {
      unawaited(_syncAndroidState());
    });
  }

  void _stopAndroidPolling() {
    _androidPollTimer?.cancel();
    _androidPollTimer = null;
  }

  Future<void> _syncAndroidState() async {
    if (!_useNativeAndroid) {
      return;
    }

    try {
      final dynamic result = await _channel.invokeMethod<dynamic>(
        'getPlaybackState',
      );
      if (result is! Map) {
        return;
      }

      final map = Map<dynamic, dynamic>.from(result);
      _isActive = map['active'] == true;
      _isPlaying = map['isPlaying'] == true;
      _isLoading = map['isLoading'] == true;
      _currentPath = _asString(map['currentPath']);
      _currentTitle = _asString(map['currentTitle']);
      _playbackSpeed = _asDouble(
        map['playbackSpeed'],
        fallback: _playbackSpeed,
      );
      _duration = Duration(milliseconds: _asInt(map['durationMs']));
      _position = Duration(milliseconds: _asInt(map['positionMs']));

      if (!_isActive && !_isPlaying) {
        _stopAndroidPolling();
      }

      notifyListeners();
    } catch (_) {}
  }

  void _resetState({bool clearSpeed = false}) {
    _isLoading = false;
    _isPlaying = false;
    _isActive = false;
    _currentPath = null;
    _currentTitle = null;
    _duration = Duration.zero;
    _position = Duration.zero;
    if (clearSpeed) {
      _playbackSpeed = 1.0;
    }
  }

  static int _asInt(dynamic value) {
    if (value is int) {
      return value;
    }
    if (value is num) {
      return value.toInt();
    }
    return int.tryParse(value?.toString() ?? '') ?? 0;
  }

  static double _asDouble(dynamic value, {double fallback = 1.0}) {
    if (value is double) {
      return value;
    }
    if (value is num) {
      return value.toDouble();
    }
    return double.tryParse(value?.toString() ?? '') ?? fallback;
  }

  static String? _asString(dynamic value) {
    final text = value?.toString();
    if (text == null || text.isEmpty || text == 'null') {
      return null;
    }
    return text;
  }

  Source _resolveSource(String path, {bool forceRemote = false}) {
    final isRemote =
        forceRemote ||
        path.startsWith('http://') ||
        path.startsWith('https://') ||
        path.startsWith('blob:');
    if (kIsWeb || isRemote) {
      return UrlSource(path);
    }
    return DeviceFileSource(path);
  }
}
