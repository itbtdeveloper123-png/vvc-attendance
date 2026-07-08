import 'dart:convert';
import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:animate_do/animate_do.dart';
import 'package:file_picker/file_picker.dart';
import 'package:image_picker/image_picker.dart';
import 'package:record/record.dart';
import 'package:audioplayers/audioplayers.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:intl/intl.dart';
import 'package:path/path.dart' as p;
import 'dart:io' as io; // Use alias to avoid web crash where possible
import '../services/api_service.dart';
import '../services/meeting_audio_draft_service.dart';
import '../services/meeting_audio_player_service.dart';
import '../services/meeting_recording_service.dart';
import '../utils/app_theme.dart';
import '../providers/user_provider.dart';
import '../widgets/app_widgets.dart';

class MeetingsScreen extends StatefulWidget {
  const MeetingsScreen({super.key});

  @override
  State<MeetingsScreen> createState() => _MeetingsScreenState();
}

class _MeetingsScreenState extends State<MeetingsScreen>
    with SingleTickerProviderStateMixin, WidgetsBindingObserver {
  late TabController _tabController;
  final ApiService _api = ApiService();
  final AudioRecorder _recorder = AudioRecorder();
  final MeetingAudioPlayerService _audioPlayerService =
      MeetingAudioPlayerService.instance;
  final ImagePicker _picker = ImagePicker();

  AudioPlayer get _audioPlayer => _audioPlayerService.player;

  // Form states
  final _formKey = GlobalKey<FormState>();
  final _topicController = TextEditingController();
  final _deptController = TextEditingController();
  final _dateController = TextEditingController(
    text: DateFormat('yyyy-MM-dd').format(DateTime.now()),
  );
  final _descController = TextEditingController();
  final _urlController = TextEditingController();

  String? _recordedPath;
  Uint8List? _selectedAudioBytes;
  String? _selectedAudioName;
  bool _isUploadedAudio = false;
  String? _selectedDraftId;
  bool _isRecording = false;
  bool _isRecordingPaused = false;
  List<XFile> _selectedPhotos = [];
  bool _isSubmitting = false;
  Timer? _recordingStateTimer;
  List<MeetingAudioDraft> _audioDrafts = [];
  bool _isLoadingDrafts = true;

  // List states
  List<dynamic> _meetingsList = [];
  bool _isLoadingList = true;

  // Recording info
  String _recordingDuration = "00:00";
  String _fileSize = "";
  DateTime? _recordingStartTime;

  // Audio Player state
  Duration _duration = Duration.zero;
  Duration _position = Duration.zero;
  double _playbackSpeed = 1.0;
  bool _isPlaying = false;
  bool _isPlayerLoading = false;
  String? _currentlyPlayingPath;

  StreamSubscription<Duration>? _durationSub;
  StreamSubscription<Duration>? _positionSub;
  StreamSubscription<PlayerState>? _playerStateSub;
  StreamSubscription<void>? _playerCompleteSub;
  VoidCallback? _playerServiceListener;

  // AI Summary State
  bool _isSummarizing = false;
  String? _currentAISummary;
  String? _currentTranscript;
  Map<String, dynamic>? _currentAIAnalysis;
  String? _currentSummaryError;
  String? _currentSummaryStatusMessage;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    final user = Provider.of<UserProvider>(context, listen: false);
    // User requested: HRM app listen only (1 tab), others show full (2 tabs)
    _tabController = TabController(
      length: (user.isHRM && !user.isAdmin) ? 1 : 2,
      vsync: this,
    );
    _loadMeetings();
    _loadAudioDrafts();

    unawaited(_audioPlayerService.initialize());
    _playerServiceListener = () {
      if (!mounted) return;
      setState(() {
        _currentlyPlayingPath = _audioPlayerService.currentPath;
        _isPlayerLoading = _audioPlayerService.isLoading;
        _playbackSpeed = _audioPlayerService.playbackSpeed;
        _duration = _audioPlayerService.duration;
        _position = _audioPlayerService.position;
        _isPlaying = _audioPlayerService.isPlaying;
      });
    };
    _audioPlayerService.addListener(_playerServiceListener!);
    _currentlyPlayingPath = _audioPlayerService.currentPath;
    _isPlayerLoading = _audioPlayerService.isLoading;
    _playbackSpeed = _audioPlayerService.playbackSpeed;
    _duration = _audioPlayerService.duration;
    _position = _audioPlayerService.position;
    _isPlaying = _audioPlayerService.isPlaying;

    // Setup player listeners
    _durationSub = _audioPlayer.onDurationChanged.listen((d) {
      if (mounted) setState(() => _duration = d);
    });
    _positionSub = _audioPlayer.onPositionChanged.listen((p) {
      if (mounted) setState(() => _position = p);
    });
    _playerStateSub = _audioPlayer.onPlayerStateChanged.listen((s) {
      if (mounted) {
        setState(() {
          _isPlaying = s == PlayerState.playing;
        });
      }
    });
    _playerCompleteSub = _audioPlayer.onPlayerComplete.listen((_) {
      if (mounted) {
        setState(() {
          _isPlaying = false;
          _position = Duration.zero;
        });
      }
    });

    _syncRecordingState();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _recordingStateTimer?.cancel();
    _durationSub?.cancel();
    _positionSub?.cancel();
    _playerStateSub?.cancel();
    _playerCompleteSub?.cancel();
    if (_playerServiceListener != null) {
      _audioPlayerService.removeListener(_playerServiceListener!);
    }
    _tabController.dispose();
    _topicController.dispose();
    _deptController.dispose();
    _dateController.dispose();
    _descController.dispose();
    _urlController.dispose();
    _recorder.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _syncRecordingState();
    }
  }

  Future<void> _generateAISummary(
    Map<String, dynamic> meeting,
    StateSetter modalSetState, {
    bool force = false,
  }) async {
    try {
      final int meetingId = int.parse(meeting['id'].toString());
      modalSetState(() {
        _isSummarizing = true;
        _currentSummaryError = null;
        _currentSummaryStatusMessage = "កំពុងចាប់ផ្តើមការសង្ខេបដោយ AI...";
      });
      Map<String, dynamic> resp = await _api.summarizeMeeting(
        meetingId,
        force: force,
      );
      if ((resp['success'] == true) && (resp['processing'] == true)) {
        modalSetState(() {
          _currentSummaryStatusMessage =
              resp['message']?.toString().trim().isNotEmpty == true
              ? resp['message']!.toString()
              : "កំពុងបម្លែងសំឡេង និងសង្ខេបដោយ AI...\nសូមរង់ចាំបន្តិច";
        });
        resp = await _waitForAISummaryResult(meetingId, modalSetState);
      }
      if (resp['success']) {
        modalSetState(() {
          _currentAISummary = resp['summary'];
          _currentTranscript = resp['transcript']?.toString();
          _currentAIAnalysis = _parseAnalysisData(resp['analysis']);
          meeting['summary'] = resp['summary'];
          meeting['transcript_text'] = resp['transcript'];
          meeting['summary_json'] = jsonEncode(_currentAIAnalysis ?? {});
          meeting['summary_generated_at'] = resp['generated_at'];
          _currentSummaryError = null;
          _currentSummaryStatusMessage = null;
          _isSummarizing = false;
        });
      } else {
        throw resp['message'] ?? 'Failed';
      }
    } catch (e) {
      final friendly = _friendlySummaryError(e.toString());
      modalSetState(() {
        _isSummarizing = false;
        _currentSummaryError = friendly;
        _currentSummaryStatusMessage = null;
      });
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(friendly)));
      }
    }
  }

  Future<Map<String, dynamic>> _waitForAISummaryResult(
    int meetingId,
    StateSetter modalSetState,
  ) async {
    const deadline = Duration(hours: 2);
    final startedAt = DateTime.now();

    while (DateTime.now().difference(startedAt) < deadline) {
      await Future.delayed(const Duration(seconds: 4));
      final statusResp = await _api.getMeetingSummaryStatus(meetingId);

      if ((statusResp['success'] == true) &&
          (statusResp['processing'] == true)) {
        modalSetState(() {
          _currentSummaryStatusMessage =
              statusResp['message']?.toString().trim().isNotEmpty == true
              ? statusResp['message']!.toString()
              : "កំពុងបម្លែងសំឡេង និងសង្ខេបដោយ AI...\nសូមរង់ចាំបន្តិច";
        });
        continue;
      }

      return statusResp;
    }

    return {
      'success': false,
      'message':
          'ការសង្ខេបដោយ AI កំពុងដំណើរការយូរ។ អ្នកអាចបិទផ្ទាំងនេះសិន ហើយត្រឡប់មកពិនិត្យម្តងទៀតក្រោយបន្តិច។',
    };
  }

  void _copyToClipboard(String text) {
    Clipboard.setData(ClipboardData(text: text));
    if (mounted) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text("ចម្លងអត្ថបទបានជោគជ័យ!")));
    }
  }

  Map<String, dynamic>? _parseAnalysisData(dynamic raw) {
    if (raw is Map<String, dynamic>) {
      return raw;
    }
    if (raw is Map) {
      return Map<String, dynamic>.from(raw);
    }
    if (raw is String && raw.trim().isNotEmpty) {
      try {
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) {
          return decoded;
        }
        if (decoded is Map) {
          return Map<String, dynamic>.from(decoded);
        }
      } catch (_) {}
    }
    return null;
  }

  String _friendlySummaryError(String raw) {
    final text = raw.replaceFirst('Exception: ', '').trim();
    if (text.contains('Request Entity Too Large') ||
        text.contains('ឯកសារសំឡេងធំពេក')) {
      return 'ឯកសារសំឡេងធំពេកសម្រាប់ AI សង្ខេប។ សូមបង្រួមជា MP3/M4A ឬបំបែកសំឡេងជាផ្នែកតូចៗ មុនសិន។';
    }
    if (text.contains('Compressed audio is still too large')) {
      return 'ប្រព័ន្ធបានព្យាយាមបង្រួមសំឡេងរួចហើយ ប៉ុន្តែឯកសារនៅតែធំពេក។ សូមកាត់សម្លេងជាផ្នែកតូចៗ មុនសិន។';
    }
    if (text.contains('Audio compression failed')) {
      return 'ប្រព័ន្ធមិនអាចបង្រួមសំឡេងដោយស្វ័យប្រវត្តិបានទេ។ សូមបម្លែងជា MP3/M4A ឬទាក់ទងឲ្យ server ដំឡើង ffmpeg។';
    }
    if (text.contains('Audio transcription provider is not configured')) {
      return 'Server មិនទាន់កំណត់ transcription provider សម្រាប់មុខងារនេះទេ។';
    }
    if (text.contains('Meeting audio file not found on server')) {
      return 'រកមិនឃើញឯកសារសំឡេងលើ server ទេ។ សូម upload សារជាថ្មី។';
    }
    if (text.contains('No transcript text could be created')) {
      return 'មិនអាចបម្លែងសំឡេងទៅជាអត្ថបទបានទេ។';
    }
    return text;
  }

  List<String> _analysisList(dynamic value) {
    if (value is! List) {
      return const [];
    }
    return value
        .map((item) => item.toString().trim())
        .where((item) => item.isNotEmpty)
        .toList();
  }

  String _buildInsightCopyText() {
    final analysis = _currentAIAnalysis ?? const <String, dynamic>{};
    final buffer = StringBuffer();

    final headline = (analysis['headline'] ?? '').toString().trim();
    final overview = (analysis['overview'] ?? '').toString().trim();

    if (headline.isNotEmpty) {
      buffer.writeln(headline);
      buffer.writeln();
    }
    if (overview.isNotEmpty) {
      buffer.writeln('សេចក្តីសង្ខេប');
      buffer.writeln(overview);
      buffer.writeln();
    }

    const labels = <String, String>{
      'key_points': 'ចំណុចសំខាន់ៗ',
      'decisions': 'សេចក្តីសម្រេច',
      'action_items': 'ការងារត្រូវអនុវត្ត',
      'next_steps': 'ជំហានបន្ទាប់',
      'keywords': 'ពាក្យគន្លឹះ',
    };

    for (final entry in labels.entries) {
      final items = _analysisList(analysis[entry.key]);
      if (items.isEmpty) {
        continue;
      }
      buffer.writeln(entry.value);
      for (final item in items) {
        buffer.writeln('- $item');
      }
      buffer.writeln();
    }

    final transcript = (_currentTranscript ?? '').trim();
    if (transcript.isNotEmpty) {
      buffer.writeln('Transcript');
      buffer.writeln(transcript);
    }

    final text = buffer.toString().trim();
    return text.isNotEmpty ? text : (_currentAISummary ?? '');
  }

  Future<void> _pickAudioFile() async {
    if (_isSubmitting || _isRecording || _isRecordingPaused) {
      return;
    }

    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowMultiple: false,
        withData: kIsWeb,
        allowedExtensions: const ['mp3', 'wav', 'm4a', 'aac', 'ogg', 'webm'],
      );

      final file = (result != null && result.files.isNotEmpty)
          ? result.files.first
          : null;
      if (file == null) {
        return;
      }

      final fileName = file.name.trim().isEmpty ? 'meeting_audio' : file.name;
      final fileSize = file.size > 0 ? _formatDraftFileSize(file.size) : '';

      setState(() {
        _selectedDraftId = null;
        _recordedPath = file.path;
        _selectedAudioBytes = file.bytes;
        _selectedAudioName = fileName;
        _isUploadedAudio = true;
        _recordingDuration = 'Upload';
        _fileSize = fileSize;
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('បានជ្រើសឯកសារសំឡេង៖ $fileName')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('មិនអាចជ្រើសឯកសារសំឡេងបានទេ: $e')),
        );
      }
    }
  }

  Future<void> _loadMeetings() async {
    setState(() => _isLoadingList = true);
    try {
      final res = await _api.fetchMeetings();
      if (res['status'] == 'success') {
        // Support both 'meetings' and 'data' response keys
        final list = res['meetings'] ?? res['data'] ?? [];
        setState(() {
          _meetingsList = list is List ? list : [];
          _isLoadingList = false;
        });
      } else {
        setState(() => _isLoadingList = false);
      }
    } catch (e) {
      setState(() => _isLoadingList = false);
    }
  }

  // ========== AUDIO RECORDING ==========
  bool get _usesNativeBackgroundRecording =>
      MeetingRecordingService.isSupported;

  String _formatRecordingDuration(Duration duration) {
    final totalSeconds = duration.inSeconds;
    final hours = totalSeconds ~/ 3600;
    final minutes = (totalSeconds % 3600) ~/ 60;
    final seconds = totalSeconds % 60;
    if (hours > 0) {
      return "${hours.toString().padLeft(2, '0')}:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}";
    }
    return "${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}";
  }

  void _applyNativeRecordingState(MeetingRecordingState state) {
    final completedPath = state.hasCompletedRecording
        ? state.lastCompletedPath
        : null;

    if (completedPath != null) {
      _updateRecordingInfo(completedPath);
    }

    if (!mounted) return;
    setState(() {
      _isRecording = state.isRecording;
      _isRecordingPaused = state.isPaused;
      _recordingDuration = _formatRecordingDuration(
        Duration(milliseconds: state.elapsedMs),
      );

      if (completedPath != null) {
        _recordedPath = completedPath;
        _selectedDraftId = null;
        _selectedAudioBytes = null;
        _selectedAudioName = null;
        _isUploadedAudio = false;
      } else if (state.active) {
        _recordedPath = null;
        _selectedDraftId = null;
        _selectedAudioBytes = null;
        _selectedAudioName = null;
        _isUploadedAudio = false;
      }
    });

    if (state.active) {
      _startRecordingStatePolling();
    } else {
      _recordingStateTimer?.cancel();
    }
  }

  Future<void> _syncRecordingState() async {
    if (!_usesNativeBackgroundRecording) return;
    try {
      final state = await MeetingRecordingService.getState();
      _applyNativeRecordingState(state);
    } catch (e) {
      debugPrint("Meeting recording sync error: $e");
    }
  }

  void _startRecordingStatePolling() {
    _recordingStateTimer?.cancel();
    _recordingStateTimer = Timer.periodic(const Duration(seconds: 1), (
      _,
    ) async {
      if (!mounted) return;
      if (!_isRecording && !_isRecordingPaused) {
        _recordingStateTimer?.cancel();
        return;
      }
      await _syncRecordingState();
    });
  }

  Future<bool> _requestRecordingPermissions() async {
    if (kIsWeb) return true;

    final micPermission = await Permission.microphone.request();
    if (!micPermission.isGranted) {
      return false;
    }

    final notificationPermission = await Permission.notification.request();
    return notificationPermission.isGranted ||
        notificationPermission.isLimited ||
        notificationPermission.isProvisional;
  }

  Future<void> _startNativeBackgroundRecording() async {
    final hasPermission = await _requestRecordingPermissions();
    if (!hasPermission) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('សូមអនុញ្ញាត Microphone មុនពេលចាប់ផ្តើមថត'),
          ),
        );
      }
      if (mounted) {
        ScaffoldMessenger.of(context)
          ..hideCurrentSnackBar()
          ..showSnackBar(
            const SnackBar(
              content: Text(
                'សូមអនុញ្ញាត Microphone និង Notifications មុនចាប់ផ្តើមថត',
              ),
            ),
          );
      }
      return;
    }

    final dir = await getApplicationCacheDirectory();
    final path = p.join(
      dir.path,
      'meeting_rec_${DateTime.now().millisecondsSinceEpoch}.m4a',
    );

    final state = await MeetingRecordingService.startRecording(path);
    _fileSize = "";
    _applyNativeRecordingState(state);
  }

  Future<void> _pauseNativeBackgroundRecording() async {
    final state = await MeetingRecordingService.pauseRecording();
    _applyNativeRecordingState(state);
  }

  Future<void> _resumeNativeBackgroundRecording() async {
    final state = await MeetingRecordingService.resumeRecording();
    _applyNativeRecordingState(state);
  }

  Future<void> _stopNativeBackgroundRecording() async {
    final state = await MeetingRecordingService.stopRecording();
    _applyNativeRecordingState(state);
    if (state.hasCompletedRecording && state.lastCompletedPath != null) {
      await _saveCurrentRecordingToDraft();
    }
  }

  Future<void> _discardRecordedAudio() async {
    final recordedPath = _recordedPath;
    final selectedDraftId = _selectedDraftId;

    if (selectedDraftId != null) {
      if (!mounted) return;
      setState(() {
        _recordedPath = null;
        _selectedDraftId = null;
        _recordingDuration = "00:00";
        _fileSize = "";
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('បានដក Draft ចេញពីជម្រើសរួចហើយ')),
      );
      return;
    }

    if (!_isUploadedAudio &&
        recordedPath != null &&
        !kIsWeb &&
        io.File(recordedPath).existsSync()) {
      try {
        await io.File(recordedPath).delete();
      } catch (_) {}
    }
    if (_usesNativeBackgroundRecording && !_isUploadedAudio) {
      await MeetingRecordingService.discardLastCompleted(path: recordedPath);
    }
    if (!mounted) return;
    setState(() {
      _recordedPath = null;
      _selectedDraftId = null;
      _selectedAudioBytes = null;
      _selectedAudioName = null;
      _isUploadedAudio = false;
      _recordingDuration = "00:00";
      _fileSize = "";
    });
  }

  Future<void> _toggleRecording() async {
    if (_usesNativeBackgroundRecording) {
      if (_isRecording || _isRecordingPaused) {
        await _stopNativeBackgroundRecording();
      } else {
        await _startNativeBackgroundRecording();
      }
      return;
    }

    if (_isRecording) {
      final path = await _recorder.stop();
      if (path != null) {
        _updateRecordingInfo(path);
      }
      setState(() {
        _isRecording = false;
        _recordedPath = path;
        _selectedAudioBytes = null;
        _selectedAudioName = null;
        _isUploadedAudio = false;
      });
      if (path != null) {
        await _saveCurrentRecordingToDraft();
      }
    } else {
      bool hasPermission = true;
      if (!kIsWeb) {
        hasPermission = await Permission.microphone.request().isGranted;
      }

      if (hasPermission) {
        String? path;

        if (!kIsWeb) {
          final dir = await getApplicationCacheDirectory();
          path = p.join(
            dir.path,
            'meeting_rec_${DateTime.now().millisecondsSinceEpoch}.m4a',
          );
        }

        // Speech-focused audio config:
        // 48kbps AAC mono at 32kHz keeps voice clear while reducing upload size a lot.
        const config = RecordConfig(
          encoder: AudioEncoder.aacLc,
          bitRate: 48000,
          sampleRate: 32000,
          numChannels: 1,
        );

        await _recorder.start(config, path: path ?? '');
        _recordingStartTime = DateTime.now();
        setState(() {
          _isRecording = true;
          _isRecordingPaused = false;
          _recordedPath = null;
          _selectedDraftId = null;
          _selectedAudioBytes = null;
          _selectedAudioName = null;
          _isUploadedAudio = false;
          _recordingDuration = "00:00";
        });

        // Track duration
        Future.doWhile(() async {
          if (!_isRecording) return false;
          await Future.delayed(const Duration(seconds: 1));
          if (mounted && _isRecording) {
            final diff = DateTime.now().difference(_recordingStartTime!);
            setState(() {
              _recordingDuration =
                  "${diff.inMinutes.toString().padLeft(2, '0')}:${(diff.inSeconds % 60).toString().padLeft(2, '0')}";
            });
          }
          return _isRecording;
        });
      }
    }
  }

  void _updateRecordingInfo(String path) {
    if (kIsWeb) {
      _fileSize = "Web Blob";
      return;
    }
    final file = io.File(path);
    if (file.existsSync()) {
      final bytes = file.lengthSync();
      if (bytes < 1024 * 1024) {
        _fileSize = "${(bytes / 1024).toStringAsFixed(1)} KB";
      } else {
        _fileSize = "${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB";
      }
    }
  }

  Future<void> _loadAudioDrafts() async {
    try {
      final drafts = await MeetingAudioDraftService.getDrafts();
      if (!mounted) return;
      setState(() {
        _audioDrafts = drafts;
        _isLoadingDrafts = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _audioDrafts = [];
        _isLoadingDrafts = false;
      });
    }
  }

  Future<void> _saveCurrentRecordingToDraft({bool showFeedback = true}) async {
    final recordedPath = _recordedPath;
    if (recordedPath == null || recordedPath.isEmpty || kIsWeb) {
      return;
    }

    final existingDraft = await MeetingAudioDraftService.findDraftByPath(
      recordedPath,
    );
    if (existingDraft != null) {
      if (!mounted) return;
      setState(() {
        _recordedPath = existingDraft.path;
        _selectedDraftId = existingDraft.id;
        _selectedAudioBytes = null;
        _selectedAudioName = null;
        _isUploadedAudio = false;
        _recordingDuration = _formatRecordingDuration(
          Duration(milliseconds: existingDraft.durationMs),
        );
        _fileSize = _formatDraftFileSize(existingDraft.sizeBytes);
      });
      if (showFeedback) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('សំឡេងនេះបានរក្សាទុកជា Draft រួចហើយ')),
        );
      }
      return;
    }

    final durationParts = _recordingDuration.split(':');
    var durationMs = 0;
    if (durationParts.length == 2) {
      final minutes = int.tryParse(durationParts[0]) ?? 0;
      final seconds = int.tryParse(durationParts[1]) ?? 0;
      durationMs = ((minutes * 60) + seconds) * 1000;
    } else if (durationParts.length == 3) {
      final hours = int.tryParse(durationParts[0]) ?? 0;
      final minutes = int.tryParse(durationParts[1]) ?? 0;
      final seconds = int.tryParse(durationParts[2]) ?? 0;
      durationMs = (((hours * 60) + minutes) * 60 + seconds) * 1000;
    }

    final draft = await MeetingAudioDraftService.saveDraft(
      sourcePath: recordedPath,
      durationMs: durationMs,
    );

    if (!kIsWeb && draft.path != recordedPath) {
      try {
        final sourceFile = io.File(recordedPath);
        if (sourceFile.existsSync()) {
          await sourceFile.delete();
        }
      } catch (_) {}
    }

    if (_usesNativeBackgroundRecording) {
      await MeetingRecordingService.discardLastCompleted(path: recordedPath);
    }

    if (!mounted) return;
    setState(() {
      _recordedPath = draft.path;
      _selectedDraftId = draft.id;
      _selectedAudioBytes = null;
      _selectedAudioName = null;
      _isUploadedAudio = false;
      _recordingDuration = _formatRecordingDuration(
        Duration(milliseconds: draft.durationMs),
      );
      _fileSize = _formatDraftFileSize(draft.sizeBytes);
    });
    await _loadAudioDrafts();
    if (!mounted) return;

    if (showFeedback) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('បានរក្សាទុកសំឡេងជា Draft')));
    }
  }

  void _selectDraft(MeetingAudioDraft draft) {
    setState(() {
      _recordedPath = draft.path;
      _selectedDraftId = draft.id;
      _selectedAudioBytes = null;
      _selectedAudioName = null;
      _isUploadedAudio = false;
      _recordingDuration = _formatRecordingDuration(
        Duration(milliseconds: draft.durationMs),
      );
      _fileSize = _formatDraftFileSize(draft.sizeBytes);
    });
  }

  Future<void> _deleteDraft(MeetingAudioDraft draft) async {
    final wasSelected = _selectedDraftId == draft.id;
    await MeetingAudioDraftService.deleteDraft(draft);
    await _loadAudioDrafts();

    if (!mounted) return;
    if (wasSelected) {
      setState(() {
        _recordedPath = null;
        _selectedDraftId = null;
        _selectedAudioBytes = null;
        _selectedAudioName = null;
        _isUploadedAudio = false;
        _recordingDuration = "00:00";
        _fileSize = "";
      });
    }

    ScaffoldMessenger.of(
      context,
    ).showSnackBar(const SnackBar(content: Text('បានលុប Draft')));
  }

  String _formatDraftFileSize(int sizeBytes) {
    if (sizeBytes < 1024 * 1024) {
      return "${(sizeBytes / 1024).toStringAsFixed(1)} KB";
    }
    return "${(sizeBytes / (1024 * 1024)).toStringAsFixed(1)} MB";
  }

  String _formatDraftDate(DateTime dateTime) {
    return DateFormat('dd/MM/yyyy HH:mm').format(dateTime);
  }

  // ========== PHOTO PICKER ==========
  Future<void> _pickPhotos() async {
    final images = await _picker.pickMultiImage();
    if (images.isNotEmpty) {
      setState(() {
        _selectedPhotos.addAll(images);
      });
    }
  }

  // ========== FORM SUBMIT ==========
  Future<void> _submitMeeting() async {
    if (!_formKey.currentState!.validate()) return;
    if (_isRecording || _isRecordingPaused) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('សូមផ្អាក ឬឈប់ការថតសំឡេងជាមុនសិន')),
      );
      return;
    }

    setState(() => _isSubmitting = true);
    try {
      final draftIdToRemove = _selectedDraftId;
      final res = await _api.saveMeeting(
        topic: _topicController.text,
        department: _deptController.text,
        date: _dateController.text,
        description: _descController.text,
        externalUrl: _urlController.text,
        audioPath: _recordedPath,
        audioBytes: _selectedAudioBytes,
        audioFilename: _selectedAudioName,
        photoPaths: _selectedPhotos.map((v) => v.path).toList(),
      );

      if (res['status'] == 'success') {
        if (draftIdToRemove != null) {
          await MeetingAudioDraftService.deleteDraftById(draftIdToRemove);
          await _loadAudioDrafts();
        }
        if (mounted) {
          ScaffoldMessenger.of(
            context,
          ).showSnackBar(const SnackBar(content: Text('បង្ហោះជោគជ័យ')));
        }
        _resetForm();
        _tabController.animateTo(1);
        _loadMeetings();
      } else {
        if (mounted) {
          ScaffoldMessenger.of(
            context,
          ).showSnackBar(SnackBar(content: Text(res['message'] ?? 'មានកំហុស')));
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('កំហុស: $e')));
      }
    } finally {
      setState(() => _isSubmitting = false);
    }
  }

  void _resetForm() {
    _topicController.clear();
    _deptController.clear();
    _descController.clear();
    _urlController.clear();
    if (_usesNativeBackgroundRecording) {
      unawaited(MeetingRecordingService.clearLastCompleted());
    }
    setState(() {
      _recordedPath = null;
      _selectedDraftId = null;
      _selectedAudioBytes = null;
      _selectedAudioName = null;
      _isUploadedAudio = false;
      _isRecording = false;
      _isRecordingPaused = false;
      _recordingDuration = "00:00";
      _fileSize = "";
      _selectedPhotos = [];
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        centerTitle: true,
        title: Text(
          "កិច្ចប្រជុំ (Meetings)",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontWeight: FontWeight.bold,
            fontSize: 18,
          ),
        ),
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppTheme.primary,
          labelStyle: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
          unselectedLabelColor: AppTheme.textSecondary,
          labelColor: AppTheme.primary,
          tabs: [
            if (!(Provider.of<UserProvider>(context, listen: false).isHRM &&
                !Provider.of<UserProvider>(context, listen: false).isAdmin))
              const Tab(text: "ចុះឈ្មោះការប្រជុំ"),
            const Tab(text: "ស្តាប់កិច្ចប្រជុំ"),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        physics: const NeverScrollableScrollPhysics(),
        children: [
          if (!(Provider.of<UserProvider>(context, listen: false).isHRM &&
              !Provider.of<UserProvider>(context, listen: false).isAdmin))
            _buildFormTabV2(),
          _buildListTab(),
        ],
      ),
    );
  }

  // ========== TAB 1: FORM ==========
  Widget _buildFormTabV2() {
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      padding: EdgeInsets.fromLTRB(
        AppResponsive.horizontalPadding(context),
        20,
        AppResponsive.horizontalPadding(context),
        AppResponsive.bottomPadding(context),
      ),
      child: AppResponsive.maxWidth(
        context: context,
        child: Form(
          key: _formKey,
          child: Column(
            children: [
              _buildField(
                "ប្រធានបទកិច្ចប្រជុំ *",
                _topicController,
                Icons.title,
                true,
              ),
              const SizedBox(height: 16),
              _buildField(
                "ផ្នែក / ឯកសារ *",
                _deptController,
                Icons.folder_open,
                true,
              ),
              const SizedBox(height: 16),
              _buildField(
                "កាលបរិច្ឆេទ",
                _dateController,
                Icons.calendar_today,
                false,
                readOnly: true,
              ),
              const SizedBox(height: 16),
              _buildField(
                "ការពិពណ៌នា",
                _descController,
                Icons.description,
                false,
                maxLines: 3,
              ),
              const SizedBox(height: 16),
              _buildField(
                "តំណភ្ជាប់ខាងក្រៅ (URL)",
                _urlController,
                Icons.link,
                false,
              ),
              const SizedBox(height: 30),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(
                  vertical: 30,
                  horizontal: 20,
                ),
                decoration: AppTheme.cardDecoration(
                  color: AppTheme.bgCard,
                  radius: AppTheme.radiusXl,
                  borderColor: _isRecording
                      ? AppTheme.primary
                      : (_isRecordingPaused
                            ? Colors.orangeAccent
                            : AppTheme.cardBorder),
                ),
                child: Column(
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          Icons.settings_voice_rounded,
                          color: AppTheme.primary,
                          size: 20,
                        ),
                        const SizedBox(width: 10),
                        Text(
                          "ការគ្រប់គ្រងសំឡេង (Audio Management)",
                          style: GoogleFonts.kantumruyPro(
                            fontWeight: FontWeight.bold,
                            color: AppTheme.textPrimary,
                            fontSize: 14,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 18),
                    Wrap(
                      alignment: WrapAlignment.center,
                      spacing: 12,
                      runSpacing: 12,
                      children: [
                        _buildActionBtn(
                          Icons.upload_file_rounded,
                          "Upload Audio",
                          AppTheme.secondary,
                          () => _pickAudioFile(),
                        ),
                        if (_isUploadedAudio)
                          _buildActionBtn(
                            Icons.delete_outline_rounded,
                            "Clear File",
                            Colors.redAccent,
                            () => _discardRecordedAudio(),
                          ),
                      ],
                    ),
                    const SizedBox(height: 35),
                    GestureDetector(
                      onTap: _isSubmitting ? null : _toggleRecording,
                      child: Stack(
                        alignment: Alignment.center,
                        children: [
                          if (_isRecording)
                            Pulse(
                              infinite: true,
                              duration: const Duration(seconds: 1),
                              child: Container(
                                height: 120,
                                width: 120,
                                decoration: BoxDecoration(
                                  color: Colors.red.withAlpha(20),
                                  shape: BoxShape.circle,
                                ),
                              ),
                            ),
                          Pulse(
                            animate: _isRecording,
                            infinite: true,
                            child: Container(
                              height: 90,
                              width: 90,
                              decoration: BoxDecoration(
                                color: _isRecording
                                    ? Colors.red
                                    : (_isRecordingPaused
                                          ? Colors.orange
                                          : AppTheme.primary),
                                shape: BoxShape.circle,
                                boxShadow: [
                                  BoxShadow(
                                    color:
                                        (_isRecording
                                                ? Colors.red
                                                : (_isRecordingPaused
                                                      ? Colors.orange
                                                      : AppTheme.primary))
                                            .withAlpha(80),
                                    blurRadius: 15,
                                    spreadRadius: 2,
                                  ),
                                ],
                              ),
                              child: Icon(
                                (_isRecording || _isRecordingPaused)
                                    ? Icons.stop_rounded
                                    : Icons.mic_rounded,
                                color: Colors.white,
                                size: 45,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 25),
                    Text(
                      _isRecording
                          ? "កំពុងថត... $_recordingDuration"
                          : (_isRecordingPaused
                                ? "បានផ្អាក... $_recordingDuration"
                                : (_recordedPath != null
                                      ? "ថតរួចរាល់ ✅ ($_recordingDuration | $_fileSize)"
                                      : "ចុចដើម្បីចាប់ផ្តើមថត")),
                      style: GoogleFonts.kantumruyPro(
                        color: _isRecording
                            ? Colors.red
                            : (_isRecordingPaused
                                  ? Colors.orangeAccent
                                  : AppTheme.textPrimary),
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    if ((_isRecording || _isRecordingPaused) &&
                        _usesNativeBackgroundRecording) ...[
                      const SizedBox(height: 20),
                      FadeInUp(
                        child: Wrap(
                          alignment: WrapAlignment.center,
                          spacing: 15,
                          runSpacing: 12,
                          children: [
                            if (_isRecording)
                              _buildActionBtn(
                                Icons.pause_circle_filled_rounded,
                                "ផ្អាក",
                                Colors.orange,
                                () => _pauseNativeBackgroundRecording(),
                              ),
                            if (_isRecordingPaused)
                              _buildActionBtn(
                                Icons.play_circle_fill_rounded,
                                "បន្ត",
                                Colors.green,
                                () => _resumeNativeBackgroundRecording(),
                              ),
                            const SizedBox(width: 15),
                            _buildActionBtn(
                              Icons.stop_circle_rounded,
                              "ឈប់",
                              Colors.red,
                              () => _stopNativeBackgroundRecording(),
                            ),
                          ],
                        ),
                      ),
                    ],
                    if (_recordedPath != null &&
                        !_isRecording &&
                        !_isRecordingPaused) ...[
                      const SizedBox(height: 20),
                      FadeInUp(
                        child: Wrap(
                          alignment: WrapAlignment.center,
                          spacing: 15,
                          runSpacing: 12,
                          children: [
                            _buildActionBtn(
                              Icons.play_circle_fill_rounded,
                              "ស្តាប់ផ្ទៀងផ្ទាត់",
                              Colors.green,
                              () => _playPreview(),
                            ),
                            if (_selectedDraftId == null && !_isUploadedAudio)
                              _buildActionBtn(
                                Icons.save_alt_rounded,
                                "Save Draft",
                                AppTheme.primary,
                                () => _saveCurrentRecordingToDraft(),
                              ),
                            _buildActionBtn(
                              Icons.delete_sweep_rounded,
                              "ថតសាថ្មី",
                              Colors.red,
                              () => _discardRecordedAudio(),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ],
                ),
              ),
              const SizedBox(height: 20),
              _buildDraftSection(),
              const SizedBox(height: 20),
              _buildPhotoSection(),
              const SizedBox(height: 30),
              SizedBox(
                width: double.infinity,
                height: 55,
                child: ElevatedButton(
                  onPressed: _isSubmitting ? null : _submitMeeting,
                  style: AppTheme.filledButtonStyle(
                    backgroundColor: AppTheme.primary,
                  ),
                  child: _isSubmitting
                      ? const CircularProgressIndicator(color: Colors.white)
                      : Text(
                          "បង្ហោះកិច្ចប្រជុំ",
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                ),
              ),
              const SizedBox(height: 50),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDraftSection() {
    if (_isLoadingDrafts) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_audioDrafts.isEmpty) {
      return const SizedBox.shrink();
    }

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppTheme.borderColor),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.archive_rounded, color: AppTheme.primary, size: 18),
              const SizedBox(width: 8),
              Text(
                "Meeting Audio Drafts",
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary,
                  fontWeight: FontWeight.bold,
                  fontSize: 14,
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          ..._audioDrafts.map((draft) {
            final isSelected = _selectedDraftId == draft.id;
            return Container(
              margin: const EdgeInsets.only(bottom: 12),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: isSelected
                    ? AppTheme.primary.withAlpha(18)
                    : Colors.black.withAlpha(10),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(
                  color: isSelected
                      ? AppTheme.primary.withAlpha(120)
                      : AppTheme.borderColor,
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          _formatDraftDate(draft.createdAt),
                          style: GoogleFonts.inter(
                            color: AppTheme.textPrimary,
                            fontWeight: FontWeight.w700,
                            fontSize: 13,
                          ),
                        ),
                      ),
                      if (isSelected)
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 10,
                            vertical: 4,
                          ),
                          decoration: BoxDecoration(
                            color: AppTheme.primary.withAlpha(30),
                            borderRadius: BorderRadius.circular(999),
                          ),
                          child: Text(
                            "Selected",
                            style: GoogleFonts.inter(
                              color: AppTheme.primary,
                              fontWeight: FontWeight.w700,
                              fontSize: 11,
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(
                    "${_formatRecordingDuration(Duration(milliseconds: draft.durationMs))} | ${_formatDraftFileSize(draft.sizeBytes)}",
                    style: GoogleFonts.inter(
                      color: AppTheme.textSecondary,
                      fontSize: 12,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 12,
                    runSpacing: 10,
                    children: [
                      _buildActionBtn(
                        Icons.check_circle_rounded,
                        "Use Draft",
                        AppTheme.primary,
                        () => _selectDraft(draft),
                      ),
                      _buildActionBtn(
                        Icons.play_circle_fill_rounded,
                        "Listen",
                        Colors.green,
                        () async {
                          await _audioPlayerService.playPath(
                            draft.path,
                            title: "Draft ${_formatDraftDate(draft.createdAt)}",
                          );
                          if (mounted) {
                            _showAudioPlayerModal();
                          }
                        },
                      ),
                      _buildActionBtn(
                        Icons.delete_outline_rounded,
                        "Delete",
                        Colors.red,
                        () => _deleteDraft(draft),
                      ),
                    ],
                  ),
                ],
              ),
            );
          }),
        ],
      ),
    );
  }

  // ignore: unused_element
  Widget _buildFormTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Form(
        key: _formKey,
        child: Column(
          children: [
            _buildField(
              "ប្រធានបទកិច្ចប្រជុំ *",
              _topicController,
              Icons.title,
              true,
            ),
            const SizedBox(height: 16),
            _buildField(
              "ផ្នែក / ថតឯកសារ *",
              _deptController,
              Icons.folder_open,
              true,
            ),
            const SizedBox(height: 16),
            _buildField(
              "កាលបរិច្ឆេទ",
              _dateController,
              Icons.calendar_today,
              false,
              readOnly: true,
            ),
            const SizedBox(height: 16),
            _buildField(
              "ការពិពណ៌នា",
              _descController,
              Icons.description,
              false,
              maxLines: 3,
            ),
            const SizedBox(height: 16),
            _buildField(
              "តំណភ្ជាប់ខាងក្រៅ (URL)",
              _urlController,
              Icons.link,
              false,
            ),

            // Improved Audio Management UI
            const SizedBox(height: 30),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(vertical: 30, horizontal: 20),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: BorderRadius.circular(25),
                border: Border.all(
                  color: _isRecording
                      ? AppTheme.primary
                      : (_isRecordingPaused
                            ? Colors.orangeAccent
                            : AppTheme.borderColor.withAlpha(100)),
                  width: 1.5,
                ),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withAlpha(20),
                    blurRadius: 15,
                    offset: const Offset(0, 10),
                  ),
                ],
              ),
              child: Column(
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(
                        Icons.settings_voice_rounded,
                        color: AppTheme.primary,
                        size: 20,
                      ),
                      const SizedBox(width: 10),
                      Text(
                        "ការគ្រប់គ្រងសំឡេង (Audio Management)",
                        style: GoogleFonts.kantumruyPro(
                          fontWeight: FontWeight.bold,
                          color: AppTheme.textPrimary,
                          fontSize: 14,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 35),
                  GestureDetector(
                    onTap: _isSubmitting ? null : _toggleRecording,
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        if (_isRecording)
                          Pulse(
                            infinite: true,
                            duration: const Duration(seconds: 1),
                            child: Container(
                              height: 120,
                              width: 120,
                              decoration: BoxDecoration(
                                color: Colors.red.withAlpha(20),
                                shape: BoxShape.circle,
                              ),
                            ),
                          ),
                        Pulse(
                          animate: _isRecording,
                          infinite: true,
                          child: Container(
                            height: 90,
                            width: 90,
                            decoration: BoxDecoration(
                              color: _isRecording
                                  ? Colors.red
                                  : (_isRecordingPaused
                                        ? Colors.orange
                                        : AppTheme.primary),
                              shape: BoxShape.circle,
                              boxShadow: [
                                BoxShadow(
                                  color:
                                      (_isRecording
                                              ? Colors.red
                                              : (_isRecordingPaused
                                                    ? Colors.orange
                                                    : AppTheme.primary))
                                          .withAlpha(80),
                                  blurRadius: 15,
                                  spreadRadius: 2,
                                ),
                              ],
                            ),
                            child: Icon(
                              (_isRecording || _isRecordingPaused)
                                  ? Icons.stop_rounded
                                  : Icons.mic_rounded,
                              color: Colors.white,
                              size: 45,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 25),
                  Text(
                    _isRecording
                        ? "កំពុងថត... $_recordingDuration"
                        : (_recordedPath != null
                              ? "ថតរួចរាល់ ✅ ($_recordingDuration | $_fileSize)"
                              : "ចុចដើម្បីចាប់ផ្ដើមថត"),
                    style: GoogleFonts.kantumruyPro(
                      color: _isRecording ? Colors.red : AppTheme.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  if (_recordedPath != null && !_isRecording) ...[
                    const SizedBox(height: 20),
                    FadeInUp(
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          _buildActionBtn(
                            Icons.play_circle_fill_rounded,
                            "ស្ដាប់ផ្ទៀងផ្ទាត់",
                            Colors.green,
                            () => _playPreview(),
                          ),
                          const SizedBox(width: 15),
                          _buildActionBtn(
                            Icons.delete_sweep_rounded,
                            "ថតសាថ្មី",
                            Colors.red,
                            () => setState(() => _recordedPath = null),
                          ),
                        ],
                      ),
                    ),
                  ],
                ],
              ),
            ),

            // Photos Section
            const SizedBox(height: 20),
            _buildPhotoSection(),

            const SizedBox(height: 30),
            SizedBox(
              width: double.infinity,
              height: 55,
              child: ElevatedButton(
                onPressed: _isSubmitting ? null : _submitMeeting,
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.primary,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(16),
                  ),
                ),
                child: _isSubmitting
                    ? const CircularProgressIndicator(color: Colors.white)
                    : Text(
                        "បង្ហោះកិច្ចប្រជុំ",
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
              ),
            ),
            const SizedBox(height: 50),
          ],
        ),
      ),
    );
  }

  Widget _buildField(
    String label,
    TextEditingController ctrl,
    IconData icon,
    bool required, {
    int maxLines = 1,
    bool readOnly = false,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontWeight: FontWeight.w600,
            fontSize: 13,
          ),
        ),
        const SizedBox(height: 8),
        TextFormField(
          controller: ctrl,
          maxLines: maxLines,
          readOnly: readOnly,
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary,
            fontSize: 14,
          ),
          decoration: InputDecoration(
            prefixIcon: Icon(icon, color: AppTheme.primary, size: 20),
            filled: true,
            fillColor: AppTheme.bgCard,
            contentPadding: const EdgeInsets.symmetric(
              horizontal: 16,
              vertical: 12,
            ),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(15),
              borderSide: BorderSide(color: AppTheme.borderColor),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(15),
              borderSide: BorderSide(color: AppTheme.borderColor),
            ),
          ),
          validator: required
              ? (v) => (v == null || v.isEmpty) ? 'មិនអាចទទេបាន' : null
              : null,
        ),
      ],
    );
  }

  Widget _buildPhotoSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              "រូបភាពពាក់ព័ន្ធ (Photos Upload)",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.w600,
                fontSize: 13,
              ),
            ),
            TextButton.icon(
              onPressed: _pickPhotos,
              icon: Icon(Icons.add_a_photo_rounded, size: 18),
              label: Text("បន្ថែម", style: GoogleFonts.kantumruyPro()),
            ),
          ],
        ),
        if (_selectedPhotos.isNotEmpty)
          SizedBox(
            height: 100,
            child: ListView.builder(
              scrollDirection: Axis.horizontal,
              itemCount: _selectedPhotos.length,
              itemBuilder: (context, index) {
                return Stack(
                  children: [
                    Container(
                      margin: const EdgeInsets.only(right: 10),
                      width: 90,
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(12),
                        image: DecorationImage(
                          image: kIsWeb
                              ? NetworkImage(_selectedPhotos[index].path)
                              : FileImage(io.File(_selectedPhotos[index].path))
                                    as ImageProvider,
                          fit: BoxFit.cover,
                        ),
                      ),
                    ),
                    Positioned(
                      top: 4,
                      right: 14,
                      child: GestureDetector(
                        onTap: () =>
                            setState(() => _selectedPhotos.removeAt(index)),
                        child: CircleAvatar(
                          radius: 10,
                          backgroundColor: Colors.red,
                          child: Icon(
                            Icons.close,
                            size: 12,
                            color: Colors.white,
                          ),
                        ),
                      ),
                    ),
                  ],
                );
              },
            ),
          ),
      ],
    );
  }

  // ========== TAB 2: LIST ==========
  Widget _buildListTab() {
    if (_isLoadingList) {
      return Center(child: CircularProgressIndicator(color: AppTheme.primary));
    }
    if (_meetingsList.isEmpty) {
      return AppStateView(
        icon: Icons.mic_off_rounded,
        title: "មិនទាន់មានកិច្ចប្រជុំ",
        message: "កិច្ចប្រជុំដែលបានបង្កើតនឹងបង្ហាញនៅទីនេះ",
        color: AppTheme.primary,
      );
    }

    // Grouping by Department/Folder
    Map<String, List<dynamic>> grouped = {};
    for (var m in _meetingsList) {
      String dept = m['department'] ?? 'ថតឯកសារទូទៅ';
      if (!grouped.containsKey(dept)) grouped[dept] = [];
      grouped[dept]!.add(m);
    }

    final depts = grouped.keys.toList();

    return RefreshIndicator(
      onRefresh: _loadMeetings,
      child: ListView.builder(
        padding: EdgeInsets.fromLTRB(
          AppResponsive.horizontalPadding(context),
          14,
          AppResponsive.horizontalPadding(context),
          AppResponsive.bottomPadding(context),
        ),
        itemCount: depts.length,
        itemBuilder: (context, i) {
          final dept = depts[i];
          final items = grouped[dept]!;
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 10),
                child: Row(
                  children: [
                    Icon(
                      Icons.folder_shared_rounded,
                      color: AppTheme.primaryLight,
                      size: 18,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      dept,
                      style: GoogleFonts.kantumruyPro(
                        fontWeight: FontWeight.bold,
                        color: AppTheme.primaryLight,
                      ),
                    ),
                  ],
                ),
              ),
              ...items.map(
                (m) => AppResponsive.maxWidth(
                  context: context,
                  child: _buildMeetingCard(m),
                ),
              ),
              const SizedBox(height: 15),
            ],
          );
        },
      ),
    );
  }

  Widget _buildMeetingCard(dynamic m) {
    // Support both 'audio_path' (api.php) and 'audio_file_path' (admin_attendance.php)
    final audioPath = (m['audio_path'] ?? m['audio_file_path'] ?? '')
        .toString();
    bool hasAudio = audioPath.isNotEmpty;

    return FadeInUp(
      duration: const Duration(milliseconds: 300),
      child: InkWell(
        onTap: () => _showMeetingDetail(m),
        borderRadius: BorderRadius.circular(16),
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: AppTheme.borderColor),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                m['topic'] ?? 'Untitled',
                style: GoogleFonts.kantumruyPro(
                  fontWeight: FontWeight.bold,
                  fontSize: 15,
                  color: AppTheme.textPrimary,
                ),
              ),
              const SizedBox(height: 6),
              Row(
                children: [
                  Icon(
                    Icons.calendar_month,
                    size: 14,
                    color: AppTheme.textSecondary,
                  ),
                  const SizedBox(width: 6),
                  Text(
                    m['meeting_date'] ?? '',
                    style: GoogleFonts.inter(
                      fontSize: 12,
                      color: AppTheme.textSecondary,
                    ),
                  ),
                ],
              ),
              if (m['description'] != null &&
                  m['description'].toString().isNotEmpty) ...[
                const SizedBox(height: 8),
                Text(
                  m['description'],
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 13,
                    color: AppTheme.textSecondary,
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
              const SizedBox(height: 12),
              Row(
                children: [
                  if (hasAudio)
                    _buildActionBtn(
                      Icons.play_circle_fill,
                      "ស្តាប់",
                      Colors.green,
                      () =>
                          _playAudio(audioPath, title: m['topic']?.toString()),
                    ),
                  const SizedBox(width: 10),
                  _buildActionBtn(
                    Icons.info_outline_rounded,
                    "លម្អិត",
                    AppTheme.primary,
                    () => _showMeetingDetail(m),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showMeetingDetail(dynamic m) {
    final audioPath = (m['audio_path'] ?? m['audio_file_path'] ?? '')
        .toString();
    final hasAudio = audioPath.isNotEmpty;
    final photosRaw = m['related_photos'] ?? m['photos'] ?? '[]';
    List<dynamic> photos = [];
    try {
      photos = photosRaw is List ? photosRaw : (jsonDecode(photosRaw) ?? []);
    } catch (e) {
      photos = [];
    }

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) {
        // Initialize states for the modal
        _currentAISummary = m['summary']?.toString();
        _currentTranscript = m['transcript_text']?.toString();
        _currentAIAnalysis = _parseAnalysisData(m['summary_json']);
        _currentSummaryError = null;
        _currentSummaryStatusMessage = null;

        return StatefulBuilder(
          builder: (context, modalSetState) {
            return Container(
              height: MediaQuery.of(context).size.height * 0.85,
              decoration: BoxDecoration(
                color: AppTheme.bgDark,
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(30),
                ),
              ),
              child: Column(
                children: [
                  const SizedBox(height: 15),
                  Container(
                    width: 40,
                    height: 4,
                    decoration: BoxDecoration(
                      color: Colors.white24,
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                  const SizedBox(height: 20),
                  Expanded(
                    child: SingleChildScrollView(
                      padding: const EdgeInsets.all(25),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Container(
                                padding: const EdgeInsets.all(10),
                                decoration: BoxDecoration(
                                  color: AppTheme.primary.withAlpha(30),
                                  shape: BoxShape.circle,
                                ),
                                child: Icon(
                                  Icons.mic_rounded,
                                  color: AppTheme.primary,
                                ),
                              ),
                              const SizedBox(width: 15),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      m['topic'] ?? 'Untitled',
                                      style: GoogleFonts.kantumruyPro(
                                        fontWeight: FontWeight.bold,
                                        fontSize: 18,
                                        color: AppTheme.textPrimary,
                                      ),
                                    ),
                                    Text(
                                      m['meeting_date'] ?? '',
                                      style: GoogleFonts.inter(
                                        color: AppTheme.textSecondary,
                                        fontSize: 13,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 30),

                          _buildDetailRow(
                            Icons.folder_open_rounded,
                            "ផ្នែក / ថតឯកសារ",
                            m['department'] ?? 'ថតឯកសារទូទៅ',
                          ),
                          const SizedBox(height: 20),

                          if (m['description'] != null &&
                              m['description'].toString().isNotEmpty) ...[
                            Text(
                              "សេចក្ដីពិពណ៌នា",
                              style: GoogleFonts.kantumruyPro(
                                fontWeight: FontWeight.bold,
                                color: AppTheme.textPrimary,
                                fontSize: 15,
                              ),
                            ),
                            const SizedBox(height: 10),
                            Container(
                              width: double.infinity,
                              padding: const EdgeInsets.all(15),
                              decoration: BoxDecoration(
                                color: AppTheme.bgCard,
                                borderRadius: BorderRadius.circular(15),
                                border: Border.all(color: AppTheme.borderColor),
                              ),
                              child: Text(
                                m['description'],
                                style: GoogleFonts.kantumruyPro(
                                  color: AppTheme.textSecondary,
                                  fontSize: 14,
                                  height: 1.6,
                                ),
                              ),
                            ),
                            const SizedBox(height: 30),
                          ],

                          // AI SUMMARY SECTION
                          Container(
                            width: double.infinity,
                            padding: const EdgeInsets.all(20),
                            decoration: BoxDecoration(
                              color: AppTheme.primary.withAlpha(32),
                              borderRadius: BorderRadius.circular(20),
                              border: Border.all(
                                color: AppTheme.primary.withAlpha(100),
                              ),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Row(
                                  mainAxisAlignment:
                                      MainAxisAlignment.spaceBetween,
                                  children: [
                                    Row(
                                      children: [
                                        const Icon(
                                          Icons.auto_awesome_rounded,
                                          color: Colors.amber,
                                          size: 20,
                                        ),
                                        const SizedBox(width: 10),
                                        Text(
                                          "សេចក្តីសង្ខេបដោយ AI",
                                          style: GoogleFonts.kantumruyPro(
                                            fontWeight: FontWeight.bold,
                                            color: AppTheme.textPrimary,
                                            fontSize: 15,
                                          ),
                                        ),
                                      ],
                                    ),
                                    if (_currentAISummary != null)
                                      IconButton(
                                        icon: const Icon(
                                          Icons.copy_rounded,
                                          color: Colors.amber,
                                          size: 20,
                                        ),
                                        onPressed: () => _copyToClipboard(
                                          _buildInsightCopyText(),
                                        ),
                                        tooltip: "ចម្លងអត្ថបទ",
                                      ),
                                  ],
                                ),
                                const SizedBox(height: 15),
                                if (_isSummarizing)
                                  Padding(
                                    padding: const EdgeInsets.all(20),
                                    child: Column(
                                      children: [
                                        const CircularProgressIndicator(),
                                        const SizedBox(height: 12),
                                        if ((_currentSummaryStatusMessage ?? '')
                                            .trim()
                                            .isNotEmpty) ...[
                                          Text(
                                            _currentSummaryStatusMessage!,
                                            textAlign: TextAlign.center,
                                            style: GoogleFonts.kantumruyPro(
                                              color: AppTheme.textSecondary,
                                              fontSize: 13,
                                              height: 1.5,
                                            ),
                                          ),
                                          const SizedBox(height: 10),
                                        ],
                                        Text(
                                          "កំពុងបម្លែងសំឡេង និងសង្ខេបដោយ AI...\nសូមរង់ចាំបន្តិច",
                                          textAlign: TextAlign.center,
                                          style: GoogleFonts.kantumruyPro(
                                            color: AppTheme.textSecondary,
                                            fontSize: 13,
                                            height: 1.5,
                                          ),
                                        ),
                                      ],
                                    ),
                                  )
                                else if ((_currentSummaryError ?? '')
                                    .trim()
                                    .isNotEmpty)
                                  Container(
                                    width: double.infinity,
                                    padding: const EdgeInsets.all(14),
                                    decoration: BoxDecoration(
                                      color: Colors.red.withAlpha(18),
                                      borderRadius: BorderRadius.circular(14),
                                      border: Border.all(
                                        color: Colors.redAccent.withAlpha(100),
                                      ),
                                    ),
                                    child: Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Text(
                                          "មិនអាចសង្ខេបបានទេ",
                                          style: GoogleFonts.kantumruyPro(
                                            color: Colors.redAccent,
                                            fontWeight: FontWeight.bold,
                                          ),
                                        ),
                                        const SizedBox(height: 8),
                                        Text(
                                          _currentSummaryError!,
                                          style: GoogleFonts.kantumruyPro(
                                            color: AppTheme.textPrimary,
                                            fontSize: 12,
                                            height: 1.5,
                                          ),
                                        ),
                                        const SizedBox(height: 10),
                                        Align(
                                          alignment: Alignment.centerRight,
                                          child: TextButton.icon(
                                            onPressed: () => _generateAISummary(
                                              m,
                                              modalSetState,
                                              force: true,
                                            ),
                                            icon: const Icon(
                                              Icons.refresh_rounded,
                                              size: 16,
                                              color: Colors.amber,
                                            ),
                                            label: Text(
                                              "សាកម្ដងទៀត",
                                              style: GoogleFonts.kantumruyPro(
                                                color: Colors.amber,
                                              ),
                                            ),
                                          ),
                                        ),
                                      ],
                                    ),
                                  )
                                else if (_currentAISummary != null)
                                  Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        _currentAISummary!,
                                        style: GoogleFonts.kantumruyPro(
                                          color: AppTheme.textPrimary.withAlpha(
                                            230,
                                          ),
                                          fontSize: 13,
                                          height: 1.6,
                                        ),
                                      ),
                                      const SizedBox(height: 10),
                                      Align(
                                        alignment: Alignment.centerRight,
                                        child: TextButton.icon(
                                          onPressed: () => _generateAISummary(
                                            m,
                                            modalSetState,
                                            force: true,
                                          ),
                                          icon: const Icon(
                                            Icons.refresh_rounded,
                                            size: 16,
                                            color: Colors.amber,
                                          ),
                                          label: Text(
                                            "សង្ខេបម្ដងទៀត",
                                            style: GoogleFonts.kantumruyPro(
                                              color: Colors.amber,
                                              fontSize: 11,
                                            ),
                                          ),
                                        ),
                                      ),
                                    ],
                                  )
                                else
                                  Center(
                                    child: TextButton.icon(
                                      onPressed: () => _generateAISummary(
                                        m,
                                        modalSetState,
                                        force: true,
                                      ),
                                      icon: const Icon(
                                        Icons.bolt_rounded,
                                        color: Colors.amber,
                                      ),
                                      label: Text(
                                        "ចុចដើម្បីសង្ខេបដោយ AI",
                                        style: GoogleFonts.kantumruyPro(
                                          color: Colors.amber,
                                        ),
                                      ),
                                    ),
                                  ),
                              ],
                            ),
                          ),
                          const SizedBox(height: 30),

                          if ((_currentAIAnalysis != null &&
                                  _currentAIAnalysis!.isNotEmpty) ||
                              ((_currentTranscript ?? '')
                                  .trim()
                                  .isNotEmpty)) ...[
                            _buildMeetingAnalysisCards(),
                            const SizedBox(height: 30),
                          ],

                          if (photos.isNotEmpty) ...[
                            Text(
                              "រូបភាពពាក់ព័ន្ធ (${photos.length})",
                              style: GoogleFonts.kantumruyPro(
                                fontWeight: FontWeight.bold,
                                color: AppTheme.textPrimary,
                                fontSize: 15,
                              ),
                            ),
                            const SizedBox(height: 15),
                            SizedBox(
                              height: 180,
                              child: ListView.builder(
                                scrollDirection: Axis.horizontal,
                                itemCount: photos.length,
                                itemBuilder: (context, index) {
                                  final imgUrl = ApiService.getFullImageUrl(
                                    photos[index].toString(),
                                  );
                                  return Container(
                                    margin: const EdgeInsets.only(right: 15),
                                    width: 250,
                                    decoration: BoxDecoration(
                                      borderRadius: BorderRadius.circular(20),
                                      border: Border.all(
                                        color: AppTheme.borderColor,
                                      ),
                                      image: DecorationImage(
                                        image: NetworkImage(imgUrl),
                                        fit: BoxFit.cover,
                                      ),
                                    ),
                                    child: InkWell(
                                      onTap: () => _viewFullPhoto(imgUrl),
                                      borderRadius: BorderRadius.circular(20),
                                    ),
                                  );
                                },
                              ),
                            ),
                            const SizedBox(height: 30),
                          ],

                          if (m['external_url'] != null &&
                              m['external_url'].toString().isNotEmpty) ...[
                            _buildDetailRow(
                              Icons.link_rounded,
                              "តំណភ្ជាប់ខាងក្រៅ",
                              m['external_url'],
                              isLink: true,
                            ),
                            const SizedBox(height: 30),
                          ],

                          const SizedBox(height: 20),
                          if (hasAudio)
                            SizedBox(
                              width: double.infinity,
                              height: 55,
                              child: ElevatedButton.icon(
                                onPressed: () {
                                  Navigator.pop(context);
                                  _playAudio(
                                    audioPath,
                                    title: m['topic']?.toString(),
                                  );
                                },
                                icon: const Icon(
                                  Icons.play_circle_fill_rounded,
                                  color: Colors.white,
                                ),
                                label: Text(
                                  "ស្តាប់សំឡេងកិច្ចប្រជុំ",
                                  style: GoogleFonts.kantumruyPro(
                                    fontWeight: FontWeight.bold,
                                    color: Colors.white,
                                  ),
                                ),
                                style: ElevatedButton.styleFrom(
                                  backgroundColor: Colors.green.shade600,
                                  shape: RoundedRectangleBorder(
                                    borderRadius: BorderRadius.circular(15),
                                  ),
                                ),
                              ),
                            ),
                          const SizedBox(height: 50),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }

  Widget _buildMeetingAnalysisCards() {
    final analysis = _currentAIAnalysis ?? const <String, dynamic>{};
    final overview = (analysis['overview'] ?? '').toString().trim();
    final headline = (analysis['headline'] ?? '').toString().trim();
    final keyPoints = _analysisList(analysis['key_points']);
    final decisions = _analysisList(analysis['decisions']);
    final actionItems = _analysisList(analysis['action_items']);
    final nextSteps = _analysisList(analysis['next_steps']);
    final keywords = _analysisList(analysis['keywords']);
    final transcript = (_currentTranscript ?? '').trim();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (headline.isNotEmpty || overview.isNotEmpty)
          _buildInsightCard(
            title: headline.isNotEmpty ? headline : 'AI Summary',
            icon: Icons.lightbulb_rounded,
            accent: Colors.amber,
            child: Text(
              overview.isNotEmpty ? overview : (_currentAISummary ?? ''),
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontSize: 14,
                height: 1.6,
              ),
            ),
          ),
        if (headline.isNotEmpty || overview.isNotEmpty)
          const SizedBox(height: 16),
        if (keyPoints.isNotEmpty)
          _buildInsightCard(
            title: 'Key Points',
            icon: Icons.format_list_bulleted_rounded,
            accent: AppTheme.primaryLight,
            child: _buildInsightList(keyPoints),
          ),
        if (keyPoints.isNotEmpty) const SizedBox(height: 16),
        if (decisions.isNotEmpty)
          _buildInsightCard(
            title: 'Decisions',
            icon: Icons.rule_folder_rounded,
            accent: Colors.cyanAccent,
            child: _buildInsightList(decisions),
          ),
        if (decisions.isNotEmpty) const SizedBox(height: 16),
        if (actionItems.isNotEmpty)
          _buildInsightCard(
            title: 'Action Items',
            icon: Icons.task_alt_rounded,
            accent: Colors.greenAccent,
            child: _buildInsightList(actionItems),
          ),
        if (actionItems.isNotEmpty) const SizedBox(height: 16),
        if (nextSteps.isNotEmpty)
          _buildInsightCard(
            title: 'Next Steps',
            icon: Icons.trending_flat_rounded,
            accent: Colors.orangeAccent,
            child: _buildInsightList(nextSteps),
          ),
        if (nextSteps.isNotEmpty) const SizedBox(height: 16),
        if (keywords.isNotEmpty)
          _buildInsightCard(
            title: 'Keywords',
            icon: Icons.sell_rounded,
            accent: AppTheme.secondary,
            child: Wrap(
              spacing: 10,
              runSpacing: 10,
              children: keywords
                  .map(
                    (item) => Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 7,
                      ),
                      decoration: BoxDecoration(
                        color: AppTheme.secondary.withAlpha(28),
                        borderRadius: BorderRadius.circular(999),
                        border: Border.all(
                          color: AppTheme.secondary.withAlpha(80),
                        ),
                      ),
                      child: Text(
                        item,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  )
                  .toList(),
            ),
          ),
        if (keywords.isNotEmpty) const SizedBox(height: 16),
        if (transcript.isNotEmpty)
          _buildInsightCard(
            title: 'Transcript',
            icon: Icons.notes_rounded,
            accent: AppTheme.textSecondary,
            child: SelectableText(
              transcript,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withAlpha(220),
                fontSize: 13,
                height: 1.65,
              ),
            ),
          ),
      ],
    );
  }

  Widget _buildInsightCard({
    required String title,
    required IconData icon,
    required Widget child,
    required Color accent,
  }) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: accent.withAlpha(80)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: accent, size: 18),
              const SizedBox(width: 10),
              Text(
                title,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.w700,
                  fontSize: 14,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }

  Widget _buildInsightList(List<String> items) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: items
          .map(
            (item) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Padding(
                    padding: EdgeInsets.only(top: 8),
                    child: Icon(Icons.circle, size: 6, color: Colors.white70),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      item,
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary.withAlpha(220),
                        fontSize: 13,
                        height: 1.55,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          )
          .toList(),
    );
  }

  Widget _buildDetailRow(
    IconData icon,
    String label,
    String value, {
    bool isLink = false,
  }) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Icon(icon, size: 18, color: AppTheme.primary),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textSecondary,
                  fontSize: 12,
                ),
              ),
              const SizedBox(height: 4),
              GestureDetector(
                onTap: isLink ? () => _openUrl(value) : null,
                child: Text(
                  value,
                  style: GoogleFonts.kantumruyPro(
                    color: isLink ? Colors.blue : AppTheme.textPrimary,
                    fontWeight: FontWeight.w600,
                    fontSize: 14,
                    decoration: isLink ? TextDecoration.underline : null,
                  ),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  void _viewFullPhoto(String url) {
    showDialog(
      context: context,
      builder: (context) => Stack(
        children: [
          Positioned.fill(child: InteractiveViewer(child: Image.network(url))),
          Positioned(
            top: 40,
            right: 20,
            child: IconButton(
              icon: const Icon(Icons.close, color: Colors.white, size: 30),
              onPressed: () => Navigator.pop(context),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildActionBtn(
    IconData icon,
    String label,
    Color color,
    VoidCallback onTap,
  ) {
    return InkWell(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          color: color.withAlpha(25),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: color.withAlpha(51)),
        ),
        child: Row(
          children: [
            Icon(icon, size: 16, color: color),
            const SizedBox(width: 6),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                fontSize: 11,
                fontWeight: FontWeight.bold,
                color: color,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _playAudio(String path, {String? title}) async {
    try {
      final String fullUrl = ApiService.getFullImageUrl(path);
      debugPrint("PLAY_REQ: $fullUrl");

      if (_currentlyPlayingPath == path) {
        if (_isPlaying) {
          await _audioPlayerService.pause();
        } else {
          await _audioPlayerService.resume();
        }
      } else {
        setState(() => _isPlayerLoading = true);
        _currentlyPlayingPath = path;
        _position = Duration.zero;
        _duration = Duration.zero;
        await _audioPlayerService.playPath(
          fullUrl,
          title: title,
          forceRemote: true,
          displayPath: path,
        );
        if (mounted) {
          setState(() => _isPlayerLoading = false);
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isPlayerLoading = false;
          _currentlyPlayingPath = null;
        });
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Playback Error: $e')));
      }
    } finally {
      if (mounted) _showAudioPlayerModal();
    }
  }

  void _showAudioPlayerModal() {
    if (!mounted) return;
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, modalSetState) {
            return Container(
              padding: const EdgeInsets.all(25),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(30),
                ),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withAlpha(50),
                    blurRadius: 20,
                    offset: const Offset(0, -5),
                  ),
                ],
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    width: 50,
                    height: 5,
                    decoration: BoxDecoration(
                      color: AppTheme.textSecondary.withAlpha(50),
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                  const SizedBox(height: 25),

                  if (_isPlayerLoading)
                    const Column(
                      children: [
                        CircularProgressIndicator(),
                        SizedBox(height: 10),
                        Text(
                          "កំពុងទាញយកសំឡេង...",
                          style: TextStyle(color: Colors.white70),
                        ),
                      ],
                    )
                  else if (_currentlyPlayingPath != null) ...[
                    Text(
                      "កំពុងចាក់សំឡេង",
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.primary,
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                  ],
                  const SizedBox(height: 10),
                  if (_currentlyPlayingPath != null)
                    Text(
                      _audioPlayerService.currentTitle ??
                          ((_meetingsList.isEmpty)
                              ? 'កិច្ចប្រជុំ'
                              : _meetingsList.whereType<Map>().firstWhere(
                                      (m) {
                                        final map = m as Map<String, dynamic>;
                                        return (map['audio_path'] ??
                                                map['audio_file_path'] ??
                                                '') ==
                                            _currentlyPlayingPath;
                                      },
                                      orElse: () => {'topic': 'កិច្ចប្រជុំ'},
                                    )['topic'] ??
                                    ''),
                      style: GoogleFonts.kantumruyPro(
                        color: AppTheme.textPrimary,
                        fontSize: 14,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  const SizedBox(height: 30),

                  Builder(
                    builder: (context) {
                      final position = _position;
                      final currentPos = position.inMilliseconds.toDouble();
                      final totalDur = _duration.inMilliseconds
                          .toDouble()
                          .clamp(1.0, double.infinity);
                      final safeVal = currentPos.clamp(0.0, totalDur);

                      return Column(
                        children: [
                          SliderTheme(
                            data: SliderTheme.of(context).copyWith(
                              trackHeight: 4,
                              thumbShape: const RoundSliderThumbShape(
                                enabledThumbRadius: 8,
                              ),
                              activeTrackColor: AppTheme.primary,
                              thumbColor: AppTheme.primary,
                            ),
                            child: Slider(
                              min: 0,
                              max: totalDur,
                              value: safeVal,
                              onChanged: (v) {
                                _audioPlayerService.seek(
                                  Duration(milliseconds: v.toInt()),
                                );
                              },
                            ),
                          ),
                          Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 20),
                            child: Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Text(
                                  _formatDuration(position),
                                  style: GoogleFonts.inter(
                                    color: AppTheme.textSecondary,
                                    fontSize: 12,
                                  ),
                                ),
                                Text(
                                  _formatDuration(_duration),
                                  style: GoogleFonts.inter(
                                    color: AppTheme.textSecondary,
                                    fontSize: 12,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      );
                    },
                  ),

                  const SizedBox(height: 20),

                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      // Speed Control
                      PopupMenuButton<double>(
                        initialValue: _playbackSpeed,
                        onSelected: (speed) async {
                          setState(() => _playbackSpeed = speed);
                          await _audioPlayerService.setPlaybackSpeed(speed);
                          modalSetState(() {});
                        },
                        child: Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 12,
                            vertical: 6,
                          ),
                          decoration: BoxDecoration(
                            color: AppTheme.primary.withAlpha(30),
                            borderRadius: BorderRadius.circular(15),
                          ),
                          child: Text(
                            "${_playbackSpeed}x",
                            style: GoogleFonts.inter(
                              color: AppTheme.primary,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                        itemBuilder: (context) => [
                          const PopupMenuItem(value: 0.5, child: Text("0.5x")),
                          const PopupMenuItem(
                            value: 1.0,
                            child: Text("1.0x (Normal)"),
                          ),
                          const PopupMenuItem(
                            value: 1.25,
                            child: Text("1.25x"),
                          ),
                          const PopupMenuItem(value: 1.5, child: Text("1.5x")),
                          const PopupMenuItem(value: 2.0, child: Text("2.0x")),
                        ],
                      ),

                      IconButton(
                        iconSize: 64,
                        icon: Icon(
                          _isPlaying
                              ? Icons.pause_circle_filled_rounded
                              : Icons.play_circle_filled_rounded,
                          color: AppTheme.primary,
                        ),
                        onPressed: () {
                          if (_isPlaying) {
                            _audioPlayerService.pause();
                          } else {
                            _audioPlayerService.resume();
                          }
                        },
                      ),

                      IconButton(
                        icon: const Icon(
                          Icons.stop_circle_rounded,
                          color: Colors.redAccent,
                          size: 30,
                        ),
                        onPressed: () {
                          _audioPlayerService.stop();
                          Navigator.pop(context);
                        },
                      ),
                    ],
                  ),
                  const SizedBox(height: 20),
                ],
              ),
            );
          },
        );
      },
    );
  }

  String _formatDuration(Duration d) {
    String twoDigits(int n) => n.toString().padLeft(2, '0');
    final minutes = twoDigits(d.inMinutes.remainder(60));
    final seconds = twoDigits(d.inSeconds.remainder(60));
    return "$minutes:$seconds";
  }

  Future<void> _playPreview() async {
    if (_recordedPath != null) {
      try {
        final selectedDraft = _selectedDraftId == null
            ? null
            : _audioDrafts.cast<MeetingAudioDraft?>().firstWhere(
                (draft) => draft?.id == _selectedDraftId,
                orElse: () => null,
              );
        await _audioPlayerService.playPath(
          _recordedPath!,
          title: selectedDraft != null
              ? "Draft ${_formatDraftDate(selectedDraft.createdAt)}"
              : "Recording Preview",
        );
        if (mounted) {
          _showAudioPlayerModal();
        }
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('កំពុងចាក់សំឡេង Preview...')),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(
            context,
          ).showSnackBar(SnackBar(content: Text('កំហុសចាក់សំឡេង: $e')));
        }
      }
    }
  }

  Future<void> _openUrl(String? url) async {
    // implementation for url launcher if needed
  }
}
