import 'dart:convert';
import 'dart:async';
import 'dart:io' as io;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:animate_do/animate_do.dart';
import 'package:file_picker/file_picker.dart';
import 'package:image_picker/image_picker.dart';
import 'package:record/record.dart' as record_pkg;
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:intl/intl.dart';
import 'package:path/path.dart' as p;
import 'package:share_plus/share_plus.dart';
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
  final record_pkg.Record _recorder = record_pkg.Record();
  final MeetingAudioPlayerService _audioPlayerService =
      MeetingAudioPlayerService.instance;
  final ImagePicker _picker = ImagePicker();

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
  Timer? _pollingTimer;
  List<MeetingAudioDraft> _audioDrafts = [];
  bool _isLoadingDrafts = true;

  // List states
  List<dynamic> _meetingsList = [];
  bool _isLoadingList = true;

  // Recording info
  String _recordingDuration = "00:00";
  String _fileSize = "";
  DateTime? _recordingStartTime;

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

    _syncRecordingState();

    _pollingTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (mounted) {
        _loadMeetingsSilently();
        _loadAudioDraftsSilently();
      }
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _recordingStateTimer?.cancel();
    _pollingTimer?.cancel();
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

    try {
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
          hasPermission = await _recorder.hasPermission();
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
          await _recorder.start(
            path: path ?? '',
            encoder: record_pkg.AudioEncoder.aacLc,
            bitRate: 48000,
            numChannels: 1,
          );
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
        } else {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text('សូមអនុញ្ញាត Microphone ដើម្បីចាប់ផ្តើមថត'),
              ),
            );
          }
        }
      }
    } catch (e) {
      debugPrint("Recording error: $e");
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('កំហុសពេលថតសំឡេង៖ $e'),
          ),
        );
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

  Future<void> _loadMeetingsSilently() async {
    try {
      final res = await _api.fetchMeetings();
      if (res['status'] == 'success' && mounted) {
        final list = res['meetings'] ?? res['data'] ?? [];
        setState(() {
          _meetingsList = list is List ? list : [];
        });
      }
    } catch (_) {}
  }

  Future<void> _loadAudioDraftsSilently() async {
    try {
      final drafts = await MeetingAudioDraftService.getDrafts();
      if (mounted) {
        setState(() {
          _audioDrafts = drafts;
        });
      }
    } catch (_) {}
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

      if (res['status'] == 'success' || res['success'] == true) {
        final bool hadAudio = (_recordedPath != null && _recordedPath!.isNotEmpty) ||
            (_selectedAudioBytes != null && _selectedAudioBytes!.isNotEmpty) ||
            (res['has_audio'] == true);
        final int newMeetingId = int.tryParse(res['meeting_id']?.toString() ?? res['id']?.toString() ?? '0') ?? 0;

        if (draftIdToRemove != null) {
          await MeetingAudioDraftService.deleteDraftById(draftIdToRemove);
          await _loadAudioDrafts();
        }
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                hadAudio
                    ? 'បង្ហោះជោគជ័យ! AI កំពុងសង្ខេបស្វ័យប្រវត្តិក្នង Background...'
                    : 'បង្ហោះជោគជ័យ',
              ),
              backgroundColor: hadAudio ? Colors.teal.shade700 : null,
            ),
          );
        }
        _resetForm();
        _tabController.animateTo(1);
        _loadMeetings();

        // ដំណើរការ AI សង្ខេបស្វ័យប្រវត្តិតែលើកិច្ចប្រជុំថ្មីដែលមានសំឡេងប៉ុណ្ណោះ (Background Task)
        if (newMeetingId > 0 && hadAudio) {
          unawaited(
            _api.summarizeMeeting(newMeetingId).then((_) {
              if (mounted) {
                _loadMeetingsSilently();
              }
            }).catchError((e) {
              debugPrint('Auto summarize error: $e');
            }),
          );
        }
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
      appBar: VvcAppBar(
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
                          _showAudioPlayerModal();
                          await _audioPlayerService.playPath(
                            draft.path,
                            title: "Draft ${_formatDraftDate(draft.createdAt)}",
                          );
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
              icon: const Icon(Icons.add_a_photo_rounded, size: 18),
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
                        child: const CircleAvatar(
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
                      () => _openAiMinutesModal(m, autoPlayAudio: true),
                    ),
                  const SizedBox(width: 8),
                  _buildActionBtn(
                    Icons.auto_awesome_rounded,
                    (m['summary'] != null && m['summary'].toString().trim().isNotEmpty)
                        ? "មើលសង្ខេប AI"
                        : "AI សង្ខេប",
                    (m['summary'] != null && m['summary'].toString().trim().isNotEmpty)
                        ? Colors.teal.shade700
                        : Colors.amber.shade800,
                    () => _openAiMinutesModal(m),
                  ),
                  const SizedBox(width: 8),
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
                              _openAiMinutesModal(m, autoPlayAudio: true);
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
                      const SizedBox(height: 12),
                      SizedBox(
                        width: double.infinity,
                        height: 55,
                        child: ElevatedButton.icon(
                          onPressed: () {
                            Navigator.pop(context);
                            _openAiMinutesModal(m);
                          },
                          icon: const Icon(
                            Icons.auto_awesome_rounded,
                            color: Colors.white,
                          ),
                          label: Text(
                            "AI សង្ខេបកិច្ចប្រជុំ (AI Minutes)",
                            style: GoogleFonts.kantumruyPro(
                              fontWeight: FontWeight.bold,
                              color: Colors.white,
                            ),
                          ),
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.amber.shade800,
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

  bool _isAudioModalOpen = false;


  void _showAudioPlayerModal() {
    if (!mounted || _isAudioModalOpen) return;
    _isAudioModalOpen = true;
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) {
        return ListenableBuilder(
          listenable: _audioPlayerService,
          builder: (context, _) {
            final isLoading = _audioPlayerService.isLoading;
            final isPlaying = _audioPlayerService.isPlaying;
            final currentTitle = _audioPlayerService.currentTitle ?? 'កិច្ចប្រជុំ';
            final position = _audioPlayerService.position;
            final duration = _audioPlayerService.duration;
            final speed = _audioPlayerService.playbackSpeed;
            final currentPos = position.inMilliseconds.toDouble();
            final totalDur =
                duration.inMilliseconds.toDouble().clamp(1.0, double.infinity);
            final safeVal = currentPos.clamp(0.0, totalDur);

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

                  if (isLoading)
                    const Column(
                      children: [
                        CircularProgressIndicator(
                          valueColor:
                              AlwaysStoppedAnimation<Color>(Color(0xFFF59E0B)),
                        ),
                        SizedBox(height: 12),
                        Text(
                          "កំពុងទាញយកសំឡេង...",
                          style: TextStyle(color: Colors.white70),
                        ),
                      ],
                    )
                  else ...[
                    Text(
                      isPlaying ? "កំពុងចាក់សំឡេង" : "ផ្អាកសំឡេង",
                      style: GoogleFonts.kantumruyPro(
                        color:
                            isPlaying ? AppTheme.primary : AppTheme.textSecondary,
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                  ],
                  const SizedBox(height: 10),
                  Text(
                    currentTitle,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 25),

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
                      onChanged: isLoading
                          ? null
                          : (v) {
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
                          _formatDuration(duration),
                          style: GoogleFonts.inter(
                            color: AppTheme.textSecondary,
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(height: 20),

                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      // Speed Control
                      PopupMenuButton<double>(
                        initialValue: speed,
                        onSelected: (newSpeed) async {
                          await _audioPlayerService.setPlaybackSpeed(newSpeed);
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
                            "${speed}x",
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
                            child: Text("1.0x (ធម្មតា)"),
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
                          isPlaying
                              ? Icons.pause_circle_filled_rounded
                              : Icons.play_circle_filled_rounded,
                          color: AppTheme.primary,
                        ),
                        onPressed: isLoading
                            ? null
                            : () async {
                                if (isPlaying) {
                                  await _audioPlayerService.pause();
                                } else {
                                  await _audioPlayerService.resume();
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
    ).whenComplete(() {
      _isAudioModalOpen = false;
    });
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

  void _openAiMinutesModal(dynamic m, {bool autoPlayAudio = false}) {
    final int meetingId = int.tryParse(m['id']?.toString() ?? '0') ?? 0;
    final String topic = m['topic']?.toString() ?? 'កិច្ចប្រជុំ';
    final String dept = m['department']?.toString() ?? '';
    final String audioPath = (m['audio_url'] ?? m['mp3_url'] ?? m['audio_path'] ?? m['audio_file_path'] ?? '').toString();

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => _AiMeetingMinutesSheet(
        meetingId: meetingId,
        topic: topic,
        department: dept,
        audioPath: audioPath,
        initialSummary: m['summary']?.toString(),
        initialTranscript: m['transcript_text']?.toString(),
        api: _api,
        autoPlayAudio: autoPlayAudio,
        onGenerated: (summary, transcript) {
          if (mounted) {
            setState(() {
              m['summary'] = summary;
              m['transcript_text'] = transcript;
            });
          }
        },
      ),
    );
  }
}

class _AiMeetingMinutesSheet extends StatefulWidget {
  final int meetingId;
  final String topic;
  final String department;
  final String audioPath;
  final String? initialSummary;
  final String? initialTranscript;
  final ApiService api;
  final bool autoPlayAudio;
  final Function(String summary, String? transcript)? onGenerated;

  const _AiMeetingMinutesSheet({
    required this.meetingId,
    required this.topic,
    required this.department,
    required this.audioPath,
    this.initialSummary,
    this.initialTranscript,
    required this.api,
    this.autoPlayAudio = false,
    this.onGenerated,
  });

  @override
  State<_AiMeetingMinutesSheet> createState() => _AiMeetingMinutesSheetState();
}

class _AiMeetingMinutesSheetState extends State<_AiMeetingMinutesSheet> {
  final MeetingAudioPlayerService _audioService = MeetingAudioPlayerService.instance;
  final ScrollController _scrollController = ScrollController();

  bool _isLoading = false;
  String? _summary;
  String? _error;

  Timer? _progressTimer;
  double _loadingProgress = 0.08;
  int _loadingSeconds = 0;

  @override
  void initState() {
    super.initState();
    _summary = widget.initialSummary;
    _audioService.addListener(_onAudioStateChanged);

    if (widget.autoPlayAudio && widget.audioPath.isNotEmpty) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        final url = _resolveAudioUrl(widget.audioPath);
        if (url.isNotEmpty) {
          _audioService.playPath(url, title: widget.topic);
        }
      });
    }

    if ((_summary == null || _summary!.isEmpty) && widget.meetingId > 0) {
      _loadOrGenerateSummary();
    }
  }

  @override
  void dispose() {
    _progressTimer?.cancel();
    _audioService.removeListener(_onAudioStateChanged);
    _scrollController.dispose();
    super.dispose();
  }

  void _onAudioStateChanged() {
    if (mounted) {
      setState(() {});
    }
  }

  String _resolveAudioUrl(String path) {
    if (path.isEmpty) return '';
    if (path.startsWith('http://') || path.startsWith('https://')) return path;
    return ApiService.getFullImageUrl(path);
  }

  String _formatDuration(Duration d) {
    final hours = d.inHours;
    final minutes = d.inMinutes.remainder(60);
    final seconds = d.inSeconds.remainder(60);
    if (hours > 0) {
      return '$hours:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
    }
    return '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
  }

  void _startProgressTimer() {
    _progressTimer?.cancel();
    _loadingProgress = 0.08;
    _loadingSeconds = 0;
    _progressTimer = Timer.periodic(const Duration(milliseconds: 300), (timer) {
      if (!mounted || !_isLoading) {
        timer.cancel();
        return;
      }
      setState(() {
        _loadingSeconds++;
        if (_loadingProgress < 0.25) {
          _loadingProgress += 0.015;
        } else if (_loadingProgress < 0.65) {
          _loadingProgress += 0.008;
        } else if (_loadingProgress < 0.88) {
          _loadingProgress += 0.004;
        } else if (_loadingProgress < 0.95) {
          _loadingProgress += 0.0015;
        }
        _loadingProgress = _loadingProgress.clamp(0.0, 0.95);
      });
    });
  }

  Future<void> _loadOrGenerateSummary({bool force = false}) async {
    setState(() {
      _isLoading = true;
      _error = null;
    });
    _startProgressTimer();

    try {
      final res = await widget.api.summarizeMeeting(widget.meetingId, force: force);
      _progressTimer?.cancel();
      if (res['success'] == true || res['status'] == 'success') {
        final summaryStr = res['summary']?.toString();
        final transcriptStr = res['transcript']?.toString() ?? res['transcript_text']?.toString();
        setState(() {
          _loadingProgress = 1.0;
          _summary = summaryStr;
          _isLoading = false;
        });
        if (summaryStr != null && summaryStr.isNotEmpty) {
          widget.onGenerated?.call(summaryStr, transcriptStr);
        }
      } else {
        setState(() {
          _error = res['message']?.toString() ?? 'មិនអាចទាញយកសេចក្តីសង្ខេប AI បានទេ';
          _isLoading = false;
        });
      }
    } catch (e) {
      _progressTimer?.cancel();
      setState(() {
        _error = 'កំហុសបច្ចេកវិទ្យា AI៖ $e';
        _isLoading = false;
      });
    }
  }

  void _copyToClipboard() {
    final text = _summary ?? '';
    if (text.isEmpty) return;
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          'បានចម្លងសេចក្តីសង្ខេប',
          style: GoogleFonts.kantumruyPro(),
        ),
        backgroundColor: const Color(0xFF6366F1),
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
    );
  }

  void _shareSummary() {
    final textToShare = "📝 AI កំណត់ហេតុកិច្ចប្រជុំ៖ ${widget.topic}\nផ្នែក៖ ${widget.department}\n\n${_summary ?? ''}";
    Share.share(textToShare);
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      height: MediaQuery.of(context).size.height * 0.90,
      decoration: const BoxDecoration(
        color: Color(0xFF0F172A),
        borderRadius: BorderRadius.vertical(top: Radius.circular(30)),
      ),
      child: Column(
        children: [
          // Drag Handle
          Center(
            child: Container(
              margin: const EdgeInsets.only(top: 12, bottom: 8),
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: Colors.white24,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          // Header
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 8),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: const Color(0xFF6366F1).withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(
                      color: const Color(0xFF6366F1).withValues(alpha: 0.3),
                    ),
                  ),
                  child: const Icon(
                    Icons.auto_awesome_rounded,
                    color: Color(0xFF818CF8),
                    size: 22,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        "AI កំណត់ហេតុ & សង្ខេបប្រជុំ",
                        style: GoogleFonts.kantumruyPro(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Colors.white,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        widget.topic,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: GoogleFonts.kantumruyPro(
                          fontSize: 12,
                          color: Colors.white60,
                        ),
                      ),
                    ],
                  ),
                ),
                IconButton(
                  onPressed: () => Navigator.pop(context),
                  icon: const Icon(Icons.close_rounded, color: Colors.white70),
                ),
              ],
            ),
          ),
          const SizedBox(height: 10),

          // Audio Player Card (at the Top)
          _buildAudioPlayerCard(),

          const SizedBox(height: 10),
          // Main Body Content
          Expanded(
            child: _isLoading
                ? _buildLoadingState()
                : (_error != null ? _buildErrorState() : _buildContentState()),
          ),
          // Bottom Action Bar
          if (!_isLoading && _summary != null && _summary!.isNotEmpty)
            Container(
              padding: const EdgeInsets.fromLTRB(20, 12, 20, 24),
              decoration: BoxDecoration(
                color: const Color(0xFF1E293B),
                border: Border(top: BorderSide(color: Colors.white.withValues(alpha: 0.08))),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: _copyToClipboard,
                      icon: const Icon(Icons.copy_rounded, size: 18),
                      label: Text("ចម្លង", style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: const Color(0xFF6366F1),
                        side: BorderSide(color: const Color(0xFF6366F1).withValues(alpha: 0.5)),
                        padding: const EdgeInsets.symmetric(vertical: 13),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: _shareSummary,
                      icon: const Icon(Icons.share_rounded, size: 18),
                      label: Text("ចែករំលែក", style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF6366F1),
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(vertical: 13),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  IconButton(
                    onPressed: () => _loadOrGenerateSummary(force: true),
                    tooltip: "បង្កើតសារជាថ្មី",
                    icon: const Icon(Icons.refresh_rounded, color: Colors.amber),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildAudioPlayerCard() {
    final audioUrl = _resolveAudioUrl(widget.audioPath);
    if (audioUrl.isEmpty) return const SizedBox.shrink();

    final isCurrentAudio = _audioService.currentPath == audioUrl;
    final isPlaying = isCurrentAudio && _audioService.isPlaying;
    final pos = isCurrentAudio ? _audioService.position : Duration.zero;
    final dur = isCurrentAudio ? _audioService.duration : Duration.zero;
    final maxSeconds = dur.inSeconds > 0 ? dur.inSeconds.toDouble() : 100.0;
    final currentSeconds = pos.inSeconds.toDouble().clamp(0.0, maxSeconds);

    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 20, vertical: 4),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            const Color(0xFF6366F1).withValues(alpha: 0.12),
            const Color(0xFFA855F7).withValues(alpha: 0.08),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: const Color(0xFF6366F1).withValues(alpha: 0.25)),
      ),
      child: Column(
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  Icon(
                    Icons.volume_up_rounded,
                    color: isPlaying ? const Color(0xFF6366F1) : Colors.white70,
                    size: 18,
                  ),
                  const SizedBox(width: 6),
                  Text(
                    "សំឡេងកិច្ចប្រជុំ (Audio Recording)",
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                      color: const Color(0xFF818CF8),
                    ),
                  ),
                ],
              ),
              // Speed buttons
              Row(
                children: [1.0, 1.25, 1.5, 2.0].map((speed) {
                  final isCur = (_audioService.playbackSpeed - speed).abs() < 0.05;
                  return Padding(
                    padding: const EdgeInsets.only(left: 4),
                    child: InkWell(
                      onTap: () => _audioService.setPlaybackSpeed(speed),
                      borderRadius: BorderRadius.circular(6),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: isCur ? const Color(0xFF6366F1) : Colors.white.withValues(alpha: 0.08),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(
                          '${speed == 1.0 || speed == 2.0 ? speed.toInt() : speed}x',
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: isCur ? Colors.white : Colors.white60,
                          ),
                        ),
                      ),
                    ),
                  );
                }).toList(),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Row(
            children: [
              // Play / Pause Button
              InkWell(
                onTap: () async {
                  if (isPlaying) {
                    await _audioService.pause();
                  } else {
                    await _audioService.playPath(audioUrl, title: widget.topic);
                  }
                },
                borderRadius: BorderRadius.circular(20),
                child: Container(
                  padding: const EdgeInsets.all(7),
                  decoration: const BoxDecoration(
                    color: Color(0xFF6366F1),
                    shape: BoxShape.circle,
                  ),
                  child: Icon(
                    isPlaying ? Icons.pause_rounded : Icons.play_arrow_rounded,
                    color: Colors.white,
                    size: 18,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              // Current Pos
              Text(
                _formatDuration(pos),
                style: GoogleFonts.inter(
                  fontSize: 10.5,
                  color: Colors.white70,
                  fontWeight: FontWeight.w600,
                ),
              ),
              // Slider
              Expanded(
                child: SliderTheme(
                  data: SliderTheme.of(context).copyWith(
                    trackHeight: 3,
                    thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 5),
                    overlayShape: const RoundSliderOverlayShape(overlayRadius: 10),
                    activeTrackColor: const Color(0xFF6366F1),
                    inactiveTrackColor: Colors.white12,
                    thumbColor: Colors.white,
                  ),
                  child: Slider(
                    value: currentSeconds,
                    min: 0.0,
                    max: maxSeconds,
                    onChanged: (val) {
                      _audioService.seek(Duration(seconds: val.toInt()));
                    },
                  ),
                ),
              ),
              // Total Duration
              Text(
                _formatDuration(dur),
                style: GoogleFonts.inter(
                  fontSize: 10.5,
                  color: Colors.white70,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildLoadingState() {
    final pct = (_loadingProgress * 100).toInt().clamp(5, 99);
    String stepBadge = "ដំណាក់កាលទី ១/៤";
    String stepTitle = "កំពុងទាញយកទិន្នន័យ & ឯកសារកិច្ចប្រជុំ...";
    IconData stepIcon = Icons.cloud_download_rounded;

    if (_loadingProgress >= 0.25 && _loadingProgress < 0.60) {
      stepBadge = "ដំណាក់កាលទី ២/៤";
      stepTitle = "AI កំពុងស្តាប់ & វិភាគខ្លឹមសារកិច្ចប្រជុំ...";
      stepIcon = Icons.graphic_eq_rounded;
    } else if (_loadingProgress >= 0.60 && _loadingProgress < 0.85) {
      stepBadge = "ដំណាក់កាលទី ៣/៤";
      stepTitle = "កំពុងស្រង់ចំណុចសំខាន់ និងការសម្រេចចិត្ត...";
      stepIcon = Icons.psychology_rounded;
    } else if (_loadingProgress >= 0.85) {
      stepBadge = "ដំណាក់កាលទី ៤/៤";
      stepTitle = "កំពុងរៀបចំកំណត់ហេតុប្រតិបត្តិ (Executive Minutes)...";
      stepIcon = Icons.auto_awesome_rounded;
    }

    final elapsedSeconds = _loadingSeconds ~/ 3;
    final elapsedStr = "${(elapsedSeconds ~/ 60).toString().padLeft(2, '0')}:${(elapsedSeconds % 60).toString().padLeft(2, '0')}";

    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
        child: Container(
          padding: const EdgeInsets.all(24),
          decoration: BoxDecoration(
            color: const Color(0xFF1E293B).withValues(alpha: 0.7),
            borderRadius: BorderRadius.circular(24),
            border: Border.all(color: const Color(0xFF6366F1).withValues(alpha: 0.3)),
            boxShadow: [
              BoxShadow(
                color: const Color(0xFF6366F1).withValues(alpha: 0.15),
                blurRadius: 30,
                offset: const Offset(0, 10),
              ),
            ],
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Glowing Animated AI Icon
              Container(
                width: 68,
                height: 68,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: const LinearGradient(
                    colors: [Color(0xFF6366F1), Color(0xFFA855F7), Color(0xFFEC4899)],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: const Color(0xFF6366F1).withValues(alpha: 0.5),
                      blurRadius: 20,
                      spreadRadius: 2,
                    ),
                  ],
                ),
                child: Center(
                  child: Icon(stepIcon, color: Colors.white, size: 34),
                ),
              ),
              const SizedBox(height: 20),

              // Title
              Text(
                "AI កំពុងវិភាគ និងសង្ខេបកិច្ចប្រជុំ",
                textAlign: TextAlign.center,
                style: GoogleFonts.kantumruyPro(
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
              const SizedBox(height: 6),

              // Subtitle
              Text(
                "ដំណើរការដោយ Google Gemini AI & Advanced Models",
                textAlign: TextAlign.center,
                style: GoogleFonts.inter(
                  fontSize: 11,
                  color: Colors.white60,
                ),
              ),
              const SizedBox(height: 24),

              // Step Badge & Percentage
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(
                      color: const Color(0xFF6366F1).withValues(alpha: 0.2),
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(color: const Color(0xFF6366F1).withValues(alpha: 0.4)),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.bolt_rounded, color: Color(0xFF818CF8), size: 14),
                        const SizedBox(width: 4),
                        Text(
                          stepBadge,
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 11.5,
                            fontWeight: FontWeight.bold,
                            color: const Color(0xFF818CF8),
                          ),
                        ),
                      ],
                    ),
                  ),
                  Text(
                    "$pct%",
                    style: GoogleFonts.outfit(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: const Color(0xFFFBBF24),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),

              // Modern Progress Bar
              ClipRRect(
                borderRadius: BorderRadius.circular(10),
                child: SizedBox(
                  height: 10,
                  child: Stack(
                    children: [
                      // Background Track
                      Container(color: Colors.white.withValues(alpha: 0.08)),
                      // Animated Fill
                      LayoutBuilder(
                        builder: (ctx, constraints) {
                          return AnimatedContainer(
                            duration: const Duration(milliseconds: 300),
                            curve: Curves.easeOutQuad,
                            width: constraints.maxWidth * _loadingProgress,
                            decoration: BoxDecoration(
                              gradient: const LinearGradient(
                                colors: [Color(0xFF6366F1), Color(0xFFA855F7), Color(0xFFEC4899)],
                              ),
                              borderRadius: BorderRadius.circular(10),
                              boxShadow: [
                                BoxShadow(
                                  color: const Color(0xFFEC4899).withValues(alpha: 0.5),
                                  blurRadius: 8,
                                ),
                              ],
                            ),
                          );
                        },
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 14),

              // Step Detail Text
              AnimatedSwitcher(
                duration: const Duration(milliseconds: 250),
                child: Text(
                  stepTitle,
                  key: ValueKey(stepTitle),
                  textAlign: TextAlign.center,
                  style: GoogleFonts.kantumruyPro(
                    fontSize: 12.5,
                    color: const Color(0xFF94A3B8),
                    height: 1.4,
                  ),
                ),
              ),
              const SizedBox(height: 18),

              // Timer Ticker Badge
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.04),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.timer_outlined, size: 14, color: Colors.white54),
                    const SizedBox(width: 6),
                    Text(
                      "រយៈពេលដំណើរការ៖ $elapsedStr",
                      style: GoogleFonts.inter(
                        fontSize: 11,
                        color: Colors.white70,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildErrorState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Container(
          padding: const EdgeInsets.all(24),
          decoration: BoxDecoration(
            color: const Color(0xFF1E293B).withValues(alpha: 0.8),
            borderRadius: BorderRadius.circular(24),
            border: Border.all(color: Colors.redAccent.withValues(alpha: 0.3)),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.redAccent.withValues(alpha: 0.15),
                  shape: BoxShape.circle,
                ),
                child: const Icon(Icons.error_outline_rounded, color: Colors.redAccent, size: 42),
              ),
              const SizedBox(height: 16),
              Text(
                "មិនអាចទាញយកសេចក្តីសង្ខេបបានទេ",
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 15,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                _error ?? 'មានកំហុសក្នុងការតភ្ជាប់ Server',
                textAlign: TextAlign.center,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.redAccent.shade100,
                  fontSize: 12.5,
                  height: 1.4,
                ),
              ),
              const SizedBox(height: 20),
              ElevatedButton.icon(
                onPressed: () => _loadOrGenerateSummary(force: true),
                icon: const Icon(Icons.refresh_rounded, size: 18),
                label: Text("ព្យាយាមម្ដងទៀត (Retry)", style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF6366F1),
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 12),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildContentState() {
    final text = _summary?.trim() ?? '';
    if (text.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.auto_awesome_rounded, size: 40, color: Colors.white24),
            const SizedBox(height: 12),
            Text(
              'មិនទាន់មានសេចក្តីសង្ខេបនៅឡើយទេ',
              style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary),
            ),
            const SizedBox(height: 14),
            ElevatedButton.icon(
              onPressed: () => _loadOrGenerateSummary(force: true),
              icon: const Icon(Icons.auto_awesome_rounded, size: 16),
              label: Text("បង្កើតសេចក្តីសង្ខេប AI ឥឡូវនេះ", style: GoogleFonts.kantumruyPro(fontSize: 12.5)),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF6366F1),
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
            ),
          ],
        ),
      );
    }
    return _buildFormattedSummary(text);
  }

  List<InlineSpan> _parseInlineSpans(String text, {Color? defaultColor, double fontSize = 13.5}) {
    final List<InlineSpan> spans = [];
    final regex = RegExp(r'\*\*(.*?)\*\*');
    int lastMatchEnd = 0;

    for (final match in regex.allMatches(text)) {
      if (match.start > lastMatchEnd) {
        spans.add(TextSpan(
          text: text.substring(lastMatchEnd, match.start),
          style: GoogleFonts.kantumruyPro(
            fontSize: fontSize,
            color: defaultColor ?? AppTheme.textPrimary,
            height: 1.85,
          ),
        ));
      }
      spans.add(TextSpan(
        text: match.group(1),
        style: GoogleFonts.kantumruyPro(
          fontSize: fontSize,
          fontWeight: FontWeight.bold,
          color: Colors.white,
          height: 1.85,
        ),
      ));
      lastMatchEnd = match.end;
    }

    if (lastMatchEnd < text.length) {
      spans.add(TextSpan(
        text: text.substring(lastMatchEnd),
        style: GoogleFonts.kantumruyPro(
          fontSize: fontSize,
          color: defaultColor ?? AppTheme.textPrimary,
          height: 1.85,
        ),
      ));
    }

    return spans;
  }

  Widget _buildFormattedSummary(String rawText) {
    final lines = rawText.split('\n');
    final List<Widget> widgets = [];

    for (int i = 0; i < lines.length; i++) {
      final line = lines[i].trim();
      if (line.isEmpty) continue;

      if (line == '---' || line == '***' || line == '___') {
        widgets.add(const Divider(color: Colors.white12, height: 24));
        continue;
      }

      // Title #
      if (line.startsWith('# ') || line.startsWith('## ')) {
        final title = line.replaceAll(RegExp(r'^#+\s*'), '');
        widgets.add(
          Container(
            margin: const EdgeInsets.symmetric(vertical: 8),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  const Color(0xFF6366F1).withValues(alpha: 0.18),
                  const Color(0xFFA855F7).withValues(alpha: 0.10),
                ],
              ),
              borderRadius: BorderRadius.circular(10),
              border: const Border(left: BorderSide(color: Color(0xFF6366F1), width: 4)),
            ),
            child: Text.rich(
              TextSpan(
                children: _parseInlineSpans(title, defaultColor: const Color(0xFF818CF8), fontSize: 14.5),
              ),
            ),
          ),
        );
        continue;
      }

      // Section Headings ### 📌, 🎯, ✅, 📋
      if (line.startsWith('### ') || RegExp(r'^(📌|🎯|✅|📋|📝|💡)\s*').hasMatch(line)) {
        final heading = line.replaceAll(RegExp(r'^###\s*'), '');
        Color badgeBg = const Color(0xFF3B82F6).withValues(alpha: 0.15);
        Color badgeColor = const Color(0xFF60A5FA);
        Color borderClr = const Color(0xFF3B82F6).withValues(alpha: 0.35);

        if (heading.contains('២.') || heading.contains('🎯') || heading.contains('ចំណុច')) {
          badgeBg = const Color(0xFFF59E0B).withValues(alpha: 0.15);
          badgeColor = const Color(0xFFFBBF24);
          borderClr = const Color(0xFFF59E0B).withValues(alpha: 0.35);
        } else if (heading.contains('៣.') || heading.contains('✅') || heading.contains('សម្រេច')) {
          badgeBg = const Color(0xFF10B981).withValues(alpha: 0.15);
          badgeColor = const Color(0xFF34D399);
          borderClr = const Color(0xFF10B981).withValues(alpha: 0.35);
        } else if (heading.contains('៤.') || heading.contains('📋') || heading.contains('សកម្មភាព')) {
          badgeBg = const Color(0xFF8B5CF6).withValues(alpha: 0.15);
          badgeColor = const Color(0xFFA78BFA);
          borderClr = const Color(0xFF8B5CF6).withValues(alpha: 0.35);
        }

        widgets.add(
          Container(
            margin: const EdgeInsets.only(top: 14, bottom: 8),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: badgeBg,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: borderClr),
            ),
            child: Text.rich(
              TextSpan(
                children: _parseInlineSpans(heading, defaultColor: badgeColor, fontSize: 13.5),
              ),
            ),
          ),
        );
        continue;
      }

      // Metadata bullet point (* **Key:** Value)
      final metaMatch = RegExp(r'^[\*\-]\s+\*\*(.*?)\*\*\s*[:៖]\s*(.*)').firstMatch(line);
      if (metaMatch != null) {
        final key = metaMatch.group(1) ?? '';
        final val = metaMatch.group(2) ?? '';
        widgets.add(
          Container(
            margin: const EdgeInsets.only(bottom: 6),
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: Colors.white.withValues(alpha: 0.03),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SizedBox(
                  width: 105,
                  child: Text(
                    "$key:",
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 12.5,
                      fontWeight: FontWeight.bold,
                      color: const Color(0xFF818CF8),
                    ),
                  ),
                ),
                Expanded(
                  child: Text.rich(
                    TextSpan(children: _parseInlineSpans(val, fontSize: 12.5)),
                  ),
                ),
              ],
            ),
          ),
        );
        continue;
      }

      // Numbered List Items
      final numMatch = RegExp(r'^(\d+)[\.\)]\s+(.*)').firstMatch(line);
      if (numMatch != null) {
        final num = numMatch.group(1) ?? '1';
        final content = numMatch.group(2) ?? '';
        widgets.add(
          Padding(
            padding: const EdgeInsets.only(bottom: 6),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  margin: const EdgeInsets.only(top: 3, right: 8),
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
                  decoration: BoxDecoration(
                    color: const Color(0xFF6366F1).withValues(alpha: 0.2),
                    borderRadius: BorderRadius.circular(5),
                  ),
                  child: Text(
                    num,
                    style: GoogleFonts.kantumruyPro(
                      fontSize: 11,
                      fontWeight: FontWeight.bold,
                      color: const Color(0xFF818CF8),
                    ),
                  ),
                ),
                Expanded(
                  child: Text.rich(
                    TextSpan(children: _parseInlineSpans(content, fontSize: 13.5)),
                  ),
                ),
              ],
            ),
          ),
        );
        continue;
      }

      // Bullet List Items
      final bulletMatch = RegExp(r'^[\*\-]\s+(.*)').firstMatch(line);
      if (bulletMatch != null) {
        final content = bulletMatch.group(1) ?? '';
        widgets.add(
          Padding(
            padding: const EdgeInsets.only(bottom: 6),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Padding(
                  padding: EdgeInsets.only(top: 5, right: 8),
                  child: Icon(Icons.circle, size: 6, color: Colors.amber),
                ),
                Expanded(
                  child: Text.rich(
                    TextSpan(children: _parseInlineSpans(content, fontSize: 13.5)),
                  ),
                ),
              ],
            ),
          ),
        );
        continue;
      }

      // Normal Paragraph
      widgets.add(
        Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: Text.rich(
            TextSpan(children: _parseInlineSpans(line, fontSize: 13.5)),
          ),
        ),
      );
    }

    return SingleChildScrollView(
      controller: _scrollController,
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 6),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: widgets,
      ),
    );
  }
}


