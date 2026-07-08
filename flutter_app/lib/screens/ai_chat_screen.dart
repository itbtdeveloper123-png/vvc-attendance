import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:image_picker/image_picker.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

class AiChatScreen extends StatefulWidget {
  const AiChatScreen({super.key});

  @override
  State<AiChatScreen> createState() => _AiChatScreenState();
}

enum _AiMessageSender { user, assistant }

enum _PromptCategory { general, attendance, leave, request, hrm }

class _PromptOption {
  const _PromptOption({required this.category, required this.text});

  final _PromptCategory category;
  final String text;
}

class _AiChatSession {
  const _AiChatSession({
    required this.id,
    required this.title,
    required this.updatedAt,
  });

  final int? id;
  final String title;
  final dynamic updatedAt;

  factory _AiChatSession.fromJson(Map<String, dynamic> json) {
    final title = '${json['title'] ?? 'AI Assistant'}'.trim();
    return _AiChatSession(
      id: _toInt(json['id']),
      title: title.isNotEmpty ? title : 'AI Assistant',
      updatedAt: json['updated_at'],
    );
  }

  static int? _toInt(dynamic value) {
    if (value is int) return value;
    return int.tryParse('${value ?? ''}');
  }
}

class _AiMessage {
  const _AiMessage({
    required this.sender,
    required this.text,
    required this.createdAt,
    this.sources = const [],
    this.provider = '',
    this.modelName = '',
    this.attachmentType = '',
    this.attachmentPath = '',
    this.attachmentBase64 = '',
    this.isError = false,
    this.retryText,
  });

  final _AiMessageSender sender;
  final String text;
  final dynamic createdAt;
  final List<String> sources;
  final String provider;
  final String modelName;
  final String attachmentType;
  final String attachmentPath;
  final String attachmentBase64;
  final bool isError;
  final String? retryText;

  bool get isUser => sender == _AiMessageSender.user;
  bool get isAssistant => sender == _AiMessageSender.assistant;
  bool get hasImageAttachment =>
      attachmentBase64.isNotEmpty ||
      (attachmentPath.isNotEmpty && attachmentType.startsWith('image/'));

  factory _AiMessage.fromJson(Map<String, dynamic> json) {
    final senderType = '${json['sender_type'] ?? ''}'.trim().toLowerCase();
    return _AiMessage(
      sender: senderType == 'user'
          ? _AiMessageSender.user
          : _AiMessageSender.assistant,
      text: '${json['message_text'] ?? ''}'.trim(),
      createdAt: json['created_at'],
      sources: List<String>.from(json['sources'] as List? ?? const []),
      provider: '${json['provider'] ?? ''}',
      modelName: '${json['model_name'] ?? json['model'] ?? ''}',
      attachmentType: '${json['attachment_type'] ?? json['mime_type'] ?? ''}',
      attachmentPath:
          '${json['attachment_path'] ?? json['image_path'] ?? ''}'.trim(),
      attachmentBase64: '${json['image_base64'] ?? ''}'.trim(),
      isError: json['is_error'] == true,
      retryText: '${json['retry_text'] ?? ''}'.trim().isNotEmpty
          ? '${json['retry_text']}'.trim()
          : null,
    );
  }

  factory _AiMessage.user(
    String text, {
    required dynamic createdAt,
    String attachmentType = '',
    String attachmentPath = '',
    String attachmentBase64 = '',
  }) {
    return _AiMessage(
      sender: _AiMessageSender.user,
      text: text,
      createdAt: createdAt,
      attachmentType: attachmentType,
      attachmentPath: attachmentPath,
      attachmentBase64: attachmentBase64,
    );
  }

  factory _AiMessage.assistant({
    required String text,
    required dynamic createdAt,
    List<String> sources = const [],
    String provider = '',
    String modelName = '',
    String attachmentType = '',
    String attachmentPath = '',
    String attachmentBase64 = '',
    bool isError = false,
    String? retryText,
  }) {
    return _AiMessage(
      sender: _AiMessageSender.assistant,
      text: text,
      createdAt: createdAt,
      sources: sources,
      provider: provider,
      modelName: modelName,
      attachmentType: attachmentType,
      attachmentPath: attachmentPath,
      attachmentBase64: attachmentBase64,
      isError: isError,
      retryText: retryText,
    );
  }

  _AiMessage copyWith({
    String? text,
    dynamic createdAt,
    List<String>? sources,
    String? provider,
    String? modelName,
    String? attachmentType,
    String? attachmentPath,
    String? attachmentBase64,
    bool? isError,
    String? retryText,
  }) {
    return _AiMessage(
      sender: sender,
      text: text ?? this.text,
      createdAt: createdAt ?? this.createdAt,
      sources: sources ?? this.sources,
      provider: provider ?? this.provider,
      modelName: modelName ?? this.modelName,
      attachmentType: attachmentType ?? this.attachmentType,
      attachmentPath: attachmentPath ?? this.attachmentPath,
      attachmentBase64: attachmentBase64 ?? this.attachmentBase64,
      isError: isError ?? this.isError,
      retryText: retryText ?? this.retryText,
    );
  }
}

class _AiChatScreenState extends State<AiChatScreen>
    with SingleTickerProviderStateMixin {
  static const Duration _phnomPenhOffset = Duration(hours: 7);

  final ApiService _api = ApiService();
  final ImagePicker _imagePicker = ImagePicker();
  final TextEditingController _messageController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final FocusNode _composerFocusNode = FocusNode();
  late final AnimationController _typingAnimationController;

  bool _isBootstrapping = true;
  bool _isLoadingHistory = false;
  bool _isSending = false;
  bool _isCreatingSession = false;
  bool _isDeletingSession = false;
  bool _hasComposerText = false;
  bool _showScrollToBottomButton = false;

  int? _activeSessionId;
  String _activeSessionTitle = 'AI Assistant';
  _PromptCategory _selectedPromptCategory = _PromptCategory.general;
  List<_AiMessage> _messages = [];
  List<_AiChatSession> _sessions = [];
  Map<int, String> _sessionTitleOverrides = {};

  @override
  void initState() {
    super.initState();
    _messageController.addListener(_handleComposerChanged);
    _scrollController.addListener(_handleScrollChanged);
    _typingAnimationController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    )..repeat();
    _bootstrap();
  }

  @override
  void dispose() {
    _messageController.removeListener(_handleComposerChanged);
    _scrollController.removeListener(_handleScrollChanged);
    _typingAnimationController.dispose();
    _messageController.dispose();
    _composerFocusNode.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _handleComposerChanged() {
    final hasText = _messageController.text.trim().isNotEmpty;
    if (hasText == _hasComposerText) return;
    setState(() => _hasComposerText = hasText);
  }

  void _handleScrollChanged() {
    if (!_scrollController.hasClients) return;
    final distanceFromBottom =
        _scrollController.position.maxScrollExtent - _scrollController.offset;
    final shouldShow = distanceFromBottom > 220;
    if (shouldShow == _showScrollToBottomButton) return;
    setState(() => _showScrollToBottomButton = shouldShow);
  }

  Future<void> _bootstrap() async {
    setState(() => _isBootstrapping = true);
    await _loadSessionTitleOverrides();
    await _loadSessions();
    if (_sessions.isNotEmpty) {
      final first = _sessions.first;
      final sessionId = first.id;
      if (sessionId != null) {
        await _loadSession(
          sessionId,
          title: _displaySessionTitle(first),
        );
      }
    }
    if (mounted) {
      setState(() => _isBootstrapping = false);
    }
  }

  Future<void> _loadSessionTitleOverrides() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString('ai_chat_session_title_overrides');
    if (raw == null || raw.trim().isEmpty) return;

    try {
      final decoded = json.decode(raw);
      if (decoded is! Map) return;
      _sessionTitleOverrides = decoded.map<int, String>(
        (key, value) => MapEntry(
          int.tryParse('$key') ?? -1,
          '$value'.trim(),
        ),
      )..removeWhere((key, value) => key <= 0 || value.isEmpty);
    } catch (_) {}
  }

  Future<void> _saveSessionTitleOverrides() async {
    final prefs = await SharedPreferences.getInstance();
    final encoded = json.encode(
      _sessionTitleOverrides.map((key, value) => MapEntry('$key', value)),
    );
    await prefs.setString('ai_chat_session_title_overrides', encoded);
  }

  String _displaySessionTitle(_AiChatSession session) {
    final override = session.id == null
        ? null
        : _sessionTitleOverrides[session.id!]?.trim();
    if (override != null && override.isNotEmpty) return override;
    return session.title;
  }

  Future<void> _loadSessions() async {
    final res = await _api.getAiChatSessions(limit: 20);
    if (!mounted) return;
    if (res['success'] == true) {
      final list = List<_AiChatSession>.from(
        (res['sessions'] as List? ?? []).map(
          (item) => _AiChatSession.fromJson(
            Map<String, dynamic>.from(item as Map),
          ),
        ),
      );
      setState(() {
        _sessions = list;
        _AiChatSession? active;
        if (_activeSessionId != null) {
          for (final item in list) {
            if (item.id == _activeSessionId) {
              active = item;
              break;
            }
          }
        }
        if (active != null) {
          _activeSessionTitle = _displaySessionTitle(active);
        }
      });
    }
  }

  Future<void> _loadSession(int sessionId, {String? title}) async {
    if (!mounted) return;
    setState(() {
      _isLoadingHistory = true;
      _activeSessionId = sessionId;
      _activeSessionTitle = title?.trim().isNotEmpty == true
          ? title!.trim()
          : 'AI Assistant';
    });

    final res = await _api.getAiChatHistory(sessionId);
    if (!mounted) return;

    if (res['success'] == true) {
      final history = List<_AiMessage>.from(
        (res['messages'] as List? ?? []).map(
          (item) => _AiMessage.fromJson(
            Map<String, dynamic>.from(item as Map),
          ),
        ),
      );
      final session = res['session'];
      setState(() {
        _messages = history;
        final serverTitle =
            '${(session is Map ? session['title'] : null) ?? _activeSessionTitle}'
                .trim();
        final sessionModel = _AiChatSession(
          id: sessionId,
          title: serverTitle.isNotEmpty ? serverTitle : 'AI Assistant',
          updatedAt: session is Map ? session['updated_at'] : null,
        );
        _activeSessionTitle = _displaySessionTitle(sessionModel);
      });
      _scrollToBottom();
    } else {
      _showSnackBar('${res['message'] ?? 'មិនអាចបើកប្រវត្តិជជែកបានទេ'}');
    }

    if (mounted) {
      setState(() => _isLoadingHistory = false);
    }
  }

  Future<void> _createNewSession() async {
    if (_isCreatingSession) return;
    setState(() => _isCreatingSession = true);

    final res = await _api.createAiChatSession(title: 'AI Assistant');
    if (!mounted) return;

    if (res['success'] == true && res['session'] is Map) {
      final session = _AiChatSession.fromJson(
        Map<String, dynamic>.from(res['session'] as Map),
      );
      setState(() {
        _messages = [];
        _activeSessionId = session.id;
        _activeSessionTitle = _displaySessionTitle(session);
      });
      await _loadSessions();
      _showSnackBar('បានបង្កើតការជជែក AI ថ្មីរួចរាល់');
    } else {
      _showSnackBar('${res['message'] ?? 'មិនអាចបង្កើតការជជែកថ្មីបានទេ'}');
    }

    if (mounted) {
      setState(() => _isCreatingSession = false);
    }
  }

  Future<bool> _confirmDeleteSession(String title) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          backgroundColor: AppTheme.bgCard,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(22),
            side: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
          ),
          title: Text(
            'លុបប្រវត្តិជជែក?',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
            ),
          ),
          content: Text(
            'ប្រវត្តិ "$title" និងសារទាំងអស់ក្នុងវានឹងត្រូវលុបជាអចិន្ត្រៃយ៍។',
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textSecondary,
              fontSize: 13,
              height: 1.45,
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(false),
              child: Text(
                'បោះបង់',
                style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary),
              ),
            ),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                backgroundColor: AppTheme.danger,
                foregroundColor: Colors.white,
              ),
              onPressed: () => Navigator.of(dialogContext).pop(true),
              icon: const Icon(Icons.delete_outline_rounded, size: 18),
              label: Text('លុប', style: GoogleFonts.kantumruyPro()),
            ),
          ],
        );
      },
    );
    return result == true;
  }

  Future<bool> _confirmDeleteAllSessions() async {
    final result = await showDialog<bool>(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          backgroundColor: AppTheme.bgCard,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(22),
            side: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
          ),
          title: Text(
            'លុបប្រវត្តិជជែកទាំងអស់?',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
            ),
          ),
          content: Text(
            'វានឹងលុប session និងសារជជែក AI ទាំងអស់ជាអចិន្ត្រៃយ៍។',
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textSecondary,
              fontSize: 13,
              height: 1.45,
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(false),
              child: Text(
                'បោះបង់',
                style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary),
              ),
            ),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                backgroundColor: AppTheme.danger,
                foregroundColor: Colors.white,
              ),
              onPressed: () => Navigator.of(dialogContext).pop(true),
              icon: const Icon(Icons.delete_sweep_rounded, size: 18),
              label: Text('លុបទាំងអស់', style: GoogleFonts.kantumruyPro()),
            ),
          ],
        );
      },
    );
    return result == true;
  }

  Future<void> _deleteSessionById(
    int sessionId, {
    String? title,
    bool skipConfirm = false,
  }) async {
    if (_isDeletingSession) return;

    final sessionTitle = (title ?? _activeSessionTitle).trim().isNotEmpty
        ? (title ?? _activeSessionTitle).trim()
        : 'AI Assistant';

    if (!skipConfirm) {
      final confirmed = await _confirmDeleteSession(sessionTitle);
      if (!mounted || !confirmed) return;
    }

    final deletingActive = sessionId == _activeSessionId;
    setState(() => _isDeletingSession = true);

    final res = await _api.deleteAiChatSession(sessionId);
    if (!mounted) return;

    if (res['success'] == true) {
      await _loadSessions();
      if (!mounted) return;

      if (deletingActive) {
        if (_sessions.isNotEmpty) {
          final next = _sessions.first;
          final nextId = next.id;
          if (nextId != null) {
            await _loadSession(
              nextId,
              title: next.title,
            );
          } else {
            setState(() {
              _activeSessionId = null;
              _activeSessionTitle = 'AI Assistant';
              _messages = [];
            });
          }
        } else {
          setState(() {
            _activeSessionId = null;
            _activeSessionTitle = 'AI Assistant';
            _messages = [];
          });
        }
      }

      _showSnackBar('បានលុបប្រវត្តិជជែក');
    } else {
      _showSnackBar('${res['message'] ?? 'មិនអាចលុបប្រវត្តិជជែកបានទេ'}');
    }

    if (mounted) {
      setState(() => _isDeletingSession = false);
    }
  }

  Future<void> _deleteAllSessions({bool skipConfirm = false}) async {
    if (_isDeletingSession) return;

    if (!skipConfirm) {
      final confirmed = await _confirmDeleteAllSessions();
      if (!mounted || !confirmed) return;
    }

    setState(() => _isDeletingSession = true);

    final res = await _api.deleteAllAiChatSessions();
    if (!mounted) return;

    if (res['success'] == true) {
      await _loadSessions();
      if (!mounted) return;

      setState(() {
        _activeSessionId = null;
        _activeSessionTitle = 'AI Assistant';
        _messages = [];
      });

      _showSnackBar('បានលុបប្រវត្តិជជែកទាំងអស់');
    } else {
      _showSnackBar('${res['message'] ?? 'មិនអាចលុបប្រវត្តិទាំងអស់បានទេ'}');
    }

    if (mounted) {
      setState(() => _isDeletingSession = false);
    }
  }

  Future<void> _sendMessage({String? preset}) async {
    if (_isSending) return;

    final rawText = preset ?? _messageController.text;
    final text = rawText.trim();
    if (text.isEmpty) return;

    FocusScope.of(context).unfocus();
    _messageController.clear();

    setState(() {
      _isSending = true;
      _messages = [
        ..._messages,
        _AiMessage.user(text, createdAt: _currentTimestamp()),
      ];
    });
    _scrollToBottom();

    final res = await _api.sendAiChatMessage(text, sessionId: _activeSessionId);
    if (!mounted) return;

    if (res['success'] == true) {
      final sessionId = _toInt(res['session_id']);
      final reply = '${res['reply'] ?? ''}'.trim();
      final sessionTitle = '${res['session_title'] ?? _activeSessionTitle}'
          .trim();
      final sources = List<String>.from(res['sources'] as List? ?? const []);
      setState(() {
        if (sessionId != null) {
          _activeSessionId = sessionId;
        }
        if (sessionTitle.isNotEmpty) {
          _activeSessionTitle = sessionTitle;
        }
        _messages = [
          ..._messages,
          _AiMessage.assistant(
            text: reply.isNotEmpty ? reply : 'មិនមានចម្លើយ',
            createdAt: _currentTimestamp(),
            sources: sources,
            provider: '${res['provider'] ?? ''}',
            modelName: '${res['model'] ?? ''}',
          ),
        ];
      });
      await _loadSessions();
      if (_activeSessionId != null) {
        _AiChatSession? current;
        for (final item in _sessions) {
          if (item.id == _activeSessionId) {
            current = item;
            break;
          }
        }
        if (current != null) {
          final currentTitle = current.title;
          setState(() {
            _activeSessionTitle = currentTitle;
          });
        }
      }
      _scrollToBottom();
    } else {
      setState(() {
        _messages = [
          ..._messages,
          _AiMessage.assistant(
            text: '${res['message'] ?? 'មិនអាចទទួលចម្លើយពី AI បានទេ'}',
            createdAt: _currentTimestamp(),
            isError: true,
            retryText: text,
          ),
        ];
      });
      _scrollToBottom();
    }

    if (mounted) {
      setState(() => _isSending = false);
    }
  }

  Future<void> _removeBackgroundFromImage() async {
    if (_isSending) return;

    final pickedFile = await _imagePicker.pickImage(
      source: ImageSource.gallery,
      maxWidth: 1280,
      maxHeight: 1280,
      imageQuality: 92,
    );
    if (pickedFile == null) return;

    late final Uint8List imageBytes;
    try {
      imageBytes = await pickedFile.readAsBytes();
    } catch (e) {
      _showSnackBar('មិនអាចអានរូបភាពបានទេ: $e');
      return;
    }

    const maxImageBytes = 8 * 1024 * 1024;
    if (imageBytes.length > maxImageBytes) {
      _showSnackBar('រូបភាពធំពេក។ សូមជ្រើសរូបក្រោម 8MB។');
      return;
    }

    final imageBase64 = base64Encode(imageBytes);
    const requestText = 'កាត់ Background រូបភាពនេះជា PNG គ្មានផ្ទៃខាងក្រោយ';

    if (!mounted) return;
    FocusScope.of(context).unfocus();
    setState(() {
      _isSending = true;
      _messages = [
        ..._messages,
        _AiMessage.user(
          requestText,
          createdAt: _currentTimestamp(),
          attachmentType: 'image/source',
          attachmentBase64: imageBase64,
        ),
      ];
    });
    _scrollToBottom();

    final res = await _api.removeAiChatImageBackground(
      imageBase64,
      sessionId: _activeSessionId,
    );
    if (!mounted) return;

    if (res['success'] == true) {
      final sessionId = _toInt(res['session_id']);
      final sessionTitle = '${res['session_title'] ?? _activeSessionTitle}'
          .trim();
      final reply = '${res['reply'] ?? ''}'.trim();

      setState(() {
        if (sessionId != null) {
          _activeSessionId = sessionId;
        }
        if (sessionTitle.isNotEmpty) {
          _activeSessionTitle = sessionTitle;
        }
        _messages = [
          ..._messages,
          _AiMessage.assistant(
            text: reply.isNotEmpty
                ? reply
                : 'បានកាត់ Background រូបភាពរួចហើយ។',
            createdAt: _currentTimestamp(),
            provider: '${res['provider'] ?? 'imgly'}',
            modelName: '${res['model'] ?? 'background-removal-node'}',
            attachmentType: '${res['attachment_type'] ?? 'image/png'}',
            attachmentPath:
                '${res['attachment_path'] ?? res['image_path'] ?? ''}',
            attachmentBase64: '${res['image_base64'] ?? ''}',
          ),
        ];
      });
      await _loadSessions();
      _scrollToBottom();
    } else {
      setState(() {
        _messages = [
          ..._messages,
          _AiMessage.assistant(
            text:
                '${res['message'] ?? 'មិនអាចកាត់ Background រូបភាពនេះបានទេ'}',
            createdAt: _currentTimestamp(),
            isError: true,
          ),
        ];
      });
      _scrollToBottom();
    }

    if (mounted) {
      setState(() => _isSending = false);
    }
  }

  Future<void> _copyAssistantReply(String text) async {
    final content = text.trim();
    if (content.isEmpty) return;

    await Clipboard.setData(ClipboardData(text: content));
    if (!mounted) return;
    _showSnackBar('បានចម្លងចម្លើយ');
  }

  Future<void> _copyImageUrl(_AiMessage message) async {
    final path = message.attachmentPath.trim();
    if (path.isEmpty) return;

    await Clipboard.setData(
      ClipboardData(text: ApiService.getFullImageUrl(path)),
    );
    if (!mounted) return;
    _showSnackBar('បានចម្លង URL រូបភាព');
  }

  Future<void> _retryMessage(String text) async {
    final retryText = text.trim();
    if (retryText.isEmpty || _isSending) return;
    await _sendMessage(preset: retryText);
  }

  Future<void> _resendUserMessage(String text) async {
    final resendText = text.trim();
    if (resendText.isEmpty || _isSending) return;
    await _sendMessage(preset: resendText);
  }

  void _editUserMessage(String text) {
    final editText = text.trim();
    if (editText.isEmpty || _isSending) return;
    _messageController.text = editText;
    _messageController.selection = TextSelection.collapsed(
      offset: _messageController.text.length,
    );
    _composerFocusNode.requestFocus();
  }

  Future<void> _renameSession(_AiChatSession session) async {
    final sessionId = session.id;
    if (sessionId == null) return;

    final controller = TextEditingController(text: _displaySessionTitle(session));
    final newTitle = await showDialog<String>(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          backgroundColor: AppTheme.bgCard,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(22),
            side: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
          ),
          title: Text(
            'កែឈ្មោះការជជែក',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
            ),
          ),
          content: TextField(
            controller: controller,
            autofocus: true,
            maxLength: 80,
            style: GoogleFonts.kantumruyPro(color: Colors.white),
            decoration: InputDecoration(
              counterStyle: GoogleFonts.inter(color: AppTheme.textMuted),
              hintText: 'ឈ្មោះថ្មី',
              hintStyle: GoogleFonts.kantumruyPro(color: AppTheme.textMuted),
              enabledBorder: UnderlineInputBorder(
                borderSide: BorderSide(
                  color: Colors.white.withValues(alpha: 0.18),
                ),
              ),
              focusedBorder: UnderlineInputBorder(
                borderSide: BorderSide(color: AppTheme.primary),
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(),
              child: Text(
                'បោះបង់',
                style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary),
              ),
            ),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                backgroundColor: AppTheme.primary,
                foregroundColor: Colors.white,
              ),
              onPressed: () =>
                  Navigator.of(dialogContext).pop(controller.text.trim()),
              icon: const Icon(Icons.drive_file_rename_outline_rounded, size: 18),
              label: Text('រក្សាទុក', style: GoogleFonts.kantumruyPro()),
            ),
          ],
        );
      },
    );
    controller.dispose();

    final title = newTitle?.trim();
    if (title == null || title.isEmpty) return;

    setState(() {
      _sessionTitleOverrides[sessionId] = title;
      if (_activeSessionId == sessionId) {
        _activeSessionTitle = title;
      }
    });
    await _saveSessionTitleOverrides();
    _showSnackBar('បានកែឈ្មោះការជជែក');
  }

  bool _isLatestAssistantMessage(int index) {
    if (index < 0 || index >= _messages.length) return false;

    for (var i = _messages.length - 1; i >= 0; i--) {
      if (_messages[i].isAssistant) {
        return i == index;
      }
    }
    return false;
  }

  Future<void> _regenerateAssistantReply(int index) async {
    if (_isSending || _activeSessionId == null) return;
    if (!_isLatestAssistantMessage(index)) {
      _showSnackBar('អាចបង្កើតចម្លើយឡើងវិញបានតែចម្លើយ AI ចុងក្រោយប៉ុណ្ណោះ');
      return;
    }

    final currentMessage = _messages[index];
    if (!currentMessage.isAssistant || currentMessage.isError) {
      return;
    }

    setState(() => _isSending = true);
    _scrollToBottom();

    final res = await _api.regenerateAiChatReply(_activeSessionId!);
    if (!mounted) return;

    if (res['success'] == true) {
      final reply = '${res['reply'] ?? ''}'.trim();
      final sources = List<String>.from(res['sources'] as List? ?? const []);
      final updatedMessages = List<_AiMessage>.from(_messages);
      updatedMessages[index] = updatedMessages[index].copyWith(
        text: reply.isNotEmpty ? reply : 'មិនមានចម្លើយ',
        createdAt: _currentTimestamp(),
        sources: sources,
        provider: '${res['provider'] ?? ''}',
        modelName: '${res['model'] ?? ''}',
        isError: false,
      );

      setState(() {
        _messages = updatedMessages;
        final sessionTitle = '${res['session_title'] ?? _activeSessionTitle}'
            .trim();
        if (sessionTitle.isNotEmpty) {
          _activeSessionTitle = sessionTitle;
        }
      });
      await _loadSessions();
      _scrollToBottom();
      _showSnackBar('បានបង្កើតចម្លើយឡើងវិញ');
    } else {
      _showSnackBar('${res['message'] ?? 'មិនអាចបង្កើតចម្លើយឡើងវិញបានទេ'}');
    }

    if (mounted) {
      setState(() => _isSending = false);
    }
  }

  Future<void> _openSessionsSheet() async {
    await _loadSessions();
    if (!mounted) return;

    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (context) {
        var query = '';

        return StatefulBuilder(
          builder: (sheetContext, setSheetState) {
            final filtered = _sessions.where((session) {
              final title = _displaySessionTitle(session).toLowerCase();
              return query.isEmpty || title.contains(query.toLowerCase());
            }).toList();

            return Container(
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(28),
                ),
                border: Border.all(
                  color: Colors.white.withValues(alpha: 0.08),
                  width: 1,
                ),
              ),
              padding: const EdgeInsets.fromLTRB(20, 18, 20, 20),
              child: SafeArea(
                top: false,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            'ប្រវត្តិជជែក AI',
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                        IconButton(
                          tooltip: 'ការជជែកថ្មី',
                          onPressed: () async {
                            Navigator.pop(context);
                            await _createNewSession();
                          },
                          icon: const Icon(Icons.add_comment_rounded),
                        ),
                        IconButton(
                          tooltip: 'លុបទាំងអស់',
                          onPressed: _sessions.isEmpty || _isDeletingSession
                              ? null
                              : () async {
                                  final confirmed =
                                      await _confirmDeleteAllSessions();
                                  if (!mounted ||
                                      !context.mounted ||
                                      !confirmed) {
                                    return;
                                  }
                                  Navigator.pop(context);
                                  await _deleteAllSessions(skipConfirm: true);
                                },
                          icon: Icon(
                            Icons.delete_sweep_rounded,
                            color: AppTheme.danger,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    TextField(
                      onChanged: (value) {
                        setSheetState(() => query = value.trim());
                      },
                      style: GoogleFonts.kantumruyPro(color: Colors.white),
                      decoration: InputDecoration(
                        prefixIcon: Icon(
                          Icons.search_rounded,
                          color: AppTheme.textMuted,
                        ),
                        hintText: 'ស្វែងរកប្រវត្តិជជែក...',
                        hintStyle: GoogleFonts.kantumruyPro(
                          color: AppTheme.textMuted,
                        ),
                        filled: true,
                        fillColor: Colors.white.withValues(alpha: 0.05),
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(16),
                          borderSide: BorderSide(
                            color: Colors.white.withValues(alpha: 0.08),
                          ),
                        ),
                        enabledBorder: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(16),
                          borderSide: BorderSide(
                            color: Colors.white.withValues(alpha: 0.08),
                          ),
                        ),
                        focusedBorder: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(16),
                          borderSide: BorderSide(color: AppTheme.primary),
                        ),
                      ),
                    ),
                    const SizedBox(height: 10),
                    if (_sessions.isEmpty)
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        child: Text(
                          'មិនទាន់មានប្រវត្តិជជែកទេ។',
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textSecondary,
                            fontSize: 13,
                          ),
                        ),
                      )
                    else if (filtered.isEmpty)
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        child: Text(
                          'រកមិនឃើញការជជែកដែលត្រូវគ្នា។',
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textSecondary,
                            fontSize: 13,
                          ),
                        ),
                      )
                    else
                      SizedBox(
                        height: MediaQuery.of(context).size.height * 0.45,
                        child: ListView.separated(
                          shrinkWrap: true,
                          itemCount: filtered.length,
                          separatorBuilder: (_, _) => Divider(
                            color: Colors.white.withValues(alpha: 0.06),
                            height: 1,
                          ),
                          itemBuilder: (context, index) {
                            final item = filtered[index];
                            final sessionId = item.id;
                            final title = _displaySessionTitle(item);
                            final isActive =
                                sessionId != null &&
                                sessionId == _activeSessionId;
                            return ListTile(
                              contentPadding: EdgeInsets.zero,
                              onTap: sessionId == null
                                  ? null
                                  : () async {
                                      Navigator.pop(context);
                                      await _loadSession(
                                        sessionId,
                                        title: title,
                                      );
                                    },
                              title: Text(
                                title,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white,
                                  fontWeight: isActive
                                      ? FontWeight.bold
                                      : FontWeight.w600,
                                ),
                              ),
                              subtitle: Text(
                                _formatTimestamp(item.updatedAt),
                                style: GoogleFonts.inter(
                                  color: AppTheme.textSecondary,
                                  fontSize: 12,
                                ),
                              ),
                              trailing: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  if (isActive)
                                    Icon(
                                      Icons.check_circle_rounded,
                                      color: AppTheme.accent,
                                    ),
                                  IconButton(
                                    tooltip: 'កែឈ្មោះ',
                                    visualDensity: VisualDensity.compact,
                                    onPressed: sessionId == null
                                        ? null
                                        : () async {
                                            await _renameSession(item);
                                            if (!sheetContext.mounted) return;
                                            setSheetState(() {});
                                          },
                                    icon: Icon(
                                      Icons.drive_file_rename_outline_rounded,
                                      color: AppTheme.textSecondary,
                                      size: 20,
                                    ),
                                  ),
                                  IconButton(
                                    tooltip: 'លុបប្រវត្តិ',
                                    visualDensity: VisualDensity.compact,
                                    onPressed:
                                        sessionId == null || _isDeletingSession
                                        ? null
                                        : () async {
                                            final confirmed =
                                                await _confirmDeleteSession(
                                                  title,
                                                );
                                            if (!mounted ||
                                                !context.mounted ||
                                                !confirmed) {
                                              return;
                                            }
                                            Navigator.pop(context);
                                            await _deleteSessionById(
                                              sessionId,
                                              title: title,
                                              skipConfirm: true,
                                            );
                                          },
                                    icon: Icon(
                                      Icons.delete_outline_rounded,
                                      color: AppTheme.danger.withValues(
                                        alpha: 0.92,
                                      ),
                                      size: 20,
                                    ),
                                  ),
                                ],
                              ),
                            );
                          },
                        ),
                      ),
                  ],
                ),
              ),
            );
          },
        );
      },
    );
  }

  List<_PromptOption> _quickPrompts(UserProvider user) {
    final prompts = <_PromptOption>[
      const _PromptOption(
        category: _PromptCategory.general,
        text: 'តើខ្ញុំគួរចាប់ផ្តើមពីអ្វី?',
      ),
      const _PromptOption(
        category: _PromptCategory.general,
        text: 'ជួយសង្ខេបអ្វីដែលខ្ញុំគួរដឹងថ្ងៃនេះ',
      ),
      const _PromptOption(
        category: _PromptCategory.attendance,
        text: 'ថ្ងៃនេះខ្ញុំបានចូលម៉ោងប៉ុន្មាន?',
      ),
      const _PromptOption(
        category: _PromptCategory.attendance,
        text: 'ស្ថានភាពវត្តមានខ្ញុំសប្តាហ៍នេះយ៉ាងម៉េច?',
      ),
      const _PromptOption(
        category: _PromptCategory.leave,
        text: 'ខ្ញុំនៅសល់ច្បាប់ឈប់ប៉ុន្មានថ្ងៃ?',
      ),
      const _PromptOption(
        category: _PromptCategory.leave,
        text: 'តើខ្ញុំមានច្បាប់ឈប់ដែលបានអនុម័តថ្មីៗទេ?',
      ),
      const _PromptOption(
        category: _PromptCategory.request,
        text: 'សំណើរបស់ខ្ញុំមានអ្វីខ្លះ?',
      ),
      const _PromptOption(
        category: _PromptCategory.request,
        text: 'សំណើណាខ្លះកំពុងរង់ចាំ?',
      ),
    ];
    if (user.isHRM) {
      prompts.addAll(
        const [
          _PromptOption(
            category: _PromptCategory.hrm,
            text: 'សំណើរង់ចាំទាំងអស់មានប៉ុន្មាន?',
          ),
          _PromptOption(
            category: _PromptCategory.hrm,
            text: 'សង្ខេប HRM data សំខាន់ៗថ្ងៃនេះ',
          ),
        ],
      );
    }
    return prompts;
  }

  String _promptCategoryLabel(_PromptCategory category) {
    switch (category) {
      case _PromptCategory.general:
        return 'ទូទៅ';
      case _PromptCategory.attendance:
        return 'វត្តមាន';
      case _PromptCategory.leave:
        return 'ច្បាប់ឈប់';
      case _PromptCategory.request:
        return 'សំណើ';
      case _PromptCategory.hrm:
        return 'HRM';
    }
  }

  IconData _promptCategoryIcon(_PromptCategory category) {
    switch (category) {
      case _PromptCategory.general:
        return Icons.auto_awesome_rounded;
      case _PromptCategory.attendance:
        return Icons.schedule_rounded;
      case _PromptCategory.leave:
        return Icons.beach_access_rounded;
      case _PromptCategory.request:
        return Icons.assignment_turned_in_rounded;
      case _PromptCategory.hrm:
        return Icons.admin_panel_settings_rounded;
    }
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scrollController.hasClients) return;
      if (_showScrollToBottomButton && mounted) {
        setState(() => _showScrollToBottomButton = false);
      }
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent + 120,
        duration: const Duration(milliseconds: 240),
        curve: Curves.easeOutCubic,
      );
    });
  }

  void _showSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), behavior: SnackBarBehavior.floating),
    );
  }

  String _currentTimestamp() {
    return DateTime.now().toUtc().toIso8601String();
  }

  DateTime? _parseTimestampValue(dynamic value) {
    final raw = '${value ?? ''}'.trim();
    if (raw.isEmpty) return null;

    if (value is DateTime) {
      return value;
    }

    final normalized = raw.replaceFirst(' ', 'T');
    final parsed =
        DateTime.tryParse(raw) ??
        DateTime.tryParse(normalized) ??
        DateTime.tryParse(_truncateTimestampPrecision(normalized));
    if (parsed != null) {
      return parsed;
    }

    final basicMatch = RegExp(
      r'^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})',
    ).firstMatch(raw);
    if (basicMatch == null) return null;

    return DateTime.tryParse('${basicMatch.group(1)}T${basicMatch.group(2)}');
  }

  String _truncateTimestampPrecision(String value) {
    final match = RegExp(
      r'^(.+\.\d{1,6})(?:\d+)(Z|[+-]\d{2}:\d{2})?$',
    ).firstMatch(value);
    if (match == null) {
      return value;
    }
    return '${match.group(1)}${match.group(2) ?? ''}';
  }

  DateTime _toPhnomPenhTime(DateTime timestamp, {required String rawValue}) {
    final hasExplicitZone = RegExp(r'(Z|[+-]\d{2}:\d{2})$').hasMatch(rawValue);
    if (timestamp.isUtc || hasExplicitZone) {
      return timestamp.toUtc().add(_phnomPenhOffset);
    }

    // Server timestamps without timezone are already stored in Phnom Penh time.
    return timestamp;
  }

  String _formatTimestamp(dynamic value) {
    final raw = '${value ?? ''}'.trim();
    if (raw.isEmpty) return '';

    final parsed = _parseTimestampValue(value);

    if (parsed == null) {
      final normalized = raw.replaceFirst('T', ' ');
      final compact = normalized.contains('.')
          ? normalized.split('.').first
          : normalized;
      return compact.length > 19 ? compact.substring(0, 19) : compact;
    }

    final phnomPenhTime = _toPhnomPenhTime(parsed, rawValue: raw);
    return '${DateFormat('dd MMM yyyy, hh:mm a', 'en_US').format(phnomPenhTime)} ICT';
  }

  int? _toInt(dynamic value) {
    if (value is int) return value;
    return int.tryParse('${value ?? ''}');
  }

  @override
  Widget build(BuildContext context) {
    final user = context.watch<UserProvider>();
    final prompts = _quickPrompts(user);

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        titleSpacing: 0,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'AI HR Assistant',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 19,
              ),
            ),
            Text(
              _activeSessionTitle,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: GoogleFonts.inter(
                color: AppTheme.textSecondary,
                fontSize: 11,
                fontWeight: FontWeight.w500,
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'ប្រវត្តិជជែក',
            onPressed: _openSessionsSheet,
            icon: const Icon(Icons.history_rounded),
          ),
          IconButton(
            tooltip: 'ការជជែកថ្មី',
            onPressed: _isCreatingSession ? null : _createNewSession,
            icon: _isCreatingSession
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.add_comment_rounded),
          ),
        ],
      ),
      body: AppBackgroundShell(
        child: SafeArea(
          top: false,
          child: Column(
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 6, 16, 10),
                child: _buildHeaderCard(user),
              ),
              Expanded(
                child: Stack(
                  children: [
                    _isBootstrapping || _isLoadingHistory
                        ? const Center(child: CircularProgressIndicator())
                        : _buildMessageArea(prompts),
                    if (_showScrollToBottomButton && !_isBootstrapping)
                      Positioned(
                        right: 16,
                        bottom: 12,
                        child: _buildScrollToBottomButton(),
                      ),
                  ],
                ),
              ),
              _buildComposer(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHeaderCard(UserProvider user) {
    final roleLabel = user.systemRoleLabel;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppTheme.bgCard.withValues(alpha: 0.88),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
        boxShadow: AppTheme.cardShadow,
      ),
      child: Row(
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: AppTheme.primary,
              borderRadius: BorderRadius.circular(16),
            ),
            child: const Icon(
              Icons.smart_toy_rounded,
              color: Colors.white,
              size: 26,
            ),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'សួរសំណួរទូទៅ ឬទិន្នន័យ HRM',
                  style: GoogleFonts.inter(
                    color: Colors.white,
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  roleLabel,
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textSecondary,
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScrollToBottomButton() {
    return FloatingActionButton.small(
      heroTag: 'ai_chat_scroll_to_bottom',
      backgroundColor: AppTheme.primary,
      foregroundColor: Colors.white,
      tooltip: 'ទៅសារចុងក្រោយ',
      onPressed: _scrollToBottom,
      child: const Icon(Icons.keyboard_arrow_down_rounded),
    );
  }

  Widget _buildMessageArea(List<_PromptOption> prompts) {
    if (_messages.isEmpty) {
      final availableCategories = _PromptCategory.values
          .where((category) => prompts.any((item) => item.category == category))
          .toList();
      if (!availableCategories.contains(_selectedPromptCategory)) {
        _selectedPromptCategory = availableCategories.isNotEmpty
            ? availableCategories.first
            : _PromptCategory.general;
      }
      final visiblePrompts = prompts
          .where((item) => item.category == _selectedPromptCategory)
          .toList();

      return ListView(
        controller: _scrollController,
        padding: const EdgeInsets.fromLTRB(16, 4, 16, 20),
        children: [
          Container(
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(
              color: AppTheme.bgCard.withValues(alpha: 0.82),
              borderRadius: BorderRadius.circular(24),
              border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'ចាប់ផ្តើមជាមួយសំណួររហ័ស',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  'អ្នកអាចសួរសំណួរទូទៅបានផងដែរ។ សម្រាប់ទិន្នន័យ HRM ដូចជា វត្តមាន ច្បាប់ឈប់ សំណើ និងសេចក្តីសង្ខេបរង់ចាំ AI នឹងប្រើទិន្នន័យប្រព័ន្ធពិតនៅពេលមាន។',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textSecondary,
                    fontSize: 13,
                    height: 1.5,
                  ),
                ),
                const SizedBox(height: 18),
                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(
                    children: availableCategories
                        .map(_buildPromptCategoryChip)
                        .toList(),
                  ),
                ),
                const SizedBox(height: 14),
                Wrap(
                  spacing: 10,
                  runSpacing: 10,
                  children: visiblePrompts
                      .map((prompt) => _buildPromptChip(prompt.text))
                      .toList(),
                ),
              ],
            ),
          ),
        ],
      );
    }

    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.fromLTRB(16, 4, 16, 20),
      itemCount: _messages.length + (_isSending ? 1 : 0),
      itemBuilder: (context, index) {
        if (_isSending && index == _messages.length) {
          return _buildTypingBubble();
        }
        final message = _messages[index];
        return _buildMessageBubble(message, index);
      },
    );
  }

  Widget _buildPromptCategoryChip(_PromptCategory category) {
    final isSelected = category == _selectedPromptCategory;
    return Padding(
      padding: const EdgeInsets.only(right: 8),
      child: ChoiceChip(
        selected: isSelected,
        showCheckmark: false,
        avatar: Icon(
          _promptCategoryIcon(category),
          size: 16,
          color: isSelected ? Colors.white : AppTheme.textSecondary,
        ),
        label: Text(
          _promptCategoryLabel(category),
          style: GoogleFonts.kantumruyPro(
            color: isSelected ? Colors.white : AppTheme.textSecondary,
            fontWeight: FontWeight.w700,
          ),
        ),
        selectedColor: AppTheme.primary,
        backgroundColor: Colors.white.withValues(alpha: 0.05),
        side: BorderSide(color: Colors.white.withValues(alpha: 0.08)),
        onSelected: (_) {
          setState(() => _selectedPromptCategory = category);
        },
      ),
    );
  }

  Widget _buildPromptChip(String prompt) {
    return InkWell(
      borderRadius: BorderRadius.circular(18),
      onTap: () => _sendMessage(preset: prompt),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        decoration: BoxDecoration(
          color: Colors.white.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
        ),
        child: Text(
          prompt,
          style: GoogleFonts.kantumruyPro(
            color: Colors.white,
            fontSize: 13,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }

  Widget _buildMessageBubble(_AiMessage message, int index) {
    final isUser = message.isUser;
    final isError = message.isError;
    final text = message.text.trim();
    final hasText = text.isNotEmpty;
    final hasImageAttachment = message.hasImageAttachment;
    final hasCopyableImageUrl =
        !isUser && message.attachmentPath.trim().isNotEmpty;
    final timestamp = _formatTimestamp(message.createdAt);
    final sources = message.sources;
    final retryText = message.retryText?.trim() ?? '';
    final canRegenerate =
        !isUser && !isError && _isLatestAssistantMessage(index) && !_isSending;
    final canRetry = isError && retryText.isNotEmpty && !_isSending;

    return Align(
      alignment: isUser ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.only(bottom: 12),
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.82,
        ),
        padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
        decoration: BoxDecoration(
          color: isUser ? AppTheme.primary : AppTheme.bgCardLight,
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(20),
            topRight: const Radius.circular(20),
            bottomLeft: Radius.circular(isUser ? 20 : 6),
            bottomRight: Radius.circular(isUser ? 6 : 20),
          ),
          border: Border.all(
            color: isError
                ? AppTheme.danger.withValues(alpha: 0.45)
                : Colors.white.withValues(alpha: 0.06),
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.16),
              blurRadius: 12,
              offset: const Offset(0, 6),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (hasImageAttachment) ...[
              _buildMessageImage(message),
              if (hasText) const SizedBox(height: 10),
            ],
            if (hasText)
              Text(
                text,
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 14,
                  fontWeight: FontWeight.w500,
                  height: 1.45,
                ),
              ),
            if (!isUser && sources.isNotEmpty) ...[
              const SizedBox(height: 10),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.06),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(
                    color: Colors.white.withValues(alpha: 0.06),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.dataset_rounded,
                          size: 14,
                          color: AppTheme.accent,
                        ),
                        const SizedBox(width: 6),
                        Text(
                          'ប្រភពទិន្នន័យ',
                          style: GoogleFonts.kantumruyPro(
                            color: AppTheme.textSecondary,
                            fontSize: 11,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Wrap(
                      spacing: 6,
                      runSpacing: 6,
                      children: sources
                          .map(
                            (source) => Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 8,
                                vertical: 4,
                              ),
                              decoration: BoxDecoration(
                                color: AppTheme.accent.withValues(alpha: 0.12),
                                borderRadius: BorderRadius.circular(999),
                              ),
                              child: Text(
                                source,
                                style: GoogleFonts.inter(
                                  color: AppTheme.accent,
                                  fontSize: 10,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                          )
                          .toList(),
                    ),
                  ],
                ),
              ),
            ],
            if (isUser && hasText) ...[
              const SizedBox(height: 10),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  _buildAssistantActionChip(
                    icon: Icons.edit_rounded,
                    label: 'កែសំណួរ',
                    onTap: () => _editUserMessage(text),
                    foregroundColor: AppTheme.bgDark,
                    backgroundColor: Colors.white.withValues(alpha: 0.62),
                    borderColor: Colors.white.withValues(alpha: 0.28),
                  ),
                  _buildAssistantActionChip(
                    icon: Icons.replay_rounded,
                    label: 'ផ្ញើម្តងទៀត',
                    onTap: () => _resendUserMessage(text),
                    foregroundColor: AppTheme.bgDark,
                    backgroundColor: Colors.white.withValues(alpha: 0.62),
                    borderColor: Colors.white.withValues(alpha: 0.28),
                  ),
                ],
              ),
            ],
            if (!isUser && hasText) ...[
              const SizedBox(height: 10),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  _buildAssistantActionChip(
                    icon: Icons.content_copy_rounded,
                    label: 'ចម្លង',
                    onTap: () => _copyAssistantReply(text),
                  ),
                  if (hasCopyableImageUrl)
                    _buildAssistantActionChip(
                      icon: Icons.link_rounded,
                      label: 'ចម្លង URL',
                      onTap: () => _copyImageUrl(message),
                    ),
                  if (canRegenerate)
                    _buildAssistantActionChip(
                      icon: Icons.refresh_rounded,
                      label: 'សាកម្ដងទៀត',
                      onTap: () => _regenerateAssistantReply(index),
                    ),
                  if (canRetry)
                    _buildAssistantActionChip(
                      icon: Icons.replay_rounded,
                      label: 'ផ្ញើម្តងទៀត',
                      onTap: () => _retryMessage(retryText),
                    ),
                ],
              ),
            ],
            if (timestamp.isNotEmpty) ...[
              const SizedBox(height: 8),
              Text(
                timestamp,
                style: GoogleFonts.inter(
                  color: Colors.white.withValues(alpha: 0.55),
                  fontSize: 10,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildMessageImage(_AiMessage message) {
    Widget image;
    final imageBase64 = message.attachmentBase64.trim();
    if (imageBase64.isNotEmpty) {
      try {
        image = Image.memory(
          base64Decode(imageBase64),
          fit: BoxFit.contain,
          gaplessPlayback: true,
          filterQuality: FilterQuality.medium,
        );
      } catch (_) {
        image = _buildImagePlaceholder();
      }
    } else {
      final imageUrl = ApiService.getFullImageUrl(message.attachmentPath);
      image = Image.network(
        imageUrl,
        fit: BoxFit.contain,
        loadingBuilder: (context, child, loadingProgress) {
          if (loadingProgress == null) return child;
          return Center(
            child: CircularProgressIndicator(
              strokeWidth: 2,
              color: AppTheme.primary,
            ),
          );
        },
        errorBuilder: (context, error, stackTrace) => _buildImagePlaceholder(),
      );
    }

    return Container(
      width: double.infinity,
      constraints: const BoxConstraints(maxHeight: 260, minHeight: 120),
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(12),
        child: Container(
          color: AppTheme.bgDark.withValues(alpha: 0.45),
          alignment: Alignment.center,
          child: image,
        ),
      ),
    );
  }

  Widget _buildImagePlaceholder() {
    return Center(
      child: Icon(
        Icons.broken_image_rounded,
        color: AppTheme.textSecondary,
        size: 34,
      ),
    );
  }

  Widget _buildAssistantActionChip({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
    Color? foregroundColor,
    Color? backgroundColor,
    Color? borderColor,
  }) {
    final effectiveForeground = foregroundColor ?? AppTheme.textSecondary;
    return InkWell(
      borderRadius: BorderRadius.circular(999),
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
          color: backgroundColor ?? Colors.white.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(999),
          border: Border.all(
            color: borderColor ?? Colors.white.withValues(alpha: 0.06),
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 14, color: effectiveForeground),
            const SizedBox(width: 6),
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: effectiveForeground,
                fontSize: 11,
                fontWeight: FontWeight.w800,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTypingBubble() {
    return Align(
      alignment: Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.only(bottom: 12),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        decoration: BoxDecoration(
          color: AppTheme.bgCardLight.withValues(alpha: 0.92),
          borderRadius: BorderRadius.circular(18),
        ),
        child: AnimatedBuilder(
          animation: _typingAnimationController,
          builder: (context, _) {
            return Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  'AI កំពុងឆ្លើយ',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textSecondary,
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(width: 8),
                ...List.generate(3, (index) {
                  final phase =
                      (_typingAnimationController.value + (index * 0.22)) % 1;
                  final alpha = 0.35 + (phase < 0.5 ? phase : 1 - phase) * 1.3;
                  return Container(
                    width: 7,
                    height: 7,
                    margin: EdgeInsets.only(right: index == 2 ? 0 : 6),
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(
                        alpha: alpha.clamp(0.35, 1.0),
                      ),
                      shape: BoxShape.circle,
                    ),
                  );
                }),
              ],
            );
          },
        ),
      ),
    );
  }

  Widget _buildComposer() {
    final canSend = !_isSending && _hasComposerText;
    final canUseImage = !_isSending;

    return SafeArea(
      top: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 6, 14, 14),
        child: Container(
          padding: const EdgeInsets.fromLTRB(14, 10, 10, 10),
          decoration: BoxDecoration(
            color: AppTheme.bgCard.withValues(alpha: 0.96),
            borderRadius: BorderRadius.circular(22),
            border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
            boxShadow: AppTheme.cardShadow,
          ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Semantics(
                button: true,
                enabled: canUseImage,
                label: 'ជ្រើសរូបភាពដើម្បីកាត់ Background',
                child: InkWell(
                  borderRadius: BorderRadius.circular(16),
                  onTap: canUseImage ? _removeBackgroundFromImage : null,
                  child: Container(
                    width: 42,
                    height: 42,
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(
                        alpha: canUseImage ? 0.08 : 0.04,
                      ),
                      borderRadius: BorderRadius.circular(15),
                      border: Border.all(
                        color: Colors.white.withValues(alpha: 0.08),
                      ),
                    ),
                    child: Icon(
                      Icons.add_photo_alternate_rounded,
                      color: AppTheme.textSecondary.withValues(
                        alpha: canUseImage ? 1 : 0.4,
                      ),
                      size: 22,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: TextField(
                  controller: _messageController,
                  focusNode: _composerFocusNode,
                  enabled: !_isSending,
                  textInputAction: TextInputAction.send,
                  minLines: 1,
                  maxLines: 4,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontSize: 14,
                  ),
                  decoration: InputDecoration.collapsed(
                    hintText: 'សួរ AI ឬពិនិត្យទិន្នន័យ HRM...',
                    hintStyle: GoogleFonts.kantumruyPro(
                      color: AppTheme.textMuted,
                      fontSize: 13,
                    ),
                  ),
                  onSubmitted: (_) {
                    if (canSend) _sendMessage();
                  },
                ),
              ),
              const SizedBox(width: 10),
              Semantics(
                button: true,
                enabled: canSend,
                label: 'ផ្ញើសារ',
                child: InkWell(
                  borderRadius: BorderRadius.circular(18),
                  onTap: canSend ? _sendMessage : null,
                  child: Container(
                    width: 44,
                    height: 44,
                    decoration: BoxDecoration(
                      color: AppTheme.primary.withValues(
                        alpha: canSend || _isSending ? 1 : 0.36,
                      ),
                      borderRadius: BorderRadius.circular(16),
                    ),
                    child: _isSending
                        ? const Padding(
                            padding: EdgeInsets.all(12),
                            child: CircularProgressIndicator(
                              strokeWidth: 2.2,
                              color: Colors.white,
                            ),
                          )
                        : Icon(
                            Icons.arrow_upward_rounded,
                            color: Colors.white.withValues(
                              alpha: canSend ? 1 : 0.58,
                            ),
                          ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
