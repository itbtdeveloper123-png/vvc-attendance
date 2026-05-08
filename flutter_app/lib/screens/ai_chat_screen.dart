import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

class AiChatScreen extends StatefulWidget {
  const AiChatScreen({super.key});

  @override
  State<AiChatScreen> createState() => _AiChatScreenState();
}

class _AiChatScreenState extends State<AiChatScreen> {
  static const Duration _phnomPenhOffset = Duration(hours: 7);

  final ApiService _api = ApiService();
  final TextEditingController _messageController = TextEditingController();
  final ScrollController _scrollController = ScrollController();

  bool _isBootstrapping = true;
  bool _isLoadingHistory = false;
  bool _isSending = false;
  bool _isCreatingSession = false;
  bool _isDeletingSession = false;

  int? _activeSessionId;
  String _activeSessionTitle = 'AI Assistant';
  List<Map<String, dynamic>> _messages = [];
  List<Map<String, dynamic>> _sessions = [];

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  @override
  void dispose() {
    _messageController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _bootstrap() async {
    setState(() => _isBootstrapping = true);
    await _loadSessions();
    if (_sessions.isNotEmpty) {
      final first = _sessions.first;
      final sessionId = _toInt(first['id']);
      if (sessionId != null) {
        await _loadSession(
          sessionId,
          title: '${first['title'] ?? 'AI Assistant'}',
        );
      }
    }
    if (mounted) {
      setState(() => _isBootstrapping = false);
    }
  }

  Future<void> _loadSessions() async {
    final res = await _api.getAiChatSessions(limit: 20);
    if (!mounted) return;
    if (res['success'] == true) {
      final list = List<Map<String, dynamic>>.from(
        (res['sessions'] as List? ?? []).map(
          (item) => Map<String, dynamic>.from(item as Map),
        ),
      );
      setState(() => _sessions = list);
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
      final history = List<Map<String, dynamic>>.from(
        (res['messages'] as List? ?? []).map(
          (item) => Map<String, dynamic>.from(item as Map),
        ),
      );
      final session = res['session'];
      setState(() {
        _messages = history;
        _activeSessionTitle =
            '${(session is Map ? session['title'] : null) ?? _activeSessionTitle}';
      });
      _scrollToBottom();
    } else {
      _showSnackBar('${res['message'] ?? 'Failed to load chat history'}');
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
      final session = Map<String, dynamic>.from(res['session'] as Map);
      final sessionId = _toInt(session['id']);
      setState(() {
        _messages = [];
        _activeSessionId = sessionId;
        _activeSessionTitle = '${session['title'] ?? 'AI Assistant'}';
      });
      await _loadSessions();
      _showSnackBar('New AI chat is ready');
    } else {
      _showSnackBar('${res['message'] ?? 'Failed to create new chat'}');
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
            'Delete chat history?',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
            ),
          ),
          content: Text(
            'This will permanently delete "$title" and all messages inside it.',
            style: GoogleFonts.inter(
              color: AppTheme.textSecondary,
              fontSize: 13,
              height: 1.45,
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(false),
              child: Text(
                'Cancel',
                style: GoogleFonts.inter(color: AppTheme.textSecondary),
              ),
            ),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                backgroundColor: AppTheme.danger,
                foregroundColor: Colors.white,
              ),
              onPressed: () => Navigator.of(dialogContext).pop(true),
              icon: const Icon(Icons.delete_outline_rounded, size: 18),
              label: const Text('Delete'),
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
            'Delete all chat history?',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
            ),
          ),
          content: Text(
            'This will permanently delete all your AI chat sessions and messages.',
            style: GoogleFonts.inter(
              color: AppTheme.textSecondary,
              fontSize: 13,
              height: 1.45,
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(false),
              child: Text(
                'Cancel',
                style: GoogleFonts.inter(color: AppTheme.textSecondary),
              ),
            ),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                backgroundColor: AppTheme.danger,
                foregroundColor: Colors.white,
              ),
              onPressed: () => Navigator.of(dialogContext).pop(true),
              icon: const Icon(Icons.delete_sweep_rounded, size: 18),
              label: const Text('Clear All'),
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
          final nextId = _toInt(next['id']);
          if (nextId != null) {
            await _loadSession(
              nextId,
              title: '${next['title'] ?? 'AI Assistant'}',
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

      _showSnackBar('Chat history deleted');
    } else {
      _showSnackBar('${res['message'] ?? 'Failed to delete chat history'}');
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

      _showSnackBar('All chat history deleted');
    } else {
      _showSnackBar('${res['message'] ?? 'Failed to delete all chat history'}');
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
        {
          'sender_type': 'user',
          'message_text': text,
          'created_at': _currentTimestamp(),
        },
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
          {
            'sender_type': 'assistant',
            'message_text': reply.isNotEmpty ? reply : 'No response',
            'created_at': _currentTimestamp(),
            'sources': sources,
            'provider': '${res['provider'] ?? ''}',
            'model_name': '${res['model'] ?? ''}',
          },
        ];
      });
      await _loadSessions();
      if (_activeSessionId != null) {
        Map<String, dynamic>? current;
        for (final item in _sessions) {
          if (_toInt(item['id']) == _activeSessionId) {
            current = item;
            break;
          }
        }
        if (current != null) {
          final currentTitle = '${current['title'] ?? _activeSessionTitle}';
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
          {
            'sender_type': 'assistant',
            'message_text':
                '${res['message'] ?? 'Unable to get a reply from AI assistant.'}',
            'created_at': _currentTimestamp(),
            'is_error': true,
          },
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
    _showSnackBar('Answer copied');
  }

  bool _isLatestAssistantMessage(int index) {
    if (index < 0 || index >= _messages.length) return false;

    for (var i = _messages.length - 1; i >= 0; i--) {
      if ('${_messages[i]['sender_type'] ?? ''}' == 'assistant') {
        return i == index;
      }
    }
    return false;
  }

  Future<void> _regenerateAssistantReply(int index) async {
    if (_isSending || _activeSessionId == null) return;
    if (!_isLatestAssistantMessage(index)) {
      _showSnackBar('You can regenerate only the latest AI answer');
      return;
    }

    final currentMessage = _messages[index];
    if ('${currentMessage['sender_type'] ?? ''}' != 'assistant' ||
        currentMessage['is_error'] == true) {
      return;
    }

    setState(() => _isSending = true);
    _scrollToBottom();

    final res = await _api.regenerateAiChatReply(_activeSessionId!);
    if (!mounted) return;

    if (res['success'] == true) {
      final reply = '${res['reply'] ?? ''}'.trim();
      final sources = List<String>.from(res['sources'] as List? ?? const []);
      final updatedMessages = List<Map<String, dynamic>>.from(_messages);
      updatedMessages[index] = {
        ...Map<String, dynamic>.from(updatedMessages[index]),
        'message_text': reply.isNotEmpty ? reply : 'No response',
        'created_at': _currentTimestamp(),
        'sources': sources,
        'provider': '${res['provider'] ?? ''}',
        'model_name': '${res['model'] ?? ''}',
        'is_error': false,
      };

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
      _showSnackBar('Answer regenerated');
    } else {
      _showSnackBar('${res['message'] ?? 'Unable to regenerate the answer'}');
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
      builder: (context) {
        return Container(
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
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
                        'AI Chat Sessions',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                    TextButton.icon(
                      onPressed: () async {
                        Navigator.pop(context);
                        await _createNewSession();
                      },
                      icon: const Icon(Icons.add_rounded, size: 18),
                      label: const Text('New'),
                    ),
                    TextButton.icon(
                      onPressed: _sessions.isEmpty || _isDeletingSession
                          ? null
                          : () async {
                              final confirmed =
                                  await _confirmDeleteAllSessions();
                              if (!mounted || !context.mounted || !confirmed) {
                                return;
                              }
                              Navigator.pop(context);
                              await _deleteAllSessions(skipConfirm: true);
                            },
                      icon: const Icon(Icons.delete_sweep_rounded, size: 18),
                      label: const Text('Clear All'),
                      style: TextButton.styleFrom(
                        foregroundColor: AppTheme.danger,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                if (_sessions.isEmpty)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    child: Text(
                      'No chat sessions yet.',
                      style: GoogleFonts.inter(
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
                      itemCount: _sessions.length,
                      separatorBuilder: (_, _) => Divider(
                        color: Colors.white.withValues(alpha: 0.06),
                        height: 1,
                      ),
                      itemBuilder: (context, index) {
                        final item = _sessions[index];
                        final sessionId = _toInt(item['id']);
                        final isActive =
                            sessionId != null && sessionId == _activeSessionId;
                        return ListTile(
                          contentPadding: EdgeInsets.zero,
                          onTap: sessionId == null
                              ? null
                              : () async {
                                  Navigator.pop(context);
                                  await _loadSession(
                                    sessionId,
                                    title: '${item['title'] ?? 'AI Assistant'}',
                                  );
                                },
                          title: Text(
                            '${item['title'] ?? 'AI Assistant'}',
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
                            _formatTimestamp(item['updated_at']),
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
                                tooltip: 'Delete history',
                                visualDensity: VisualDensity.compact,
                                onPressed:
                                    sessionId == null || _isDeletingSession
                                    ? null
                                    : () async {
                                        final title =
                                            '${item['title'] ?? 'AI Assistant'}';
                                        final confirmed =
                                            await _confirmDeleteSession(title);
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
  }

  // ignore: unused_element
  List<String> _quickPromptsLegacy(UserProvider user) {
    final prompts = <String>[
      'ថ្ងៃនេះខ្ញុំចូលម៉ោងប៉ុន្មាន?',
      'ខ្ញុំនៅសល់ leave ប៉ុន្មានថ្ងៃ?',
      'សំណើរបស់ខ្ញុំមានអ្វីខ្លះ?',
    ];
    if (user.isHRM) {
      prompts.add('សំណើ pending ទាំងអស់មានប៉ុន្មាន?');
    }
    return prompts;
  }

  List<String> _quickPrompts(UserProvider user) {
    final prompts = <String>[
      'ថ្ងៃនេះខ្ញុំបានចូលម៉ោងប៉ុន្មាន?',
      'ខ្ញុំនៅសល់ច្បាប់ឈប់ប៉ុន្មានថ្ងៃ?',
      'សំណើរបស់ខ្ញុំមានអ្វីខ្លះ?',
    ];
    if (user.isHRM) {
      prompts.add('សំណើរង់ចាំទាំងអស់មានប៉ុន្មាន?');
    }
    return prompts;
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scrollController.hasClients) return;
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
            tooltip: 'Sessions',
            onPressed: _openSessionsSheet,
            icon: const Icon(Icons.history_rounded),
          ),
          IconButton(
            tooltip: 'New chat',
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
                child: _isBootstrapping || _isLoadingHistory
                    ? const Center(child: CircularProgressIndicator())
                    : _buildMessageArea(prompts),
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
                  'Ask general questions or HRM data',
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

  Widget _buildMessageArea(List<String> prompts) {
    if (_messages.isEmpty) {
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
                  'Start with a quick prompt',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  'You can ask general questions too. For HRM facts like attendance, leave, requests, and pending summaries, the assistant uses real system data when available.',
                  style: GoogleFonts.inter(
                    color: AppTheme.textSecondary,
                    fontSize: 13,
                    height: 1.5,
                  ),
                ),
                const SizedBox(height: 18),
                Wrap(
                  spacing: 10,
                  runSpacing: 10,
                  children: prompts.map(_buildPromptChip).toList(),
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

  Widget _buildMessageBubble(Map<String, dynamic> message, int index) {
    final isUser = '${message['sender_type'] ?? ''}' == 'user';
    final isError = message['is_error'] == true;
    final text = '${message['message_text'] ?? ''}'.trim();
    final timestamp = _formatTimestamp(message['created_at']);
    final sources = List<String>.from(message['sources'] as List? ?? const []);
    final canRegenerate =
        !isUser && !isError && _isLatestAssistantMessage(index) && !_isSending;

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
                          color: Colors.white.withValues(alpha: 0.08),
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
            if (!isUser && text.isNotEmpty) ...[
              const SizedBox(height: 10),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  _buildAssistantActionChip(
                    icon: Icons.content_copy_rounded,
                    label: 'Copy',
                    onTap: () => _copyAssistantReply(text),
                  ),
                  if (canRegenerate)
                    _buildAssistantActionChip(
                      icon: Icons.refresh_rounded,
                      label: 'Regenerate',
                      onTap: () => _regenerateAssistantReply(index),
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

  Widget _buildAssistantActionChip({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
  }) {
    return InkWell(
      borderRadius: BorderRadius.circular(999),
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
          color: Colors.white.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(999),
          border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 14, color: AppTheme.textSecondary),
            const SizedBox(width: 6),
            Text(
              label,
              style: GoogleFonts.inter(
                color: AppTheme.textSecondary,
                fontSize: 11,
                fontWeight: FontWeight.w700,
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
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: List.generate(
            3,
            (index) => Container(
              width: 7,
              height: 7,
              margin: EdgeInsets.only(right: index == 2 ? 0 : 6),
              decoration: BoxDecoration(
                color: Colors.white.withValues(alpha: 0.75),
                shape: BoxShape.circle,
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildComposer() {
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
              Expanded(
                child: TextField(
                  controller: _messageController,
                  enabled: !_isSending,
                  minLines: 1,
                  maxLines: 4,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontSize: 14,
                  ),
                  decoration: InputDecoration(
                    border: InputBorder.none,
                    hintText: 'Ask AI anything, or check HRM data...',
                    hintStyle: GoogleFonts.inter(
                      color: AppTheme.textMuted,
                      fontSize: 13,
                    ),
                  ),
                  onSubmitted: (_) => _sendMessage(),
                ),
              ),
              const SizedBox(width: 10),
              InkWell(
                borderRadius: BorderRadius.circular(18),
                onTap: _isSending ? null : _sendMessage,
                child: Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    color: AppTheme.primary,
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
                      : const Icon(
                          Icons.arrow_upward_rounded,
                          color: Colors.white,
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
