import 'dart:ui';
import 'dart:convert';
import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:image_picker/image_picker.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_storage/firebase_storage.dart' as firebase_storage;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:record/record.dart' as record_pkg;
import 'package:audioplayers/audioplayers.dart';
import 'package:path_provider/path_provider.dart';
import 'package:animate_do/animate_do.dart';
import 'package:cached_network_image/cached_network_image.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import 'profile_screen.dart';
import 'shared_media_screen.dart';
import '../widgets/image_viewer.dart';

class TeamChatScreen extends StatefulWidget {
  final String targetUserId;
  final String targetUserName;
  final String targetUserPhoto;
  final bool isGroup;

  const TeamChatScreen({
    super.key,
    required this.targetUserId,
    required this.targetUserName,
    this.targetUserPhoto = '',
    this.isGroup = false,
  });

  @override
  State<TeamChatScreen> createState() => _TeamChatScreenState();
}

class _TeamChatScreenState extends State<TeamChatScreen>
    with TickerProviderStateMixin {
  late TextEditingController _msgController;
  late ScrollController _scrollController;
  late TextEditingController _searchController;
  late record_pkg.AudioRecorder _recorder;

  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final ImagePicker _picker = ImagePicker();

  String currentUserId = '';
  String currentUserPhoto = '';
  StreamSubscription<QuerySnapshot>? _messageSubscription;
  final List<DocumentSnapshot> _messageDocs = [];

  // Upload progress tracking: key -> progress (0..1)
  final Map<String, double> _uploadProgress = {};
  // Failed uploads map: taskId/fileName -> local temp file path for retry
  final Map<String, String> _failedUploads = {};
  // Active upload tasks for cancellation
  final Map<String, firebase_storage.UploadTask?> _uploadTasks = {};
  String groupStatus = 'accepted';

  // Persist failed uploads across restarts
  Future<void> _loadFailedUploadsFromPrefs() async {
    if (kIsWeb) return; // persistence handled differently on web
    try {
      final prefs = await SharedPreferences.getInstance();
      final jsonStr = prefs.getString('failed_uploads') ?? '{}';
      final Map parsed = jsonDecode(jsonStr) as Map<dynamic, dynamic>;
      parsed.forEach((k, v) {
        if (v is String) _failedUploads[k.toString()] = v;
      });
      setState(() {});
    } catch (e) {
      debugPrint('Failed to load failed uploads prefs: $e');
    }
  }

  Future<void> _saveFailedUploadsToPrefs() async {
    if (kIsWeb) return;
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('failed_uploads', jsonEncode(_failedUploads));
    } catch (e) {
      debugPrint('Failed to save failed uploads prefs: $e');
    }
  }

  bool _isRecording = false;
  int _recordingDuration = 0;
  Timer? _recordingTimer;
  String? _audioPath;

  // Phase 1 & 2 Features
  Map<String, dynamic>? _replyTo;
  final List<String> _emojiReactions = ['👍', '❤️', '😂', '😮', '😢', '🙏'];
  bool _showSearch = false;
  String _searchQuery = '';
  List<String> _pinnedMessageIds = [];
  StreamSubscription? _typingSubscription;

  @override
  void initState() {
    super.initState();
    _msgController = TextEditingController();
    _scrollController = ScrollController();
    _searchController = TextEditingController();
    _recorder = record_pkg.AudioRecorder();
    _scrollController.addListener(_onScroll);
    _loadUser();
    // Load persisted failed uploads (non-blocking)
    _loadFailedUploadsFromPrefs();
  }

  Future<void> _loadUser() async {
    final prefs = await SharedPreferences.getInstance();
    currentUserId = prefs.getString('employee_id') ?? 'EMP_UNKNOWN';
    if (mounted) {
      final userProvider = Provider.of<UserProvider>(context, listen: false);
      currentUserPhoto = userProvider.avatar ?? '';
    }
    if (widget.isGroup) {
      final groupDoc = await _firestore
          .collection('groups')
          .doc(widget.targetUserId)
          .get();
      if (groupDoc.exists) {
        final members = Map<String, dynamic>.from(
          groupDoc.data()?['members'] ?? {},
        );
        setState(() => groupStatus = members[currentUserId] ?? 'none');
      }
    }
    _setupMessageStream();
    _setupTypingListener();
    _loadPinnedMessages();
    if (mounted) setState(() {});
    _updatePresence(true);
  }

  String _getDateSeparator(Timestamp? timestamp) {
    if (timestamp == null) return '';
    final date = timestamp.toDate();
    final now = DateTime.now();
    final difference = now.difference(date).inDays;

    if (difference == 0) return 'ថ្ងៃនេះ';
    if (difference == 1) return 'ម្សិលមិញ';
    return DateFormat('dd MMM yyyy', 'km').format(date);
  }

  bool _shouldShowDateSeparator(
    Map<String, dynamic> currentMsg,
    Map<String, dynamic>? previousMsg,
  ) {
    if (previousMsg == null) return false;
    final current = _getDateSeparator(currentMsg['timestamp']);
    final previous = _getDateSeparator(previousMsg['timestamp']);
    return current != previous;
  }

  String _getMessageStatus(Map<String, dynamic> msg) {
    if (!msg.containsKey('seenBy')) return '✓';
    final seenBy = List.from(msg['seenBy'] ?? []);
    if (seenBy.contains(widget.targetUserId)) return '✓✓';
    return '✓';
  }

  Future<void> _updateTypingStatus(bool isTyping) async {
    if (currentUserId.isEmpty) return;
    try {
      await _firestore.collection('users').doc(currentUserId).set({
        'typing': isTyping,
      }, SetOptions(merge: true));
    } catch (e) {
      debugPrint('Error updating typing status: $e');
    }
  }

  Future<void> _loadPinnedMessages() async {
    final roomId = _getChatRoomId();
    final collection = widget.isGroup ? 'groups' : 'chats';
    try {
      final doc = await _firestore.collection(collection).doc(roomId).get();
      if (doc.exists && doc.data()?['pinnedMessages'] != null) {
        setState(() {
          _pinnedMessageIds = List<String>.from(
            doc.data()?['pinnedMessages'] ?? [],
          );
        });
      }
    } catch (e) {
      debugPrint('Error loading pinned messages: $e');
    }
  }

  void _setupTypingListener() {
    if (!widget.isGroup) {
      _typingSubscription = _firestore
          .collection('users')
          .doc(widget.targetUserId)
          .snapshots()
          .listen((snapshot) {
            if (!mounted) return;
            final data = snapshot.data();
            if (data?['typing'] == true) {
              if (mounted) setState(() {});
              Future.delayed(const Duration(seconds: 3), () {
                if (mounted) setState(() {});
              });
            }
          });
    }
  }

  void _setupMessageStream() {
    final roomId = _getChatRoomId();
    final collection = widget.isGroup ? 'groups' : 'chats';

    _messageSubscription?.cancel();
    _messageSubscription = _firestore
        .collection(collection)
        .doc(roomId)
        .collection('messages')
        .orderBy('timestamp', descending: true)
        .limit(100)
        .snapshots()
        .listen(
          (snapshot) {
            if (!mounted) return;
            setState(() {
              _messageDocs.clear();
              _messageDocs.addAll(snapshot.docs);
            });
          },
          onError: (e) {
            debugPrint('Message stream error: $e');
          },
        );
  }

  String _getChatRoomId() {
    if (widget.isGroup) return widget.targetUserId;
    if (widget.targetUserId == 'ALL') return 'GROUP_TEAM_ALL';
    List<String> ids = [currentUserId, widget.targetUserId];
    ids.sort();
    return "PRIVATE_${ids[0]}_${ids[1]}";
  }

  Future<void> _updatePresence(bool isOnline) async {
    if (currentUserId.isEmpty) return;
    try {
      await _firestore.collection('users').doc(currentUserId).set({
        'isOnline': isOnline,
        'lastSeen': FieldValue.serverTimestamp(),
      }, SetOptions(merge: true));
    } catch (e) {
      debugPrint(e.toString());
    }
  }

  Future<void> _sendMessage({
    String? base64Image,
    String? base64Audio,
    String? imageUrl,
    String? editDocId,
  }) async {
    final text = _msgController.text.trim();
    if (text.isEmpty &&
        base64Image == null &&
        base64Audio == null &&
        (imageUrl == null || imageUrl.isEmpty) &&
        editDocId == null) {
      return;
    }
    final roomId = _getChatRoomId();
    final collection = widget.isGroup ? 'groups' : 'chats';

    try {
      if (editDocId != null) {
        await _firestore
            .collection(collection)
            .doc(roomId)
            .collection('messages')
            .doc(editDocId)
            .update({'message': text, 'isEdited': true});
        _msgController.clear();
        setState(() => _replyTo = null);
        return;
      }

      final messageData = {
        'senderId': currentUserId,
        'senderPhoto': currentUserPhoto,
        'message': text,
        'imageBase64': base64Image ?? '',
        'imageUrl': imageUrl ?? '',
        'audioBase64': base64Audio ?? '',
        'timestamp': FieldValue.serverTimestamp(),
        'isRead': false,
        'seenBy': [currentUserId],
        'isEdited': false,
        'reactions': {},
        if (_replyTo != null) 'replyTo': _replyTo,
      };

      await _firestore
          .collection(collection)
          .doc(roomId)
          .collection('messages')
          .add(messageData);

      String lastMsg = text.isNotEmpty
          ? text
          : (imageUrl != null && imageUrl.isNotEmpty
                ? '📷 រូបភាព (Image)'
                : (base64Image != null
                      ? '📷 រូបភាព (Image)'
                      : '🎤 សារសំឡេង (Voice Message)'));

      await _firestore.collection(collection).doc(roomId).set({
        'lastMessage': lastMsg,
        'lastTimestamp': FieldValue.serverTimestamp(),
        'lastSenderId': currentUserId,
      }, SetOptions(merge: true));

      if ((base64Image == null || base64Image.isEmpty) &&
          (base64Audio == null || base64Audio.isEmpty) &&
          (imageUrl == null || imageUrl.isEmpty)) {
        _msgController.clear();
      }
      setState(() => _replyTo = null);
      _scrollToBottom();
      await _updateTypingStatus(false);
    } catch (e) {
      debugPrint(e.toString());
    }
  }

  void _scrollToBottom() {
    // With reverse: true, 0.0 offset is the bottom (latest message)
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        0.0,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOutCubic,
      );
    }
  }

  String _formatLastSeen(Timestamp? timestamp) {
    if (timestamp == null) return "Offline";
    final DateTime lastSeen = timestamp.toDate();
    final DateTime now = DateTime.now();
    final Duration diff = now.difference(lastSeen);
    if (diff.inSeconds < 60) return "ទើបតែបិទ";
    if (diff.inMinutes < 60) return "បិទ ${diff.inMinutes} នាទីមុន";
    if (diff.inHours < 24) return "បិទ ${diff.inHours} ម៉ោងមុន";
    if (diff.inDays < 7) return "បិទ ${diff.inDays} ថ្ងៃមុន";
    return "បិទតាំងពី ${DateFormat('dd/MM/yyyy').format(lastSeen)}";
  }

  // Audio Recording Methods
  Future<void> _startRecording() async {
    FocusScope.of(context).unfocus();

    try {
      if (await _recorder.hasPermission()) {
        final fileName = 'audio_${DateTime.now().microsecondsSinceEpoch}.m4a';
        final path = kIsWeb
            ? fileName
            : '${(await getTemporaryDirectory()).path}/$fileName';
        _audioPath = path;
        await _recorder.start(
          record_pkg.RecordConfig(
            encoder: record_pkg.AudioEncoder.aacLc,
            bitRate: 128000,
            sampleRate: 44100,
          ),
          path: path,
        );
        setState(() {
          _isRecording = true;
          _recordingDuration = 0;
        });
        _recordingTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
          setState(() => _recordingDuration++);
        });
      }
    } catch (e) {
      debugPrint("Recording start error: $e");
    }
  }

  Future<void> _stopRecording() async {
    try {
      final path = await _recorder.stop();
      _recordingTimer?.cancel();
      setState(() => _isRecording = false);

      final String? finalPath = path ?? _audioPath;

      if (finalPath != null && finalPath.isNotEmpty) {
        final audioFile = XFile(
          finalPath,
          mimeType: 'audio/mp4',
          name: 'voice_message.m4a',
        );
        final bytes = await audioFile.readAsBytes();

        if (bytes.isNotEmpty) {
          final base64String = await compute(base64Encode, bytes);
          await _sendMessage(base64Audio: base64String);
          debugPrint("Audio sent, size: ${bytes.length} bytes");
        } else {
          _showError("ឯកសារសំឡេងទទេ (Empty audio)");
        }
      } else {
        _showError("មិនអាចស្វែងរកសំឡេងដែលបានថតបានទេ");
      }
    } catch (e) {
      debugPrint("Recording stop error: $e");
      _showError("ការថតសំឡេងមានបញ្ហា: $e");
    }
  }

  void _showError(String msg) {
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(msg), backgroundColor: Colors.redAccent),
      );
    }
  }

  @override
  void dispose() {
    _updatePresence(false);
    _updateTypingStatus(false);
    _msgController.dispose();
    _searchController.dispose();
    _scrollController.dispose();
    _recordingTimer?.cancel();
    _typingSubscription?.cancel();
    _messageSubscription?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      extendBodyBehindAppBar: true,
      appBar: _buildAppBar(),
      body: Stack(
        children: [
          _buildBackground(),
          Column(
            children: [
              // Add top spacing to account for the translucent AppBar when
              // extendBodyBehindAppBar is true so the search field is visible
              // and not hidden behind the AppBar.
              SizedBox(
                height: kToolbarHeight + MediaQuery.of(context).padding.top,
              ),
              Expanded(child: _buildMessageList()),
              if (groupStatus == 'pending')
                _buildInvitationPrompt()
              else
                _buildInputArea(),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildBackground() {
    return Positioned.fill(
      child: Container(
        decoration: BoxDecoration(
          gradient: RadialGradient(
            center: const Alignment(0.6, -0.8),
            radius: 1.4,
            colors: [
              const Color(0xFF1a2744).withValues(alpha: 0.9),
              AppTheme.bgSurface,
            ],
          ),
        ),
        child: CustomPaint(
          painter: _ChatBackgroundPainter(),
        ),
      ),
    );
  }

  PreferredSizeWidget _buildAppBar() {
    return PreferredSize(
      preferredSize: const Size.fromHeight(70),
      child: ClipRRect(
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 15, sigmaY: 15),
          child: AppBar(
            backgroundColor: AppTheme.bgDark.withValues(alpha: 0.3),
            elevation: 0,
            toolbarHeight: 70,
            leading: IconButton(
              icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 20),
              onPressed: () => Navigator.pop(context),
            ),
            title: InkWell(
              onTap: () {
                if (!widget.isGroup) {
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) =>
                          ProfileScreen(targetEmployeeId: widget.targetUserId),
                    ),
                  );
                }
              },
              child: Row(
                children: [
                  _buildAvatar(
                    widget.targetUserId,
                    widget.targetUserPhoto,
                    size: 44,
                    icon: widget.isGroup ? Icons.groups_rounded : null,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          widget.targetUserName,
                          style: GoogleFonts.kantumruyPro(
                            fontWeight: FontWeight.bold,
                            fontSize: 17,
                            color: AppTheme.textPrimary,
                          ),
                        ),
                        StreamBuilder<DocumentSnapshot>(
                          stream: _firestore
                              .collection('users')
                              .doc(widget.targetUserId)
                              .snapshots(),
                          builder: (context, snapshot) {
                            if (widget.isGroup) {
                              return Text(
                                'ក្រុមការងារ',
                                style: GoogleFonts.kantumruyPro(
                                  fontSize: 10,
                                  color: AppTheme.primaryLight,
                                ),
                              );
                            }
                            if (!snapshot.hasData || !snapshot.data!.exists) {
                              return Text(
                                'Offline',
                                style: GoogleFonts.inter(
                                  fontSize: 10,
                                  color: AppTheme.textMuted,
                                ),
                              );
                            }
                            final data =
                                snapshot.data!.data() as Map<String, dynamic>;

                            // Show typing indicator
                            if (data['typing'] == true) {
                              return Row(
                                children: [
                                  Text(
                                    'កំពុងវាយ',
                                    style: GoogleFonts.kantumruyPro(
                                      fontSize: 10,
                                      color: Colors.greenAccent,
                                      fontStyle: FontStyle.italic,
                                    ),
                                  ),
                                  const SizedBox(width: 4),
                                  _buildTypingDots(),
                                ],
                              );
                            }

                            if (data['isOnline'] == true) {
                              return Text(
                                'Online',
                                style: GoogleFonts.inter(
                                  fontSize: 10,
                                  color: Colors.greenAccent,
                                ),
                              );
                            }
                            return Text(
                              _formatLastSeen(data['lastSeen'] as Timestamp?),
                              style: GoogleFonts.kantumruyPro(
                                fontSize: 10,
                                color: AppTheme.textMuted,
                              ),
                            );
                          },
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            actions: [
              if (_pinnedMessageIds.isNotEmpty)
                IconButton(
                  icon: const Icon(Icons.push_pin_rounded, size: 20),
                  onPressed: _showPinnedMessagesBottomSheet,
                  tooltip: 'ផ្ដេងសារ (${_pinnedMessageIds.length})',
                ),
              IconButton(
                icon: const Icon(Icons.search_rounded, size: 20),
                onPressed: () => setState(() {
                  _showSearch = !_showSearch;
                  if (!_showSearch) {
                    _searchQuery = '';
                    _searchController.clear();
                  }
                }),
              ),
              if (!widget.isGroup)
                IconButton(
                  icon: const Icon(Icons.image_rounded, size: 20),
                  onPressed: _showMediaGallery,
                  tooltip: 'វគ្គសិល្ប៍',
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildTypingDots() {
    return SizedBox(
      width: 12,
      height: 8,
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: List.generate(3, (i) {
          return FadeIn(
            child: Container(
              width: 3,
              height: 3,
              decoration: BoxDecoration(
                color: Colors.greenAccent,
                shape: BoxShape.circle,
              ),
            ),
          );
        }),
      ),
    );
  }

  Widget _buildMessageList() {
    return Column(
      children: [
        AnimatedSize(
          duration: const Duration(milliseconds: 220),
          curve: Curves.easeInOut,
          child: _showSearch
              ? Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 16,
                    vertical: 8,
                  ),
                  child: Container(
                    height: 48,
                    decoration: BoxDecoration(
                      color: AppTheme.bgCard.withValues(alpha: 0.7),
                      borderRadius: BorderRadius.circular(12),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.25),
                          blurRadius: 8,
                          offset: const Offset(0, 2),
                        ),
                      ],
                    ),
                    child: TextField(
                      controller: _searchController,
                      style: GoogleFonts.kantumruyPro(color: Colors.white),
                      onChanged: (value) =>
                          setState(() => _searchQuery = value),
                      decoration: InputDecoration(
                        hintText: 'ស្វែងរកសារ...',
                        hintStyle: const TextStyle(color: Colors.white38),
                        border: InputBorder.none,
                        contentPadding: const EdgeInsets.symmetric(
                          vertical: 14,
                        ),
                        prefixIcon: Padding(
                          padding: const EdgeInsets.only(left: 12, right: 8),
                          child: Icon(
                            Icons.search,
                            color: AppTheme.primaryLight,
                          ),
                        ),
                        prefixIconConstraints: const BoxConstraints(
                          minWidth: 40,
                        ),
                        suffixIcon: _searchQuery.isNotEmpty
                            ? IconButton(
                                icon: const Icon(
                                  Icons.clear,
                                  color: Colors.white70,
                                ),
                                onPressed: () {
                                  _searchController.clear();
                                  setState(() => _searchQuery = '');
                                },
                              )
                            : null,
                      ),
                    ),
                  ),
                )
              : const SizedBox.shrink(),
        ),
        if (_pinnedMessageIds.isNotEmpty)
          GestureDetector(
            onTap: _showPinnedMessagesBottomSheet,
            child: Container(
              padding: const EdgeInsets.all(12),
              color: Colors.orange.withValues(alpha: 0.2),
              child: Row(
                children: [
                  const Icon(Icons.push_pin_rounded, color: Colors.orange, size: 18),
                  const SizedBox(width: 8),
                  Text(
                    'ផ្ដេងសារ ${_pinnedMessageIds.length}',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.orange,
                      fontSize: 12,
                    ),
                  ),
                  const Spacer(),
                  const Icon(
                    Icons.chevron_right,
                    color: Colors.orange,
                    size: 18,
                  ),
                ],
              ),
            ),
          ),
        Expanded(
          child: ListView.builder(
            controller: _scrollController,
            reverse: true,
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 20),
            itemCount: _messageDocs.length,
            itemBuilder: (context, index) {
              final doc = _messageDocs[index];
              final msg = doc.data() as Map<String, dynamic>;
              final isMe = msg['senderId'] == currentUserId;

              // In reverse: true
              // - index - 1 is NEWER (visually lower)
              // - index + 1 is OLDER (visually higher)

              // Show avatar if this is the bottom-most message of a consecutive block from sender
              bool showAvatar = true;
              if (index > 0) {
                final newer = _messageDocs[index - 1].data() as Map<String, dynamic>;
                showAvatar = newer['senderId'] != msg['senderId'];
              }

              // Show date separator above this message if it's the oldest message (index == length - 1)
              // OR if date of msg != date of older message (index + 1)
              bool showDateSeparator = false;
              if (index == _messageDocs.length - 1) {
                showDateSeparator = true;
              } else {
                final older = _messageDocs[index + 1].data() as Map<String, dynamic>;
                showDateSeparator = _shouldShowDateSeparator(msg, older);
              }

              return Column(
                key: ValueKey(doc.id),
                children: [
                  if (showDateSeparator)
                    _buildDateSeparator(msg['timestamp']),
                  _buildMessageBubble(doc.id, msg, isMe, showAvatar),
                ],
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildDateSeparator(Timestamp? timestamp) {
    final label = _getDateSeparator(timestamp);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 16),
      child: Row(
        children: [
          Expanded(
            child: Container(
              height: 0.5,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    Colors.transparent,
                    Colors.white.withValues(alpha: 0.12),
                  ],
                ),
              ),
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
            margin: const EdgeInsets.symmetric(horizontal: 12),
            decoration: BoxDecoration(
              color: AppTheme.bgCard.withValues(alpha: 0.6),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(
                color: Colors.white.withValues(alpha: 0.08),
                width: 0.5,
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.15),
                  blurRadius: 6,
                  offset: const Offset(0, 2),
                ),
              ],
            ),
            child: Text(
              label,
              style: GoogleFonts.kantumruyPro(
                fontSize: 11,
                color: Colors.white.withValues(alpha: 0.65),
                letterSpacing: 0.3,
              ),
            ),
          ),
          Expanded(
            child: Container(
              height: 0.5,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    Colors.white.withValues(alpha: 0.12),
                    Colors.transparent,
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMessageBubble(
    String docId,
    Map<String, dynamic> msg,
    bool isMe,
    bool showAvatar,
  ) {
    final hasReply = msg.containsKey('replyTo') && msg['replyTo'] != null;

    return Align(
      alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: EdgeInsets.only(bottom: showAvatar ? 12 : 4),
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.75,
        ),
        child: Column(
          crossAxisAlignment: isMe
              ? CrossAxisAlignment.end
              : CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: isMe
                  ? MainAxisAlignment.end
                  : MainAxisAlignment.start,
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                if (!isMe) ...[
                  if (showAvatar)
                    _buildAvatar(
                      msg['senderId'] ?? '',
                      msg['senderPhoto'] ?? '',
                      size: 36,
                    )
                  else
                    const SizedBox(width: 36),
                  const SizedBox(width: 8),
                ],
                Flexible(
                  child: GestureDetector(
                    onLongPress: () => _showQuickReactions(docId, msg, isMe),
                    onHorizontalDragEnd: (details) {
                      if (!isMe && details.primaryVelocity! > 0) {
                        setState(
                          () => _replyTo = {
                            'id': docId,
                            'senderId': msg['senderId'],
                            'text': msg['message'] ?? '(ឯកសារ)',
                          },
                        );
                      }
                    },
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 14,
                        vertical: 10,
                      ),
                      decoration: BoxDecoration(
                        gradient: isMe
                            ? const LinearGradient(
                                colors: [Color(0xFF5B6CF6), Color(0xFF8B5CF6)],
                                begin: Alignment.topLeft,
                                end: Alignment.bottomRight,
                              )
                            : null,
                        color: !isMe
                            ? const Color(0xFF1E2942).withValues(alpha: 0.92)
                            : null,
                        borderRadius: isMe
                            ? const BorderRadius.only(
                                topLeft: Radius.circular(20),
                                topRight: Radius.circular(6),
                                bottomLeft: Radius.circular(20),
                                bottomRight: Radius.circular(20),
                              )
                            : const BorderRadius.only(
                                topLeft: Radius.circular(6),
                                topRight: Radius.circular(20),
                                bottomLeft: Radius.circular(20),
                                bottomRight: Radius.circular(20),
                              ),
                        boxShadow: [
                          BoxShadow(
                            color: isMe
                                ? const Color(0xFF5B6CF6).withValues(alpha: 0.25)
                                : Colors.black.withValues(alpha: 0.20),
                            blurRadius: isMe ? 14 : 8,
                            spreadRadius: isMe ? 0 : 0,
                            offset: const Offset(0, 4),
                          ),
                        ],
                        border: Border.all(
                          color: isMe
                              ? Colors.white.withValues(alpha: 0.10)
                              : Colors.white.withValues(alpha: 0.06),
                          width: 0.8,
                        ),
                      ),
                      child: Column(
                        crossAxisAlignment: isMe
                            ? CrossAxisAlignment.end
                            : CrossAxisAlignment.start,
                        children: [
                          // Reply preview inside bubble
                          if (hasReply) ...[
                            Container(
                              padding: const EdgeInsets.all(8),
                              margin: const EdgeInsets.only(bottom: 8),
                              decoration: BoxDecoration(
                                color: Colors.white.withValues(alpha: 0.1),
                                borderRadius: BorderRadius.circular(8),
                                border: Border(
                                  left: BorderSide(
                                    color: AppTheme.primaryLight,
                                    width: 3,
                                  ),
                                ),
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    msg['replyTo']['senderId'] ?? 'Unknown',
                                    style: GoogleFonts.kantumruyPro(
                                      fontSize: 10,
                                      color: AppTheme.primaryLight,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                  const SizedBox(height: 4),
                                  Text(
                                    msg['replyTo']['text'] ?? '',
                                    maxLines: 2,
                                    overflow: TextOverflow.ellipsis,
                                    style: GoogleFonts.kantumruyPro(
                                      fontSize: 11,
                                      color: Colors.white70,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                          // Audio or Image
                          if (msg['audioBase64'] != null &&
                              msg['audioBase64'].toString().isNotEmpty)
                            AudioMessageBubble(
                              audioBase64: msg['audioBase64'],
                              isMe: isMe,
                            )
                          else ...[
                            if (msg['imageUrl'] != null &&
                                (msg['imageUrl'] as String).isNotEmpty)
                              Padding(
                                padding: const EdgeInsets.only(bottom: 8),
                                child: ClipRRect(
                                  borderRadius: BorderRadius.circular(12),
                                  child: GestureDetector(
                                    onTap: () {
                                      Navigator.push(
                                        context,
                                        MaterialPageRoute(
                                          builder: (_) => ImageViewerPage(
                                            imageUrl: msg['imageUrl'],
                                          ),
                                        ),
                                      );
                                    },
                                    child: CachedNetworkImage(
                                      imageUrl: msg['imageUrl'],
                                      placeholder: (c, u) => Container(
                                        width: double.infinity,
                                        height: 150,
                                        color: Colors.black12,
                                        child: const Center(
                                          child: CircularProgressIndicator(
                                            color: Colors.white54,
                                          ),
                                        ),
                                      ),
                                      errorWidget: (c, u, e) => Container(
                                        width: double.infinity,
                                        height: 150,
                                        color: Colors.black12,
                                        child: const Center(
                                          child: Icon(
                                            Icons.broken_image,
                                            color: Colors.white54,
                                          ),
                                        ),
                                      ),
                                      fit: BoxFit.cover,
                                    ),
                                  ),
                                ),
                              )
                            else if (msg['imageBase64'] != null &&
                                (msg['imageBase64'] as String).length > 100)
                              Padding(
                                padding: const EdgeInsets.only(bottom: 8),
                                child: ClipRRect(
                                  borderRadius: BorderRadius.circular(12),
                                  child: GestureDetector(
                                    onTap: () {
                                      Navigator.push(
                                        context,
                                        MaterialPageRoute(
                                          builder: (_) => ImageViewerPage(
                                            base64Image: msg['imageBase64'],
                                          ),
                                        ),
                                      );
                                    },
                                    child: _buildDecodedImage(
                                      msg['imageBase64'],
                                    ),
                                  ),
                                ),
                              ),
                            if (msg['message'] != null &&
                                msg['message'].isNotEmpty)
                              _buildMessageText(msg['message'], _searchQuery),
                          ],
                          const SizedBox(height: 4),
                          Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              if (msg['isEdited'] == true) ...[
                                Text(
                                  "កែប្រែ ",
                                  style: GoogleFonts.kantumruyPro(
                                    fontSize: 8,
                                    color: Colors.white60,
                                    fontStyle: FontStyle.italic,
                                  ),
                                ),
                                const SizedBox(width: 4),
                              ],
                              Text(
                                DateFormat('hh:mm a').format(
                                  (msg['timestamp'] as Timestamp?)?.toDate() ??
                                      DateTime.now(),
                                ),
                                style: GoogleFonts.inter(
                                  fontSize: 9,
                                  color: Colors.white70,
                                ),
                              ),
                              if (isMe && !widget.isGroup) ...[
                                const SizedBox(width: 4),
                                Text(
                                  _getMessageStatus(msg),
                                  style: GoogleFonts.inter(
                                    fontSize: 9,
                                    color:
                                        (msg['seenBy'] as List?)?.contains(
                                              widget.targetUserId,
                                            ) ==
                                            true
                                        ? Colors.blue
                                        : Colors.white70,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              ],
                            ],
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                if (isMe) ...[
                  const SizedBox(width: 8),
                  if (showAvatar)
                    _buildAvatar(currentUserId, currentUserPhoto, size: 36)
                  else
                    const SizedBox(width: 36),
                ],
              ],
            ),
            // Reactions display
            if ((msg['reactions'] as Map?)?.isNotEmpty == true)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: _buildReactionsDisplay(msg['reactions'] ?? {}),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildMessageText(String text, String searchQuery) {
    if (searchQuery.isEmpty) {
      return Text(
        text,
        style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 15),
      );
    }

    final spans = <TextSpan>[];
    final pattern = RegExp(searchQuery, caseSensitive: false);
    var lastIndex = 0;

    for (final match in pattern.allMatches(text)) {
      if (match.start > lastIndex) {
        spans.add(TextSpan(text: text.substring(lastIndex, match.start)));
      }
      spans.add(
        TextSpan(
          text: text.substring(match.start, match.end),
          style: const TextStyle(backgroundColor: Colors.yellow),
        ),
      );
      lastIndex = match.end;
    }

    if (lastIndex < text.length) {
      spans.add(TextSpan(text: text.substring(lastIndex)));
    }

    return RichText(
      text: TextSpan(
        style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 15),
        children: spans,
      ),
    );
  }

  Widget _buildReactionsDisplay(Map<dynamic, dynamic> reactions) {
    if (reactions.isEmpty) return const SizedBox();

    final reactionMap = Map<String, List<String>>.from(
      reactions.map(
        (k, v) => MapEntry(k.toString(), List<String>.from(v as List)),
      ),
    );

    return Wrap(
      spacing: 6,
      children: reactionMap.entries.map((entry) {
        final reacted = entry.value.contains(currentUserId);
        return GestureDetector(
          onTap: () {
            HapticFeedback.selectionClick();
            _toggleReaction(entry.key);
          },
          child: AnimatedSwitcher(
            duration: const Duration(milliseconds: 220),
            transitionBuilder: (child, anim) =>
                ScaleTransition(scale: anim, child: child),
            child: Container(
              key: ValueKey('${entry.key}-${entry.value.length}-$reacted'),
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: reacted
                    ? AppTheme.primary.withValues(alpha: 0.14)
                    : Colors.white.withValues(alpha: 0.04),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(
                  color: reacted ? AppTheme.primaryLight : Colors.transparent,
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(entry.key, style: const TextStyle(fontSize: 14)),
                  const SizedBox(width: 6),
                  Text(
                    '${entry.value.length}',
                    style: const TextStyle(fontSize: 12),
                  ),
                ],
              ),
            ),
          ),
        );
      }).toList(),
    );
  }

  Future<void> _toggleReaction(String emoji) async {
    // This would need the message ID to update properly
    debugPrint('Toggle reaction: $emoji');
  }

  Widget _buildInputArea() {
    return Container(
      constraints: const BoxConstraints(minHeight: 70),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: AppTheme.bgDark.withValues(alpha: 0.9),
        border: Border(
          top: BorderSide(color: Colors.white.withValues(alpha: 0.05)),
        ),
      ),
      child: SafeArea(
        top: false,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Failed uploads list (shows items that can be retried)
            if (_failedUploads.isNotEmpty)
              Container(
                margin: const EdgeInsets.only(bottom: 8),
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.red.withValues(alpha: 0.06),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: _failedUploads.entries.map((entry) {
                    final name = entry.key;
                    final path = entry.value;
                    return Padding(
                      padding: const EdgeInsets.symmetric(vertical: 6.0),
                      child: Row(
                        children: [
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  name,
                                  style: GoogleFonts.kantumruyPro(
                                    color: Colors.white,
                                    fontSize: 13,
                                    fontWeight: FontWeight.w600,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                                const SizedBox(height: 4),
                                Text(
                                  path,
                                  style: GoogleFonts.inter(
                                    color: Colors.white54,
                                    fontSize: 11,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ],
                            ),
                          ),
                          // Thumbnail preview (if available)
                          if (!kIsWeb && path.isNotEmpty) ...[
                            Container(
                              width: 48,
                              height: 48,
                              margin: const EdgeInsets.only(right: 8),
                              decoration: BoxDecoration(
                                borderRadius: BorderRadius.circular(8),
                                color: Colors.white12,
                              ),
                              child: ClipRRect(
                                borderRadius: BorderRadius.circular(8),
                                child: Image.file(
                                  File(path),
                                  fit: BoxFit.cover,
                                  errorBuilder: (c, e, s) => const Icon(
                                    Icons.broken_image,
                                    color: Colors.white54,
                                  ),
                                ),
                              ),
                            ),
                          ] else ...[
                            const SizedBox(width: 8),
                          ],

                          IconButton(
                            icon: const Icon(
                              Icons.refresh,
                              color: Colors.white70,
                              size: 18,
                            ),
                            tooltip: 'Retry',
                            onPressed: () => _retryUpload(name),
                          ),
                          IconButton(
                            icon: const Icon(
                              Icons.send_outlined,
                              color: Colors.white70,
                              size: 18,
                            ),
                            tooltip: 'Send inline (base64)',
                            onPressed: () => _sendAsBase64(name),
                          ),
                          IconButton(
                            icon: const Icon(
                              Icons.delete_outline,
                              color: Colors.white54,
                              size: 18,
                            ),
                            tooltip: 'Remove',
                            onPressed: () => _removeFailed(name),
                          ),
                        ],
                      ),
                    );
                  }).toList(),
                ),
              ),

            // Upload progress bar(s)
            if (_uploadProgress.isNotEmpty)
              Column(
                children: _uploadProgress.entries.map((e) {
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 6.0),
                    child: Row(
                      children: [
                        Expanded(
                          child: LinearProgressIndicator(
                            value: e.value,
                            minHeight: 6,
                            backgroundColor: Colors.white12,
                            valueColor: AlwaysStoppedAnimation(
                              AppTheme.primaryLight,
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Text(
                          '${(e.value * 100).toStringAsFixed(0)}%',
                          style: const TextStyle(
                            color: Colors.white70,
                            fontSize: 12,
                          ),
                        ),
                        const SizedBox(width: 8),
                        IconButton(
                          icon: const Icon(
                            Icons.cancel,
                            color: Colors.white70,
                            size: 18,
                          ),
                          onPressed: () {
                            // Cancel the ongoing upload task if present
                            _cancelUpload(e.key);
                          },
                        ),
                      ],
                    ),
                  );
                }).toList(),
              ),
            // Reply preview card
            if (_replyTo != null)
              Container(
                padding: const EdgeInsets.all(8),
                margin: const EdgeInsets.only(bottom: 8),
                decoration: BoxDecoration(
                  color: AppTheme.primary.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(12),
                  border: Border(
                    left: BorderSide(color: AppTheme.primaryLight, width: 3),
                  ),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'ឆ្លើយក្លាយ: ${_replyTo!['senderId']}',
                            style: GoogleFonts.kantumruyPro(
                              fontSize: 10,
                              color: AppTheme.primaryLight,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            _replyTo!['text'],
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: GoogleFonts.kantumruyPro(
                              fontSize: 11,
                              color: Colors.white70,
                            ),
                          ),
                        ],
                      ),
                    ),
                    IconButton(
                      icon: const Icon(Icons.close, size: 18),
                      onPressed: () => setState(() => _replyTo = null),
                    ),
                  ],
                ),
              ),
            AnimatedSwitcher(
              duration: const Duration(milliseconds: 200),
              child: _isRecording
                  ? _buildRecordingUI()
                  : Row(
                      key: const ValueKey('input_row'),
                      children: [
                        IconButton(
                          icon: Icon(
                            Icons.add_photo_alternate_rounded,
                            color: AppTheme.primaryLight,
                            size: 28,
                          ),
                          onPressed: _pickImage,
                        ),
                        Expanded(
                          child: Container(
                            constraints: const BoxConstraints(
                              minHeight: 48,
                              maxHeight: 120,
                            ),
                            padding: const EdgeInsets.symmetric(
                              horizontal: 14,
                              vertical: 2,
                            ),
                            decoration: BoxDecoration(
                              color: const Color(0xFF1A2540).withValues(alpha: 0.85),
                              borderRadius: BorderRadius.circular(26),
                              border: Border.all(
                                color: Colors.white.withValues(alpha: 0.09),
                                width: 0.8,
                              ),
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withValues(alpha: 0.15),
                                  blurRadius: 8,
                                  offset: const Offset(0, 2),
                                ),
                              ],
                            ),
                            child: Row(
                              children: [
                                Expanded(
                                  child: TextField(
                                    controller: _msgController,
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.white,
                                      fontSize: 15,
                                    ),
                                    maxLines: 5,
                                    minLines: 1,
                                    onChanged: (v) {
                                      setState(() {});
                                      _updateTypingStatus(v.isNotEmpty);
                                    },
                                    decoration: InputDecoration(
                                      hintText: "សរសេរសារ...",
                                      border: InputBorder.none,
                                      hintStyle: TextStyle(
                                        color: Colors.white.withValues(alpha: 0.28),
                                        fontSize: 14,
                                      ),
                                      isDense: true,
                                      contentPadding: const EdgeInsets.symmetric(
                                        vertical: 13,
                                      ),
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        _msgController.text.trim().isEmpty
                            ? Material(
                                color: Colors.transparent,
                                child: Ink(
                                  width: 48,
                                  height: 48,
                                  decoration: BoxDecoration(
                                    gradient: LinearGradient(
                                      colors: [
                                        AppTheme.primary.withValues(alpha: 1.0),
                                        AppTheme.primaryLight.withValues(
                                          alpha: 1.0,
                                        ),
                                      ],
                                      begin: Alignment.topLeft,
                                      end: Alignment.bottomRight,
                                    ),
                                    shape: BoxShape.circle,
                                    boxShadow: [
                                      BoxShadow(
                                        color: Colors.black.withValues(
                                          alpha: 0.35,
                                        ),
                                        blurRadius: 10,
                                        offset: const Offset(0, 4),
                                      ),
                                    ],
                                  ),
                                  child: InkWell(
                                    onTap: _isRecording
                                        ? null
                                        : _startRecording,
                                    customBorder: const CircleBorder(),
                                    splashColor: Colors.white24,
                                    child: Center(
                                      child: AnimatedSwitcher(
                                        duration: const Duration(
                                          milliseconds: 180,
                                        ),
                                        transitionBuilder: (child, anim) =>
                                            ScaleTransition(
                                              scale: anim,
                                              child: child,
                                            ),
                                        child: Icon(
                                          _isRecording
                                              ? Icons.mic_rounded
                                              : Icons.mic_none_rounded,
                                          key: ValueKey<bool>(_isRecording),
                                          color: Colors.white,
                                          size: 22,
                                        ),
                                      ),
                                    ),
                                  ),
                                ),
                              )
                            : Material(
                                color: Colors.transparent,
                                child: Ink(
                                  width: 48,
                                  height: 48,
                                  decoration: BoxDecoration(
                                    color: AppTheme.primary,
                                    shape: BoxShape.circle,
                                    boxShadow: [
                                      BoxShadow(
                                        color: Colors.black.withValues(
                                          alpha: 0.25,
                                        ),
                                        blurRadius: 8,
                                        offset: const Offset(0, 3),
                                      ),
                                    ],
                                  ),
                                  child: InkWell(
                                    onTap: () => _sendMessage(),
                                    customBorder: const CircleBorder(),
                                    splashColor: Colors.white24,
                                    child: Center(
                                      child: AnimatedSwitcher(
                                        duration: const Duration(
                                          milliseconds: 180,
                                        ),
                                        transitionBuilder: (child, anim) =>
                                            ScaleTransition(
                                              scale: anim,
                                              child: child,
                                            ),
                                        child: const Icon(
                                          Icons.send_rounded,
                                          key: ValueKey<String>('send_icon'),
                                          color: Colors.white,
                                          size: 22,
                                        ),
                                      ),
                                    ),
                                  ),
                                ),
                              ),
                      ],
                    ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildRecordingUI() {
    return FadeIn(
      child: Container(
        height: 54,
        padding: const EdgeInsets.symmetric(horizontal: 4),
        child: Row(
          children: [
            // Cancel Button
            IconButton(
              icon: const Icon(
                Icons.delete_forever_rounded,
                color: Colors.redAccent,
                size: 26,
              ),
              onPressed: () {
                _recorder.stop();
                _recordingTimer?.cancel();
                setState(() => _isRecording = false);
              },
            ),
            const SizedBox(width: 4),
            Expanded(
              child: Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 8,
                ),
                decoration: BoxDecoration(
                  color: Colors.redAccent.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Row(
                  children: [
                    const Icon(
                      Icons.fiber_manual_record,
                      color: Colors.redAccent,
                      size: 12,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      "${_recordingDuration ~/ 60}:${(_recordingDuration % 60).toString().padLeft(2, '0')}",
                      style: GoogleFonts.inter(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        "កំពុងថត...",
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.redAccent,
                          fontSize: 12,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(width: 10),
            // Stop and Send Button
            GestureDetector(
              onTap: _stopRecording,
              child: Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Colors.greenAccent,
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.check_rounded,
                  color: Colors.black87,
                  size: 22,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInvitationPrompt() {
    return Container(
      padding: const EdgeInsets.all(20),
      margin: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            'តើអ្នកចង់ចូលរួមក្នុងក្រុមនេះដែរឬទេ?',
            style: GoogleFonts.kantumruyPro(color: Colors.white),
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: TextButton(
                  onPressed: () => _respondToInvite(false),
                  child: const Text('បដិសេធ'),
                ),
              ),
              Expanded(
                child: ElevatedButton(
                  onPressed: () => _respondToInvite(true),
                  child: const Text('យល់ព្រម'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Future<void> _pickImage() async {
    final XFile? image = await _picker.pickImage(
      source: ImageSource.gallery,
      imageQuality: 80,
      maxWidth: 2048,
      maxHeight: 2048,
    );
    if (image != null) {
      final roomId = _getChatRoomId();
      final fileName =
          'chat_${DateTime.now().millisecondsSinceEpoch}_${image.name}';
      try {
        // Copy to app temp directory to ensure the file persists for retries
        final tempDir = await getTemporaryDirectory();
        final targetPath = '${tempDir.path}/$fileName';
        // On some platforms image.path may be null or empty; guard
        if (image.path.isNotEmpty) {
          await File(image.path).copy(targetPath);
        } else {
          // fallback: read bytes and write to file
          final bytes = await image.readAsBytes();
          await File(targetPath).writeAsBytes(bytes);
        }

        final downloadUrl = await _startUploadFromPath(
          roomId,
          fileName,
          targetPath,
        );
        if (downloadUrl != null && downloadUrl.isNotEmpty) {
          await _sendMessage(imageUrl: downloadUrl);
        } else {
          // upload failed — _startUploadFromPath already recorded _failedUploads
          _showMessage(
            'បរាជ័យក្នុងការផ្ទុកឡើង — ទាញឡើងឡើងវិញពីបញ្ជីការផ្ទុកដែលបរាជ័យ។',
          );
        }
      } catch (e) {
        debugPrint('Image upload failed (pick path): $e');
        _showMessage('មិនអាចផ្ទះក្រុមបាន: $e');
      } finally {
        // ensure UI update
        setState(() {});
      }
    }
  }

  Future<void> _respondToInvite(bool accept) async {
    if (accept) {
      await _firestore.collection('groups').doc(widget.targetUserId).update({
        'members.$currentUserId': 'accepted',
      });
      if (!mounted) return;
      setState(() => groupStatus = 'accepted');
    } else {
      await _firestore.collection('groups').doc(widget.targetUserId).update({
        'members.$currentUserId': FieldValue.delete(),
        'participantIds': FieldValue.arrayRemove([currentUserId]),
      });
      if (!mounted) return;
      Navigator.pop(context);
    }
  }

  // Retry a failed upload from local temp file
  Future<void> _retryUpload(String fileName) async {
    final path = _failedUploads[fileName];
    if (path == null) return;
    final roomId = _getChatRoomId();
    setState(() {
      _uploadProgress[fileName] = 0.0;
      // keep the failed entry until success; remove visually to indicate retry
      _failedUploads.remove(fileName);
    });

    final downloadUrl = await _startUploadFromPath(roomId, fileName, path);
    if (downloadUrl != null && downloadUrl.isNotEmpty) {
      await _sendMessage(imageUrl: downloadUrl);
      // success: save prefs already handled in startUpload
    } else {
      // re-add to failed if still exists
      try {
        if (!kIsWeb && await File(path).exists()) {
          setState(() => _failedUploads[fileName] = path);
          await _saveFailedUploadsToPrefs();
        }
      } catch (_) {}
    }
  }

  // Remove failed upload entry and delete temp file
  Future<void> _removeFailed(String fileName) async {
    final path = _failedUploads.remove(fileName);
    if (path != null) {
      try {
        final f = File(path);
        if (await f.exists()) await f.delete();
      } catch (_) {}
      await _saveFailedUploadsToPrefs();
    }
    setState(() {});
  }

  // Cancel an ongoing upload
  Future<void> _cancelUpload(String fileName) async {
    final task = _uploadTasks[fileName];
    if (task != null) {
      try {
        await task.cancel();
      } catch (e) {
        debugPrint('Cancel upload error: $e');
      }
    }
    _uploadTasks.remove(fileName);
    _uploadProgress.remove(fileName);
    setState(() {});
  }

  // Send as inline base64 fallback
  Future<void> _sendAsBase64(String fileName) async {
    final path = _failedUploads[fileName];
    if (path == null) return;
    try {
      final bytes = await File(path).readAsBytes();
      if (bytes.isNotEmpty) {
        final base64String = base64Encode(bytes);
        await _sendMessage(base64Image: base64String);
        // remove failed entry and delete temp file
        await _removeFailed(fileName);
      } else {
        _showError('ឯកសារពុំមានទិន្នន័យ (Empty file)');
      }
    } catch (e) {
      debugPrint('Send as base64 error: $e');
      _showError('មិនអាចផ្ញើជាកូដ base64 បាន: $e');
    }
  }

  void _showMessageOptions(String docId, Map<String, dynamic> msg, bool isMe) {
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.bgCard,
      builder: (_) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Emoji Reactions
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 12),
              child: Text(
                'ប្រតិកម្ម',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 12,
                ),
              ),
            ),
            SizedBox(
              height: 40,
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.symmetric(horizontal: 16),
                itemCount: _emojiReactions.length,
                itemBuilder: (context, index) {
                  return GestureDetector(
                    onTap: () {
                      _addReaction(docId, _emojiReactions[index]);
                      Navigator.pop(context);
                    },
                    child: Container(
                      margin: const EdgeInsets.symmetric(horizontal: 4),
                      padding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 6,
                      ),
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: Text(
                        _emojiReactions[index],
                        style: const TextStyle(fontSize: 20),
                      ),
                    ),
                  );
                },
              ),
            ),
            const Divider(),
            // Reply option (if not sender)
            if (!isMe)
              ListTile(
                leading: const Icon(Icons.reply, color: Colors.blue),
                title: Text(
                  'ឆ្លើយ',
                  style: GoogleFonts.kantumruyPro(color: Colors.white),
                ),
                onTap: () {
                  Navigator.pop(context);
                  setState(
                    () => _replyTo = {
                      'id': docId,
                      'senderId': msg['senderId'],
                      'text': msg['message'] ?? '(ឯកសារ)',
                    },
                  );
                },
              ),
            // Pin message option (if sender or group admin)
            ListTile(
              leading: Icon(
                _pinnedMessageIds.contains(docId)
                    ? Icons.push_pin
                    : Icons.push_pin_outlined,
                color: Colors.orange,
              ),
              title: Text(
                _pinnedMessageIds.contains(docId) ? 'ដក់ផ្ដេង' : 'ផ្ដេង',
                style: GoogleFonts.kantumruyPro(color: Colors.white),
              ),
              onTap: () {
                Navigator.pop(context);
                _togglePinMessage(docId);
              },
            ),
            // Forward message option
            ListTile(
              leading: const Icon(Icons.forward, color: Colors.green),
              title: Text(
                'ផ្ញើបន្ត',
                style: GoogleFonts.kantumruyPro(color: Colors.white),
              ),
              onTap: () {
                Navigator.pop(context);
                _showForwardDialog(msg);
              },
            ),
            // Edit option (if sender and text message)
            if (isMe && (msg['message'] != null && msg['message'].isNotEmpty))
              ListTile(
                leading: const Icon(Icons.edit, color: Colors.blue),
                title: Text(
                  'កែសម្រួល',
                  style: GoogleFonts.kantumruyPro(color: Colors.white),
                ),
                onTap: () {
                  Navigator.pop(context);
                  _showEditDialog(docId, msg['message']);
                },
              ),
            // Delete option (if sender)
            if (isMe)
              ListTile(
                leading: const Icon(Icons.delete, color: Colors.red),
                title: Text(
                  'លុប',
                  style: GoogleFonts.kantumruyPro(color: Colors.white),
                ),
                onTap: () {
                  Navigator.pop(context);
                  _firestore
                      .collection(widget.isGroup ? 'groups' : 'chats')
                      .doc(_getChatRoomId())
                      .collection('messages')
                      .doc(docId)
                      .delete();
                },
              ),
          ],
        ),
      ),
    );
  }

  Future<void> _addReaction(String docId, String emoji) async {
    final roomId = _getChatRoomId();
    final collection = widget.isGroup ? 'groups' : 'chats';
    try {
      final docRef = _firestore
          .collection(collection)
          .doc(roomId)
          .collection('messages')
          .doc(docId);

      // Toggle reaction: add if not present, remove if already reacted
      final snapshot = await docRef.get();
      if (!snapshot.exists) return;
      final data = snapshot.data() as Map<String, dynamic>;
      final reactions = Map<String, dynamic>.from(data['reactions'] ?? {});
      final List current = List.from(reactions[emoji] ?? []);
      if (current.contains(currentUserId)) {
        await docRef.update({
          'reactions.$emoji': FieldValue.arrayRemove([currentUserId]),
        });
        HapticFeedback.selectionClick();
      } else {
        await docRef.update({
          'reactions.$emoji': FieldValue.arrayUnion([currentUserId]),
        });
        HapticFeedback.selectionClick();
      }
    } catch (e) {
      debugPrint('Error adding reaction: $e');
    }
  }

  void _showQuickReactions(String docId, Map<String, dynamic> msg, bool isMe) {
    showDialog(
      context: context,
      builder: (context) => Dialog(
        backgroundColor: Colors.transparent,
        insetPadding: const EdgeInsets.all(24),
        child: Align(
          alignment: Alignment.bottomCenter,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(24),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                ..._emojiReactions.map(
                  (e) => GestureDetector(
                    onTap: () {
                      Navigator.pop(context);
                      _addReaction(docId, e);
                    },
                    child: Container(
                      margin: const EdgeInsets.symmetric(horizontal: 6),
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.04),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Text(e, style: const TextStyle(fontSize: 22)),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  icon: const Icon(Icons.more_horiz, color: Colors.white70),
                  onPressed: () {
                    Navigator.pop(context);
                    _showMessageOptions(docId, msg, isMe);
                  },
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _togglePinMessage(String docId) async {
    final roomId = _getChatRoomId();
    final collection = widget.isGroup ? 'groups' : 'chats';
    try {
      final isPinned = _pinnedMessageIds.contains(docId);
      if (isPinned) {
        await _firestore.collection(collection).doc(roomId).update({
          'pinnedMessages': FieldValue.arrayRemove([docId]),
        });
        _pinnedMessageIds.remove(docId);
      } else {
        await _firestore.collection(collection).doc(roomId).update({
          'pinnedMessages': FieldValue.arrayUnion([docId]),
        });
        _pinnedMessageIds.add(docId);
      }
      setState(() {});
      _showMessage(isPinned ? 'ដក់ផ្ដេងហើយ' : 'ផ្ដេងហើយ');
    } catch (e) {
      debugPrint('Error toggling pin: $e');
    }
  }

  void _showMessage(String message) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), duration: const Duration(seconds: 2)),
    );
  }

  void _showForwardDialog(Map<String, dynamic> msg) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        title: Text(
          'ផ្ញើបន្ត',
          style: GoogleFonts.kantumruyPro(color: Colors.white),
        ),
        content: SizedBox(
          width: double.maxFinite,
          height: 300,
          child: FutureBuilder<QuerySnapshot>(
            future: _firestore
                .collection('chats')
                .orderBy('lastTimestamp', descending: true)
                .limit(20)
                .get(),
            builder: (context, snapshot) {
              if (!snapshot.hasData) {
                return const Center(child: CircularProgressIndicator());
              }
              return ListView.builder(
                itemCount: snapshot.data!.docs.length,
                itemBuilder: (context, index) {
                  final doc = snapshot.data!.docs[index];
                  final data = doc.data() as Map<String, dynamic>;
                  return ListTile(
                    title: Text(
                      data['lastMessage'] ?? 'ចូលលេង',
                      style: GoogleFonts.kantumruyPro(color: Colors.white70),
                    ),
                    onTap: () {
                      _forwardMessage(doc.id, msg);
                      Navigator.pop(context);
                    },
                  );
                },
              );
            },
          ),
        ),
      ),
    );
  }

  Future<void> _forwardMessage(
    String targetChatId,
    Map<String, dynamic> msg,
  ) async {
    try {
      await _firestore
          .collection('chats')
          .doc(targetChatId)
          .collection('messages')
          .add({
            'senderId': currentUserId,
            'senderPhoto': currentUserPhoto,
            'message': '[ផ្ញើបន្ត] ${msg['message']}',
            'imageBase64': msg['imageBase64'] ?? '',
            'audioBase64': msg['audioBase64'] ?? '',
            'timestamp': FieldValue.serverTimestamp(),
            'isRead': false,
            'seenBy': [currentUserId],
            'isEdited': false,
            'reactions': {},
          });
      _showMessage('ផ្ញើបន្តដោយបានជោគជ័យ');
    } catch (e) {
      debugPrint('Error forwarding message: $e');
      _showMessage('ការផ្ញើបន្តបរាជ័យ');
    }
  }

  void _showPinnedMessagesBottomSheet() {
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.bgCard,
      builder: (_) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                'ផ្ដេងសារ (${_pinnedMessageIds.length})',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
            Expanded(
              child: FutureBuilder<List<DocumentSnapshot>>(
                future: Future.wait(
                  _pinnedMessageIds.map((id) {
                    final collection = widget.isGroup ? 'groups' : 'chats';
                    return _firestore
                        .collection(collection)
                        .doc(_getChatRoomId())
                        .collection('messages')
                        .doc(id)
                        .get();
                  }),
                ),
                builder: (context, snapshot) {
                  if (!snapshot.hasData) {
                    return const Center(child: CircularProgressIndicator());
                  }
                  return ListView.builder(
                    itemCount: snapshot.data!.length,
                    itemBuilder: (context, index) {
                      final msgDoc = snapshot.data![index];
                      final msg = msgDoc.data() as Map<String, dynamic>;
                      return ListTile(
                        title: Text(
                          msg['message'] ?? '(ឯកសារ)',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: GoogleFonts.kantumruyPro(color: Colors.white),
                        ),
                        subtitle: Text(
                          DateFormat('dd MMM hh:mm').format(
                            (msg['timestamp'] as Timestamp?)?.toDate() ??
                                DateTime.now(),
                          ),
                          style: GoogleFonts.inter(
                            fontSize: 10,
                            color: Colors.white54,
                          ),
                        ),
                        onTap: () {
                          Navigator.pop(context);
                          _scrollToMessage(msgDoc.id);
                        },
                      );
                    },
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _scrollToMessage(String messageId) {
    // This would need to scroll the ListView to the message
    debugPrint('Scroll to message: $messageId');
  }

  void _showMediaGallery() {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => SharedMediaScreen(
          targetUserId: widget.targetUserId,
          targetUserName: widget.targetUserName,
          roomId: _getChatRoomId(),
        ),
      ),
    );
  }

  void _showEditDialog(String docId, String oldMsg) {
    _msgController.text = oldMsg;
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        title: const Text('កែសម្រួលសារ'),
        content: TextField(
          controller: _msgController,
          autofocus: true,
          style: const TextStyle(color: Colors.white),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('បោះបង់'),
          ),
          TextButton(
            onPressed: () {
              _sendMessage(editDocId: docId);
              Navigator.pop(context);
            },
            child: const Text('រក្សាទុក'),
          ),
        ],
      ),
    );
  }

  Widget _buildAvatar(
    String id,
    String photo, {
    double size = 32,
    IconData? icon,
  }) {
    if (icon != null) {
      return Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          color: AppTheme.primary,
          shape: BoxShape.circle,
        ),
        child: Icon(icon, color: Colors.white, size: size * 0.6),
      );
    }
    final String url = ApiService.getFullImageUrl(
      photo.isNotEmpty ? photo : "$id.jpg",
    );
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        shape: BoxShape.circle,
        border: Border.all(color: AppTheme.primary.withValues(alpha: 0.3)),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(size / 2),
        child: Image.network(
          url,
          fit: BoxFit.cover,
          errorBuilder: (_, _, _) => Center(
            child: Text(
              id.isNotEmpty ? id.substring(id.length - 1).toUpperCase() : '?',
              style: GoogleFonts.inter(
                fontSize: size * 0.45,
                color: Colors.white,
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildDecodedImage(String base64Str) {
    return FutureBuilder<Uint8List>(
      future: compute(base64Decode, base64Str),
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const SizedBox(
            height: 150,
            child: Center(
              child: CircularProgressIndicator(color: Colors.white54),
            ),
          );
        }
        return Image.memory(snapshot.data!);
      },
    );
  }

  void _onScroll() {
    if (_scrollController.position.pixels ==
        _scrollController.position.maxScrollExtent) {
      _loadMoreMessages();
    }
  }

  void _loadMoreMessages() {
    // Load earlier messages when scrolling to the top
    // Implementation for loading older messages
  }

  Future<String?> _startUploadFromPath(
    String roomId,
    String fileName,
    String filePath,
  ) async {
    try {
      final file = File(filePath);
      if (!await file.exists()) {
        debugPrint('File not found: $filePath');
        _failedUploads[fileName] = filePath;
        return null;
      }

      final uploadRef =
          firebase_storage.FirebaseStorage.instance.ref().child('chats/$roomId/$fileName');

      final uploadTask = uploadRef.putFile(file);
      _uploadTasks[fileName] = uploadTask;

      uploadTask.snapshotEvents.listen((event) {
        final progress = event.bytesTransferred / event.totalBytes;
        setState(() {
          _uploadProgress[fileName] = progress;
        });
      });

      await uploadTask;
      final downloadUrl = await uploadRef.getDownloadURL();

      _failedUploads.remove(fileName);
      _uploadTasks.remove(fileName);
      _uploadProgress.remove(fileName);

      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('failed_uploads', jsonEncode(_failedUploads));

      return downloadUrl;
    } catch (e) {
      debugPrint('Upload failed: $e');
      _failedUploads[fileName] = filePath;
      _uploadTasks.remove(fileName);
      _uploadProgress.remove(fileName);

      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('failed_uploads', jsonEncode(_failedUploads));

      return null;
    }
  }
}

class AudioMessageBubble extends StatefulWidget {
  final String audioBase64;
  final bool isMe;
  const AudioMessageBubble({
    super.key,
    required this.audioBase64,
    required this.isMe,
  });

  @override
  State<AudioMessageBubble> createState() => _AudioMessageBubbleState();
}

class _AudioMessageBubbleState extends State<AudioMessageBubble> {
  late AudioPlayer _player;
  bool _isPlaying = false;
  Duration _duration = Duration.zero;
  Duration _position = Duration.zero;
  Uint8List? _audioBytes;

  @override
  void initState() {
    super.initState();
    _player = AudioPlayer();
    _player.onPositionChanged.listen((p) => setState(() => _position = p));
    _player.onDurationChanged.listen((d) => setState(() => _duration = d));
    _player.onPlayerComplete.listen((_) => setState(() => _isPlaying = false));
    _prepareSource();
  }

  Future<void> _prepareSource() async {
    final bytes = await compute(base64Decode, widget.audioBase64);
    if (!mounted) return;
    setState(() => _audioBytes = bytes);
  }

  Future<void> _togglePlay() async {
    if (_audioBytes == null) return;
    if (_isPlaying) {
      await _player.pause();
      setState(() => _isPlaying = false);
    } else {
      if (_position > Duration.zero && _position < _duration) {
        await _player.resume();
      } else {
        await _player.play(BytesSource(_audioBytes!, mimeType: 'audio/mp4'));
      }
      setState(() => _isPlaying = true);
    }
  }

  @override
  void dispose() {
    _player.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        IconButton(
          icon: Icon(
            _isPlaying
                ? Icons.pause_circle_filled_rounded
                : Icons.play_circle_filled_rounded,
            color: Colors.white,
            size: 38,
          ),
          onPressed: _togglePlay,
        ),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
              width: 120,
              child: SliderTheme(
                data: SliderThemeData(
                  trackHeight: 2,
                  thumbShape: const RoundSliderThumbShape(
                    enabledThumbRadius: 6,
                  ),
                  activeTrackColor: Colors.white,
                  inactiveTrackColor: Colors.white30,
                  thumbColor: Colors.white,
                ),
                child: Slider(
                  value: _position.inSeconds.toDouble(),
                  max: _duration.inSeconds.toDouble() > 0
                      ? _duration.inSeconds.toDouble()
                      : 1.0,
                  onChanged: (v) => _player.seek(Duration(seconds: v.toInt())),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: Text(
                "${_position.inSeconds}s / ${_duration.inSeconds}s",
                style: GoogleFonts.inter(fontSize: 10, color: Colors.white70),
              ),
            ),
          ],
        ),
      ],
    );
  }
}

class _ChatBackgroundPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.white.withValues(alpha: 0.015)
      ..strokeWidth = 1.0;

    const step = 32.0;
    for (double x = 0; x < size.width; x += step) {
      for (double y = 0; y < size.height; y += step) {
        canvas.drawCircle(Offset(x, y), 1.2, paint);
      }
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

