import 'dart:convert';
import 'dart:async';
import 'dart:io';
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:image_picker/image_picker.dart';
import 'package:file_picker/file_picker.dart';
import 'package:geolocator/geolocator.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:record/record.dart' as record_pkg;
import 'package:audioplayers/audioplayers.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../widgets/chat_wallpaper_picker.dart';

Color _getAvatarBgColor(String name) {
  if (name.isEmpty) return const Color(0xFF0084FF);
  const colors = [
    Color(0xFF0084FF),
    Color(0xFFFFB300),
    Color(0xFFAB47BC),
    Color(0xFF26A69A),
    Color(0xFFFF7043),
    Color(0xFF66BB6A),
    Color(0xFFEC407A),
  ];
  return colors[name.codeUnitAt(0) % colors.length];
}

// Memory Cache to prevent Base64 Image Flickering
final Map<String, MemoryImage> _base64ImageCache = {};

MemoryImage _getMemoryImage(String base64Str) {
  return _base64ImageCache.putIfAbsent(
    base64Str,
    () => MemoryImage(base64Decode(base64Str.contains(',') ? base64Str.split(',').last : base64Str)),
  );
}

// ==========================================
// MESSENGER DARK THEME TOKENS
// ==========================================
class _MsgDark {
  static const Color bg = Color(0xFF000000);
  static const Color card = Color(0xFF242526);
  static const Color sentBubble = Color(0xFF0084FF);
  static const Color receivedBubble = Color(0xFF3A3B3C);
  static const Color textPrimary = Color(0xFFFFFFFF);
  static const Color textMuted = Color(0xFFB0B3B8);
  static const Color iconColor = Color(0xFF0084FF);
}

class ChatDetailScreen extends StatefulWidget {
  final String targetUserId;
  final String targetUserName;
  final String targetUserPhoto;
  final bool isGroup;

  const ChatDetailScreen({
    super.key,
    required this.targetUserId,
    required this.targetUserName,
    this.targetUserPhoto = '',
    this.isGroup = false,
  });

  @override
  State<ChatDetailScreen> createState() => _ChatDetailScreenState();
}

class _ChatDetailScreenState extends State<ChatDetailScreen> {
  final TextEditingController _msgController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  final record_pkg.Record _audioRecorder = record_pkg.Record();
  final AudioPlayer _audioPlayer = AudioPlayer();

  String currentUserId = '';
  String currentUserPhoto = '';
  String _currentWallpaper = '';
  List<DocumentSnapshot> _messageDocs = [];
  StreamSubscription<QuerySnapshot>? _messageSubscription;
  StreamSubscription<Duration>? _positionSub;
  StreamSubscription<Duration>? _durationSub;

  bool _isLoadingHistory = true;

  // Realtime Presence State
  bool _isTargetOnline = false;
  DateTime? _targetLastActive;
  StreamSubscription<DocumentSnapshot>? _presenceSubscription;
  StreamSubscription<DocumentSnapshot>? _roomStateSubscription;

  // Typing & Recording Indicator State
  bool _isTargetTyping = false;
  bool _isTargetRecordingVoice = false;
  Timer? _typingDebounceTimer;

  // Voice Recording state
  bool _isRecording = false;
  int _recordingSeconds = 0;
  Timer? _recordingTimer;

  // Plus Menu State (+)
  bool _showPlusMenu = false;

  // Audio Playback state
  String? _currentlyPlayingAudio;
  bool _isPlayingAudio = false;
  double _playbackSpeed = 1.0;
  Duration _currentAudioPosition = Duration.zero;
  Duration _currentAudioDuration = Duration.zero;

  // Reply State
  String? _replyingToMessage;

  String get _roomId {
    if (widget.isGroup) return widget.targetUserId;
    final List<String> ids = [currentUserId, widget.targetUserId]..sort();
    return 'PRIVATE_${ids[0]}_${ids[1]}';
  }

  @override
  void initState() {
    super.initState();
    _init();

    _positionSub = _audioPlayer.onPositionChanged.listen((p) {
      if (mounted) setState(() => _currentAudioPosition = p);
    });
    _durationSub = _audioPlayer.onDurationChanged.listen((d) {
      if (mounted) setState(() => _currentAudioDuration = d);
    });
    _audioPlayer.onPlayerComplete.listen((_) {
      if (mounted) {
        setState(() {
          _isPlayingAudio = false;
          _currentlyPlayingAudio = null;
          _currentAudioPosition = Duration.zero;
        });
      }
    });
  }

  Future<void> _init() async {
    final prefs = await SharedPreferences.getInstance();
    currentUserId = prefs.getString('employee_id') ?? '';
    currentUserPhoto = prefs.getString('avatar') ?? '';
    final wp = await ChatWallpaperManager.getWallpaper(widget.targetUserId);
    if (mounted) {
      setState(() => _currentWallpaper = wp);
    }
    _updateMyPresence(true);
    _listenTargetPresence();
    _listenRoomState();
    _listenMessages();

    _msgController.addListener(_onTextChanged);
  }

  void _listenMessages() {
    if (currentUserId.isEmpty) return;
    _messageSubscription = _firestore
        .collection('chats')
        .doc(_roomId)
        .collection('messages')
        .orderBy('timestamp', descending: false)
        .snapshots()
        .listen((snap) {
      if (mounted) {
        setState(() {
          _messageDocs = snap.docs;
          _isLoadingHistory = false;
        });
        _markMessagesAsRead(snap.docs);
        WidgetsBinding.instance.addPostFrameCallback((_) => _scrollToBottom());
      }
    });
  }

  Future<void> _markMessagesAsRead(List<DocumentSnapshot> docs) async {
    if (currentUserId.isEmpty) return;
    final batch = _firestore.batch();
    bool hasUnread = false;

    for (var doc in docs) {
      final data = doc.data() as Map<String, dynamic>?;
      if (data != null && data['senderId'] != currentUserId && data['isRead'] == false) {
        batch.update(doc.reference, {'isRead': true});
        hasUnread = true;
      }
    }

    if (hasUnread) {
      batch.set(_firestore.collection('chats').doc(_roomId), {
        'isRead': true,
      }, SetOptions(merge: true));
      await batch.commit();
    }
  }

  void _scrollToBottom() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        _scrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeOut,
      );
    }
  }

  Future<void> _sendMessage() async {
    final text = _msgController.text.trim();
    if (text.isEmpty || currentUserId.isEmpty) return;
    _msgController.clear();

    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final msgData = {
      'text': text,
      'senderId': currentUserId,
      'senderName': userProvider.name ?? '',
      'senderPhoto': userProvider.avatar ?? '',
      'timestamp': FieldValue.serverTimestamp(),
      'type': 'text',
      'isRead': false,
      if (_replyingToMessage != null) 'replyTo': _replyingToMessage,
    };

    setState(() => _replyingToMessage = null);

    final batch = _firestore.batch();
    final msgRef = _firestore.collection('chats').doc(_roomId).collection('messages').doc();
    batch.set(msgRef, msgData);
    batch.set(_firestore.collection('chats').doc(_roomId), {
      'participants': [currentUserId, widget.targetUserId],
      'lastMessage': text,
      'lastTimestamp': FieldValue.serverTimestamp(),
      'lastSenderId': currentUserId,
      'isRead': false,
    }, SetOptions(merge: true));
    await batch.commit();
  }

  Future<void> _updateMyPresence(bool online) async {
    if (currentUserId.isEmpty) return;
    try {
      await _firestore.collection('users').doc(currentUserId).set({
        'isOnline': online,
        'lastActive': FieldValue.serverTimestamp(),
      }, SetOptions(merge: true));
    } catch (_) {}
  }

  void _listenTargetPresence() {
    if (widget.isGroup || widget.targetUserId.isEmpty) return;
    _presenceSubscription?.cancel();
    _presenceSubscription = _firestore
        .collection('users')
        .doc(widget.targetUserId)
        .snapshots()
        .listen((doc) {
      if (doc.exists && mounted) {
        final data = doc.data();
        final online = data?['isOnline'] == true;
        final ts = data?['lastActive'] as Timestamp?;
        setState(() {
          _isTargetOnline = online;
          _targetLastActive = ts?.toDate();
        });
      }
    });
  }

  void _listenRoomState() {
    _roomStateSubscription?.cancel();
    _roomStateSubscription = _firestore
        .collection('chats')
        .doc(_roomId)
        .snapshots()
        .listen((doc) {
      if (doc.exists && mounted) {
        final data = doc.data();
        if (data != null) {
          final typingMap = data['typing'] as Map<String, dynamic>? ?? {};
          final recordingMap = data['recordingVoice'] as Map<String, dynamic>? ?? {};
          setState(() {
            _isTargetTyping = typingMap[widget.targetUserId] == true;
            _isTargetRecordingVoice = recordingMap[widget.targetUserId] == true;
          });
        }
      }
    });
  }

  void _onTextChanged() {
    if (currentUserId.isEmpty) return;
    _typingDebounceTimer?.cancel();
    _setTypingState(true);
    _typingDebounceTimer = Timer(const Duration(seconds: 2), () {
      _setTypingState(false);
    });
  }

  Future<void> _setTypingState(bool isTyping) async {
    if (currentUserId.isEmpty) return;
    try {
      await _firestore.collection('chats').doc(_roomId).set({
        'typing': {currentUserId: isTyping},
      }, SetOptions(merge: true));
    } catch (_) {}
  }

  Future<void> _setRecordingVoiceState(bool isRecording) async {
    if (currentUserId.isEmpty) return;
    try {
      await _firestore.collection('chats').doc(_roomId).set({
        'recordingVoice': {currentUserId: isRecording},
      }, SetOptions(merge: true));
    } catch (_) {}
  }

  @override
  void dispose() {
    _updateMyPresence(false);
    _setTypingState(false);
    _setRecordingVoiceState(false);
    _messageSubscription?.cancel();
    _presenceSubscription?.cancel();
    _roomStateSubscription?.cancel();
    _positionSub?.cancel();
    _durationSub?.cancel();
    _recordingTimer?.cancel();
    _typingDebounceTimer?.cancel();
    _msgController.dispose();
    _scrollController.dispose();
    _audioRecorder.dispose();
    _audioPlayer.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _MsgDark.bg,
      body: Container(
        decoration: _currentWallpaper.isNotEmpty
            ? BoxDecoration(
                image: DecorationImage(
                  image: AssetImage(_currentWallpaper),
                  fit: BoxFit.cover,
                  colorFilter: ColorFilter.mode(
                    Colors.black.withValues(alpha: 0.18),
                    BlendMode.darken,
                  ),
                ),
              )
            : null,
        child: SafeArea(
          child: Column(
            children: [
              _buildHeader(),
              Expanded(
                child: _buildMessageFeed(),
              ),
              if (_replyingToMessage != null) _buildReplyPreviewBanner(),
              if (_showPlusMenu) _buildPlusMenuOverlay(),
              _buildInputToolbar(),
            ],
          ),
        ),
      ),
    );
  }

  // ==========================================
  // A. CUSTOM APP BAR (Translucent Messenger Style)
  // ==========================================
  Widget _buildHeader() {
    String statusText = 'គ្មាន Online';
    if (_isTargetOnline) {
      statusText = 'Active Now';
    } else if (_targetLastActive != null) {
      final diff = DateTime.now().difference(_targetLastActive!);
      if (diff.inMinutes < 60) {
        statusText = 'Active ${diff.inMinutes}m ago';
      } else if (diff.inHours < 24) {
        statusText = 'Active ${diff.inHours}h ago';
      } else {
        statusText = DateFormat('dd/MM HH:mm').format(_targetLastActive!);
      }
    }

    return ClipRect(
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 16, sigmaY: 16),
        child: Container(
          color: Colors.black.withValues(alpha: 0.20),
          padding: const EdgeInsets.symmetric(horizontal: 8.0, vertical: 8.0),
          child: Row(
            children: [
              IconButton(
                icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 22),
                onPressed: () => Navigator.pop(context),
              ),
              GestureDetector(
                onTap: _showUserProfileModal,
                child: Row(
                  children: [
                    Stack(
                      children: [
                        CircleAvatar(
                          radius: 20.0,
                          backgroundImage: widget.targetUserPhoto.isNotEmpty
                              ? NetworkImage(ApiService.getFullImageUrl(widget.targetUserPhoto))
                              : null,
                          backgroundColor: _getAvatarBgColor(widget.targetUserName),
                          child: widget.targetUserPhoto.isEmpty
                              ? Text(
                                  widget.targetUserName.isNotEmpty ? widget.targetUserName[0].toUpperCase() : 'U',
                                  style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, fontSize: 16, color: Colors.white),
                                )
                              : null,
                        ),
                        Positioned(
                          right: 0,
                          bottom: 0,
                          child: Container(
                            width: 11,
                            height: 11,
                            decoration: BoxDecoration(
                              color: _isTargetOnline ? const Color(0xFF44B700) : Colors.grey,
                              shape: BoxShape.circle,
                              border: Border.all(color: Colors.black, width: 1.8),
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(width: 10.0),
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          widget.targetUserName,
                          style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16.0),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        Text(
                          statusText,
                          style: GoogleFonts.inter(color: Colors.white70, fontSize: 11.5, fontWeight: FontWeight.w400),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.phone_rounded, color: Colors.white, size: 24),
                onPressed: () => _showCallDialog(false),
              ),
              IconButton(
                icon: const Icon(Icons.videocam_rounded, color: Colors.white, size: 26),
                onPressed: () => _showCallDialog(true),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showUserProfileModal() {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1C1C1E),
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(28.0)),
      ),
      builder: (ctx) {
        return StreamBuilder<DocumentSnapshot>(
          stream: _firestore.collection('users').doc(widget.targetUserId).snapshots(),
          builder: (context, snapshot) {
            Map<String, dynamic> uData = {};
            if (snapshot.hasData && snapshot.data!.exists) {
              uData = snapshot.data!.data() as Map<String, dynamic>;
            }

            final name = uData['name'] ?? widget.targetUserName;
            final avatar = uData['avatar'] ?? widget.targetUserPhoto;
            final position = uData['position'] ?? uData['role'] ?? 'បុគ្គលិក';
            final department = uData['department'] ?? 'VVC';
            final phone = uData['phone'] ?? uData['phone_number'] ?? 'គ្មានទិន្នន័យ';
            final email = uData['email'] ?? 'គ្មានទិន្នន័យ';
            final bool online = uData['isOnline'] == true;

            return Padding(
              padding: const EdgeInsets.fromLTRB(20.0, 12.0, 20.0, 30.0),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(width: 40, height: 4.5, decoration: BoxDecoration(color: Colors.white30, borderRadius: BorderRadius.circular(10))),
                  const SizedBox(height: 20),
                  Stack(
                    children: [
                      CircleAvatar(
                        radius: 46.0,
                        backgroundImage: avatar.isNotEmpty ? NetworkImage(ApiService.getFullImageUrl(avatar)) : null,
                        backgroundColor: _getAvatarBgColor(name),
                        child: avatar.isEmpty
                            ? Text(name.isNotEmpty ? name[0].toUpperCase() : 'U', style: GoogleFonts.kantumruyPro(fontSize: 32, color: Colors.white, fontWeight: FontWeight.bold))
                            : null,
                      ),
                      Positioned(
                        right: 2,
                        bottom: 2,
                        child: Container(
                          width: 18,
                          height: 18,
                          decoration: BoxDecoration(
                            color: online ? const Color(0xFF44B700) : Colors.grey,
                            shape: BoxShape.circle,
                            border: Border.all(color: const Color(0xFF1C1C1E), width: 3),
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),
                  Text(
                    name,
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '$position • $department',
                    style: GoogleFonts.kantumruyPro(color: _MsgDark.textMuted, fontSize: 13.5),
                  ),
                  const SizedBox(height: 18),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      _buildProfileActionButton(Icons.phone_rounded, 'ការហៅ', () {
                        Navigator.pop(ctx);
                        _showCallDialog(false);
                      }),
                      _buildProfileActionButton(Icons.videocam_rounded, 'វីដេអូ', () {
                        Navigator.pop(ctx);
                        _showCallDialog(true);
                      }),
                      _buildProfileActionButton(Icons.wallpaper_rounded, 'Wallpaper', () {
                        Navigator.pop(ctx);
                        showChatWallpaperPicker(
                          context,
                          targetId: widget.targetUserId,
                          targetName: widget.targetUserName,
                          onWallpaperSelected: (wp) => setState(() => _currentWallpaper = wp),
                        );
                      }),
                    ],
                  ),
                  const SizedBox(height: 22),
                  Container(
                    decoration: BoxDecoration(
                      color: const Color(0xFF2C2C2E),
                      borderRadius: BorderRadius.circular(16),
                    ),
                    child: Column(
                      children: [
                        ListTile(
                          leading: const Icon(Icons.phone_outlined, color: _MsgDark.iconColor),
                          title: Text('លេខទូរស័ព្ទ', style: GoogleFonts.kantumruyPro(color: _MsgDark.textMuted, fontSize: 12)),
                          subtitle: Text(phone, style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
                        ),
                        const Divider(height: 1, color: Colors.white12),
                        ListTile(
                          leading: const Icon(Icons.email_outlined, color: _MsgDark.iconColor),
                          title: Text('អ៊ីមែល', style: GoogleFonts.kantumruyPro(color: _MsgDark.textMuted, fontSize: 12)),
                          subtitle: Text(email, style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
                        ),
                      ],
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

  Widget _buildProfileActionButton(IconData icon, String label, VoidCallback onTap) {
    return Column(
      children: [
        InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(30),
          child: Container(
            width: 48,
            height: 48,
            decoration: const BoxDecoration(
              color: Color(0xFF2C2C2E),
              shape: BoxShape.circle,
            ),
            child: Icon(icon, color: _MsgDark.iconColor, size: 24),
          ),
        ),
        const SizedBox(height: 6),
        Text(label, style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
      ],
    );
  }

  Widget _buildTypingIndicator() {
    return Align(
      alignment: Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 4.0),
        padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 10.0),
        decoration: BoxDecoration(
          color: const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(18.0),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'កំពុងវាយ...',
              style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5),
            ),
            const SizedBox(width: 8.0),
            const SizedBox(
              width: 14,
              height: 14,
              child: CircularProgressIndicator(strokeWidth: 2.0, color: _MsgDark.iconColor),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildVoiceRecordingIndicator() {
    return Align(
      alignment: Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 4.0),
        padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 10.0),
        decoration: BoxDecoration(
          color: const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(18.0),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.mic_rounded, color: Colors.redAccent, size: 16),
            const SizedBox(width: 6.0),
            Text(
              'កំពុងថតសំឡេង...',
              style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // B. MESSAGE FEED LIST
  // ==========================================
  Widget _buildMessageFeed() {
    if (_isLoadingHistory) {
      return const Center(child: CircularProgressIndicator(color: _MsgDark.iconColor));
    }
    if (_messageDocs.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            CircleAvatar(
              radius: 40,
              backgroundColor: _getAvatarBgColor(widget.targetUserName),
              backgroundImage: widget.targetUserPhoto.isNotEmpty
                  ? NetworkImage(ApiService.getFullImageUrl(widget.targetUserPhoto))
                  : null,
              child: widget.targetUserPhoto.isEmpty
                  ? Text(widget.targetUserName[0].toUpperCase(), style: GoogleFonts.inter(fontSize: 32, color: Colors.white, fontWeight: FontWeight.bold))
                  : null,
            ),
            const SizedBox(height: 12),
            Text(widget.targetUserName, style: GoogleFonts.kantumruyPro(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.white)),
            const SizedBox(height: 4),
            Text('ចាប់ផ្តើមការសន្ទនាជាមួយគ្នា!', style: GoogleFonts.kantumruyPro(color: _MsgDark.textMuted, fontSize: 13)),
          ],
        ),
      );
    }

    final bool hasIndicator = _isTargetTyping || _isTargetRecordingVoice;

    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.symmetric(horizontal: 12.0, vertical: 8.0),
      itemCount: _messageDocs.length + (hasIndicator ? 1 : 0),
      itemBuilder: (context, index) {
        if (index == _messageDocs.length) {
          if (_isTargetRecordingVoice) return _buildVoiceRecordingIndicator();
          return _buildTypingIndicator();
        }

        final doc = _messageDocs[index];
        final data = doc.data() as Map<String, dynamic>;
        final String senderId = data['senderId'] ?? '';
        final bool isMine = senderId == currentUserId;

        final Timestamp? ts = data['timestamp'] as Timestamp?;
        final DateTime msgTime = ts?.toDate() ?? DateTime.now();

        final String rawText = (data['text'] ?? data['message'] ?? data['content'] ?? '').toString();
        final String imageUrl = (data['imageUrl'] ?? data['mediaUrl'] ?? (data['type'] == 'image' ? rawText : '')).toString();
        final String audioUrl = (data['audioUrl'] ?? data['voiceUrl'] ?? data['base64Audio'] ?? '').toString();
        final int durationSeconds = (data['audioDuration'] ?? data['duration'] ?? 3) as int;
        final String rawType = (data['type'] ?? '').toString();
        final bool isRead = data['isRead'] == true;
        final String? replyTo = data['replyTo'] as String?;

        final bool showDivider = _shouldShowDateDivider(index, ts);

        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (showDivider) _buildDateDivider(msgTime),
            if (rawType == 'callMissed') _buildCallEventCard(isMissed: true, time: msgTime),
            if (rawType == 'callVideo') _buildCallEventCard(isMissed: false, time: msgTime),
            if (imageUrl.isNotEmpty || rawType == 'image')
              _buildImageBubble(docId: doc.id, imageUrl: imageUrl, isMine: isMine, time: msgTime, isRead: isRead),
            if (audioUrl.isNotEmpty || rawType == 'audio' || rawType == 'voice')
              _buildVoiceBubble(docId: doc.id, audioUrl: audioUrl, durationSeconds: durationSeconds, isMine: isMine, time: msgTime, isRead: isRead),
            if (rawType == 'file')
              _buildFileBubble(fileName: (data['fileName'] ?? 'Document').toString(), fileSize: (data['fileSize'] ?? '').toString(), isMine: isMine, time: msgTime, isRead: isRead),
            if (rawType == 'location')
              _buildLocationBubble(text: rawText, lat: (data['latitude'] ?? 0.0) as double, lng: (data['longitude'] ?? 0.0) as double, isMine: isMine, time: msgTime, isRead: isRead),
            if (rawType == 'sticker' || rawText == '👍')
              _buildStickerBubble(text: rawText.isNotEmpty ? rawText : '👍', isMine: isMine),
            if (rawType != 'callMissed' && rawType != 'callVideo' && !imageUrl.isNotEmpty && rawType != 'image' && !audioUrl.isNotEmpty && rawType != 'audio' && rawType != 'voice' && rawType != 'file' && rawType != 'location' && rawType != 'sticker' && rawText != '👍' && rawText.isNotEmpty)
              _buildTextBubble(text: rawText, replyTo: replyTo, isMine: isMine, time: msgTime, isRead: isRead),
          ],
        );
      },
    );
  }

  bool _shouldShowDateDivider(int index, Timestamp? currentTs) {
    if (index == 0 || currentTs == null) return true;
    final prevDoc = _messageDocs[index - 1].data() as Map<String, dynamic>?;
    final Timestamp? prevTs = prevDoc?['timestamp'] as Timestamp?;
    if (prevTs == null) return true;

    final currDate = currentTs.toDate();
    final prevDate = prevTs.toDate();
    return currDate.day != prevDate.day || currDate.month != prevDate.month || currDate.year != prevDate.year;
  }

  // Date Divider in Khmer
  Widget _buildDateDivider(DateTime date) {
    final now = DateTime.now();
    String dateStr = '';

    if (date.year == now.year && date.month == now.month && date.day == now.day) {
      dateStr = 'ថ្ងៃនេះ (Today)';
    } else if (date.year == now.year && date.month == now.month && date.day == now.day - 1) {
      dateStr = 'ម្សិលមិញ (Yesterday)';
    } else {
      dateStr = DateFormat('E, d MMM yyyy').format(date);
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 14.0),
      child: Row(
        children: [
          const Expanded(child: Divider(color: Colors.white24, height: 1)),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 10.0),
            child: Text(
              dateStr,
              style: GoogleFonts.kantumruyPro(fontSize: 11.5, color: _MsgDark.textMuted, fontWeight: FontWeight.w600),
            ),
          ),
          const Expanded(child: Divider(color: Colors.white24, height: 1)),
        ],
      ),
    );
  }

  Widget _buildReadStatusIcon(bool isRead) {
    if (isRead) {
      return widget.targetUserPhoto.isNotEmpty
          ? CircleAvatar(
              radius: 6.0,
              backgroundImage: NetworkImage(ApiService.getFullImageUrl(widget.targetUserPhoto)),
            )
          : const Icon(Icons.done_all_rounded, size: 14, color: _MsgDark.iconColor);
    }
    return const Icon(Icons.done_all_rounded, size: 14, color: Colors.white38);
  }

  // Text Message Bubble
  Widget _buildTextBubble({
    required String text,
    String? replyTo,
    required bool isMine,
    required DateTime time,
    required bool isRead,
  }) {
    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          Container(
            margin: const EdgeInsets.symmetric(vertical: 3.0),
            padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 10.0),
            constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.72),
            decoration: BoxDecoration(
              color: isMine ? _MsgDark.sentBubble : _MsgDark.receivedBubble,
              borderRadius: BorderRadius.only(
                topLeft: const Radius.circular(18.0),
                topRight: const Radius.circular(18.0),
                bottomLeft: Radius.circular(isMine ? 18.0 : 4.0),
                bottomRight: Radius.circular(isMine ? 4.0 : 18.0),
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (replyTo != null) ...[
                  Container(
                    padding: const EdgeInsets.all(6),
                    margin: const EdgeInsets.only(bottom: 6),
                    decoration: BoxDecoration(
                      color: Colors.black26,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(
                      '↩️ $replyTo',
                      style: GoogleFonts.kantumruyPro(fontSize: 11.5, color: Colors.white70),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
                Text(
                  text,
                  style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14.5, height: 1.35, fontWeight: FontWeight.bold),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(left: 4.0, right: 4.0, bottom: 4.0),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  DateFormat('h:mm a').format(time),
                  style: GoogleFonts.inter(fontSize: 10.0, color: _MsgDark.textMuted),
                ),
                if (isMine) ...[
                  const SizedBox(width: 4.0),
                  _buildReadStatusIcon(isRead),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  // Sticker / Emoji Bubble
  Widget _buildStickerBubble({required String text, required bool isMine}) {
    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 4.0),
        child: Text(text, style: const TextStyle(fontSize: 48.0)),
      ),
    );
  }

  // Call Event Card
  Widget _buildCallEventCard({required bool isMissed, required DateTime time}) {
    return Align(
      alignment: Alignment.centerRight,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 6.0),
        width: 220.0,
        decoration: BoxDecoration(
          color: _MsgDark.card,
          borderRadius: BorderRadius.circular(16.0),
        ),
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(14.0, 14.0, 14.0, 10.0),
              child: Row(
                children: [
                  Container(
                    width: 40.0,
                    height: 40.0,
                    decoration: const BoxDecoration(
                      color: Color(0xFF3E4042),
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      isMissed ? Icons.phone_disabled_rounded : Icons.videocam_rounded,
                      size: 20.0,
                      color: isMissed ? Colors.redAccent : _MsgDark.iconColor,
                    ),
                  ),
                  const SizedBox(width: 12.0),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          isMissed ? 'Missed audio call' : 'Video call',
                          style: GoogleFonts.inter(
                            color: _MsgDark.textPrimary,
                            fontWeight: FontWeight.w600,
                            fontSize: 14.0,
                          ),
                        ),
                        const SizedBox(height: 2.0),
                        Text(
                          isMissed ? DateFormat('h:mm a').format(time) : '4 min, 31 secs',
                          style: GoogleFonts.inter(fontSize: 12.0, color: _MsgDark.textMuted),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const Divider(height: 1.0, color: Color(0xFF3E4042)),
            InkWell(
              onTap: () => _showCallDialog(false),
              borderRadius: const BorderRadius.only(
                bottomLeft: Radius.circular(16.0),
                bottomRight: Radius.circular(16.0),
              ),
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(vertical: 10.0),
                child: Text(
                  'Call again',
                  textAlign: TextAlign.center,
                  style: GoogleFonts.inter(
                    color: _MsgDark.iconColor,
                    fontWeight: FontWeight.w600,
                    fontSize: 14.0,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // Non-Flickering Image Bubble + Full Screen Action Viewer
  Widget _buildImageBubble({
    required String docId,
    required String imageUrl,
    required bool isMine,
    required DateTime time,
    required bool isRead,
  }) {
    final bool isBase64 = imageUrl.startsWith('data:image');
    final ImageProvider imgProvider = isBase64
        ? _getMemoryImage(imageUrl)
        : NetworkImage(imageUrl) as ImageProvider;

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          GestureDetector(
            key: ValueKey(imageUrl),
            onTap: () => _showFullScreenImageViewer(imgProvider, imageUrl),
            child: Container(
              margin: const EdgeInsets.symmetric(vertical: 4.0),
              constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.7),
              height: 200.0,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(16.0),
                image: DecorationImage(image: imgProvider, fit: BoxFit.cover),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(left: 4.0, right: 4.0, bottom: 4.0),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  DateFormat('h:mm a').format(time),
                  style: GoogleFonts.inter(fontSize: 10.0, color: _MsgDark.textMuted),
                ),
                if (isMine) ...[
                  const SizedBox(width: 4.0),
                  _buildReadStatusIcon(isRead),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  // Full Screen Image Viewer Modal (Close, Download, Forward, Share)
  void _showFullScreenImageViewer(ImageProvider imgProvider, String rawUrl) {
    showDialog(
      context: context,
      builder: (ctx) => Dialog(
        backgroundColor: Colors.black.withValues(alpha: 0.92),
        insetPadding: EdgeInsets.zero,
        child: Stack(
          alignment: Alignment.bottomCenter,
          children: [
            Center(
              child: InteractiveViewer(
                child: Image(image: imgProvider, fit: BoxFit.contain),
              ),
            ),
            // Top Bar: Close Button
            Positioned(
              top: 40.0,
              right: 16.0,
              child: CircleAvatar(
                backgroundColor: Colors.black54,
                child: IconButton(
                  icon: const Icon(Icons.close_rounded, color: Colors.white, size: 24),
                  onPressed: () => Navigator.pop(ctx),
                ),
              ),
            ),
            // Bottom Action Bar (Download, Forward, Share)
            Container(
              padding: const EdgeInsets.symmetric(vertical: 16.0, horizontal: 24.0),
              color: Colors.black87,
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  IconButton(
                    icon: const Icon(Icons.download_rounded, color: Colors.white, size: 26),
                    onPressed: () async {
                      Navigator.pop(ctx);
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text('បានរក្សាទុករូបភាពក្នុង Gallery!', style: GoogleFonts.kantumruyPro())),
                      );
                    },
                    tooltip: 'Save Image',
                  ),
                  IconButton(
                    icon: const Icon(Icons.shortcut_rounded, color: Colors.white, size: 26),
                    onPressed: () {
                      Navigator.pop(ctx);
                      _showForwardModal(rawUrl, 'image');
                    },
                    tooltip: 'Forward Image',
                  ),
                  IconButton(
                    icon: const Icon(Icons.share_rounded, color: Colors.white, size: 26),
                    onPressed: () async {
                      Navigator.pop(ctx);
                      if (rawUrl.startsWith('http')) {
                        Share.share(rawUrl);
                      } else {
                        final dir = await getTemporaryDirectory();
                        final tempFile = File('${dir.path}/shared_img_${DateTime.now().millisecondsSinceEpoch}.jpg');
                        await tempFile.writeAsBytes(base64Decode(rawUrl.split(',').last));
                        Share.shareXFiles([XFile(tempFile.path)]);
                      }
                    },
                    tooltip: 'Share Image',
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  // Interactive Playable Voice Message Bubble (Clean Messenger Style)
  Widget _buildVoiceBubble({
    required String docId,
    required String audioUrl,
    required int durationSeconds,
    required bool isMine,
    required DateTime time,
    required bool isRead,
  }) {
    final bool isThisPlaying = _isPlayingAudio && _currentlyPlayingAudio == audioUrl;

    double progress = 0.0;
    if (isThisPlaying && _currentAudioDuration.inMilliseconds > 0) {
      progress = (_currentAudioPosition.inMilliseconds / _currentAudioDuration.inMilliseconds).clamp(0.0, 1.0);
    }

    final Color bubbleBg = isMine ? const Color(0xFFF29BB8) : const Color(0xDD4E1025);
    final Color textColor = isMine ? const Color(0xFF1E1E1E) : Colors.white;
    final Color playBg = isMine ? Colors.black.withValues(alpha: 0.25) : Colors.white.withValues(alpha: 0.25);
    final Color playIconColor = isMine ? const Color(0xFF1E1E1E) : Colors.white;

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          GestureDetector(
            onLongPress: () => _showVoiceOptionsModal(docId, audioUrl),
            child: Container(
              margin: const EdgeInsets.symmetric(vertical: 4.0),
              padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 10.0),
              decoration: BoxDecoration(
                color: bubbleBg,
                borderRadius: BorderRadius.only(
                  topLeft: const Radius.circular(22.0),
                  topRight: const Radius.circular(22.0),
                  bottomLeft: Radius.circular(isMine ? 22.0 : 4.0),
                  bottomRight: Radius.circular(isMine ? 4.0 : 22.0),
                ),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.15),
                    blurRadius: 6,
                    offset: const Offset(0, 2),
                  ),
                ],
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Play / Pause Button
                  GestureDetector(
                    onTap: () => _togglePlayAudio(audioUrl),
                    child: Container(
                      width: 40.0,
                      height: 40.0,
                      decoration: BoxDecoration(
                        color: playBg,
                        shape: BoxShape.circle,
                      ),
                      child: Icon(
                        isThisPlaying ? Icons.pause_rounded : Icons.play_arrow_rounded,
                        color: playIconColor,
                        size: 26.0,
                      ),
                    ),
                  ),
                  const SizedBox(width: 12.0),

                  // Waveform Bars (Vertical Audio Wave)
                  GestureDetector(
                    onHorizontalDragUpdate: (details) {
                      if (isThisPlaying && _currentAudioDuration.inMilliseconds > 0) {
                        final dx = details.localPosition.dx.clamp(0.0, 130.0);
                        final val = dx / 130.0;
                        final seekMs = (val * _currentAudioDuration.inMilliseconds).round();
                        _audioPlayer.seek(Duration(milliseconds: seekMs));
                      }
                    },
                    child: SizedBox(
                      width: 130.0,
                      height: 32.0,
                      child: Center(
                        child: _buildWaveformBars(
                          isPlaying: isThisPlaying,
                          progress: progress,
                          isMine: isMine,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12.0),

                  // Duration Readout
                  Text(
                    isThisPlaying
                        ? _formatDuration(_currentAudioPosition.inSeconds)
                        : _formatDuration(durationSeconds),
                    style: GoogleFonts.inter(
                      color: textColor,
                      fontSize: 12.5,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(left: 4.0, right: 4.0, bottom: 4.0),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  DateFormat('h:mm a').format(time),
                  style: GoogleFonts.inter(fontSize: 10.0, color: _MsgDark.textMuted),
                ),
                if (isMine) ...[
                  const SizedBox(width: 4.0),
                  _buildReadStatusIcon(isRead),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildWaveformBars({
    required bool isPlaying,
    required double progress,
    required bool isMine,
  }) {
    const barsCount = 26;
    const heights = [
      8.0, 16.0, 24.0, 12.0, 30.0, 18.0, 26.0, 10.0,
      22.0, 32.0, 14.0, 28.0, 20.0, 34.0, 16.0, 24.0,
      10.0, 28.0, 18.0, 30.0, 12.0, 22.0, 16.0, 8.0, 14.0, 10.0
    ];

    return Row(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.center,
      children: List.generate(barsCount, (index) {
        final barHeight = heights[index % heights.length];
        final barProgress = (index + 1) / barsCount;
        final isPlayed = isPlaying && barProgress <= progress;

        final Color barColor = isMine
            ? (isPlayed ? const Color(0xFF1E1E1E) : Colors.black38)
            : (isPlayed ? Colors.white : Colors.white38);

        return Container(
          width: 3.0,
          height: barHeight,
          margin: const EdgeInsets.symmetric(horizontal: 1.0),
          decoration: BoxDecoration(
            color: barColor,
            borderRadius: BorderRadius.circular(1.5),
          ),
        );
      }),
    );
  }

  // Voice Message Options BottomSheet (Reply, Forward, Pin, Delete)
  void _showVoiceOptionsModal(String docId, String audioUrl) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF2C2C2E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20.0)),
      ),
      builder: (ctx) {
        return SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const SizedBox(height: 8),
              Container(width: 36, height: 4, decoration: BoxDecoration(color: Colors.white30, borderRadius: BorderRadius.circular(2))),
              const SizedBox(height: 12),
              ListTile(
                leading: const Icon(Icons.reply_rounded, color: Colors.white),
                title: Text('ឆ្លើយតប (Reply)', style: GoogleFonts.kantumruyPro(color: Colors.white)),
                onTap: () {
                  Navigator.pop(ctx);
                  setState(() => _replyingToMessage = '🎙️ សារសំឡេង');
                },
              ),
              ListTile(
                leading: const Icon(Icons.shortcut_rounded, color: Colors.white),
                title: Text('បញ្ជូនបន្ត (Forward)', style: GoogleFonts.kantumruyPro(color: Colors.white)),
                onTap: () {
                  Navigator.pop(ctx);
                  _showForwardModal(audioUrl, 'voice');
                },
              ),
              ListTile(
                leading: const Icon(Icons.push_pin_rounded, color: Colors.white),
                title: Text('ប៉ិនទុក (Pin)', style: GoogleFonts.kantumruyPro(color: Colors.white)),
                onTap: () {
                  Navigator.pop(ctx);
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('បានប៉ិនសារទុក!', style: GoogleFonts.kantumruyPro())),
                  );
                },
              ),
              ListTile(
                leading: const Icon(Icons.delete_forever_rounded, color: Colors.redAccent),
                title: Text('លុបសារ (Delete)', style: GoogleFonts.kantumruyPro(color: Colors.redAccent)),
                onTap: () async {
                  Navigator.pop(ctx);
                  await _firestore.collection('chats').doc(_roomId).collection('messages').doc(docId).delete();
                },
              ),
              const SizedBox(height: 12),
            ],
          ),
        );
      },
    );
  }

  // Forward Message Modal to Select Contact
  void _showForwardModal(String content, String type) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF2C2C2E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20.0)),
      ),
      builder: (ctx) {
        return StreamBuilder<QuerySnapshot>(
          stream: _firestore.collection('users').snapshots(),
          builder: (context, snap) {
            if (!snap.hasData) return const Center(child: CircularProgressIndicator());
            final users = snap.data!.docs.where((d) => d.id != currentUserId).toList();

            return Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Text(
                    'បញ្ជូនបន្តទៅកាន់ (Forward to)',
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                ),
                Expanded(
                  child: ListView.builder(
                    itemCount: users.length,
                    itemBuilder: (context, index) {
                      final u = users[index].data() as Map<String, dynamic>;
                      final targetId = users[index].id;
                      final name = u['name'] ?? 'User';
                      final avatar = u['avatar'] ?? '';

                      return ListTile(
                        leading: CircleAvatar(
                          backgroundImage: avatar.isNotEmpty ? NetworkImage(ApiService.getFullImageUrl(avatar)) : null,
                          backgroundColor: _getAvatarBgColor(name),
                          child: avatar.isEmpty ? Text(name[0].toUpperCase(), style: const TextStyle(color: Colors.white)) : null,
                        ),
                        title: Text(name, style: GoogleFonts.kantumruyPro(color: Colors.white)),
                        trailing: const Icon(Icons.send_rounded, color: _MsgDark.iconColor),
                        onTap: () async {
                          Navigator.pop(ctx);
                          final userProvider = Provider.of<UserProvider>(context, listen: false);
                          final targetRoomId = "PRIVATE_${([currentUserId, targetId]..sort()).join('_')}";

                          final msgData = {
                            'text': type == 'text' ? content : '',
                            if (type == 'image') 'imageUrl': content,
                            if (type == 'voice') 'base64Audio': content,
                            'type': type,
                            'senderId': currentUserId,
                            'senderName': userProvider.name ?? '',
                            'senderPhoto': userProvider.avatar ?? '',
                            'timestamp': FieldValue.serverTimestamp(),
                            'isRead': false,
                          };

                          final messenger = ScaffoldMessenger.of(context);
                          final batch = _firestore.batch();
                          final msgRef = _firestore.collection('chats').doc(targetRoomId).collection('messages').doc();
                          batch.set(msgRef, msgData);
                          batch.set(_firestore.collection('chats').doc(targetRoomId), {
                            'participants': [currentUserId, targetId],
                            'lastMessage': '↪️ បានបញ្ជូនបន្តសារ',
                            'lastTimestamp': FieldValue.serverTimestamp(),
                            'lastSenderId': currentUserId,
                            'isRead': false,
                          }, SetOptions(merge: true));
                          await batch.commit();

                          if (mounted) {
                            messenger.showSnackBar(
                              SnackBar(content: Text('បានបញ្ជូនបន្តសារទៅកាន់ $name រួចរាល់!', style: GoogleFonts.kantumruyPro())),
                            );
                          }
                        },
                      );
                    },
                  ),
                ),
              ],
            );
          },
        );
      },
    );
  }

  String _formatDuration(int seconds) {
    final mins = seconds ~/ 60;
    final secs = seconds % 60;
    return '$mins:${secs.toString().padLeft(2, '0')}';
  }

  Future<void> _togglePlayAudio(String url) async {
    try {
      if (_isPlayingAudio && _currentlyPlayingAudio == url) {
        await _audioPlayer.pause();
        setState(() => _isPlayingAudio = false);
        return;
      }

      await _audioPlayer.stop();

      if (url.startsWith('data:audio')) {
        final base64Str = url.split(',').last;
        final bytes = base64Decode(base64Str);
        final dir = await getTemporaryDirectory();
        final tempFile = File('${dir.path}/temp_play_${DateTime.now().millisecondsSinceEpoch}.m4a');
        await tempFile.writeAsBytes(bytes);
        await _audioPlayer.play(DeviceFileSource(tempFile.path));
      } else {
        await _audioPlayer.play(UrlSource(url));
      }

      await _audioPlayer.setPlaybackRate(_playbackSpeed);

      setState(() {
        _currentlyPlayingAudio = url;
        _isPlayingAudio = true;
      });
    } catch (e) {
      debugPrint('Audio playback error: $e');
    }
  }

  // File Bubble
  Widget _buildFileBubble({
    required String fileName,
    required String fileSize,
    required bool isMine,
    required DateTime time,
    required bool isRead,
  }) {
    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          Container(
            margin: const EdgeInsets.symmetric(vertical: 4.0),
            padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 10.0),
            decoration: BoxDecoration(
              color: isMine ? _MsgDark.sentBubble : const Color(0xFF2C2C2E),
              borderRadius: BorderRadius.circular(16.0),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.insert_drive_file_rounded, color: Colors.white, size: 28.0),
                const SizedBox(width: 10.0),
                Flexible(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        fileName,
                        style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14.0),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      if (fileSize.isNotEmpty)
                        Text(
                          fileSize,
                          style: GoogleFonts.inter(color: Colors.white70, fontSize: 11.0),
                        ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(left: 4.0, right: 4.0, bottom: 4.0),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  DateFormat('h:mm a').format(time),
                  style: GoogleFonts.inter(fontSize: 10.0, color: _MsgDark.textMuted),
                ),
                if (isMine) ...[
                  const SizedBox(width: 4.0),
                  _buildReadStatusIcon(isRead),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  // Rich Google Maps Card Widget
  Widget _buildLocationBubble({
    required String text,
    required double lat,
    required double lng,
    required bool isMine,
    required DateTime time,
    required bool isRead,
  }) {
    final mapsUrl = 'https://maps.google.com/?q=$lat,$lng';
    String addressStr = text.replaceFirst('📍 ទីតាំងបច្ចុប្បន្ន៖\n', '').trim();
    if (addressStr.startsWith('http') || addressStr.isEmpty) {
      addressStr = 'រាជធានីភ្នំពេញ, ប្រទេសកម្ពុជា ($lat, $lng)';
    }

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          GestureDetector(
            onTap: () async {
              final uri = Uri.parse(mapsUrl);
              if (await canLaunchUrl(uri)) {
                await launchUrl(uri, mode: LaunchMode.externalApplication);
              }
            },
            child: Container(
              margin: const EdgeInsets.symmetric(vertical: 4.0),
              width: 250.0,
              decoration: BoxDecoration(
                color: isMine ? _MsgDark.sentBubble : const Color(0xFF2C2C2E),
                borderRadius: BorderRadius.circular(20.0),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.3),
                    blurRadius: 10,
                    offset: const Offset(0, 4),
                  ),
                ],
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    height: 95.0,
                    decoration: const BoxDecoration(
                      color: Color(0xFF1E293B),
                      borderRadius: BorderRadius.vertical(top: Radius.circular(20.0)),
                    ),
                    child: Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Container(
                            padding: const EdgeInsets.all(8),
                            decoration: const BoxDecoration(
                              color: Colors.white,
                              shape: BoxShape.circle,
                            ),
                            child: const Icon(Icons.location_on_rounded, color: Colors.redAccent, size: 28.0),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            'Google Maps Location',
                            style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12),
                          ),
                        ],
                      ),
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.all(12.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '📍 ទីតាំងបច្ចុប្បន្ន',
                          style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13.5),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          addressStr,
                          style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.0),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 10),
                        Row(
                          children: [
                            Text(
                              'បើកមើលក្នុង Google Maps',
                              style: GoogleFonts.kantumruyPro(color: isMine ? Colors.white : Colors.tealAccent, fontWeight: FontWeight.bold, fontSize: 12.5),
                            ),
                            const SizedBox(width: 4),
                            Icon(Icons.arrow_forward_rounded, size: 14, color: isMine ? Colors.white : Colors.tealAccent),
                          ],
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(left: 4.0, right: 4.0, bottom: 4.0),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  DateFormat('h:mm a').format(time),
                  style: GoogleFonts.inter(fontSize: 10.0, color: _MsgDark.textMuted),
                ),
                if (isMine) ...[
                  const SizedBox(width: 4.0),
                  _buildReadStatusIcon(isRead),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  // Interactive Call Dialog with Timer, Mute & Speaker
  void _showCallDialog(bool isVideo) {
    int callSeconds = 0;
    bool isMuted = false;
    bool isSpeaker = false;

    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) {
        Timer? callTimer;
        return StatefulBuilder(
          builder: (context, setStateCall) {
            callTimer ??= Timer.periodic(const Duration(seconds: 1), (timer) {
              if (ctx.mounted) {
                setStateCall(() => callSeconds++);
              } else {
                timer.cancel();
              }
            });

            return AlertDialog(
              backgroundColor: const Color(0xFF242526),
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  CircleAvatar(
                    radius: 40,
                    backgroundImage: widget.targetUserPhoto.isNotEmpty
                        ? NetworkImage(ApiService.getFullImageUrl(widget.targetUserPhoto))
                        : null,
                    backgroundColor: _getAvatarBgColor(widget.targetUserName),
                    child: widget.targetUserPhoto.isEmpty
                        ? Text(widget.targetUserName[0].toUpperCase(), style: GoogleFonts.inter(fontSize: 28, color: Colors.white, fontWeight: FontWeight.bold))
                        : null,
                  ),
                  const SizedBox(height: 16),
                  Text(widget.targetUserName, style: GoogleFonts.kantumruyPro(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.white)),
                  const SizedBox(height: 6),
                  Text(
                    isVideo ? 'កំពុងការហៅវីដេអូ (${_formatDuration(callSeconds)})' : 'កំពុងការហៅសំឡេង (${_formatDuration(callSeconds)})',
                    style: GoogleFonts.kantumruyPro(fontSize: 13, color: _MsgDark.textMuted),
                  ),
                  const SizedBox(height: 24),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      IconButton(
                        icon: Icon(isMuted ? Icons.mic_off_rounded : Icons.mic_rounded, color: isMuted ? Colors.redAccent : Colors.white, size: 28),
                        onPressed: () => setStateCall(() => isMuted = !isMuted),
                      ),
                      FloatingActionButton(
                        backgroundColor: Colors.redAccent,
                        elevation: 0,
                        onPressed: () => Navigator.pop(ctx),
                        child: const Icon(Icons.call_end_rounded, color: Colors.white),
                      ),
                      IconButton(
                        icon: Icon(isSpeaker ? Icons.volume_up_rounded : Icons.volume_down_rounded, color: isSpeaker ? _MsgDark.iconColor : Colors.white, size: 28),
                        onPressed: () => setStateCall(() => isSpeaker = !isSpeaker),
                      ),
                    ],
                  )
                ],
              ),
            );
          },
        );
      },
    );
  }

  // Pick and Send Image
  Future<void> _pickAndSendImage(ImageSource source) async {
    try {
      final XFile? file = await ImagePicker().pickImage(source: source, imageQuality: 70);
      if (file == null || currentUserId.isEmpty) return;
      final bytes = await file.readAsBytes();
      if (bytes.isEmpty) return;

      if (!mounted) return;
      final base64Image = 'data:image/jpeg;base64,${base64Encode(bytes)}';
      final userProvider = Provider.of<UserProvider>(context, listen: false);

      final msgData = {
        'text': '',
        'imageUrl': base64Image,
        'type': 'image',
        'senderId': currentUserId,
        'senderName': userProvider.name ?? '',
        'senderPhoto': userProvider.avatar ?? '',
        'timestamp': FieldValue.serverTimestamp(),
        'isRead': false,
      };

      final batch = _firestore.batch();
      final msgRef = _firestore.collection('chats').doc(_roomId).collection('messages').doc();
      batch.set(msgRef, msgData);
      batch.set(_firestore.collection('chats').doc(_roomId), {
        'participants': [currentUserId, widget.targetUserId],
        'lastMessage': '📷 បានផ្ញើរូបភាព',
        'lastTimestamp': FieldValue.serverTimestamp(),
        'lastSenderId': currentUserId,
        'isRead': false,
      }, SetOptions(merge: true));
      await batch.commit();
    } catch (e) {
      debugPrint('Pick image error: $e');
    }
  }

  // Send Thumbs Up
  Future<void> _sendThumbsUp() async {
    if (currentUserId.isEmpty) return;
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final msgData = {
      'text': '👍',
      'type': 'sticker',
      'senderId': currentUserId,
      'senderName': userProvider.name ?? '',
      'senderPhoto': userProvider.avatar ?? '',
      'timestamp': FieldValue.serverTimestamp(),
      'isRead': false,
    };

    final batch = _firestore.batch();
    final msgRef = _firestore.collection('chats').doc(_roomId).collection('messages').doc();
    batch.set(msgRef, msgData);
    batch.set(_firestore.collection('chats').doc(_roomId), {
      'participants': [currentUserId, widget.targetUserId],
      'lastMessage': '👍',
      'lastTimestamp': FieldValue.serverTimestamp(),
      'lastSenderId': currentUserId,
      'isRead': false,
    }, SetOptions(merge: true));
    await batch.commit();
  }

  // Voice Recording Functions
  Future<void> _startRecording() async {
    try {
      if (await _audioRecorder.hasPermission()) {
        final dir = await getTemporaryDirectory();
        final path = '${dir.path}/voice_${DateTime.now().millisecondsSinceEpoch}.m4a';
        await _audioRecorder.start(
          path: path,
          encoder: record_pkg.AudioEncoder.aacLc,
        );
        _setRecordingVoiceState(true);
        setState(() {
          _isRecording = true;
          _recordingSeconds = 0;
        });
        _recordingTimer?.cancel();
        _recordingTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
          if (mounted) {
            setState(() => _recordingSeconds++);
          }
        });
      }
    } catch (e) {
      debugPrint('Start recording error: $e');
    }
  }

  Future<void> _stopAndSendRecording() async {
    try {
      _recordingTimer?.cancel();
      _setRecordingVoiceState(false);
      final path = await _audioRecorder.stop();
      final duration = _recordingSeconds;
      setState(() {
        _isRecording = false;
        _recordingSeconds = 0;
      });

      if (path != null && path.isNotEmpty) {
        final file = File(path);
        if (await file.exists()) {
          final bytes = await file.readAsBytes();
          if (bytes.isNotEmpty && currentUserId.isNotEmpty) {
            final base64Audio = 'data:audio/mp4;base64,${base64Encode(bytes)}';
            if (!mounted) return;
            final userProvider = Provider.of<UserProvider>(context, listen: false);

            final msgData = {
              'text': '',
              'base64Audio': base64Audio,
              'audioDuration': duration > 0 ? duration : 1,
              'type': 'voice',
              'senderId': currentUserId,
              'senderName': userProvider.name ?? '',
              'senderPhoto': userProvider.avatar ?? '',
              'timestamp': FieldValue.serverTimestamp(),
              'isRead': false,
            };

            final batch = _firestore.batch();
            final msgRef = _firestore.collection('chats').doc(_roomId).collection('messages').doc();
            batch.set(msgRef, msgData);
            batch.set(_firestore.collection('chats').doc(_roomId), {
              'participants': [currentUserId, widget.targetUserId],
              'lastMessage': '🎙️ សារសំឡេង (${_formatDuration(duration)})',
              'lastTimestamp': FieldValue.serverTimestamp(),
              'lastSenderId': currentUserId,
              'isRead': false,
            }, SetOptions(merge: true));
            await batch.commit();
          }
        }
      }
    } catch (e) {
      debugPrint('Stop recording error: $e');
    }
  }

  Future<void> _cancelRecording() async {
    try {
      _recordingTimer?.cancel();
      _setRecordingVoiceState(false);
      await _audioRecorder.stop();
      setState(() {
        _isRecording = false;
        _recordingSeconds = 0;
      });
    } catch (e) {
      debugPrint('Cancel recording error: $e');
    }
  }

  Widget _buildReplyPreviewBanner() {
    return Container(
      color: const Color(0xFF2C2C2E),
      padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Text(
              'កំពុងឆ្លើយតបទៅកាន់៖ $_replyingToMessage',
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 12.5),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          IconButton(
            icon: const Icon(Icons.close_rounded, color: Colors.white70, size: 18),
            onPressed: () => setState(() => _replyingToMessage = null),
          ),
        ],
      ),
    );
  }

  // Plus Menu Actions (Share a file & Location)
  Widget _buildPlusMenuOverlay() {
    return Align(
      alignment: Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.only(left: 12.0, bottom: 8.0),
        width: 210.0,
        decoration: BoxDecoration(
          color: const Color(0xFF2C2C2E),
          borderRadius: BorderRadius.circular(16.0),
          boxShadow: const [
            BoxShadow(color: Colors.black54, blurRadius: 12, offset: Offset(0, 4)),
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            _buildPlusMenuItem(
              title: 'Share a file',
              icon: Icons.insert_drive_file_rounded,
              onTap: _pickAndSendFile,
            ),
            const Divider(height: 1.0, color: Color(0xFF38383A)),
            _buildPlusMenuItem(
              title: 'Location',
              icon: Icons.near_me_rounded,
              onTap: _sendLocation,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPlusMenuItem({
    required String title,
    required IconData icon,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16.0),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 14.0),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              title,
              style: GoogleFonts.inter(
                color: Colors.white,
                fontSize: 15.0,
                fontWeight: FontWeight.w500,
              ),
            ),
            Icon(icon, color: Colors.white70, size: 20.0),
          ],
        ),
      ),
    );
  }

  Future<void> _pickAndSendFile() async {
    setState(() => _showPlusMenu = false);
    try {
      final result = await FilePicker.platform.pickFiles();
      if (result == null || result.files.isEmpty || currentUserId.isEmpty) return;

      final platformFile = result.files.first;
      final fileName = platformFile.name;
      final fileSize = '${(platformFile.size / 1024).toStringAsFixed(1)} KB';

      String fileBase64 = '';
      if (platformFile.bytes != null) {
        fileBase64 = 'data:application/octet-stream;base64,${base64Encode(platformFile.bytes!)}';
      } else if (platformFile.path != null) {
        final file = File(platformFile.path!);
        if (await file.exists()) {
          final bytes = await file.readAsBytes();
          fileBase64 = 'data:application/octet-stream;base64,${base64Encode(bytes)}';
        }
      }

      if (!mounted) return;
      final userProvider = Provider.of<UserProvider>(context, listen: false);

      final msgData = {
        'text': '📄 ឯកសារ៖ $fileName ($fileSize)',
        'fileName': fileName,
        'fileSize': fileSize,
        'base64File': fileBase64,
        'type': 'file',
        'senderId': currentUserId,
        'senderName': userProvider.name ?? '',
        'senderPhoto': userProvider.avatar ?? '',
        'timestamp': FieldValue.serverTimestamp(),
        'isRead': false,
      };

      final batch = _firestore.batch();
      final msgRef = _firestore.collection('chats').doc(_roomId).collection('messages').doc();
      batch.set(msgRef, msgData);
      batch.set(_firestore.collection('chats').doc(_roomId), {
        'participants': [currentUserId, widget.targetUserId],
        'lastMessage': '📄 ឯកសារ៖ $fileName',
        'lastTimestamp': FieldValue.serverTimestamp(),
        'lastSenderId': currentUserId,
        'isRead': false,
      }, SetOptions(merge: true));
      await batch.commit();
    } catch (e) {
      debugPrint('Pick file error: $e');
    }
  }

  Future<void> _sendLocation() async {
    setState(() => _showPlusMenu = false);
    try {
      LocationPermission permission = await Geolocator.checkPermission();
      if (permission == LocationPermission.denied) {
        permission = await Geolocator.requestPermission();
      }

      if (permission == LocationPermission.whileInUse || permission == LocationPermission.always) {
        final pos = await Geolocator.getCurrentPosition(
          locationSettings: const LocationSettings(accuracy: LocationAccuracy.high),
        );
        final mapsUrl = 'https://maps.google.com/?q=${pos.latitude},${pos.longitude}';

        if (!mounted) return;
        final userProvider = Provider.of<UserProvider>(context, listen: false);

        final msgData = {
          'text': '📍 ទីតាំងបច្ចុប្បន្ន៖\n$mapsUrl',
          'latitude': pos.latitude,
          'longitude': pos.longitude,
          'type': 'location',
          'senderId': currentUserId,
          'senderName': userProvider.name ?? '',
          'senderPhoto': userProvider.avatar ?? '',
          'timestamp': FieldValue.serverTimestamp(),
          'isRead': false,
        };

        final batch = _firestore.batch();
        final msgRef = _firestore.collection('chats').doc(_roomId).collection('messages').doc();
        batch.set(msgRef, msgData);
        batch.set(_firestore.collection('chats').doc(_roomId), {
          'participants': [currentUserId, widget.targetUserId],
          'lastMessage': '📍 បានផ្ញើទីតាំង (Location)',
          'lastTimestamp': FieldValue.serverTimestamp(),
          'lastSenderId': currentUserId,
          'isRead': false,
        }, SetOptions(merge: true));
        await batch.commit();
      } else {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('សូមអនុញ្ញាតសិទ្ធិមើលទីតាំង (Location Permission)', style: GoogleFonts.kantumruyPro())),
          );
        }
      }
    } catch (e) {
      debugPrint('Location error: $e');
    }
  }

  // ==========================================
  // C. BOTTOM INPUT TOOLBAR (Translucent Messenger Style)
  // ==========================================
  Widget _buildInputToolbar() {
    if (_isRecording) {
      return ClipRect(
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 16, sigmaY: 16),
          child: Container(
            color: Colors.black.withValues(alpha: 0.20),
            padding: const EdgeInsets.fromLTRB(12.0, 8.0, 12.0, 12.0),
            child: Container(
              height: 48.0,
              decoration: BoxDecoration(
                color: const Color(0xFF2C2C2E),
                borderRadius: BorderRadius.circular(24.0),
              ),
              padding: const EdgeInsets.symmetric(horizontal: 10.0),
              child: Row(
                children: [
                  IconButton(
                    icon: const Icon(Icons.delete_outline_rounded, color: Colors.white70, size: 24),
                    onPressed: _cancelRecording,
                  ),
                  const SizedBox(width: 4.0),
                  Container(
                    width: 32.0,
                    height: 32.0,
                    decoration: const BoxDecoration(
                      color: Colors.redAccent,
                      shape: BoxShape.circle,
                    ),
                    child: const Icon(Icons.mic_rounded, color: Colors.white, size: 18),
                  ),
                  const SizedBox(width: 10.0),
                  Expanded(
                    child: Row(
                      children: List.generate(22, (i) {
                        final heights = [10.0, 18.0, 8.0, 24.0, 14.0, 20.0, 12.0, 16.0, 26.0, 10.0, 18.0, 12.0];
                        final h = heights[(i + _recordingSeconds) % heights.length];
                        return Container(
                          width: 3.0,
                          height: h,
                          margin: const EdgeInsets.symmetric(horizontal: 1.5),
                          decoration: BoxDecoration(
                            color: const Color(0xFF0084FF),
                            borderRadius: BorderRadius.circular(2.0),
                          ),
                        );
                      }),
                    ),
                  ),
                  const SizedBox(width: 8.0),
                  Text(
                    _formatDuration(_recordingSeconds),
                    style: GoogleFonts.inter(color: Colors.white, fontSize: 13.0, fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(width: 10.0),
                  GestureDetector(
                    onTap: _stopAndSendRecording,
                    child: Container(
                      width: 36.0,
                      height: 36.0,
                      decoration: const BoxDecoration(
                        color: Color(0xFF0084FF),
                        shape: BoxShape.circle,
                      ),
                      child: const Icon(Icons.send_rounded, color: Colors.white, size: 18),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      );
    }

    return ClipRect(
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 16, sigmaY: 16),
        child: Container(
          color: Colors.black.withValues(alpha: 0.20),
          padding: const EdgeInsets.fromLTRB(8.0, 8.0, 8.0, 12.0),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              _buildToolbarIcon(
                _showPlusMenu ? Icons.cancel_rounded : Icons.add_circle_rounded,
                onTap: () {
                  setState(() => _showPlusMenu = !_showPlusMenu);
                },
              ),
              _buildToolbarIcon(Icons.camera_alt_rounded, onTap: () {
                _pickAndSendImage(ImageSource.camera);
              }),
              _buildToolbarIcon(Icons.photo_rounded, onTap: () {
                _pickAndSendImage(ImageSource.gallery);
              }),
              _buildToolbarIcon(Icons.mic_rounded, onTap: _startRecording),
              const SizedBox(width: 4.0),

              // Text input field with translucent pill shape
              Expanded(
                child: Container(
                  constraints: const BoxConstraints(minHeight: 38.0, maxHeight: 120.0),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.20),
                    borderRadius: BorderRadius.circular(22.0),
                  ),
                  padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 2.0),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.center,
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _msgController,
                          maxLines: null,
                          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 15.0),
                          cursorColor: Colors.white,
                          decoration: InputDecoration(
                            hintText: 'Aa',
                            hintStyle: GoogleFonts.inter(color: Colors.white70, fontSize: 15.0),
                            border: InputBorder.none,
                            enabledBorder: InputBorder.none,
                            focusedBorder: InputBorder.none,
                            filled: false,
                            isDense: true,
                            contentPadding: const EdgeInsets.symmetric(vertical: 8.0),
                          ),
                          onSubmitted: (_) => _sendMessage(),
                        ),
                      ),
                      const Icon(Icons.sentiment_satisfied_alt_rounded, color: Colors.white70, size: 22.0),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 6.0),

              // Send / Thumbs up button
              ValueListenableBuilder<TextEditingValue>(
                valueListenable: _msgController,
                builder: (context, value, _) {
                  final hasText = value.text.trim().isNotEmpty;
                  return GestureDetector(
                    onTap: hasText ? _sendMessage : _sendThumbsUp,
                    child: Padding(
                      padding: const EdgeInsets.only(left: 2.0),
                      child: Icon(
                        hasText ? Icons.send_rounded : Icons.thumb_up_alt_rounded,
                        color: Colors.white,
                        size: 28.0,
                      ),
                    ),
                  );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildToolbarIcon(IconData icon, {VoidCallback? onTap}) {
    return IconButton(
      icon: Icon(icon, color: Colors.white, size: 26.0),
      onPressed: onTap ?? () {},
      padding: const EdgeInsets.symmetric(horizontal: 4.0),
      constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
    );
  }
}
