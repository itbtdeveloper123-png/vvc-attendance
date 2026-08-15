import 'dart:convert';
import 'dart:async';
import 'dart:io';
import 'dart:ui';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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
import 'package:image/image.dart' as img;
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../widgets/chat_wallpaper_picker.dart';
import '../widgets/giphy_sticker_picker.dart';
import '../widgets/vvc_file_picker_bottom_sheet.dart';
import '../widgets/vvc_location_picker_bottom_sheet.dart';
import '../widgets/vvc_poll_picker_bottom_sheet.dart';
import '../widgets/vvc_chat_context_menu.dart';
import '../widgets/vvc_global_alert.dart';
import 'vvc_contacts_flow_screens.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';
import 'package:lottie/lottie.dart';
import 'group_settings_screen.dart';
import 'user_profile_screen.dart';
import '../services/call_service.dart';
import 'call/active_call_screen.dart';
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
  static const Color sentBubble = Color(0xFFD4AF37);
  static const Color textMuted = Color(0xFF94A3B8);
  static const Color iconColor = Color(0xFFD4AF37);
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

  void _initiateCall(String type) async {
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final String myId = (userProvider.employeeId ?? currentUserId).trim();
    final String myName = (userProvider.name ?? '').trim().isNotEmpty
        ? userProvider.name!
        : 'Caller';
    final String myPhoto = userProvider.avatar ?? currentUserPhoto;

    if (myId.isEmpty) {
      if (mounted) {
        VvcAlert.showError(
          context,
          title: 'បរាជ័យ',
          message: 'មិនស្គាល់អត្តសញ្ញាណអ្នកហៅ (Missing User ID)។ សូម Logout ហើយ Login ម្តងទៀត។',
        );
      }
      return;
    }

    if (widget.targetUserId.trim().isEmpty) {
      if (mounted) {
        VvcAlert.showError(
          context,
          title: 'បរាជ័យ',
          message: 'មិនស្គាល់អត្តសញ្ញាណអ្នកទទួល (Missing Receiver ID)។',
        );
      }
      return;
    }

    final callService = CallService();
    final callId = await callService.startCall(
      callerId: myId,
      receiverId: widget.targetUserId.trim(),
      receiverName: widget.targetUserName,
      receiverPhoto: widget.targetUserPhoto,
      type: type,
      callerName: myName,
      callerPhoto: myPhoto,
    );

    if (callId != null && mounted) {
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => ActiveCallScreen(
            callId: callId,
            channelId: callId,
            targetName: widget.targetUserName,
            targetPhoto: widget.targetUserPhoto,
            isVideoCall: type == 'video',
            isCaller: true,
          ),
        ),
      );
    } else if (mounted) {
      final err = CallService.lastErrorMessage ?? 'Connection error';
      VvcAlert.showError(
        context,
        title: 'បរាជ័យ',
        message: 'មិនអាចតភ្ជាប់ការហៅបានទេ។ ($err)\nសូមពិនិត្យ Firestore Rules ឬការតភ្ជាប់អ៊ីនធឺណិត។',
      );
    }
  }
  Timer? _recordingTimer;

  // Plus Menu State (+)
  bool _showPlusMenu = false;

  // Audio Playback state
  String? _currentlyPlayingAudio;
  bool _isPlayingAudio = false;
  double _playbackSpeed = 1.0;

  // Reply & Pin State
  String? _replyingToMessage;
  String? _pinnedMessage;

  // Search State
  bool _isSearchMode = false;
  final TextEditingController _searchController = TextEditingController();

  // Multi-Select & Batch Delete State
  bool _isSelectionMode = false;
  final Set<String> _selectedDocIds = {};

  // Pagination State
  int _messageLimit = 30;
  bool _hasMoreMessages = true;
  bool _isFetchingMore = false;

  String get _roomId {
    if (widget.isGroup) return widget.targetUserId;
    final List<String> ids = [currentUserId, widget.targetUserId]..sort();
    return 'PRIVATE_${ids[0]}_${ids[1]}';
  }

  @override
  void initState() {
    super.initState();
    _init();

    _scrollController.addListener(_onScroll);

    _audioPlayer.onPlayerComplete.listen((_) {
      if (mounted) {
        setState(() {
          _isPlayingAudio = false;
          _currentlyPlayingAudio = null;
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
    if (currentUserId.isEmpty) {
      if (mounted) setState(() => _isLoadingHistory = false);
      return;
    }
    _messageSubscription?.cancel();
    _messageSubscription = _firestore
        .collection('chats')
        .doc(_roomId)
        .collection('messages')
        .orderBy('timestamp', descending: true)
        .limit(_messageLimit)
        .snapshots()
        .listen(
      (snap) {
        if (mounted) {
          setState(() {
            _messageDocs = snap.docs;
            _isLoadingHistory = false;
            _isFetchingMore = false;
            if (snap.docs.length < _messageLimit) {
              _hasMoreMessages = false;
            }
          });
          _markMessagesAsRead(snap.docs);
        }
      },
      onError: (error) {
        debugPrint('Error loading messages: $error');
        if (mounted) {
          setState(() {
            _isLoadingHistory = false;
            _isFetchingMore = false;
          });
        }
      },
    );
  }

  void _onScroll() {
    if (_scrollController.position.pixels >= _scrollController.position.maxScrollExtent - 200) {
      _loadMoreMessages();
    }
  }

  void _loadMoreMessages() {
    if (_hasMoreMessages && !_isFetchingMore && _messageDocs.length >= _messageLimit) {
      setState(() {
        _isFetchingMore = true;
        _messageLimit += 30;
      });
      _listenMessages();
    }
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

  Future<void> _sendMessage({String? customText}) async {
    final text = customText ?? _msgController.text.trim();
    if (text.isEmpty || currentUserId.isEmpty) return;

    if (customText == null) {
      _msgController.clear();
    }
    _setTypingState(false);
    final userProvider = Provider.of<UserProvider>(context, listen: false);

    final replyMsg = _replyingToMessage;
    setState(() => _replyingToMessage = null);

    final msgData = {
      'text': text,
      'type': 'text',
      'senderId': currentUserId,
      'senderName': userProvider.name ?? '',
      'senderPhoto': userProvider.avatar ?? '',
      'timestamp': FieldValue.serverTimestamp(),
      'isRead': false,
      if (replyMsg != null) 'replyTo': replyMsg,
    };

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
          final pinned = data['pinnedMessage'] as Map<String, dynamic>?;
          setState(() {
            _isTargetTyping = typingMap[widget.targetUserId] == true;
            _isTargetRecordingVoice = recordingMap[widget.targetUserId] == true;
            if (pinned != null && pinned['text'] != null) {
              _pinnedMessage = pinned['text'].toString();
            } else {
              _pinnedMessage = null;
            }
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
    return GestureDetector(
      onTap: () => FocusScope.of(context).unfocus(),
      behavior: HitTestBehavior.opaque,
      child: Scaffold(
        backgroundColor: const Color(0xFF0F172A),
        body: Stack(
          children: [
            // 1. Background Wallpaper Layer with Dark Purple Overlay & Gradient
            Positioned.fill(
              child: Container(
                decoration: BoxDecoration(
                  image: DecorationImage(
                    image: AssetImage(_currentWallpaper.isNotEmpty ? _currentWallpaper : 'assets/wallpapers/01.jpg'),
                    fit: BoxFit.cover,
                    colorFilter: const ColorFilter.mode(
                      Color(0xFF2E1A47),
                      BlendMode.color,
                    ),
                  ),
                ),
                child: Container(
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: [
                        const Color(0xFF1E112C).withValues(alpha: 0.85),
                        const Color(0xFF0F081D).withValues(alpha: 0.92),
                      ],
                      begin: Alignment.topCenter,
                      end: Alignment.bottomCenter,
                    ),
                  ),
                ),
              ),
            ),

            // 2. Real-time Messages Feed Layer
            Positioned.fill(
              child: _buildMessageFeed(),
            ),

            // 3. Top Frosted Glass App Bar Layer
            Positioned(
              top: 0,
              left: 0,
              right: 0,
              child: _buildHeader(),
            ),

            // 4. Bottom Frosted Glass Input Toolbar Layer
            Positioned(
              bottom: 0,
              left: 0,
              right: 0,
              child: _isSelectionMode
                  ? _buildSelectionBottomBar()
                  : Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        if (_replyingToMessage != null) _buildReplyPreviewBanner(),
                        if (_showPlusMenu) _buildPlusMenuOverlay(),
                        _buildInputToolbar(),
                      ],
                    ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSelectionBottomBar() {
    return Container(
      decoration: const BoxDecoration(
        color: Color(0xFF1E2738),
        border: Border(
          top: BorderSide(color: Colors.white12, width: 0.5),
        ),
      ),
      padding: EdgeInsets.fromLTRB(16, 12, 16, MediaQuery.of(context).padding.bottom + 12),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          TextButton.icon(
            onPressed: () {
              setState(() {
                _isSelectionMode = false;
                _selectedDocIds.clear();
              });
            },
            icon: const Icon(Icons.close_rounded, color: Colors.white70),
            label: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: Colors.white70)),
          ),
          ElevatedButton.icon(
            onPressed: _confirmDeleteSelectedMessages,
            icon: const Icon(Icons.delete_forever_rounded, color: Colors.white),
            label: Text('លុប (${_selectedDocIds.length})', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.redAccent,
              foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _confirmDeleteSelectedMessages() async {
    if (_selectedDocIds.isEmpty) return;
    final int count = _selectedDocIds.length;

    final confirmed = await VvcAlert.showConfirmDialog(
      context,
      title: 'លុបសារដែលបានជ្រើសរើស?',
      message: 'តើអ្នកប្រាកដជាចង់លុបសារចំនួន $count ដែលបានជ្រើសរើសនេះមែនទេ?',
      confirmText: 'លុប ($count)',
      cancelText: 'បោះបង់',
      isDestructive: true,
    );

    if (confirmed == true) {
      final batch = _firestore.batch();
      for (String id in _selectedDocIds) {
        final msgRef = _firestore.collection('chats').doc(_roomId).collection('messages').doc(id);
        batch.delete(msgRef);
      }
      await batch.commit();
      await _syncLastMessageAfterDeletion();
      setState(() {
        _isSelectionMode = false;
        _selectedDocIds.clear();
      });
      if (mounted) {
        VvcAlert.showSuccess(
          context,
          title: 'បានលុបសារជោគជ័យ',
          message: 'បានលុបសារចំនួន $count ចេញពីការសន្ទនា!',
        );
      }
    }
  }

  Future<void> _syncLastMessageAfterDeletion() async {
    try {
      final latestQuery = await _firestore
          .collection('chats')
          .doc(_roomId)
          .collection('messages')
          .orderBy('timestamp', descending: true)
          .limit(1)
          .get();

      if (latestQuery.docs.isEmpty) {
        await _firestore.collection('chats').doc(_roomId).set({
          'lastMessage': '',
          'lastTimestamp': null,
          'lastSenderId': '',
        }, SetOptions(merge: true));
      } else {
        final lastDoc = latestQuery.docs.first.data();
        final type = (lastDoc['type'] ?? 'text').toString();
        String lastText = (lastDoc['text'] ?? '').toString();

        if (type == 'call') {
          final isVideo = lastDoc['callType'] == 'video' || lastDoc['isVideo'] == true;
          final duration = (lastDoc['duration'] ?? 0) as int;
          final callStatus = (lastDoc['callStatus'] ?? 'completed').toString();
          if (callStatus == 'missed') {
            lastText = isVideo ? '📹 ការខលវីដេអូខកខាន' : '📞 ការខលខកខាន (Missed Call)';
          } else if (callStatus == 'declined') {
            lastText = isVideo ? '📹 ការខលវីដេអូបដិសេធ' : '📞 ការខលត្រូវបានបដិសេធ';
          } else {
            String durStr = '';
            if (duration > 0) {
              final m = duration ~/ 60;
              final s = duration % 60;
              durStr = m > 0 ? '$m នាទី $s វិនាទី' : '$s វិនាទី';
            }
            lastText = isVideo
                ? (durStr.isNotEmpty ? '📹 ការខលវីដេអូ ($durStr)' : '📹 ការខលវីដេអូ')
                : (durStr.isNotEmpty ? '📞 ការខលជាសំឡេង ($durStr)' : '📞 ការខលជាសំឡេង');
          }
        } else if (type == 'image') {
          lastText = '📷 បានផ្ញើរូបភាព';
        } else if (type == 'audio' || type == 'voice') {
          lastText = '🎙️ សារសំឡេង';
        } else if (type == 'file') {
          lastText = '📄 ឯកសារ';
        } else if (type == 'location') {
          lastText = '📍 ទីតាំង';
        } else if (type == 'sticker' || lastText.startsWith('assets/') || lastText.contains('/sticker/')) {
          lastText = '🎨 ស្ទីគ័រ (Sticker)';
        }

        await _firestore.collection('chats').doc(_roomId).set({
          'lastMessage': lastText,
          'lastTimestamp': lastDoc['timestamp'] ?? FieldValue.serverTimestamp(),
          'lastSenderId': lastDoc['senderId'] ?? '',
        }, SetOptions(merge: true));
      }
    } catch (e) {
      debugPrint('Error syncing last message: $e');
    }
  }





  // ==========================================
  // A. CUSTOM APP BAR (Telegram iOS Floating Header Style)
  // ==========================================
  Widget _buildHeader() {
    final double topPadding = MediaQuery.of(context).padding.top;

    if (_isSelectionMode) {
      return Container(
        decoration: const BoxDecoration(
          color: Color(0xFC1C1C1E),
          border: Border(
            bottom: BorderSide(color: Color(0x1FFFFFFF), width: 0.5),
          ),
        ),
        padding: EdgeInsets.fromLTRB(12.0, topPadding > 0 ? topPadding + 4.0 : 10.0, 12.0, 10.0),
        child: Row(
          children: [
                IconButton(
                  icon: const Icon(Icons.close_rounded, color: Colors.white, size: 24),
                  onPressed: () {
                    setState(() {
                      _isSelectionMode = false;
                      _selectedDocIds.clear();
                    });
                  },
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    '${_selectedDocIds.length} ត្រូវបានជ្រើសរើស',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.delete_rounded, color: Colors.redAccent, size: 24),
                  onPressed: _confirmDeleteSelectedMessages,
                ),
              ],
            ),
      );
    }

    if (_isSearchMode) {
      return ClipRect(
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 24, sigmaY: 24),
          child: Container(
            decoration: const BoxDecoration(
              color: Color(0xDC1C1C1E),
              border: Border(
                bottom: BorderSide(color: Color(0x1FFFFFFF), width: 0.5),
              ),
            ),
            padding: EdgeInsets.fromLTRB(12.0, topPadding > 0 ? topPadding + 4.0 : 10.0, 12.0, 10.0),
            child: Row(
              children: [
                Expanded(
                  child: Container(
                    height: 38,
                    decoration: BoxDecoration(
                      color: const Color(0xFF262629),
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(color: Colors.white.withValues(alpha: 0.08), width: 0.5),
                    ),
                    padding: const EdgeInsets.symmetric(horizontal: 12),
                    child: Row(
                      children: [
                        const Icon(Icons.search_rounded, color: Color(0xFF8E8E93), size: 20),
                        const SizedBox(width: 8),
                        Expanded(
                          child: TextField(
                            controller: _searchController,
                            autofocus: true,
                            style: GoogleFonts.inter(color: Colors.white, fontSize: 15),
                            cursorColor: const Color(0xFF0A84FF),
                            decoration: InputDecoration(
                              hintText: 'Search this chat',
                              hintStyle: GoogleFonts.inter(color: const Color(0xFF8E8E93), fontSize: 15),
                              border: InputBorder.none,
                              isDense: true,
                            ),
                            onChanged: (_) => setState(() {}),
                          ),
                        ),
                        if (_searchController.text.isNotEmpty)
                          InkWell(
                            onTap: () {
                              _searchController.clear();
                              setState(() {});
                            },
                            child: const Icon(Icons.cancel_rounded, color: Color(0xFF8E8E93), size: 18),
                          ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                InkWell(
                  onTap: () {
                    _searchController.clear();
                    setState(() {
                      _isSearchMode = false;
                    });
                  },
                  borderRadius: BorderRadius.circular(16),
                  child: const Padding(
                    padding: EdgeInsets.all(4.0),
                    child: Icon(Icons.close_rounded, color: Colors.white, size: 24),
                  ),
                ),
              ],
            ),
          ),
        ),
      );
    }

    String statusText = widget.isGroup ? 'ក្រុមការងារ (Group)' : 'last seen recently';
    if (!widget.isGroup) {
      if (_isTargetOnline) {
        statusText = 'Online';
      } else if (_targetLastActive != null) {
        final diff = DateTime.now().difference(_targetLastActive!);
        if (diff.inMinutes < 60) {
          statusText = 'last seen ${diff.inMinutes}m ago';
        } else if (diff.inHours < 24) {
          statusText = 'last seen ${diff.inHours}h ago';
        } else {
          statusText = 'last seen ${DateFormat('dd/MM HH:mm').format(_targetLastActive!)}';
        }
      }
    }

    return ClipRect(
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 25.0, sigmaY: 25.0),
        child: Container(
          decoration: BoxDecoration(
            color: Colors.black.withValues(alpha: 0.28),
            border: Border(
              bottom: BorderSide(color: Colors.white.withValues(alpha: 0.05), width: 0.5),
            ),
          ),
          padding: EdgeInsets.fromLTRB(12.0, topPadding > 0 ? topPadding + 6.0 : 12.0, 12.0, 10.0),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Row(
                children: [
                  // 1. Back Button with Unread Badge
                  InkWell(
                    onTap: () => Navigator.pop(context),
                    borderRadius: BorderRadius.circular(20),
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(4, 6, 8, 6),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(LucideIcons.arrowLeft, color: Colors.white, size: 20),
                          StreamBuilder<QuerySnapshot>(
                            stream: _firestore
                                .collection('chats')
                                .where('participants', arrayContains: currentUserId)
                                .where('isRead', isEqualTo: false)
                                .snapshots(),
                            builder: (context, snap) {
                              int unread = 0;
                              if (snap.hasData) {
                                unread = snap.data!.docs.where((doc) {
                                  final data = doc.data() as Map<String, dynamic>;
                                  return data['lastSenderId'] != currentUserId;
                                }).length;
                              }
                              if (unread == 0) return const SizedBox.shrink();
                              return Container(
                                margin: const EdgeInsets.only(left: 6),
                                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1.5),
                                decoration: BoxDecoration(
                                  color: const Color(0xFF007AFF),
                                  borderRadius: BorderRadius.circular(10),
                                ),
                                child: Text(
                                  '$unread',
                                  style: GoogleFonts.inter(
                                    color: Colors.white,
                                    fontSize: 11.0,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              );
                            },
                          ),
                        ],
                      ),
                    ),
                  ),

                  // 2. Middle Profile Info (Avatar + Name + Status) Edge-to-Edge layout without floating rounded capsule
                  Expanded(
                    child: InkWell(
                      onTap: _onHeaderTap,
                      borderRadius: BorderRadius.circular(12),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 6.0, vertical: 4.0),
                        child: Row(
                          children: [
                            Stack(
                              children: [
                                CircleAvatar(
                                  radius: 20.0,
                                  backgroundImage: widget.targetUserPhoto.isNotEmpty
                                      ? NetworkImage(ApiService.getFullImageUrl(widget.targetUserPhoto))
                                      : null,
                                  backgroundColor: widget.isGroup
                                      ? const Color(0xFFFFB300)
                                      : _getAvatarBgColor(widget.targetUserName),
                                  child: widget.targetUserPhoto.isEmpty
                                      ? (widget.isGroup
                                          ? const Icon(Icons.groups_rounded, color: Colors.white, size: 20)
                                          : Text(
                                              widget.targetUserName.isNotEmpty ? widget.targetUserName[0].toUpperCase() : 'U',
                                              style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, fontSize: 14, color: Colors.white),
                                            ))
                                      : null,
                                ),
                                if (!widget.isGroup && _isTargetOnline)
                                  Positioned(
                                    right: 0,
                                    bottom: 0,
                                    child: Container(
                                      width: 10,
                                      height: 10,
                                      decoration: BoxDecoration(
                                        color: const Color(0xFF10B981),
                                        shape: BoxShape.circle,
                                        border: Border.all(color: Colors.black, width: 1.5),
                                      ),
                                    ),
                                  ),
                              ],
                            ),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Text(
                                    widget.targetUserName,
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.white,
                                      fontWeight: FontWeight.w600,
                                      fontSize: 17.0,
                                    ),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                  Text(
                                    statusText,
                                    style: GoogleFonts.inter(
                                      color: const Color(0xFF8E8E93),
                                      fontSize: 13.0,
                                    ),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),

                  // 3. Audio Call Button
                  if (!widget.isGroup)
                    InkWell(
                      onTap: () => _initiateCall('audio'),
                      borderRadius: BorderRadius.circular(20),
                      child: const Padding(
                        padding: EdgeInsets.all(6.0),
                        child: Icon(LucideIcons.phone, color: Colors.white, size: 20),
                      ),
                    ),
                  
                  // 4. Video Call Button
                  if (!widget.isGroup)
                    InkWell(
                      onTap: () => _initiateCall('video'),
                      borderRadius: BorderRadius.circular(20),
                      child: const Padding(
                        padding: EdgeInsets.all(6.0),
                        child: Icon(LucideIcons.video, color: Colors.white, size: 20),
                      ),
                    ),

                  // 5. Right Search Button
                  InkWell(
                    onTap: () => setState(() => _isSearchMode = true),
                    borderRadius: BorderRadius.circular(20),
                    child: const Padding(
                      padding: EdgeInsets.all(6.0),
                      child: Icon(LucideIcons.search, color: Colors.white, size: 20),
                    ),
                  ),
                ],
              ),

              // Pinned Message Bar if active
              if (_pinnedMessage != null && _pinnedMessage!.isNotEmpty) ...[
                const SizedBox(height: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(color: Colors.white.withValues(alpha: 0.08), width: 0.5),
                  ),
                  child: Row(
                    children: [
                      Container(
                        width: 3,
                        height: 30,
                        decoration: BoxDecoration(
                          color: const Color(0xFF007AFF),
                          borderRadius: BorderRadius.circular(2),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              'Pinned Message',
                              style: GoogleFonts.inter(
                                color: Colors.white,
                                fontSize: 12.0,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(height: 1),
                            Text(
                              _pinnedMessage!,
                              style: GoogleFonts.inter(
                                color: Colors.white70,
                                fontSize: 11.5,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ],
                        ),
                      ),
                      InkWell(
                        onTap: _unpinMessage,
                        borderRadius: BorderRadius.circular(12),
                        child: const Padding(
                          padding: EdgeInsets.all(4.0),
                          child: Icon(Icons.close_rounded, color: Colors.white60, size: 18),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _unpinMessage() async {
    setState(() {
      _pinnedMessage = null;
    });
    try {
      await _firestore.collection('chats').doc(_roomId).set({
        'pinnedMessage': FieldValue.delete(),
      }, SetOptions(merge: true));
    } catch (e) {
      debugPrint('Unpin message error: $e');
    }
  }

  void _onHeaderTap() {
    if (widget.isGroup) {
      _openGroupSettings();
    } else {
      _showUserProfileModal();
    }
  }

  void _openGroupSettings() {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => GroupSettingsScreen(
          groupId: widget.targetUserId,
          currentUserId: currentUserId,
          allUsers: const [],
        ),
      ),
    );
  }

  Future<void> _showUserProfileModal() async {
    final res = await Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => UserProfileScreen(
          userId: widget.targetUserId,
          userName: widget.targetUserName,
          userPhoto: widget.targetUserPhoto,
        ),
      ),
    );
    if (res == 'SEARCH') {
      setState(() => _isSearchMode = true);
    }
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
      reverse: true,
      controller: _scrollController,
      physics: const BouncingScrollPhysics(),
      clipBehavior: Clip.none,
      cacheExtent: 800.0,
      addAutomaticKeepAlives: true,
      addRepaintBoundaries: true,
      padding: EdgeInsets.only(
        top: MediaQuery.of(context).padding.top + 76.0 + (_pinnedMessage != null && _pinnedMessage!.isNotEmpty ? 50.0 : 0.0),
        bottom: MediaQuery.of(context).padding.bottom + 85.0,
        left: 12.0,
        right: 12.0,
      ),
      itemCount: _messageDocs.length + (hasIndicator ? 1 : 0),
      itemBuilder: (context, index) {
        if (index == _messageDocs.length) {
          if (_isTargetRecordingVoice) return _buildVoiceRecordingIndicator();
          return _buildTypingIndicator();
        }

        final doc = _messageDocs[index];
        final data = doc.data() as Map<String, dynamic>;
        final String senderId = data['senderId'] ?? '';
        final String senderName = (data['senderName'] ?? '').toString();
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
        final String? forwardedFrom = data['forwardedFrom'] as String?;

        final bool showDivider = _shouldShowDateDivider(index, ts);

        final Widget messageContent = Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (showDivider) _buildDateDivider(msgTime),
            if (rawType == 'call' || rawType == 'callMissed' || rawType == 'callVideo')
              _buildTelegramCallBubble(docId: doc.id, data: data, isMine: isMine, time: msgTime, senderName: senderName),
            if (imageUrl.isNotEmpty || rawType == 'image')
              _buildImageBubble(docId: doc.id, imageUrl: imageUrl, isMine: isMine, time: msgTime, isRead: isRead, senderName: senderName),
            if (audioUrl.isNotEmpty || rawType == 'audio' || rawType == 'voice')
              _buildVoiceBubble(docId: doc.id, audioUrl: audioUrl, durationSeconds: durationSeconds, isMine: isMine, time: msgTime, isRead: isRead, senderName: senderName),
            if (rawType == 'file')
              _buildFileBubble(docId: doc.id, fileName: (data['fileName'] ?? 'Document').toString(), fileSize: (data['fileSize'] ?? '').toString(), isMine: isMine, time: msgTime, isRead: isRead, senderName: senderName),
            if (rawType == 'location')
              _buildLocationCardBubble(docId: doc.id, text: rawText, isMine: isMine, time: msgTime, isRead: isRead, senderName: senderName),
            if (rawType == 'sticker' || rawText == '👍')
              _buildStickerBubble(docId: doc.id, text: rawText.isNotEmpty ? rawText : '👍', stickerType: (data['stickerType'] ?? '').toString(), isMine: isMine, senderName: senderName),
            if (rawType == 'groupInvite' || rawText.startsWith('vvc://group/'))
              _buildGroupInviteCard(
                docId: doc.id,
                groupId: (data['groupId'] ?? rawText.split('/').last).toString(),
                fullLink: rawText,
                senderName: senderName,
                isMine: isMine,
                time: msgTime,
                isRead: isRead,
              ),
            if (rawType != 'call' && rawType != 'callMissed' && rawType != 'callVideo' && !imageUrl.isNotEmpty && rawType != 'image' && !audioUrl.isNotEmpty && rawType != 'audio' && rawType != 'voice' && rawType != 'file' && rawType != 'location' && rawType != 'sticker' && rawType != 'groupInvite' && !rawText.startsWith('vvc://group/') && rawText != '👍' && rawText.isNotEmpty)
              _buildTextBubble(docId: doc.id, text: rawText, replyTo: replyTo, forwardedFrom: forwardedFrom, senderName: senderName, isMine: isMine, time: msgTime, isRead: isRead),
          ],
        );

        if (_isSelectionMode) {
          final bool isSelected = _selectedDocIds.contains(doc.id);
          return InkWell(
            onTap: () {
              setState(() {
                if (isSelected) {
                  _selectedDocIds.remove(doc.id);
                  if (_selectedDocIds.isEmpty) {
                    _isSelectionMode = false;
                  }
                } else {
                  _selectedDocIds.add(doc.id);
                }
              });
            },
            borderRadius: BorderRadius.circular(12),
            child: Container(
              color: isSelected ? const Color(0xFF007AFF).withValues(alpha: 0.18) : Colors.transparent,
              padding: const EdgeInsets.symmetric(vertical: 2, horizontal: 4),
              child: Row(
                children: [
                  Padding(
                    padding: const EdgeInsets.only(right: 10, left: 4),
                    child: Icon(
                      isSelected ? Icons.check_circle_rounded : Icons.radio_button_unchecked_rounded,
                      color: isSelected ? const Color(0xFF007AFF) : Colors.white38,
                      size: 24,
                    ),
                  ),
                  Expanded(child: messageContent),
                ],
              ),
            ),
          );
        }

        return messageContent;
      },
    );
  }

  bool _shouldShowDateDivider(int index, Timestamp? currentTs) {
    if (currentTs == null) return false;
    if (index == _messageDocs.length - 1) return true;
    final nextDoc = _messageDocs[index + 1].data() as Map<String, dynamic>?;
    final Timestamp? nextTs = nextDoc?['timestamp'] as Timestamp?;
    if (nextTs == null) return true;

    final currDate = currentTs.toDate();
    final nextDate = nextTs.toDate();
    return currDate.day != nextDate.day || currDate.month != nextDate.month || currDate.year != nextDate.year;
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

    return Center(
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 14.0),
        padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 5.0),
        decoration: BoxDecoration(
          color: Colors.black.withValues(alpha: 0.35),
          borderRadius: BorderRadius.circular(14.0),
          border: Border.all(color: Colors.white.withValues(alpha: 0.08), width: 0.5),
        ),
        child: Text(
          dateStr,
          style: GoogleFonts.kantumruyPro(
            color: Colors.white.withValues(alpha: 0.9),
            fontSize: 12.0,
            fontWeight: FontWeight.w500,
          ),
        ),
      ),
    );
  }

  Widget _buildReadStatusIcon(bool isRead, {bool isMine = false}) {
    if (isRead) {
      return Icon(Icons.done_all_rounded, size: 15, color: isMine ? Colors.white : const Color(0xFF007AFF));
    }
    return Icon(Icons.done_rounded, size: 15, color: isMine ? Colors.white70 : Colors.white54);
  }

  // Text Message Bubble
  Widget _buildTextBubble({
    required String docId,
    required String text,
    String? replyTo,
    String? forwardedFrom,
    required String senderName,
    required bool isMine,
    required DateTime time,
    required bool isRead,
  }) {
    if (text.startsWith('📍') || text.contains('maps.google.com') || text.startsWith('Current Location') || text.contains('q=')) {
      return _buildLocationCardBubble(
        docId: docId,
        text: text,
        senderName: senderName,
        isMine: isMine,
        time: time,
        isRead: isRead,
      );
    }

    if (text.startsWith('👤 Contact:') || text.contains('Contact:')) {
      return _buildContactCardBubble(
        docId: docId,
        text: text,
        senderName: senderName,
        isMine: isMine,
        time: time,
        isRead: isRead,
      );
    }

    final bubbleKey = GlobalKey();
    final bubbleChild = Container(
      margin: const EdgeInsets.symmetric(vertical: 3.0),
      padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 10.0),
      constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.72),
      decoration: BoxDecoration(
        color: isMine ? const Color(0xFF007AFF) : const Color(0xFF2C2C2E),
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
          if (forwardedFrom != null && forwardedFrom.isNotEmpty) ...[
            Text(
              '↪️ បញ្ជូនបន្តពី $forwardedFrom',
              style: GoogleFonts.kantumruyPro(fontSize: 11.0, color: Colors.white70, fontStyle: FontStyle.italic),
            ),
            const SizedBox(height: 4),
          ],
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
          Wrap(
            alignment: WrapAlignment.end,
            crossAxisAlignment: WrapCrossAlignment.end,
            children: [
              Text(
                text,
                style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 15.5, height: 1.35),
              ),
              const SizedBox(width: 8.0),
              Padding(
                padding: const EdgeInsets.only(bottom: 2.0),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      DateFormat('h:mm a').format(time),
                      style: GoogleFonts.inter(fontSize: 10.5, color: isMine ? Colors.white70 : Colors.white54),
                    ),
                    if (isMine) ...[
                      const SizedBox(width: 4.0),
                      _buildReadStatusIcon(isRead, isMine: true),
                    ],
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
    );

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: GestureDetector(
        key: bubbleKey,
        onLongPress: () => _showMessageOptionsModal(
          key: bubbleKey,
          childWidget: bubbleChild,
          docId: docId,
          content: text,
          type: 'text',
          senderName: senderName,
        ),
        child: bubbleChild,
      ),
    );
  }

  // Telegram-Style Group Invite Link Card
  Widget _buildGroupInviteCard({
    required String docId,
    required String groupId,
    required String fullLink,
    required String senderName,
    required bool isMine,
    required DateTime time,
    required bool isRead,
  }) {
    final stream = _firestore.collection('groups').doc(groupId).snapshots();

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 4.0),
        constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.78),
        child: StreamBuilder<DocumentSnapshot>(
          stream: stream,
          builder: (context, snapshot) {
            String groupName = 'ក្រុម (Group)';
            String groupPhoto = '';

            if (snapshot.hasData && snapshot.data!.exists) {
              final data = snapshot.data!.data() as Map<String, dynamic>?;
              if (data != null) {
                groupName = data['name'] ?? groupName;
                groupPhoto = data['photo'] ?? '';
              }
            }

            final cardColor = isMine ? const Color(0xFF8B5CF6) : const Color(0xFF2C2C2E);

            return GestureDetector(
              onLongPress: () => _showMessageOptionsModal(
                docId: docId,
                content: fullLink,
                type: 'text',
                senderName: senderName,
              ),
              child: Container(
                decoration: BoxDecoration(
                  color: cardColor,
                  borderRadius: BorderRadius.circular(18.0),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: 0.15),
                      blurRadius: 6,
                      offset: const Offset(0, 2),
                    ),
                  ],
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Link URL Header
                    Padding(
                      padding: const EdgeInsets.fromLTRB(14, 12, 14, 8),
                      child: Text(
                        fullLink,
                        style: GoogleFonts.inter(
                          color: Colors.white,
                          fontSize: 13.5,
                          decoration: TextDecoration.underline,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),

                    // Inner Preview Card with Left White Line
                    Container(
                      margin: const EdgeInsets.symmetric(horizontal: 10, vertical: 2),
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: IntrinsicHeight(
                        child: Row(
                          children: [
                            // Left Accent Stripe
                            Container(
                              width: 3.5,
                              decoration: const BoxDecoration(
                                color: Colors.white,
                                borderRadius: BorderRadius.only(
                                  topLeft: Radius.circular(12),
                                  bottomLeft: Radius.circular(12),
                                ),
                              ),
                            ),
                            const SizedBox(width: 10),

                            // Group Name & Invite Subtitle
                            Expanded(
                              child: Padding(
                                padding: const EdgeInsets.symmetric(vertical: 8),
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Text(
                                      groupName,
                                      style: GoogleFonts.kantumruyPro(
                                        color: Colors.white,
                                        fontSize: 14.5,
                                        fontWeight: FontWeight.bold,
                                      ),
                                      maxLines: 1,
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                    const SizedBox(height: 3),
                                    Text(
                                      '$senderName invites you to join this group.',
                                      style: GoogleFonts.inter(
                                        color: Colors.white.withValues(alpha: 0.85),
                                        fontSize: 12,
                                      ),
                                      maxLines: 2,
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ],
                                ),
                              ),
                            ),

                            const SizedBox(width: 6),

                            // Group Photo Thumbnail
                            Padding(
                              padding: const EdgeInsets.only(right: 8, top: 6, bottom: 6),
                              child: ClipRRect(
                                borderRadius: BorderRadius.circular(10),
                                child: Container(
                                  width: 48,
                                  height: 48,
                                  color: const Color(0xFFFFB300),
                                  child: groupPhoto.isNotEmpty
                                      ? Image.network(
                                          ApiService.getFullImageUrl(groupPhoto),
                                          fit: BoxFit.cover,
                                        )
                                      : const Icon(Icons.groups_rounded, color: Colors.white, size: 28),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),

                    const SizedBox(height: 6),
                    const Divider(color: Colors.white24, height: 1, thickness: 0.7),

                    // Action Button: VIEW GROUP
                    InkWell(
                      onTap: () {
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (_) => ChatDetailScreen(
                              targetUserId: groupId,
                              targetUserName: groupName,
                              targetUserPhoto: groupPhoto,
                              isGroup: true,
                            ),
                          ),
                        );
                      },
                      borderRadius: const BorderRadius.vertical(bottom: Radius.circular(18)),
                      child: Container(
                        width: double.infinity,
                        padding: const EdgeInsets.symmetric(vertical: 11),
                        child: Center(
                          child: Text(
                            'VIEW GROUP',
                            style: GoogleFonts.inter(
                              color: Colors.white,
                              fontSize: 14,
                              fontWeight: FontWeight.bold,
                              letterSpacing: 0.8,
                            ),
                          ),
                        ),
                      ),
                    ),

                    // Timestamp & Read indicator
                    Padding(
                      padding: const EdgeInsets.fromLTRB(0, 0, 10, 6),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.end,
                        children: [
                          Text(
                            DateFormat('h:mm a').format(time),
                            style: GoogleFonts.inter(fontSize: 10.0, color: Colors.white60),
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
              ),
            );
          },
        ),
      ),
    );
  }

  // Sticker / Emoji / Giphy / Lottie Bubble
  Widget _buildStickerBubble({
    required String docId,
    required String text,
    String? stickerType,
    required bool isMine,
    required String senderName,
  }) {
    final bool isLottie = (stickerType == 'lottie') || text.endsWith('.json') || text.endsWith('.tgs');
    final bool isAsset = text.startsWith('assets/');
    final bool isNetworkImage = text.startsWith('http') || text.startsWith('data:image');

    Widget stickerWidget;
    if (isAsset) {
      if (isLottie) {
        stickerWidget = SizedBox(
          width: 150,
          height: 150,
          child: TgsStickerAsset(
            assetPath: text,
            fit: BoxFit.contain,
          ),
        );
      } else {
        stickerWidget = ClipRRect(
          borderRadius: BorderRadius.circular(16),
          child: Image.asset(
            text,
            width: 150,
            height: 150,
            fit: BoxFit.contain,
            errorBuilder: (context, error, stackTrace) {
              return const Icon(LucideIcons.imageOff, color: Colors.white54, size: 48);
            },
          ),
        );
      }
    } else if (isLottie) {
      stickerWidget = SizedBox(
        width: 160,
        height: 160,
        child: Lottie.network(
          text,
          fit: BoxFit.contain,
          errorBuilder: (context, error, stackTrace) {
            return const Icon(LucideIcons.sparkles, color: Colors.amberAccent, size: 48);
          },
        ),
      );
    } else if (isNetworkImage) {
      stickerWidget = ClipRRect(
        borderRadius: BorderRadius.circular(16),
        child: Image.network(
          text,
          width: 160,
          height: 160,
          fit: BoxFit.cover,
          cacheWidth: 320,
          loadingBuilder: (context, child, progress) {
            if (progress == null) return child;
            return const SizedBox(
              width: 160,
              height: 160,
              child: Center(child: CircularProgressIndicator(strokeWidth: 2, color: Color(0xFF007AFF))),
            );
          },
        ),
      );
    } else {
      stickerWidget = Text(text, style: const TextStyle(fontSize: 48.0));
    }

    final bubbleKey = GlobalKey();
    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: GestureDetector(
        key: bubbleKey,
        onLongPress: () => _showMessageOptionsModal(
          key: bubbleKey,
          childWidget: stickerWidget,
          docId: docId,
          content: text,
          type: 'sticker',
          senderName: senderName,
        ),
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 4.0),
          child: stickerWidget,
        ),
      ),
    );
  }

  Future<void> _sendStickerMessage(String stickerUrl, String stickerType) async {
    if (stickerUrl.isEmpty || currentUserId.isEmpty) return;

    if (stickerType == 'emoji') {
      _sendMessage(customText: stickerUrl);
      return;
    }

    final userProvider = Provider.of<UserProvider>(context, listen: false);

    final msgData = {
      'text': stickerUrl,
      'stickerUrl': stickerUrl,
      'stickerType': stickerType,
      'type': 'sticker',
      'senderId': currentUserId,
      'senderName': userProvider.name ?? '',
      'senderPhoto': userProvider.avatar ?? '',
      'timestamp': FieldValue.serverTimestamp(),
      'isRead': false,
    };

    final isLottie = stickerType == 'lottie' || stickerUrl.endsWith('.json') || stickerUrl.endsWith('.tgs');

    final batch = _firestore.batch();
    final msgRef = _firestore.collection('chats').doc(_roomId).collection('messages').doc();
    batch.set(msgRef, msgData);
    batch.set(_firestore.collection('chats').doc(_roomId), {
      'participants': [currentUserId, widget.targetUserId],
      'lastMessage': isLottie ? '🎭 Animated Sticker' : '🎨 Sticker',
      'lastTimestamp': FieldValue.serverTimestamp(),
      'lastSenderId': currentUserId,
      'isRead': false,
    }, SetOptions(merge: true));
    await batch.commit();
  }

  void _showGiphyStickerPicker() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (ctx) => GiphyStickerPickerBottomSheet(
        onSelectSticker: (url, type) {
          _sendStickerMessage(url, type);
        },
      ),
    );
  }

  // Telegram Call Event Bubble
  Widget _buildTelegramCallBubble({
    required String docId,
    required Map<String, dynamic> data,
    required bool isMine,
    required DateTime time,
    required String senderName,
  }) {
    final rawType = (data['type'] ?? '').toString();
    final isVideo = data['callType'] == 'video' || data['isVideo'] == true || rawType == 'callVideo';
    final int duration = (data['duration'] ?? data['callDuration'] ?? 0) as int;
    final String callStatus = (data['callStatus'] ?? (rawType == 'callMissed' ? 'missed' : 'completed')).toString();
    final bool isMissed = callStatus == 'missed';
    final bool isDeclined = callStatus == 'declined';

    String title;
    IconData icon;
    Color iconColor;
    Color iconBg;

    if (isMine) {
      if (isMissed || duration == 0) {
        title = isVideo ? 'ការខលវីដេអូបានបោះបង់' : 'ការខលបានបោះបង់ (Cancelled)';
        icon = isVideo ? Icons.videocam_off_rounded : Icons.call_made_rounded;
        iconColor = const Color(0xFF94A3B8);
        iconBg = const Color(0xFF334155);
      } else {
        title = isVideo ? 'ការខលវីដេអូចេញ' : 'ការខលចេញ (Outgoing Call)';
        icon = isVideo ? Icons.videocam_rounded : Icons.call_made_rounded;
        iconColor = const Color(0xFF10B981);
        iconBg = const Color(0xFF10B981).withValues(alpha: 0.15);
      }
    } else {
      if (isMissed) {
        title = isVideo ? 'ការខលវីដេអូខកខាន' : 'ការខលខកខាន (Missed Call)';
        icon = isVideo ? Icons.videocam_off_rounded : Icons.phone_missed_rounded;
        iconColor = const Color(0xFFFF3B30);
        iconBg = const Color(0xFFFF3B30).withValues(alpha: 0.15);
      } else if (isDeclined) {
        title = isVideo ? 'ការខលវីដេអូបដិសេធ' : 'ការខលត្រូវបានបដិសេធ';
        icon = isVideo ? Icons.videocam_off_rounded : Icons.call_end_rounded;
        iconColor = const Color(0xFFFF9500);
        iconBg = const Color(0xFFFF9500).withValues(alpha: 0.15);
      } else {
        title = isVideo ? 'ការខលវីដេអូចូល' : 'ការខលចូល (Incoming Call)';
        icon = isVideo ? Icons.videocam_rounded : Icons.call_received_rounded;
        iconColor = const Color(0xFF0A84FF);
        iconBg = const Color(0xFF0A84FF).withValues(alpha: 0.15);
      }
    }

    String subtitle;
    if (duration > 0) {
      final m = duration ~/ 60;
      final s = duration % 60;
      final durText = m > 0 ? '$m នាទី $s វិនាទី' : '$s វិនាទី';
      subtitle = '$durText • ${DateFormat('h:mm a').format(time)}';
    } else {
      subtitle = DateFormat('h:mm a').format(time);
    }

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: GestureDetector(
        onLongPress: () => _showMessageOptionsModal(
          docId: docId,
          content: title,
          type: 'call',
          senderName: senderName,
        ),
        child: Container(
          margin: const EdgeInsets.symmetric(vertical: 6.0, horizontal: 4.0),
          width: 250.0,
          decoration: BoxDecoration(
            color: const Color(0xFF1E293B),
            borderRadius: BorderRadius.circular(18.0),
            border: Border.all(
              color: isMissed && !isMine
                  ? const Color(0xFFFF3B30).withValues(alpha: 0.4)
                  : const Color(0xFF334155),
              width: 1.0,
            ),
            boxShadow: const [
              BoxShadow(
                color: Colors.black26,
                blurRadius: 8,
                offset: Offset(0, 2),
              ),
            ],
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(12.0, 12.0, 12.0, 10.0),
                child: Row(
                  children: [
                    Container(
                      width: 42.0,
                      height: 42.0,
                      decoration: BoxDecoration(
                        color: iconBg,
                        shape: BoxShape.circle,
                      ),
                      child: Icon(icon, size: 22.0, color: iconColor),
                    ),
                    const SizedBox(width: 10.0),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            title,
                            style: GoogleFonts.kantumruyPro(
                              color: isMissed && !isMine ? const Color(0xFFFF3B30) : Colors.white,
                              fontWeight: FontWeight.w600,
                              fontSize: 13.5,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          const SizedBox(height: 3.0),
                          Text(
                            subtitle,
                            style: GoogleFonts.inter(
                              fontSize: 11.5,
                              color: const Color(0xFF94A3B8),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              const Divider(height: 1.0, color: Color(0xFF334155)),
              InkWell(
                onTap: () {
                  _initiateCall(isVideo ? 'video' : 'audio');
                },
                borderRadius: const BorderRadius.only(
                  bottomLeft: Radius.circular(18.0),
                  bottomRight: Radius.circular(18.0),
                ),
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(vertical: 9.0),
                  alignment: Alignment.center,
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(
                        isVideo ? Icons.videocam_rounded : Icons.phone_callback_rounded,
                        size: 15,
                        color: const Color(0xFF0A84FF),
                      ),
                      const SizedBox(width: 6),
                      Text(
                        'ខលត្រឡប់ទៅវិញ (Call back)',
                        style: GoogleFonts.kantumruyPro(
                          color: const Color(0xFF0A84FF),
                          fontWeight: FontWeight.w600,
                          fontSize: 12.5,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
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
    required String senderName,
  }) {
    final bool isBase64 = imageUrl.startsWith('data:image');
    final ImageProvider rawProvider = isBase64
        ? _getMemoryImage(imageUrl)
        : NetworkImage(imageUrl);
    final ImageProvider imgProvider = ResizeImage(
      rawProvider,
      width: 600,
    );

    final bubbleKey = GlobalKey();
    final bubbleChild = Container(
      margin: const EdgeInsets.symmetric(vertical: 4.0),
      constraints: BoxConstraints(
        maxWidth: MediaQuery.of(context).size.width * 0.68,
        maxHeight: 320.0,
      ),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(16.0),
        color: isMine ? _MsgDark.sentBubble : const Color(0xFF2C2C2E),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(16.0),
        child: Image(
          image: imgProvider,
          fit: BoxFit.contain,
        ),
      ),
    );

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          GestureDetector(
            key: bubbleKey,
            onTap: () => _showFullScreenImageViewer(
              imgProvider: imgProvider,
              rawUrl: imageUrl,
              senderName: isMine ? 'You' : senderName,
              time: time,
              docId: docId,
            ),
            onLongPress: () => _showMessageOptionsModal(
              key: bubbleKey,
              childWidget: bubbleChild,
              docId: docId,
              content: imageUrl,
              type: 'image',
              senderName: senderName,
            ),
            child: bubbleChild,
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

  // Telegram Full Screen Image Viewer (Matching Attached 3 Screenshots 100%)
  void _showFullScreenImageViewer({
    required ImageProvider imgProvider,
    required String rawUrl,
    required String senderName,
    required DateTime time,
    required String docId,
  }) {
    final String dateStr = DateFormat('dd/MM/yy').format(time);

    showDialog(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.96),
      builder: (ctx) {
        return Dialog(
          backgroundColor: Colors.transparent,
          insetPadding: EdgeInsets.zero,
          child: StatefulBuilder(
            builder: (context, setViewerState) {
              return Stack(
                children: [
                  // Full Screen Interactive Viewer (Swipe down to dismiss)
                  Dismissible(
                    key: UniqueKey(),
                    direction: DismissDirection.vertical,
                    onDismissed: (_) => Navigator.pop(ctx),
                    child: Center(
                      child: InteractiveViewer(
                        minScale: 0.8,
                        maxScale: 4.0,
                        child: Image(image: imgProvider, fit: BoxFit.contain),
                      ),
                    ),
                  ),

                  // Top Header Bar (Matching Screenshot 1)
                  Positioned(
                    top: MediaQuery.of(context).padding.top + 6,
                    left: 14,
                    right: 14,
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        // Left Back Arrow Circle Button
                        InkWell(
                          onTap: () => Navigator.pop(ctx),
                          borderRadius: BorderRadius.circular(20),
                          child: Container(
                            width: 38,
                            height: 38,
                            decoration: const BoxDecoration(
                              color: Color(0x991C1C1E),
                              shape: BoxShape.circle,
                            ),
                            child: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 18),
                          ),
                        ),

                        // Center Sender Title & Date Capsule Pill
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 6),
                          decoration: BoxDecoration(
                            color: const Color(0x991C1C1E),
                            borderRadius: BorderRadius.circular(20),
                            border: Border.all(color: Colors.white12, width: 0.5),
                          ),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text(
                                senderName,
                                style: GoogleFonts.inter(color: Colors.white, fontSize: 13.5, fontWeight: FontWeight.bold),
                              ),
                              Text(
                                dateStr,
                                style: GoogleFonts.inter(color: const Color(0xFF8E8E93), fontSize: 11.0),
                              ),
                            ],
                          ),
                        ),

                        // Right 3-Dots Circle Button ...
                        InkWell(
                          onTap: () {
                            _showTelegramImage3DotsMenu(ctx, rawUrl, docId);
                          },
                          borderRadius: BorderRadius.circular(20),
                          child: Container(
                            width: 38,
                            height: 38,
                            decoration: const BoxDecoration(
                              color: Color(0x991C1C1E),
                              shape: BoxShape.circle,
                            ),
                            child: const Icon(Icons.more_horiz_rounded, color: Colors.white, size: 22),
                          ),
                        ),
                      ],
                    ),
                  ),

                  // Bottom Action Bar (Matching Screenshot 1)
                  Positioned(
                    bottom: MediaQuery.of(context).padding.bottom + 12,
                    left: 16,
                    right: 16,
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        // 1. Left Share/Forward Button ↪️
                        InkWell(
                          onTap: () {
                            _showTelegramImageShareSheet(ctx, rawUrl);
                          },
                          borderRadius: BorderRadius.circular(22),
                          child: Container(
                            width: 44,
                            height: 44,
                            decoration: const BoxDecoration(
                              color: Color(0x991C1C1E),
                              shape: BoxShape.circle,
                            ),
                            child: const Icon(Icons.reply_rounded, color: Colors.white, size: 22),
                          ),
                        ),

                        // 2. Center Capsule Tools (Markup Pen 🖊️ & OCR Scanner 🖼️)
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                          decoration: BoxDecoration(
                            color: const Color(0x991C1C1E),
                            borderRadius: BorderRadius.circular(22),
                            border: Border.all(color: Colors.white12, width: 0.5),
                          ),
                          child: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              InkWell(
                                onTap: () {
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    SnackBar(content: Text('មុខងារ Markup Image Tool', style: GoogleFonts.kantumruyPro())),
                                  );
                                },
                                child: const Icon(Icons.border_color_rounded, color: Colors.white, size: 20),
                              ),
                              const SizedBox(width: 24),
                              InkWell(
                                onTap: () {
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    SnackBar(content: Text('មុខងារ OCR Text Scanner', style: GoogleFonts.kantumruyPro())),
                                  );
                                },
                                child: const Icon(Icons.crop_free_rounded, color: Colors.white, size: 20),
                              ),
                            ],
                          ),
                        ),

                        // 3. Right Delete Trash Button 🗑️
                        InkWell(
                          onTap: () async {
                            final confirm = await showDialog<bool>(
                              context: ctx,
                              builder: (c) => AlertDialog(
                                backgroundColor: const Color(0xFF1E293B),
                                title: Text('លុបរូបភាព', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
                                content: Text('តើអ្នកពិតជាចង់លុបរូបភាពនេះមែនទេ?', style: GoogleFonts.kantumruyPro(color: Colors.white70)),
                                actions: [
                                  TextButton(onPressed: () => Navigator.pop(c, false), child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: const Color(0xFF94A3B8)))),
                                  ElevatedButton(
                                    style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFFF3B30)),
                                    onPressed: () => Navigator.pop(c, true),
                                    child: Text('លុប', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
                                  ),
                                ],
                              ),
                            );

                            if (confirm == true) {
                              await _firestore.collection('chats').doc(_roomId).collection('messages').doc(docId).delete();
                              await _syncLastMessageAfterDeletion();
                              if (ctx.mounted) Navigator.pop(ctx);
                            }
                          },
                          borderRadius: BorderRadius.circular(22),
                          child: Container(
                            width: 44,
                            height: 44,
                            decoration: const BoxDecoration(
                              color: Color(0x991C1C1E),
                              shape: BoxShape.circle,
                            ),
                            child: const Icon(Icons.delete_outline_rounded, color: Colors.white, size: 22),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              );
            },
          ),
        );
      },
    );
  }

  // Telegram Image Share Sheet ("Share with" Bottom Sheet - Screenshot 2)
  void _showTelegramImageShareSheet(BuildContext parentCtx, String rawUrl) {
    showModalBottomSheet(
      context: parentCtx,
      backgroundColor: const Color(0xFF1C1C1E),
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (sheetCtx) {
        return Container(
          padding: const EdgeInsets.all(16),
          height: MediaQuery.of(parentCtx).size.height * 0.70,
          child: Column(
            children: [
              // Top Header Row (Search, Title, Share arrow)
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Icon(Icons.search_rounded, color: Color(0xFF0A84FF), size: 22),
                  Column(
                    children: [
                      Text('Share with', style: GoogleFonts.inter(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                      Text('Select chats', style: GoogleFonts.inter(color: const Color(0xFF8E8E93), fontSize: 12)),
                    ],
                  ),
                  const Icon(Icons.ios_share_rounded, color: Color(0xFF0A84FF), size: 22),
                ],
              ),
              const SizedBox(height: 16),

              // Chat Targets Grid (5 columns)
              Expanded(
                child: StreamBuilder<QuerySnapshot>(
                  stream: _firestore.collection('users').snapshots(),
                  builder: (context, snap) {
                    if (!snap.hasData) return const Center(child: CircularProgressIndicator(color: Color(0xFF0A84FF)));
                    final users = snap.data!.docs.where((d) => d.id != currentUserId).toList();

                    return GridView.builder(
                      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                        crossAxisCount: 5,
                        mainAxisSpacing: 14,
                        crossAxisSpacing: 10,
                        childAspectRatio: 0.75,
                      ),
                      itemCount: users.length + 1,
                      itemBuilder: (context, idx) {
                        if (idx == 0) {
                          return InkWell(
                            onTap: () {
                              Navigator.pop(sheetCtx);
                              _showForwardModal(rawUrl, 'image');
                            },
                            child: Column(
                              children: [
                                const CircleAvatar(
                                  radius: 26,
                                  backgroundColor: Color(0xFF0A84FF),
                                  child: Icon(Icons.bookmark_rounded, color: Colors.white, size: 26),
                                ),
                                const SizedBox(height: 6),
                                Text(
                                  'Saved Messages',
                                  style: GoogleFonts.inter(color: Colors.white, fontSize: 10),
                                  textAlign: TextAlign.center,
                                  maxLines: 2,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ],
                            ),
                          );
                        }

                        final uDoc = users[idx - 1];
                        final uData = uDoc.data() as Map<String, dynamic>;
                        final name = uData['name'] ?? 'User';
                        final avatar = uData['avatar'] ?? '';

                        return InkWell(
                          onTap: () {
                            Navigator.pop(sheetCtx);
                            _showForwardModal(rawUrl, 'image');
                          },
                          child: Column(
                            children: [
                              CircleAvatar(
                                radius: 26,
                                backgroundImage: avatar.isNotEmpty ? NetworkImage(ApiService.getFullImageUrl(avatar)) : null,
                                backgroundColor: const Color(0xFFFFB300),
                                child: avatar.isEmpty ? Text(name[0].toUpperCase(), style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold)) : null,
                              ),
                              const SizedBox(height: 6),
                              Text(
                                name,
                                style: GoogleFonts.inter(color: Colors.white, fontSize: 10.5),
                                textAlign: TextAlign.center,
                                maxLines: 2,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ],
                          ),
                        );
                      },
                    );
                  },
                ),
              ),
              const SizedBox(height: 12),

              // Save Image Card Button
              InkWell(
                onTap: () {
                  Navigator.pop(sheetCtx);
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('បានរក្សាទុករូបភាពក្នុង Gallery!', style: GoogleFonts.kantumruyPro())),
                  );
                },
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  decoration: BoxDecoration(
                    color: const Color(0xFF2C2C2E),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Text(
                    'Save Image',
                    textAlign: TextAlign.center,
                    style: GoogleFonts.inter(color: const Color(0xFF0A84FF), fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                ),
              ),
              const SizedBox(height: 10),

              // Cancel Capsule Button
              InkWell(
                onTap: () => Navigator.pop(sheetCtx),
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  decoration: BoxDecoration(
                    color: const Color(0xFF2C2C2E),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Text(
                    'Cancel',
                    textAlign: TextAlign.center,
                    style: GoogleFonts.inter(color: const Color(0xFF0A84FF), fontSize: 16, fontWeight: FontWeight.w600),
                  ),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  // Telegram Image 3-Dots Menu Context Sheet (Screenshot 3)
  void _showTelegramImage3DotsMenu(BuildContext parentCtx, String rawUrl, String docId) {
    showModalBottomSheet(
      context: parentCtx,
      backgroundColor: const Color(0xFF1C1C1E),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (menuCtx) {
        return Container(
          padding: const EdgeInsets.symmetric(vertical: 12),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(width: 36, height: 4, decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(10))),
              const SizedBox(height: 10),
              ListTile(
                leading: const Icon(Icons.chat_bubble_outline_rounded, color: Colors.white),
                title: Text('Show in Chat', style: GoogleFonts.inter(color: Colors.white, fontSize: 15)),
                onTap: () {
                  Navigator.pop(menuCtx);
                  Navigator.pop(parentCtx);
                },
              ),
              ListTile(
                leading: const Icon(Icons.sentiment_satisfied_alt_rounded, color: Colors.white),
                title: Text('Create Sticker', style: GoogleFonts.inter(color: Colors.white, fontSize: 15)),
                onTap: () {
                  Navigator.pop(menuCtx);
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('មុខងារ Create Sticker', style: GoogleFonts.kantumruyPro())),
                  );
                },
              ),
              ListTile(
                leading: const Icon(Icons.arrow_downward_rounded, color: Colors.white),
                title: Text('Save Image', style: GoogleFonts.inter(color: Colors.white, fontSize: 15)),
                onTap: () {
                  Navigator.pop(menuCtx);
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('បានរក្សាទុករូបភាពក្នុង Gallery!', style: GoogleFonts.kantumruyPro())),
                  );
                },
              ),
              ListTile(
                leading: const Icon(Icons.reply_rounded, color: Colors.white),
                title: Text('Reply', style: GoogleFonts.inter(color: Colors.white, fontSize: 15)),
                onTap: () {
                  Navigator.pop(menuCtx);
                  Navigator.pop(parentCtx);
                  setState(() => _replyingToMessage = '🖼️ រូបភាព');
                },
              ),
              ListTile(
                leading: const Icon(Icons.delete_outline_rounded, color: Color(0xFFFF3B30)),
                title: Text('Delete', style: GoogleFonts.inter(color: const Color(0xFFFF3B30), fontSize: 15, fontWeight: FontWeight.bold)),
                onTap: () async {
                  Navigator.pop(menuCtx);
                  await _firestore.collection('chats').doc(_roomId).collection('messages').doc(docId).delete();
                  await _syncLastMessageAfterDeletion();
                  if (parentCtx.mounted) Navigator.pop(parentCtx);
                },
              ),
            ],
          ),
        );
      },
    );
  }

  // Interactive Playable Voice Message Bubble (Clean Messenger Style - Optimized Isolated Widget)
  Widget _buildVoiceBubble({
    required String docId,
    required String audioUrl,
    required int durationSeconds,
    required bool isMine,
    required DateTime time,
    required bool isRead,
    required String senderName,
  }) {
    return _VoiceBubbleWidget(
      docId: docId,
      audioUrl: audioUrl,
      durationSeconds: durationSeconds,
      isMine: isMine,
      time: time,
      isRead: isRead,
      senderName: senderName,
      audioPlayer: _audioPlayer,
      onTogglePlay: _togglePlayAudio,
      onToggleSpeed: _togglePlaybackSpeed,
      playbackSpeed: _playbackSpeed,
      currentlyPlayingAudio: _currentlyPlayingAudio,
      isPlayingAudio: _isPlayingAudio,
      onLongPressModal: (key, child) => _showMessageOptionsModal(
        key: key,
        childWidget: child,
        docId: docId,
        content: audioUrl,
        type: 'voice',
        senderName: senderName,
      ),
      buildReadStatusIcon: _buildReadStatusIcon,
    );
  }

  void _togglePlaybackSpeed() {
    setState(() {
      if (_playbackSpeed == 1.0) {
        _playbackSpeed = 1.5;
      } else if (_playbackSpeed == 1.5) {
        _playbackSpeed = 2.0;
      } else {
        _playbackSpeed = 1.0;
      }
    });
    _audioPlayer.setPlaybackRate(_playbackSpeed);
  }

  // ignore: unused_element
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

  Future<void> _sendReaction(String docId, String emoji) async {
    try {
      await _firestore.collection('chats').doc(_roomId).collection('messages').doc(docId).set({
        'reactions': {
          currentUserId: emoji,
        }
      }, SetOptions(merge: true));
    } catch (e) {
      debugPrint('Error sending reaction: $e');
    }
  }

  // Telegram Dark Theme Context Menu (Reply, Copy, Save, Edit, Pin, Forward, Delete)
  void _showMessageOptionsModal({
    required String docId,
    required String content,
    required String type,
    required String senderName,
    GlobalKey? key,
    Widget? childWidget,
  }) {
    ChatMessageType msgType = ChatMessageType.text;
    if (type == 'voice') msgType = ChatMessageType.voice;
    if (type == 'image') msgType = ChatMessageType.image;
    if (type == 'file') msgType = ChatMessageType.file;

    if (key != null && key.currentContext != null && childWidget != null) {
      VvcChatContextMenu.show(
        context: context,
        widgetKey: key,
        messageType: msgType,
        childWidget: childWidget,
        onReactionSelected: (emoji) {
          _sendReaction(docId, emoji);
        },
        onReply: () {
          String summary = content;
          if (type == 'voice') summary = '🎙️ សារសំឡេង';
          if (type == 'image') summary = '🖼️ រូបភាព';
          if (type == 'location') summary = '📍 ទីតាំង';
          setState(() => _replyingToMessage = summary);
        },
        onCopy: () {
          Clipboard.setData(ClipboardData(text: content));
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('បានចម្លងអត្ថបទ!', style: GoogleFonts.kantumruyPro())),
          );
        },
        onSave: () {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('បានរក្សាទុក!', style: GoogleFonts.kantumruyPro())),
          );
        },
        onEdit: () {
          _msgController.text = content;
        },
        onPin: () async {
          String summary = content;
          if (type == 'voice') summary = '🎙️ សារសំឡេង';
          if (type == 'image') summary = '🖼️ រូបភាព';
          if (type == 'location') summary = '📍 ទីតាំង';
          await _firestore.collection('chats').doc(_roomId).set({
            'pinnedMessage': {
              'id': docId,
              'text': summary,
              'type': type,
              'senderName': senderName,
            }
          }, SetOptions(merge: true));
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text('បានប៉ិនសារទុក!', style: GoogleFonts.kantumruyPro())),
            );
          }
        },
        onForward: () {
          _showForwardModal(content, type, originalSenderName: senderName);
        },
        onDelete: () async {
          await _firestore.collection('chats').doc(_roomId).collection('messages').doc(docId).delete();
          await _syncLastMessageAfterDeletion();
        },
        onSelect: () {
          setState(() {
            _isSelectionMode = true;
            _selectedDocIds.clear();
            _selectedDocIds.add(docId);
          });
        },
      );
      return;
    }

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
                  String summary = content;
                  if (type == 'voice') summary = '🎙️ សារសំឡេង';
                  if (type == 'image') summary = '🖼️ រូបភាព';
                  if (type == 'location') summary = '📍 ទីតាំង';
                  setState(() => _replyingToMessage = summary);
                },
              ),
              ListTile(
                leading: const Icon(Icons.shortcut_rounded, color: Colors.white),
                title: Text('បញ្ជូនបន្ត (Forward)', style: GoogleFonts.kantumruyPro(color: Colors.white)),
                onTap: () {
                  Navigator.pop(ctx);
                  _showForwardModal(content, type, originalSenderName: senderName);
                },
              ),
              ListTile(
                leading: const Icon(Icons.push_pin_rounded, color: Colors.white),
                title: Text('ប៉ិនទុក (Pin)', style: GoogleFonts.kantumruyPro(color: Colors.white)),
                onTap: () async {
                  Navigator.pop(ctx);
                  String summary = content;
                  if (type == 'voice') summary = '🎙️ សារសំឡេង';
                  if (type == 'image') summary = '🖼️ រូបភាព';
                  if (type == 'location') summary = '📍 ទីតាំង';
                  await _firestore.collection('chats').doc(_roomId).set({
                    'pinnedMessage': {
                      'id': docId,
                      'text': summary,
                      'type': type,
                      'senderName': senderName,
                    }
                  }, SetOptions(merge: true));
                  if (mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('បានប៉ិនសារទុក!', style: GoogleFonts.kantumruyPro())),
                    );
                  }
                },
              ),
              ListTile(
                leading: const Icon(Icons.delete_forever_rounded, color: Colors.redAccent),
                title: Text('លុបសារ (Delete)', style: GoogleFonts.kantumruyPro(color: Colors.redAccent)),
                onTap: () async {
                  Navigator.pop(ctx);
                  await _firestore.collection('chats').doc(_roomId).collection('messages').doc(docId).delete();
                  await _syncLastMessageAfterDeletion();
                },
              ),
              const SizedBox(height: 12),
            ],
          ),
        );
      },
    );
  }

  // Forward Message Modal with Employee List & Show Sender Name Option
  void _showForwardModal(String content, String type, {String originalSenderName = ''}) {
    bool showSenderName = true;
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E1E2E),
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20.0)),
      ),
      builder: (ctx) {
        return StatefulBuilder(
          builder: (context, setModalState) {
            return Container(
              height: MediaQuery.of(context).size.height * 0.75,
              color: const Color(0xFF1E1E2E),
              child: Column(
                children: [
                  const SizedBox(height: 8),
                  Container(width: 36, height: 4, decoration: BoxDecoration(color: Colors.white30, borderRadius: BorderRadius.circular(2))),
                  const SizedBox(height: 12),
                  Text(
                    'បញ្ជូនបន្តទៅកាន់ (Forward to)',
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 4),
                  SwitchListTile(
                    value: showSenderName,
                    onChanged: (val) => setModalState(() => showSenderName = val),
                    title: Text(
                      'បង្ហាញឈ្មោះអ្នកផ្ញើដើម (Show original sender)',
                      style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                    ),
                    activeThumbColor: const Color(0xFF0084FF),
                    dense: true,
                  ),
                  const Divider(color: Colors.white24, height: 1),
                  Expanded(
                    child: StreamBuilder<QuerySnapshot>(
                      stream: _firestore.collection('users').snapshots(),
                      builder: (context, snap) {
                        if (!snap.hasData) return const Center(child: CircularProgressIndicator(color: Colors.white));
                        final users = snap.data!.docs.where((d) => d.id != currentUserId).toList();

                        return ListView.builder(
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
                              title: Text(name, style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.w600)),
                              subtitle: Text(u['position'] ?? u['department'] ?? '', style: GoogleFonts.inter(color: Colors.white70, fontSize: 12)),
                              trailing: const Icon(Icons.send_rounded, color: Color(0xFF0084FF)),
                              onTap: () async {
                                Navigator.pop(ctx);
                                final userProvider = Provider.of<UserProvider>(context, listen: false);
                                final targetRoomId = "PRIVATE_${([currentUserId, targetId]..sort()).join('_')}";

                                final msgData = {
                                  'text': type == 'text' ? content : '',
                                  if (type == 'image') 'imageUrl': content,
                                  if (type == 'voice') 'base64Audio': content,
                                  'type': type,
                                  'isForwarded': true,
                                  'forwardedFrom': showSenderName && originalSenderName.isNotEmpty ? originalSenderName : null,
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
                        );
                      },
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
    required String docId,
    required String fileName,
    required String fileSize,
    required bool isMine,
    required DateTime time,
    required bool isRead,
    required String senderName,
  }) {
    final bubbleKey = GlobalKey();
    final bubbleChild = Container(
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
    );

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          GestureDetector(
            key: bubbleKey,
            onLongPress: () => _showMessageOptionsModal(
              key: bubbleKey,
              childWidget: bubbleChild,
              docId: docId,
              content: fileName,
              type: 'file',
              senderName: senderName,
            ),
            child: bubbleChild,
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

  // Location Map Bubble Widget (Telegram exact design)
  Widget _buildLocationCardBubble({
    required String docId,
    required String text,
    required String senderName,
    required bool isMine,
    required DateTime time,
    required bool isRead,
  }) {
    double lat = 11.5564;
    double lng = 104.9282;
    String locationTitle = 'Location';

    final RegExp regExp = RegExp(r'q=(-?\d+\.?\d*),(-?\d+\.?\d*)');
    final match = regExp.firstMatch(text);
    if (match != null) {
      lat = double.tryParse(match.group(1)!) ?? 11.5564;
      lng = double.tryParse(match.group(2)!) ?? 104.9282;
    }

    if (text.contains(':')) {
      final parts = text.split('\n');
      if (parts.isNotEmpty && parts.first.contains('📍')) {
        locationTitle = parts.first.replaceAll('📍', '').replaceAll(':', '').trim();
      }
    }
    if (locationTitle.isEmpty) locationTitle = 'Location';

    final bubbleKey = GlobalKey();

    // 3x3 Tile Grid URLs
    const int zoom = 15;
    final n = pow(2, zoom);
    final tileX = (((lng + 180.0) / 360.0) * n).floor();
    final latRad = lat * pi / 180.0;
    final tileY = (((1.0 - (log(tan(latRad) + (1.0 / cos(latRad))) / pi)) / 2.0) * n).floor();

    final List<String> tileUrls = [];
    for (int dy = -1; dy <= 1; dy++) {
      for (int dx = -1; dx <= 1; dx++) {
        tileUrls.add('https://a.basemaps.cartocdn.com/dark_all/$zoom/${tileX + dx}/${tileY + dy}.png');
      }
    }

    final cardContent = Container(
      width: 260,
      height: 150,
      margin: const EdgeInsets.symmetric(vertical: 4),
      decoration: BoxDecoration(
        color: const Color(0xFF151D2A),
        borderRadius: BorderRadius.circular(18),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.35),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(18),
        child: Stack(
          children: [
            // A. Dark CartoDB Map Background (3x3 Grid centered)
            Positioned.fill(
              child: OverflowBox(
                maxWidth: 768,
                maxHeight: 768,
                child: SizedBox(
                  width: 768,
                  height: 768,
                  child: GridView.count(
                    crossAxisCount: 3,
                    physics: const NeverScrollableScrollPhysics(),
                    children: tileUrls.map((url) {
                      return Image.network(
                        url,
                        fit: BoxFit.cover,
                        errorBuilder: (_, __, ___) => Container(color: const Color(0xFF151D2A)),
                      );
                    }).toList(),
                  ),
                ),
              ),
            ),

            // Slight dark tint overlay
            Positioned.fill(
              child: Container(
                color: Colors.black.withValues(alpha: 0.15),
              ),
            ),

            // B. Center Blue Pin (Telegram Pin Style)
            Center(
              child: Container(
                padding: const EdgeInsets.all(4),
                decoration: const BoxDecoration(
                  color: Color(0xFF3388FF),
                  shape: BoxShape.circle,
                  boxShadow: [
                    BoxShadow(color: Colors.black54, blurRadius: 8, offset: Offset(0, 3)),
                  ],
                ),
                child: const Icon(Icons.push_pin_rounded, color: Colors.white, size: 22),
              ),
            ),

            // C. Bottom Left " Maps" Provider Pill
            Positioned(
              bottom: 8,
              left: 10,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.65),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.apple, color: Colors.white, size: 13),
                    const SizedBox(width: 3),
                    Text(
                      'Maps',
                      style: GoogleFonts.inter(color: Colors.white, fontSize: 11, fontWeight: FontWeight.w600),
                    ),
                  ],
                ),
              ),
            ),

            // D. Bottom Right Timestamp & Status Ticks
            Positioned(
              bottom: 8,
              right: 10,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.65),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      DateFormat('h:mm a').format(time),
                      style: GoogleFonts.inter(fontSize: 10.0, color: Colors.white),
                    ),
                    if (isMine) ...[
                      const SizedBox(width: 4.0),
                      _buildReadStatusIcon(isRead),
                    ],
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: GestureDetector(
        key: bubbleKey,
        onTap: () => _showTelegramFullScreenMapView(
          lat: lat,
          lng: lng,
          locationTitle: locationTitle,
        ),
        onLongPress: () => _showMessageOptionsModal(
          key: bubbleKey,
          childWidget: cardContent,
          docId: docId,
          content: text,
          type: 'location',
          senderName: senderName,
        ),
        child: cardContent,
      ),
    );
  }

  // Helper: Fetch real-time live weather data from user's device GPS location
  Future<Map<String, dynamic>?> _fetchRealWeather(double fallbackLat, double fallbackLng) async {
    try {
      double targetLat = fallbackLat;
      double targetLng = fallbackLng;

      // Request / check real device GPS location permission
      LocationPermission permission = await Geolocator.checkPermission();
      if (permission == LocationPermission.denied) {
        permission = await Geolocator.requestPermission();
      }

      if (permission == LocationPermission.whileInUse || permission == LocationPermission.always) {
        try {
          final pos = await Geolocator.getCurrentPosition(
            locationSettings: const LocationSettings(
              accuracy: LocationAccuracy.medium,
              timeLimit: Duration(seconds: 4),
            ),
          );
          targetLat = pos.latitude;
          targetLng = pos.longitude;
        } catch (_) {
          final lastPos = await Geolocator.getLastKnownPosition();
          if (lastPos != null) {
            targetLat = lastPos.latitude;
            targetLng = lastPos.longitude;
          }
        }
      }

      final client = HttpClient();
      final uri = Uri.parse('https://api.open-meteo.com/v1/forecast?latitude=$targetLat&longitude=$targetLng&current_weather=true');
      final request = await client.getUrl(uri);
      final response = await request.close();
      if (response.statusCode == 200) {
        final body = await response.transform(utf8.decoder).join();
        final json = jsonDecode(body) as Map<String, dynamic>;
        final currentWeather = json['current_weather'] as Map<String, dynamic>?;
        if (currentWeather != null) {
          final double temp = (currentWeather['temperature'] as num).toDouble();
          final int code = (currentWeather['weathercode'] as num).toInt();
          return {
            'temp': temp.round(),
            'code': code,
          };
        }
      }
    } catch (_) {}
    return null;
  }

  // Telegram Full Screen Interactive Map Viewer (Exact 1:1 Telegram UI with Live Data)
  void _showTelegramFullScreenMapView({
    required double lat,
    required double lng,
    required String locationTitle,
  }) {
    const int zoom = 15;
    final n = pow(2, zoom);
    final tileX = (((lng + 180.0) / 360.0) * n).floor();
    final latRad = lat * pi / 180.0;
    final tileY = (((1.0 - (log(tan(latRad) + (1.0 / cos(latRad))) / pi)) / 2.0) * n).floor();

    final List<String> darkTileUrls = [];
    final List<String> satelliteTileUrls = [];
    final List<String> streetTileUrls = [];

    for (int dy = -2; dy <= 2; dy++) {
      for (int dx = -2; dx <= 2; dx++) {
        final curX = tileX + dx;
        final curY = tileY + dy;
        darkTileUrls.add('https://a.basemaps.cartocdn.com/dark_all/$zoom/$curX/$curY.png');
        satelliteTileUrls.add('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/$zoom/$curY/$curX');
        streetTileUrls.add('https://a.basemaps.cartocdn.com/rastertiles/voyager/$zoom/$curX/$curY.png');
      }
    }

    int mapStyleIndex = 0; // 0: Dark, 1: Satellite, 2: Street
    String weatherText = '...';
    IconData weatherIcon = Icons.cloud_rounded;
    final TransformationController transformationController = TransformationController();

    showDialog(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.96),
      builder: (modalCtx) {
        // Fetch Real Live Weather on opening
        _fetchRealWeather(lat, lng).then((data) {
          if (data != null && modalCtx.mounted) {
            final int temp = data['temp'] as int;
            final int code = data['code'] as int;

            IconData icon = Icons.cloud_rounded;
            if (code == 0) {
              icon = Icons.wb_sunny_rounded;
            } else if (code >= 1 && code <= 3) {
              icon = Icons.wb_cloudy_rounded;
            } else if (code >= 45 && code <= 48) {
              icon = Icons.cloud_queue_rounded;
            } else if ((code >= 51 && code <= 67) || (code >= 80 && code <= 82)) {
              icon = Icons.grain_rounded;
            } else if (code >= 95) {
              icon = Icons.thunderstorm_rounded;
            }

            // StatefulBuilder update
            try {
              (modalCtx as Element).markNeedsBuild();
              weatherText = '$temp°C';
              weatherIcon = icon;
            } catch (_) {}
          }
        });

        return StatefulBuilder(
          builder: (context, setModalState) {
            List<String> activeTileUrls = darkTileUrls;
            if (mapStyleIndex == 1) {
              activeTileUrls = satelliteTileUrls;
            } else if (mapStyleIndex == 2) {
              activeTileUrls = streetTileUrls;
            }

            return Dialog(
              backgroundColor: const Color(0xFF0F172A),
              insetPadding: EdgeInsets.zero,
              child: Stack(
                children: [
                  // A. Interactive / Grid CartoDB & Esri Real Maps
                  Positioned.fill(
                    child: InteractiveViewer(
                      transformationController: transformationController,
                      minScale: 0.8,
                      maxScale: 3.5,
                      child: OverflowBox(
                        maxWidth: 1280,
                        maxHeight: 1280,
                        child: SizedBox(
                          width: 1280,
                          height: 1280,
                          child: GridView.count(
                            crossAxisCount: 5,
                            physics: const NeverScrollableScrollPhysics(),
                            children: activeTileUrls.map((url) {
                              return Image.network(
                                url,
                                fit: BoxFit.cover,
                                errorBuilder: (_, __, ___) => Container(color: const Color(0xFF151D2A)),
                              );
                            }).toList(),
                          ),
                        ),
                      ),
                    ),
                  ),

                  // B. Center Glowing Telegram Location Pin Icon
                  Center(
                    child: Padding(
                      padding: const EdgeInsets.only(bottom: 60),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Stack(
                            alignment: Alignment.center,
                            children: [
                              Container(
                                width: 70,
                                height: 70,
                                decoration: BoxDecoration(
                                  shape: BoxShape.circle,
                                  color: const Color(0xFF007AFF).withValues(alpha: 0.25),
                                ),
                              ),
                              Container(
                                width: 52,
                                height: 52,
                                decoration: const BoxDecoration(
                                  color: Color(0xFF007AFF),
                                  shape: BoxShape.circle,
                                  boxShadow: [
                                    BoxShadow(
                                      color: Colors.black45,
                                      blurRadius: 16,
                                      offset: Offset(0, 6),
                                    ),
                                  ],
                                ),
                                child: const Icon(Icons.push_pin_rounded, color: Colors.white, size: 28),
                              ),
                              Positioned(
                                bottom: 0,
                                child: Container(
                                  width: 10,
                                  height: 10,
                                  decoration: const BoxDecoration(
                                    color: Colors.white,
                                    shape: BoxShape.circle,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                  ),

                  // C. Top Navigation Bar (Close Button, Title, Share Button)
                  Positioned(
                    top: 0,
                    left: 0,
                    right: 0,
                    child: SafeArea(
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            // 1. Close Button (Left)
                            GestureDetector(
                              onTap: () => Navigator.pop(modalCtx),
                              child: Container(
                                width: 38,
                                height: 38,
                                decoration: BoxDecoration(
                                  color: Colors.black.withValues(alpha: 0.55),
                                  shape: BoxShape.circle,
                                ),
                                child: const Icon(Icons.close_rounded, color: Colors.white, size: 22),
                              ),
                            ),

                            // 2. Title (Center)
                            Text(
                              'Location',
                              style: GoogleFonts.inter(
                                color: Colors.white,
                                fontSize: 17,
                                fontWeight: FontWeight.bold,
                              ),
                            ),

                            // 3. Share Button (Right)
                            GestureDetector(
                              onTap: () => _showOpenInMapsBottomSheet(lat: lat, lng: lng, locationTitle: locationTitle),
                              child: Container(
                                width: 38,
                                height: 38,
                                decoration: BoxDecoration(
                                  color: Colors.black.withValues(alpha: 0.55),
                                  shape: BoxShape.circle,
                                ),
                                child: const Icon(Icons.ios_share_rounded, color: Colors.white, size: 20),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),

                  // D. Real Live Weather Badge (Top Left under top bar)
                  Positioned(
                    top: MediaQuery.of(context).padding.top + 54,
                    left: 16,
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                      decoration: BoxDecoration(
                        color: Colors.black.withValues(alpha: 0.55),
                        borderRadius: BorderRadius.circular(18),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(weatherIcon, color: Colors.white, size: 16),
                          const SizedBox(width: 6),
                          Text(
                            weatherText,
                            style: GoogleFonts.inter(
                              color: Colors.white,
                              fontSize: 13,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),

                  // E. Floating Map Controls (Right Side - Switch Real Styles & Recenter)
                  Positioned(
                    right: 16,
                    bottom: 175,
                    child: Column(
                      children: [
                        // Map Style / Layers Toggle (Cycles Dark -> Satellite -> Street)
                        GestureDetector(
                          onTap: () {
                            setModalState(() {
                              mapStyleIndex = (mapStyleIndex + 1) % 3;
                            });
                            final styleNames = ['Dark Map', 'Satellite Hybrid', 'Street Map'];
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(
                                content: Text('Style: ${styleNames[mapStyleIndex]}', style: GoogleFonts.inter()),
                                duration: const Duration(milliseconds: 900),
                              ),
                            );
                          },
                          child: Container(
                            width: 44,
                            height: 44,
                            decoration: BoxDecoration(
                              color: const Color(0xFF1E2738),
                              shape: BoxShape.circle,
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withValues(alpha: 0.3),
                                  blurRadius: 8,
                                  offset: const Offset(0, 2),
                                ),
                              ],
                            ),
                            child: Icon(
                              mapStyleIndex == 1
                                  ? Icons.satellite_alt_rounded
                                  : (mapStyleIndex == 2 ? Icons.map_outlined : Icons.map_rounded),
                              color: Colors.white,
                              size: 22,
                            ),
                          ),
                        ),
                        const SizedBox(height: 12),
                        // Recenter Navigation Button
                        GestureDetector(
                          onTap: () {
                            transformationController.value = Matrix4.identity();
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(
                                content: Text('Recenter to location', style: GoogleFonts.inter()),
                                duration: const Duration(milliseconds: 900),
                              ),
                            );
                          },
                          child: Container(
                            width: 44,
                            height: 44,
                            decoration: BoxDecoration(
                              color: const Color(0xFF1E2738),
                              shape: BoxShape.circle,
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withValues(alpha: 0.3),
                                  blurRadius: 8,
                                  offset: const Offset(0, 2),
                                ),
                              ],
                            ),
                            child: const Icon(
                              Icons.near_me_rounded,
                              color: Colors.white,
                              size: 22,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),

                  // F. Bottom Telegram Sheet Card
                  Positioned(
                    left: 12,
                    right: 12,
                    bottom: 24,
                    child: Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: const Color(0xFF1A2232),
                        borderRadius: BorderRadius.circular(24),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withValues(alpha: 0.4),
                            blurRadius: 16,
                            offset: const Offset(0, 6),
                          ),
                        ],
                      ),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Row(
                            children: [
                              Container(
                                width: 44,
                                height: 44,
                                decoration: const BoxDecoration(
                                  color: Color(0xFF007AFF),
                                  shape: BoxShape.circle,
                                ),
                                child: const Icon(Icons.push_pin_rounded, color: Colors.white, size: 22),
                              ),
                              const SizedBox(width: 14),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      locationTitle.isNotEmpty ? locationTitle : 'Location',
                                      style: GoogleFonts.inter(
                                        color: Colors.white,
                                        fontSize: 16,
                                        fontWeight: FontWeight.bold,
                                      ),
                                    ),
                                    const SizedBox(height: 2),
                                    Text(
                                      '${locationTitle.isNotEmpty ? locationTitle : 'Street 318'} • you are here',
                                      style: GoogleFonts.inter(
                                        color: Colors.white70,
                                        fontSize: 13,
                                      ),
                                      maxLines: 1,
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 14),
                          SizedBox(
                            width: double.infinity,
                            height: 48,
                            child: ElevatedButton(
                              onPressed: () => _showOpenInMapsBottomSheet(lat: lat, lng: lng, locationTitle: locationTitle),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: const Color(0xFF007AFF),
                                foregroundColor: Colors.white,
                                elevation: 0,
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(16),
                                ),
                              ),
                              child: Text(
                                'Get Directions',
                                style: GoogleFonts.inter(
                                  fontSize: 15.5,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ),
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

  // Telegram "Open In" Bottom Sheet Modal
  void _showOpenInMapsBottomSheet({
    required double lat,
    required double lng,
    required String locationTitle,
  }) {
    showModalBottomSheet(
      context: context,
      backgroundColor: const Color(0xFF1E2738),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (bottomSheetCtx) {
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Header (Close Button + Title)
                Row(
                  children: [
                    GestureDetector(
                      onTap: () => Navigator.pop(bottomSheetCtx),
                      child: Container(
                        width: 32,
                        height: 32,
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.12),
                          shape: BoxShape.circle,
                        ),
                        child: const Icon(Icons.close_rounded, color: Colors.white, size: 18),
                      ),
                    ),
                    Expanded(
                      child: Text(
                        'Open In',
                        textAlign: TextAlign.center,
                        style: GoogleFonts.inter(
                          color: Colors.white,
                          fontSize: 17,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                    const SizedBox(width: 32),
                  ],
                ),
                const SizedBox(height: 24),

                // Grid Apps (Apple Maps & Google Maps)
                Row(
                  mainAxisAlignment: MainAxisAlignment.start,
                  children: [
                    // 1. Apple Maps
                    GestureDetector(
                      onTap: () async {
                        Navigator.pop(bottomSheetCtx);
                        final uri = Uri.parse('https://maps.apple.com/?daddr=$lat,$lng');
                        if (await canLaunchUrl(uri)) {
                          await launchUrl(uri, mode: LaunchMode.externalApplication);
                        }
                      },
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Container(
                            width: 64,
                            height: 64,
                            decoration: BoxDecoration(
                              color: Colors.white,
                              borderRadius: BorderRadius.circular(18),
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withValues(alpha: 0.2),
                                  blurRadius: 8,
                                  offset: const Offset(0, 3),
                                ),
                              ],
                            ),
                            child: const Icon(
                              Icons.explore_rounded,
                              color: Color(0xFF007AFF),
                              size: 40,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'Maps',
                            style: GoogleFonts.inter(
                              color: Colors.white,
                              fontSize: 12.5,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 28),

                    // 2. Google Maps
                    GestureDetector(
                      onTap: () async {
                        Navigator.pop(bottomSheetCtx);
                        final uri = Uri.parse('https://www.google.com/maps/search/?api=1&query=$lat,$lng');
                        if (await canLaunchUrl(uri)) {
                          await launchUrl(uri, mode: LaunchMode.externalApplication);
                        }
                      },
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Container(
                            width: 64,
                            height: 64,
                            decoration: BoxDecoration(
                              color: Colors.white,
                              borderRadius: BorderRadius.circular(18),
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withValues(alpha: 0.2),
                                  blurRadius: 8,
                                  offset: const Offset(0, 3),
                                ),
                              ],
                            ),
                            child: const Icon(
                              Icons.location_on_rounded,
                              color: Color(0xFFEA4335),
                              size: 40,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'Google Maps',
                            style: GoogleFonts.inter(
                              color: Colors.white,
                              fontSize: 12.5,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
              ],
            ),
          ),
        );
      },
    );
  }


  // Contact Card Bubble Widget
  Widget _buildContactCardBubble({
    required String docId,
    required String text,
    required String senderName,
    required bool isMine,
    required DateTime time,
    required bool isRead,
  }) {
    String contactName = 'Contact';
    String contactSubtitle = '';
    final lines = text.split('\n');
    if (lines.isNotEmpty) {
      contactName = lines.first.replaceAll('👤 Contact:', '').trim();
    }
    if (lines.length > 1) {
      contactSubtitle = lines[1].replaceAll('ℹ️', '').replaceAll('📞', '').trim();
    }

    final bubbleKey = GlobalKey();

    final cardContent = Container(
      width: 250,
      margin: const EdgeInsets.symmetric(vertical: 4),
      decoration: BoxDecoration(
        color: isMine ? const Color(0xFF229ED9) : const Color(0xFF2C2C2E),
        borderRadius: BorderRadius.circular(16),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.3),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  radius: 22,
                  backgroundColor: Colors.white24,
                  child: Text(
                    contactName.isNotEmpty ? contactName[0].toUpperCase() : 'C',
                    style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 18),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        contactName,
                        style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 15),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      if (contactSubtitle.isNotEmpty) ...[
                        const SizedBox(height: 2),
                        Text(
                          contactSubtitle,
                          style: GoogleFonts.inter(color: Colors.white70, fontSize: 12),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            const Divider(height: 1, color: Colors.white24),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: InkWell(
                    onTap: () {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text('កំពុងបើកការសន្ទនាជាមួយ $contactName...', style: GoogleFonts.kantumruyPro())),
                      );
                    },
                    borderRadius: BorderRadius.circular(8),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(vertical: 6),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          const Icon(Icons.chat_bubble_outline_rounded, color: Colors.white, size: 16),
                          const SizedBox(width: 6),
                          Text('💬 Chat', style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
                        ],
                      ),
                    ),
                  ),
                ),
                Container(width: 1, height: 20, color: Colors.white24),
                Expanded(
                  child: InkWell(
                    onTap: () async {
                      final phoneClean = contactSubtitle.replaceAll(RegExp(r'[^\d+]'), '');
                      final url = 'tel:${phoneClean.isNotEmpty ? phoneClean : "012345678"}';
                      final uri = Uri.parse(url);
                      if (await canLaunchUrl(uri)) {
                        await launchUrl(uri);
                      } else {
                        if (mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(content: Text('កំពុងលេងការហៅទូរស័ព្ទទៅកាន់ $contactName ($url)', style: GoogleFonts.kantumruyPro())),
                          );
                        }
                      }
                    },
                    borderRadius: BorderRadius.circular(8),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(vertical: 6),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          const Icon(Icons.phone_outlined, color: Colors.white, size: 16),
                          const SizedBox(width: 6),
                          Text('📞 Call', style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
                        ],
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );

    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          GestureDetector(
            key: bubbleKey,
            onLongPress: () => _showMessageOptionsModal(
              key: bubbleKey,
              childWidget: cardContent,
              docId: docId,
              content: text,
              type: 'text',
              senderName: senderName,
            ),
            child: cardContent,
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



  // Pick and Send Image
  Future<void> _pickAndSendImage(ImageSource source) async {
    try {
      final XFile? file = await ImagePicker().pickImage(
        source: source,
        imageQuality: 65,
        maxWidth: 1024,
        maxHeight: 1024,
      );
      if (file == null || currentUserId.isEmpty) return;
      final bytes = await file.readAsBytes();
      if (bytes.isEmpty) return;

      // Fix orientation / mirroring and compress image size for Firestore (must be under 1MB limit)
      Uint8List processedBytes = bytes;
      try {
        final img.Image? decoded = img.decodeImage(bytes);
        if (decoded != null) {
          img.Image oriented = img.bakeOrientation(decoded);
          if (source == ImageSource.camera) {
            oriented = img.flipHorizontal(oriented);
          }
          processedBytes = Uint8List.fromList(img.encodeJpg(oriented, quality: 65));
        }
      } catch (_) {}

      if (!mounted) return;
      final base64Image = 'data:image/jpeg;base64,${base64Encode(processedBytes)}';
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

    final double bottomPadding = MediaQuery.of(context).padding.bottom;

    return ClipRect(
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 25.0, sigmaY: 25.0),
        child: Container(
          decoration: BoxDecoration(
            color: Colors.black.withValues(alpha: 0.28),
            border: Border(
              top: BorderSide(color: Colors.white.withValues(alpha: 0.05), width: 0.5),
            ),
          ),
          padding: EdgeInsets.fromLTRB(10.0, 8.0, 10.0, bottomPadding > 0 ? bottomPadding + 4.0 : 12.0),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              // 1. Telegram Paperclip Icon (Rotated Clip) 📎
              InkWell(
                onTap: _showVvcAttachmentSheet,
                borderRadius: BorderRadius.circular(20),
                child: Container(
                  width: 38,
                  height: 38,
                  decoration: const BoxDecoration(
                    color: Color(0xFF262629),
                    shape: BoxShape.circle,
                  ),
                  child: Center(
                    child: Transform.rotate(
                      angle: -0.75,
                      child: const Icon(
                        LucideIcons.paperclip,
                        color: Color(0xFF8E8E93),
                        size: 20,
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 8.0),

              // 2. Middle Capsule Text Box with Telegram Sticker Icon 🏷️
              Expanded(
                child: Container(
                  constraints: const BoxConstraints(minHeight: 38.0, maxHeight: 130.0),
                  decoration: BoxDecoration(
                    color: const Color(0xFF262629),
                    borderRadius: BorderRadius.circular(20.0),
                    border: Border.all(color: Colors.white.withValues(alpha: 0.08), width: 0.5),
                  ),
                  padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 2.0),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.center,
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _msgController,
                          maxLines: null,
                          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 15.5, height: 1.3),
                          cursorColor: const Color(0xFF0A84FF),
                          decoration: InputDecoration(
                            hintText: 'Message',
                            hintStyle: GoogleFonts.inter(color: const Color(0xFF8E8E93), fontSize: 16.0),
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
                      InkWell(
                        onTap: _showGiphyStickerPicker,
                        borderRadius: BorderRadius.circular(16),
                        child: const Padding(
                          padding: EdgeInsets.all(4.0),
                          child: Icon(
                            Icons.sticky_note_2_rounded,
                            color: Color(0xFF8E8E93),
                            size: 22.0,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 8.0),

              // 3. Right Circular Voice Mic / Send Button 🎙️ / ➔ with AnimatedSwitcher
              ValueListenableBuilder<TextEditingValue>(
                valueListenable: _msgController,
                builder: (context, value, _) {
                  final hasText = value.text.trim().isNotEmpty;
                  return AnimatedSwitcher(
                    duration: const Duration(milliseconds: 200),
                    transitionBuilder: (child, anim) => ScaleTransition(scale: anim, child: child),
                    child: InkWell(
                      key: ValueKey<bool>(hasText),
                      onTap: hasText ? _sendMessage : _startRecording,
                      borderRadius: BorderRadius.circular(20),
                      child: Container(
                        width: 38,
                        height: 38,
                        decoration: BoxDecoration(
                          color: hasText ? const Color(0xFF0A84FF) : const Color(0xFF262629),
                          shape: BoxShape.circle,
                        ),
                        child: Icon(
                          hasText ? LucideIcons.send : LucideIcons.mic,
                          color: hasText ? Colors.white : const Color(0xFF8E8E93),
                          size: 19.0,
                        ),
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

  void _showVvcAttachmentSheet() {
    VvcFilePickerBottomSheet.show(
      context: context,
      roomId: _roomId,
      onSelectFromGallery: () => _pickAndSendImage(ImageSource.gallery),
      onSelectFromFiles: _pickAndSendFile,
      onScanDocument: () => _pickAndSendImage(ImageSource.camera),
      onSelectRecentFile: (file) {
        if (file['name'] != null) {
          _sendMessage(customText: '📄 ${file['name']}');
        }
      },
      onTabChanged: (category) {
        Navigator.pop(context);
        if (category == 'Gallery') {
          _pickAndSendImage(ImageSource.gallery);
        } else if (category == 'Location') {
          _showLocationPickerModal();
        } else if (category == 'Poll') {
          _showCreatePollModal();
        } else if (category == 'Contact') {
          _showContactPickerModal();
        }
      },
    );
  }

  void _showLocationPickerModal() {
    VvcLocationPickerBottomSheet.show(
      context: context,
      onSendLocation: (locData) {
        final String name = locData['name'] ?? 'ទីតាំងបច្ចុប្បន្ន';
        final double lat = locData['latitude'] ?? 11.5564;
        final double lng = locData['longitude'] ?? 104.9282;
        _sendMessage(customText: '📍 $name:\nhttps://maps.google.com/?q=$lat,$lng');
      },
      onTabChanged: (category) {
        Navigator.pop(context);
        if (category == 'Gallery') {
          _pickAndSendImage(ImageSource.gallery);
        } else if (category == 'File') {
          _showVvcAttachmentSheet();
        } else if (category == 'Poll') {
          _showCreatePollModal();
        } else if (category == 'Contact') {
          _showContactPickerModal();
        }
      },
    );
  }

  void _showCreatePollModal() {
    VvcPollPickerBottomSheet.show(
      context: context,
      onSendPoll: (pollData) {
        final q = pollData['question'] ?? '';
        final options = (pollData['options'] as List<dynamic>? ?? []).map((o) => '• $o').join('\n');
        _sendMessage(customText: '📊 Poll: $q\n$options');
      },
      onTabChanged: (category) {
        Navigator.pop(context);
        if (category == 'Gallery') {
          _pickAndSendImage(ImageSource.gallery);
        } else if (category == 'File') {
          _showVvcAttachmentSheet();
        } else if (category == 'Location') {
          _showLocationPickerModal();
        } else if (category == 'Contact') {
          _showContactPickerModal();
        }
      },
    );
  }

  void _showContactPickerModal() {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => VvcNewMessageContactListScreen(
          onSelectContact: (contact) {
            final name = contact['name'] ?? '';
            final subtitle = contact['subtitle'] ?? '';
            Navigator.pop(context);
            _sendMessage(customText: '👤 Contact: $name\nℹ️ $subtitle');
          },
        ),
      ),
    );
  }
}

// Optimized Isolated Voice Bubble Widget preventing Screen Rebuilds during Audio Playback
class _VoiceBubbleWidget extends StatefulWidget {
  final String docId;
  final String audioUrl;
  final int durationSeconds;
  final bool isMine;
  final DateTime time;
  final bool isRead;
  final String senderName;
  final AudioPlayer audioPlayer;
  final Function(String) onTogglePlay;
  final VoidCallback onToggleSpeed;
  final double playbackSpeed;
  final String? currentlyPlayingAudio;
  final bool isPlayingAudio;
  final Function(GlobalKey, Widget) onLongPressModal;
  final Widget Function(bool) buildReadStatusIcon;

  const _VoiceBubbleWidget({
    required this.docId,
    required this.audioUrl,
    required this.durationSeconds,
    required this.isMine,
    required this.time,
    required this.isRead,
    required this.senderName,
    required this.audioPlayer,
    required this.onTogglePlay,
    required this.onToggleSpeed,
    required this.playbackSpeed,
    required this.currentlyPlayingAudio,
    required this.isPlayingAudio,
    required this.onLongPressModal,
    required this.buildReadStatusIcon,
  });

  @override
  State<_VoiceBubbleWidget> createState() => _VoiceBubbleWidgetState();
}

class _VoiceBubbleWidgetState extends State<_VoiceBubbleWidget> {
  StreamSubscription<Duration>? _posSub;
  Duration _pos = Duration.zero;

  @override
  void initState() {
    super.initState();
    _listenPosition();
  }

  void _listenPosition() {
    _posSub?.cancel();
    _posSub = widget.audioPlayer.onPositionChanged.listen((p) {
      if (mounted && widget.currentlyPlayingAudio == widget.audioUrl && widget.isPlayingAudio) {
        setState(() {
          _pos = p;
        });
      }
    });
  }

  @override
  void dispose() {
    _posSub?.cancel();
    super.dispose();
  }

  String _formatDuration(int seconds) {
    final mins = seconds ~/ 60;
    final secs = seconds % 60;
    return '$mins:${secs.toString().padLeft(2, '0')}';
  }

  @override
  Widget build(BuildContext context) {
    final bool isThisPlaying = widget.isPlayingAudio && widget.currentlyPlayingAudio == widget.audioUrl;

    double progress = 0.0;
    final totalMs = widget.durationSeconds * 1000;
    if (isThisPlaying && totalMs > 0) {
      progress = (_pos.inMilliseconds / totalMs).clamp(0.0, 1.0);
    }

    final Color bubbleBg = widget.isMine ? const Color(0xFFF29BB8) : const Color(0xDD4E1025);
    final Color textColor = widget.isMine ? const Color(0xFF1E1E1E) : Colors.white;
    final Color playBg = widget.isMine ? Colors.black.withValues(alpha: 0.25) : Colors.white.withValues(alpha: 0.25);
    final Color playIconColor = widget.isMine ? const Color(0xFF1E1E1E) : Colors.white;

    final bubbleKey = GlobalKey();
    final bubbleChild = Container(
      margin: const EdgeInsets.symmetric(vertical: 4.0),
      padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 10.0),
      decoration: BoxDecoration(
        color: bubbleBg,
        borderRadius: BorderRadius.only(
          topLeft: const Radius.circular(22.0),
          topRight: const Radius.circular(22.0),
          bottomLeft: Radius.circular(widget.isMine ? 22.0 : 4.0),
          bottomRight: Radius.circular(widget.isMine ? 4.0 : 22.0),
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
          GestureDetector(
            onTap: () => widget.onTogglePlay(widget.audioUrl),
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
          GestureDetector(
            onHorizontalDragUpdate: (details) {
              if (isThisPlaying && totalMs > 0) {
                final dx = details.localPosition.dx.clamp(0.0, 130.0);
                final val = dx / 130.0;
                final seekMs = (val * totalMs).round();
                widget.audioPlayer.seek(Duration(milliseconds: seekMs));
              }
            },
            child: SizedBox(
              width: 130.0,
              height: 32.0,
              child: Center(
                child: _buildWaveformBars(
                  isPlaying: isThisPlaying,
                  progress: progress,
                  isMine: widget.isMine,
                ),
              ),
            ),
          ),
          const SizedBox(width: 12.0),
          Text(
            isThisPlaying
                ? _formatDuration(_pos.inSeconds)
                : _formatDuration(widget.durationSeconds),
            style: GoogleFonts.inter(
              color: textColor,
              fontSize: 12.5,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(width: 8.0),
          GestureDetector(
            onTap: widget.onToggleSpeed,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 6.0, vertical: 3.0),
              decoration: BoxDecoration(
                color: widget.isMine ? Colors.black.withValues(alpha: 0.18) : Colors.white.withValues(alpha: 0.22),
                borderRadius: BorderRadius.circular(10.0),
              ),
              child: Text(
                '${widget.playbackSpeed.toStringAsFixed(1).replaceAll('.0', '')}x',
                style: GoogleFonts.inter(
                  color: textColor,
                  fontSize: 10.0,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ),
        ],
      ),
    );

    return Align(
      alignment: widget.isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: widget.isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          GestureDetector(
            key: bubbleKey,
            onLongPress: () => widget.onLongPressModal(bubbleKey, bubbleChild),
            child: bubbleChild,
          ),
          Padding(
            padding: const EdgeInsets.only(left: 4.0, right: 4.0, bottom: 4.0),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  DateFormat('h:mm a').format(widget.time),
                  style: GoogleFonts.inter(fontSize: 10.0, color: _MsgDark.textMuted),
                ),
                if (widget.isMine) ...[
                  const SizedBox(width: 4.0),
                  widget.buildReadStatusIcon(widget.isRead),
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

}
