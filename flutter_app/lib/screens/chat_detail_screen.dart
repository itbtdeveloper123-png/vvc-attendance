import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';

// ==========================================
// MESSENGER DARK THEME TOKENS
// ==========================================
class _MsgDark {
  static const Color bg = Color(0xFF000000);
  static const Color card = Color(0xFF242526);
  static const Color inputBg = Color(0xFF3A3B3C);
  static const Color sentBubble = Color(0xFF0084FF);
  static const Color receivedBubble = Color(0xFF3A3B3C);
  static const Color textPrimary = Color(0xFFFFFFFF);
  static const Color textMuted = Color(0xFFB0B3B8);
  static const Color iconColor = Color(0xFF0084FF);
}

// ==========================================
// DATA MODELS
// ==========================================
enum MessageType { text, sticker, callMissed, callVideo, security }

class ChatMessage {
  final String id;
  final String text;
  final MessageType type;
  final bool isSentByMe;
  final DateTime timestamp;
  final String? callDuration;
  final bool showAvatar;

  const ChatMessage({
    required this.id,
    required this.text,
    required this.type,
    required this.isSentByMe,
    required this.timestamp,
    this.callDuration,
    this.showAvatar = false,
  });
}

// ==========================================
// MAIN SCREEN WIDGET
// ==========================================
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

  String currentUserId = '';
  String currentUserPhoto = '';
  List<DocumentSnapshot> _messageDocs = [];
  StreamSubscription<QuerySnapshot>? _messageSubscription;
  bool _isLoadingHistory = true;
  String get _roomId {
    if (widget.isGroup) return widget.targetUserId;
    final List<String> ids = [currentUserId, widget.targetUserId]..sort();
    return 'PRIVATE_${ids[0]}_${ids[1]}';
  }

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    final prefs = await SharedPreferences.getInstance();
    currentUserId = prefs.getString('employee_id') ?? '';
    currentUserPhoto = prefs.getString('avatar') ?? '';
    _listenMessages();
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
        WidgetsBinding.instance.addPostFrameCallback((_) => _scrollToBottom());
      }
    });
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
    };

    final batch = _firestore.batch();
    final msgRef = _firestore.collection('chats').doc(_roomId).collection('messages').doc();
    batch.set(msgRef, msgData);
    batch.set(_firestore.collection('chats').doc(_roomId), {
      'participants': [currentUserId, widget.targetUserId],
      'lastMessage': text,
      'lastTimestamp': FieldValue.serverTimestamp(),
      'lastSenderId': currentUserId,
    }, SetOptions(merge: true));
    await batch.commit();
  }

  @override
  void dispose() {
    _messageSubscription?.cancel();
    _msgController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _MsgDark.bg,
      body: SafeArea(
        child: Column(
          children: [
            _buildHeader(),
            Expanded(child: _buildMessageFeed()),
            _buildInputToolbar(),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // A. CUSTOM HEADER / APP BAR
  // ==========================================
  Widget _buildHeader() {
    return Container(
      color: _MsgDark.bg,
      padding: const EdgeInsets.symmetric(horizontal: 6.0, vertical: 8.0),
      child: Row(
        children: [
          // Back arrow
          IconButton(
            icon: const Icon(Icons.arrow_back_ios_new_rounded, color: _MsgDark.iconColor, size: 20),
            onPressed: () => Navigator.pop(context),
          ),

          // Avatar
          CircleAvatar(
            radius: 20.0,
            backgroundImage: widget.targetUserPhoto.isNotEmpty
                ? NetworkImage(ApiService.getFullImageUrl(widget.targetUserPhoto))
                : null,
            backgroundColor: _MsgDark.card,
            child: widget.targetUserPhoto.isEmpty
                ? Text(
                    widget.targetUserName.isNotEmpty ? widget.targetUserName[0].toUpperCase() : 'U',
                    style: GoogleFonts.inter(color: _MsgDark.textPrimary, fontWeight: FontWeight.bold),
                  )
                : null,
          ),
          const SizedBox(width: 10.0),

          // Name & status
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  widget.targetUserName,
                  style: GoogleFonts.kantumruyPro(
                    color: _MsgDark.textPrimary,
                    fontWeight: FontWeight.bold,
                    fontSize: 16.0,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                StreamBuilder<DocumentSnapshot>(
                  stream: _firestore.collection('users').doc(widget.targetUserId).snapshots(),
                  builder: (context, snap) {
                    String status = 'Offline';
                    Color statusColor = _MsgDark.textMuted;
                    if (snap.hasData && snap.data!.exists) {
                      final data = snap.data!.data() as Map<String, dynamic>?;
                      if (data?['isOnline'] == true) {
                        status = 'Active now';
                        statusColor = const Color(0xFF44B700);
                      } else if (data?['lastActive'] != null) {
                        final last = (data!['lastActive'] as Timestamp).toDate();
                        final diff = DateTime.now().difference(last);
                        if (diff.inMinutes < 60) {
                          status = 'Active ${diff.inMinutes}m ago';
                        } else if (diff.inHours < 24) {
                          status = 'Active ${diff.inHours}h ago';
                        } else {
                          status = 'Active ${diff.inDays}d ago';
                        }
                      }
                    }
                    return Text(
                      status,
                      style: GoogleFonts.inter(
                        fontSize: 12.0,
                        color: statusColor,
                        fontWeight: FontWeight.w400,
                      ),
                    );
                  },
                ),
              ],
            ),
          ),

          // Audio call button
          _buildHeaderIconBtn(Icons.call_rounded, onTap: () {}),
          _buildHeaderIconBtn(Icons.videocam_rounded, onTap: () {}),
        ],
      ),
    );
  }

  Widget _buildHeaderIconBtn(IconData icon, {required VoidCallback onTap}) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 36.0,
        height: 36.0,
        margin: const EdgeInsets.only(left: 4.0),
        decoration: const BoxDecoration(
          color: Color(0xFF3A3B3C),
          shape: BoxShape.circle,
        ),
        child: Icon(icon, size: 18.0, color: _MsgDark.iconColor),
      ),
    );
  }

  // ==========================================
  // B. MESSAGE FEED
  // ==========================================
  Widget _buildMessageFeed() {
    if (_isLoadingHistory) {
      return const Center(child: CircularProgressIndicator(color: _MsgDark.iconColor, strokeWidth: 2));
    }

    if (_messageDocs.isEmpty) {
      return _buildEmptyState();
    }

    return ListView.builder(
      controller: _scrollController,
      physics: const BouncingScrollPhysics(),
      padding: const EdgeInsets.symmetric(horizontal: 12.0, vertical: 8.0),
      itemCount: _messageDocs.length,
      itemBuilder: (context, index) {
        final doc = _messageDocs[index];
        final data = doc.data() as Map<String, dynamic>;
        final isMine = (data['senderId'] ?? '') == currentUserId;
        final Timestamp? ts = data['timestamp'] as Timestamp?;
        final DateTime msgTime = ts?.toDate() ?? DateTime.now();
        final String msgType = data['type'] ?? 'text';
        final String text = data['text'] ?? '';

        // Show date divider if day changed from previous message
        final bool showDivider = _shouldShowDateDivider(index, ts);

        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (showDivider) _buildDateDivider(msgTime),
            if (msgType == 'callMissed') _buildCallEventCard(isMissed: true, time: msgTime),
            if (msgType == 'callVideo') _buildCallEventCard(isMissed: false, time: msgTime),
            if (msgType == 'text') _buildTextBubble(text: text, isMine: isMine, time: msgTime),
            if (msgType == 'sticker') _buildStickerBubble(text: text, isMine: isMine),
          ],
        );
      },
    );
  }

  bool _shouldShowDateDivider(int index, Timestamp? ts) {
    if (ts == null) return false;
    if (index == 0) return true;
    final prevDoc = _messageDocs[index - 1];
    final prevData = prevDoc.data() as Map<String, dynamic>;
    final Timestamp? prevTs = prevData['timestamp'] as Timestamp?;
    if (prevTs == null) return false;
    final cur = ts.toDate();
    final prev = prevTs.toDate();
    return cur.day != prev.day || cur.month != prev.month || cur.year != prev.year;
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          CircleAvatar(
            radius: 40.0,
            backgroundImage: widget.targetUserPhoto.isNotEmpty
                ? NetworkImage(ApiService.getFullImageUrl(widget.targetUserPhoto))
                : null,
            backgroundColor: _MsgDark.card,
            child: widget.targetUserPhoto.isEmpty
                ? Text(
                    widget.targetUserName.isNotEmpty ? widget.targetUserName[0].toUpperCase() : 'U',
                    style: GoogleFonts.inter(color: _MsgDark.textPrimary, fontSize: 28, fontWeight: FontWeight.bold),
                  )
                : null,
          ),
          const SizedBox(height: 16),
          Text(
            widget.targetUserName,
            style: GoogleFonts.kantumruyPro(
              color: _MsgDark.textPrimary,
              fontSize: 20,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'ចាប់ផ្ដើមការជជែករបស់អ្នក!',
            style: GoogleFonts.kantumruyPro(color: _MsgDark.textMuted, fontSize: 14),
          ),
          const SizedBox(height: 24),
          _buildSecurityBanner(),
        ],
      ),
    );
  }

  // Date Divider
  Widget _buildDateDivider(DateTime date) {
    final now = DateTime.now();
    String label;
    if (date.day == now.day && date.month == now.month && date.year == now.year) {
      label = 'TODAY ${DateFormat('HH:mm').format(date)}';
    } else if (date.year == now.year) {
      label = '${DateFormat('EEE d MMM').format(date).toUpperCase()} AT ${DateFormat('HH:mm').format(date)}';
    } else {
      label = '${DateFormat('d MMM yyyy').format(date).toUpperCase()} AT ${DateFormat('HH:mm').format(date)}';
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 16.0),
      child: Center(
        child: Text(
          label,
          style: GoogleFonts.inter(
            fontSize: 11.0,
            fontWeight: FontWeight.w500,
            color: _MsgDark.textMuted,
            letterSpacing: 0.4,
          ),
        ),
      ),
    );
  }

  // Text Bubble
  Widget _buildTextBubble({
    required String text,
    required bool isMine,
    required DateTime time,
  }) {
    return Align(
      alignment: isMine ? Alignment.centerRight : Alignment.centerLeft,
      child: Column(
        crossAxisAlignment: isMine ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          Container(
            margin: const EdgeInsets.symmetric(vertical: 2.0),
            constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.72),
            padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 10.0),
            decoration: BoxDecoration(
              color: isMine ? _MsgDark.sentBubble : _MsgDark.receivedBubble,
              borderRadius: BorderRadius.only(
                topLeft: const Radius.circular(18.0),
                topRight: const Radius.circular(18.0),
                bottomLeft: Radius.circular(isMine ? 18.0 : 4.0),
                bottomRight: Radius.circular(isMine ? 4.0 : 18.0),
              ),
            ),
            child: Text(
              text,
              style: GoogleFonts.kantumruyPro(
                color: _MsgDark.textPrimary,
                fontSize: 15.0,
                height: 1.4,
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(left: 4.0, right: 4.0, bottom: 4.0),
            child: Text(
              DateFormat('h:mm a').format(time),
              style: GoogleFonts.inter(fontSize: 10.0, color: _MsgDark.textMuted),
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

  // Security Banner
  Widget _buildSecurityBanner() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20.0, vertical: 12.0),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.lock_rounded, size: 14.0, color: _MsgDark.textMuted),
          const SizedBox(width: 6.0),
          Flexible(
            child: RichText(
              textAlign: TextAlign.center,
              text: TextSpan(
                style: GoogleFonts.inter(fontSize: 12.0, color: _MsgDark.textMuted, height: 1.5),
                children: [
                  const TextSpan(
                    text: 'New messages and calls are secured with end-to-end encryption. Only people in this chat can read, listen to or share them. ',
                  ),
                  TextSpan(
                    text: 'Learn more',
                    style: GoogleFonts.inter(
                      fontSize: 12.0,
                      color: _MsgDark.iconColor,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
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
                          isMissed
                              ? DateFormat('h:mm a').format(time)
                              : '4 min, 31 secs',
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
              onTap: () {},
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

  // ==========================================
  // C. BOTTOM INPUT TOOLBAR
  // ==========================================
  Widget _buildInputToolbar() {
    return Container(
      color: _MsgDark.bg,
      padding: const EdgeInsets.fromLTRB(8.0, 8.0, 8.0, 12.0),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          // Action icons left
          _buildToolbarIcon(Icons.add_circle_rounded),
          _buildToolbarIcon(Icons.camera_alt_rounded),
          _buildToolbarIcon(Icons.photo_rounded),
          _buildToolbarIcon(Icons.mic_rounded),
          const SizedBox(width: 4.0),

          // Text input field
          Expanded(
            child: Container(
              constraints: const BoxConstraints(minHeight: 38.0, maxHeight: 120.0),
              decoration: BoxDecoration(
                color: _MsgDark.inputBg,
                borderRadius: BorderRadius.circular(22.0),
              ),
              padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 2.0),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Expanded(
                    child: TextField(
                      controller: _msgController,
                      maxLines: null,
                      style: GoogleFonts.kantumruyPro(color: _MsgDark.textPrimary, fontSize: 15.0),
                      cursorColor: _MsgDark.iconColor,
                      decoration: InputDecoration(
                        hintText: 'Aa',
                        hintStyle: GoogleFonts.inter(color: _MsgDark.textMuted, fontSize: 15.0),
                        border: InputBorder.none,
                        isDense: true,
                        contentPadding: const EdgeInsets.symmetric(vertical: 8.0),
                      ),
                      onSubmitted: (_) => _sendMessage(),
                    ),
                  ),
                  const Icon(Icons.sentiment_satisfied_alt_rounded, color: _MsgDark.iconColor, size: 22.0),
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
                onTap: hasText ? _sendMessage : () {},
                child: Padding(
                  padding: const EdgeInsets.only(left: 2.0, bottom: 6.0),
                  child: Icon(
                    hasText ? Icons.send_rounded : Icons.thumb_up_alt_rounded,
                    color: _MsgDark.iconColor,
                    size: 28.0,
                  ),
                ),
              );
            },
          ),
        ],
      ),
    );
  }

  Widget _buildToolbarIcon(IconData icon) {
    return IconButton(
      icon: Icon(icon, color: _MsgDark.iconColor, size: 26.0),
      onPressed: () {},
      padding: const EdgeInsets.symmetric(horizontal: 4.0),
      constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
    );
  }
}
