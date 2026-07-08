import 'dart:ui';
import 'dart:convert';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:record/record.dart';
import 'package:audioplayers/audioplayers.dart';
import 'package:path_provider/path_provider.dart';
import 'package:flutter/foundation.dart';
import 'package:animate_do/animate_do.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import 'profile_screen.dart';

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

class _TeamChatScreenState extends State<TeamChatScreen> {
  final TextEditingController _msgController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  String currentUserId = '';
  String currentUserPhoto = '';
  final ImagePicker _picker = ImagePicker();
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  Stream<QuerySnapshot>? _messageStream;
  String groupStatus = 'accepted';

  // Audio recording
  late AudioRecorder _recorder;
  bool _isRecording = false;
  String? _audioPath;
  Timer? _recordingTimer;
  int _recordingDuration = 0;

  @override
  void initState() {
    super.initState();
    _recorder = AudioRecorder();
    _loadUser();
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
    if (mounted) setState(() {});
    _updatePresence(true);
  }

  void _setupMessageStream() {
    final roomId = _getChatRoomId();
    final collection = widget.isGroup ? 'groups' : 'chats';
    _messageStream = _firestore
        .collection(collection)
        .doc(roomId)
        .collection('messages')
        .orderBy('timestamp', descending: true)
        .snapshots();
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
    String? editDocId,
  }) async {
    final text = _msgController.text.trim();
    if (text.isEmpty &&
        base64Image == null &&
        base64Audio == null &&
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
        return;
      }

      await _firestore
          .collection(collection)
          .doc(roomId)
          .collection('messages')
          .add({
            'senderId': currentUserId,
            'senderPhoto': currentUserPhoto,
            'message': text,
            'imageBase64': base64Image ?? '',
            'audioBase64': base64Audio ?? '',
            'timestamp': FieldValue.serverTimestamp(),
            'isRead': false,
            'seenBy': [],
            'isEdited': false,
          });

      String lastMsg = text.isNotEmpty
          ? text
          : (base64Image != null
                ? '📷 រូបភាព (Image)'
                : '🎤 សារសំឡេង (Voice Message)');

      await _firestore.collection(collection).doc(roomId).set({
        'lastMessage': lastMsg,
        'lastTimestamp': FieldValue.serverTimestamp(),
        'lastSenderId': currentUserId,
      }, SetOptions(merge: true));

      if (base64Image == null && base64Audio == null) _msgController.clear();
      _scrollToBottom();
    } catch (e) {
      debugPrint(e.toString());
    }
  }

  void _scrollToBottom() {
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        0.0,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeOut,
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
    // Close keyboard first to avoid jumping
    FocusScope.of(context).unfocus();

    try {
      if (await _recorder.hasPermission()) {
        String? path;
        if (!kIsWeb) {
          final dir = await getTemporaryDirectory();
          path =
              '${dir.path}/audio_${DateTime.now().microsecondsSinceEpoch}.m4a';
        }
        _audioPath = path;
        const config = RecordConfig();
        await _recorder.start(config, path: path ?? '');
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
    _msgController.dispose();
    _scrollController.dispose();
    _recorder.dispose();
    _recordingTimer?.cancel();
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
      child: Container(decoration: BoxDecoration(color: AppTheme.bgSurface)),
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
          ),
        ),
      ),
    );
  }

  Widget _buildMessageList() {
    return StreamBuilder<QuerySnapshot>(
      stream: _messageStream,
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final messages = snapshot.data!.docs;
        return ListView.builder(
          controller: _scrollController,
          reverse: true,
          padding: const EdgeInsets.fromLTRB(16, 110, 16, 20),
          itemCount: messages.length,
          itemBuilder: (context, index) {
            final msg = messages[index].data() as Map<String, dynamic>;
            final isMe = msg['senderId'] == currentUserId;
            bool showAvatar =
                index == 0 ||
                (messages[index - 1].data() as Map)['senderId'] !=
                    msg['senderId'];
            return _buildMessageBubble(
              messages[index].id,
              msg,
              isMe,
              showAvatar,
            );
          },
        );
      },
    );
  }

  Widget _buildMessageBubble(
    String docId,
    Map<String, dynamic> msg,
    bool isMe,
    bool showAvatar,
  ) {
    return Align(
      alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: EdgeInsets.only(bottom: showAvatar ? 12 : 4),
        constraints: BoxConstraints(
          maxWidth: MediaQuery.of(context).size.width * 0.8,
        ),
        child: Row(
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
                onLongPress: isMe
                    ? () => _showEditDeleteMenu(
                        docId,
                        msg['message'] ?? '',
                        msg['audioBase64'] != null &&
                            msg['audioBase64'].isNotEmpty,
                      )
                    : null,
                child: Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: isMe
                        ? AppTheme.primary.withValues(alpha: 0.85)
                        : AppTheme.bgCard.withValues(alpha: 0.6),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(
                      color: Colors.white.withValues(alpha: 0.1),
                    ),
                  ),
                  child: Column(
                    crossAxisAlignment: isMe
                        ? CrossAxisAlignment.end
                        : CrossAxisAlignment.start,
                    children: [
                      if (msg['audioBase64'] != null &&
                          msg['audioBase64'].toString().isNotEmpty)
                        AudioMessageBubble(
                          audioBase64: msg['audioBase64'],
                          isMe: isMe,
                        )
                      else ...[
                        if (msg['imageBase64'] != null &&
                            msg['imageBase64'].length > 100)
                          Padding(
                            padding: const EdgeInsets.only(bottom: 8),
                            child: ClipRRect(
                              borderRadius: BorderRadius.circular(12),
                              child: _buildDecodedImage(msg['imageBase64']),
                            ),
                          ),
                        if (msg['message'] != null && msg['message'].isNotEmpty)
                          Text(
                            msg['message'],
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 15,
                            ),
                          ),
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
                          if (isMe &&
                              !widget.isGroup &&
                              msg['isRead'] == true) ...[
                            const SizedBox(width: 4),
                            _buildReadIndicator(
                              widget.targetUserId,
                              widget.targetUserPhoto,
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
      ),
    );
  }

  Widget _buildReadIndicator(String id, String photo) {
    final String url = ApiService.getFullImageUrl(
      photo.isNotEmpty ? photo : "$id.jpg",
    );
    return Container(
      width: 12,
      height: 12,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        border: Border.all(color: Colors.white, width: 0.5),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(6),
        child: Image.network(
          url,
          fit: BoxFit.cover,
          errorBuilder: (_, _, _) => const Icon(
            Icons.check_circle,
            size: 10,
            color: Colors.greenAccent,
          ),
        ),
      ),
    );
  }

  Widget _buildInputArea() {
    return Container(
      constraints: const BoxConstraints(minHeight: 70), // Keep height stable
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: AppTheme.bgDark.withValues(alpha: 0.9),
        border: Border(
          top: BorderSide(color: Colors.white.withValues(alpha: 0.05)),
        ),
      ),
      child: SafeArea(
        top: false,
        child: AnimatedSwitcher(
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
                        padding: const EdgeInsets.symmetric(horizontal: 16),
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.08),
                          borderRadius: BorderRadius.circular(25),
                          border: Border.all(
                            color: Colors.white.withValues(alpha: 0.1),
                          ),
                        ),
                        child: TextField(
                          controller: _msgController,
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontSize: 15,
                          ),
                          maxLines: null,
                          onChanged: (v) => setState(() {}),
                          decoration: const InputDecoration(
                            hintText: "សរសេរសារ...",
                            border: InputBorder.none,
                            hintStyle: TextStyle(color: Colors.white30),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    _msgController.text.trim().isEmpty
                        ? GestureDetector(
                            onTap: _isRecording ? null : _startRecording,
                            child: Container(
                              padding: const EdgeInsets.all(10),
                              decoration: BoxDecoration(
                                color: AppTheme.primary,
                                shape: BoxShape.circle,
                                boxShadow: [
                                  BoxShadow(
                                    color: AppTheme.primary.withValues(
                                      alpha: 0.3,
                                    ),
                                    blurRadius: 10,
                                    offset: const Offset(0, 4),
                                  ),
                                ],
                              ),
                              child: Icon(
                                _isRecording
                                    ? Icons.mic_rounded
                                    : Icons.mic_none_rounded,
                                color: Colors.white,
                                size: 24,
                              ),
                            ),
                          )
                        : GestureDetector(
                            onTap: () => _sendMessage(),
                            child: Container(
                              padding: const EdgeInsets.all(10),
                              decoration: BoxDecoration(
                                color: AppTheme.primary,
                                shape: BoxShape.circle,
                                boxShadow: [
                                  BoxShadow(
                                    color: AppTheme.primary.withValues(
                                      alpha: 0.3,
                                    ),
                                    blurRadius: 10,
                                    offset: const Offset(0, 4),
                                  ),
                                ],
                              ),
                              child: const Icon(
                                Icons.send_rounded,
                                color: Colors.white,
                                size: 24,
                              ),
                            ),
                          ),
                  ],
                ),
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
      imageQuality: 70,
      maxWidth: 1024,
      maxHeight: 1024,
    );
    if (image != null) {
      final bytes = await image.readAsBytes();
      final base64String = await compute(base64Encode, bytes);
      _sendMessage(base64Image: base64String);
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

  void _showEditDeleteMenu(String docId, String currentMsg, bool isAudio) {
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.bgCard,
      builder: (_) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (!isAudio)
              ListTile(
                leading: const Icon(Icons.edit, color: Colors.blue),
                title: Text(
                  'កែសម្រួល',
                  style: GoogleFonts.kantumruyPro(color: Colors.white),
                ),
                onTap: () {
                  Navigator.pop(context);
                  _showEditDialog(docId, currentMsg);
                },
              ),
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
