import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import '../models/chat_message_model.dart';
import '../controllers/chat_controller.dart';
import '../services/isar_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

class ChatConversationScreen extends StatefulWidget {
  final String roomId;
  final String title;
  final String currentUserId;
  final String currentUserName;
  final String? currentUserAvatar;

  const ChatConversationScreen({
    super.key,
    required this.roomId,
    required this.title,
    required this.currentUserId,
    required this.currentUserName,
    this.currentUserAvatar,
  });

  @override
  State<ChatConversationScreen> createState() => _ChatConversationScreenState();
}

class _ChatConversationScreenState extends State<ChatConversationScreen> {
  late ChatController _controller;
  final TextEditingController _textCtrl = TextEditingController();
  final ScrollController _scrollCtrl = ScrollController();

  @override
  void initState() {
    super.initState();
    _controller = ChatController(
      roomId: widget.roomId,
      currentUserId: widget.currentUserId,
      currentUserName: widget.currentUserName,
      currentUserAvatar: widget.currentUserAvatar,
    );

    _scrollCtrl.addListener(_onScroll);
  }

  void _onScroll() {
    if (_scrollCtrl.position.pixels >= _scrollCtrl.position.maxScrollExtent - 200) {
      _controller.loadMoreMessages();
    }
  }

  @override
  void dispose() {
    _scrollCtrl.removeListener(_onScroll);
    _scrollCtrl.dispose();
    _textCtrl.dispose();
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider.value(
      value: _controller,
      child: Scaffold(
        backgroundColor: const Color(0xFF0F172A),
        appBar: VvcAppBar(
          backgroundColor: const Color(0xFF1E293B),
          elevation: 1,
          title: Text(
            widget.title,
            style: GoogleFonts.kantumruyPro(
              fontSize: 16,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
          leading: IconButton(
            icon: const Icon(Icons.arrow_back, color: Colors.white),
            onPressed: () => Navigator.of(context).pop(),
          ),
        ),
        body: Column(
          children: [
            Expanded(
              child: StreamBuilder<List<ChatMessage>>(
                stream: IsarService().watchMessages(widget.roomId),
                builder: (context, snapshot) {
                  final messages = snapshot.data ?? _controller.messages;

                  if (messages.isEmpty) {
                    return Center(
                      child: Text(
                        'មិនទាន់មានសារនៅឡើយទេ\nផ្ញើសារដំបូងរបស់អ្នកឥឡូវនេះ',
                        textAlign: TextAlign.center,
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white38,
                          fontSize: 13,
                        ),
                      ),
                    );
                  }

                  return ListView.builder(
                    controller: _scrollCtrl,
                    reverse: true, // Newest messages at the bottom
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                    itemCount: messages.length + (_controller.isLoadingMore ? 1 : 0),
                    itemBuilder: (context, index) {
                      if (index == messages.length) {
                        return const Padding(
                          padding: EdgeInsets.all(12),
                          child: Center(
                            child: CircularProgressIndicator(strokeWidth: 2),
                          ),
                        );
                      }

                      final msg = messages[index];
                      final isMe = msg.senderId == widget.currentUserId;
                      return _buildMessageBubble(msg, isMe);
                    },
                  );
                },
              ),
            ),
            _buildInputBar(),
          ],
        ),
      ),
    );
  }

  Widget _buildMessageBubble(ChatMessage msg, bool isMe) {
    final timeStr = DateFormat('HH:mm').format(DateTime.fromMillisecondsSinceEpoch(msg.timestamp));

    return Align(
      alignment: isMe ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 4),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.76),
        decoration: BoxDecoration(
          color: isMe ? const Color(0xFF2563EB) : const Color(0xFF1E293B),
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(16),
            topRight: const Radius.circular(16),
            bottomLeft: isMe ? const Radius.circular(16) : const Radius.circular(4),
            bottomRight: isMe ? const Radius.circular(4) : const Radius.circular(16),
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.15),
              blurRadius: 4,
              offset: const Offset(0, 2),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: isMe ? CrossAxisAlignment.end : CrossAxisAlignment.start,
          children: [
            if (!isMe && (msg.senderName != null && msg.senderName!.isNotEmpty))
              Padding(
                padding: const EdgeInsets.only(bottom: 3),
                child: Text(
                  msg.senderName!,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.amberAccent,
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            Text(
              msg.content,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 13.5,
                height: 1.3,
              ),
            ),
            const SizedBox(height: 4),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  timeStr,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white54,
                    fontSize: 10,
                  ),
                ),
                if (isMe) ...[
                  const SizedBox(width: 4),
                  Icon(
                    msg.isSent ? Icons.done_all : Icons.access_time,
                    size: 13,
                    color: msg.isSent ? Colors.lightBlueAccent : Colors.white38,
                  ),
                ],
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInputBar() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: const BoxDecoration(
        color: Color(0xFF1E293B),
        border: Border(top: BorderSide(color: Colors.white10, width: 1)),
      ),
      child: SafeArea(
        child: Row(
          children: [
            IconButton(
              icon: const Icon(Icons.attach_file, color: Colors.white70),
              onPressed: () {
                // Media selection dialog
              },
            ),
            Expanded(
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 14),
                decoration: BoxDecoration(
                  color: const Color(0xFF0F172A),
                  borderRadius: BorderRadius.circular(24),
                  border: Border.all(color: Colors.white12),
                ),
                child: TextField(
                  controller: _textCtrl,
                  style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14),
                  decoration: InputDecoration(
                    hintText: 'សរសេរសារ...',
                    hintStyle: GoogleFonts.kantumruyPro(color: Colors.white38, fontSize: 14),
                    border: InputBorder.none,
                  ),
                  maxLines: null,
                ),
              ),
            ),
            const SizedBox(width: 8),
            CircleAvatar(
              backgroundColor: AppTheme.primary,
              radius: 20,
              child: IconButton(
                icon: const Icon(Icons.send, color: Colors.white, size: 18),
                onPressed: () {
                  final text = _textCtrl.text;
                  if (text.trim().isNotEmpty) {
                    _controller.sendTextMessage(text);
                    _textCtrl.clear();
                  }
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}
