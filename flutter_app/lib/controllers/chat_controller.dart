import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:isar/isar.dart';
import '../models/chat_message_model.dart';
import '../models/chat_room_model.dart';
import '../services/isar_service.dart';
import '../services/firebase_sync_service.dart';
import '../services/r2_storage_service.dart';

/// Production-ready Chat Controller with Optimistic UI & Local Caching
class ChatController extends ChangeNotifier {
  final String roomId;
  final String currentUserId;
  final String currentUserName;
  final String? currentUserAvatar;

  final IsarService _isar = IsarService();
  final FirebaseSyncService _syncService = FirebaseSyncService();
  final R2StorageService _r2Service = R2StorageService();

  List<ChatMessage> _messages = [];
  bool _isLoadingMore = false;
  bool _hasMore = true;
  int _currentOffset = 0;
  static const int _pageSize = 20;

  List<ChatMessage> get messages => _messages;
  bool get isLoadingMore => _isLoadingMore;
  bool get hasMore => _hasMore;

  ChatController({
    required this.roomId,
    required this.currentUserId,
    required this.currentUserName,
    this.currentUserAvatar,
  }) {
    _initChat();
  }

  Future<void> _initChat() async {
    // 1. Subscribe to Firebase real-time transit messages
    _syncService.subscribeToRoom(roomId, currentUserId);

    // 2. Initial load from Isar local database
    await loadInitialMessages();

    // 3. Mark unread count as zero in Isar
    _resetUnreadCount();
  }

  /// Initial messages load
  Future<void> loadInitialMessages() async {
    _currentOffset = 0;
    _messages = await _isar.getMessages(
      roomId: roomId,
      limit: _pageSize,
      offset: 0,
    );
    _hasMore = _messages.length >= _pageSize;
    notifyListeners();
  }

  /// Paginated lazy-loading (Scroll up to load older messages)
  Future<void> loadMoreMessages() async {
    if (_isLoadingMore || !_hasMore) return;

    _isLoadingMore = true;
    notifyListeners();

    _currentOffset += _pageSize;
    final olderMessages = await _isar.getMessages(
      roomId: roomId,
      limit: _pageSize,
      offset: _currentOffset,
    );

    if (olderMessages.isEmpty) {
      _hasMore = false;
    } else {
      _messages.addAll(olderMessages);
      if (olderMessages.length < _pageSize) {
        _hasMore = false;
      }
    }

    _isLoadingMore = false;
    notifyListeners();
  }

  /// Send Text Message (Optimistic UI Update)
  Future<void> sendTextMessage(String text) async {
    if (text.trim().isEmpty) return;

    final msgId = 'MSG_${DateTime.now().millisecondsSinceEpoch}_${currentUserId.substring(0, 3)}';
    final message = ChatMessage(
      messageId: msgId,
      roomId: roomId,
      senderId: currentUserId,
      senderName: currentUserName,
      senderAvatar: currentUserAvatar,
      type: MessageType.text,
      content: text.trim(),
      timestamp: DateTime.now().millisecondsSinceEpoch,
      isSent: false,
    );

    // Step A: Optimistic UI - Save locally first
    await _isar.saveMessage(message);
    _messages.insert(0, message);
    notifyListeners();

    // Step B: Send to Firebase Transit DB
    final sentSuccess = await _syncService.sendTransitMessage(message);

    // Step C: Update local status
    message.isSent = sentSuccess;
    await _isar.saveMessage(message);
    notifyListeners();
  }

  /// Send Media Message (Photo, Attachment, Voice Note) with Cloudflare R2 Upload
  Future<void> sendMediaMessage({
    required File file,
    required MessageType type,
    String? fileName,
    int? voiceDuration,
  }) async {
    final msgId = 'MSG_${DateTime.now().millisecondsSinceEpoch}_${currentUserId.substring(0, 3)}';
    final fileSize = await file.length();

    // Local temporary file path for immediate rendering
    final message = ChatMessage(
      messageId: msgId,
      roomId: roomId,
      senderId: currentUserId,
      senderName: currentUserName,
      senderAvatar: currentUserAvatar,
      type: type,
      content: file.path, // Temporary local path
      fileName: fileName ?? file.path.split('/').last,
      fileSize: fileSize,
      voiceDuration: voiceDuration,
      timestamp: DateTime.now().millisecondsSinceEpoch,
      isSent: false,
    );

    // Step A: Optimistic UI
    await _isar.saveMessage(message);
    _messages.insert(0, message);
    notifyListeners();

    // Step B: Upload file to Cloudflare R2
    final folder = type == MessageType.image
        ? 'chat_images'
        : (type == MessageType.voice ? 'voice_notes' : 'chat_files');

    final r2Url = await _r2Service.uploadMedia(file: file, folder: folder);

    if (r2Url != null) {
      message.content = r2Url; // Set final R2 public URL
      final sentSuccess = await _syncService.sendTransitMessage(message);
      message.isSent = sentSuccess;
    } else {
      message.isSent = false;
    }

    // Step C: Persist final status to Isar DB
    await _isar.saveMessage(message);
    notifyListeners();
  }

  Future<void> _resetUnreadCount() async {
    final db = await _isar.db;
    final room = await db.chatRooms.filter().roomIdEqualTo(roomId).findFirst();
    if (room != null && room.unreadCount > 0) {
      room.unreadCount = 0;
      await _isar.saveChatRoom(room);
    }
  }

  @override
  void dispose() {
    _syncService.unsubscribeFromRoom(roomId);
    super.dispose();
  }
}
