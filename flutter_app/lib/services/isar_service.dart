import 'package:flutter/foundation.dart';
import 'package:isar/isar.dart';
import 'package:path_provider/path_provider.dart';
import '../models/chat_room_model.dart';
import '../models/chat_message_model.dart';

/// Singleton Isar Database Service for Offline-First Enterprise Chat
class IsarService {
  static final IsarService _instance = IsarService._internal();
  factory IsarService() => _instance;
  IsarService._internal();

  Isar? _isar;

  /// Get active Isar instance or initialize if needed
  Future<Isar> get db async {
    if (_isar != null && _isar!.isOpen) {
      return _isar!;
    }
    _isar = await _initIsar();
    return _isar!;
  }

  /// Initialize Isar DB instance with schemas
  Future<Isar> _initIsar() async {
    if (Isar.instanceNames.contains('chat_db')) {
      return Isar.getInstance('chat_db')!;
    }

    final dir = await getApplicationDocumentsDirectory();
    return await Isar.open(
      [ChatRoomSchema, ChatMessageSchema],
      directory: dir.path,
      name: 'chat_db',
      inspector: kDebugMode,
    );
  }

  // =========================================================================
  // MESSAGE OPERATIONS
  // =========================================================================

  /// Save or update a single message
  Future<void> saveMessage(ChatMessage message) async {
    final isar = await db;
    await isar.writeTxn(() async {
      await isar.chatMessages.putByMessageId(message);
    });
  }

  /// Save or update a batch of messages
  Future<void> saveMessages(List<ChatMessage> messages) async {
    if (messages.isEmpty) return;
    final isar = await db;
    await isar.writeTxn(() async {
      await isar.chatMessages.putAllByMessageId(messages);
    });
  }

  /// Get paginated messages for a specific room (Telegram-style, newest first)
  Future<List<ChatMessage>> getMessages({
    required String roomId,
    int limit = 20,
    int offset = 0,
  }) async {
    final isar = await db;
    return await isar.chatMessages
        .filter()
        .roomIdEqualTo(roomId)
        .sortByTimestampDesc()
        .offset(offset)
        .limit(limit)
        .findAll();
  }

  /// Real-time stream of messages for a chat room (reactive UI)
  Stream<List<ChatMessage>> watchMessages(String roomId) async* {
    final isar = await db;
    yield* isar.chatMessages
        .filter()
        .roomIdEqualTo(roomId)
        .sortByTimestampDesc()
        .build()
        .watch(fireImmediately: true);
  }

  /// Delete a message by messageId
  Future<void> deleteMessage(String messageId) async {
    final isar = await db;
    await isar.writeTxn(() async {
      final existing = await isar.chatMessages.filter().messageIdEqualTo(messageId).findFirst();
      if (existing != null) {
        await isar.chatMessages.delete(existing.id);
      }
    });
  }

  // =========================================================================
  // ROOM OPERATIONS
  // =========================================================================

  /// Save or update a chat room
  Future<void> saveChatRoom(ChatRoom room) async {
    final isar = await db;
    await isar.writeTxn(() async {
      await isar.chatRooms.putByRoomId(room);
    });
  }

  /// Get all chat rooms sorted by lastMessageTime
  Future<List<ChatRoom>> getChatRooms() async {
    final isar = await db;
    return await isar.chatRooms
        .where()
        .sortByLastMessageTimeDesc()
        .findAll();
  }

  /// Watch real-time list of chat rooms
  Stream<List<ChatRoom>> watchChatRooms() async* {
    final isar = await db;
    yield* isar.chatRooms
        .where()
        .sortByLastMessageTimeDesc()
        .build()
        .watch(fireImmediately: true);
  }

  /// Clear all local chat data (on logout)
  Future<void> clearAll() async {
    final isar = await db;
    await isar.writeTxn(() async {
      await isar.clear();
    });
  }

  /// Clear all local DB data and temporary media cache
  Future<void> clearCacheAndLocalDb() async {
    await clearAll();
    try {
      final tempDir = await getTemporaryDirectory();
      if (tempDir.existsSync()) {
        tempDir.deleteSync(recursive: true);
      }
    } catch (e) {
      debugPrint('Error deleting temp directory: $e');
    }
  }
}
