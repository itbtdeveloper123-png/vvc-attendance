import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:isar/isar.dart';
import '../models/chat_message_model.dart';
import '../models/chat_room_model.dart';
import 'isar_service.dart';

/// Firebase Real-time Sync Service
/// 
/// Operates as an ephemeral message transit layer:
/// 1. Listens for incoming real-time messages for active room(s).
/// 2. Saves incoming messages immediately into Isar Local DB.
/// 3. Acknowledges & clears transit nodes from Firebase to keep storage & read/write costs at zero.
class FirebaseSyncService {
  static final FirebaseSyncService _instance = FirebaseSyncService._internal();
  factory FirebaseSyncService() => _instance;
  FirebaseSyncService._internal();

  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final IsarService _isar = IsarService();

  final Map<String, StreamSubscription> _roomSubscriptions = {};

  /// Start listening for real-time messages in a specific room
  void subscribeToRoom(String roomId, String currentUserId) {
    if (_roomSubscriptions.containsKey(roomId)) return;

    final sub = _firestore
        .collection('chat_transit')
        .doc(roomId)
        .collection('messages')
        .snapshots()
        .listen(
      (snapshot) async {
        for (var change in snapshot.docChanges) {
          if (change.type == DocumentChangeType.added) {
            final data = change.doc.data();
            if (data == null) continue;

            final msg = ChatMessage.fromJson(data);

            // 1. Immediately save to Isar Local DB
            await _isar.saveMessage(msg);

            // 2. Update ChatRoom metadata in Isar Local DB
            await _updateLocalRoomState(msg, currentUserId);

            // 3. Clear/Delete transit document from Firebase to minimize DB costs
            try {
              await change.doc.reference.delete();
            } catch (e) {
              debugPrint('Failed to delete Firebase transit message: $e');
            }
          }
        }
      },
      onError: (e) {
        debugPrint('FirebaseSync error for room $roomId: $e');
      },
    );

    _roomSubscriptions[roomId] = sub;
  }

  /// Unsubscribe real-time listener for a room
  void unsubscribeFromRoom(String roomId) {
    _roomSubscriptions[roomId]?.cancel();
    _roomSubscriptions.remove(roomId);
  }

  /// Send message via Firebase transit layer
  Future<bool> sendTransitMessage(ChatMessage message) async {
    try {
      final docRef = _firestore
          .collection('chat_transit')
          .doc(message.roomId)
          .collection('messages')
          .doc(message.messageId);

      await docRef.set(message.toJson());
      return true;
    } catch (e) {
      debugPrint('Failed to send transit message via Firebase: $e');
      return false;
    }
  }

  /// Helper to update ChatRoom last message and unread count in Isar
  Future<void> _updateLocalRoomState(ChatMessage msg, String currentUserId) async {
    final isarDb = await _isar.db;
    ChatRoom? room = await isarDb.chatRooms
        .filter()
        .roomIdEqualTo(msg.roomId)
        .findFirst();

    room ??= ChatRoom(
      roomId: msg.roomId,
      memberIds: [msg.senderId, currentUserId],
    );

    room.lastMessageText = _formatLastMessageText(msg);
    room.lastMessageTime = msg.timestamp;
    room.lastMessageSenderId = msg.senderId;

    if (msg.senderId != currentUserId) {
      room.unreadCount += 1;
    }

    await _isar.saveChatRoom(room);
  }

  String _formatLastMessageText(ChatMessage msg) {
    switch (msg.type) {
      case MessageType.image:
        return '📷 រូបភាព (Image)';
      case MessageType.file:
        return '📁 ឯកសារ (${msg.fileName ?? 'File'})';
      case MessageType.voice:
        return '🎙️ សារសំឡេង (Voice Note)';
      case MessageType.text:
        return msg.content;
    }
  }

  /// Clear all active subscriptions
  void dispose() {
    for (var sub in _roomSubscriptions.values) {
      sub.cancel();
    }
    _roomSubscriptions.clear();
  }
}
