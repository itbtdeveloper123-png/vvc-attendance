import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:flutter/foundation.dart';
import 'package:uuid/uuid.dart';

class CallService {
  FirebaseFirestore get _firestore => FirebaseFirestore.instance;

  static String? lastErrorMessage;
  
  // Start a new call
  Future<String?> startCall({
    required String callerId,
    required String receiverId,
    required String receiverName,
    required String receiverPhoto,
    required String type, // 'audio' or 'video'
    required String callerName,
    required String callerPhoto,
  }) async {
    lastErrorMessage = null;
    try {
      if (callerId.isEmpty) {
        lastErrorMessage = 'Missing Caller ID';
        debugPrint('startCall: callerId is empty!');
        return null;
      }
      if (receiverId.isEmpty) {
        lastErrorMessage = 'Missing Receiver ID';
        debugPrint('startCall: receiverId is empty!');
        return null;
      }

      final callId = const Uuid().v4();
      
      await _firestore.collection('calls').doc(callId).set({
        'callId': callId,
        'callerId': callerId,
        'callerName': callerName,
        'callerPhoto': callerPhoto,
        'receiverId': receiverId,
        'receiverName': receiverName,
        'receiverPhoto': receiverPhoto,
        'status': 'ringing',
        'type': type,
        'channelId': callId, // Using callId as Agora channel
        'timestamp': FieldValue.serverTimestamp(),
      });
      
      return callId;
    } catch (e, stack) {
      lastErrorMessage = e.toString();
      debugPrint('Error starting call: $e\n$stack');
      return null;
    }
  }

  // Accept incoming call
  Future<void> acceptCall(String callId) async {
    try {
      await _firestore.collection('calls').doc(callId).update({
        'status': 'accepted',
      });
    } catch (e) {
      debugPrint('Error accepting call: $e');
    }
  }

  // Reject or End call and log call message to chat
  Future<void> endCall(String callId, {int duration = 0, String endReason = 'ended'}) async {
    try {
      final docRef = _firestore.collection('calls').doc(callId);
      final docSnap = await docRef.get();
      if (!docSnap.exists) return;

      final data = docSnap.data()!;
      final previousStatus = data['status'] as String? ?? 'ringing';

      await docRef.update({
        'status': endReason == 'rejected' ? 'rejected' : 'ended',
        'duration': duration,
        'endedAt': FieldValue.serverTimestamp(),
      });

      // Avoid duplicate chat message logging
      if (data['loggedToChat'] == true) return;
      await docRef.update({'loggedToChat': true});

      final String callerId = (data['callerId'] ?? '').toString();
      final String receiverId = (data['receiverId'] ?? '').toString();
      final String callerName = (data['callerName'] ?? 'Caller').toString();
      final String callerPhoto = (data['callerPhoto'] ?? '').toString();
      final String receiverName = (data['receiverName'] ?? 'Receiver').toString();
      final String receiverPhoto = (data['receiverPhoto'] ?? '').toString();
      final String type = (data['type'] ?? 'audio').toString();

      if (callerId.isEmpty || receiverId.isEmpty) return;

      final List<String> ids = [callerId, receiverId]..sort();
      final String roomId = 'PRIVATE_${ids[0]}_${ids[1]}';

      String callStatus = 'completed';
      if (endReason == 'rejected' || previousStatus == 'rejected') {
        callStatus = 'declined';
      } else if (duration <= 0 && (previousStatus == 'ringing' || previousStatus == 'connecting')) {
        callStatus = 'missed';
      }

      String formatDur(int s) {
        if (s <= 0) return '';
        final m = s ~/ 60;
        final sec = s % 60;
        if (m > 0) {
          return '$m នាទី $sec វិនាទី';
        }
        return '$sec វិនាទី';
      }

      String summaryText;
      final isVideo = type == 'video';
      if (callStatus == 'missed') {
        summaryText = isVideo ? '📹 ការខលវីដេអូខកខាន' : '📞 ការខលខកខាន (Missed Call)';
      } else if (callStatus == 'declined') {
        summaryText = isVideo ? '📹 ការខលវីដេអូបដិសេធ' : '📞 ការខលត្រូវបានបដិសេធ';
      } else {
        final durStr = formatDur(duration);
        summaryText = isVideo
            ? (durStr.isNotEmpty ? '📹 ការខលវីដេអូ ($durStr)' : '📹 ការខលវីដេអូ')
            : (durStr.isNotEmpty ? '📞 ការខលជាសំឡេង ($durStr)' : '📞 ការខលជាសំឡេង');
      }

      final msgRef = _firestore.collection('chats').doc(roomId).collection('messages').doc();
      final batch = _firestore.batch();
      batch.set(msgRef, {
        'type': 'call',
        'callId': callId,
        'callType': type,
        'callStatus': callStatus,
        'duration': duration,
        'text': summaryText,
        'senderId': callerId,
        'senderName': callerName,
        'senderPhoto': callerPhoto,
        'receiverId': receiverId,
        'receiverName': receiverName,
        'receiverPhoto': receiverPhoto,
        'timestamp': FieldValue.serverTimestamp(),
        'isRead': false,
      });

      batch.set(_firestore.collection('chats').doc(roomId), {
        'participants': [callerId, receiverId],
        'lastMessage': summaryText,
        'lastTimestamp': FieldValue.serverTimestamp(),
        'lastSenderId': callerId,
        'isRead': false,
      }, SetOptions(merge: true));

      await batch.commit();
    } catch (e) {
      debugPrint('Error ending call or logging to chat: $e');
    }
  }

  // Listen to incoming calls for current user
  Stream<QuerySnapshot> getIncomingCalls(String currentUserId) {
    if (currentUserId.isEmpty) return const Stream.empty();
    try {
      return _firestore
          .collection('calls')
          .where('receiverId', isEqualTo: currentUserId)
          .where('status', isEqualTo: 'ringing')
          .snapshots();
    } catch (e) {
      debugPrint('Error listening to incoming calls: $e');
      return const Stream.empty();
    }
  }

  // Listen to specific call state (e.g. to know if receiver accepted)
  Stream<DocumentSnapshot> getCallState(String callId) {
    return _firestore.collection('calls').doc(callId).snapshots();
  }
}
