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

  // Reject or End call
  Future<void> endCall(String callId) async {
    try {
      await _firestore.collection('calls').doc(callId).update({
        'status': 'ended',
      });
    } catch (e) {
      debugPrint('Error ending call: $e');
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
