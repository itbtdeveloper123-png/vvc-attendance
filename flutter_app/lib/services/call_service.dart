import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:uuid/uuid.dart';

class CallService {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  final FirebaseAuth _auth = FirebaseAuth.instance;
  
  // Start a new call
  Future<String?> startCall({
    required String receiverId,
    required String receiverName,
    required String receiverPhoto,
    required String type, // 'audio' or 'video'
    required String callerName,
    required String callerPhoto,
  }) async {
    try {
      final callerId = _auth.currentUser?.uid;
      if (callerId == null) return null;

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
    } catch (e) {
      print('Error starting call: $e');
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
      print('Error accepting call: $e');
    }
  }

  // Reject or End call
  Future<void> endCall(String callId) async {
    try {
      await _firestore.collection('calls').doc(callId).update({
        'status': 'ended',
      });
    } catch (e) {
      print('Error ending call: $e');
    }
  }

  // Listen to incoming calls for current user
  Stream<QuerySnapshot> getIncomingCalls() {
    final currentUserId = _auth.currentUser?.uid ?? '';
    return _firestore
        .collection('calls')
        .where('receiverId', isEqualTo: currentUserId)
        .where('status', isEqualTo: 'ringing')
        .snapshots();
  }

  // Listen to specific call state (e.g. to know if receiver accepted)
  Stream<DocumentSnapshot> getCallState(String callId) {
    return _firestore.collection('calls').doc(callId).snapshots();
  }
}
