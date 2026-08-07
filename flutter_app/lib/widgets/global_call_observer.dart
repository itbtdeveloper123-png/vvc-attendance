import 'dart:async';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:flutter/material.dart';
import '../services/call_service.dart';
import '../screens/call/incoming_call_screen.dart';

class GlobalCallObserver extends StatefulWidget {
  final Widget child;

  const GlobalCallObserver({super.key, required this.child});

  @override
  State<GlobalCallObserver> createState() => _GlobalCallObserverState();
}

class _GlobalCallObserverState extends State<GlobalCallObserver> {
  final CallService _callService = CallService();
  StreamSubscription<QuerySnapshot>? _callSub;
  String? _currentRingingCallId;

  @override
  void initState() {
    super.initState();
    _listenForIncomingCalls();
  }

  void _listenForIncomingCalls() {
    _callSub = _callService.getIncomingCalls().listen((snapshot) {
      if (snapshot.docs.isNotEmpty) {
        final doc = snapshot.docs.first;
        final data = doc.data() as Map<String, dynamic>;
        final callId = data['callId'] as String;
        final callerName = data['callerName'] as String? ?? 'Unknown';
        final callerPhoto = data['callerPhoto'] as String? ?? '';
        final callType = data['type'] as String? ?? 'audio';

        // Only show if we aren't already ringing for this call
        if (_currentRingingCallId != callId) {
          _currentRingingCallId = callId;
          _showIncomingCall(callId, callerName, callerPhoto, callType);
        }
      } else {
        // If ringing call was cancelled
        if (_currentRingingCallId != null) {
          // If we are currently showing the incoming call screen, we might want to pop it.
          // For safety, the IncomingCallScreen itself could listen, but we handle simple clean up here.
          _currentRingingCallId = null;
        }
      }
    });
  }

  void _showIncomingCall(String callId, String callerName, String callerPhoto, String callType) {
    // Navigate to incoming call screen
    if (context.mounted) {
      Navigator.of(context).push(
        MaterialPageRoute(
          builder: (ctx) => IncomingCallScreen(
            callId: callId,
            callerName: callerName,
            callerPhoto: callerPhoto,
            callType: callType,
          ),
          fullscreenDialog: true,
        ),
      );
    }
  }

  @override
  void dispose() {
    _callSub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return widget.child;
  }
}
