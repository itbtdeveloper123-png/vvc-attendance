import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../services/call_service.dart';
import 'active_call_screen.dart';

class IncomingCallScreen extends StatefulWidget {
  final String callId;
  final String callerName;
  final String callerPhoto;
  final String callType; // 'audio' or 'video'

  const IncomingCallScreen({
    super.key,
    required this.callId,
    required this.callerName,
    required this.callerPhoto,
    required this.callType,
  });

  @override
  State<IncomingCallScreen> createState() => _IncomingCallScreenState();
}

class _IncomingCallScreenState extends State<IncomingCallScreen> {
  final CallService _callService = CallService();
  bool _isActionTaken = false;

  void _acceptCall() async {
    if (_isActionTaken) return;
    setState(() => _isActionTaken = true);
    
    await _callService.acceptCall(widget.callId);
    
    if (mounted) {
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(
          builder: (_) => ActiveCallScreen(
            callId: widget.callId,
            channelId: widget.callId,
            targetName: widget.callerName,
            isVideoCall: widget.callType == 'video',
            isCaller: false,
          ),
        ),
      );
    }
  }

  void _declineCall() async {
    if (_isActionTaken) return;
    setState(() => _isActionTaken = true);
    
    await _callService.endCall(widget.callId);
    if (mounted) {
      Navigator.pop(context);
    }
  }

  @override
  Widget build(BuildContext context) {
    final bool isVideo = widget.callType == 'video';
    
    return Scaffold(
      backgroundColor: const Color(0xFF1C1C1E),
      body: SafeArea(
        child: Column(
          children: [
            const SizedBox(height: 80),
            // Caller Avatar
            CircleAvatar(
              radius: 60,
              backgroundColor: Colors.grey.shade800,
              backgroundImage: widget.callerPhoto.isNotEmpty
                  ? NetworkImage(widget.callerPhoto)
                  : null,
              child: widget.callerPhoto.isEmpty
                  ? const Icon(Icons.person, size: 60, color: Colors.white)
                  : null,
            ),
            const SizedBox(height: 24),
            // Caller Name
            Text(
              widget.callerName,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 28,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            // Call Type
            Text(
              'Incoming ${isVideo ? 'Video' : 'Audio'} Call...',
              style: GoogleFonts.inter(
                color: Colors.white70,
                fontSize: 16,
              ),
            ),
            const Spacer(),
            // Action Buttons
            Padding(
              padding: const EdgeInsets.only(bottom: 60, left: 40, right: 40),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  // Decline Button
                  GestureDetector(
                    onTap: _declineCall,
                    child: Column(
                      children: [
                        Container(
                          width: 72,
                          height: 72,
                          decoration: const BoxDecoration(
                            color: Colors.redAccent,
                            shape: BoxShape.circle,
                          ),
                          child: const Icon(Icons.call_end_rounded, color: Colors.white, size: 36),
                        ),
                        const SizedBox(height: 12),
                        Text('Decline', style: GoogleFonts.inter(color: Colors.white, fontSize: 15)),
                      ],
                    ),
                  ),
                  // Accept Button
                  GestureDetector(
                    onTap: _acceptCall,
                    child: Column(
                      children: [
                        Container(
                          width: 72,
                          height: 72,
                          decoration: const BoxDecoration(
                            color: Colors.green,
                            shape: BoxShape.circle,
                          ),
                          child: Icon(
                            isVideo ? Icons.videocam_rounded : Icons.call_rounded,
                            color: Colors.white,
                            size: 36,
                          ),
                        ),
                        const SizedBox(height: 12),
                        Text('Accept', style: GoogleFonts.inter(color: Colors.white, fontSize: 15)),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
