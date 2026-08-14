import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../services/call_service.dart';
import '../../services/api_service.dart';
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

class _IncomingCallScreenState extends State<IncomingCallScreen>
    with SingleTickerProviderStateMixin {
  final CallService _callService = CallService();
  bool _isActionTaken = false;
  late AnimationController _pulseController;
  late Animation<double> _pulseAnimation;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1500),
    )..repeat(reverse: true);

    _pulseAnimation = Tween<double>(begin: 1.0, end: 1.08).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _pulseController.dispose();
    super.dispose();
  }

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
            targetPhoto: widget.callerPhoto,
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
    final fullAvatarUrl = ApiService.getFullImageUrl(widget.callerPhoto);

    return Scaffold(
      backgroundColor: const Color(0xFF0B111E),
      body: SafeArea(
        child: Stack(
          children: [
            // Background Radial Gradient
            Positioned.fill(
              child: Container(
                decoration: const BoxDecoration(
                  gradient: RadialGradient(
                    center: Alignment(0, -0.25),
                    radius: 0.9,
                    colors: [
                      Color(0xFF1E293B),
                      Color(0xFF0F172A),
                      Color(0xFF090D16),
                    ],
                  ),
                ),
              ),
            ),

            Column(
              children: [
                const SizedBox(height: 50),

                // Top Badge
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                  decoration: BoxDecoration(
                    color: Colors.white.withAlpha(20),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(color: Colors.white.withAlpha(30)),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        isVideo ? Icons.videocam_rounded : Icons.phone_in_talk_rounded,
                        size: 14,
                        color: const Color(0xFF10B981),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        isVideo ? 'ការហៅជាវីដេអូចូល...' : 'ការហៅជាសំឡេងចូល...',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white70,
                          fontSize: 13,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 24),

                // Caller Name
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 24),
                  child: Text(
                    widget.callerName,
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 30,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 0.3,
                    ),
                    textAlign: TextAlign.center,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),

                const SizedBox(height: 8),
                Text(
                  'Incoming ${isVideo ? 'Video' : 'Voice'} Call...',
                  style: GoogleFonts.inter(
                    color: Colors.white54,
                    fontSize: 15,
                  ),
                ),

                const Spacer(),

                // Pulsating Avatar
                ScaleTransition(
                  scale: _pulseAnimation,
                  child: Container(
                    width: 150,
                    height: 150,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      gradient: const LinearGradient(
                        colors: [Color(0xFF334155), Color(0xFF1E293B)],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      ),
                      border: Border.all(
                        color: const Color(0xFF10B981).withAlpha(160),
                        width: 3.5,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: const Color(0xFF10B981).withAlpha(70),
                          blurRadius: 30,
                          spreadRadius: 4,
                        ),
                        BoxShadow(
                          color: Colors.black.withAlpha(140),
                          blurRadius: 20,
                          offset: const Offset(0, 8),
                        ),
                      ],
                    ),
                    clipBehavior: Clip.antiAlias,
                    child: fullAvatarUrl.isNotEmpty
                        ? Image.network(
                            fullAvatarUrl,
                            fit: BoxFit.cover,
                            errorBuilder: (_, __, ___) => _defaultAvatar(),
                          )
                        : _defaultAvatar(),
                  ),
                ),

                const Spacer(),

                // Action Buttons (Decline & Accept)
                Padding(
                  padding: const EdgeInsets.only(bottom: 60, left: 48, right: 48),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      // Decline Button
                      GestureDetector(
                        onTap: _declineCall,
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Container(
                              width: 72,
                              height: 72,
                              decoration: BoxDecoration(
                                shape: BoxShape.circle,
                                gradient: const LinearGradient(
                                  colors: [Color(0xFFEF4444), Color(0xFFDC2626)],
                                  begin: Alignment.topLeft,
                                  end: Alignment.bottomRight,
                                ),
                                boxShadow: [
                                  BoxShadow(
                                    color: const Color(0xFFEF4444).withAlpha(100),
                                    blurRadius: 20,
                                    spreadRadius: 2,
                                    offset: const Offset(0, 6),
                                  ),
                                ],
                              ),
                              child: const Icon(
                                Icons.call_end_rounded,
                                color: Colors.white,
                                size: 34,
                              ),
                            ),
                            const SizedBox(height: 12),
                            Text(
                              'បដិសេធ',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white70,
                                fontSize: 14,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                          ],
                        ),
                      ),

                      // Accept Button
                      GestureDetector(
                        onTap: _acceptCall,
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Container(
                              width: 72,
                              height: 72,
                              decoration: BoxDecoration(
                                shape: BoxShape.circle,
                                gradient: const LinearGradient(
                                  colors: [Color(0xFF10B981), Color(0xFF059669)],
                                  begin: Alignment.topLeft,
                                  end: Alignment.bottomRight,
                                ),
                                boxShadow: [
                                  BoxShadow(
                                    color: const Color(0xFF10B981).withAlpha(120),
                                    blurRadius: 22,
                                    spreadRadius: 3,
                                    offset: const Offset(0, 6),
                                  ),
                                ],
                              ),
                              child: Icon(
                                isVideo
                                    ? Icons.videocam_rounded
                                    : Icons.call_rounded,
                                color: Colors.white,
                                size: 34,
                              ),
                            ),
                            const SizedBox(height: 12),
                            Text(
                              'ទទួល',
                              style: GoogleFonts.kantumruyPro(
                                color: const Color(0xFF10B981),
                                fontSize: 14,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _defaultAvatar() {
    return Center(
      child: Icon(
        Icons.person_rounded,
        size: 70,
        color: Colors.white.withAlpha(160),
      ),
    );
  }
}

