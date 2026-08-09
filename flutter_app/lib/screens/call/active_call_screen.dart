import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:agora_rtc_engine/agora_rtc_engine.dart';
import 'package:permission_handler/permission_handler.dart';
import '../../services/call_service.dart';

const String appId = '0170fac7ff8444fcb7f09528e18b27bf';

class ActiveCallScreen extends StatefulWidget {
  final String callId;
  final String channelId;
  final String targetName;
  final bool isVideoCall;
  final bool
  isCaller; // If caller, we wait for the other to join. If receiver, we just joined.

  const ActiveCallScreen({
    super.key,
    required this.callId,
    required this.channelId,
    required this.targetName,
    required this.isVideoCall,
    required this.isCaller,
  });

  @override
  State<ActiveCallScreen> createState() => _ActiveCallScreenState();
}

class _ActiveCallScreenState extends State<ActiveCallScreen> {
  final CallService _callService = CallService();
  int? _remoteUid;
  bool _localUserJoined = false;
  late RtcEngine _engine;

  bool _isMuted = false;
  bool _isVideoDisabled = false;

  StreamSubscription? _callStateSub;
  String _callStatus = 'connecting';

  @override
  void initState() {
    super.initState();
    _initAgora();
    _listenToCallState();
  }

  void _listenToCallState() {
    _callStateSub = _callService.getCallState(widget.callId).listen((doc) {
      if (doc.exists) {
        final data = doc.data() as Map<String, dynamic>;
        final status = data['status'];
        setState(() => _callStatus = status);

        if (status == 'ended' || status == 'rejected') {
          _endCallLocally();
        }
      } else {
        _endCallLocally(); // doc deleted
      }
    });
  }

  Future<void> _initAgora() async {
    // Check permissions
    await [Permission.microphone, Permission.camera].request();

    // Create the engine
    _engine = createAgoraRtcEngine();
    await _engine.initialize(
      const RtcEngineContext(
        appId: appId,
        channelProfile: ChannelProfileType.channelProfileCommunication,
      ),
    );

    _engine.registerEventHandler(
      RtcEngineEventHandler(
        onJoinChannelSuccess: (RtcConnection connection, int elapsed) {
          debugPrint("local user \${connection.localUid} joined");
          setState(() {
            _localUserJoined = true;
          });
        },
        onUserJoined: (RtcConnection connection, int remoteUid, int elapsed) {
          debugPrint("remote user $remoteUid joined");
          setState(() {
            _remoteUid = remoteUid;
            _callStatus = 'connected';
          });
        },
        onUserOffline: (
          RtcConnection connection,
          int remoteUid,
          UserOfflineReasonType reason,
        ) {
          debugPrint("remote user $remoteUid left channel");
          setState(() {
            _remoteUid = null;
          });
          _endCallAndLeave();
        },
        onTokenPrivilegeWillExpire: (RtcConnection connection, String token) {
          debugPrint(
            '[onTokenPrivilegeWillExpire] connection: \${connection.toJson()}, token: $token',
          );
        },
      ),
    );

    if (widget.isVideoCall) {
      await _engine.enableVideo();
      await _engine.startPreview();
    } else {
      await _engine.disableVideo();
    }

    // Join channel
    await _engine.joinChannel(
      token:
          '', // Use empty token for testing, or generate on server for production
      channelId: widget.channelId,
      uid: 0,
      options: const ChannelMediaOptions(),
    );
  }

  void _toggleMute() {
    setState(() {
      _isMuted = !_isMuted;
    });
    _engine.muteLocalAudioStream(_isMuted);
  }

  void _toggleVideo() {
    if (!widget.isVideoCall) return;
    setState(() {
      _isVideoDisabled = !_isVideoDisabled;
    });
    _engine.muteLocalVideoStream(_isVideoDisabled);
  }

  void _switchCamera() {
    if (!widget.isVideoCall) return;
    _engine.switchCamera();
  }

  void _endCallAndLeave() async {
    await _callService.endCall(widget.callId);
    _endCallLocally();
  }

  void _endCallLocally() async {
    if (mounted) {
      Navigator.pop(context);
    }
  }

  @override
  void dispose() {
    _callStateSub?.cancel();
    _engine.leaveChannel();
    _engine.release();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF151D2A),
      body: SafeArea(
        child: Stack(
          children: [
            // Remote Video or Audio Avatar
            if (widget.isVideoCall) _remoteVideo() else _audioCallPlaceholder(),

            // Local Video (PiP)
            if (widget.isVideoCall && _localUserJoined && !_isVideoDisabled)
              Positioned(
                top: 16,
                right: 16,
                child: Container(
                  width: 100,
                  height: 140,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: Colors.white24, width: 2),
                  ),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(10),
                    child: AgoraVideoView(
                      controller: VideoViewController(
                        rtcEngine: _engine,
                        canvas: const VideoCanvas(uid: 0),
                      ),
                    ),
                  ),
                ),
              ),

            // Status/Name Header
            Positioned(
              top: 30,
              left: 0,
              right: 0,
              child: Column(
                children: [
                  Text(
                    widget.targetName,
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    _getStatusText(),
                    style: GoogleFonts.inter(
                      color: Colors.white70,
                      fontSize: 14,
                    ),
                  ),
                ],
              ),
            ),

            // Controls
            Align(
              alignment: Alignment.bottomCenter,
              child: Padding(
                padding: const EdgeInsets.only(bottom: 40),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    _buildControlButton(
                      icon:
                          _isMuted ? Icons.mic_off_rounded : Icons.mic_rounded,
                      onTap: _toggleMute,
                      color: _isMuted ? Colors.white : Colors.white24,
                      iconColor: _isMuted ? Colors.black : Colors.white,
                    ),
                    _buildControlButton(
                      icon: Icons.call_end_rounded,
                      onTap: _endCallAndLeave,
                      color: Colors.redAccent,
                      iconColor: Colors.white,
                      size: 64,
                    ),
                    if (widget.isVideoCall)
                      _buildControlButton(
                        icon:
                            _isVideoDisabled
                                ? Icons.videocam_off_rounded
                                : Icons.videocam_rounded,
                        onTap: _toggleVideo,
                        color: _isVideoDisabled ? Colors.white : Colors.white24,
                        iconColor:
                            _isVideoDisabled ? Colors.black : Colors.white,
                      )
                    else
                      const SizedBox(width: 56), // spacer for audio call

                    if (widget.isVideoCall)
                      _buildControlButton(
                        icon: Icons.flip_camera_ios_rounded,
                        onTap: _switchCamera,
                        color: Colors.white24,
                        iconColor: Colors.white,
                      ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  String _getStatusText() {
    if (_callStatus == 'ringing') return 'Ringing...';
    if (_callStatus == 'connecting') return 'Connecting...';
    if (_callStatus == 'connected')
      return '00:00'; // Could implement a timer here
    if (_callStatus == 'ended') return 'Call Ended';
    if (_callStatus == 'rejected') return 'Call Declined';
    return _callStatus;
  }

  Widget _remoteVideo() {
    if (_remoteUid != null) {
      return AgoraVideoView(
        controller: VideoViewController.remote(
          rtcEngine: _engine,
          canvas: VideoCanvas(uid: _remoteUid),
          connection: RtcConnection(channelId: widget.channelId),
        ),
      );
    } else {
      return Center(
        child: Text(
          'Waiting for \${widget.targetName} to join...',
          style: GoogleFonts.inter(color: Colors.white60),
          textAlign: TextAlign.center,
        ),
      );
    }
  }

  Widget _audioCallPlaceholder() {
    return const Center(
      child: CircleAvatar(
        radius: 80,
        backgroundColor: Colors.white10,
        child: Icon(Icons.person, size: 80, color: Colors.white30),
      ),
    );
  }

  Widget _buildControlButton({
    required IconData icon,
    required VoidCallback onTap,
    required Color color,
    required Color iconColor,
    double size = 56,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: size,
        height: size,
        decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        child: Icon(icon, color: iconColor, size: size * 0.5),
      ),
    );
  }
}
