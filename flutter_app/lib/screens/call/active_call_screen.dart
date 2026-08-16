import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:agora_rtc_engine/agora_rtc_engine.dart';
import 'package:permission_handler/permission_handler.dart';
import '../../services/call_service.dart';
import '../../services/api_service.dart';

const String appId = '0170fac7ff8444fcb7f09528e18b27bf';

class ActiveCallScreen extends StatefulWidget {
  final String callId;
  final String channelId;
  final String targetName;
  final String targetPhoto;
  final bool isVideoCall;
  final bool isCaller;

  const ActiveCallScreen({
    super.key,
    required this.callId,
    required this.channelId,
    required this.targetName,
    this.targetPhoto = '',
    required this.isVideoCall,
    required this.isCaller,
  });

  @override
  State<ActiveCallScreen> createState() => _ActiveCallScreenState();
}

class _ActiveCallScreenState extends State<ActiveCallScreen>
    with SingleTickerProviderStateMixin {
  final CallService _callService = CallService();
  late RtcEngine _engine;
  bool _engineInitialized = false;

  int? _remoteUid;
  bool _localUserJoined = false;
  bool _hasRemoteVideo = false;
  bool _isRemoteVideoMuted = false;
  bool _isRemoteAudioMuted = false;

  late bool _isVideoEnabled;
  bool _isLocalCameraMuted = false;
  bool _isLocalAudioMuted = false;
  bool _isSpeakerOn = true;
  bool _isFrontCamera = true;
  bool _isSwappedView = false; // Swap PIP with Fullscreen

  // Draggable PIP coordinates
  Offset _pipPosition = const Offset(20, 90);

  StreamSubscription? _callStateSub;
  String _callStatus = 'connecting'; // 'connecting', 'ringing', 'connected', 'ended'
  int _callSeconds = 0;
  Timer? _durationTimer;

  late AnimationController _rippleController;
  late Animation<double> _rippleAnimation;

  bool _isEnding = false;

  @override
  void initState() {
    super.initState();
    _isVideoEnabled = widget.isVideoCall;
    _callStatus = widget.isCaller ? 'ringing' : 'connecting';

    _rippleController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 2200),
    )..repeat();

    _rippleAnimation = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(parent: _rippleController, curve: Curves.easeOutCubic),
    );

    _initAgora();
    _listenToCallState();
  }

  void _listenToCallState() {
    _callStateSub = _callService.getCallState(widget.callId).listen((doc) {
      if (!mounted || _isEnding) return;

      if (doc.exists) {
        final data = doc.data() as Map<String, dynamic>;
        final status = data['status'] as String? ?? 'connecting';

        if (status == 'accepted' || status == 'connected') {
          if (_callStatus != 'connected') {
            setState(() {
              _callStatus = 'connected';
            });
          }
          _startCallTimer();
        } else if (status == 'ended' || status == 'rejected') {
          _endCallLocally();
        } else if (status == 'ringing' || status == 'connecting') {
          // Do not overwrite connected status or when remote UID is already present
          if (_callStatus != 'connected' && _remoteUid == null && _callSeconds == 0) {
            if (mounted) {
              setState(() => _callStatus = status);
            }
          }
        }
      } else {
        _endCallLocally();
      }
    });
  }

  void _startCallTimer() {
    if (_durationTimer != null && _durationTimer!.isActive) return;
    _durationTimer?.cancel();
    _durationTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (!mounted || _isEnding) {
        timer.cancel();
        return;
      }
      if (_callStatus == 'connected' || _remoteUid != null) {
        setState(() {
          _callSeconds++;
        });
      }
    });
  }

  Future<void> _initAgora() async {
    try {
      // 1. Request microphone & camera permissions
      await [Permission.microphone, Permission.camera].request();

      // 2. Initialize Engine
      _engine = createAgoraRtcEngine();
      await _engine.initialize(
        const RtcEngineContext(
          appId: appId,
          channelProfile: ChannelProfileType.channelProfileCommunication,
        ),
      );

      // 3. Register Event Handlers
      _engine.registerEventHandler(
        RtcEngineEventHandler(
          onJoinChannelSuccess: (RtcConnection connection, int elapsed) {
            debugPrint("Agora: Local user ${connection.localUid} joined channel");
            if (mounted) {
              setState(() {
                _localUserJoined = true;
              });
            }
          },
          onUserJoined: (RtcConnection connection, int remoteUid, int elapsed) {
            debugPrint("Agora: Remote user $remoteUid joined");
            if (mounted) {
              setState(() {
                _remoteUid = remoteUid;
                _callStatus = 'connected';
              });
              _startCallTimer();
            }
          },
          onUserOffline: (
            RtcConnection connection,
            int remoteUid,
            UserOfflineReasonType reason,
          ) {
            debugPrint("Agora: Remote user $remoteUid left channel");
            if (mounted) {
              setState(() {
                _remoteUid = null;
                _hasRemoteVideo = false;
              });
              _endCallAndLeave();
            }
          },
          onFirstRemoteVideoFrame: (
            RtcConnection connection,
            int remoteUid,
            int width,
            int height,
            int elapsed,
          ) {
            debugPrint("Agora: First remote video frame from $remoteUid ($width x $height)");
            if (mounted) {
              setState(() {
                _remoteUid = remoteUid;
                _hasRemoteVideo = true;
                _isRemoteVideoMuted = false;
              });
            }
          },
          onRemoteVideoStateChanged: (
            RtcConnection connection,
            int remoteUid,
            RemoteVideoState state,
            RemoteVideoStateReason reason,
            int elapsed,
          ) {
            debugPrint("Agora: Remote video state changed $state, reason $reason");
            if (mounted) {
              setState(() {
                _remoteUid = remoteUid;
                _hasRemoteVideo = state == RemoteVideoState.remoteVideoStateDecoding ||
                    state == RemoteVideoState.remoteVideoStateStarting;
                _isRemoteVideoMuted = state == RemoteVideoState.remoteVideoStateStopped ||
                    reason == RemoteVideoStateReason.remoteVideoStateReasonRemoteMuted;
              });
            }
          },
          onUserMuteVideo: (RtcConnection connection, int remoteUid, bool muted) {
            debugPrint("Agora: Remote user $remoteUid muted video: $muted");
            if (mounted) {
              setState(() {
                _isRemoteVideoMuted = muted;
              });
            }
          },
          onUserMuteAudio: (RtcConnection connection, int remoteUid, bool muted) {
            debugPrint("Agora: Remote user $remoteUid muted audio: $muted");
            if (mounted) {
              setState(() {
                _isRemoteAudioMuted = muted;
              });
            }
          },
          onError: (ErrorCodeType err, String msg) {
            debugPrint("Agora Error [$err]: $msg");
          },
        ),
      );

      // 4. Configure Audio for Clear Full-Duplex VoIP Call
      await _engine.enableAudio();
      await _engine.enableLocalAudio(true);
      await _engine.setClientRole(role: ClientRoleType.clientRoleBroadcaster);
      await _engine.setAudioProfile(
        profile: AudioProfileType.audioProfileDefault,
        scenario: AudioScenarioType.audioScenarioMeeting,
      );
      await _engine.setDefaultAudioRouteToSpeakerphone(_isSpeakerOn);
      await _engine.setEnableSpeakerphone(_isSpeakerOn);
      await _engine.adjustRecordingSignalVolume(100);
      await _engine.adjustPlaybackSignalVolume(100);
      await _engine.muteLocalAudioStream(false);
      await _engine.muteAllRemoteAudioStreams(false);

      // 5. Configure Video if video call
      if (_isVideoEnabled) {
        await _engine.enableVideo();
        await _engine.startPreview();
        await _engine.enableLocalVideo(true);
      } else {
        await _engine.disableVideo();
      }

      // 6. Fetch Dynamic Agora RTC Token from Backend
      String token = '';
      try {
        final tokenRes = await ApiService().fetchAgoraToken(widget.channelId);
        if (tokenRes['success'] == true && tokenRes['token'] != null) {
          token = tokenRes['token'].toString();
          debugPrint("Agora: Successfully retrieved RTC Token from server!");
        } else {
          debugPrint("Agora Token fetch notice: ${tokenRes['message']}");
        }
      } catch (e) {
        debugPrint("Agora Token fetch error: $e");
      }

      // 7. Join Channel with Token
      await _engine.joinChannel(
        token: token,
        channelId: widget.channelId,
        uid: 0,
        options: ChannelMediaOptions(
          clientRoleType: ClientRoleType.clientRoleBroadcaster,
          channelProfile: ChannelProfileType.channelProfileCommunication,
          publishMicrophoneTrack: true,
          publishCameraTrack: _isVideoEnabled,
          autoSubscribeAudio: true,
          autoSubscribeVideo: true,
          enableAudioRecordingOrPlayout: true,
        ),
      );

      if (mounted) {
        setState(() {
          _engineInitialized = true;
        });
      }
    } catch (e) {
      debugPrint("Agora Init Exception: $e");
    }
  }

  void _toggleMuteAudio() async {
    final nextMute = !_isLocalAudioMuted;
    setState(() {
      _isLocalAudioMuted = nextMute;
    });
    await _engine.muteLocalAudioStream(nextMute);
  }

  void _toggleSpeaker() async {
    final nextSpeaker = !_isSpeakerOn;
    setState(() {
      _isSpeakerOn = nextSpeaker;
    });
    await _engine.setEnableSpeakerphone(nextSpeaker);
  }

  void _toggleVideo() async {
    final nextVideo = !_isVideoEnabled;
    setState(() {
      _isVideoEnabled = nextVideo;
      _isLocalCameraMuted = !nextVideo;
    });

    if (nextVideo) {
      await _engine.enableVideo();
      await _engine.startPreview();
      await _engine.enableLocalVideo(true);
      await _engine.muteLocalVideoStream(false);
      await _engine.updateChannelMediaOptions(
        const ChannelMediaOptions(publishCameraTrack: true),
      );
    } else {
      await _engine.muteLocalVideoStream(true);
      await _engine.stopPreview();
      await _engine.updateChannelMediaOptions(
        const ChannelMediaOptions(publishCameraTrack: false),
      );
    }
  }

  void _switchCamera() async {
    if (!_isVideoEnabled) return;
    await _engine.switchCamera();
    setState(() {
      _isFrontCamera = !_isFrontCamera;
    });
  }

  void _endCallAndLeave() {
    if (_isEnding) return;
    _isEnding = true;

    _durationTimer?.cancel();
    try {
      _rippleController.stop();
    } catch (_) {}

    // Leave Agora channel immediately
    if (_engineInitialized) {
      try {
        _engine.leaveChannel();
      } catch (e) {
        debugPrint("Agora leaveChannel error: $e");
      }
    }

    // Inform Firestore & save call log to chat in background (fire-and-forget)
    _callService.endCall(widget.callId, duration: _callSeconds).catchError((e) {
      debugPrint("endCall background error: $e");
    });

    // Exit call screen immediately
    _endCallLocally();
  }

  void _endCallLocally() {
    _isEnding = true;
    _durationTimer?.cancel();
    try {
      _rippleController.stop();
    } catch (_) {}

    if (_engineInitialized) {
      try {
        _engine.leaveChannel();
      } catch (_) {}
    }

    if (mounted) {
      if (Navigator.of(context).canPop()) {
        Navigator.of(context).pop();
      }
    }
  }

  @override
  void dispose() {
    _isEnding = true;
    _durationTimer?.cancel();
    _callStateSub?.cancel();
    _rippleController.dispose();
    if (_engineInitialized) {
      try {
        _engine.leaveChannel();
        _engine.release();
      } catch (e) {
        debugPrint("Agora dispose error: $e");
      }
    }
    super.dispose();
  }

  String _formatTimer(int totalSeconds) {
    final minutes = (totalSeconds ~/ 60).toString().padLeft(2, '0');
    final seconds = (totalSeconds % 60).toString().padLeft(2, '0');
    return '$minutes:$seconds';
  }

  String _getStatusText() {
    if (_callStatus == 'connected' || _remoteUid != null || _callSeconds > 0) {
      return _formatTimer(_callSeconds);
    }
    if (_callStatus == 'ringing') return 'កំពុងរោទ៍... (Ringing)';
    if (_callStatus == 'connecting') return 'កំពុងតភ្ជាប់... (Connecting)';
    if (_callStatus == 'ended') return 'ការហៅបានបញ្ចប់';
    if (_callStatus == 'rejected') return 'បានបដិសេធ';
    return _callStatus;
  }

  @override
  Widget build(BuildContext context) {
    final fullAvatarUrl = ApiService.getFullImageUrl(widget.targetPhoto);
    final size = MediaQuery.of(context).size;

    return Scaffold(
      backgroundColor: const Color(0xFF090D16),
      body: SafeArea(
        top: false,
        child: Stack(
          children: [
            // 1. Fullscreen Main View (Remote Video or Audio Mode)
            Positioned.fill(
              child: _buildMainView(fullAvatarUrl),
            ),

            // 2. Floating Local Camera Preview (PiP) for Video Call
            if (_isVideoEnabled && _localUserJoined && !_isLocalCameraMuted && _engineInitialized)
              Positioned(
                left: _pipPosition.dx,
                top: _pipPosition.dy,
                child: GestureDetector(
                  onPanUpdate: (details) {
                    setState(() {
                      _pipPosition = Offset(
                        (_pipPosition.dx + details.delta.dx)
                            .clamp(10.0, size.width - 130.0),
                        (_pipPosition.dy + details.delta.dy)
                            .clamp(60.0, size.height - 240.0),
                      );
                    });
                  },
                  onTap: () {
                    setState(() {
                      _isSwappedView = !_isSwappedView;
                    });
                  },
                  child: Container(
                    width: 120,
                    height: 170,
                    decoration: BoxDecoration(
                      color: Colors.black,
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(
                        color: const Color(0xFFF59E0B).withAlpha(160),
                        width: 2,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withAlpha(180),
                          blurRadius: 16,
                          offset: const Offset(0, 6),
                        ),
                      ],
                    ),
                    clipBehavior: Clip.antiAlias,
                    child: Stack(
                      children: [
                        AgoraVideoView(
                          controller: VideoViewController(
                            rtcEngine: _engine,
                            canvas: const VideoCanvas(
                              uid: 0,
                              renderMode: RenderModeType.renderModeHidden,
                            ),
                          ),
                        ),
                        Positioned(
                          bottom: 6,
                          left: 6,
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: Colors.black.withAlpha(140),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              'ខ្ញុំ (You)',
                              style: GoogleFonts.kantumruyPro(
                                color: Colors.white,
                                fontSize: 10,
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),

            // 3. Top Header: Gradient overlay, Badges, Name, Duration
            Positioned(
              top: 0,
              left: 0,
              right: 0,
              child: Container(
                padding: EdgeInsets.only(
                  top: MediaQuery.of(context).padding.top + 12,
                  left: 20,
                  right: 20,
                  bottom: 24,
                ),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      Colors.black.withAlpha(200),
                      Colors.black.withAlpha(80),
                      Colors.transparent,
                    ],
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                  ),
                ),
                child: Column(
                  children: [
                    // Security / HD Badge
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
                      decoration: BoxDecoration(
                        color: Colors.white.withAlpha(25),
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(color: Colors.white.withAlpha(35)),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            _isVideoEnabled ? Icons.videocam_rounded : Icons.lock_rounded,
                            size: 13,
                            color: const Color(0xFF10B981),
                          ),
                          const SizedBox(width: 6),
                          Text(
                            _isVideoEnabled ? 'VVC HD Video Call' : 'VVC End-to-End Encrypted',
                            style: GoogleFonts.inter(
                              color: Colors.white70,
                              fontSize: 11,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ],
                      ),
                    ),

                    const SizedBox(height: 12),

                    // Target Name
                    Text(
                      widget.targetName,
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontSize: 26,
                        fontWeight: FontWeight.bold,
                        letterSpacing: 0.3,
                        shadows: [
                          const Shadow(
                            color: Colors.black54,
                            blurRadius: 10,
                          ),
                        ],
                      ),
                      textAlign: TextAlign.center,
                    ),

                    const SizedBox(height: 4),

                    // Status / Timer
                    AnimatedSwitcher(
                      duration: const Duration(milliseconds: 250),
                      child: Text(
                        _getStatusText(),
                        key: ValueKey(_callStatus + _callSeconds.toString()),
                        style: GoogleFonts.inter(
                          color: _callStatus == 'connected'
                              ? const Color(0xFF10B981)
                              : Colors.white70,
                          fontSize: _callStatus == 'connected' ? 16 : 14,
                          fontWeight: _callStatus == 'connected'
                              ? FontWeight.w700
                              : FontWeight.w400,
                          letterSpacing: 0.5,
                          shadows: [
                            const Shadow(
                              color: Colors.black54,
                              blurRadius: 8,
                            ),
                          ],
                        ),
                      ),
                    ),

                    // Remote Participant Status Badges (Muted mic / camera off)
                    if (_callStatus == 'connected')
                      Padding(
                        padding: const EdgeInsets.only(top: 8),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            if (_isRemoteAudioMuted)
                              Container(
                                margin: const EdgeInsets.symmetric(horizontal: 4),
                                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
                                decoration: BoxDecoration(
                                  color: Colors.redAccent.withAlpha(60),
                                  borderRadius: BorderRadius.circular(12),
                                  border: Border.all(color: Colors.redAccent.withAlpha(100)),
                                ),
                                child: Row(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    const Icon(Icons.mic_off_rounded, size: 12, color: Colors.white),
                                    const SizedBox(width: 4),
                                    Text(
                                      '${widget.targetName} បានបិទសំឡេង',
                                      style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 11),
                                    ),
                                  ],
                                ),
                              ),
                            if (_isRemoteVideoMuted && _isVideoEnabled)
                              Container(
                                margin: const EdgeInsets.symmetric(horizontal: 4),
                                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
                                decoration: BoxDecoration(
                                  color: Colors.amber.shade800.withAlpha(60),
                                  borderRadius: BorderRadius.circular(12),
                                  border: Border.all(color: Colors.amber.shade800.withAlpha(100)),
                                ),
                                child: Row(
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    const Icon(Icons.videocam_off_rounded, size: 12, color: Colors.white),
                                    const SizedBox(width: 4),
                                    Text(
                                      'បានបិទកាមេរ៉ា',
                                      style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 11),
                                    ),
                                  ],
                                ),
                              ),
                          ],
                        ),
                      ),
                  ],
                ),
              ),
            ),

            // 4. Bottom Glassmorphic Control Bar
            Positioned(
              bottom: 0,
              left: 0,
              right: 0,
              child: Container(
                padding: EdgeInsets.only(
                  top: 24,
                  bottom: MediaQuery.of(context).padding.bottom + 20,
                  left: 20,
                  right: 20,
                ),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      Colors.transparent,
                      Colors.black.withAlpha(160),
                      Colors.black.withAlpha(220),
                    ],
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                  ),
                ),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                  decoration: BoxDecoration(
                    color: const Color(0xFF1E293B).withAlpha(200),
                    borderRadius: BorderRadius.circular(36),
                    border: Border.all(color: Colors.white.withAlpha(30)),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withAlpha(160),
                        blurRadius: 28,
                        offset: const Offset(0, 10),
                      ),
                    ],
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      // 1. Mute / Unmute Mic
                      _buildControlButton(
                        icon: _isLocalAudioMuted
                            ? Icons.mic_off_rounded
                            : Icons.mic_rounded,
                        label: _isLocalAudioMuted ? 'បើកសំឡេង' : 'បិទសំឡេង',
                        isActive: _isLocalAudioMuted,
                        activeColor: Colors.amber.shade700,
                        onTap: _toggleMuteAudio,
                      ),

                      // 2. Speakerphone Toggle
                      _buildControlButton(
                        icon: _isSpeakerOn
                            ? Icons.volume_up_rounded
                            : Icons.volume_down_rounded,
                        label: _isSpeakerOn ? 'Speaker' : 'Earpiece',
                        isActive: _isSpeakerOn,
                        activeColor: const Color(0xFF3B82F6),
                        onTap: _toggleSpeaker,
                      ),

                      // 3. Video Camera Toggle (Works for both Voice & Video Calls)
                      _buildControlButton(
                        icon: _isVideoEnabled
                            ? Icons.videocam_rounded
                            : Icons.videocam_off_rounded,
                        label: _isVideoEnabled ? 'បិទវីដេអូ' : 'បើកវីដេអូ',
                        isActive: _isVideoEnabled,
                        activeColor: const Color(0xFF10B981),
                        onTap: _toggleVideo,
                      ),

                      // 4. Flip Camera (if Video Active)
                      if (_isVideoEnabled)
                        _buildControlButton(
                          icon: Icons.flip_camera_ios_rounded,
                          label: 'ប្តូរកាមេរ៉ា',
                          onTap: _switchCamera,
                        ),

                      // 5. End Call Button (Large Red Glow)
                      GestureDetector(
                        behavior: HitTestBehavior.opaque,
                        onTap: _endCallAndLeave,
                        child: Container(
                          width: 56,
                          height: 56,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            gradient: const LinearGradient(
                              colors: [Color(0xFFEF4444), Color(0xFFDC2626)],
                              begin: Alignment.topLeft,
                              end: Alignment.bottomRight,
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: const Color(0xFFEF4444).withAlpha(120),
                                blurRadius: 20,
                                spreadRadius: 2,
                                offset: const Offset(0, 4),
                              ),
                            ],
                          ),
                          child: const Center(
                            child: Icon(
                              Icons.call_end_rounded,
                              color: Colors.white,
                              size: 28,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildMainView(String fullAvatarUrl) {
    // If Video Call with active remote video stream
    if (_isVideoEnabled && _remoteUid != null && _hasRemoteVideo && !_isRemoteVideoMuted && _engineInitialized) {
      return AgoraVideoView(
        controller: VideoViewController.remote(
          rtcEngine: _engine,
          canvas: VideoCanvas(
            uid: _remoteUid,
            renderMode: RenderModeType.renderModeHidden,
          ),
          connection: RtcConnection(channelId: widget.channelId),
        ),
      );
    }

    // Default: Premium Voice Avatar UI with ambient glow
    return Container(
      decoration: const BoxDecoration(
        gradient: RadialGradient(
          center: Alignment(0, -0.15),
          radius: 0.9,
          colors: [
            Color(0xFF1E293B),
            Color(0xFF0F172A),
            Color(0xFF070B12),
          ],
        ),
      ),
      child: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const SizedBox(height: 20),

            // Pulsating Rings around Avatar
            Stack(
              alignment: Alignment.center,
              children: [
                // Ripple 1
                if (_callStatus == 'connected' || _callStatus == 'ringing')
                  AnimatedBuilder(
                    animation: _rippleAnimation,
                    builder: (context, child) {
                      final scale = 1.0 + (_rippleAnimation.value * 0.45);
                      final opacity = (1.0 - _rippleAnimation.value).clamp(0.0, 1.0);
                      return Transform.scale(
                        scale: scale,
                        child: Container(
                          width: 175,
                          height: 175,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: const Color(0xFFF59E0B).withAlpha((opacity * 55).toInt()),
                          ),
                        ),
                      );
                    },
                  ),

                // Ripple 2
                if (_callStatus == 'connected' || _callStatus == 'ringing')
                  AnimatedBuilder(
                    animation: _rippleAnimation,
                    builder: (context, child) {
                      final scale = 1.0 + (_rippleAnimation.value * 0.25);
                      final opacity = (1.0 - _rippleAnimation.value).clamp(0.0, 1.0);
                      return Transform.scale(
                        scale: scale,
                        child: Container(
                          width: 175,
                          height: 175,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: const Color(0xFF3B82F6).withAlpha((opacity * 45).toInt()),
                          ),
                        ),
                      );
                    },
                  ),

                // Avatar Container
                Container(
                  width: 160,
                  height: 160,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: const LinearGradient(
                      colors: [Color(0xFF334155), Color(0xFF1E293B)],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    border: Border.all(
                      color: const Color(0xFFF59E0B).withAlpha(180),
                      width: 3.5,
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFFF59E0B).withAlpha(90),
                        blurRadius: 32,
                        spreadRadius: 2,
                      ),
                      BoxShadow(
                        color: Colors.black.withAlpha(160),
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
              ],
            ),

            const SizedBox(height: 30),

            if (_isVideoEnabled && (_remoteUid == null || !_hasRemoteVideo))
              Container(
                margin: const EdgeInsets.symmetric(horizontal: 40),
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                decoration: BoxDecoration(
                  color: Colors.black.withAlpha(100),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: Colors.white.withAlpha(20)),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        valueColor: AlwaysStoppedAnimation<Color>(Color(0xFFF59E0B)),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Flexible(
                      child: Text(
                        'កំពុងរង់ចាំកាមេរ៉ាពី ${widget.targetName}...',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white70,
                          fontSize: 13,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                ),
              ),

            const SizedBox(height: 100),
          ],
        ),
      ),
    );
  }

  Widget _defaultAvatar() {
    return Center(
      child: Icon(
        Icons.person_rounded,
        size: 80,
        color: Colors.white.withAlpha(160),
      ),
    );
  }

  Widget _buildControlButton({
    required IconData icon,
    required String label,
    required VoidCallback onTap,
    bool isActive = false,
    Color? activeColor,
  }) {
    final bgColor = isActive
        ? (activeColor ?? Colors.white)
        : Colors.white.withAlpha(25);
    final iconColor = isActive ? Colors.white : Colors.white70;

    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: 48,
        height: 48,
        decoration: BoxDecoration(
          color: bgColor,
          shape: BoxShape.circle,
          border: Border.all(
            color: isActive
                ? (activeColor ?? Colors.white).withAlpha(140)
                : Colors.white.withAlpha(20),
          ),
        ),
        child: Icon(icon, color: iconColor, size: 22),
      ),
    );
  }
}
