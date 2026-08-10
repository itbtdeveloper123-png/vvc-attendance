import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/whisper_service.dart';
import '../utils/app_theme.dart';
import '../widgets/vvc_global_alert.dart';

class MeetingTranscribeScreen extends StatefulWidget {
  final String? initialAudioPath;

  const MeetingTranscribeScreen({
    super.key,
    this.initialAudioPath,
  });

  @override
  State<MeetingTranscribeScreen> createState() => _MeetingTranscribeScreenState();
}

class _MeetingTranscribeScreenState extends State<MeetingTranscribeScreen> {
  final WhisperService _whisperService = WhisperService();
  final TextEditingController _urlController = TextEditingController();

  String? _selectedFilePath;
  bool _isTranscribing = false;
  WhisperTranscriptionResult? _result;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _selectedFilePath = widget.initialAudioPath;
    // Default Ngrok URL for OpenAI Whisper Large-v3 Khmer STT
    _urlController.text = 'https://uncombable-tari-brawly.ngrok-free.dev';
  }

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  Future<void> _pickAudioFile() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['mp3', 'wav', 'm4a', 'aac', 'ogg', 'flac', 'mp4'],
      );

      if (result != null && result.files.single.path != null) {
        setState(() {
          _selectedFilePath = result.files.single.path;
          _errorMessage = null;
        });
      }
    } catch (e) {
      if (mounted) {
        VvcAlert.showError(context, title: 'កំហុស', message: 'មិនអាចជ្រើសរើសឯកសារសម្លេងបានទេ៖ $e');
      }
    }
  }

  Future<void> _startTranscription() async {
    final apiUrl = _urlController.text.trim();
    if (apiUrl.isEmpty || apiUrl.contains('your-ngrok-url')) {
      VvcAlert.showError(
        context,
        title: 'ទាមទារ Ngrok URL',
        message: 'សូមបញ្ចូល Ngrok Server API URL ត្រឹមត្រូវ (ឧ. https://xxxx.ngrok-free.app)',
      );
      return;
    }

    if (_selectedFilePath == null || _selectedFilePath!.isEmpty) {
      VvcAlert.showError(
        context,
        title: 'ទាមទារឯកសារសម្លេង',
        message: 'សូមជ្រើសរើសឯកសារសម្លេងប្រជុំមុនពេលចាប់ផ្តើមបកប្រែ (STT)',
      );
      return;
    }

    setState(() {
      _isTranscribing = true;
      _errorMessage = null;
      _result = null;
    });

    try {
      final res = await _whisperService.transcribeMeeting(_selectedFilePath!, apiUrl);
      if (mounted) {
        setState(() {
          _result = res;
          _isTranscribing = false;
        });
        VvcAlert.showSuccess(
          context,
          title: 'ជោគជ័យ',
          message: 'បានបកប្រែសម្លេងប្រជុំជាអត្ថបទភាសាខ្មែរដោយជោគជ័យ!',
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _errorMessage = e.toString().replaceAll('Exception: ', '');
          _isTranscribing = false;
        });
        VvcAlert.showError(
          context,
          title: 'បរាជ័យក្នុងការបកប្រែ',
          message: _errorMessage!,
        );
      }
    }
  }

  void _copyToClipboard() {
    if (_result == null || _result!.segments.isEmpty) return;
    final text = _result!.segments
        .map((s) => '[${s.formattedTimestamp}] ${s.text}')
        .join('\n');
    Clipboard.setData(ClipboardData(text: text));
    VvcAlert.showSuccess(
      context,
      title: 'ចម្លងជោគជ័យ',
      message: 'បានចម្លងអត្ថបទបកប្រែភាសាខ្មែរទាំងអស់ទៅកាន់ Clipboard រួចរាល់!',
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: const Color(0xFF111E33),
        title: Text(
          'បកប្រែសម្លេងប្រជុំ (Khmer STT)',
          style: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.bold,
            color: Colors.white,
            fontSize: 17,
          ),
        ),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          if (_result != null && _result!.segments.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.copy_rounded, color: Colors.amberAccent),
              tooltip: 'ចម្លងអត្ថបទ',
              onPressed: _copyToClipboard,
            ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 1. Ngrok API URL Configuration Card
            _buildUrlInputCard(),
            const SizedBox(height: 14),

            // 2. Audio File Selection Card
            _buildFileSelectorCard(),
            const SizedBox(height: 16),

            // 3. Start Transcription Button
            _buildSubmitButton(),
            const SizedBox(height: 20),

            // 4. Loading / Error / Results Display
            if (_isTranscribing)
              _buildLoadingState()
            else if (_errorMessage != null)
              _buildErrorState()
            else if (_result != null)
              _buildTranscriptionResultsList(),
          ],
        ),
      ),
    );
  }

  Widget _buildUrlInputCard() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF111E33),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.cloud_sync_rounded, color: Colors.amberAccent, size: 22),
              const SizedBox(width: 8),
              Text(
                'Whisper FastAPI Server URL (Ngrok)',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 14,
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _urlController,
            style: GoogleFonts.inter(color: Colors.white, fontSize: 13.5),
            decoration: InputDecoration(
              hintText: 'https://xxxx.ngrok-free.app',
              hintStyle: GoogleFonts.inter(color: Colors.white30, fontSize: 13),
              filled: true,
              fillColor: Colors.white.withValues(alpha: 0.05),
              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.1)),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.1)),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: const BorderSide(color: Colors.amberAccent),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFileSelectorCard() {
    final fileName = _selectedFilePath != null
        ? _selectedFilePath!.split(Platform.pathSeparator).last
        : null;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF111E33),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  const Icon(Icons.audiotrack_rounded, color: AppTheme.primary, size: 22),
                  const SizedBox(width: 8),
                  Text(
                    'ឯកសារសម្លេងប្រជុំ (Audio File)',
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                      fontSize: 14,
                    ),
                  ),
                ],
              ),
              ElevatedButton.icon(
                onPressed: _pickAudioFile,
                icon: const Icon(Icons.folder_open_rounded, size: 18),
                label: Text('ជ្រើសរើស', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, fontSize: 12.5)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.primary,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.white.withValues(alpha: 0.04),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
            ),
            child: Row(
              children: [
                Icon(
                  fileName != null ? Icons.graphic_eq_rounded : Icons.info_outline_rounded,
                  color: fileName != null ? Colors.greenAccent : Colors.white38,
                  size: 20,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    fileName ?? 'មិនទាន់បានជ្រើសរើសឯកសារសម្លេង (MP3, WAV, M4A)...',
                    style: GoogleFonts.kantumruyPro(
                      color: fileName != null ? Colors.white : Colors.white38,
                      fontSize: 13,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSubmitButton() {
    return SizedBox(
      width: double.infinity,
      child: ElevatedButton.icon(
        onPressed: _isTranscribing ? null : _startTranscription,
        icon: const Icon(Icons.record_voice_over_rounded, color: Colors.black),
        label: Text(
          _isTranscribing ? 'កំពុងបកប្រែសម្លេង (STT)...' : 'ចាប់ផ្តើមបកប្រែភាសាខ្មែរ (OpenAI Whisper)',
          style: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.bold,
            fontSize: 15,
            color: Colors.black,
          ),
        ),
        style: ElevatedButton.styleFrom(
          backgroundColor: Colors.amberAccent,
          padding: const EdgeInsets.symmetric(vertical: 16),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        ),
      ),
    );
  }

  Widget _buildLoadingState() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(32),
      decoration: BoxDecoration(
        color: const Color(0xFF111E33),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.2)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const CircularProgressIndicator(color: Colors.amberAccent),
          const SizedBox(height: 20),
          Text(
            'កំពុងបកប្រែសម្លេងប្រជុំជាអត្ថបទភាសាខ្មែរ...',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 15,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'OpenAI Whisper Large-v3 (CUDA High Precision Model)',
            style: GoogleFonts.inter(
              color: Colors.white54,
              fontSize: 12,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorState() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: Colors.redAccent.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.redAccent.withValues(alpha: 0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.error_outline_rounded, color: Colors.redAccent, size: 22),
              const SizedBox(width: 8),
              Text(
                'កំហុសក្នុងការបកប្រែ',
                style: GoogleFonts.kantumruyPro(color: Colors.redAccent, fontWeight: FontWeight.bold, fontSize: 14.5),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            _errorMessage ?? 'កំហុសមិនស្គាល់',
            style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13),
          ),
        ],
      ),
    );
  }

  Widget _buildTranscriptionResultsList() {
    final segments = _result?.segments ?? [];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              'លទ្ធផលបកប្រែជាភាសាខ្មែរ (Khmer Text):',
              style: GoogleFonts.kantumruyPro(
                color: Colors.amberAccent,
                fontWeight: FontWeight.bold,
                fontSize: 15,
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: Colors.green.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.green.withValues(alpha: 0.4)),
              ),
              child: Text(
                '${segments.length} ចំណុច',
                style: GoogleFonts.kantumruyPro(color: Colors.greenAccent, fontSize: 12, fontWeight: FontWeight.bold),
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        ListView.separated(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          itemCount: segments.length,
          separatorBuilder: (ctx, i) => const SizedBox(height: 10),
          itemBuilder: (ctx, index) {
            final seg = segments[index];
            return Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: const Color(0xFF111E33),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                    decoration: BoxDecoration(
                      color: AppTheme.primary.withValues(alpha: 0.2),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Text(
                      '[${seg.formattedTimestamp}]',
                      style: GoogleFonts.inter(
                        color: Colors.cyanAccent,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    seg.text,
                    style: GoogleFonts.kantumruyPro(
                      color: Colors.white,
                      fontSize: 14.5,
                      height: 1.5,
                    ),
                  ),
                ],
              ),
            );
          },
        ),
      ],
    );
  }
}
