import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:google_mlkit_digital_ink_recognition/google_mlkit_digital_ink_recognition.dart' as mlkit;
import '../services/digital_ink_service.dart';

/// Digital Ink Recognition Screen (Handwriting & Shape recognition)
class DigitalInkScreen extends StatefulWidget {
  const DigitalInkScreen({super.key});

  @override
  State<DigitalInkScreen> createState() => _DigitalInkScreenState();
}

class _DigitalInkScreenState extends State<DigitalInkScreen> {
  final DigitalInkService _inkService = DigitalInkService();
  final mlkit.Ink _ink = mlkit.Ink();

  final List<_StrokeData> _strokes = [];
  _StrokeData? _currentStroke;

  final TextEditingController _textController = TextEditingController();
  List<mlkit.RecognitionCandidate> _candidates = [];
  bool _isRecognizing = false;

  String _selectedLanguage = 'en-US';
  final Map<String, String> _languages = {
    'en-US': 'អង់គ្លេស (English)',
    'km-KH': 'ខ្មែរ (Khmer)',
    'zxx-x-autodraw': 'រូបរាង និង Emoji',
  };

  Color _penColor = Colors.white;
  final double _penWidth = 4.0;

  @override
  void dispose() {
    _inkService.dispose();
    _textController.dispose();
    super.dispose();
  }

  void _onPanStart(DragStartDetails details) {
    final point = mlkit.StrokePoint(
      x: details.localPosition.dx,
      y: details.localPosition.dy,
      t: DateTime.now().millisecondsSinceEpoch,
    );
    _currentStroke = _StrokeData(color: _penColor, width: _penWidth);
    _currentStroke!.points.add(details.localPosition);
    _currentStroke!.mlkitStroke.points.add(point);
    setState(() {
      _strokes.add(_currentStroke!);
    });
  }

  void _onPanUpdate(DragUpdateDetails details) {
    if (_currentStroke == null) return;
    final point = mlkit.StrokePoint(
      x: details.localPosition.dx,
      y: details.localPosition.dy,
      t: DateTime.now().millisecondsSinceEpoch,
    );
    setState(() {
      _currentStroke!.points.add(details.localPosition);
      _currentStroke!.mlkitStroke.points.add(point);
    });
  }

  void _onPanEnd(DragEndDetails details) {
    if (_currentStroke != null) {
      _ink.strokes.add(_currentStroke!.mlkitStroke);
      _currentStroke = null;
      _recognizeHandwriting();
    }
  }

  Future<void> _recognizeHandwriting() async {
    if (_ink.strokes.isEmpty) return;

    setState(() {
      _isRecognizing = true;
    });

    try {
      final results = await _inkService.recognizeInk(_ink);
      setState(() {
        _candidates = results;
        _isRecognizing = false;
      });
    } catch (e) {
      setState(() {
        _isRecognizing = false;
      });
    }
  }

  void _clearCanvas() {
    setState(() {
      _strokes.clear();
      _ink.strokes.clear();
      _candidates.clear();
    });
  }

  void _undoStroke() {
    if (_strokes.isNotEmpty) {
      setState(() {
        _strokes.removeLast();
        if (_ink.strokes.isNotEmpty) {
          _ink.strokes.removeLast();
        }
      });
      _recognizeHandwriting();
    }
  }

  void _appendCandidateText(String text) {
    setState(() {
      if (_textController.text.isNotEmpty) {
        _textController.text += ' $text';
      } else {
        _textController.text = text;
      }
      _clearCanvas();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF0F172A),
        elevation: 0,
        centerTitle: true,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          'សរសេរដៃ (Digital Ink OCR)',
          style: GoogleFonts.kantumruyPro(fontSize: 17, fontWeight: FontWeight.bold, color: Colors.white),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.undo_rounded, color: Colors.white70),
            onPressed: _undoStroke,
            tooltip: 'សារដើម',
          ),
          IconButton(
            icon: const Icon(Icons.delete_outline_rounded, color: Colors.redAccent),
            onPressed: _clearCanvas,
            tooltip: 'សម្អាត',
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            // Top Toolbar: Language Selector & Color Palette
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              color: const Color(0xFF141428),
              child: Row(
                children: [
                  // Language Dropdown
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(alpha: 0.08),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.white.withValues(alpha: 0.15)),
                    ),
                    child: DropdownButtonHideUnderline(
                      child: DropdownButton<String>(
                        value: _selectedLanguage,
                        dropdownColor: const Color(0xFF1E293B),
                        style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 12),
                        icon: const Icon(Icons.keyboard_arrow_down_rounded, color: Colors.tealAccent, size: 20),
                        items: _languages.entries.map((e) {
                          return DropdownMenuItem<String>(
                            value: e.key,
                            child: Text(e.value),
                          );
                        }).toList(),
                        onChanged: (lang) async {
                          if (lang != null) {
                            setState(() {
                              _selectedLanguage = lang;
                            });
                            await _inkService.switchLanguage(lang);
                            _recognizeHandwriting();
                          }
                        },
                      ),
                    ),
                  ),

                  const Spacer(),

                  // Pen Color Selectors
                  Row(
                    children: [Colors.white, Colors.amber, Colors.cyanAccent, Colors.pinkAccent].map((c) {
                      final isSelected = _penColor == c;
                      return GestureDetector(
                        onTap: () {
                          setState(() {
                            _penColor = c;
                          });
                        },
                        child: Container(
                          margin: const EdgeInsets.only(left: 8),
                          width: 26,
                          height: 26,
                          decoration: BoxDecoration(
                            color: c,
                            shape: BoxShape.circle,
                            border: Border.all(color: isSelected ? Colors.tealAccent : Colors.white24, width: isSelected ? 2.5 : 1),
                          ),
                        ),
                      );
                    }).toList(),
                  ),
                ],
              ),
            ),

            // Real-time Recognition Candidates Bar
            Container(
              height: 48,
              color: const Color(0xFF1E293B),
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              child: Row(
                children: [
                  if (_isRecognizing)
                    const SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(strokeWidth: 2, color: Colors.tealAccent),
                    )
                  else
                    const Icon(Icons.auto_awesome_rounded, color: Colors.tealAccent, size: 18),
                  const SizedBox(width: 8),
                  Expanded(
                    child: _candidates.isEmpty
                        ? Text(
                            'សរសេរដៃលើអេក្រង់ខាងក្រោម...',
                            style: GoogleFonts.kantumruyPro(color: Colors.white38, fontSize: 12),
                          )
                        : ListView.builder(
                            scrollDirection: Axis.horizontal,
                            itemCount: _candidates.length,
                            itemBuilder: (context, index) {
                              final text = _candidates[index].text;
                              return GestureDetector(
                                onTap: () => _appendCandidateText(text),
                                child: Container(
                                  margin: const EdgeInsets.only(right: 8),
                                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                                  decoration: BoxDecoration(
                                    color: Colors.white.withValues(alpha: 0.1),
                                    borderRadius: BorderRadius.circular(16),
                                    border: Border.all(color: Colors.tealAccent.withValues(alpha: 0.3)),
                                  ),
                                  child: Text(
                                    text,
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.tealAccent,
                                      fontSize: 13,
                                      fontWeight: FontWeight.bold,
                                    ),
                                  ),
                                ),
                              );
                            },
                          ),
                  ),
                ],
              ),
            ),

            // Touchscreen Drawing Canvas Area
            Expanded(
              child: Container(
                margin: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFF0A0A16),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
                ),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(16),
                  child: GestureDetector(
                    onPanStart: _onPanStart,
                    onPanUpdate: _onPanUpdate,
                    onPanEnd: _onPanEnd,
                    child: CustomPaint(
                      painter: _InkCanvasPainter(strokes: _strokes),
                      size: Size.infinite,
                    ),
                  ),
                ),
              ),
            ),

            // Extracted / Accumulated Text Output Area
            Container(
              padding: const EdgeInsets.all(16),
              decoration: const BoxDecoration(
                color: Color(0xFF141428),
                borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(
                        'អត្ថបទដែលទទួលស្គាល់បាន (Recognized Text)៖',
                        style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.w600),
                      ),
                      const Spacer(),
                      IconButton(
                        icon: const Icon(Icons.copy_rounded, color: Colors.tealAccent, size: 18),
                        onPressed: () {
                          if (_textController.text.isNotEmpty) {
                            Clipboard.setData(ClipboardData(text: _textController.text));
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(
                                content: Text('ចម្លងអត្ថបទចូល Clipboard រួចរាល់', style: GoogleFonts.kantumruyPro()),
                                backgroundColor: Colors.teal,
                              ),
                            );
                          }
                        },
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  TextField(
                    controller: _textController,
                    maxLines: 3,
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14),
                    decoration: InputDecoration(
                      hintText: 'អត្ថបទនឹងបង្ហាញនៅទីនេះ ឬចុចលើពាក្យខាងលើដើម្បីបន្ថែម...',
                      hintStyle: GoogleFonts.kantumruyPro(color: Colors.white24, fontSize: 12),
                      filled: true,
                      fillColor: Colors.white.withValues(alpha: 0.05),
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide.none),
                      contentPadding: const EdgeInsets.all(12),
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

class _StrokeData {
  final Color color;
  final double width;
  final List<Offset> points = [];
  final mlkit.Stroke mlkitStroke = mlkit.Stroke();

  _StrokeData({required this.color, required this.width});
}

class _InkCanvasPainter extends CustomPainter {
  final List<_StrokeData> strokes;

  _InkCanvasPainter({required this.strokes});

  @override
  void paint(Canvas canvas, Size size) {
    for (final stroke in strokes) {
      if (stroke.points.isEmpty) continue;

      final paint = Paint()
        ..color = stroke.color
        ..strokeCap = StrokeCap.round
        ..strokeJoin = StrokeJoin.round
        ..strokeWidth = stroke.width
        ..style = PaintingStyle.stroke;

      if (stroke.points.length == 1) {
        canvas.drawCircle(stroke.points.first, stroke.width / 2, paint..style = PaintingStyle.fill);
      } else {
        final path = Path()..moveTo(stroke.points.first.dx, stroke.points.first.dy);
        for (int i = 1; i < stroke.points.length; i++) {
          path.lineTo(stroke.points[i].dx, stroke.points[i].dy);
        }
        canvas.drawPath(path, paint);
      }
    }
  }

  @override
  bool shouldRepaint(covariant _InkCanvasPainter oldDelegate) => true;
}
