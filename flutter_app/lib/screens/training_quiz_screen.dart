import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:vvc_hrm/services/api_service.dart';
import '../utils/app_theme.dart';

class TrainingQuizScreen extends StatefulWidget {
  const TrainingQuizScreen({super.key});

  @override
  State<TrainingQuizScreen> createState() => _TrainingQuizScreenState();
}

class _TrainingQuizScreenState extends State<TrainingQuizScreen> {
  final ApiService _apiService = ApiService();
  int _currentQuestionIndex = 0;
  int _score = 0;
  bool _isAnswered = false;
  int _selectedAnswerIndex = -1;
  bool _isLoading = true;
  String _errorMessage = '';

  List<Map<String, dynamic>> _questions = [];

  @override
  void initState() {
    super.initState();
    _fetchQuestions();
  }

  Future<void> _fetchQuestions() async {
    setState(() {
      _isLoading = true;
      _errorMessage = '';
    });
    try {
      final res = await _apiService.fetchTrainingQuestions();
      if ((res['status'] == 'success' || res['success'] == true) && res['data'] != null) {
        setState(() {
          _questions = List<Map<String, dynamic>>.from(res['data']);
          _isLoading = false;
        });
      } else {
        setState(() {
          _errorMessage = res['message'] ?? 'មិនអាចទាញយកសំណួរបានទេ';
          _isLoading = false;
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = 'កំហុសបច្ចេកទេស: $e';
        _isLoading = false;
      });
    }
  }

  void _checkAnswer(int index) {
    if (_isAnswered || _questions.isEmpty) return;
    setState(() {
      _selectedAnswerIndex = index;
      _isAnswered = true;
      if (index == _questions[_currentQuestionIndex]['correct_index']) {
        _score++;
      }
    });

    Future.delayed(const Duration(seconds: 3), () {
      if (!mounted) return;
      if (_currentQuestionIndex < _questions.length - 1) {
        setState(() {
          _currentQuestionIndex++;
          _isAnswered = false;
          _selectedAnswerIndex = -1;
        });
      } else {
        _showResult();
      }
    });
  }

  Future<void> _showResult() async {
    final prefs = await SharedPreferences.getInstance();
    final employeeId = prefs.getString('employee_id') ?? '';
    
    // Auto-award badge if perfect score
    if (_score == _questions.length && employeeId.isNotEmpty) {
      try {
        final docRef = FirebaseFirestore.instance.collection('users').doc(employeeId);
        await docRef.set({
          'badges': FieldValue.arrayUnion(['QUIZ_MASTER'])
        }, SetOptions(merge: true));
      } catch (e) {
        debugPrint('Error awarding badge: $e');
      }
    }

    if (!mounted) return;
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => Container(
        padding: const EdgeInsets.all(24),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: const BorderRadius.vertical(top: Radius.circular(30)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 80, height: 80,
              decoration: BoxDecoration(color: _score == _questions.length ? Colors.orangeAccent.withValues(alpha: 0.2) : Colors.blueAccent.withValues(alpha: 0.2), shape: BoxShape.circle),
              child: Icon(
                _score == _questions.length ? Icons.emoji_events_rounded : Icons.thumb_up_rounded,
                color: _score == _questions.length ? Colors.orangeAccent : Colors.blueAccent,
                size: 40,
              ),
            ),
            const SizedBox(height: 20),
            Text(
              "លទ្ធផលរបស់អ្នក",
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 24, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 10),
            Text(
              "$_score / ${_questions.length}",
              style: GoogleFonts.inter(color: Colors.white, fontSize: 40, fontWeight: FontWeight.w900),
            ),
            const SizedBox(height: 20),
            Text(
              _score == _questions.length
                  ? "សូមអបអរសាទរ! អ្នកទទួលបានមេដាយ 🧠 Quiz Master ប្រចាំសប្ដាហ៍នេះ!"
                  : "ព្យាយាមម្ដងទៀតនៅសប្ដាហ៍ក្រោយដើម្បីប្រមូលមេដាយកិត្តិយស!",
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(color: AppTheme.textSecondary, fontSize: 14),
            ),
            const SizedBox(height: 30),
            SizedBox(
              width: double.infinity,
              height: 54,
              child: ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.primary,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                ),
                onPressed: () {
                  Navigator.pop(context);
                  Navigator.pop(context);
                },
                child: Text("ត្រឡប់ទៅវិញ", style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
              ),
            ),
            const SizedBox(height: 20),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return Scaffold(
        backgroundColor: AppTheme.bgDark,
        body: const Center(child: CircularProgressIndicator()),
      );
    }

    if (_errorMessage.isNotEmpty) {
      return Scaffold(
        backgroundColor: AppTheme.bgDark,
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text(_errorMessage, style: GoogleFonts.kantumruyPro(color: Colors.white)),
              const SizedBox(height: 20),
              ElevatedButton(onPressed: _fetchQuestions, child: const Text("ព្យាយាមម្ដងទៀត")),
            ],
          ),
        ),
      );
    }

    if (_questions.isEmpty) {
      return Scaffold(
        backgroundColor: AppTheme.bgDark,
        appBar: AppBar(title: const Text("Quiz")),
        body: Center(child: Text("មិនទាន់មានសំណួរនៅឡើយទេ", style: GoogleFonts.kantumruyPro(color: Colors.white))),
      );
    }

    final q = _questions[_currentQuestionIndex];
    
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        title: Text("វគ្គបណ្ដុះបណ្ដាល (Quiz)", style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
        backgroundColor: Colors.transparent,
        elevation: 0,
        centerTitle: true,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Progress Bar
              Row(
                children: [
                  Text("សំណួរទី ${_currentQuestionIndex + 1}/${_questions.length}", style: GoogleFonts.kantumruyPro(color: AppTheme.primaryLight, fontWeight: FontWeight.bold)),
                  const Spacer(),
                  Text("ពិន្ទុ: $_score", style: GoogleFonts.kantumruyPro(color: Colors.orangeAccent, fontWeight: FontWeight.bold)),
                ],
              ),
              const SizedBox(height: 10),
              LinearProgressIndicator(
                value: (_currentQuestionIndex + 1) / _questions.length,
                backgroundColor: Colors.white.withValues(alpha: 0.1),
                color: AppTheme.primary,
                minHeight: 8,
                borderRadius: BorderRadius.circular(4),
              ),
              const SizedBox(height: 30),
              
              // Question Card
              FadeInDown(
                key: ValueKey(_currentQuestionIndex),
                child: Container(
                  padding: const EdgeInsets.all(24),
                  decoration: BoxDecoration(
                    color: AppTheme.bgCard,
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(color: Colors.white.withValues(alpha: 0.05)),
                    boxShadow: [
                      BoxShadow(color: AppTheme.primary.withValues(alpha: 0.05), blurRadius: 20, spreadRadius: 5),
                    ],
                  ),
                  child: Text(
                    q['question'] ?? 'No Question',
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 18, height: 1.5, fontWeight: FontWeight.w600),
                    textAlign: TextAlign.center,
                  ),
                ),
              ),
              const SizedBox(height: 30),
              
              // Options
              Expanded(
                child: ListView.builder(
                  physics: const BouncingScrollPhysics(),
                  itemCount: (q['options'] as List).length,
                  itemBuilder: (context, index) {
                    final isCorrect = index == q['correct_index'];
                    final isSelected = index == _selectedAnswerIndex;
                    
                    Color bgColor = AppTheme.bgCard;
                    Color borderColor = Colors.white.withValues(alpha: 0.1);
                    
                    if (_isAnswered) {
                      if (isCorrect) {
                        bgColor = Colors.green.shade800.withValues(alpha: 0.3);
                        borderColor = Colors.greenAccent;
                      } else if (isSelected) {
                        bgColor = Colors.red.shade800.withValues(alpha: 0.3);
                        borderColor = Colors.redAccent;
                      }
                    }

                    return FadeInUp(
                      delay: Duration(milliseconds: index * 100),
                      child: GestureDetector(
                        onTap: () => _checkAnswer(index),
                        child: AnimatedContainer(
                          duration: const Duration(milliseconds: 300),
                          margin: const EdgeInsets.only(bottom: 12),
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            color: bgColor,
                            borderRadius: BorderRadius.circular(16),
                            border: Border.all(color: borderColor, width: 1.5),
                          ),
                          child: Row(
                            children: [
                              Container(
                                width: 30, height: 30,
                                decoration: BoxDecoration(
                                  color: _isAnswered && isCorrect ? Colors.greenAccent.withValues(alpha: 0.2) : Colors.white.withValues(alpha: 0.05),
                                  shape: BoxShape.circle,
                                ),
                                child: Center(
                                  child: Text(
                                    String.fromCharCode(65 + index),
                                    style: GoogleFonts.inter(color: _isAnswered && isCorrect ? Colors.greenAccent : Colors.white, fontWeight: FontWeight.bold),
                                  ),
                                ),
                              ),
                              const SizedBox(width: 16),
                              Expanded(
                                child: Text(
                                  q['options'][index] ?? '',
                                  style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14),
                                ),
                              ),
                              if (_isAnswered && isCorrect)
                                const Icon(Icons.check_circle_rounded, color: Colors.greenAccent, size: 20)
                              else if (_isAnswered && isSelected && !isCorrect)
                                const Icon(Icons.cancel_rounded, color: Colors.redAccent, size: 20)
                            ],
                          ),
                        ),
                      ),
                    );
                  },
                ),
              ),

              // Explanation Box
              if (_isAnswered)
                FadeInUp(
                  child: Container(
                    margin: const EdgeInsets.only(bottom: 20),
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: Colors.blueAccent.withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: Colors.blueAccent.withValues(alpha: 0.3)),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.lightbulb_outline_rounded, color: Colors.blueAccent, size: 18),
                            const SizedBox(width: 8),
                            Text("ពន្យល់បកស្រាយ:", style: GoogleFonts.kantumruyPro(color: Colors.blueAccent, fontWeight: FontWeight.bold, fontSize: 13)),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(
                          q['explanation'] ?? '',
                          style: GoogleFonts.kantumruyPro(color: Colors.white.withValues(alpha: 0.8), fontSize: 13, height: 1.4),
                        ),
                      ],
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
