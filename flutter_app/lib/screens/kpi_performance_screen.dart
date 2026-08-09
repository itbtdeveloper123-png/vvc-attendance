import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../providers/user_provider.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import '../widgets/vvc_global_alert.dart';

class KpiPerformanceScreen extends StatefulWidget {
  const KpiPerformanceScreen({super.key});

  @override
  State<KpiPerformanceScreen> createState() => _KpiPerformanceScreenState();
}

class _KpiPerformanceScreenState extends State<KpiPerformanceScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  bool _isLoading = false;

  // Sample KPI goals data if Firestore is empty
  List<Map<String, dynamic>> _goals = [];
  double _selfRating = 4.0;
  double _managerRating = 4.5;
  String _selfFeedback = '';

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadKpiData();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadKpiData() async {
    setState(() => _isLoading = true);
    try {
      final userProvider = context.read<UserProvider>();
      final userId = userProvider.employeeId ?? '';

      if (userId.isNotEmpty) {
        final doc = await _firestore.collection('kpi_reviews').doc(userId).get();
        if (doc.exists) {
          final data = doc.data()!;
          _selfRating = double.tryParse(data['selfRating']?.toString() ?? '4.0') ?? 4.0;
          _managerRating = double.tryParse(data['managerRating']?.toString() ?? '4.5') ?? 4.5;
          _selfFeedback = data['selfFeedback'] ?? '';
          if (data['goals'] != null) {
            _goals = List<Map<String, dynamic>>.from(data['goals']);
          }
        }
      }
    } catch (_) {}

    if (_goals.isEmpty) {
      _goals = [
        {
          'id': '1',
          'title': 'បំពេញការងារទាន់ពេលវេលា (On-Time Attendance)',
          'category': 'Attendance',
          'target': 98.0,
          'current': 95.5,
          'unit': '%',
          'weight': 30,
        },
        {
          'id': '2',
          'title': 'ការបញ្ចប់ Task & សំណើគម្រោង (Project Task Completion)',
          'category': 'Performance',
          'target': 100.0,
          'current': 90.0,
          'unit': '%',
          'weight': 40,
        },
        {
          'id': '3',
          'title': 'ការអភិវឌ្ឍជំនាញ & វគ្គបណ្តុះបណ្តាល (Skill & Training)',
          'category': 'Learning',
          'target': 4.0,
          'current': 3.0,
          'unit': 'Courses',
          'weight': 30,
        },
      ];
    }

    setState(() => _isLoading = false);
  }

  Future<void> _saveEvaluation() async {
    try {
      final userProvider = context.read<UserProvider>();
      final userId = userProvider.employeeId ?? '';

      if (userId.isNotEmpty) {
        await _firestore.collection('kpi_reviews').doc(userId).set({
          'userId': userId,
          'employeeName': userProvider.name ?? '',
          'selfRating': _selfRating,
          'managerRating': _managerRating,
          'selfFeedback': _selfFeedback,
          'goals': _goals,
          'updatedAt': FieldValue.serverTimestamp(),
        }, SetOptions(merge: true));
      }

      if (mounted) {
        VvcAlert.showSuccess(
          context,
          title: 'រក្សាទុកជោគជ័យ!',
          message: 'បានរក្សាទុកការវាយតម្លៃ និងគោលដៅ KPI រួចរាល់',
        );
      }
    } catch (e) {
      if (mounted) {
        VvcAlert.showError(
          context,
          title: 'បរាជ័យ',
          message: 'មិនអាចរក្សាទុកបានទេ: $e',
        );
      }
    }
  }

  double get _calculateOverallScore {
    if (_goals.isEmpty) return 0.0;
    double weightedSum = 0;
    double totalWeight = 0;

    for (var g in _goals) {
      final target = double.tryParse(g['target'].toString()) ?? 1.0;
      final current = double.tryParse(g['current'].toString()) ?? 0.0;
      final weight = double.tryParse(g['weight'].toString()) ?? 1.0;
      final progress = (current / target).clamp(0.0, 1.2);
      weightedSum += (progress * weight);
      totalWeight += weight;
    }

    return totalWeight > 0 ? (weightedSum / totalWeight) * 100 : 0.0;
  }

  @override
  Widget build(BuildContext context) {
    final overallScore = _calculateOverallScore;

    return DynamicAppBarWrapper(
      title: "ការវាយតម្លៃប្រតិបត្តិការងារ (KPI/OKR)",
      leading: IconButton(
        icon: const Icon(Icons.arrow_back_ios_new_rounded),
        onPressed: () => Navigator.pop(context),
      ),
      actions: [
        IconButton(
          tooltip: 'រក្សាទុក',
          icon: const Icon(Icons.save_rounded, color: Colors.white),
          onPressed: _saveEvaluation,
        ),
      ],
      body: AppBackgroundShell(
        child: Column(
          children: [
            SizedBox(height: MediaQuery.of(context).padding.top + kToolbarHeight + 6),
            _buildScorecardHeader(overallScore),
            const SizedBox(height: 10),
            TabBar(
              controller: _tabController,
              indicatorColor: AppTheme.primary,
              labelColor: Colors.white,
              unselectedLabelColor: AppTheme.textSecondary,
              labelStyle: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, fontSize: 13.5),
              tabs: const [
                Tab(text: "គោលដៅ KPI & OKR"),
                Tab(text: "ការវាយតម្លៃ (Evaluation)"),
              ],
            ),
            Expanded(
              child: TabBarView(
                controller: _tabController,
                children: [
                  _buildGoalsTab(),
                  _buildEvaluationTab(),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildScorecardHeader(double score) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16),
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: AppTheme.primary.withValues(alpha: 0.15)),
        boxShadow: AppTheme.cardShadow,
      ),
      child: Row(
        children: [
          Container(
            width: 72,
            height: 72,
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [AppTheme.primary, AppTheme.primaryDark],
              ),
              shape: BoxShape.circle,
            ),
            child: Center(
              child: Text(
                '${score.toStringAsFixed(0)}%',
                style: GoogleFonts.poppins(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 20,
                ),
              ),
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'ពិន្ទុប្រតិបត្តិការងារសរុប (Overall Score)',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textSecondary,
                    fontSize: 12.5,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  score >= 90
                      ? '⭐ ប្រសើរណាស់ (Excellent Performance)'
                      : score >= 75
                          ? '👍 ល្អ (Good Performance)'
                          : '⚠️ ត្រូវកែលម្អបន្ថែម (Needs Improvement)',
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 14,
                  ),
                ),
                const SizedBox(height: 6),
                ClipRRect(
                  borderRadius: BorderRadius.circular(6),
                  child: LinearProgressIndicator(
                    value: (score / 100).clamp(0.0, 1.0),
                    minHeight: 8,
                    backgroundColor: Colors.white.withValues(alpha: 0.1),
                    color: score >= 90 ? Colors.greenAccent : AppTheme.primary,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildGoalsTab() {
    if (_isLoading) return const Center(child: CircularProgressIndicator());

    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
      children: [
        // Manager Action Bar
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              'បញ្ជីគោលដៅ (${_goals.length})',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontSize: 15,
                fontWeight: FontWeight.bold,
              ),
            ),
            ElevatedButton.icon(
              onPressed: () => _showAddEditGoalDialog(),
              icon: const Icon(Icons.add_rounded, size: 18),
              label: Text(
                'បង្កើតគោលដៅ KPI',
                style: GoogleFonts.kantumruyPro(
                  fontWeight: FontWeight.bold,
                  fontSize: 12.5,
                ),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.primary,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
              ),
            ),
          ],
        ),
        const SizedBox(height: 14),

        for (int i = 0; i < _goals.length; i++) ...[
          _buildSingleGoalCard(_goals[i], i),
        ],
      ],
    );
  }

  Widget _buildSingleGoalCard(Map<String, dynamic> g, int index) {
    final target = double.tryParse(g['target'].toString()) ?? 1.0;
    final current = double.tryParse(g['current'].toString()) ?? 0.0;
    final progress = (current / target).clamp(0.0, 1.0);
    final category = (g['category'] ?? 'Performance').toString();

    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: const Color(0xFF111E33),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.18),
            blurRadius: 12,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: AppTheme.primary.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: AppTheme.primary.withValues(alpha: 0.25)),
                ),
                child: Text(
                  '$category (${g['weight']}%)',
                  style: GoogleFonts.inter(
                    color: AppTheme.primaryLight,
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              Row(
                children: [
                  Text(
                    '${(progress * 100).toStringAsFixed(0)}%',
                    style: GoogleFonts.poppins(
                      color: Colors.amberAccent,
                      fontWeight: FontWeight.bold,
                      fontSize: 16,
                    ),
                  ),
                  const SizedBox(width: 8),
                  InkWell(
                    onTap: () => _showAddEditGoalDialog(goal: g, index: index),
                    borderRadius: BorderRadius.circular(8),
                    child: Padding(
                      padding: const EdgeInsets.all(4),
                      child: Icon(Icons.edit_outlined, color: Colors.white.withValues(alpha: 0.7), size: 18),
                    ),
                  ),
                  const SizedBox(width: 4),
                  InkWell(
                    onTap: () {
                      VvcAlert.showConfirmDialog(
                        context,
                        title: 'លុបគោលដៅនេះ?',
                        message: 'តើអ្នកពិតជាចង់លុបគោលដៅ "${g['title']}" នេះមែនទេ?',
                        isDestructive: true,
                      ).then((confirm) {
                        if (confirm == true) {
                          setState(() => _goals.removeAt(index));
                          _saveEvaluation();
                        }
                      });
                    },
                    borderRadius: BorderRadius.circular(8),
                    child: Padding(
                      padding: const EdgeInsets.all(4),
                      child: Icon(Icons.delete_outline_rounded, color: Colors.redAccent.withValues(alpha: 0.7), size: 18),
                    ),
                  ),
                ],
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            g['title'] ?? '',
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 15,
            ),
          ),
          const SizedBox(height: 12),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'សម្រេចបាន: $current / $target ${g['unit']}',
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textSecondary,
                  fontSize: 13,
                ),
              ),
              Row(
                children: [
                  InkWell(
                    onTap: () {
                      if (current > 0) {
                        setState(() => g['current'] = current - 1);
                        _saveEvaluation();
                      }
                    },
                    child: Container(
                      padding: const EdgeInsets.all(4),
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.08),
                        shape: BoxShape.circle,
                      ),
                      child: const Icon(Icons.remove_rounded, color: Colors.white, size: 16),
                    ),
                  ),
                  const SizedBox(width: 8),
                  InkWell(
                    onTap: () {
                      setState(() => g['current'] = current + 1);
                      _saveEvaluation();
                    },
                    child: Container(
                      padding: const EdgeInsets.all(4),
                      decoration: BoxDecoration(
                        color: AppTheme.primary.withValues(alpha: 0.3),
                        shape: BoxShape.circle,
                      ),
                      child: const Icon(Icons.add_rounded, color: Colors.white, size: 16),
                    ),
                  ),
                ],
              ),
            ],
          ),
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(6),
            child: LinearProgressIndicator(
              value: progress,
              minHeight: 8,
              backgroundColor: Colors.white10,
              color: progress >= 0.9 ? Colors.greenAccent : AppTheme.primary,
            ),
          ),
        ],
      ),
    );
  }

  void _showAddEditGoalDialog({Map<String, dynamic>? goal, int? index}) {
    final isEditing = goal != null;
    final titleCtrl = TextEditingController(text: goal?['title'] ?? '');
    final targetCtrl = TextEditingController(text: goal?['target']?.toString() ?? '100');
    final currentCtrl = TextEditingController(text: goal?['current']?.toString() ?? '0');
    final weightCtrl = TextEditingController(text: goal?['weight']?.toString() ?? '25');
    final unitCtrl = TextEditingController(text: goal?['unit'] ?? '%');
    String category = goal?['category'] ?? 'Attendance';

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => Dialog(
          backgroundColor: Colors.transparent,
          child: Container(
            padding: const EdgeInsets.all(22),
            decoration: BoxDecoration(
              color: const Color(0xFF131D2E).withValues(alpha: 0.95),
              borderRadius: BorderRadius.circular(24),
              border: Border.all(color: Colors.white.withValues(alpha: 0.12)),
            ),
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(
                        isEditing ? Icons.edit_note_rounded : Icons.add_chart_rounded,
                        color: AppTheme.primaryLight,
                      ),
                      const SizedBox(width: 8),
                      Text(
                        isEditing ? 'កែប្រែគោលដៅ KPI' : 'បង្កើតគោលដៅ KPI ថ្មី',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 16.5,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  Text('ឈ្មោះគោលដៅ (KPI Title)', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5)),
                  const SizedBox(height: 6),
                  TextField(
                    controller: titleCtrl,
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                    decoration: InputDecoration(
                      hintText: 'ឧ. វត្តមានទាន់ពេលវេលា ឬ ការបញ្ចប់ Task',
                      hintStyle: GoogleFonts.kantumruyPro(color: Colors.white30, fontSize: 12.5),
                      filled: true,
                      fillColor: Colors.white.withValues(alpha: 0.05),
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                  ),
                  const SizedBox(height: 14),
                  Text('ប្រភេទ (Category)', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5)),
                  const SizedBox(height: 6),
                  DropdownButtonFormField<String>(
                    initialValue: category,
                    dropdownColor: const Color(0xFF1E293B),
                    style: GoogleFonts.inter(color: Colors.white, fontSize: 13.5),
                    items: const [
                      DropdownMenuItem(value: 'Attendance', child: Text('Attendance (វត្តមាន)')),
                      DropdownMenuItem(value: 'Performance', child: Text('Performance (លទ្ធផលការងារ)')),
                      DropdownMenuItem(value: 'Learning', child: Text('Learning (ជំនាញ & បណ្តុះបណ្តាល)')),
                      DropdownMenuItem(value: 'Sales', child: Text('Sales / Target (លក់/ចំណូល)')),
                      DropdownMenuItem(value: 'Quality', child: Text('Quality / Service (គុណភាព)')),
                    ],
                    onChanged: (val) => setDialogState(() => category = val!),
                    decoration: InputDecoration(
                      filled: true,
                      fillColor: Colors.white.withValues(alpha: 0.05),
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                  ),
                  const SizedBox(height: 14),
                  Row(
                    children: [
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text('គោលដៅ (Target)', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
                            const SizedBox(height: 4),
                            TextField(
                              controller: targetCtrl,
                              keyboardType: TextInputType.number,
                              style: GoogleFonts.inter(color: Colors.white, fontSize: 13.5),
                              decoration: InputDecoration(
                                filled: true,
                                fillColor: Colors.white.withValues(alpha: 0.05),
                                border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text('សម្រេចបាន (Current)', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
                            const SizedBox(height: 4),
                            TextField(
                              controller: currentCtrl,
                              keyboardType: TextInputType.number,
                              style: GoogleFonts.inter(color: Colors.white, fontSize: 13.5),
                              decoration: InputDecoration(
                                filled: true,
                                fillColor: Colors.white.withValues(alpha: 0.05),
                                border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 14),
                  Row(
                    children: [
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text('ទម្ងន់ % (Weight)', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
                            const SizedBox(height: 4),
                            TextField(
                              controller: weightCtrl,
                              keyboardType: TextInputType.number,
                              style: GoogleFonts.inter(color: Colors.white, fontSize: 13.5),
                              decoration: InputDecoration(
                                filled: true,
                                fillColor: Colors.white.withValues(alpha: 0.05),
                                border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text('ខ្នាត (Unit)', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
                            const SizedBox(height: 4),
                            TextField(
                              controller: unitCtrl,
                              style: GoogleFonts.inter(color: Colors.white, fontSize: 13.5),
                              decoration: InputDecoration(
                                hintText: '%, Tasks, \$',
                                hintStyle: GoogleFonts.inter(color: Colors.white30, fontSize: 12),
                                filled: true,
                                fillColor: Colors.white.withValues(alpha: 0.05),
                                border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 20),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      TextButton(
                        onPressed: () => Navigator.pop(ctx),
                        child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: Colors.white60)),
                      ),
                      const SizedBox(width: 8),
                      ElevatedButton(
                        onPressed: () {
                          final title = titleCtrl.text.trim();
                          if (title.isEmpty) return;

                          final newGoal = {
                            'id': goal?['id'] ?? DateTime.now().millisecondsSinceEpoch.toString(),
                            'title': title,
                            'category': category,
                            'target': double.tryParse(targetCtrl.text) ?? 100.0,
                            'current': double.tryParse(currentCtrl.text) ?? 0.0,
                            'weight': double.tryParse(weightCtrl.text) ?? 20.0,
                            'unit': unitCtrl.text.trim().isEmpty ? '%' : unitCtrl.text.trim(),
                          };

                          setState(() {
                            if (isEditing && index != null) {
                              _goals[index] = newGoal;
                            } else {
                              _goals.add(newGoal);
                            }
                          });
                          Navigator.pop(ctx);
                          _saveEvaluation();
                        },
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppTheme.primary,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                        ),
                        child: Text('រក្សាទុក', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildEvaluationTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Self Rating Card
          _buildRatingCard(
            title: "១. ការស្វ័យវាយតម្លៃ (Self Evaluation)",
            subtitle: "សូមវាយតម្លៃប្រតិបត្តិការងាររបស់អ្នកក្នុងត្រីមាសនេះ (១ ដល់ ៥ ផ្កាយ)",
            rating: _selfRating,
            onChanged: (val) => setState(() => _selfRating = val),
          ),
          const SizedBox(height: 16),

          // Manager Rating Card
          _buildRatingCard(
            title: "២. ការវាយតម្លៃពីប្រធានផ្នែក (Manager Rating)",
            subtitle: "ពិន្ទុវាយតម្លៃផ្លូវការពីប្រធានផ្នែកផ្ទាល់ (Line Manager)",
            rating: _managerRating,
            isEditable: false,
          ),
          const SizedBox(height: 16),

          // Qualitative Feedback Input
          Container(
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(20),
              border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  "មតិយោបល់បន្ថែម & គោលដៅត្រីមាសបន្ទាប់",
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 14,
                  ),
                ),
                const SizedBox(height: 10),
                TextField(
                  maxLines: 4,
                  onChanged: (val) => _selfFeedback = val,
                  controller: TextEditingController(text: _selfFeedback),
                  style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                  decoration: InputDecoration(
                    hintText: "សរសេរមតិយោបល់ ឬសមិទ្ធផលដែលសម្រេចបាន...",
                    hintStyle: GoogleFonts.kantumruyPro(color: AppTheme.textMuted, fontSize: 13),
                    filled: true,
                    fillColor: Colors.white.withValues(alpha: 0.04),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(14),
                      borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.1)),
                    ),
                    enabledBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(14),
                      borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.1)),
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: _saveEvaluation,
              icon: const Icon(Icons.check_circle_rounded),
              label: Text(
                'រក្សាទុកការវាយតម្លៃ',
                style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, fontSize: 15),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.primary,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 16),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRatingCard({
    required String title,
    required String subtitle,
    required double rating,
    ValueChanged<double>? onChanged,
    bool isEditable = true,
  }) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: GoogleFonts.kantumruyPro(
              color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 14.5,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            subtitle,
            style: GoogleFonts.kantumruyPro(
              color: AppTheme.textSecondary,
              fontSize: 12,
            ),
          ),
          const SizedBox(height: 14),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: List.generate(5, (index) {
                  final starVal = index + 1;
                  return IconButton(
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
                    icon: Icon(
                      starVal <= rating ? Icons.star_rounded : Icons.star_border_rounded,
                      color: starVal <= rating ? Colors.amber : Colors.white24,
                      size: 30,
                    ),
                    onPressed: isEditable && onChanged != null
                        ? () => onChanged(starVal.toDouble())
                        : null,
                  );
                }),
              ),
              Text(
                '${rating.toStringAsFixed(1)} / 5.0',
                style: GoogleFonts.poppins(
                  color: Colors.amber,
                  fontWeight: FontWeight.bold,
                  fontSize: 16,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
