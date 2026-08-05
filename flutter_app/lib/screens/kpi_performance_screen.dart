import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../providers/user_provider.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

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
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('បានរក្សាទុកការវាយតម្លៃ KPI រួចរាល់!', style: GoogleFonts.kantumruyPro()),
            backgroundColor: Colors.green,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('មិនអាចរក្សាទុកបានទេ: $e', style: GoogleFonts.kantumruyPro()),
            backgroundColor: Colors.redAccent,
          ),
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
            const SizedBox(height: 10),
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
    return _isLoading
        ? const Center(child: CircularProgressIndicator())
        : ListView.builder(
            padding: const EdgeInsets.all(16),
            itemCount: _goals.length,
            itemBuilder: (context, index) {
              final g = _goals[index];
              final target = double.tryParse(g['target'].toString()) ?? 1.0;
              final current = double.tryParse(g['current'].toString()) ?? 0.0;
              final progress = (current / target).clamp(0.0, 1.0);

              return Container(
                margin: const EdgeInsets.only(bottom: 14),
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(
                  color: AppTheme.bgCard,
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
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
                          ),
                          child: Text(
                            '${g['category']} (${g['weight']}%)',
                            style: GoogleFonts.inter(
                              color: AppTheme.primaryLight,
                              fontSize: 11,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                        Text(
                          '${(progress * 100).toStringAsFixed(0)}%',
                          style: GoogleFonts.poppins(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: 15,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 10),
                    Text(
                      g['title'] ?? '',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 14.5,
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
                            fontSize: 12.5,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(6),
                      child: LinearProgressIndicator(
                        value: progress,
                        minHeight: 8,
                        backgroundColor: Colors.white10,
                        color: AppTheme.primary,
                      ),
                    ),
                  ],
                ),
              );
            },
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
