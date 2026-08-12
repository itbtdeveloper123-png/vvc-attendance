import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/vvc_global_alert.dart';
import 'hrm_poll_management_screen.dart';

class PollVotingScreen extends StatefulWidget {
  const PollVotingScreen({super.key});

  @override
  State<PollVotingScreen> createState() => _PollVotingScreenState();
}

class _PollVotingScreenState extends State<PollVotingScreen> {
  final ApiService _api = ApiService();

  List<dynamic> _polls = [];
  List<dynamic> _allUsers = [];
  bool _isLoading = true;
  String? _errorMessage;
  String _selectedCategoryFilter = 'all'; // 'all', 'skilled', or 'worker'

  @override
  void initState() {
    super.initState();
    _loadInitialData();
  }

  Future<void> _loadInitialData() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final results = await Future.wait([
        _api.fetchActivePolls(),
        _api.fetchUsers(),
      ]);

      final apiRes = results[0];
      final usersRes = results[1];

      if (usersRes['success'] == true && usersRes['data'] != null) {
        _allUsers = List<dynamic>.from(usersRes['data']);
      }

      if (apiRes['success'] == true && apiRes['data'] != null && (apiRes['data'] as List).isNotEmpty) {
        _polls = List<dynamic>.from(apiRes['data']);
      } else {
        final fallbackRes = await _api.getPolls();
        if (fallbackRes['success'] == true && fallbackRes['data'] != null) {
          _polls = List<dynamic>.from(fallbackRes['data']);
        } else if (apiRes['data'] != null) {
          _polls = List<dynamic>.from(apiRes['data']);
        } else {
          _polls = [];
        }
      }

      // Format candidate details with user database records (preserve server Khmer names)
      final khmerRegex = RegExp(r'[\u1780-\u17FF]');
      for (var poll in _polls) {
        if (poll['candidates'] != null && poll['candidates'] is List) {
          for (var c in poll['candidates']) {
            final empId = c['employee_id']?.toString() ?? '';
            final existingName = (c['name'] ?? '').toString().trim();

            // If name from server already has Khmer characters, preserve it!
            if (existingName.isNotEmpty && khmerRegex.hasMatch(existingName)) {
              continue;
            }

            if (_allUsers.isNotEmpty && empId.isNotEmpty) {
              final matches = _allUsers.where(
                (u) =>
                    u['employee_id']?.toString() == empId ||
                    (empId.replaceAll(RegExp(r'^0+'), '').isNotEmpty &&
                        u['employee_id']?.toString().replaceAll(RegExp(r'^0+'), '') ==
                            empId.replaceAll(RegExp(r'^0+'), '')),
              ).toList();

              if (matches.isNotEmpty) {
                final khmerMatch = matches.firstWhere(
                  (u) => khmerRegex.hasMatch((u['name'] ?? u['full_name'] ?? u['khmer_name'] ?? '').toString()),
                  orElse: () => matches.first,
                );
                final mName = (khmerMatch['khmer_name'] ?? khmerMatch['full_name'] ?? khmerMatch['name'] ?? '').toString().trim();
                if (mName.isNotEmpty) {
                  c['name'] = mName;
                }
                c['department'] = khmerMatch['department'] ?? khmerMatch['position'] ?? c['department'];
                c['photo_url'] = khmerMatch['photo_url'] ?? khmerMatch['photo'] ?? khmerMatch['avatar'] ?? c['photo_url'];
              }
            }
          }
        }
      }

      setState(() {
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _isLoading = false;
        _errorMessage = e.toString();
      });
    }
  }

  Future<void> _castVote(String pollDocId, String candidateEmployeeId, {int? candidateId}) async {
    final confirmed = await VvcAlert.showConfirmDialog(
      context,
      title: 'បោះឆ្នោតបុគ្គលិកឆ្នើម',
      message: 'តើអ្នកប្រាកដជាចង់បោះឆ្នោតជូនបេក្ខជននេះមែនទេ?',
    );

    if (confirmed != true) return;

    try {
      final cleanId = pollDocId.replaceAll(RegExp(r'\D'), '');
      final pollIdInt = int.tryParse(cleanId) ?? int.tryParse(pollDocId) ?? 0;
      if (pollIdInt > 0) {
        final res = await _api.castVote(pollIdInt, candidateEmployeeId, candidateId: candidateId);
        if (res['success'] == true) {
          if (mounted) {
            setState(() {
              for (var p in _polls) {
                if ((p['doc_id'] ?? p['id'] ?? '').toString() == pollDocId || (p['id'] ?? '').toString() == pollIdInt.toString()) {
                  p['has_voted'] = true;
                  p['voted_candidate_employee_id'] = candidateEmployeeId;
                  p['voted_candidate_id'] = candidateEmployeeId;
                }
              }
            });
            VvcAlert.showSuccess(context, title: 'បោះឆ្នោតជោគជ័យ!', message: 'ការបោះឆ្នោតរបស់អ្នកត្រូវបានរក្សាទុកក្នុង DB');
            await _loadInitialData();
          }
        } else {
          if (mounted) {
            VvcAlert.showError(context, title: 'បរាជ័យ', message: res['message'] ?? 'មិនអាចបោះឆ្នោតបានទេ');
          }
        }
      } else {
        if (mounted) {
          VvcAlert.showError(context, title: 'បរាជ័យ', message: 'មិនអាចកំណត់ ID នៃការបោះឆ្នោតបានទេ ($pollDocId)');
        }
      }
    } catch (e) {
      if (mounted) {
        VvcAlert.showError(context, title: 'បរាជ័យ', message: 'មិនអាចបោះឆ្នោតបានទេ: $e');
      }
    }
  }

  bool _isWorkerCandidate(Map<String, dynamic> c) {
    final cat = (c['category'] ?? '').toString().toLowerCase();
    final dept = (c['department'] ?? c['position'] ?? '').toString().toLowerCase();
    return cat.contains('warehouse') ||
        cat.contains('store') ||
        cat.contains('worker') ||
        cat.contains('ឃ្លាំង') ||
        cat.contains('កម្មករ') ||
        dept.contains('កម្មករ') ||
        dept.contains('ឃ្លាំង') ||
        dept.contains('driver') ||
        dept.contains('cleaner') ||
        dept.contains('security') ||
        dept.contains('ដឹកជញ្ជូន');
  }

  @override
  Widget build(BuildContext context) {
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final bool isHrmOrAdmin = userProvider.isHRM || userProvider.isAdmin;

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: AppTheme.bgDark,
        elevation: 0,
        title: Text(
          'បោះឆ្នោតបុគ្គលិកឆ្នើម',
          style: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.bold,
            color: Colors.white,
            fontSize: 18,
          ),
        ),
        actions: [
          if (isHrmOrAdmin)
            IconButton(
              tooltip: 'ផ្ទាំងគ្រប់គ្រង HRM',
              icon: const Icon(Icons.admin_panel_settings_rounded, color: Colors.amberAccent, size: 24),
              onPressed: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const HrmPollManagementScreen()),
                );
              },
            ),
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh_rounded, color: Colors.white70),
            onPressed: _loadInitialData,
          ),
        ],
      ),
      body: _buildBody(isHrmOrAdmin),
    );
  }

  Widget _buildBody(bool isHrmOrAdmin) {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator(color: Colors.amberAccent));
    }

    if (_errorMessage != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.error_outline_rounded, color: Colors.redAccent, size: 48),
              const SizedBox(height: 12),
              Text(
                'មិនអាចទាញយកទិន្នន័យបានទេ',
                style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16),
              ),
              const SizedBox(height: 6),
              Text(
                _errorMessage!,
                textAlign: TextAlign.center,
                style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 13),
              ),
              const SizedBox(height: 18),
              ElevatedButton.icon(
                onPressed: _loadInitialData,
                icon: const Icon(Icons.refresh_rounded),
                label: Text('ព្យាយាមម្តងទៀត', style: GoogleFonts.kantumruyPro()),
                style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary),
              ),
            ],
          ),
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _loadInitialData,
      color: AppTheme.primary,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // HRM Banner if user is Admin / HRM
          if (isHrmOrAdmin) ...[
            Container(
              margin: const EdgeInsets.only(bottom: 16),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  colors: [Color(0xFF2A1F0D), Color(0xFF161B26)],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.4)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.admin_panel_settings_rounded, color: Colors.amberAccent, size: 22),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'លោកអ្នកជាអ្នកគ្រប់គ្រង HRM / Admin',
                      style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13),
                    ),
                  ),
                  ElevatedButton.icon(
                    onPressed: () {
                      Navigator.push(
                        context,
                        MaterialPageRoute(builder: (_) => const HrmPollManagementScreen()),
                      );
                    },
                    icon: const Icon(Icons.bar_chart_rounded, color: Colors.black, size: 16),
                    label: Text(
                      'គ្រប់គ្រង & លទ្ធផល',
                      style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 12),
                    ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.amberAccent,
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                    ),
                  ),
                ],
              ),
            ),
          ],

          // Welcome Employee Info Banner
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  AppTheme.primary.withValues(alpha: 0.25),
                  const Color(0xFF111E33),
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(18),
              border: Border.all(color: AppTheme.primary.withValues(alpha: 0.3)),
            ),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: AppTheme.primary.withValues(alpha: 0.2),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(Icons.how_to_vote_rounded, color: Colors.cyanAccent, size: 24),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'ចូលរួមបោះឆ្នោតជ្រើសរើសបុគ្គលិកឆ្នើម',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                          fontSize: 14.5,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        'សូមជ្រើសរើសបេក្ខជនដែលលោកអ្នកពេញចិត្តខាងក្រោម',
                        style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 18),

          // Category Filter Tabs: 📋 ទាំងអស់ | 👔 បុគ្គលិកជំនាញ | 👷‍♂️ កម្មករ
          Container(
            padding: const EdgeInsets.all(4),
            decoration: BoxDecoration(
              color: const Color(0xFF111E33),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
            ),
            child: Row(
              children: [
                Expanded(
                  child: _buildCategoryFilterButton('all', '📋 ទាំងអស់', _selectedCategoryFilter == 'all'),
                ),
                Expanded(
                  child: _buildCategoryFilterButton('skilled', '👔 បុគ្គលិកជំនាញ', _selectedCategoryFilter == 'skilled'),
                ),
                Expanded(
                  child: _buildCategoryFilterButton('worker', '👷‍♂️ កម្មករ / ឃ្លាំង', _selectedCategoryFilter == 'worker'),
                ),
              ],
            ),
          ),

          const SizedBox(height: 18),

          if (_polls.isEmpty)
            Container(
              padding: const EdgeInsets.all(32),
              decoration: BoxDecoration(
                color: const Color(0xFF111E33),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
              ),
              child: Column(
                children: [
                  const Icon(Icons.inbox_rounded, color: Colors.white38, size: 48),
                  const SizedBox(height: 12),
                  Text(
                    'បច្ចុប្បន្នមិនទាន់មានការបោះឆ្នោតដែលបើកដំណើរការទេ',
                    textAlign: TextAlign.center,
                    style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 14, fontWeight: FontWeight.bold),
                  ),
                ],
              ),
            )
          else
            ..._polls.map((poll) => _buildEmployeeVotingCard(poll)),
        ],
      ),
    );
  }

  Widget _buildCategoryFilterButton(String key, String label, bool isSelected) {
    return GestureDetector(
      onTap: () => setState(() => _selectedCategoryFilter = key),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(vertical: 10),
        decoration: BoxDecoration(
          color: isSelected ? AppTheme.primary : Colors.transparent,
          borderRadius: BorderRadius.circular(10),
        ),
        child: Center(
          child: Text(
            label,
            style: GoogleFonts.kantumruyPro(
              color: isSelected ? Colors.white : Colors.white70,
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildEmployeeVotingCard(Map<String, dynamic> poll) {
    final title = poll['title'] ?? 'បោះឆ្នោតបុគ្គលិកឆ្នើម';
    final quarter = poll['quarter'] ?? '';
    final location = poll['location'] ?? 'Head Office';
    final bool hasVoted = poll['has_voted'] == true || poll['has_voted'] == 1 || poll['has_voted'] == '1' || poll['has_voted'] == 'true';
    final docId = (poll['doc_id'] ?? poll['id'] ?? '').toString();

    final rawCandidates = (poll['candidates'] as List<dynamic>?) ?? [];
    List<Map<String, dynamic>> allCandidates = [];
    for (var c in rawCandidates) {
      if (c is Map<String, dynamic>) {
        allCandidates.add(c);
      } else if (c is Map) {
        allCandidates.add(Map<String, dynamic>.from(c.cast<String, dynamic>()));
      }
    }

    // Filter candidates by active category filter
    List<Map<String, dynamic>> candidates;
    if (_selectedCategoryFilter == 'skilled') {
      candidates = allCandidates.where((c) => !_isWorkerCandidate(c)).toList();
    } else if (_selectedCategoryFilter == 'worker') {
      candidates = allCandidates.where((c) => _isWorkerCandidate(c)).toList();
    } else {
      candidates = List.from(allCandidates);
    }

    String? selectedCandidateEmployeeId;

    return StatefulBuilder(
      builder: (context, setCardState) {
        return Container(
          margin: const EdgeInsets.only(bottom: 20),
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(
            color: const Color(0xFF111E33),
            borderRadius: BorderRadius.circular(22),
            border: Border.all(
              color: hasVoted ? const Color(0xFF10B981).withValues(alpha: 0.5) : AppTheme.primary.withValues(alpha: 0.3),
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.25),
                blurRadius: 10,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          title,
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: 16,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Row(
                          children: [
                            if (quarter.isNotEmpty) ...[
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                                decoration: BoxDecoration(
                                  color: AppTheme.primary.withValues(alpha: 0.2),
                                  borderRadius: BorderRadius.circular(8),
                                ),
                                child: Text(
                                  quarter,
                                  style: GoogleFonts.kantumruyPro(color: Colors.cyanAccent, fontSize: 11.5, fontWeight: FontWeight.bold),
                                ),
                              ),
                              const SizedBox(width: 6),
                            ],
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                              decoration: BoxDecoration(
                                color: Colors.white.withValues(alpha: 0.08),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: Text(
                                location,
                                style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 11.5),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(
                      color: hasVoted ? const Color(0xFF10B981).withValues(alpha: 0.2) : Colors.amberAccent.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: hasVoted ? const Color(0xFF10B981) : Colors.amberAccent),
                    ),
                    child: Row(
                      children: [
                        Icon(hasVoted ? Icons.check_circle_rounded : Icons.pending_rounded,
                            color: hasVoted ? const Color(0xFF10B981) : Colors.amberAccent, size: 14),
                        const SizedBox(width: 4),
                        Text(
                          hasVoted ? 'បានបោះរួចរាល់' : 'កំពុងដំណើរការ',
                          style: GoogleFonts.kantumruyPro(
                            color: hasVoted ? const Color(0xFF10B981) : Colors.amberAccent,
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),

              const SizedBox(height: 16),

              if (candidates.isEmpty) ...[
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.03),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Text(
                    'មិនមានបេក្ខជនក្នុងប្រភេទនេះទេ',
                    style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 13),
                  ),
                ),
              ] else ...[
                Row(
                  children: [
                    Text(
                      'ជ្រើសរើសបេក្ខជនដើម្បីបោះឆ្នោត:',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.amberAccent,
                        fontWeight: FontWeight.bold,
                        fontSize: 13.5,
                      ),
                    ),
                    const Spacer(),
                    Text(
                      '(${candidates.length} នាក់)',
                      style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 12),
                    ),
                  ],
                ),
                const SizedBox(height: 8),

                ...candidates.map((candidate) {
                  final empId = candidate['employee_id']?.toString() ?? '';
                  final candIdStr = candidate['id']?.toString() ?? '';
                  final khmerRegex = RegExp(r'[\u1780-\u17FF]');
                  String name = (candidate['name'] ?? '').toString().trim();
                  if (name.isEmpty) name = empId;

                  if (!khmerRegex.hasMatch(name) && _allUsers.isNotEmpty && empId.isNotEmpty) {
                    final matches = _allUsers.where(
                      (u) =>
                          u['employee_id']?.toString() == empId ||
                          (empId.replaceAll(RegExp(r'^0+'), '').isNotEmpty &&
                              u['employee_id']?.toString().replaceAll(RegExp(r'^0+'), '') ==
                                  empId.replaceAll(RegExp(r'^0+'), '')),
                    ).toList();
                    if (matches.isNotEmpty) {
                      final khmerMatch = matches.firstWhere(
                        (u) => khmerRegex.hasMatch((u['name'] ?? u['full_name'] ?? u['khmer_name'] ?? '').toString()),
                        orElse: () => matches.first,
                      );
                      final mName = (khmerMatch['khmer_name'] ?? khmerMatch['full_name'] ?? khmerMatch['name'] ?? '').toString().trim();
                      if (mName.isNotEmpty) {
                        name = mName;
                      }
                    }
                  }

                  final votedCandId = (poll['voted_candidate_id'] ?? '').toString();
                  final votedCandEmpId = (poll['voted_candidate_employee_id'] ?? '').toString();

                  final isUserVotedChoice = hasVoted &&
                      ((votedCandId.isNotEmpty &&
                              (votedCandId == empId ||
                                  votedCandId == candIdStr ||
                                  (empId.isNotEmpty &&
                                      votedCandId.replaceAll(RegExp(r'^0+'), '') ==
                                          empId.replaceAll(RegExp(r'^0+'), '')))) ||
                          (votedCandEmpId.isNotEmpty &&
                              (votedCandEmpId == empId ||
                                  (empId.isNotEmpty &&
                                      votedCandEmpId.replaceAll(RegExp(r'^0+'), '') ==
                                          empId.replaceAll(RegExp(r'^0+'), '')))));

                  final isSelected = isUserVotedChoice || (selectedCandidateEmployeeId == empId);
                  final dept = candidate['department'] ?? candidate['dept'] ?? candidate['position'] ?? 'បុគ្គលិក';
                  final cat = candidate['category'] ?? (poll['location'] ?? 'Head Office');

                  return Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    decoration: BoxDecoration(
                      color: isUserVotedChoice
                          ? const Color(0xFF10B981).withValues(alpha: 0.18)
                          : (isSelected ? AppTheme.primary.withValues(alpha: 0.15) : Colors.white.withValues(alpha: 0.04)),
                      borderRadius: BorderRadius.circular(14),
                      border: Border.all(
                        color: isUserVotedChoice
                            ? const Color(0xFF10B981)
                            : (isSelected ? AppTheme.primary : Colors.white.withValues(alpha: 0.08)),
                      ),
                    ),
                    child: CheckboxListTile(
                      value: isSelected,
                      onChanged: hasVoted
                          ? null
                          : (value) {
                              setCardState(() {
                                selectedCandidateEmployeeId = value == true ? empId : null;
                              });
                            },
                      title: Row(
                        children: [
                          Expanded(
                            child: Text(
                              name,
                              style: GoogleFonts.kantumruyPro(
                                fontWeight: FontWeight.bold,
                                color: Colors.white,
                                fontSize: 14,
                              ),
                            ),
                          ),
                          if (isUserVotedChoice)
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                              decoration: BoxDecoration(
                                color: const Color(0xFF10B981),
                                borderRadius: BorderRadius.circular(12),
                              ),
                              child: Text(
                                '✓ បានបោះឆ្នោតជូន',
                                style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 10.5, fontWeight: FontWeight.bold),
                              ),
                            ),
                        ],
                      ),
                      subtitle: Row(
                        children: [
                          Expanded(
                            child: Text('ផ្នែក: $dept', style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 12)),
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: Colors.white.withValues(alpha: 0.08),
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Text(
                              cat.toString(),
                              style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 10.5, fontWeight: FontWeight.w600),
                            ),
                          ),
                        ],
                      ),
                      controlAffinity: ListTileControlAffinity.leading,
                      activeColor: isUserVotedChoice ? const Color(0xFF10B981) : AppTheme.primary,
                    ),
                  );
                }),

                const SizedBox(height: 12),

                if (!hasVoted && selectedCandidateEmployeeId != null)
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton.icon(
                      onPressed: () => _castVote(docId, selectedCandidateEmployeeId!),
                      icon: const Icon(Icons.how_to_vote_rounded, color: Colors.white),
                      label: Text(
                        'បោះឆ្នោតឥឡូវនេះ',
                        style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 15),
                      ),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppTheme.primary,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                      ),
                    ),
                  ),

                if (hasVoted) ...[
                  const SizedBox(height: 10),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                    decoration: BoxDecoration(
                      color: const Color(0xFF10B981).withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: const Color(0xFF10B981).withValues(alpha: 0.3)),
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.check_circle_rounded, color: Color(0xFF10B981), size: 20),
                        const SizedBox(width: 8),
                        Text(
                          'អ្នកបានបោះឆ្នោតរួចរាល់ហើយ! (សូមអរគុណ)',
                          style: GoogleFonts.kantumruyPro(
                            color: const Color(0xFF10B981),
                            fontSize: 13,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ],
            ],
          ),
        );
      },
    );
  }
}
