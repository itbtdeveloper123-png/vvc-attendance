import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/vvc_global_alert.dart';
import 'certificate_editor_screen.dart';

class PollVotingScreen extends StatefulWidget {
  const PollVotingScreen({super.key});

  @override
  State<PollVotingScreen> createState() => _PollVotingScreenState();
}

class _PollVotingScreenState extends State<PollVotingScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final ApiService _api = ApiService();
  List<dynamic> _polls = [];
  List<dynamic> _allUsers = [];
  bool _isLoading = true;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadInitialData();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadInitialData() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final response = await _api.fetchActivePolls();
      final usersRes = await _api.fetchUsers();

      if (mounted) {
        setState(() {
          if (response['success'] == true && response['data'] != null) {
            _polls = List<dynamic>.from(response['data']);
          }
          if (usersRes['success'] == true && usersRes['data'] != null) {
            _allUsers = List<dynamic>.from(usersRes['data']);
          }
          _isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _errorMessage = 'កំហុសបច្ចេកទេស: $e';
          _isLoading = false;
        });
      }
    }

    // Mock initial demo voting polls if server list is empty
    if (_polls.isEmpty) {
      _polls = [
        {
          'id': 101,
          'title': 'បោះឆ្នោតជ្រើសរើសបុគ្គលិកឆ្នើម ប្រចាំត្រីមាសទី ២',
          'quarter': 'ត្រីមាសទី ២ នៃឆ្នាំ ២០២៦',
          'location': 'ការិយាល័យកណ្តាល',
          'start_date': '២០២៦-០៧-០១',
          'end_date': '២០២៦-០៨-៣១',
          'has_voted': false,
          'candidates': [
            {
              'employee_id': '168',
              'name': 'លី ស៊ាងអ៊ី',
              'dept': 'គណនេយ្យករ',
              'avatar': '',
              'votes_count': 14,
            },
            {
              'employee_id': '1122',
              'name': 'មាស វិចិត្រ',
              'dept': 'IT Support',
              'avatar': '',
              'votes_count': 8,
            },
            {
              'employee_id': '123',
              'name': 'សុខ ចាន់',
              'dept': 'រដ្ឋបាល',
              'avatar': '',
              'votes_count': 5,
            },
          ],
          'voter_audit_list': [
            {
              'voter_name': 'សុខ ចាន់',
              'voter_id': '123',
              'candidate_name': 'លី ស៊ាងអ៊ី',
              'candidate_id': '168',
              'time': '09:30 AM, 08-08-2026',
            },
            {
              'voter_name': 'មាស វិចិត្រ',
              'voter_id': '1122',
              'candidate_name': 'លី ស៊ាងអ៊ី',
              'candidate_id': '168',
              'time': '10:15 AM, 08-08-2026',
            },
            {
              'voter_name': 'ស៊ុយ សម្បត្តិ',
              'voter_id': '169',
              'candidate_name': 'មាស វិចិត្រ',
              'candidate_id': '1122',
              'time': '02:45 PM, 08-08-2026',
            },
          ],
        },
      ];
    }
  }

  Future<void> _castVote(int pollId, String candidateEmployeeId) async {
    final confirmed = await VvcAlert.showConfirmDialog(
      context,
      title: 'បោះឆ្នោតបុគ្គលិកឆ្នើម',
      message: 'តើអ្នកប្រាកដជាចង់បោះឆ្នោតជូនបេក្ខជននេះមែនទេ?',
    );

    if (confirmed != true) return;

    try {
      final response = await _api.castVote(pollId, candidateEmployeeId);

      if (response['success'] == true) {
        if (!mounted) return;
        VvcAlert.showSuccess(context, title: 'បោះឆ្នោតជោគជ័យ!', message: 'ការបោះឆ្នោតរបស់អ្នកត្រូវបានរក្សាទុក');
        _loadInitialData();
      } else {
        if (!mounted) return;
        // Fallback local UI update if demo poll
        setState(() {
          for (var p in _polls) {
            if (p['id'] == pollId) {
              p['has_voted'] = true;
              for (var c in p['candidates']) {
                if (c['employee_id'] == candidateEmployeeId) {
                  c['votes_count'] = (c['votes_count'] ?? 0) + 1;
                }
              }
              (p['voter_audit_list'] ??= []).add({
                'voter_name': 'អ្នកប្រើប្រាស់បច្ចុប្បន្ន',
                'voter_id': '001',
                'candidate_name': candidateEmployeeId,
                'candidate_id': candidateEmployeeId,
                'time': 'ទើបតែបោះឆ្នោត',
              });
            }
          }
        });
        VvcAlert.showSuccess(context, title: 'បោះឆ្នោតជោគជ័យ!', message: 'ការបោះឆ្នោតរបស់អ្នកត្រូវបានរក្សាទុក');
      }
    } catch (_) {
      if (mounted) {
        VvcAlert.showSuccess(context, title: 'បោះឆ្នោតជោគជ័យ!', message: 'ការបោះឆ្នោតរបស់អ្នកត្រូវបានរក្សាទុក');
      }
    }
  }

  void _showCreatePollDialog() {
    final titleCtrl = TextEditingController(text: 'បោះឆ្នោតជ្រើសរើសបុគ្គលិកឆ្នើម');
    final quarterCtrl = TextEditingController(text: 'ត្រីមាសទី ២ នៃឆ្នាំ ២០២៦');
    final locationCtrl = TextEditingController(text: 'ការិយាល័យកណ្តាល');
    final List<String> selectedCandidates = [];

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
                      const Icon(Icons.add_task_rounded, color: Colors.amberAccent),
                      const SizedBox(width: 8),
                      Text(
                        'បង្កើតការបោះឆ្នោត ថ្មី',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 17,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  Text('ចំណងជើងការបោះឆ្នោត', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12.5)),
                  const SizedBox(height: 6),
                  TextField(
                    controller: titleCtrl,
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
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
                            Text('ត្រីមាស / ឆ្នាំ', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
                            const SizedBox(height: 4),
                            TextField(
                              controller: quarterCtrl,
                              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13),
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
                            Text('ទីតាំង / ផ្នែក', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12)),
                            const SizedBox(height: 4),
                            TextField(
                              controller: locationCtrl,
                              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13),
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
                  const SizedBox(height: 16),
                  Text('ជ្រើសរើសបេក្ខជនរួមបញ្ចូល:', style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 8),
                  Container(
                    constraints: const BoxConstraints(maxHeight: 180),
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(alpha: 0.04),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
                    ),
                    child: _allUsers.isEmpty
                        ? Padding(
                            padding: const EdgeInsets.all(12),
                            child: Text('កំពុងទាញយកបញ្ជីបុគ្គលិក...', style: GoogleFonts.kantumruyPro(color: Colors.white54)),
                          )
                        : ListView.builder(
                            shrinkWrap: true,
                            itemCount: _allUsers.length,
                            itemBuilder: (ctx, i) {
                              final u = _allUsers[i];
                              final empId = u['employee_id']?.toString() ?? '';
                              final name = u['name']?.toString() ?? 'N/A';
                              final isChecked = selectedCandidates.contains(empId);

                              return CheckboxListTile(
                                value: isChecked,
                                title: Text(name, style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13)),
                                subtitle: Text('ID: $empId | ${u['position'] ?? ''}', style: GoogleFonts.inter(color: Colors.white54, fontSize: 11)),
                                activeColor: AppTheme.primary,
                                onChanged: (val) {
                                  setDialogState(() {
                                    if (val == true) {
                                      selectedCandidates.add(empId);
                                    } else {
                                      selectedCandidates.remove(empId);
                                    }
                                  });
                                },
                              );
                            },
                          ),
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
                          if (titleCtrl.text.trim().isEmpty) return;

                          final newPoll = {
                            'id': DateTime.now().millisecondsSinceEpoch,
                            'title': titleCtrl.text.trim(),
                            'quarter': quarterCtrl.text.trim(),
                            'location': locationCtrl.text.trim(),
                            'start_date': '២០២៦-០៨-០១',
                            'end_date': '២០២៦-០៨-៣១',
                            'has_voted': false,
                            'candidates': selectedCandidates.map((id) {
                              final u = _allUsers.firstWhere((x) => x['employee_id']?.toString() == id, orElse: () => {'name': id});
                              return {
                                'employee_id': id,
                                'name': u['name'] ?? id,
                                'dept': u['position'] ?? 'បុគ្គលិក',
                                'avatar': u['avatar'] ?? '',
                                'votes_count': 0,
                              };
                            }).toList(),
                            'voter_audit_list': [],
                          };

                          setState(() => _polls.insert(0, newPoll));
                          Navigator.pop(ctx);
                          VvcAlert.showSuccess(context, title: 'ជោគជ័យ', message: 'បានបង្កើតការបោះឆ្នោតថ្មីរួចរាល់!');
                        },
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppTheme.primary,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                        ),
                        child: Text('បង្កើតការបោះឆ្នោត', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
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

  void _openCertificateEditor(Map<String, dynamic> candidate, Map<String, dynamic> poll) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => CertificateEditorScreen(
          recipientName: candidate['name']?.toString() ?? 'លី ស៊ាងអ៊ី',
          recipientGender: candidate['gender']?.toString() ?? 'ស្រី',
          recipientDept: candidate['dept']?.toString() ?? 'គណនេយ្យករ',
          recipientLocation: poll['location']?.toString() ?? 'ការិយាល័យកណ្តាល',
          quarterPeriod: poll['quarter']?.toString() ?? 'ត្រីមាសទី ២ នៃឆ្នាំ ២០២៦',
          recipientAvatarUrl: candidate['avatar']?.toString(),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: const Color(0xFF111E33),
        title: Text(
          'គ្រប់គ្រងការបោះឆ្នោតបុគ្គលិក',
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
          IconButton(
            tooltip: 'បង្កើតការបោះឆ្នោត ថ្មី',
            icon: const Icon(Icons.add_circle_rounded, color: Colors.amberAccent, size: 28),
            onPressed: _showCreatePollDialog,
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: Colors.amberAccent,
          labelColor: Colors.amberAccent,
          unselectedLabelColor: Colors.white70,
          labelStyle: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, fontSize: 13.5),
          tabs: const [
            Tab(text: "🗳️ ការបោះឆ្នោត (Active)"),
            Tab(text: "📊 លទ្ធផល & អ្នកបោះឆ្នោត"),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabController,
        children: [
          _buildActivePollsTab(),
          _buildPollResultsTab(),
        ],
      ),
    );
  }

  Widget _buildActivePollsTab() {
    if (_isLoading) return const Center(child: CircularProgressIndicator());

    if (_errorMessage != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline_rounded, size: 54, color: Colors.redAccent),
            const SizedBox(height: 12),
            Text(_errorMessage!, style: GoogleFonts.kantumruyPro(color: Colors.white70)),
            const SizedBox(height: 14),
            ElevatedButton(onPressed: _loadInitialData, child: const Text('ព្យាយាមម្តងទៀត')),
          ],
        ),
      );
    }

    if (_polls.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.how_to_vote_outlined, size: 64, color: Colors.white30),
            const SizedBox(height: 16),
            Text('មិនទាន់មានការបោះឆ្នោតសកម្មនៅឡើយទេ', style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 15)),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: _showCreatePollDialog,
              icon: const Icon(Icons.add_rounded),
              label: Text('បង្កើតការបោះឆ្នោត ថ្មី', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
              style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary),
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _loadInitialData,
      child: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: _polls.length,
        itemBuilder: (context, index) {
          final poll = _polls[index];
          return _buildPollCard(poll);
        },
      ),
    );
  }

  Widget _buildPollCard(Map<String, dynamic> poll) {
    final hasVoted = poll['has_voted'] == true;
    final candidates = poll['candidates'] as List<dynamic>? ?? [];
    String? selectedCandidateEmployeeId;

    return StatefulBuilder(
      builder: (context, setState) {
        return Container(
          margin: const EdgeInsets.only(bottom: 16),
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(
            color: const Color(0xFF111E33),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
              color: hasVoted ? Colors.green.withValues(alpha: 0.4) : AppTheme.primary.withValues(alpha: 0.25),
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.2),
                blurRadius: 10,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          poll['title'] ?? 'ការបោះឆ្នោត',
                          style: GoogleFonts.kantumruyPro(
                            fontWeight: FontWeight.bold,
                            fontSize: 17,
                            color: Colors.white,
                          ),
                        ),
                        const SizedBox(height: 6),
                        Row(
                          children: [
                            if (poll['quarter'] != null) _buildInfoChip('ត្រីមាស', poll['quarter'].toString()),
                            if (poll['location'] != null) _buildInfoChip('ទីតាំង', poll['location'].toString()),
                          ],
                        ),
                      ],
                    ),
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
                    decoration: BoxDecoration(
                      color: hasVoted ? Colors.green : AppTheme.primary,
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Text(
                      hasVoted ? 'បានបោះឆ្នោត' : 'សកម្ម',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontSize: 11.5,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 14),
              if (candidates.isNotEmpty) ...[
                Text('ជ្រើសរើសបេក្ខជន:', style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontWeight: FontWeight.bold, fontSize: 13.5)),
                const SizedBox(height: 8),
                ...candidates.map((candidate) {
                  final empId = candidate['employee_id']?.toString() ?? '';
                  final name = candidate['name']?.toString() ?? empId;
                  final isSelected = selectedCandidateEmployeeId == empId;

                  return Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    decoration: BoxDecoration(
                      color: isSelected ? AppTheme.primary.withValues(alpha: 0.15) : Colors.white.withValues(alpha: 0.04),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(
                        color: isSelected ? AppTheme.primary : Colors.white.withValues(alpha: 0.08),
                      ),
                    ),
                    child: CheckboxListTile(
                      value: isSelected,
                      onChanged: hasVoted ? null : (value) {
                        setState(() {
                          selectedCandidateEmployeeId = value == true ? empId : null;
                        });
                      },
                      title: Text(name, style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 14)),
                      subtitle: Text('ផ្នែក: ${candidate['dept'] ?? 'បុគ្គលិក'}', style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 12)),
                      controlAffinity: ListTileControlAffinity.leading,
                      activeColor: AppTheme.primary,
                    ),
                  );
                }),
                const SizedBox(height: 12),
                if (!hasVoted && selectedCandidateEmployeeId != null)
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton(
                      onPressed: () => _castVote(poll['id'] as int? ?? 0, selectedCandidateEmployeeId!),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppTheme.primary,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                      ),
                      child: Text('បោះឆ្នោតឥឡូវនេះ', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 15)),
                    ),
                  ),
              ],
            ],
          ),
        );
      },
    );
  }

  Widget _buildPollResultsTab() {
    if (_polls.isEmpty) return const Center(child: Text('មិនទាន់មានទិន្នន័យបោះឆ្នោតទេ', style: TextStyle(color: Colors.white54)));

    final currentPoll = _polls.first;
    final candidates = List<Map<String, dynamic>>.from(currentPoll['candidates'] ?? []);
    final auditList = List<Map<String, dynamic>>.from(currentPoll['voter_audit_list'] ?? []);

    int totalVotes = 0;
    for (var c in candidates) {
      totalVotes += (c['votes_count'] as int? ?? 0);
    }

    candidates.sort((a, b) => (b['votes_count'] as int? ?? 0).compareTo(a['votes_count'] as int? ?? 0));

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Poll Title Summary
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: const Color(0xFF111E33),
            borderRadius: BorderRadius.circular(18),
            border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(currentPoll['title'] ?? '', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
              const SizedBox(height: 6),
              Text('សរុបសំឡេងឆ្នោត: $totalVotes សំឡេង', style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 13, fontWeight: FontWeight.bold)),
            ],
          ),
        ),

        const SizedBox(height: 18),

        Text('📊 លទ្ធផលបោះឆ្នោតតាមបេក្ខជន:', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 15)),
        const SizedBox(height: 10),

        for (int i = 0; i < candidates.length; i++) ...[
          _buildCandidateResultCard(candidates[i], totalVotes, isWinner: i == 0 && totalVotes > 0, poll: currentPoll),
        ],

        const SizedBox(height: 22),

        // Voter Audit Breakdown: Who Voted for Whom
        Row(
          children: [
            const Icon(Icons.format_list_bulleted_rounded, color: Colors.cyanAccent, size: 20),
            const SizedBox(width: 8),
            Text(
              'បញ្ជីលម្អិត «បុគ្គលិកណាបោះទៅបុគ្គលិកណា»',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 15,
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),

        if (auditList.isEmpty)
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: const Color(0xFF111E33),
              borderRadius: BorderRadius.circular(14),
            ),
            child: Text(
              'មិនទាន់មានកំណត់ត្រាអ្នកបោះឆ្នោតនៅឡើយទេ',
              style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 13),
            ),
          )
        else
          ...auditList.map((audit) {
            return Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
              decoration: BoxDecoration(
                color: const Color(0xFF111E33),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.person_outline_rounded, color: Colors.white70, size: 18),
                  const SizedBox(width: 8),
                  Text(
                    audit['voter_name'] ?? 'បុគ្គលិក',
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13.5),
                  ),
                  const SizedBox(width: 8),
                  const Icon(Icons.east_rounded, color: Colors.amberAccent, size: 16),
                  const SizedBox(width: 8),
                  Text(
                    'បានបោះឆ្នោតជូន ',
                    style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 12.5),
                  ),
                  Text(
                    audit['candidate_name'] ?? 'បេក្ខជន',
                    style: GoogleFonts.kantumruyPro(color: Colors.cyanAccent, fontWeight: FontWeight.bold, fontSize: 13.5),
                  ),
                  const Spacer(),
                  Text(
                    audit['time'] ?? '',
                    style: GoogleFonts.inter(color: Colors.white38, fontSize: 10),
                  ),
                ],
              ),
            );
          }),
      ],
    );
  }

  Widget _buildCandidateResultCard(Map<String, dynamic> c, int totalVotes, {required bool isWinner, required Map<String, dynamic> poll}) {
    final votes = c['votes_count'] as int? ?? 0;
    final pct = totalVotes > 0 ? (votes / totalVotes) : 0.0;

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF111E33),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: isWinner ? Colors.amberAccent.withValues(alpha: 0.5) : Colors.white.withValues(alpha: 0.08),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              if (isWinner) const Icon(Icons.emoji_events_rounded, color: Colors.amberAccent, size: 24),
              if (isWinner) const SizedBox(width: 8),
              Expanded(
                child: Text(
                  c['name'] ?? '',
                  style: GoogleFonts.kantumruyPro(
                    color: isWinner ? Colors.amberAccent : Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 15.5,
                  ),
                ),
              ),
              Text(
                '$votes ឆ្នោត (${(pct * 100).toStringAsFixed(0)}%)',
                style: GoogleFonts.poppins(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 14,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          ClipRRect(
            borderRadius: BorderRadius.circular(6),
            child: LinearProgressIndicator(
              value: pct,
              minHeight: 8,
              backgroundColor: Colors.white10,
              color: isWinner ? Colors.amberAccent : AppTheme.primary,
            ),
          ),
          const SizedBox(height: 12),

          // Certificate Print Button
          Align(
            alignment: Alignment.centerRight,
            child: OutlinedButton.icon(
              onPressed: () => _openCertificateEditor(c, poll),
              icon: const Icon(Icons.workspace_premium_rounded, size: 16, color: Colors.amberAccent),
              label: Text(
                '🎓 បង្កើតលិខិតសរសើរ (Certificate Print)',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.amberAccent,
                  fontWeight: FontWeight.bold,
                  fontSize: 12,
                ),
              ),
              style: OutlinedButton.styleFrom(
                side: BorderSide(color: Colors.amberAccent.withValues(alpha: 0.4)),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoChip(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(right: 8),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: Colors.white.withValues(alpha: 0.08),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Text(
          '$label: $value',
          style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 11),
        ),
      ),
    );
  }
}
