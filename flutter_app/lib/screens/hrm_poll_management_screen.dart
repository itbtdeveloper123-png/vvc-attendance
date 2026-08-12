import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/vvc_global_alert.dart';
import '../widgets/vvc_dropdown.dart';
import 'certificate_editor_screen.dart';
import 'poll_voting_screen.dart';

class HrmPollManagementScreen extends StatefulWidget {
  const HrmPollManagementScreen({super.key});

  @override
  State<HrmPollManagementScreen> createState() => _HrmPollManagementScreenState();
}

class _HrmPollManagementScreenState extends State<HrmPollManagementScreen> {
  final ApiService _api = ApiService();

  List<dynamic> _polls = [];
  List<dynamic> _allUsers = [];
  bool _isLoading = true;
  String? _errorMessage;
  String _resultsCategory = 'all'; // 'all', 'skilled', or 'worker'

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
        _api.getPolls(),
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
        final fallbackRes = await _api.fetchActivePolls();
        if (fallbackRes['success'] == true && fallbackRes['data'] != null) {
          _polls = List<dynamic>.from(fallbackRes['data']);
        } else if (apiRes['data'] != null) {
          _polls = List<dynamic>.from(apiRes['data']);
        } else {
          _polls = [];
        }
      }

      // Format candidates with user details if needed
      for (var poll in _polls) {
        if (poll['candidates'] != null && poll['candidates'] is List) {
          for (var c in poll['candidates']) {
            final empId = c['employee_id']?.toString() ?? '';
            if (_allUsers.isNotEmpty && empId.isNotEmpty) {
              final match = _allUsers.firstWhere(
                (u) =>
                    u['employee_id']?.toString() == empId ||
                    (empId.replaceAll(RegExp(r'^0+'), '').isNotEmpty &&
                        u['employee_id']?.toString().replaceAll(RegExp(r'^0+'), '') ==
                            empId.replaceAll(RegExp(r'^0+'), '')),
                orElse: () => null,
              );
              if (match != null) {
                final mName = (match['name'] ?? '').toString().trim();
                if (mName.isNotEmpty) {
                  c['name'] = mName;
                }
                c['department'] = match['department'] ?? match['position'] ?? c['department'];
                c['photo_url'] = match['photo_url'] ?? match['photo'] ?? match['avatar'] ?? c['photo_url'];
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

  Future<void> _deletePoll(Map<String, dynamic> poll) async {
    final confirmed = await VvcAlert.showConfirmDialog(
      context,
      title: 'លុបការបោះឆ្នោត',
      message: 'តើអ្នកប្រាកដជាចង់លុបការបោះឆ្នោត "${poll['title']}" នេះមែនទេ?',
    );

    if (confirmed != true) return;

    try {
      final pollIdInt = int.tryParse((poll['id'] ?? poll['doc_id'] ?? '').toString());
      if (pollIdInt != null && pollIdInt > 0) {
        await _api.deletePoll(pollIdInt);
      }

      _loadInitialData();

      if (mounted) {
        VvcAlert.showSuccess(context, title: 'ជោគជ័យ', message: 'បានលុបការបោះឆ្នោតរួចរាល់!');
      }
    } catch (e) {
      if (mounted) {
        VvcAlert.showError(context, title: 'កំហុស', message: 'មិនអាចលុបការបោះឆ្នោតបានទេ: $e');
      }
    }
  }

  void _openCertificateEditor(
    Map<String, dynamic> candidate,
    Map<String, dynamic> poll, {
    int rankNumber = 1,
    String category = 'skilled',
  }) {
    final String empId = (candidate['employee_id'] ?? candidate['voter_employee_id'] ?? '').toString();
    final String candidateName = (candidate['name'] ?? candidate['voter_name'] ?? '').toString();

    Map<String, dynamic>? foundUser;
    if (_allUsers.isNotEmpty) {
      foundUser = _allUsers.firstWhere(
        (u) {
          final uId = u['employee_id']?.toString() ?? '';
          final uName = u['name']?.toString() ?? '';
          if (empId.isNotEmpty && uId.isNotEmpty) {
            final cleanUId = uId.replaceAll(RegExp(r'^0+'), '');
            final cleanEmpId = empId.replaceAll(RegExp(r'^0+'), '');
            if (uId == empId || cleanUId == cleanEmpId) return true;
          }
          if (candidateName.isNotEmpty && uName.isNotEmpty) {
            if (uName.trim().toLowerCase() == candidateName.trim().toLowerCase()) return true;
          }
          return false;
        },
        orElse: () => <String, dynamic>{},
      );
    }

    String? avatarUrl = candidate['photo_url']?.toString() ??
        candidate['avatar']?.toString() ??
        candidate['photo']?.toString() ??
        candidate['image']?.toString();

    if ((avatarUrl == null || avatarUrl.trim().isEmpty) && foundUser != null) {
      avatarUrl = foundUser['photo_url']?.toString() ??
          foundUser['avatar']?.toString() ??
          foundUser['photo']?.toString() ??
          foundUser['image']?.toString();
    }

    final String gender = candidate['gender']?.toString() ?? foundUser?['gender']?.toString() ?? 'ស្រី';
    final String dept = candidate['dept']?.toString() ??
        candidate['department']?.toString() ??
        foundUser?['position']?.toString() ??
        foundUser?['department']?.toString() ??
        'បុគ្គលិក';
    final String recipientName =
        candidateName.isNotEmpty ? candidateName : (foundUser?['name']?.toString() ?? 'លី ស៊ាងអ៊ី');

    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => CertificateEditorScreen(
          recipientName: recipientName,
          recipientGender: gender,
          recipientDept: dept,
          recipientLocation: poll['location']?.toString() ?? 'ការិយាល័យកណ្តាល',
          quarterPeriod: poll['quarter']?.toString() ?? 'ត្រីមាសទី ២ នៃឆ្នាំ ២០២៦',
          recipientAvatarUrl: avatarUrl,
          rankNumber: rankNumber,
          initialCategory: category,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: AppTheme.bgDark,
        elevation: 0,
        centerTitle: true,
        title: Text(
          'គ្រប់គ្រងការបោះឆ្នោត HRM',
          style: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.bold,
            color: Colors.white,
            fontSize: 17,
          ),
        ),
        actions: [
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh_rounded, color: Colors.white70),
            onPressed: _loadInitialData,
          ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
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

    // Compute summary stats
    final int totalPollsCount = _polls.length;
    int activePollsCount = 0;
    int totalVotesCast = 0;

    for (var p in _polls) {
      final bool isActive = (p['is_active'] == 1 || p['is_active'] == '1' || p['is_active'] == true);
      if (isActive) activePollsCount++;

      final candidates = (p['candidates'] as List<dynamic>?) ?? [];
      for (var c in candidates) {
        final v = int.tryParse(c['votes_count']?.toString() ?? c['votes']?.toString() ?? '0') ?? 0;
        totalVotesCast += v;
      }
      final auditList = (p['voter_audit_list'] as List<dynamic>?) ?? [];
      if (totalVotesCast == 0 && auditList.isNotEmpty) {
        totalVotesCast += auditList.length;
      }
    }

    return RefreshIndicator(
      onRefresh: _loadInitialData,
      color: Colors.amberAccent,
      child: ListView(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        children: [
          // Top Summary Banner Card
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [
                  Color(0xFF1E293B),
                  Color(0xFF0F172A),
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(18),
              border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
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
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: Colors.amberAccent.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: const Icon(Icons.admin_panel_settings_rounded, color: Colors.amberAccent, size: 22),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'ផ្ទាំងគ្រប់គ្រងការបោះឆ្នោត HRM',
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontWeight: FontWeight.bold,
                              fontSize: 15,
                            ),
                          ),
                          Text(
                            'គ្រប់គ្រង បង្កើត មើលលទ្ធផល & ចេញប័ណ្ណសរសើរ',
                            style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 11.5),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 14),
                Row(
                  children: [
                    _buildStatCard('ការបោះឆ្នោតសរុប', '$totalPollsCount', Icons.ballot_rounded, Colors.amberAccent),
                    const SizedBox(width: 8),
                    _buildStatCard('កំពុងដំណើរការ', '$activePollsCount', Icons.play_circle_fill_rounded, Colors.greenAccent),
                    const SizedBox(width: 8),
                    _buildStatCard('សំឡេងឆ្នោតសរុប', '$totalVotesCast', Icons.how_to_vote_rounded, Colors.cyanAccent),
                  ],
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Expanded(
                      child: ElevatedButton.icon(
                        onPressed: () => _showCreatePollDialog(),
                        icon: const Icon(Icons.add_rounded, color: Colors.black, size: 18),
                        label: Text(
                          'បង្កើត Poll ថ្មី',
                          style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 12.5),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.amberAccent,
                          padding: const EdgeInsets.symmetric(vertical: 11),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                        ),
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () {
                          Navigator.push(
                            context,
                            MaterialPageRoute(builder: (_) => const PollVotingScreen()),
                          );
                        },
                        icon: const Icon(Icons.how_to_vote_rounded, color: Colors.cyanAccent, size: 17),
                        label: Text(
                          'ទំព័របោះឆ្នោត',
                          style: GoogleFonts.kantumruyPro(color: Colors.cyanAccent, fontWeight: FontWeight.bold, fontSize: 12.5),
                        ),
                        style: OutlinedButton.styleFrom(
                          side: BorderSide(color: Colors.cyanAccent.withValues(alpha: 0.6)),
                          padding: const EdgeInsets.symmetric(vertical: 11),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),

          const SizedBox(height: 16),

          Row(
            children: [
              const Icon(Icons.format_list_bulleted_rounded, color: Colors.amberAccent, size: 18),
              const SizedBox(width: 8),
              Text(
                'បញ្ជីការបោះឆ្នោតទាំងអស់ (${_polls.length})',
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: 15,
                ),
              ),
            ],
          ),

          const SizedBox(height: 12),

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
                    'មិនទាន់មានការបោះឆ្នោតនៅឡើយទេ',
                    style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 14, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 14),
                  ElevatedButton.icon(
                    onPressed: () => _showCreatePollDialog(),
                    icon: const Icon(Icons.add_rounded, color: Colors.black),
                    label: Text('បង្កើតការបោះឆ្នោតដំបូង', style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold)),
                    style: ElevatedButton.styleFrom(backgroundColor: Colors.amberAccent),
                  ),
                ],
              ),
            )
          else
            ..._polls.map((poll) => _buildHrmPollCard(poll)),
        ],
      ),
    );
  }

  Widget _buildStatCard(String label, String value, IconData icon, Color color) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
        decoration: BoxDecoration(
          color: Colors.white.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: color.withValues(alpha: 0.2)),
        ),
        child: Column(
          children: [
            Icon(icon, color: color, size: 20),
            const SizedBox(height: 6),
            Text(
              value,
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16),
            ),
            Text(
              label,
              textAlign: TextAlign.center,
              style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 10.5),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHrmPollCard(Map<String, dynamic> poll) {
    final title = (poll['title'] ?? 'បោះឆ្នោតបុគ្គលិកឆ្នើម').toString();
    final quarter = (poll['quarter'] ?? '').toString();
    final location = (poll['location'] ?? 'Head Office').toString();
    final bool isActive = (poll['is_active'] == 1 || poll['is_active'] == '1' || poll['is_active'] == true);

    final candidates = (poll['candidates'] as List<dynamic>?) ?? [];
    int totalVotes = 0;
    for (var c in candidates) {
      final v = int.tryParse(c['votes_count']?.toString() ?? c['votes']?.toString() ?? '0') ?? 0;
      totalVotes += v;
    }
    final auditList = (poll['voter_audit_list'] as List<dynamic>?) ?? [];
    if (totalVotes == 0 && auditList.isNotEmpty) {
      totalVotes = auditList.length;
    }

    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1E293B),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: isActive ? Colors.amberAccent.withValues(alpha: 0.35) : Colors.white.withValues(alpha: 0.08),
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
          // 1. Top Header: Title & Action Buttons (Edit, Delete)
          Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(7),
                decoration: BoxDecoration(
                  color: isActive ? Colors.amberAccent.withValues(alpha: 0.15) : Colors.white.withValues(alpha: 0.06),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(Icons.poll_rounded, color: isActive ? Colors.amberAccent : Colors.white60, size: 18),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  title,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: GoogleFonts.kantumruyPro(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 15.5,
                  ),
                ),
              ),
              const SizedBox(width: 6),
              // Action Buttons
              InkWell(
                onTap: () => _showCreatePollDialog(pollToEdit: poll),
                borderRadius: BorderRadius.circular(8),
                child: Container(
                  padding: const EdgeInsets.all(7),
                  decoration: BoxDecoration(
                    color: Colors.amberAccent.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(Icons.edit_rounded, color: Colors.amberAccent, size: 17),
                ),
              ),
              const SizedBox(width: 6),
              InkWell(
                onTap: () => _deletePoll(poll),
                borderRadius: BorderRadius.circular(8),
                child: Container(
                  padding: const EdgeInsets.all(7),
                  decoration: BoxDecoration(
                    color: Colors.redAccent.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(Icons.delete_outline_rounded, color: Colors.redAccent, size: 17),
                ),
              ),
            ],
          ),

          const SizedBox(height: 12),

          // 2. Meta Tags Row (Quarter, Location, Status)
          Wrap(
            spacing: 6,
            runSpacing: 6,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              if (quarter.isNotEmpty)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: Colors.cyanAccent.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(color: Colors.cyanAccent.withValues(alpha: 0.3)),
                  ),
                  child: Text(
                    quarter,
                    style: GoogleFonts.kantumruyPro(color: Colors.cyanAccent, fontSize: 11, fontWeight: FontWeight.bold),
                  ),
                ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.06),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  location,
                  style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 11),
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: isActive ? Colors.green.withValues(alpha: 0.15) : Colors.red.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: isActive ? Colors.greenAccent.withValues(alpha: 0.4) : Colors.redAccent.withValues(alpha: 0.4)),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 6,
                      height: 6,
                      decoration: BoxDecoration(
                        color: isActive ? Colors.greenAccent : Colors.redAccent,
                        shape: BoxShape.circle,
                      ),
                    ),
                    const SizedBox(width: 5),
                    Text(
                      isActive ? 'កំពុងដំណើរការ' : 'បានបញ្ចប់',
                      style: GoogleFonts.kantumruyPro(
                        color: isActive ? Colors.greenAccent : Colors.redAccent,
                        fontSize: 11,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),

          const SizedBox(height: 12),
          const Divider(color: Colors.white10, height: 1),
          const SizedBox(height: 12),

          // 3. Stats Pill Row
          Row(
            children: [
              Expanded(
                child: Container(
                  padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 10),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.04),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(Icons.people_alt_rounded, color: Colors.amberAccent, size: 16),
                      const SizedBox(width: 6),
                      Flexible(
                        child: Text(
                          'បេក្ខជន៖ ${candidates.length} នាក់',
                          style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 12, fontWeight: FontWeight.w600),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Container(
                  padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 10),
                  decoration: BoxDecoration(
                    color: const Color(0xFF10B981).withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: const Color(0xFF10B981).withValues(alpha: 0.25)),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(Icons.how_to_vote_rounded, color: Color(0xFF10B981), size: 16),
                      const SizedBox(width: 6),
                      Flexible(
                        child: Text(
                          'បោះឆ្នោត៖ $totalVotes សំឡេង',
                          style: GoogleFonts.kantumruyPro(color: const Color(0xFF10B981), fontSize: 12, fontWeight: FontWeight.bold),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),

          const SizedBox(height: 12),

          // 4. Main Action Button: Open Results Modal
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: () => _showPollResultsModal(poll),
              icon: const Icon(Icons.analytics_rounded, color: Colors.black, size: 18),
              label: Text(
                'មើលលទ្ធផល & កំណត់ត្រាបោះឆ្នោត',
                style: GoogleFonts.kantumruyPro(
                  fontWeight: FontWeight.bold,
                  color: Colors.black,
                  fontSize: 13,
                ),
              ),
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.amberAccent,
                padding: const EdgeInsets.symmetric(vertical: 11),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                elevation: 0,
              ),
            ),
          ),
        ],
      ),
    );
  }

  // Admin Create/Edit Poll Dialog
  void _showCreatePollDialog({Map<String, dynamic>? pollToEdit}) {
    final isEditing = pollToEdit != null;
    final titleController = TextEditingController(text: pollToEdit?['title'] ?? '');
    final locationController = TextEditingController(text: pollToEdit?['location'] ?? 'Head Office');
    final passcodeController = TextEditingController(text: pollToEdit?['access_code'] ?? pollToEdit?['passcode'] ?? '');

    String selectedQuarter = pollToEdit?['quarter'] ?? 'Q2 2026';
    DateTime startDate = pollToEdit?['start_date'] != null && pollToEdit!['start_date'].toString().isNotEmpty
        ? (DateTime.tryParse(pollToEdit['start_date'].toString()) ?? DateTime.now())
        : DateTime.now();
    DateTime endDate = pollToEdit?['end_date'] != null && pollToEdit!['end_date'].toString().isNotEmpty
        ? (DateTime.tryParse(pollToEdit['end_date'].toString()) ?? DateTime.now().add(const Duration(days: 30)))
        : DateTime.now().add(const Duration(days: 30));

    List<Map<String, dynamic>> selectedCandidates = [];
    if (pollToEdit?['candidates'] != null) {
      selectedCandidates = List<Map<String, dynamic>>.from(pollToEdit!['candidates']);
    }

    List<String> excludedCandidateIds = [];
    if (pollToEdit?['excluded_employee_ids'] != null) {
      final rawEx = pollToEdit!['excluded_employee_ids'];
      if (rawEx is List) {
        excludedCandidateIds = rawEx.map((e) => e.toString()).toList();
      } else if (rawEx is String) {
        try {
          final dec = jsonDecode(rawEx);
          if (dec is List) {
            excludedCandidateIds = dec.map((e) => e.toString()).toList();
          }
        } catch (_) {
          excludedCandidateIds = rawEx.split(',').map((e) => e.trim()).toList();
        }
      }
    }

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setModalState) => Container(
          height: MediaQuery.of(context).size.height * 0.9,
          decoration: BoxDecoration(
            color: AppTheme.bgDark,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
            border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.3)),
          ),
          child: Column(
            children: [
              const SizedBox(height: 12),
              Container(width: 40, height: 4, decoration: BoxDecoration(color: Colors.white30, borderRadius: BorderRadius.circular(10))),
              const SizedBox(height: 14),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: Row(
                  children: [
                    Icon(isEditing ? Icons.edit_note_rounded : Icons.add_circle_rounded, color: Colors.amberAccent, size: 24),
                    const SizedBox(width: 10),
                    Text(
                      isEditing ? 'កែប្រែការបោះឆ្នោត' : 'បង្កើតការបោះឆ្នោតថ្មី',
                      style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 17),
                    ),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.close_rounded, color: Colors.white70),
                      onPressed: () => Navigator.pop(ctx),
                    ),
                  ],
                ),
              ),
              const Divider(color: Colors.white12),
              Expanded(
                child: ListView(
                  padding: const EdgeInsets.all(20),
                  children: [
                    _buildFormLabel('ចំណងជើងការបោះឆ្នោត:'),
                    const SizedBox(height: 6),
                    TextField(
                      controller: titleController,
                      style: GoogleFonts.kantumruyPro(color: Colors.white),
                      decoration: _inputDecoration('ឧ. បោះឆ្នោតបុគ្គលិកឆ្នើមប្រចាំត្រីមាសទី ២'),
                    ),
                    const SizedBox(height: 14),
                    _buildFormLabel('ត្រីមាស / វគ្គ:'),
                    const SizedBox(height: 6),
                    VvcDropdown<String>(
                      value: selectedQuarter,
                      items: const [
                        VvcDropdownItem(value: 'Q1 2026', label: 'ត្រីមាសទី ១ (Q1 2026)'),
                        VvcDropdownItem(value: 'Q2 2026', label: 'ត្រីមាសទី ២ (Q2 2026)'),
                        VvcDropdownItem(value: 'Q3 2026', label: 'ត្រីមាសទី ៣ (Q3 2026)'),
                        VvcDropdownItem(value: 'Q4 2026', label: 'ត្រីមាសទី ៤ (Q4 2026)'),
                      ],
                      onChanged: (val) {
                        if (val != null) setModalState(() => selectedQuarter = val);
                      },
                    ),
                    const SizedBox(height: 14),
                    _buildFormLabel('ទីតាំង / ផ្នែក:'),
                    const SizedBox(height: 6),
                    TextField(
                      controller: locationController,
                      style: GoogleFonts.kantumruyPro(color: Colors.white),
                      decoration: _inputDecoration('ឧ. Head Office ឬ All Branches'),
                    ),
                    const SizedBox(height: 14),
                    Row(
                      children: [
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              _buildFormLabel('ថ្ងៃចាប់ផ្តើម:'),
                              const SizedBox(height: 6),
                              InkWell(
                                onTap: () async {
                                  final picked = await showDatePicker(
                                    context: context,
                                    initialDate: startDate,
                                    firstDate: DateTime(2025),
                                    lastDate: DateTime(2030),
                                  );
                                  if (picked != null) setModalState(() => startDate = picked);
                                },
                                child: Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                                  decoration: BoxDecoration(
                                    color: Colors.white.withValues(alpha: 0.05),
                                    borderRadius: BorderRadius.circular(12),
                                    border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
                                  ),
                                  child: Text(
                                    '${startDate.day}/${startDate.month}/${startDate.year}',
                                    style: GoogleFonts.kantumruyPro(color: Colors.white),
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              _buildFormLabel('ថ្ងៃបញ្ចប់:'),
                              const SizedBox(height: 6),
                              InkWell(
                                onTap: () async {
                                  final picked = await showDatePicker(
                                    context: context,
                                    initialDate: endDate,
                                    firstDate: DateTime(2025),
                                    lastDate: DateTime(2030),
                                  );
                                  if (picked != null) setModalState(() => endDate = picked);
                                },
                                child: Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                                  decoration: BoxDecoration(
                                    color: Colors.white.withValues(alpha: 0.05),
                                    borderRadius: BorderRadius.circular(12),
                                    border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
                                  ),
                                  child: Text(
                                    '${endDate.day}/${endDate.month}/${endDate.year}',
                                    style: GoogleFonts.kantumruyPro(color: Colors.white),
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 14),
                    _buildFormLabel('លេខកូដសម្ងាត់ (Passcode សម្រាប់បុគ្គលិកមើលលទ្ធផល):'),
                    const SizedBox(height: 6),
                    TextField(
                      controller: passcodeController,
                      keyboardType: TextInputType.number,
                      style: GoogleFonts.kantumruyPro(color: Colors.white),
                      decoration: _inputDecoration('ទុកទំនេរប្រសិនបើមិនត្រូវការលេខកូដ'),
                    ),
                    const SizedBox(height: 18),

                    // Candidates Selection
                    Row(
                      children: [
                        _buildFormLabel('បញ្ជីបេក្ខជន (${selectedCandidates.length} នាក់):'),
                        const Spacer(),
                        TextButton.icon(
                          onPressed: () {
                            _showCandidatePickerModal(context, selectedCandidates, (updated) {
                              setModalState(() => selectedCandidates = updated);
                            });
                          },
                          icon: const Icon(Icons.add_rounded, color: Colors.amberAccent, size: 18),
                          label: Text('ជ្រើសរើសបេក្ខជន', style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontWeight: FontWeight.bold)),
                        ),
                      ],
                    ),
                    if (selectedCandidates.isEmpty)
                      Container(
                        padding: const EdgeInsets.all(16),
                        decoration: BoxDecoration(
                          color: Colors.white.withValues(alpha: 0.03),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(color: Colors.white.withValues(alpha: 0.06)),
                        ),
                        child: Text(
                          'មិនទាន់បានជ្រើសរើសបេក្ខជននៅឡើយទេ។ សូមចុច «ជ្រើសរើសបេក្ខជន» ខាងលើ។',
                          style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 12.5),
                        ),
                      )
                    else
                      ...selectedCandidates.map((cand) {
                        return Container(
                          margin: const EdgeInsets.only(bottom: 6),
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                          decoration: BoxDecoration(
                            color: Colors.white.withValues(alpha: 0.05),
                            borderRadius: BorderRadius.circular(10),
                          ),
                          child: Row(
                            children: [
                              const Icon(Icons.person_rounded, color: Colors.amberAccent, size: 18),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  '${cand['name'] ?? cand['employee_id']} (${cand['department'] ?? cand['category'] ?? 'បុគ្គលិក'})',
                                  style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13),
                                ),
                              ),
                              IconButton(
                                icon: const Icon(Icons.remove_circle_outline, color: Colors.redAccent, size: 18),
                                onPressed: () {
                                  setModalState(() {
                                    selectedCandidates.removeWhere((c) => (c['employee_id'] ?? c['id']) == (cand['employee_id'] ?? cand['id']));
                                  });
                                },
                              ),
                            ],
                          ),
                        );
                      }),
                  ],
                ),
              ),
              Padding(
                padding: const EdgeInsets.all(20),
                child: SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: () async {
                      final title = titleController.text.trim();
                      if (title.isEmpty) {
                        VvcAlert.showError(context, title: 'ខ្វះព័ត៌មាន', message: 'សូមបញ្ចូលចំណងជើងការបោះឆ្នោត');
                        return;
                      }

                      Navigator.pop(ctx);
                      setState(() => _isLoading = true);

                      try {
                        final pollIdInt = int.tryParse((pollToEdit?['id'] ?? pollToEdit?['doc_id'] ?? '').toString());
                        final res = await _api.savePoll(
                          id: isEditing ? pollIdInt : null,
                          title: title,
                          quarter: selectedQuarter,
                          location: locationController.text.trim().isEmpty ? 'Head Office' : locationController.text.trim(),
                          startDate: '${startDate.year}-${startDate.month.toString().padLeft(2, '0')}-${startDate.day.toString().padLeft(2, '0')}',
                          endDate: '${endDate.year}-${endDate.month.toString().padLeft(2, '0')}-${endDate.day.toString().padLeft(2, '0')}',
                          passcode: passcodeController.text.trim(),
                          excludedCandidates: excludedCandidateIds,
                          candidates: selectedCandidates,
                        );

                        if (res['success'] == true) {
                          if (mounted) {
                            VvcAlert.showSuccess(context, title: 'ជោគជ័យ', message: isEditing ? 'បានកែប្រែការបោះឆ្នោតរួចរាល់' : 'បានបង្កើតការបោះឆ្នោតថ្មីជោគជ័យ');
                          }
                          _loadInitialData();
                        } else {
                          if (mounted) {
                            VvcAlert.showError(context, title: 'បរាជ័យ', message: res['message'] ?? 'មិនអាចរក្សាទុកបានទេ');
                          }
                        }
                      } catch (e) {
                        if (mounted) {
                          VvcAlert.showError(context, title: 'កំហុស', message: 'មានបញ្ហាក្នុងការរក្សាទុក: $e');
                        }
                      } finally {
                        if (mounted) setState(() => _isLoading = false);
                      }
                    },
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.amberAccent,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                    ),
                    child: Text(
                      isEditing ? 'រក្សាទុកការកែប្រែ' : 'បង្កើតការបោះឆ្នោតឥឡូវនេះ',
                      style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 15),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showCandidatePickerModal(
    BuildContext context,
    List<Map<String, dynamic>> currentSelected,
    Function(List<Map<String, dynamic>>) onDone,
  ) {
    List<Map<String, dynamic>> tempSelected = List.from(currentSelected);
    String searchQuery = '';

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setPickerState) {
          final filteredUsers = _allUsers.where((u) {
            final name = (u['name'] ?? '').toString().toLowerCase();
            final empId = (u['employee_id'] ?? '').toString().toLowerCase();
            final dept = (u['department'] ?? u['position'] ?? '').toString().toLowerCase();
            final q = searchQuery.toLowerCase();
            return name.contains(q) || empId.contains(q) || dept.contains(q);
          }).toList();

          return Container(
            height: MediaQuery.of(context).size.height * 0.85,
            decoration: BoxDecoration(
              color: AppTheme.bgDark,
              borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
            ),
            child: Column(
              children: [
                const SizedBox(height: 12),
                Container(width: 40, height: 4, decoration: BoxDecoration(color: Colors.white30, borderRadius: BorderRadius.circular(10))),
                const SizedBox(height: 14),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 20),
                  child: Row(
                    children: [
                      Text(
                        'ជ្រើសរើសបេក្ខជន (${tempSelected.length})',
                        style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16),
                      ),
                      const Spacer(),
                      ElevatedButton(
                        onPressed: () {
                          onDone(tempSelected);
                          Navigator.pop(ctx);
                        },
                        style: ElevatedButton.styleFrom(backgroundColor: Colors.amberAccent, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10))),
                        child: Text('រួចរាល់', style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold)),
                      ),
                    ],
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: TextField(
                    onChanged: (v) => setPickerState(() => searchQuery = v),
                    style: GoogleFonts.kantumruyPro(color: Colors.white),
                    decoration: _inputDecoration('ស្វែងរកឈ្មោះ ឬអត្តលេខ...'),
                  ),
                ),
                Expanded(
                  child: ListView.builder(
                    itemCount: filteredUsers.length,
                    itemBuilder: (ctx, i) {
                      final u = filteredUsers[i];
                      final empId = u['employee_id']?.toString() ?? '';
                      final isSelected = tempSelected.any((c) => (c['employee_id'] ?? c['id'])?.toString() == empId);

                      return CheckboxListTile(
                        value: isSelected,
                        onChanged: (val) {
                          setPickerState(() {
                            if (val == true) {
                              tempSelected.add({
                                'id': u['id'] ?? 0,
                                'employee_id': empId,
                                'name': u['name'] ?? empId,
                                'department': u['department'] ?? u['position'] ?? 'បុគ្គលិក',
                                'category': u['branch'] ?? u['department'] ?? 'Head Office',
                                'photo_url': u['photo_url'] ?? u['photo'] ?? '',
                              });
                            } else {
                              tempSelected.removeWhere((c) => (c['employee_id'] ?? c['id'])?.toString() == empId);
                            }
                          });
                        },
                        title: Text(u['name'] ?? empId, style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
                        subtitle: Text('អត្តលេខ: $empId | ផ្នែក: ${u['department'] ?? u['position'] ?? 'បុគ្គលិក'}', style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 12)),
                        activeColor: Colors.amberAccent,
                        checkColor: Colors.black,
                      );
                    },
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  // HRM Results Modal Dashboard with Category Switcher, Medal Progress Bars, and Voter Audit
  void _showPollResultsModal(Map<String, dynamic> poll) async {
    final pollIdInt = int.tryParse((poll['id'] ?? poll['doc_id'] ?? '').toString()) ?? 0;

    Map<String, dynamic>? freshPollData;
    try {
      if (pollIdInt > 0) {
        final res = await _api.getPollResults(pollIdInt);
        if (res['success'] == true && res['data'] != null) {
          final data = res['data'];
          if (data is Map<String, dynamic>) {
            freshPollData = data;
          } else if (data is List && data.isNotEmpty) {
            freshPollData = data.first as Map<String, dynamic>;
          }
        }
      }
    } catch (_) {}

    if (!mounted) return;

    final targetPoll = freshPollData ?? poll;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setModalState) {
          final rawCandidates = (targetPoll['results'] ?? targetPoll['candidates'] ?? []) as List<dynamic>;
          List<Map<String, dynamic>> candidates = [];

          for (var item in rawCandidates) {
            if (item is Map<String, dynamic>) {
              candidates.add(Map<String, dynamic>.from(item));
            } else if (item is Map) {
              candidates.add(Map<String, dynamic>.from(item.cast<String, dynamic>()));
            }
          }

          final rawAuditList = (targetPoll['voter_audit_list'] ?? []) as List<dynamic>;
          List<Map<String, dynamic>> auditList = [];
          for (var a in rawAuditList) {
            if (a is Map<String, dynamic>) {
              auditList.add(Map<String, dynamic>.from(a));
            } else if (a is Map) {
              auditList.add(Map<String, dynamic>.from(a.cast<String, dynamic>()));
            }
          }

          // Format candidate names with _allUsers
          for (var c in candidates) {
            final empId = c['employee_id']?.toString() ?? '';
            if (_allUsers.isNotEmpty && empId.isNotEmpty) {
              final match = _allUsers.firstWhere(
                (u) =>
                    u['employee_id']?.toString() == empId ||
                    (empId.replaceAll(RegExp(r'^0+'), '').isNotEmpty &&
                        u['employee_id']?.toString().replaceAll(RegExp(r'^0+'), '') ==
                            empId.replaceAll(RegExp(r'^0+'), '')),
                orElse: () => null,
              );
              if (match != null) {
                final mName = (match['name'] ?? '').toString().trim();
                if (mName.isNotEmpty) {
                  c['name'] = mName;
                }
                c['department'] = match['department'] ?? match['position'] ?? c['department'];
                c['photo_url'] = match['photo_url'] ?? match['photo'] ?? match['avatar'] ?? c['photo_url'];
              }
            }
          }

          // Format audit list names with _allUsers
          for (var a in auditList) {
            final vId = (a['voter_id'] ?? a['voter_employee_id'] ?? '').toString();
            final cId = (a['candidate_id'] ?? a['candidate_employee_id'] ?? '').toString();

            if (_allUsers.isNotEmpty && vId.isNotEmpty) {
              final matchV = _allUsers.firstWhere(
                (u) =>
                    u['employee_id']?.toString() == vId ||
                    (vId.replaceAll(RegExp(r'^0+'), '').isNotEmpty &&
                        u['employee_id']?.toString().replaceAll(RegExp(r'^0+'), '') ==
                            vId.replaceAll(RegExp(r'^0+'), '')),
                orElse: () => null,
              );
              if (matchV != null) {
                final mVName = (matchV['name'] ?? '').toString().trim();
                if (mVName.isNotEmpty) {
                  a['voter_name'] = mVName;
                }
                a['voter_department'] = matchV['department'] ?? matchV['position'] ?? a['voter_department'];
              }
            }

            if (_allUsers.isNotEmpty && cId.isNotEmpty) {
              final matchC = _allUsers.firstWhere(
                (u) =>
                    u['employee_id']?.toString() == cId ||
                    (cId.replaceAll(RegExp(r'^0+'), '').isNotEmpty &&
                        u['employee_id']?.toString().replaceAll(RegExp(r'^0+'), '') ==
                            cId.replaceAll(RegExp(r'^0+'), '')),
                orElse: () => null,
              );
              if (matchC != null) {
                final mCName = (matchC['name'] ?? '').toString().trim();
                if (mCName.isNotEmpty) {
                  a['candidate_name'] = mCName;
                }
              }
            }
          }

          // Calculate vote counts with fallback to auditList records if votes_count is 0
          for (var c in candidates) {
            int v = int.tryParse(c['votes_count']?.toString() ?? c['votes']?.toString() ?? '0') ?? 0;
            if (v == 0 && auditList.isNotEmpty) {
              final cId = (c['employee_id'] ?? '').toString();
              final cName = (c['name'] ?? '').toString().trim().toLowerCase();
              final auditCount = auditList.where((a) {
                final aCandId = (a['candidate_id'] ?? '').toString();
                final aCandName = (a['candidate_name'] ?? '').toString().trim().toLowerCase();
                if (cId.isNotEmpty && aCandId.isNotEmpty) {
                  if (cId == aCandId || cId.replaceAll(RegExp(r'^0+'), '') == aCandId.replaceAll(RegExp(r'^0+'), '')) {
                    return true;
                  }
                }
                if (cName.isNotEmpty && aCandName.isNotEmpty && cName == aCandName) {
                  return true;
                }
                return false;
              }).length;
              if (auditCount > 0) {
                v = auditCount;
                c['votes_count'] = v;
                c['votes'] = v;
              }
            }
          }

          int totalVotes = 0;
          for (var c in candidates) {
            final v = int.tryParse(c['votes_count']?.toString() ?? c['votes']?.toString() ?? '0') ?? 0;
            totalVotes += v;
          }
          if (totalVotes == 0 && auditList.isNotEmpty) {
            totalVotes = auditList.length;
          }

          candidates.sort((a, b) {
            final vA = int.tryParse(a['votes_count']?.toString() ?? a['votes']?.toString() ?? '0') ?? 0;
            final vB = int.tryParse(b['votes_count']?.toString() ?? b['votes']?.toString() ?? '0') ?? 0;
            return vB.compareTo(vA);
          });

          bool isWorkerCandidate(Map<String, dynamic> c) {
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

          List<Map<String, dynamic>> displayCandidates;
          if (_resultsCategory == 'skilled') {
            displayCandidates = candidates.where((c) => !isWorkerCandidate(c)).toList();
          } else if (_resultsCategory == 'worker') {
            displayCandidates = candidates.where((c) => isWorkerCandidate(c)).toList();
          } else {
            displayCandidates = List.from(candidates);
          }

          final votedCandidates = displayCandidates.where((c) {
            final v = int.tryParse(c['votes_count']?.toString() ?? c['votes']?.toString() ?? '0') ?? 0;
            return v > 0;
          }).toList();

          final bool hasVotes = votedCandidates.isNotEmpty;
          final topWinner = hasVotes
              ? votedCandidates.first
              : (displayCandidates.isNotEmpty ? displayCandidates.first : <String, dynamic>{});
          final int winnerVotes =
              int.tryParse(topWinner['votes_count']?.toString() ?? topWinner['votes']?.toString() ?? '0') ?? 0;

          return Container(
            height: MediaQuery.of(context).size.height * 0.88,
            decoration: BoxDecoration(
              color: AppTheme.bgDark,
              borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
            ),
            child: Column(
              children: [
                const SizedBox(height: 12),
                Container(width: 40, height: 4, decoration: BoxDecoration(color: Colors.white30, borderRadius: BorderRadius.circular(10))),
                const SizedBox(height: 16),
                Expanded(
                  child: ListView(
                    padding: const EdgeInsets.all(20),
                    children: [
                      // Header Card
                      Container(
                        padding: const EdgeInsets.all(18),
                        decoration: BoxDecoration(
                          color: const Color(0xFF111E33),
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.3)),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                Expanded(
                                  child: Text(
                                    targetPoll['title'] ?? 'បោះឆ្នោតបុគ្គលិកឆ្នើម',
                                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 17),
                                  ),
                                ),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                                  decoration: BoxDecoration(
                                    color: Colors.amberAccent.withValues(alpha: 0.15),
                                    borderRadius: BorderRadius.circular(10),
                                  ),
                                  child: Text(
                                    targetPoll['quarter'] ?? 'ត្រីមាសទី ២',
                                    style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontWeight: FontWeight.bold, fontSize: 11),
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 8),
                            Row(
                              children: [
                                Text('សរុបសំឡេងឆ្នោត ៖ ', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13)),
                                Text(
                                  '$totalVotes សំឡេង',
                                  style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontWeight: FontWeight.bold, fontSize: 15),
                                ),
                                const Spacer(),
                                Text('បេក្ខជនសរុប ៖ ', style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13)),
                                Text(
                                  '${candidates.length} នាក់',
                                  style: GoogleFonts.kantumruyPro(color: Colors.cyanAccent, fontWeight: FontWeight.bold, fontSize: 15),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),

                      const SizedBox(height: 16),

                      // Category Switcher Tabs: 📋 ទាំងអស់ | 👔 ជំនាញ | 👷‍♂️ កម្មករ
                      Container(
                        padding: const EdgeInsets.all(4),
                        decoration: BoxDecoration(
                          color: const Color(0xFF111E33),
                          borderRadius: BorderRadius.circular(16),
                          border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
                        ),
                        child: Row(
                          children: [
                            Expanded(
                              child: _buildCategoryTab('all', '📋 ទាំងអស់', _resultsCategory == 'all', setModalState),
                            ),
                            Expanded(
                              child: _buildCategoryTab('skilled', '👔 ជំនាញ', _resultsCategory == 'skilled', setModalState),
                            ),
                            Expanded(
                              child: _buildCategoryTab('worker', '👷‍♂️ កម្មករ', _resultsCategory == 'worker', setModalState),
                            ),
                          ],
                        ),
                      ),

                      const SizedBox(height: 16),

                      // Certificate Generator Quick Action for Winner
                      if (topWinner.isNotEmpty && winnerVotes > 0)
                        Container(
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            gradient: const LinearGradient(
                              colors: [Color(0xFF2A1C05), Color(0xFF1B1408)],
                              begin: Alignment.topLeft,
                              end: Alignment.bottomRight,
                            ),
                            borderRadius: BorderRadius.circular(18),
                            border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.4)),
                          ),
                          child: Row(
                            children: [
                              Container(
                                padding: const EdgeInsets.all(10),
                                decoration: const BoxDecoration(color: Colors.amber, shape: BoxShape.circle),
                                child: const Icon(Icons.workspace_premium_rounded, color: Colors.black, size: 22),
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      'ជ័យលាភីលេខ ១ ៖ ${topWinner['name'] ?? topWinner['employee_id']}',
                                      style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontWeight: FontWeight.bold, fontSize: 13.5),
                                    ),
                                    Text(
                                      'ទទួលបាន $winnerVotes សំឡេងឆ្នោត',
                                      style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 11.5),
                                    ),
                                  ],
                                ),
                              ),
                              ElevatedButton.icon(
                                onPressed: () {
                                  Navigator.pop(ctx);
                                  _openCertificateEditor(
                                    topWinner,
                                    targetPoll,
                                    rankNumber: 1,
                                    category: _resultsCategory,
                                  );
                                },
                                icon: const Icon(Icons.card_membership_rounded, color: Colors.black, size: 16),
                                label: Text(
                                  'ចេញប័ណ្ណ',
                                  style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 12),
                                ),
                                style: ElevatedButton.styleFrom(
                                  backgroundColor: Colors.amberAccent,
                                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                                ),
                              ),
                            ],
                          ),
                        ),

                      const SizedBox(height: 18),

                      Row(
                        children: [
                          const Icon(Icons.bar_chart_rounded, color: Colors.amberAccent, size: 20),
                          const SizedBox(width: 8),
                          Text(
                            '📊 លទ្ធផលបោះឆ្នោត (${displayCandidates.length} នាក់):',
                            style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 15),
                          ),
                        ],
                      ),

                      const SizedBox(height: 10),

                      if (displayCandidates.isEmpty)
                        Container(
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            color: const Color(0xFF111E33),
                            borderRadius: BorderRadius.circular(14),
                          ),
                          child: Text(
                            'មិនទាន់មានបេក្ខជនក្នុងប្រភេទនេះនៅឡើយទេ',
                            style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 13),
                          ),
                        )
                      else
                        for (int i = 0; i < displayCandidates.length; i++) ...[
                          _buildCandidateResultCard(
                            displayCandidates[i],
                            totalVotes,
                            isWinner: i == 0 &&
                                totalVotes > 0 &&
                                (int.tryParse(displayCandidates[i]['votes_count']?.toString() ??
                                        displayCandidates[i]['votes']?.toString() ??
                                        '0') ??
                                    0) >
                                    0,
                            poll: targetPoll,
                            rankNumber: i + 1,
                            category: _resultsCategory,
                            parentContext: ctx,
                          ),
                        ],

                      const SizedBox(height: 22),

                      // Voter Audit Breakdown
                      Row(
                        children: [
                          const Icon(Icons.format_list_bulleted_rounded, color: Colors.cyanAccent, size: 20),
                          const SizedBox(width: 8),
                          Text(
                            'បញ្ជីលម្អិត «បុគ្គលិកណាបោះទៅបុគ្គលិកណា» (${auditList.length})',
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
                        Container(
                          decoration: BoxDecoration(
                            color: const Color(0xFF111E33),
                            borderRadius: BorderRadius.circular(16),
                            border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
                          ),
                          child: Column(
                            children: auditList.map((audit) {
                              final voterName = audit['voter_name'] ?? audit['voter_id'] ?? 'បុគ្គលិក';
                              final candidateName = audit['candidate_name'] ?? audit['candidate_id'] ?? 'បេក្ខជន';
                              final time = audit['time'] ?? '';

                              return Container(
                                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                                decoration: BoxDecoration(
                                  border: Border(bottom: BorderSide(color: Colors.white.withValues(alpha: 0.05))),
                                ),
                                child: Row(
                                  children: [
                                    const Icon(Icons.check_circle_outline_rounded, color: Colors.greenAccent, size: 18),
                                    const SizedBox(width: 10),
                                    Expanded(
                                      child: Column(
                                        crossAxisAlignment: CrossAxisAlignment.start,
                                        children: [
                                          RichText(
                                            text: TextSpan(
                                              style: GoogleFonts.kantumruyPro(fontSize: 13, color: Colors.white),
                                              children: [
                                                TextSpan(text: voterName, style: const TextStyle(fontWeight: FontWeight.bold)),
                                                const TextSpan(text: '  ➔ បោះជូន  ', style: TextStyle(color: Colors.white60, fontSize: 11)),
                                                TextSpan(text: candidateName, style: const TextStyle(fontWeight: FontWeight.bold, color: Colors.amberAccent)),
                                              ],
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),
                                    if (time.isNotEmpty)
                                      Text(
                                        time,
                                        style: GoogleFonts.kantumruyPro(color: Colors.white38, fontSize: 11),
                                      ),
                                  ],
                                ),
                              );
                            }).toList(),
                          ),
                        ),

                      const SizedBox(height: 30),
                    ],
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  Widget _buildCategoryTab(String catKey, String label, bool isSelected, StateSetter setModalState) {
    return GestureDetector(
      onTap: () {
        setState(() => _resultsCategory = catKey);
        setModalState(() {});
      },
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(vertical: 10),
        decoration: BoxDecoration(
          color: isSelected ? Colors.amberAccent : Colors.transparent,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Center(
          child: Text(
            label,
            style: GoogleFonts.kantumruyPro(
              color: isSelected ? Colors.black : Colors.white70,
              fontWeight: FontWeight.bold,
              fontSize: 12.5,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildCandidateResultCard(
    Map<String, dynamic> candidate,
    int totalVotes, {
    required bool isWinner,
    required Map<String, dynamic> poll,
    required int rankNumber,
    required String category,
    required BuildContext parentContext,
  }) {
    final votes = int.tryParse(candidate['votes_count']?.toString() ?? candidate['votes']?.toString() ?? '0') ?? 0;
    final percentage = totalVotes > 0 ? (votes / totalVotes) : 0.0;
    final empId = candidate['employee_id']?.toString() ?? '';
    final name = candidate['name']?.toString() ?? empId;
    final dept = candidate['department'] ?? candidate['dept'] ?? candidate['category'] ?? 'បុគ្គលិក';

    Color rankColor;
    String rankBadge;

    if (rankNumber == 1 && votes > 0) {
      rankColor = const Color(0xFFFFD700);
      rankBadge = '🥇 លេខ ១';
    } else if (rankNumber == 2 && votes > 0) {
      rankColor = const Color(0xFFC0C0C0);
      rankBadge = '🥈 លេខ ២';
    } else if (rankNumber == 3 && votes > 0) {
      rankColor = const Color(0xFFCD7F32);
      rankBadge = '🥉 លេខ ៣';
    } else {
      rankColor = Colors.white38;
      rankBadge = '#$rankNumber';
    }

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: isWinner ? const Color(0xFF1A2638) : const Color(0xFF111E33),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: isWinner ? Colors.amberAccent : Colors.white.withValues(alpha: 0.08),
          width: isWinner ? 1.5 : 1.0,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: rankColor.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: rankColor),
                ),
                child: Text(
                  rankBadge,
                  style: GoogleFonts.kantumruyPro(color: rankColor, fontWeight: FontWeight.bold, fontSize: 11),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      name,
                      style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14),
                    ),
                    Text(
                      'ផ្នែក: $dept',
                      style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 11.5),
                    ),
                  ],
                ),
              ),
              Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Text(
                    '$votes សំឡេង',
                    style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontWeight: FontWeight.bold, fontSize: 14),
                  ),
                  Text(
                    '${(percentage * 100).toStringAsFixed(1)}%',
                    style: GoogleFonts.kantumruyPro(color: Colors.white60, fontSize: 11),
                  ),
                ],
              ),
            ],
          ),
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(8),
            child: LinearProgressIndicator(
              value: percentage,
              minHeight: 8,
              backgroundColor: Colors.white.withValues(alpha: 0.08),
              valueColor: AlwaysStoppedAnimation<Color>(
                isWinner ? Colors.amberAccent : AppTheme.primary,
              ),
            ),
          ),
          if (votes > 0) ...[
            const SizedBox(height: 10),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton.icon(
                onPressed: () {
                  Navigator.pop(parentContext);
                  _openCertificateEditor(candidate, poll, rankNumber: rankNumber, category: category);
                },
                icon: const Icon(Icons.card_membership_rounded, color: Colors.amberAccent, size: 16),
                label: Text('ចេញប័ណ្ណសរសើរ', style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontSize: 12, fontWeight: FontWeight.bold)),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildFormLabel(String label) {
    return Text(
      label,
      style: GoogleFonts.kantumruyPro(
        color: Colors.white.withValues(alpha: 0.9),
        fontSize: 13,
        fontWeight: FontWeight.bold,
      ),
    );
  }

  InputDecoration _inputDecoration(String hint) {
    return InputDecoration(
      hintText: hint,
      hintStyle: GoogleFonts.kantumruyPro(color: Colors.white30, fontSize: 13),
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
    );
  }
}
