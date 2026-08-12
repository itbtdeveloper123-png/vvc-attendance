import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/vvc_global_alert.dart';
import '../widgets/vvc_dropdown.dart';
import 'certificate_editor_screen.dart';

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
  String _resultsCategory = 'skilled'; // 'skilled' (បុគ្គលិកជំនាញ) or 'worker' (កម្មករ)

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
      final usersRes = await _api.fetchUsers();
      if (usersRes['success'] == true && usersRes['data'] != null) {
        _allUsers = List<dynamic>.from(usersRes['data']);
      }

      // Fetch polls from Backend API (MySQL DB in Admin Panel) with fallback
      final apiRes = await _api.fetchActivePolls();
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

      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    } catch (e) {
      debugPrint('API fetchActivePolls error: $e');
      if (mounted) {
        setState(() {
          _errorMessage = 'មិនអាចទាញយកទិន្នន័យបានទេ: $e';
          _isLoading = false;
        });
      }
    }
  }

  Future<void> _castVote(String pollDocId, String candidateEmployeeId) async {
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
        final res = await _api.castVote(pollIdInt, candidateEmployeeId);
        if (res['success'] == true) {
          if (mounted) {
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

  // Admin Panel 100% Matching Form Modal (Supports Create & Edit)
  void _showCreatePollDialog({Map<String, dynamic>? pollToEdit}) {
    final isEditing = pollToEdit != null;
    final pollIdInt = isEditing ? int.tryParse((pollToEdit['id'] ?? pollToEdit['doc_id'] ?? '').toString()) : null;

    final titleCtrl = TextEditingController(text: pollToEdit?['title']?.toString() ?? '');
    final passcodeCtrl = TextEditingController(text: pollToEdit?['passcode']?.toString() ?? pollToEdit?['access_code']?.toString() ?? '');

    String rawQ = pollToEdit?['quarter']?.toString() ?? 'ត្រីមាសទី ១';
    if (rawQ == 'Q1') {
      rawQ = 'ត្រីមាសទី ១';
    } else if (rawQ == 'Q2') {
      rawQ = 'ត្រីមាសទី ២';
    } else if (rawQ == 'Q3') {
      rawQ = 'ត្រីមាសទី ៣';
    } else if (rawQ == 'Q4') {
      rawQ = 'ត្រីមាសទី ៤';
    }
    String selectedQuarter = rawQ;
    String selectedWarehouse = pollToEdit?['location']?.toString() ?? 'Head Office';

    DateTime startDate = pollToEdit?['start_date'] != null
        ? (DateTime.tryParse(pollToEdit!['start_date'].toString()) ?? DateTime.now())
        : DateTime.now();
    DateTime endDate = pollToEdit?['end_date'] != null
        ? (DateTime.tryParse(pollToEdit!['end_date'].toString()) ?? DateTime.now().add(const Duration(days: 7)))
        : DateTime.now().add(const Duration(days: 7));

    final List<String> selectedCandidates = [];
    final List<String> excludedCandidates = [];

    bool containsEmpId(List<String> list, String targetId) {
      if (targetId.isEmpty) return false;
      final cleanTarget = targetId.replaceAll(RegExp(r'^0+'), '');
      return list.any((e) => e == targetId || (cleanTarget.isNotEmpty && e.replaceAll(RegExp(r'^0+'), '') == cleanTarget));
    }

    void toggleEmpId(List<String> list, String targetId, bool add) {
      if (targetId.isEmpty) return;
      final cleanTarget = targetId.replaceAll(RegExp(r'^0+'), '');
      list.removeWhere((e) => e == targetId || (cleanTarget.isNotEmpty && e.replaceAll(RegExp(r'^0+'), '') == cleanTarget));
      if (add) {
        list.add(targetId);
      }
    }

    if (isEditing) {
      final rawAllowed = pollToEdit['allowed_employee_ids'] ?? pollToEdit['candidates'];
      if (rawAllowed is List) {
        for (var c in rawAllowed) {
          if (c is Map && c['employee_id'] != null) {
            selectedCandidates.add(c['employee_id'].toString());
          } else if (c != null) {
            selectedCandidates.add(c.toString());
          }
        }
      } else if (rawAllowed is String && rawAllowed.trim().isNotEmpty) {
        try {
          final decoded = jsonDecode(rawAllowed);
          if (decoded is List) {
            for (var c in decoded) {
              if (c is Map && c['employee_id'] != null) {
                selectedCandidates.add(c['employee_id'].toString());
              } else if (c != null) {
                selectedCandidates.add(c.toString());
              }
            }
          }
        } catch (_) {
          selectedCandidates.addAll(rawAllowed.split(',').map((e) => e.trim()).where((e) => e.isNotEmpty));
        }
      }

      final rawExcluded = pollToEdit['excluded_employee_ids'] ?? pollToEdit['excluded_candidates'];
      if (rawExcluded is List) {
        for (var e in rawExcluded) {
          if (e != null) excludedCandidates.add(e.toString());
        }
      } else if (rawExcluded is String && rawExcluded.trim().isNotEmpty) {
        try {
          final decoded = jsonDecode(rawExcluded);
          if (decoded is List) {
            for (var e in decoded) {
              if (e != null) excludedCandidates.add(e.toString());
            }
          }
        } catch (_) {
          excludedCandidates.addAll(rawExcluded.split(',').map((e) => e.trim()).where((e) => e.isNotEmpty));
        }
      }
    }

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => Dialog(
          backgroundColor: Colors.transparent,
          insetPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 24),
          child: Container(
            constraints: const BoxConstraints(maxWidth: 500),
            decoration: BoxDecoration(
              color: const Color(0xFF131D2E).withValues(alpha: 0.96),
              borderRadius: BorderRadius.circular(24),
              border: Border.all(color: Colors.white.withValues(alpha: 0.12)),
            ),
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(22),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Form Header
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(6),
                            decoration: BoxDecoration(
                              color: isEditing ? Colors.amberAccent : AppTheme.primary,
                              shape: BoxShape.circle,
                            ),
                            child: Icon(isEditing ? Icons.edit_rounded : Icons.add, color: Colors.white, size: 20),
                          ),
                          const SizedBox(width: 10),
                          Text(
                            isEditing ? 'កែប្រែការបោះឆ្នោត' : 'បង្កើតការបោះឆ្នោតថ្មី',
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                      IconButton(
                        icon: const Icon(Icons.close_rounded, color: Colors.white70),
                        onPressed: () => Navigator.pop(ctx),
                      ),
                    ],
                  ),
                  const SizedBox(height: 18),

                  // 1. ចំណងជើង *
                  _buildFormLabel('ចំណងជើង *'),
                  const SizedBox(height: 6),
                  TextField(
                    controller: titleCtrl,
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14),
                    decoration: _inputDecoration('បញ្ចូលចំណងជើងការបោះឆ្នោត...'),
                  ),
                  const SizedBox(height: 14),

                  // 2. ត្រីមាស (Quarter Dropdown)
                  VvcDropdown<String>(
                    label: 'ត្រីមាស',
                    value: selectedQuarter,
                    prefixIcon: Icons.calendar_today_rounded,
                    items: const [
                      VvcDropdownItem(value: 'ត្រីមាសទី ១', label: 'ត្រីមាសទី ១'),
                      VvcDropdownItem(value: 'ត្រីមាសទី ២', label: 'ត្រីមាសទី ២'),
                      VvcDropdownItem(value: 'ត្រីមាសទី ៣', label: 'ត្រីមាសទី ៣'),
                      VvcDropdownItem(value: 'ត្រីមាសទី ៤', label: 'ត្រីមាសទី ៤'),
                    ],
                    onChanged: (val) {
                      if (val != null) setDialogState(() => selectedQuarter = val);
                    },
                  ),
                  const SizedBox(height: 14),

                  // 3. WAREHOUSE (ទីតាំង/ឃ្លាំង)
                  VvcDropdown<String>(
                    label: 'WAREHOUSE (ទីតាំង/ឃ្លាំង)',
                    value: selectedWarehouse,
                    prefixIcon: Icons.location_on_rounded,
                    items: const [
                      VvcDropdownItem(value: 'Head Office', label: 'Head Office (ការិយាល័យកណ្តាល)'),
                      VvcDropdownItem(value: 'Phnom Penh', label: 'Phnom Penh (ភ្នំពេញ)'),
                      VvcDropdownItem(value: 'Siem Reap', label: 'Siem Reap (សៀមរាប)'),
                      VvcDropdownItem(value: 'Battambang', label: 'Battambang (បាត់ដំបង)'),
                      VvcDropdownItem(value: 'Kampong Cham', label: 'Kampong Cham (កំពង់ចាម)'),
                    ],
                    onChanged: (val) {
                      if (val != null) setDialogState(() => selectedWarehouse = val);
                    },
                  ),
                  const SizedBox(height: 14),

                  // 4. កាលបរិច្ឆេទចាប់ផ្តើម
                  _buildFormLabel('កាលបរិច្ឆេទចាប់ផ្តើម'),
                  const SizedBox(height: 6),
                  InkWell(
                    onTap: () async {
                      final picked = await showDatePicker(
                        context: context,
                        initialDate: startDate,
                        firstDate: DateTime(2024),
                        lastDate: DateTime(2030),
                      );
                      if (picked != null) setDialogState(() => startDate = picked);
                    },
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.05),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
                      ),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            '${startDate.year}-${startDate.month.toString().padLeft(2, '0')}-${startDate.day.toString().padLeft(2, '0')}',
                            style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                          ),
                          const Icon(Icons.calendar_today_rounded, color: Colors.amberAccent, size: 18),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 14),

                  // 5. កាលបរិច្ឆេទបញ្ចប់
                  _buildFormLabel('កាលបរិច្ឆេទបញ្ចប់'),
                  const SizedBox(height: 6),
                  InkWell(
                    onTap: () async {
                      final picked = await showDatePicker(
                        context: context,
                        initialDate: endDate,
                        firstDate: DateTime(2024),
                        lastDate: DateTime(2030),
                      );
                      if (picked != null) setDialogState(() => endDate = picked);
                    },
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.05),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: Colors.white.withValues(alpha: 0.1)),
                      ),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            '${endDate.year}-${endDate.month.toString().padLeft(2, '0')}-${endDate.day.toString().padLeft(2, '0')}',
                            style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13.5),
                          ),
                          const Icon(Icons.calendar_today_rounded, color: Colors.amberAccent, size: 18),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 14),

                  // 6. លេខសម្ងាត់ចូលមើលលទ្ធផល (Passcode)
                  _buildFormLabel('លេខសម្ងាត់ចូលមើលលទ្ធផល (Passcode)'),
                  const SizedBox(height: 6),
                  TextField(
                    controller: passcodeCtrl,
                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 14),
                    decoration: _inputDecoration('ឧទាហរណ៍: 123456 (ទុកទទេបើមិនត្រូវការ)'),
                  ),
                  const SizedBox(height: 14),

                  // 7. ឈ្មោះដែលមិនត្រូវបោះឆ្នោត (OPTIONAL Excluded Candidates List)
                  _buildFormLabel('ឈ្មោះដែលមិនត្រូវបោះឆ្នោត (OPTIONAL)'),
                  const SizedBox(height: 6),
                  Container(
                    constraints: const BoxConstraints(maxHeight: 140),
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(alpha: 0.04),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
                    ),
                    child: _allUsers.isEmpty
                        ? Padding(
                            padding: const EdgeInsets.all(12),
                            child: Text('កំពុងទាញយកបញ្ជី...', style: GoogleFonts.kantumruyPro(color: Colors.white54)),
                          )
                        : ListView.builder(
                            shrinkWrap: true,
                            itemCount: _allUsers.length,
                            itemBuilder: (ctx, i) {
                              final u = _allUsers[i];
                              final empId = u['employee_id']?.toString() ?? '';
                              final name = u['name']?.toString() ?? empId;
                              final isChecked = containsEmpId(excludedCandidates, empId);

                              return CheckboxListTile(
                                value: isChecked,
                                title: Text('$name ($empId)', style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 12.5)),
                                subtitle: Text(u['branch'] ?? u['position'] ?? '', style: GoogleFonts.inter(color: Colors.white54, fontSize: 11)),
                                activeColor: Colors.redAccent,
                                onChanged: (val) {
                                  setDialogState(() {
                                    toggleEmpId(excludedCandidates, empId, val == true);
                                    if (val == true) {
                                      toggleEmpId(selectedCandidates, empId, false);
                                    }
                                  });
                                },
                              );
                            },
                          ),
                  ),
                  const SizedBox(height: 14),

                  // 8. បុគ្គលិកដែលអនុញ្ញាតឱ្យបោះឆ្នោត / បេក្ខជន
                  _buildFormLabel('បុគ្គលិកដែលអនុញ្ញាតឱ្យបោះឆ្នោត (បេក្ខជន) *'),
                  const SizedBox(height: 6),
                  Container(
                    constraints: const BoxConstraints(maxHeight: 160),
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(alpha: 0.04),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
                    ),
                    child: _allUsers.isEmpty
                        ? Padding(
                            padding: const EdgeInsets.all(12),
                            child: Text('កំពុងទាញយកបញ្ជី...', style: GoogleFonts.kantumruyPro(color: Colors.white54)),
                          )
                        : ListView.builder(
                            shrinkWrap: true,
                            itemCount: _allUsers.length,
                            itemBuilder: (ctx, i) {
                              final u = _allUsers[i];
                              final empId = u['employee_id']?.toString() ?? '';
                              final name = u['name']?.toString() ?? empId;
                              final isChecked = containsEmpId(selectedCandidates, empId);
                              final isExcluded = containsEmpId(excludedCandidates, empId);

                              if (isExcluded) return const SizedBox.shrink();

                              return CheckboxListTile(
                                value: isChecked,
                                title: Text('$name ($empId)', style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 13)),
                                subtitle: Text('ផ្នែក: ${u['position'] ?? 'បុគ្គលិក'}', style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 11)),
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
                  const SizedBox(height: 22),

                  // Submit Buttons
                  Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: [
                      TextButton(
                        onPressed: () => Navigator.pop(ctx),
                        child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: Colors.white60)),
                      ),
                      const SizedBox(width: 10),
                      ElevatedButton(
                        onPressed: () async {
                          final title = titleCtrl.text.trim();
                          if (title.isEmpty) {
                            VvcAlert.showError(context, title: 'សូមបញ្ចូលចំណងជើង', message: 'ចំណងជើងការបោះឆ្នោតមិនអាចទទេបានទេ');
                            return;
                          }

                          final candidatesData = selectedCandidates.map((id) {
                            final u = _allUsers.firstWhere((x) => x['employee_id']?.toString() == id, orElse: () => {'name': id});
                            return {
                              'employee_id': id,
                              'name': u['name'] ?? id,
                              'dept': u['position'] ?? 'បុគ្គលិក',
                              'avatar': u['avatar'] ?? '',
                              'votes_count': 0,
                            };
                          }).toList();

                          final startDateStr = '${startDate.year}-${startDate.month.toString().padLeft(2, '0')}-${startDate.day.toString().padLeft(2, '0')}';
                          final endDateStr = '${endDate.year}-${endDate.month.toString().padLeft(2, '0')}-${endDate.day.toString().padLeft(2, '0')}';

                          try {
                            await _api.savePoll(
                              id: pollIdInt,
                              title: title,
                              quarter: selectedQuarter,
                              location: selectedWarehouse,
                              startDate: startDateStr,
                              endDate: endDateStr,
                              passcode: passcodeCtrl.text.trim(),
                              excludedCandidates: excludedCandidates,
                              candidates: candidatesData,
                            );

                            _loadInitialData();

                            if (!ctx.mounted) return;
                            Navigator.pop(ctx);
                            if (mounted) {
                              VvcAlert.showSuccess(
                                context,
                                title: 'ជោគជ័យ',
                                message: isEditing ? 'បានធ្វើបច្ចុប្បន្នភាពការបោះឆ្នោតជោគជ័យ!' : 'បានបង្កើតការបោះឆ្នោតថ្មីត្រឹមត្រូវ!',
                              );
                            }
                          } catch (e) {
                            if (!ctx.mounted) return;
                            Navigator.pop(ctx);
                            if (mounted) VvcAlert.showError(context, title: 'កំហុស', message: 'មិនអាចរក្សាទុកការបោះឆ្នោតបានទេ: $e');
                          }
                        },
                        style: ElevatedButton.styleFrom(
                          backgroundColor: isEditing ? Colors.amberAccent : AppTheme.primary,
                          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                        ),
                        child: Text(
                          isEditing ? 'រក្សាទុកការកែប្រែ' : 'បង្កើតការបោះឆ្នោត',
                          style: GoogleFonts.kantumruyPro(color: isEditing ? Colors.black : Colors.white, fontWeight: FontWeight.bold),
                        ),
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
    final String recipientName = candidateName.isNotEmpty ? candidateName : (foundUser?['name']?.toString() ?? 'លី ស៊ាងអ៊ី');

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
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final bool isHrmOrAdmin = userProvider.isHRM || userProvider.isAdmin;

    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: const Color(0xFF111E33),
        title: Text(
          isHrmOrAdmin ? 'គ្រប់គ្រងការបោះឆ្នោតបុគ្គលិក' : 'បោះឆ្នោតបុគ្គលិក',
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
          if (isHrmOrAdmin)
            IconButton(
              tooltip: 'បង្កើតការបោះឆ្នោត ថ្មី (Admin Panel)',
              icon: const Icon(Icons.add_circle_rounded, color: Colors.amberAccent, size: 28),
              onPressed: _showCreatePollDialog,
            ),
        ],
      ),
      body: _buildActivePollsTab(),
    );
  }

  Widget _buildActivePollsTab() {
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final isHrmOrAdmin = userProvider.isHRM || userProvider.isAdmin;

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
            if (isHrmOrAdmin) ...[
              const SizedBox(height: 16),
              ElevatedButton.icon(
                onPressed: _showCreatePollDialog,
                icon: const Icon(Icons.add_rounded),
                label: Text('បង្កើត Form បោះឆ្នោតថ្មី (Admin Panel)', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold)),
                style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary),
              ),
            ],
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
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final isHrmOrAdmin = userProvider.isHRM || userProvider.isAdmin;
    final bool hasVoted = poll['has_voted'] == true || poll['has_voted'] == 1 || poll['has_voted'] == '1' || poll['has_voted'] == 'true';
    List<dynamic> candidates = List<dynamic>.from(poll['candidates'] as List<dynamic>? ?? []);
    if (candidates.isEmpty && _allUsers.isNotEmpty) {
      final List<String> empIds = [];
      if (poll['allowed_employee_ids'] != null) {
        final raw = poll['allowed_employee_ids'];
        if (raw is List) {
          empIds.addAll(raw.map((e) => e.toString()));
        } else if (raw is String && raw.trim().isNotEmpty) {
          try {
            final decoded = jsonDecode(raw);
            if (decoded is List) {
              empIds.addAll(decoded.map((e) => e.toString()));
            }
          } catch (_) {}
        }
      }
      if (empIds.isEmpty && poll['target_employee_ids'] != null) {
        final raw = poll['target_employee_ids'].toString();
        empIds.addAll(raw.split(',').map((e) => e.trim()).where((e) => e.isNotEmpty));
      }

      if (empIds.isNotEmpty) {
        candidates = _allUsers
            .where((u) => empIds.contains(u['employee_id']?.toString()))
            .map((u) => {
                  'employee_id': u['employee_id'],
                  'name': u['name'] ?? u['employee_id'],
                  'department': u['position'] ?? u['department'] ?? 'បុគ្គលិក',
                  'votes_count': 0,
                })
            .toList();
      }
    }

    final docId = (poll['doc_id'] ?? poll['id'] ?? '').toString();
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
                            if (poll['quarter'] != null) _buildInfoChip('ត្រីមាស', _formatQuarter(poll['quarter'].toString())),
                            if (poll['location'] != null) _buildInfoChip('ទីតាំង', poll['location'].toString()),
                          ],
                        ),
                      ],
                    ),
                  ),
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
                        decoration: BoxDecoration(
                          color: hasVoted ? const Color(0xFF10B981) : Colors.amber,
                          borderRadius: BorderRadius.circular(20),
                        ),
                        child: Text(
                          hasVoted ? 'បានបោះរួចរាល់' : 'សកម្ម',
                          style: GoogleFonts.kantumruyPro(
                            color: hasVoted ? Colors.white : Colors.black,
                            fontSize: 11.5,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                      if (isHrmOrAdmin) ...[
                        const SizedBox(width: 8),
                        InkWell(
                          onTap: () => _showCreatePollDialog(pollToEdit: poll),
                          child: Container(
                            padding: const EdgeInsets.all(6),
                            decoration: const BoxDecoration(
                              color: Colors.amber,
                              shape: BoxShape.circle,
                            ),
                            child: const Icon(Icons.edit, color: Colors.black, size: 16),
                          ),
                        ),
                        const SizedBox(width: 6),
                        InkWell(
                          onTap: () => _deletePoll(poll),
                          child: Container(
                            padding: const EdgeInsets.all(6),
                            decoration: const BoxDecoration(
                              color: Colors.redAccent,
                              shape: BoxShape.circle,
                            ),
                            child: const Icon(Icons.delete, color: Colors.white, size: 16),
                          ),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 14),
              if (isHrmOrAdmin) ...[
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.04),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: Colors.white.withValues(alpha: 0.08)),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.groups_rounded, color: Colors.amberAccent, size: 20),
                      const SizedBox(width: 10),
                      Text(
                        'បេក្ខជនក្នុងបញ្ជី៖ ${candidates.length} នាក់',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                          fontSize: 13.5,
                        ),
                      ),
                      const Spacer(),
                      const Icon(Icons.chevron_right_rounded, color: Colors.white54, size: 20),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    onPressed: () => _verifyPasscodeAndShowResults(poll),
                    icon: const Icon(Icons.bar_chart_rounded, color: Colors.black, size: 18),
                    label: Text(
                      '📊 មើលលទ្ធផល & អ្នកបោះឆ្នោត (Live HRM)',
                      style: GoogleFonts.kantumruyPro(
                        fontWeight: FontWeight.bold,
                        color: Colors.black,
                        fontSize: 13.5,
                      ),
                    ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.amberAccent,
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                  ),
                ),
                const SizedBox(height: 14),
              ],
              if (candidates.isNotEmpty) ...[
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
                  String name = candidate['name']?.toString() ?? empId;

                  if ((name.isEmpty || name == empId || RegExp(r'^\d+$').hasMatch(name)) && _allUsers.isNotEmpty) {
                    final match = _allUsers.firstWhere(
                      (u) => u['employee_id']?.toString() == empId || (empId.replaceAll(RegExp(r'^0+'), '').isNotEmpty && u['employee_id']?.toString().replaceAll(RegExp(r'^0+'), '') == empId.replaceAll(RegExp(r'^0+'), '')),
                      orElse: () => null,
                    );
                    if (match != null && (match['name'] ?? '').toString().isNotEmpty) {
                      name = match['name'];
                    }
                  }

                  final votedCandId = (poll['voted_candidate_id'] ?? '').toString();
                  final votedCandEmpId = (poll['voted_candidate_employee_id'] ?? '').toString();

                  final isUserVotedChoice = hasVoted && (
                    (votedCandId.isNotEmpty && (votedCandId == empId || votedCandId == candIdStr)) ||
                    (votedCandEmpId.isNotEmpty && (votedCandEmpId == empId || (empId.isNotEmpty && votedCandEmpId.replaceAll(RegExp(r'^0+'), '') == empId.replaceAll(RegExp(r'^0+'), ''))))
                  );
                  final isSelected = isUserVotedChoice || (selectedCandidateEmployeeId == empId);

                  final dept = candidate['department'] ?? candidate['dept'] ?? candidate['position'] ?? 'បុគ្គលិក';
                  final cat = candidate['category'] ?? (poll['location'] ?? 'Head Office');

                  return Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    decoration: BoxDecoration(
                      color: isUserVotedChoice
                          ? const Color(0xFF10B981).withValues(alpha: 0.18)
                          : (isSelected ? AppTheme.primary.withValues(alpha: 0.15) : Colors.white.withValues(alpha: 0.04)),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(
                        color: isUserVotedChoice
                            ? const Color(0xFF10B981)
                            : (isSelected ? AppTheme.primary : Colors.white.withValues(alpha: 0.08)),
                      ),
                    ),
                    child: CheckboxListTile(
                      value: isSelected,
                      onChanged: hasVoted ? null : (value) {
                        setState(() {
                          selectedCandidateEmployeeId = value == true ? empId : null;
                        });
                      },
                      title: Row(
                        children: [
                          Expanded(
                            child: Text(name, style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 14)),
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
                    child: ElevatedButton(
                      onPressed: () => _castVote(docId, selectedCandidateEmployeeId!),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppTheme.primary,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                      ),
                      child: Text('បោះឆ្នោតឥឡូវនេះ', style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, color: Colors.white, fontSize: 15)),
                    ),
                  ),
                if (hasVoted) ...[
                  const SizedBox(height: 10),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                    decoration: BoxDecoration(
                      color: Colors.green.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: Colors.green.withValues(alpha: 0.3)),
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.check_circle_rounded, color: Colors.greenAccent, size: 20),
                        const SizedBox(width: 8),
                        Text(
                          'អ្នកបានបោះឆ្នោតរួចរាល់ហើយ! (សូមអរគុណ)',
                          style: GoogleFonts.kantumruyPro(
                            color: Colors.greenAccent,
                            fontWeight: FontWeight.bold,
                            fontSize: 13.5,
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

  Future<void> _verifyPasscodeAndShowResults(Map<String, dynamic> poll) async {
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final bool isHrmOrAdmin = userProvider.isHRM || userProvider.isAdmin;
    final rawPasscode = (poll['access_code'] ?? poll['passcode'] ?? '').toString().trim();
    if (isHrmOrAdmin || rawPasscode.isEmpty) {
      _showPollResultsModal(poll);
      return;
    }

    final codeController = TextEditingController();
    final verified = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF131D2E),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(20),
          side: BorderSide(color: Colors.amberAccent.withValues(alpha: 0.3)),
        ),
        title: Row(
          children: [
            const Icon(Icons.lock_rounded, color: Colors.amberAccent, size: 22),
            const SizedBox(width: 8),
            Text(
              'ត្រូវការលេខកូដសម្ងាត់',
              style: GoogleFonts.kantumruyPro(
                color: Colors.white,
                fontWeight: FontWeight.bold,
                fontSize: 16,
              ),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'សូមបញ្ចូលលេខកូដសម្ងាត់ដើម្បីចូលមើលលទ្ធផលការបោះឆ្នោត៖',
              style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: codeController,
              autofocus: true,
              keyboardType: TextInputType.number,
              obscureText: true,
              style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 16, letterSpacing: 3),
              decoration: InputDecoration(
                hintText: 'បញ្ចូលលេខកូដសម្ងាត់',
                hintStyle: GoogleFonts.kantumruyPro(color: Colors.white38, fontSize: 13, letterSpacing: 0),
                filled: true,
                fillColor: Colors.white.withValues(alpha: 0.06),
                contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide(color: Colors.white.withValues(alpha: 0.15)),
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: const BorderSide(color: Colors.amberAccent),
                ),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text('បោះបង់', style: GoogleFonts.kantumruyPro(color: Colors.white60)),
          ),
          ElevatedButton(
            onPressed: () {
              if (codeController.text.trim() == rawPasscode) {
                Navigator.pop(ctx, true);
              } else {
                VvcAlert.showError(
                  ctx,
                  title: 'លេខកូដមិនត្រឹមត្រូវ',
                  message: 'លេខកូដសម្ងាត់ដែលអ្នកបញ្ចូលមិនត្រឹមត្រូវទេ!',
                );
              }
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.amberAccent,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
            ),
            child: Text(
              'ផ្ទៀងផ្ទាត់',
              style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold),
            ),
          ),
        ],
      ),
    );

    if (verified == true) {
      _showPollResultsModal(poll);
    }
  }

  void _showPollResultsModal(Map<String, dynamic> initialPoll) async {
    final userProvider = Provider.of<UserProvider>(context, listen: false);
    final bool isHrmOrAdmin = userProvider.isHRM || userProvider.isAdmin;
    if (!isHrmOrAdmin) {
      VvcAlert.showError(
        context,
        title: 'គ្មានសិទ្ធិ',
        message: 'មានតែផ្នែក HRM / Admin ប៉ុណ្ណោះដែលអាចមើលលទ្ធផល និងអ្នកបោះឆ្នោតបាន',
      );
      return;
    }

    // Refresh active polls first so we have the newest DB data
    Map<String, dynamic> poll = initialPoll;
    try {
      final freshRes = await _api.fetchActivePolls();
      if (freshRes['success'] == true && freshRes['data'] != null) {
        final List<dynamic> freshList = List<dynamic>.from(freshRes['data']);
        final targetId = (initialPoll['id'] ?? initialPoll['doc_id'])?.toString();
        final targetTitle = initialPoll['title']?.toString();
        final found = freshList.firstWhere(
          (p) => (p['id'] ?? p['doc_id'])?.toString() == targetId || (targetTitle != null && p['title']?.toString() == targetTitle),
          orElse: () => initialPoll,
        );
        if (found is Map<String, dynamic>) {
          poll = found;
        }
      }
    } catch (_) {}

    if (!mounted) return;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setModalState) {
            List<Map<String, dynamic>> candidates = List<Map<String, dynamic>>.from(poll['candidates'] ?? []);
            if (candidates.isEmpty && _allUsers.isNotEmpty) {
              final List<String> empIds = [];
              if (poll['allowed_employee_ids'] != null) {
                final raw = poll['allowed_employee_ids'];
                if (raw is List) {
                  empIds.addAll(raw.map((e) => e.toString()));
                } else if (raw is String && raw.trim().isNotEmpty) {
                  try {
                    final decoded = jsonDecode(raw);
                    if (decoded is List) {
                      empIds.addAll(decoded.map((e) => e.toString()));
                    }
                  } catch (_) {}
                }
              }
              if (empIds.isEmpty && poll['target_employee_ids'] != null) {
                final raw = poll['target_employee_ids'].toString();
                empIds.addAll(raw.split(',').map((e) => e.trim()).where((e) => e.isNotEmpty));
              }

              if (empIds.isNotEmpty) {
                candidates = _allUsers
                    .where((u) => empIds.contains(u['employee_id']?.toString()))
                    .map((u) => {
                          'employee_id': u['employee_id'],
                          'name': u['name'] ?? u['employee_id'],
                          'department': u['position'] ?? u['department'] ?? 'បុគ្គលិក',
                          'votes_count': 0,
                        })
                    .toList();
              }
            }
            final auditList = List<Map<String, dynamic>>.from(poll['voter_audit_list'] ?? []);

            // Enrich candidate names if missing or numeric ID
            for (var c in candidates) {
              final cEmpId = (c['employee_id'] ?? '').toString();
              final cName = (c['name'] ?? '').toString().trim();
              if ((cName.isEmpty || cName == cEmpId || RegExp(r'^\d+$').hasMatch(cName)) && _allUsers.isNotEmpty) {
                final match = _allUsers.firstWhere(
                  (u) => u['employee_id']?.toString() == cEmpId || (cEmpId.replaceAll(RegExp(r'^0+'), '').isNotEmpty && u['employee_id']?.toString().replaceAll(RegExp(r'^0+'), '') == cEmpId.replaceAll(RegExp(r'^0+'), '')),
                  orElse: () => null,
                );
                if (match != null && (match['name'] ?? '').toString().isNotEmpty) {
                  c['name'] = match['name'];
                }
              }
            }

            // Enrich audit list voter & candidate names if missing or numeric employee IDs
            for (var audit in auditList) {
              final vId = (audit['voter_id'] ?? '').toString();
              final vName = (audit['voter_name'] ?? '').toString().trim();
              if ((vName.isEmpty || vName == vId || RegExp(r'^\d+$').hasMatch(vName)) && _allUsers.isNotEmpty) {
                final match = _allUsers.firstWhere(
                  (u) => u['employee_id']?.toString() == vId || (vId.replaceAll(RegExp(r'^0+'), '').isNotEmpty && u['employee_id']?.toString().replaceAll(RegExp(r'^0+'), '') == vId.replaceAll(RegExp(r'^0+'), '')),
                  orElse: () => null,
                );
                if (match != null && (match['name'] ?? '').toString().isNotEmpty) {
                  audit['voter_name'] = match['name'];
                }
              }

              final candId = (audit['candidate_id'] ?? '').toString();
              final candName = (audit['candidate_name'] ?? '').toString().trim();
              if ((candName.isEmpty || candName == candId || candName == 'បេក្ខជន' || RegExp(r'^\d+$').hasMatch(candName)) && _allUsers.isNotEmpty) {
                final match = _allUsers.firstWhere(
                  (u) => u['employee_id']?.toString() == candId || (candId.replaceAll(RegExp(r'^0+'), '').isNotEmpty && u['employee_id']?.toString().replaceAll(RegExp(r'^0+'), '') == candId.replaceAll(RegExp(r'^0+'), '')),
                  orElse: () => null,
                );
                if (match != null && (match['name'] ?? '').toString().isNotEmpty) {
                  audit['candidate_name'] = match['name'];
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

            final bool isSkilledTab = _resultsCategory == 'skilled';
            final List<Map<String, dynamic>> categoryCandidates = candidates.where((c) {
              final isWorker = isWorkerCandidate(c);
              return isSkilledTab ? !isWorker : isWorker;
            }).toList();

            final List<Map<String, dynamic>> displayCandidates = categoryCandidates.isNotEmpty ? categoryCandidates : candidates;

            final votedCandidates = displayCandidates.where((c) {
              final v = int.tryParse(c['votes_count']?.toString() ?? c['votes']?.toString() ?? '0') ?? 0;
              return v > 0;
            }).toList();

            final bool hasVotes = votedCandidates.isNotEmpty;
            final topWinner = hasVotes ? votedCandidates.first : (displayCandidates.isNotEmpty ? displayCandidates.first : <String, dynamic>{});
            final int winnerVotes = int.tryParse(topWinner['votes_count']?.toString() ?? topWinner['votes']?.toString() ?? '0') ?? 0;

            return Container(
              height: MediaQuery.of(context).size.height * 0.85,
              decoration: BoxDecoration(
                color: AppTheme.bgDark,
                borderRadius: const BorderRadius.vertical(top: Radius.circular(28)),
              ),
              child: Column(
                children: [
                  const SizedBox(height: 12),
                  Container(
                    width: 40,
                    height: 4,
                    decoration: BoxDecoration(
                      color: Colors.white30,
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Expanded(
                    child: ListView(
                      padding: const EdgeInsets.all(20),
                      children: [
                        // Poll Title Summary Header
                        Container(
                          padding: const EdgeInsets.all(18),
                          decoration: BoxDecoration(
                            color: const Color(0xFF111E33),
                            borderRadius: BorderRadius.circular(20),
                            border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.2)),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                poll['title'] ?? 'បោះឆ្នោតបុគ្គលិកឆ្នើម',
                                style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 17),
                              ),
                              const SizedBox(height: 6),
                              Row(
                                children: [
                                  Text(
                                    'សរុបសំឡេងឆ្នោត ៖ ',
                                    style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 13),
                                  ),
                                  Text(
                                    '$totalVotes សំឡេង',
                                    style: GoogleFonts.kantumruyPro(color: Colors.amberAccent, fontWeight: FontWeight.bold, fontSize: 14),
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ),

                        const SizedBox(height: 16),

                        // Category Switcher
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
                                child: GestureDetector(
                                  onTap: () {
                                    setState(() => _resultsCategory = 'skilled');
                                    setModalState(() {});
                                  },
                                  child: AnimatedContainer(
                                    duration: const Duration(milliseconds: 200),
                                    padding: const EdgeInsets.symmetric(vertical: 11),
                                    decoration: BoxDecoration(
                                      color: isSkilledTab ? Colors.amberAccent : Colors.transparent,
                                      borderRadius: BorderRadius.circular(12),
                                    ),
                                    child: Row(
                                      mainAxisAlignment: MainAxisAlignment.center,
                                      children: [
                                        Icon(
                                          Icons.badge_rounded,
                                          size: 18,
                                          color: isSkilledTab ? Colors.black : Colors.white70,
                                        ),
                                        const SizedBox(width: 6),
                                        Text(
                                          '👔 បុគ្គលិកជំនាញ',
                                          style: GoogleFonts.kantumruyPro(
                                            color: isSkilledTab ? Colors.black : Colors.white70,
                                            fontWeight: FontWeight.bold,
                                            fontSize: 13.5,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                ),
                              ),
                              Expanded(
                                child: GestureDetector(
                                  onTap: () {
                                    setState(() => _resultsCategory = 'worker');
                                    setModalState(() {});
                                  },
                                  child: AnimatedContainer(
                                    duration: const Duration(milliseconds: 200),
                                    padding: const EdgeInsets.symmetric(vertical: 11),
                                    decoration: BoxDecoration(
                                      color: !isSkilledTab ? Colors.cyanAccent : Colors.transparent,
                                      borderRadius: BorderRadius.circular(12),
                                    ),
                                    child: Row(
                                      mainAxisAlignment: MainAxisAlignment.center,
                                      children: [
                                        Icon(
                                          Icons.engineering_rounded,
                                          size: 18,
                                          color: !isSkilledTab ? Colors.black : Colors.white70,
                                        ),
                                        const SizedBox(width: 6),
                                        Text(
                                          '👷‍♂️ កម្មករ / ប្រតិបត្តិការ',
                                          style: GoogleFonts.kantumruyPro(
                                            color: !isSkilledTab ? Colors.black : Colors.white70,
                                            fontWeight: FontWeight.bold,
                                            fontSize: 13.5,
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

                        const SizedBox(height: 16),

                        // Certificate generator button
                        if (candidates.isNotEmpty)
                          Container(
                            padding: const EdgeInsets.all(16),
                            decoration: BoxDecoration(
                              gradient: const LinearGradient(
                                colors: [Color(0xFF1E293B), Color(0xFF0F172A)],
                                begin: Alignment.topLeft,
                                end: Alignment.bottomRight,
                              ),
                              borderRadius: BorderRadius.circular(18),
                              border: Border.all(color: Colors.amberAccent.withValues(alpha: 0.3)),
                            ),
                            child: Row(
                              children: [
                                Container(
                                  padding: const EdgeInsets.all(10),
                                  decoration: BoxDecoration(
                                    color: Colors.amberAccent.withValues(alpha: 0.15),
                                    shape: BoxShape.circle,
                                  ),
                                  child: const Icon(Icons.workspace_premium_rounded, color: Colors.amberAccent, size: 28),
                                ),
                                const SizedBox(width: 14),
                                Expanded(
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        isSkilledTab
                                            ? '🎓 បង្កើតប័ណ្ណសរសើរជំនាញ (២ សន្លឹក)'
                                            : '🎓 បង្កើតប័ណ្ណសរសើរកម្មករ (លេខ ១,២,៣)',
                                        style: GoogleFonts.kantumruyPro(
                                          color: Colors.amberAccent,
                                          fontWeight: FontWeight.bold,
                                          fontSize: 14.5,
                                        ),
                                      ),
                                      const SizedBox(height: 2),
                                      Text(
                                        winnerVotes > 0
                                            ? 'ជ័យលាភី៖ ${topWinner['name'] ?? 'បុគ្គលិកឆ្នើម'} ($winnerVotes ឆ្នោត)'
                                            : 'ជ័យលាភី៖ មិនទាន់មានសំឡេងឆ្នោត',
                                        style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 12),
                                      ),
                                    ],
                                  ),
                                ),
                                ElevatedButton.icon(
                                  onPressed: () => _openCertificateEditor(
                                    topWinner,
                                    poll,
                                    rankNumber: 1,
                                    category: _resultsCategory,
                                  ),
                                  icon: const Icon(Icons.print_rounded, size: 16, color: Colors.black),
                                  label: Text(
                                    'បង្កើត',
                                    style: GoogleFonts.kantumruyPro(color: Colors.black, fontWeight: FontWeight.bold),
                                  ),
                                  style: ElevatedButton.styleFrom(
                                    backgroundColor: Colors.amberAccent,
                                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
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
                              isSkilledTab
                                  ? '📊 លទ្ធផលបោះឆ្នោត (បុគ្គលិកជំនាញ):'
                                  : '📊 លទ្ធផលបោះឆ្នោត (កម្មករ - លេខ ១,២,៣):',
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
                              isWinner: i == 0 && totalVotes > 0 && (int.tryParse(displayCandidates[i]['votes_count']?.toString() ?? displayCandidates[i]['votes']?.toString() ?? '0') ?? 0) > 0,
                              poll: poll,
                              rankNumber: i + 1,
                              category: _resultsCategory,
                            ),
                          ],

                        const SizedBox(height: 22),

                        // Voter Audit Breakdown
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
                    ),
                  ),
                ],
              ),
            );
          },
        );
      },
    );
  }

  Widget _buildCandidateResultCard(
    Map<String, dynamic> c,
    int totalVotes, {
    required bool isWinner,
    required Map<String, dynamic> poll,
    int rankNumber = 1,
    String category = 'skilled',
  }) {
    final votes = int.tryParse(c['votes_count']?.toString() ?? c['votes']?.toString() ?? '0') ?? 0;
    final pct = totalVotes > 0 ? (votes / totalVotes) : 0.0;
    final bool isWorker = category == 'worker';

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
              if (isWorker)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  margin: const EdgeInsets.only(right: 8),
                  decoration: BoxDecoration(
                    color: rankNumber == 1
                        ? Colors.amber.withValues(alpha: 0.2)
                        : (rankNumber == 2 ? Colors.blueGrey.withValues(alpha: 0.2) : Colors.brown.withValues(alpha: 0.2)),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: rankNumber == 1 ? Colors.amber : (rankNumber == 2 ? Colors.blueGrey : Colors.brown),
                    ),
                  ),
                  child: Text(
                    rankNumber == 1 ? '🥇 លេខ ១' : (rankNumber == 2 ? '🥈 លេខ ២' : '🥉 លេខ ៣'),
                    style: GoogleFonts.kantumruyPro(
                      color: rankNumber == 1 ? Colors.amberAccent : (rankNumber == 2 ? Colors.cyanAccent : Colors.orangeAccent),
                      fontSize: 11.5,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                )
              else if (isWinner) ...[
                const Icon(Icons.emoji_events_rounded, color: Colors.amberAccent, size: 24),
                const SizedBox(width: 8),
              ],
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
          const SizedBox(height: 10),
          ClipRRect(
            borderRadius: BorderRadius.circular(6),
            child: LinearProgressIndicator(
              value: pct,
              minHeight: 8,
              backgroundColor: Colors.white10,
              color: isWinner ? Colors.amberAccent : AppTheme.primary,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoChip(String label, String value) {
    if (value.trim().isEmpty) return const SizedBox.shrink();
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

  String _formatQuarter(String raw) {
    if (raw == 'Q1') return 'ត្រីមាសទី ១';
    if (raw == 'Q2') return 'ត្រីមាសទី ២';
    if (raw == 'Q3') return 'ត្រីមាសទី ៣';
    if (raw == 'Q4') return 'ត្រីមាសទី ៤';
    return raw;
  }
}
