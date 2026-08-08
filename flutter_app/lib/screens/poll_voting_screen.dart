import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';

class PollVotingScreen extends StatefulWidget {
  const PollVotingScreen({super.key});

  @override
  State<PollVotingScreen> createState() => _PollVotingScreenState();
}

class _PollVotingScreenState extends State<PollVotingScreen> {
  final ApiService _api = ApiService();
  List<dynamic> _polls = [];
  bool _isLoading = true;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _loadActivePolls();
  }

  Future<void> _loadActivePolls() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final response = await _api.fetchActivePolls();
      if (response['success'] == true && response['data'] != null) {
        setState(() {
          _polls = response['data'] as List<dynamic>;
          _isLoading = false;
        });
      } else {
        setState(() {
          _errorMessage = response['message']?.toString() ?? 'មិនអាចទាញយកការបោះឆ្នោតបានទេ';
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

  Future<void> _castVote(int pollId, String candidateEmployeeId) async {
    // Show confirmation dialog
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('បោះឆ្នោត'),
        content: const Text('តើអ្នកប្រាកដជាចង់បោះឆ្នោតសម្រាប់បេក្ខជននេះមែនទេ?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('បោះបង់'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.primary,
            ),
            child: const Text('បោះឆ្នោត'),
          ),
        ],
      ),
    );

    if (confirmed != true) return;

    // Show loading indicator
    if (!mounted) return;
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => const Center(
        child: CircularProgressIndicator(),
      ),
    );

    try {
      final response = await _api.castVote(pollId, candidateEmployeeId);

      // Hide loading indicator
      if (!mounted) return;
      Navigator.pop(context);

      if (response['success'] == true) {
        // Show success message
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(response['message']?.toString() ?? 'បោះឆ្នោតបានជោគជ័យ!'),
            backgroundColor: Colors.green,
          ),
        );
        // Reload polls
        _loadActivePolls();
      } else {
        // Show error message
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(response['message']?.toString() ?? 'មិនអាចបោះឆ្នោតបានទេ'),
            backgroundColor: Colors.red,
          ),
        );
      }
    } catch (e) {
      // Hide loading indicator
      if (!mounted) return;
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('កំហុសបច្ចេកទេស: $e'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: VvcAppBar(
        backgroundColor: AppTheme.bgDark,
        elevation: 0,
        title: Text(
          'បោះឆ្នោតបុគ្គលិក',
          style: GoogleFonts.kantumruyPro(
            fontWeight: FontWeight.bold,
            color: AppTheme.textPrimary,
          ),
        ),
        iconTheme: IconThemeData(color: AppTheme.textPrimary),
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return const Center(
        child: CircularProgressIndicator(),
      );
    }

    if (_errorMessage != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.error_outline,
              size: 64,
              color: AppTheme.helperTextColor,
            ),
            const SizedBox(height: 16),
            Text(
              _errorMessage!,
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.helperTextColor,
                fontSize: 16,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _loadActivePolls,
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.primary,
              ),
              child: const Text('ព្យាយាមម្តងទៀត'),
            ),
          ],
        ),
      );
    }

    if (_polls.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.how_to_vote_outlined,
              size: 64,
              color: AppTheme.helperTextColor,
            ),
            const SizedBox(height: 16),
            Text(
              'មិនមានការបោះឆ្នោតសកម្មនៅពេលនេះទេ',
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.helperTextColor,
                fontSize: 16,
              ),
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _loadActivePolls,
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
    
    // State for checkbox selection
    String? selectedCandidateEmployeeId;

    return StatefulBuilder(
      builder: (context, setState) {
        return Container(
          margin: const EdgeInsets.only(bottom: 16),
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: hasVoted 
                  ? Colors.green.withValues(alpha: 0.3)
                  : AppTheme.primary.withValues(alpha: 0.2),
            ),
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
                            fontSize: 18,
                            color: AppTheme.textPrimary,
                          ),
                        ),
                        const SizedBox(height: 8),
                        if (poll['quarter'] != null && poll['quarter'].toString().isNotEmpty)
                          _buildInfoChip('ត្រីមាស', poll['quarter'].toString()),
                        if (poll['location'] != null && poll['location'].toString().isNotEmpty)
                          _buildInfoChip('ទីតាំង', poll['location'].toString()),
                      ],
                    ),
                  ),
                  if (hasVoted)
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                      decoration: BoxDecoration(
                        color: Colors.green,
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: Text(
                        'បានបោះឆ្នោត',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 12,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    )
                  else
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                      decoration: BoxDecoration(
                        color: AppTheme.primary,
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: Text(
                        'សកម្ម',
                        style: GoogleFonts.kantumruyPro(
                          color: Colors.white,
                          fontSize: 12,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                ],
              ),
              const SizedBox(height: 12),
              Text(
                'កាលបរិច្ឆេទ: ${poll['start_date'] ?? '-'} ដល់ ${poll['end_date'] ?? '-'}',
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.helperTextColor,
                  fontSize: 12,
                ),
              ),
              const SizedBox(height: 16),
              if (candidates.isNotEmpty) ...[
                Text(
                  'ជ្រើសរើសបេក្ខជន:',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontWeight: FontWeight.bold,
                    fontSize: 14,
                  ),
                ),
                const SizedBox(height: 8),
                ...candidates.map((candidate) {
                  final empId = candidate['employee_id']?.toString() ?? '';
                  final name = candidate['name']?.toString() ?? empId;
                  final isSelected = selectedCandidateEmployeeId == empId;
                  
                  return Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    decoration: BoxDecoration(
                      color: isSelected 
                          ? AppTheme.primary.withValues(alpha: 0.1)
                          : AppTheme.bgDark,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: isSelected 
                            ? AppTheme.primary
                            : AppTheme.borderDark,
                      ),
                    ),
                    child: CheckboxListTile(
                      value: isSelected,
                      onChanged: hasVoted ? null : (value) {
                        setState(() {
                          selectedCandidateEmployeeId = value == true ? empId : null;
                        });
                      },
                      title: Text(
                        name,
                        style: GoogleFonts.kantumruyPro(
                          fontWeight: FontWeight.bold,
                          color: AppTheme.textPrimary,
                        ),
                      ),
                      controlAffinity: ListTileControlAffinity.leading,
                      activeColor: AppTheme.primary,
                      checkColor: Colors.white,
                    ),
                  );
                }),
                const SizedBox(height: 12),
                if (!hasVoted && selectedCandidateEmployeeId != null && selectedCandidateEmployeeId!.isNotEmpty)
                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton(
                      onPressed: () => _castVote(poll['id'] as int? ?? 0, selectedCandidateEmployeeId!),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppTheme.primary,
                        padding: const EdgeInsets.symmetric(vertical: 12),
                      ),
                      child: Text(
                        'បោះឆ្នោត',
                        style: GoogleFonts.kantumruyPro(
                          fontWeight: FontWeight.bold,
                          color: Colors.white,
                        ),
                      ),
                    ),
                  )
                else if (hasVoted)
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    decoration: BoxDecoration(
                      color: Colors.green.withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.green),
                    ),
                    child: Center(
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          const Icon(Icons.check_circle, color: Colors.green),
                          const SizedBox(width: 8),
                          Text(
                            'អ្នកបានបោះឆ្នោតរួចហើយ',
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.green,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
              ] else
                Text(
                  'មិនទាន់មានបេក្ខជនទេ',
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.helperTextColor,
                    fontSize: 14,
                  ),
                ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildInfoChip(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(right: 8, bottom: 4),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        decoration: BoxDecoration(
          color: AppTheme.primary.withValues(alpha: 0.1),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Text(
          '$label: $value',
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.primary,
            fontSize: 12,
          ),
        ),
      ),
    );
  }
}
