import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import 'package:intl/intl.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import 'package:url_launcher/url_launcher.dart';

class AttendanceReportScreen extends StatefulWidget {
  const AttendanceReportScreen({super.key});

  @override
  State<AttendanceReportScreen> createState() => _AttendanceReportScreenState();
}

class _AttendanceReportScreenState extends State<AttendanceReportScreen> {
  final ApiService _api = ApiService();
  List<dynamic> _allLogs = [];
  bool _isLoading = true;
  DateTime _selectedDate = DateTime.now();

  @override
  void initState() {
    super.initState();
    _loadLogs();
  }

  Future<void> _loadLogs() async {
    setState(() => _isLoading = true);
    try {
      final res = await _api.fetchAllAttendanceLogs();
      if (res['success'] == true) {
        setState(() {
          _allLogs = res['data'] ?? [];
          _isLoading = false;
        });
      } else {
        setState(() => _isLoading = false);
        _showError(res['message'] ?? 'Error fetching logs');
      }
    } catch (e) {
      setState(() => _isLoading = false);
      _showError('Connection error: $e');
    }
  }

  void _showError(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(msg), backgroundColor: Colors.redAccent),
    );
  }

  List<dynamic> _getFilteredLogs(String role) {
    final dateStr = DateFormat('dd/MM/yyyy').format(_selectedDate);
    var filtered = _allLogs.where((log) {
      final logDate = log['log_datetime']?.toString().split(' ')[0] ?? '';
      final logRole = (log['system_role']?.toString() ?? '').toLowerCase();
      
      bool matchesDate = logDate == dateStr;
      bool matchesRole = false;
      
      // Filter ONLY Outside Scans (qr_location_id == 0 or null)
      bool isOutside = log['qr_location_id'] == null || log['qr_location_id'] == 0 || log['qr_location_id'] == '0';
      if (!isOutside) return false;
      
      if (role == 'Skills') {
        // If join failed (logRole empty), we still show it in Skills as a fallback for now
        matchesRole = logRole.isEmpty || logRole == 'skills' || logRole == 'it' || logRole == 'admin' || logRole == 'hrm' || logRole == 'accounting' || logRole == 'employee' || logRole.contains('admin');
      } else {
        matchesRole = logRole == 'worker' || logRole.contains('worker') || logRole.contains('កិច្ចសន្យា');
      }
      
      return matchesDate && matchesRole;
    }).toList();

    debugPrint('Filtered ${filtered.length} logs for $dateStr ($role)');

    // Sort by name or ID
    filtered.sort((a, b) {
      final nameA = (a['user_name'] ?? a['employee_id'] ?? '').toString().toLowerCase();
      final nameB = (b['user_name'] ?? b['employee_id'] ?? '').toString().toLowerCase();
      return nameA.compareTo(nameB);
    });

    return filtered;
  }

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 2,
      child: Scaffold(
        backgroundColor: AppTheme.bgDark,
        appBar: AppBar(
          title: Text(
            "របាយការណ៍វត្តមាន",
            style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
          ),
          centerTitle: true,
          backgroundColor: Colors.transparent,
          elevation: 0,
          leading: IconButton(
            icon: const Icon(Icons.arrow_back_ios_new_rounded),
            onPressed: () => Navigator.pop(context),
          ),
          actions: [
            IconButton(
              icon: const Icon(Icons.refresh_rounded),
              onPressed: _loadLogs,
            ),
          ],
          bottom: TabBar(
            indicatorColor: AppTheme.primary,
            indicatorWeight: 3,
            labelColor: AppTheme.primary,
            unselectedLabelColor: AppTheme.textPrimary.withValues(alpha: 0.4),
            labelStyle: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold, fontSize: 16),
            tabs: const [
              Tab(text: "ជំនាញ (Skills)"),
              Tab(text: "កម្មករ (Worker)"),
            ],
          ),
        ),
        body: AppBackgroundShell(
          child: Column(
            children: [
              _buildFilterBar(),
              Expanded(
                child: TabBarView(
                  children: [
                    _buildLogList('Skills'),
                    _buildLogList('Worker'),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildFilterBar() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      margin: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppTheme.bgCard.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.05)),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              Icon(Icons.calendar_today_rounded, size: 20, color: AppTheme.primary),
              const SizedBox(width: 12),
              Text(
                DateFormat('dd / MM / yyyy').format(_selectedDate),
                style: GoogleFonts.inter(
                  color: AppTheme.textPrimary,
                  fontWeight: FontWeight.bold,
                  fontSize: 16,
                ),
              ),
            ],
          ),
          Material(
            color: Colors.transparent,
            child: InkWell(
              onTap: () async {
                final picked = await showDatePicker(
                  context: context,
                  initialDate: _selectedDate,
                  firstDate: DateTime(2023),
                  lastDate: DateTime(2030),
                  builder: (context, child) {
                    return Theme(
                      data: Theme.of(context).copyWith(
                        colorScheme: ColorScheme.dark(
                          primary: AppTheme.primary,
                          onPrimary: Colors.white,
                          surface: AppTheme.bgCard,
                          onSurface: Colors.white,
                        ),
                      ),
                      child: child!,
                    );
                  },
                );
                if (picked != null) {
                  setState(() => _selectedDate = picked);
                }
              },
              borderRadius: BorderRadius.circular(10),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                decoration: BoxDecoration(
                  border: Border.all(color: AppTheme.primary.withValues(alpha: 0.5)),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  "ប្តូរថ្ងៃ",
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.primary,
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLogList(String type) {
    if (_isLoading) {
      return _buildShimmerList();
    }
    
    final logs = _getFilteredLogs(type);
    
    if (logs.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.history_rounded, size: 64, color: AppTheme.textPrimary.withValues(alpha: 0.1)),
            const SizedBox(height: 16),
            Text(
              "មិនទាន់មានទិន្នន័យសម្រាប់ថ្ងៃនេះ",
              style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary.withValues(alpha: 0.3)),
            ),
          ],
        ),
      );
    }

    return AnimationLimiter(
      child: ListView.builder(
        padding: const EdgeInsets.symmetric(horizontal: 16),
        itemCount: logs.length,
        itemBuilder: (context, index) => AnimationConfiguration.staggeredList(
          position: index,
          duration: const Duration(milliseconds: 500),
          child: SlideAnimation(
            verticalOffset: 50.0,
            child: FadeInAnimation(
              child: _buildLogCard(logs[index], index),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildShimmerList() {
    return ListView.builder(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      itemCount: 8,
      itemBuilder: (context, index) => Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: AppShimmer(
          child: Container(
            height: 100,
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(24),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildLogCard(Map<String, dynamic> log, int index) {
    final name = log['user_name'] ?? 'N/A';
    final dept = log['user_dept'] ?? '';
    final dtStr = log['log_datetime'] ?? '';
    final status = log['status']?.toString() ?? 'Good';
    final location = log['location_name']?.toString() ?? 'N/A';
    final action = log['action_type']?.toString() ?? 'Check-In';

    // dtStr is in format '%d/%m/%Y %h:%i %p' e.g. "08/04/2026 09:30 AM"
    // So we can extract the time directly from the string by splitting it!
    String timeTxt = '';
    if (dtStr.length >= 16) {
      final parts = dtStr.split(' ');
      if (parts.length >= 3) {
        timeTxt = '${parts[1]} ${parts[2]}'; // gets "09:30 AM"
      } else {
        timeTxt = dtStr;
      }
    } else {
       timeTxt = dtStr;
    }

    final isLate = status.toLowerCase() == 'late' || status.contains('យឺត');
    final isOut = action.toLowerCase().contains('out');

    return FadeInUp(
      duration: const Duration(milliseconds: 300),
      delay: Duration(milliseconds: index * 30),
      child: Container(
        margin: const EdgeInsets.only(bottom: 12),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(24),
          border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.05)),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.1),
              blurRadius: 10,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Column(
          children: [
            Row(
              children: [
                Container(
                  width: 50,
                  height: 50,
                  decoration: BoxDecoration(
                    color: (isOut ? Colors.orange : AppTheme.primary).withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(15),
                  ),
                  child: Icon(
                    isOut ? Icons.logout_rounded : Icons.login_rounded,
                    color: isOut ? Colors.orange : AppTheme.primary,
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        (name == 'N/A' || name.isEmpty) ? (log['employee_id'] ?? 'N/A') : name,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontWeight: FontWeight.bold,
                          fontSize: 15,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Row(
                        children: [
                          Icon(Icons.business_center_rounded, size: 12, color: AppTheme.textPrimary.withValues(alpha: 0.4)),
                          const SizedBox(width: 4),
                          Text(
                            dept,
                            style: GoogleFonts.kantumruyPro(
                              color: AppTheme.textPrimary.withValues(alpha: 0.5),
                              fontSize: 11,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Text(
                      timeTxt,
                      style: GoogleFonts.inter(
                        color: AppTheme.primaryLight,
                        fontWeight: FontWeight.bold,
                        fontSize: 14,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(
                        color: (isLate ? Colors.red : Colors.green).withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        isLate ? "យឺតយ៉ាវ (Late)" : "ទាន់ពេល (Good)",
                        style: GoogleFonts.kantumruyPro(
                          color: isLate ? Colors.redAccent : Colors.greenAccent,
                          fontSize: 10,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
            const SizedBox(height: 12),
            const Divider(color: Colors.white10, height: 1),
            const SizedBox(height: 10),
            Row(
              children: [
                Icon(Icons.location_on_rounded, size: 14, color: AppTheme.primary.withValues(alpha: 0.7)),
                const SizedBox(width: 6),
                Expanded(
                  child: Text(
                    "ទីតាំង៖ $location",
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary.withValues(alpha: 0.6),
                      fontSize: 12,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                if (log['latitude'] != null && log['longitude'] != null)
                  GestureDetector(
                    onTap: () async {
                      final lat = log['latitude'];
                      final lon = log['longitude'];
                      final url = 'https://www.google.com/maps/search/?api=1&query=$lat,$lon';
                      if (await canLaunchUrl(Uri.parse(url))) {
                        await launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication);
                      }
                    },
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: AppTheme.primary.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: AppTheme.primary.withValues(alpha: 0.3)),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.map_rounded, size: 14, color: AppTheme.primary),
                          const SizedBox(width: 4),
                          Text(
                            "ទីតាំង",
                            style: GoogleFonts.kantumruyPro(color: AppTheme.primary, fontSize: 10, fontWeight: FontWeight.bold),
                          ),
                        ],
                      ),
                    ),
                  ),
                const SizedBox(width: 8),
                if (log['photo_path'] != null && log['photo_path'].toString().isNotEmpty)
                  GestureDetector(
                    onTap: () {
                       showDialog(
                         context: context,
                         builder: (context) => Dialog(
                           backgroundColor: Colors.transparent,
                           insetPadding: const EdgeInsets.all(10),
                           child: Container(
                             width: double.infinity,
                             decoration: BoxDecoration(
                                color: AppTheme.bgDark,
                                borderRadius: BorderRadius.circular(24),
                                border: Border.all(color: AppTheme.primary.withValues(alpha: 0.3)),
                             ),
                             child: Column(
                               mainAxisSize: MainAxisSize.min,
                               children: [
                                Stack(
                                  children: [
                                    ClipRRect(
                                      borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
                                      child: Image.network(
                                        ApiService.getFullImageUrl(log['photo_path']),
                                        fit: BoxFit.contain,
                                        width: double.infinity,
                                        errorBuilder: (c,e,s) => Container(color: Colors.white10, height: 200, child: const Center(child: Icon(Icons.broken_image, color: Colors.white54, size: 40))),
                                      ),
                                    ),
                                    // Watermark Overlay
                                    Positioned(
                                      bottom: 10,
                                      left: 10,
                                      right: 10,
                                      child: Container(
                                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                                        decoration: BoxDecoration(
                                          color: Colors.black54,
                                          borderRadius: BorderRadius.circular(10),
                                        ),
                                        child: Column(
                                          crossAxisAlignment: CrossAxisAlignment.start,
                                          mainAxisSize: MainAxisSize.min,
                                          children: [
                                            Row(
                                              children: [
                                                const Icon(Icons.location_on, color: Colors.redAccent, size: 14),
                                                const SizedBox(width: 4),
                                                Expanded(
                                                  child: Text(
                                                    location,
                                                    style: GoogleFonts.kantumruyPro(color: Colors.white, fontSize: 11, fontWeight: FontWeight.w600),
                                                    maxLines: 1,
                                                    overflow: TextOverflow.ellipsis,
                                                  ),
                                                ),
                                              ],
                                            ),
                                            const SizedBox(height: 2),
                                            Row(
                                              children: [
                                                const Icon(Icons.access_time_filled, color: Colors.cyanAccent, size: 14),
                                                const SizedBox(width: 4),
                                                Text(
                                                  timeTxt,
                                                  style: GoogleFonts.inter(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold),
                                                ),
                                              ],
                                            ),
                                          ],
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                               const SizedBox(height: 16),
                               Padding(
                                 padding: const EdgeInsets.symmetric(horizontal: 16),
                                 child: Text(name, style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
                               ),
                               const SizedBox(height: 16),
                               Padding(
                                 padding: const EdgeInsets.only(bottom: 16),
                                 child: ElevatedButton(
                                   style: ElevatedButton.styleFrom(
                                     backgroundColor: AppTheme.primary,
                                     shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))
                                   ),
                                   onPressed: () => Navigator.pop(context), 
                                   child: Text("បិទ", style: GoogleFonts.kantumruyPro(color: Colors.white))
                                 ),
                               )
                             ]
                           ) // End Column
                           ) // End Container
                         ) // End Dialog
                       ); // End showDialog
                    },
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: Colors.cyanAccent.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.cyanAccent.withValues(alpha: 0.3)),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(Icons.image_rounded, size: 14, color: Colors.cyanAccent),
                          const SizedBox(width: 4),
                          Text(
                            "រូបភាព",
                            style: GoogleFonts.kantumruyPro(color: Colors.cyanAccent, fontSize: 10, fontWeight: FontWeight.bold),
                          ),
                        ],
                      ),
                    ),
                  )
              ],
            ),
          ],
        ),
      ),
    );
  }
}
