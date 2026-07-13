import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:flutter_staggered_animations/flutter_staggered_animations.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import 'package:url_launcher/url_launcher.dart';

class OutsideReportScreen extends StatefulWidget {
  const OutsideReportScreen({super.key});

  @override
  State<OutsideReportScreen> createState() => _OutsideReportScreenState();
}

class _OutsideReportScreenState extends State<OutsideReportScreen> {
  final ApiService _api = ApiService();
  List<dynamic> _allLogs = [];
  bool _isLoading = true;
  DateTime _selectedDate = DateTime.now();
  Timer? _pollingTimer;

  @override
  void initState() {
    super.initState();
    _loadLogs();
    _pollingTimer = Timer.periodic(const Duration(seconds: 10), (_) {
      if (mounted) _loadLogsSilently();
    });
  }

  @override
  void dispose() {
    _pollingTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadLogsSilently() async {
    try {
      final res = await _api.fetchAllAttendanceLogs();
      if (res['success'] == true && mounted) {
        setState(() {
          _allLogs = res['data'] ?? [];
        });
      }
    } catch (_) {}
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

  List<dynamic> _getFilteredLogs() {
    final dateStr = DateFormat('dd/MM/yyyy').format(_selectedDate);
    var filtered = _allLogs.where((log) {
      final logDate = log['log_datetime']?.toString().split(' ')[0] ?? '';
      // We are much looser here now to ensure data is seen
      bool matchesDate = logDate == dateStr;

      // Keep photo filter if user specifically wants outside report with photos
      // but let's make it more resilient
      bool hasPhoto =
          log['photo_path'] != null &&
          log['photo_path'].toString().trim().isNotEmpty;

      return matchesDate && hasPhoto;
    }).toList();

    filtered.sort((a, b) {
      final tA = a['log_datetime'] ?? '';
      final tB = b['log_datetime'] ?? '';
      return tB.compareTo(tA); // Newest first
    });

    return filtered;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        title: Text(
          "របាយការណ៍វត្តមានក្រៅ",
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
      ),
      body: AppBackgroundShell(
        child: Column(
          children: [
            _buildFilterBar(),
            Expanded(child: _buildFeedList()),
          ],
        ),
      ),
    );
  }

  Widget _buildFilterBar() {
    final hPad = AppResponsive.horizontalPadding(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      margin: EdgeInsets.fromLTRB(hPad, 10, hPad, 12),
      decoration: AppTheme.cardDecoration(
        color: AppTheme.bgCard.withValues(alpha: 0.72),
        radius: AppTheme.radiusLg,
        borderColor: AppTheme.cardBorder,
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              Icon(
                Icons.calendar_today_rounded,
                size: 20,
                color: AppTheme.primary,
              ),
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
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 6,
                ),
                decoration: BoxDecoration(
                  border: Border.all(
                    color: AppTheme.primary.withValues(alpha: 0.5),
                  ),
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

  Widget _buildFeedList() {
    if (_isLoading) {
      return Center(child: CircularProgressIndicator(color: AppTheme.primary));
    }

    final logs = _getFilteredLogs();

    if (logs.isEmpty) {
      return AppStateView(
        icon: Icons.photo_library_rounded,
        title: "មិនទាន់មានទិន្នន័យខាងក្រៅ",
        message: "សាកល្បងប្តូរថ្ងៃ ឬ refresh ម្តងទៀត",
        color: AppTheme.primary,
      );
    }

    return AnimationLimiter(
      child: ListView.builder(
        padding: EdgeInsets.fromLTRB(
          AppResponsive.horizontalPadding(context),
          0,
          AppResponsive.horizontalPadding(context),
          AppResponsive.bottomPadding(context),
        ),
        itemCount: logs.length,
        itemBuilder: (context, index) => AnimationConfiguration.staggeredList(
          position: index,
          duration: const Duration(milliseconds: 500),
          child: SlideAnimation(
            verticalOffset: 50.0,
            child: FadeInAnimation(
              child: AppResponsive.maxWidth(
                context: context,
                child: _buildFeedCard(logs[index]),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildFeedCard(Map<String, dynamic> log) {
    final name = log['user_name'] ?? 'N/A';
    final dept = log['user_dept'] ?? '';
    final dtStr = log['log_datetime'] ?? '';
    final location = log['location_name']?.toString() ?? 'Outside';
    final reason = log['late_reason']?.toString() ?? '';
    final action = log['action_type']?.toString() ?? 'Check-In';
    final avatar = log['avatar'];
    final photoPath = log['photo_path'];

    String timeTxt = '';
    if (dtStr.length >= 16) {
      final parts = dtStr.split(' ');
      if (parts.length >= 3) {
        timeTxt = '${parts[1]} ${parts[2]}';
      } else {
        timeTxt = dtStr;
      }
    } else {
      timeTxt = dtStr;
    }

    final isOut = action.toLowerCase().contains('out');
    final color = isOut ? Colors.orangeAccent : Colors.cyanAccent;

    return Container(
      margin: const EdgeInsets.only(bottom: 24),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: AppTheme.textPrimary.withValues(alpha: 0.05)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.2),
            blurRadius: 15,
            offset: const Offset(0, 5),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header (Profile & Time)
          Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                CircleAvatar(
                  radius: 24,
                  backgroundColor: AppTheme.primary.withValues(alpha: 0.2),
                  backgroundImage:
                      (avatar != null && avatar.toString().isNotEmpty)
                      ? NetworkImage(ApiService.getFullImageUrl(avatar))
                      : null,
                  child: (avatar == null || avatar.toString().isEmpty)
                      ? Icon(Icons.person, color: AppTheme.primary)
                      : null,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        (name == 'N/A' || name.isEmpty)
                            ? (log['employee_id'] ?? 'N/A')
                            : name,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        dept,
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary.withValues(alpha: 0.5),
                          fontSize: 12,
                        ),
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
                        color: AppTheme.textPrimary.withValues(alpha: 0.7),
                        fontWeight: FontWeight.w600,
                        fontSize: 13,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 8,
                        vertical: 3,
                      ),
                      decoration: BoxDecoration(
                        color: color.withValues(alpha: 0.15),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Text(
                        action,
                        style: GoogleFonts.inter(
                          color: color,
                          fontSize: 10,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),

          // Reason text if any
          if (reason.isNotEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
              child: Text(
                reason,
                style: GoogleFonts.kantumruyPro(
                  color: AppTheme.textPrimary.withValues(alpha: 0.85),
                  fontSize: 14,
                  height: 1.4,
                ),
              ),
            ),

          const SizedBox(height: 8),

          // Big Photo Attached
          if (photoPath != null && photoPath.toString().isNotEmpty)
            GestureDetector(
              onTap: () {
                Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => Scaffold(
                      backgroundColor: Colors.black,
                      appBar: AppBar(
                        backgroundColor: Colors.transparent,
                        iconTheme: const IconThemeData(color: Colors.white),
                      ),
                      body: Center(
                        child: Stack(
                          children: [
                            InteractiveViewer(
                              child: Image.network(
                                ApiService.getFullImageUrl(photoPath),
                                fit: BoxFit.contain,
                              ),
                            ),
                            // Watermark in Full Preview
                            Positioned(
                              bottom: 20,
                              left: 20,
                              right: 20,
                              child: Container(
                                padding: const EdgeInsets.all(12),
                                decoration: BoxDecoration(
                                  color: Colors.black54,
                                  borderRadius: BorderRadius.circular(12),
                                ),
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  mainAxisSize: MainAxisSize.min,
                                  children: [
                                    Row(
                                      children: [
                                        const Icon(
                                          Icons.location_on,
                                          color: Colors.redAccent,
                                          size: 16,
                                        ),
                                        const SizedBox(width: 6),
                                        Expanded(
                                          child: Text(
                                            "${log['geo_address'] ?? location} ${log['latitude'] != null ? '\nGPS: ${log['latitude']}, ${log['longitude']}' : ''}",
                                            style: GoogleFonts.kantumruyPro(
                                              color: Colors.white,
                                              fontSize: 13,
                                            ),
                                          ),
                                        ),
                                      ],
                                    ),
                                    const SizedBox(height: 4),
                                    Row(
                                      children: [
                                        const Icon(
                                          Icons.access_time_filled,
                                          color: Colors.cyanAccent,
                                          size: 16,
                                        ),
                                        const SizedBox(width: 6),
                                        Text(
                                          dtStr,
                                          style: GoogleFonts.inter(
                                            color: Colors.white,
                                            fontSize: 13,
                                            fontWeight: FontWeight.bold,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                );
              },
              child: Stack(
                children: [
                  Container(
                    width: double.infinity,
                    height: 250,
                    decoration: BoxDecoration(
                      color: Colors.black.withValues(alpha: 0.3),
                      image: DecorationImage(
                        image: NetworkImage(
                          ApiService.getFullImageUrl(photoPath),
                        ),
                        fit: BoxFit.cover,
                      ),
                    ),
                  ),
                  Positioned(
                    bottom: 0,
                    left: 0,
                    right: 0,
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 8,
                      ),
                      decoration: const BoxDecoration(color: Colors.black54),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Row(
                            children: [
                              const Icon(
                                Icons.location_on,
                                color: Colors.redAccent,
                                size: 14,
                              ),
                              const SizedBox(width: 4),
                              Expanded(
                                child: Text(
                                  "${log['geo_address'] ?? location} ${log['latitude'] != null ? '(${log['latitude']}, ${log['longitude']})' : ''}",
                                  style: GoogleFonts.kantumruyPro(
                                    color: Colors.white,
                                    fontSize: 10,
                                    fontWeight: FontWeight.w600,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 2),
                          Row(
                            children: [
                              const Icon(
                                Icons.access_time_filled,
                                color: Colors.cyanAccent,
                                size: 14,
                              ),
                              const SizedBox(width: 4),
                              Text(
                                timeTxt,
                                style: GoogleFonts.inter(
                                  color: Colors.white,
                                  fontSize: 11,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                  ),
                  Positioned(
                    top: 12,
                    right: 12,
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 6,
                      ),
                      decoration: BoxDecoration(
                        color: Colors.black.withValues(alpha: 0.7),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Row(
                        children: [
                          const Icon(
                            Icons.zoom_out_map_rounded,
                            color: Colors.white,
                            size: 14,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            "ចុចពង្រីក",
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white,
                              fontSize: 10,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),

          // Info Panel (Location)
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.bgDark.withValues(alpha: 0.3),
              borderRadius: const BorderRadius.only(
                bottomLeft: Radius.circular(20),
                bottomRight: Radius.circular(20),
              ),
            ),
            child: Row(
              children: [
                Icon(Icons.location_on_rounded, color: color, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    location,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary.withValues(alpha: 0.7),
                      fontSize: 13,
                    ),
                  ),
                ),
                if (log['latitude'] != null && log['longitude'] != null)
                  IconButton(
                    icon: Icon(Icons.map_rounded, color: color),
                    onPressed: () async {
                      final lat = log['latitude'];
                      final lon = log['longitude'];
                      final url =
                          'https://www.google.com/maps/search/?api=1&query=$lat,$lon';
                      if (await canLaunchUrl(Uri.parse(url))) {
                        await launchUrl(
                          Uri.parse(url),
                          mode: LaunchMode.externalApplication,
                        );
                      }
                    },
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
