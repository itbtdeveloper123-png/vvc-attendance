import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import '../services/api_service.dart';
import '../utils/app_theme.dart';
import '../widgets/app_widgets.dart';
import 'trip_tracking_screen.dart';

class TripReportScreen extends StatefulWidget {
  const TripReportScreen({super.key});

  @override
  State<TripReportScreen> createState() => _TripReportScreenState();
}

class _TripReportScreenState extends State<TripReportScreen>
    with SingleTickerProviderStateMixin {
  final ApiService _api = ApiService();
  List<dynamic> _allTrips = [];
  bool _isLoading = true;
  late TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadTrips();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadTrips() async {
    if (!mounted) return;
    setState(() => _isLoading = true);
    try {
      final res = await _api.fetchAllTrips();
      if (res['success'] == true) {
        setState(() {
          _allTrips = res['data'] ?? [];
          _isLoading = false;
        });
      } else {
        setState(() {
          _isLoading = false;
        });
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('បរាជ័យ: ${res['message'] ?? "មិនត្រឹមត្រូវ"}'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    } catch (e) {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  List<dynamic> _getFilteredTrips(String role) {
    if (role == 'Skills') {
      return _allTrips.where((t) {
        final r = t['system_role']?.toString().toLowerCase().trim() ?? '';
        return r != 'worker';
      }).toList();
    } else {
      return _allTrips.where((t) {
        final r = t['system_role']?.toString().toLowerCase().trim() ?? '';
        return r == 'worker';
      }).toList();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        title: Text(
          "របាយការណ៍ការធ្វើដំណើរ",
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        centerTitle: true,
        backgroundColor: Colors.transparent,
        elevation: 0,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _loadTrips,
          ),
        ],
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppTheme.primary,
          labelStyle: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
          tabs: const [
            Tab(text: "ជំនាញ (Skills)"),
            Tab(text: "កម្មករ (Workers)"),
          ],
        ),
      ),
      body: AppBackgroundShell(
        child: _isLoading
            ? const Center(child: CircularProgressIndicator())
            : TabBarView(
                controller: _tabController,
                children: [
                  _buildTripList(_getFilteredTrips('Skills')),
                  _buildTripList(_getFilteredTrips('Workers')),
                ],
              ),
      ),
    );
  }

  Widget _buildTripList(List<dynamic> trips) {
    if (trips.isEmpty) {
      return const Center(
        child: Text(
          "មិនទាន់មានទិន្នន័យ",
          style: TextStyle(color: Colors.white54),
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: trips.length,
      itemBuilder: (context, index) {
        final trip = trips[index];
        final name =
            trip['user_name'] ??
            trip['employee_name'] ??
            trip['employee_id'] ??
            'N/A';
        final eid = trip['employee_id'] ?? '';
        final customer = trip['customer_name'] ?? 'N/A';
        final status = trip['status'] ?? 'unknown';
        final duration = trip['duration_minutes'] ?? 0;
        final double dist =
            double.tryParse(
              (trip['distance_km'] ?? trip['total_distance_km'] ?? '0')
                  .toString(),
            ) ??
            0.0;
        final started = trip['started_at'] ?? '';
        final finished = trip['finished_at'] ?? trip['ended_at'] ?? '';

        final isActive = status == 'active';

        return FadeInUp(
          duration: Duration(milliseconds: 300 + (index * 20)),
          child: Container(
            margin: const EdgeInsets.only(bottom: 12),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.bgCard,
              borderRadius: BorderRadius.circular(24),
              border: Border.all(
                color: isActive
                    ? AppTheme.primary.withValues(alpha: 0.3)
                    : AppTheme.textPrimary.withValues(alpha: 0.05),
              ),
              boxShadow: isActive
                  ? [
                      BoxShadow(
                        color: AppTheme.primary.withValues(alpha: 0.1),
                        blurRadius: 10,
                        offset: const Offset(0, 4),
                      ),
                    ]
                  : null,
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Stack(
                      children: [
                        Container(
                          width: 48,
                          height: 48,
                          decoration: BoxDecoration(
                            color:
                                (isActive
                                        ? AppTheme.primary
                                        : AppTheme.textSecondary)
                                    .withValues(alpha: 0.1),
                            shape: BoxShape.circle,
                          ),
                          child: Icon(
                            isActive
                                ? Icons.directions_car_rounded
                                : Icons.person_rounded,
                            color: isActive
                                ? AppTheme.primary
                                : AppTheme.textSecondary,
                            size: 24,
                          ),
                        ),
                        if (isActive)
                          Positioned(
                            top: 0,
                            right: 0,
                            child: Pulse(
                              infinite: true,
                              child: Container(
                                width: 12,
                                height: 12,
                                decoration: const BoxDecoration(
                                  color: Colors.greenAccent,
                                  shape: BoxShape.circle,
                                ),
                              ),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Text(
                                name,
                                style: GoogleFonts.kantumruyPro(
                                  color: Colors.white,
                                  fontWeight: FontWeight.bold,
                                  fontSize: 15,
                                ),
                              ),
                              const SizedBox(width: 8),
                              Text(
                                "($eid)",
                                style: GoogleFonts.inter(
                                  color: Colors.white54,
                                  fontSize: 11,
                                ),
                              ),
                            ],
                          ),
                          Text(
                            customer,
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.white70,
                              fontSize: 13,
                            ),
                          ),
                        ],
                      ),
                    ),
                    if (isActive)
                      ElevatedButton(
                        onPressed: () {
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (context) => TripTrackingScreen(
                                tripId: int.parse(trip['id'].toString()),
                              ),
                            ),
                          );
                        },
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppTheme.primary,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.symmetric(
                            horizontal: 12,
                            vertical: 8,
                          ),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12),
                          ),
                          elevation: 0,
                        ),
                        child: Text(
                          "តាមដាន",
                          style: GoogleFonts.kantumruyPro(
                            fontSize: 12,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                  ],
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: AppTheme.bgDark.withValues(alpha: 0.3),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Row(
                    children: [
                      Expanded(child: _buildInfoItem("ចាប់ផ្ដម", started)),
                      Container(width: 1, height: 24, color: Colors.white10),
                      Expanded(
                        child: _buildInfoItem(
                          "បញ្ចប់",
                          finished.isEmpty ? "កុំពង់ធ្វើដំណើរ" : finished,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    _buildMetric(
                      Icons.straighten_rounded,
                      "ចំងាយ",
                      "${dist.toStringAsFixed(1)} KM",
                    ),
                    _buildMetric(
                      Icons.timer_outlined,
                      "រយៈពេល",
                      "$duration នាទី",
                    ),
                    _buildStatusBadge(status),
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildInfoItem(String label, String val) {
    return Column(
      children: [
        Text(
          label,
          style: GoogleFonts.kantumruyPro(color: Colors.white54, fontSize: 10),
        ),
        const SizedBox(height: 2),
        Text(
          val,
          style: GoogleFonts.inter(
            color: Colors.white,
            fontSize: 11,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }

  Widget _buildMetric(IconData icon, String label, String val) {
    return Row(
      children: [
        Icon(icon, size: 14, color: AppTheme.primary.withValues(alpha: 0.6)),
        const SizedBox(width: 4),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: GoogleFonts.kantumruyPro(
                color: Colors.white38,
                fontSize: 9,
              ),
            ),
            Text(
              val,
              style: GoogleFonts.inter(
                color: Colors.white70,
                fontSize: 11,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildStatusBadge(String status) {
    final bool isActive = status == 'active';
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: (isActive ? Colors.greenAccent : Colors.white12).withValues(
          alpha: 0.1,
        ),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(
        isActive ? "កំពុងដំណើរការ" : "បានបញ្ចប់",
        style: GoogleFonts.kantumruyPro(
          color: isActive ? Colors.greenAccent : Colors.white38,
          fontSize: 10,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}
