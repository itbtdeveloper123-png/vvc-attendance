import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter/foundation.dart';
import 'local_db_service.dart';
import 'api_service.dart';

class OfflineSyncService {
  final LocalDbService _localDb = LocalDbService();
  final ApiService _apiService = ApiService();

  void startListening() {
    Connectivity().onConnectivityChanged.listen((List<ConnectivityResult> results) {
      if (results.contains(ConnectivityResult.mobile) || results.contains(ConnectivityResult.wifi)) {
        debugPrint('Internet restored. Attempting to sync offline punches...');
        syncOfflinePunches();
      }
    });
  }

  Future<void> syncOfflinePunches() async {
    final unsyncedPunches = await _localDb.getUnsyncedPunches();
    if (unsyncedPunches.isEmpty) return;

    for (var punch in unsyncedPunches) {
      try {
        final res = await _apiService.submitAttendance(
          action: punch['action'],
          employeeId: punch['employee_id'],
          workplace: punch['workplace'] ?? '',
          branch: punch['branch'] ?? '',
          locationRaw: punch['location_raw'] ?? '',
          qrSecret: punch['qr_secret'] ?? '',
          qrLocationId: punch['qr_location_id'] ?? 0,
          lateReason: punch['late_reason'],
          manualDistance: punch['manual_distance'],
          manualLocationName: punch['manual_location_name'],
        );

        if (res['success'] == true || (res['status'] != null && res['status'] == 'success')) {
          await _localDb.markAsSynced(punch['id']);
          debugPrint('Successfully synced offline punch ID: ${punch['id']}');
        } else {
          debugPrint('Failed to sync punch ID: ${punch['id']}, Reason: ${res['message']}');
        }
      } catch (e) {
        debugPrint('Error syncing punch ID: ${punch['id']}, Error: $e');
      }
    }
    
    // Cleanup old synced punches
    await _localDb.clearSyncedPunches();
  }
}
