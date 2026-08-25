import 'dart:async';

import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter/foundation.dart';

import 'api_service.dart';
import 'local_db_service.dart';

class OfflineSyncService {
  static final OfflineSyncService _instance = OfflineSyncService._internal();

  factory OfflineSyncService() => _instance;

  OfflineSyncService._internal();

  final LocalDbService _localDb = LocalDbService();
  final ApiService _apiService = ApiService();

  StreamSubscription<List<ConnectivityResult>>? _connectivitySub;
  bool _isSyncing = false;

  void startListening() {
    if (kIsWeb || _connectivitySub != null) return;

    final connectivity = Connectivity();
    _connectivitySub = connectivity.onConnectivityChanged.listen((
      List<ConnectivityResult> results,
    ) {
      if (_hasInternet(results)) {
        debugPrint('Internet restored. Attempting to sync offline data...');
        unawaited(syncOfflineData());
      }
    });

    unawaited(_syncIfOnline(connectivity));
  }

  static bool _hasInternet(List<ConnectivityResult> results) {
    return results.any((result) => result != ConnectivityResult.none);
  }

  Future<void> _syncIfOnline(Connectivity connectivity) async {
    final results = await connectivity.checkConnectivity();
    if (_hasInternet(results)) {
      await syncOfflineData();
    }
  }

  Future<void> syncOfflineData() async {
    if (kIsWeb || _isSyncing) return;
    _isSyncing = true;
    try {
      await syncOfflinePunches();
      await syncOfflineTripPoints();
    } finally {
      _isSyncing = false;
    }
  }

  Future<void> syncOfflinePunches() async {
    await _apiService.syncOfflineAttendance();
    await _localDb.clearSyncedPunches();
  }

  Future<void> syncOfflineTripPoints() async {
    if (kIsWeb) return;

    final unsyncedPoints = await _localDb.getUnsyncedTripPoints();
    if (unsyncedPoints.isEmpty) return;

    debugPrint('Syncing ${unsyncedPoints.length} offline GPS trip points...');

    try {
      final List<Map<String, dynamic>> pointsPayload = unsyncedPoints.map((p) => {
        'trip_id': p['trip_id'],
        'latitude': (p['latitude'] as num).toDouble(),
        'longitude': (p['longitude'] as num).toDouble(),
        'speed': (p['speed'] as num?)?.toDouble() ?? 0,
        'accuracy': (p['accuracy'] as num?)?.toDouble() ?? 0,
        'recorded_at': p['recorded_at'] ?? DateTime.now().toIso8601String(),
      }).toList();

      final res = await _apiService.batchUpdateTripLocations(pointsPayload);
      if (res['success'] == true) {
        for (final point in unsyncedPoints) {
          await _localDb.markTripPointSynced(point['id'] as int);
        }
        debugPrint('Successfully batch-synced ${unsyncedPoints.length} GPS trip points');
      } else {
        // Fallback to sequential sync
        for (final point in unsyncedPoints) {
          final singleRes = await _apiService.updateTripLocation(
            tripId: point['trip_id'] as int,
            latitude: (point['latitude'] as num).toDouble(),
            longitude: (point['longitude'] as num).toDouble(),
            speed: (point['speed'] as num?)?.toDouble() ?? 0,
            accuracy: (point['accuracy'] as num?)?.toDouble() ?? 0,
          );
          if (singleRes['success'] == true) {
            await _localDb.markTripPointSynced(point['id'] as int);
          } else {
            break;
          }
        }
      }
    } catch (e) {
      debugPrint('Error syncing GPS trip points batch: $e');
    }

    await _localDb.clearSyncedTripPoints();
  }
}
