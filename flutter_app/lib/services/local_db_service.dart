import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart';

class LocalDbService {
  static final LocalDbService _instance = LocalDbService._internal();
  factory LocalDbService() => _instance;
  LocalDbService._internal();

  Database? _database;

  Future<Database> get database async {
    if (_database != null) return _database!;
    _database = await _initDb();
    return _database!;
  }

  Future<Database> _initDb() async {
    String path = join(await getDatabasesPath(), 'attendance_offline.db');
    return await openDatabase(
      path,
      version: 2,
      onCreate: _onCreate,
      onUpgrade: _onUpgrade,
    );
  }

  Future<void> _onCreate(Database db, int version) async {
    await db.execute('''
      CREATE TABLE offline_punches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        employee_id TEXT,
        workplace TEXT,
        branch TEXT,
        location_raw TEXT,
        qr_secret TEXT,
        qr_location_id INTEGER,
        late_reason TEXT,
        manual_distance REAL,
        manual_location_name TEXT,
        timestamp TEXT,
        synced INTEGER DEFAULT 0
      )
    ''');
    await db.execute('''
      CREATE TABLE offline_trip_points (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trip_id INTEGER NOT NULL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        speed REAL DEFAULT 0,
        accuracy REAL DEFAULT 0,
        timestamp TEXT NOT NULL,
        synced INTEGER DEFAULT 0
      )
    ''');
  }

  Future<void> _onUpgrade(Database db, int oldVersion, int newVersion) async {
    if (oldVersion < 2) {
      await db.execute('''
        CREATE TABLE IF NOT EXISTS offline_trip_points (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          trip_id INTEGER NOT NULL,
          latitude REAL NOT NULL,
          longitude REAL NOT NULL,
          speed REAL DEFAULT 0,
          accuracy REAL DEFAULT 0,
          timestamp TEXT NOT NULL,
          synced INTEGER DEFAULT 0
        )
      ''');
    }
  }

  // ─── Offline Punches ────────────────────────────────────────────────────────

  Future<int> insertPunch(Map<String, dynamic> punchData) async {
    Database db = await database;
    return await db.insert('offline_punches', punchData);
  }

  Future<List<Map<String, dynamic>>> getUnsyncedPunches() async {
    Database db = await database;
    return await db.query('offline_punches', where: 'synced = 0');
  }

  Future<int> markAsSynced(int id) async {
    Database db = await database;
    return await db.update('offline_punches', {'synced': 1}, where: 'id = ?', whereArgs: [id]);
  }

  Future<int> clearSyncedPunches() async {
    Database db = await database;
    return await db.delete('offline_punches', where: 'synced = 1');
  }

  // ─── Offline Trip GPS Points ────────────────────────────────────────────────

  Future<int> insertTripPoint({
    required int tripId,
    required double latitude,
    required double longitude,
    double speed = 0,
    double accuracy = 0,
  }) async {
    final db = await database;
    return await db.insert('offline_trip_points', {
      'trip_id': tripId,
      'latitude': latitude,
      'longitude': longitude,
      'speed': speed,
      'accuracy': accuracy,
      'timestamp': DateTime.now().toIso8601String(),
      'synced': 0,
    });
  }

  Future<List<Map<String, dynamic>>> getUnsyncedTripPoints() async {
    final db = await database;
    return await db.query(
      'offline_trip_points',
      where: 'synced = 0',
      orderBy: 'id ASC',
    );
  }

  Future<int> markTripPointSynced(int id) async {
    final db = await database;
    return await db.update(
      'offline_trip_points',
      {'synced': 1},
      where: 'id = ?',
      whereArgs: [id],
    );
  }

  Future<int> clearSyncedTripPoints() async {
    final db = await database;
    return await db.delete('offline_trip_points', where: 'synced = 1');
  }
}
