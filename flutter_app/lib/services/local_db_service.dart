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
      version: 1,
      onCreate: _onCreate,
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
  }

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
}
