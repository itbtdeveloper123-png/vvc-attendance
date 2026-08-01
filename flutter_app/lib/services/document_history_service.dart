import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Document History Service
/// Manages local storage of scanned documents using SQLite
class DocumentHistoryService {
  static final DocumentHistoryService _instance = DocumentHistoryService._internal();
  factory DocumentHistoryService() => _instance;
  DocumentHistoryService._internal();

  static const String _databaseName = 'document_history.db';
  static const int _databaseVersion = 1;

  Database? _database;

  // Table names
  static const String _tableDocuments = 'documents';
  static const String _tablePages = 'pages';

  Future<Database> get _db async {
    if (_database != null) return _database!;
    _database = await _initDatabase();
    return _database!;
  }

  Future<Database> _initDatabase() async {
    final directory = await getApplicationDocumentsDirectory();
    final path = p.join(directory.path, _databaseName);

    return await openDatabase(
      path,
      version: _databaseVersion,
      onCreate: _onCreate,
      onUpgrade: _onUpgrade,
    );
  }

  Future<void> _onCreate(Database db, int version) async {
    // Create documents table
    await db.execute('''
      CREATE TABLE $_tableDocuments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        custom_name TEXT NOT NULL,
        page_count INTEGER NOT NULL DEFAULT 1,
        thumbnail_path TEXT,
        file_paths TEXT NOT NULL,
        scan_date TEXT NOT NULL,
        ocr_text TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    ''');

    // Create pages table
    await db.execute('''
      CREATE TABLE $_tablePages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER NOT NULL,
        page_number INTEGER NOT NULL,
        image_path TEXT NOT NULL,
        filter_type TEXT DEFAULT 'original',
        FOREIGN KEY (document_id) REFERENCES $_tableDocuments (id) ON DELETE CASCADE
      )
    ''');

    // Create indexes
    await db.execute('CREATE INDEX idx_document_id ON $_tablePages(document_id)');
    await db.execute('CREATE INDEX idx_scan_date ON $_tableDocuments(scan_date)');
  }

  Future<void> _onUpgrade(Database db, int oldVersion, int newVersion) async {
    // Handle database upgrades
    if (oldVersion < 2) {
      // Add future migrations here
    }
  }

  /// Save a new document with multiple pages
  Future<int> saveDocument({
    required String customName,
    required List<String> imagePaths,
    String? thumbnailPath,
    String? ocrText,
  }) async {
    final db = await _db;

    final now = DateTime.now().toIso8601String();
    final filePathsJson = imagePaths.join(',');

    final documentId = await db.insert(_tableDocuments, {
      'custom_name': customName,
      'page_count': imagePaths.length,
      'thumbnail_path': thumbnailPath ?? imagePaths.first,
      'file_paths': filePathsJson,
      'scan_date': now,
      'ocr_text': ocrText,
      'created_at': now,
    });

    // Save individual pages
    for (int i = 0; i < imagePaths.length; i++) {
      await db.insert(_tablePages, {
        'document_id': documentId,
        'page_number': i + 1,
        'image_path': imagePaths[i],
        'filter_type': 'original',
      });
    }

    return documentId;
  }

  /// Get all documents
  Future<List<Map<String, dynamic>>> getAllDocuments() async {
    final db = await _db;
    final results = await db.query(
      _tableDocuments,
      orderBy: 'scan_date DESC',
    );
    return results.toList();
  }

  /// Get document by ID
  Future<Map<String, dynamic>?> getDocument(int id) async {
    final db = await _db;
    final results = await db.query(
      _tableDocuments,
      where: 'id = ?',
      whereArgs: [id],
    );
    if (results.isEmpty) return null;
    return results.first;
  }

  /// Get pages for a document
  Future<List<Map<String, dynamic>>> getDocumentPages(int documentId) async {
    final db = await _db;
    final results = await db.query(
      _tablePages,
      where: 'document_id = ?',
      whereArgs: [documentId],
      orderBy: 'page_number ASC',
    );
    return results.toList();
  }

  /// Update document name
  Future<bool> updateDocumentName(int id, String newName) async {
    final db = await _db;
    final count = await db.update(
      _tableDocuments,
      {'custom_name': newName},
      where: 'id = ?',
      whereArgs: [id],
    );
    return count > 0;
  }

  /// Update document pages (reorder, add, delete)
  Future<bool> updateDocumentPages(int documentId, List<String> imagePaths) async {
    final db = await _db;

    // Delete existing pages
    await db.delete(
      _tablePages,
      where: 'document_id = ?',
      whereArgs: [documentId],
    );

    // Insert new pages
    for (int i = 0; i < imagePaths.length; i++) {
      await db.insert(_tablePages, {
        'document_id': documentId,
        'page_number': i + 1,
        'image_path': imagePaths[i],
        'filter_type': 'original',
      });
    }

    // Update document metadata
    final count = await db.update(
      _tableDocuments,
      {
        'page_count': imagePaths.length,
        'file_paths': imagePaths.join(','),
        'thumbnail_path': imagePaths.first,
      },
      where: 'id = ?',
      whereArgs: [documentId],
    );

    return count > 0;
  }

  /// Update OCR text
  Future<bool> updateOCRText(int id, String ocrText) async {
    final db = await _db;
    final count = await db.update(
      _tableDocuments,
      {'ocr_text': ocrText},
      where: 'id = ?',
      whereArgs: [id],
    );
    return count > 0;
  }

  /// Delete document
  Future<bool> deleteDocument(int id) async {
    final db = await _db;
    final count = await db.delete(
      _tableDocuments,
      where: 'id = ?',
      whereArgs: [id],
    );
    return count > 0;
  }

  /// Delete a specific page from a document
  Future<bool> deletePage(int pageId) async {
    final db = await _db;
    final page = await db.query(
      _tablePages,
      where: 'id = ?',
      whereArgs: [pageId],
    );

    if (page.isEmpty) return false;

    final documentId = page.first['document_id'];
    await db.delete(
      _tablePages,
      where: 'id = ?',
      whereArgs: [pageId],
    );

    // Reorder remaining pages
    final remainingPages = await db.query(
      _tablePages,
      where: 'document_id = ?',
      whereArgs: [documentId],
      orderBy: 'page_number ASC',
    );

    for (int i = 0; i < remainingPages.length; i++) {
      await db.update(
        _tablePages,
        {'page_number': i + 1},
        where: 'id = ?',
        whereArgs: [remainingPages[i]['id']],
      );
    }

    // Update document metadata
    final newFilePaths = remainingPages.map((p) => p['image_path'] as String).toList();
    await db.update(
      _tableDocuments,
      {
        'page_count': remainingPages.length,
        'file_paths': newFilePaths.join(','),
        'thumbnail_path': newFilePaths.isNotEmpty ? newFilePaths.first : null,
      },
      where: 'id = ?',
      whereArgs: [documentId],
    );

    return true;
  }

  /// Update page filter type
  Future<bool> updatePageFilter(int pageId, String filterType) async {
    final db = await _db;
    final count = await db.update(
      _tablePages,
      {'filter_type': filterType},
      where: 'id = ?',
      whereArgs: [pageId],
    );
    return count > 0;
  }

  /// Search documents by name
  Future<List<Map<String, dynamic>>> searchDocuments(String query) async {
    final db = await _db;
    final results = await db.query(
      _tableDocuments,
      where: 'custom_name LIKE ?',
      whereArgs: ['%$query%'],
      orderBy: 'scan_date DESC',
    );
    return results.toList();
  }

  /// Get document count
  Future<int> getDocumentCount() async {
    final db = await _db;
    final result = await db.rawQuery('SELECT COUNT(*) FROM $_tableDocuments');
    return Sqflite.firstIntValue(result) ?? 0;
  }

  /// Close database
  Future<void> close() async {
    final db = await _db;
    await db.close();
    _database = null;
  }
}
