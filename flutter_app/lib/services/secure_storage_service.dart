import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureStorageService {
  // Singleton pattern
  static final SecureStorageService _instance = SecureStorageService._internal();
  factory SecureStorageService() => _instance;
  SecureStorageService._internal();

  final FlutterSecureStorage _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  /// Write a sensitive value to secure storage
  Future<void> write(String key, String value) async {
    await _storage.write(key: key, value: value);
  }

  /// Read a sensitive value from secure storage
  Future<String?> read(String key) async {
    return await _storage.read(key: key);
  }

  /// Delete a sensitive value from secure storage
  Future<void> delete(String key) async {
    await _storage.delete(key: key);
  }

  /// Clear all secure storage entries
  Future<void> clear() async {
    await _storage.deleteAll();
  }
}
