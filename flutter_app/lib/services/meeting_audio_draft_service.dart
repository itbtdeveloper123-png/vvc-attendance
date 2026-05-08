import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

class MeetingAudioDraft {
  const MeetingAudioDraft({
    required this.id,
    required this.path,
    required this.durationMs,
    required this.sizeBytes,
    required this.createdAtIso,
  });

  final String id;
  final String path;
  final int durationMs;
  final int sizeBytes;
  final String createdAtIso;

  DateTime get createdAt =>
      DateTime.tryParse(createdAtIso) ?? DateTime.fromMillisecondsSinceEpoch(0);

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'path': path,
      'durationMs': durationMs,
      'sizeBytes': sizeBytes,
      'createdAtIso': createdAtIso,
    };
  }

  factory MeetingAudioDraft.fromJson(Map<String, dynamic> json) {
    return MeetingAudioDraft(
      id: (json['id'] ?? '').toString(),
      path: (json['path'] ?? '').toString(),
      durationMs: _asInt(json['durationMs']),
      sizeBytes: _asInt(json['sizeBytes']),
      createdAtIso: (json['createdAtIso'] ?? '').toString(),
    );
  }

  static int _asInt(dynamic value) {
    if (value is int) return value;
    if (value is num) return value.toInt();
    return int.tryParse(value?.toString() ?? '') ?? 0;
  }
}

class MeetingAudioDraftService {
  static const String _prefsKey = 'meeting_audio_drafts_v1';

  static Future<List<MeetingAudioDraft>> getDrafts() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_prefsKey);
    if (raw == null || raw.trim().isEmpty) {
      return const [];
    }

    List<dynamic> decoded;
    try {
      decoded = jsonDecode(raw) as List<dynamic>;
    } catch (_) {
      return const [];
    }

    final drafts = <MeetingAudioDraft>[];
    var changed = false;

    for (final item in decoded) {
      if (item is! Map) {
        changed = true;
        continue;
      }

      final draft = MeetingAudioDraft.fromJson(Map<String, dynamic>.from(item));
      if (draft.id.isEmpty || draft.path.isEmpty) {
        changed = true;
        continue;
      }

      if (!File(draft.path).existsSync()) {
        changed = true;
        continue;
      }

      drafts.add(draft);
    }

    drafts.sort((a, b) => b.createdAt.compareTo(a.createdAt));

    if (changed) {
      await _saveDrafts(drafts);
    }

    return drafts;
  }

  static Future<MeetingAudioDraft> saveDraft({
    required String sourcePath,
    required int durationMs,
  }) async {
    final sourceFile = File(sourcePath);
    if (!sourceFile.existsSync()) {
      throw StateError('Audio file not found: $sourcePath');
    }

    final draftsDir = await _draftDirectory();
    await draftsDir.create(recursive: true);

    final extension = p.extension(sourcePath).isEmpty
        ? '.m4a'
        : p.extension(sourcePath);
    final id = 'draft_${DateTime.now().millisecondsSinceEpoch}';
    final destinationPath = p.join(draftsDir.path, '$id$extension');

    await sourceFile.copy(destinationPath);

    final savedFile = File(destinationPath);
    final draft = MeetingAudioDraft(
      id: id,
      path: destinationPath,
      durationMs: durationMs,
      sizeBytes: await savedFile.length(),
      createdAtIso: DateTime.now().toIso8601String(),
    );

    final drafts = await getDrafts();
    final updated = [draft, ...drafts];
    await _saveDrafts(updated);
    return draft;
  }

  static Future<void> deleteDraftById(String id) async {
    final drafts = await getDrafts();
    final updated = <MeetingAudioDraft>[];

    for (final draft in drafts) {
      if (draft.id == id) {
        final file = File(draft.path);
        if (file.existsSync()) {
          await file.delete();
        }
        continue;
      }
      updated.add(draft);
    }

    await _saveDrafts(updated);
  }

  static Future<void> deleteDraft(MeetingAudioDraft draft) {
    return deleteDraftById(draft.id);
  }

  static Future<MeetingAudioDraft?> findDraftByPath(String path) async {
    final normalizedTarget = _normalizePath(path);
    final drafts = await getDrafts();
    for (final draft in drafts) {
      if (_normalizePath(draft.path) == normalizedTarget) {
        return draft;
      }
    }
    return null;
  }

  static Future<void> _saveDrafts(List<MeetingAudioDraft> drafts) async {
    final prefs = await SharedPreferences.getInstance();
    final payload = jsonEncode(drafts.map((draft) => draft.toJson()).toList());
    await prefs.setString(_prefsKey, payload);
  }

  static Future<Directory> _draftDirectory() async {
    final docsDir = await getApplicationDocumentsDirectory();
    return Directory(p.join(docsDir.path, 'meeting_audio_drafts'));
  }

  static String _normalizePath(String path) {
    return p.normalize(path).replaceAll('\\', '/').toLowerCase();
  }
}
