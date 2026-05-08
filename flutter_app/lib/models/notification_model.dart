import '../services/api_service.dart';

class NotificationModel {
  final int id;
  final String title;
  final String message;
  final String sentAt;
  final bool isRead;
  final String type;
  final int targetId;
  final String? imageUrl;

  NotificationModel({
    required this.id,
    required this.title,
    required this.message,
    required this.sentAt,
    required this.isRead,
    this.type = 'general',
    this.targetId = 0,
    this.imageUrl,
  });

  factory NotificationModel.fromJson(Map<String, dynamic> json) {
    return NotificationModel(
      id: json['id'] is int
          ? json['id']
          : int.tryParse(json['id']?.toString() ?? '0') ?? 0,
      title: json['title'] ?? 'No Title',
      message: json['message'] ?? '',
      sentAt: json['created_at'] ?? json['sent_at'] ?? '',
      isRead:
          json['is_read'] == true ||
          json['is_read'] == 1 ||
          json['is_read'] == '1' ||
          json['is_read'] == 'true',
      type: json['type'] ?? 'general',
      targetId: json['target_id'] is int
          ? json['target_id']
          : int.tryParse(json['target_id']?.toString() ?? '0') ?? 0,
      imageUrl: ApiService.getFullImageUrl(json['image_url']),
    );
  }
}
