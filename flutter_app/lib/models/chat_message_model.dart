import 'package:isar/isar.dart';

part 'chat_message_model.g.dart';

/// Supported Message Types in Enterprise Chat
enum MessageType { text, image, file, voice }

@collection
class ChatMessage {
  Id id = Isar.autoIncrement;

  @Index(unique: true, replace: true)
  late String messageId;

  @Index()
  late String roomId;

  late String senderId;
  String? senderName;
  String? senderAvatar;

  @Enumerated(EnumType.name)
  late MessageType type;

  /// Text content or Cloudflare R2 Media URL
  late String content;

  String? fileName;
  int? fileSize; // in bytes
  int? voiceDuration; // in seconds

  @Index()
  late int timestamp; // epoch milliseconds

  bool isSent;
  bool isRead;

  ChatMessage({
    required this.messageId,
    required this.roomId,
    required this.senderId,
    this.senderName,
    this.senderAvatar,
    this.type = MessageType.text,
    required this.content,
    this.fileName,
    this.fileSize,
    this.voiceDuration,
    required this.timestamp,
    this.isSent = true,
    this.isRead = false,
  });

  Map<String, dynamic> toJson() => {
        'messageId': messageId,
        'roomId': roomId,
        'senderId': senderId,
        'senderName': senderName,
        'senderAvatar': senderAvatar,
        'type': type.name,
        'content': content,
        'fileName': fileName,
        'fileSize': fileSize,
        'voiceDuration': voiceDuration,
        'timestamp': timestamp,
        'isSent': isSent,
        'isRead': isRead,
      };

  factory ChatMessage.fromJson(Map<String, dynamic> json) {
    MessageType parsedType;
    try {
      parsedType = MessageType.values.byName(json['type'] ?? 'text');
    } catch (_) {
      parsedType = MessageType.text;
    }

    return ChatMessage(
      messageId: json['messageId'] ?? '',
      roomId: json['roomId'] ?? '',
      senderId: json['senderId'] ?? '',
      senderName: json['senderName'],
      senderAvatar: json['senderAvatar'],
      type: parsedType,
      content: json['content'] ?? '',
      fileName: json['fileName'],
      fileSize: json['fileSize'],
      voiceDuration: json['voiceDuration'],
      timestamp: json['timestamp'] ?? DateTime.now().millisecondsSinceEpoch,
      isSent: json['isSent'] ?? true,
      isRead: json['isRead'] ?? false,
    );
  }
}
