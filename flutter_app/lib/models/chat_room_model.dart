import 'package:isar/isar.dart';

part 'chat_room_model.g.dart';

@collection
class ChatRoom {
  Id id = Isar.autoIncrement;

  @Index(unique: true, replace: true)
  late String roomId;

  String? name;
  String? avatar;
  String type; // 'direct' or 'group'
  List<String> memberIds;
  
  String? lastMessageText;
  int? lastMessageTime;
  String? lastMessageSenderId;
  int unreadCount;

  ChatRoom({
    required this.roomId,
    this.name,
    this.avatar,
    this.type = 'direct',
    this.memberIds = const [],
    this.lastMessageText,
    this.lastMessageTime,
    this.lastMessageSenderId,
    this.unreadCount = 0,
  });

  Map<String, dynamic> toJson() => {
        'roomId': roomId,
        'name': name,
        'avatar': avatar,
        'type': type,
        'memberIds': memberIds,
        'lastMessageText': lastMessageText,
        'lastMessageTime': lastMessageTime,
        'lastMessageSenderId': lastMessageSenderId,
        'unreadCount': unreadCount,
      };

  factory ChatRoom.fromJson(Map<String, dynamic> json) => ChatRoom(
        roomId: json['roomId'] ?? '',
        name: json['name'],
        avatar: json['avatar'],
        type: json['type'] ?? 'direct',
        memberIds: List<String>.from(json['memberIds'] ?? []),
        lastMessageText: json['lastMessageText'],
        lastMessageTime: json['lastMessageTime'],
        lastMessageSenderId: json['lastMessageSenderId'],
        unreadCount: json['unreadCount'] ?? 0,
      );
}
