import 'package:isar/isar.dart';

part 'chat_user_model.g.dart';

@embedded
class ChatUser {
  String? id;
  String? name;
  String? avatar;
  String? role;
  bool isOnline;
  int? lastSeen;

  ChatUser({
    this.id,
    this.name,
    this.avatar,
    this.role,
    this.isOnline = false,
    this.lastSeen,
  });

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'avatar': avatar,
      'role': role,
      'isOnline': isOnline,
      'lastSeen': lastSeen,
    };
  }

  factory ChatUser.fromJson(Map<String, dynamic> json) {
    return ChatUser(
      id: json['id']?.toString(),
      name: json['name']?.toString(),
      avatar: json['avatar']?.toString(),
      role: json['role']?.toString(),
      isOnline: json['isOnline'] == true,
      lastSeen: json['lastSeen'] != null ? int.tryParse(json['lastSeen'].toString()) : null,
    );
  }
}
