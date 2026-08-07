import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:google_fonts/google_fonts.dart';
import 'dart:convert';
import '../utils/app_theme.dart';
import '../services/api_service.dart';

class SharedMediaScreen extends StatelessWidget {
  final String targetUserId;
  final String targetUserName;
  final String roomId;

  const SharedMediaScreen({
    super.key, 
    required this.targetUserId, 
    required this.targetUserName,
    required this.roomId,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: AppTheme.bgCard,
        title: Text('រូបភាពដែលបានផ្ញើ ($targetUserName)', 
          style: GoogleFonts.kantumruyPro(fontSize: 16, fontWeight: FontWeight.bold)),
        elevation: 0,
      ),
      body: StreamBuilder<QuerySnapshot>(
        stream: FirebaseFirestore.instance
            .collection('chats')
            .doc(roomId)
            .collection('messages')
            .orderBy('timestamp', descending: true)
            .snapshots(),
        builder: (context, snapshot) {
          if (!snapshot.hasData) return const Center(child: CircularProgressIndicator());
          
          final docs = snapshot.data!.docs.where((doc) {
            final data = doc.data() as Map<String, dynamic>;
            final type = data['type']?.toString() ?? '';
            final hasImg = data['imageUrl'] != null || data['mediaUrl'] != null || data['fileUrl'] != null || data['imageBase64'] != null || type == 'image';
            return hasImg;
          }).toList();

          if (docs.isEmpty) {
            return Center(child: Text('មិនទាន់មានរូបភាពនៅឡើយទេ', 
              style: GoogleFonts.kantumruyPro(color: AppTheme.textMuted)));
          }

          return GridView.builder(
            padding: const EdgeInsets.all(10),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 3,
              crossAxisSpacing: 8,
              mainAxisSpacing: 8,
            ),
            itemCount: docs.length,
            itemBuilder: (context, index) {
              final msg = docs[index].data() as Map<String, dynamic>;
              final base64Str = (msg['imageBase64'] ?? '').toString();
              final rawUrl = (msg['imageUrl'] ?? msg['mediaUrl'] ?? msg['fileUrl'] ?? (msg['type'] == 'image' ? msg['text'] : '') ?? '').toString();

              Widget imgWidget;
              if (base64Str.isNotEmpty) {
                imgWidget = Image.memory(base64Decode(base64Str), fit: BoxFit.cover);
              } else {
                imgWidget = Image.network(
                  ApiService.getFullImageUrl(rawUrl),
                  fit: BoxFit.cover,
                  errorBuilder: (_, __, ___) => const Icon(Icons.image_not_supported_rounded, color: Colors.white38),
                );
              }

              return GestureDetector(
                onTap: () => _viewImage(context, base64Str: base64Str, rawUrl: rawUrl),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(10),
                  child: Container(
                    color: AppTheme.bgCard,
                    child: imgWidget,
                  ),
                ),
              );
            },
          );
        },
      ),
    );
  }

  void _viewImage(BuildContext context, {String base64Str = '', String rawUrl = ''}) {
    showDialog(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.9),
      builder: (context) => Dialog(
        backgroundColor: Colors.transparent,
        insetPadding: EdgeInsets.zero,
        child: Stack(
          alignment: Alignment.center,
          children: [
            InteractiveViewer(
              child: base64Str.isNotEmpty
                  ? Image.memory(base64Decode(base64Str))
                  : Image.network(
                      ApiService.getFullImageUrl(rawUrl),
                      fit: BoxFit.contain,
                      errorBuilder: (_, __, ___) => const Icon(Icons.image_not_supported_rounded, color: Colors.white38, size: 60),
                    ),
            ),
            Positioned(
              top: MediaQuery.of(context).padding.top + 10,
              right: 16,
              child: IconButton(
                icon: const Icon(Icons.close_rounded, color: Colors.white, size: 30),
                onPressed: () => Navigator.pop(context),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
