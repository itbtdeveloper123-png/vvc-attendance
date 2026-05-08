import 'package:flutter/material.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:google_fonts/google_fonts.dart';
import 'dart:convert';
import '../utils/app_theme.dart';

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
            .where('imageBase64', isNotEqualTo: '')
            .snapshots(),
        builder: (context, snapshot) {
          if (!snapshot.hasData) return const Center(child: CircularProgressIndicator());
          
          final docs = snapshot.data!.docs;
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
              return GestureDetector(
                onTap: () => _viewImage(context, msg['imageBase64']),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(10),
                  child: Image.memory(
                    base64Decode(msg['imageBase64']),
                    fit: BoxFit.cover,
                  ),
                ),
              );
            },
          );
        },
      ),
    );
  }

  void _viewImage(BuildContext context, String base64) {
    showDialog(
      context: context,
      builder: (context) => Dialog.fullscreen(
        backgroundColor: Colors.black,
        child: Stack(
          children: [
            Center(child: InteractiveViewer(child: Image.memory(base64Decode(base64)))),
            Positioned(
              top: 40,
              right: 20,
              child: IconButton(
                icon: const Icon(Icons.close, color: Colors.white, size: 30),
                onPressed: () => Navigator.pop(context),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
