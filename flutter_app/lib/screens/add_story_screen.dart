import 'dart:io';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:image_picker/image_picker.dart';
import 'package:provider/provider.dart';
import '../providers/user_provider.dart';
import '../services/r2_storage_service.dart';

class AddStoryScreen extends StatefulWidget {
  const AddStoryScreen({super.key});

  @override
  State<AddStoryScreen> createState() => _AddStoryScreenState();
}

class _AddStoryScreenState extends State<AddStoryScreen> {
  final ImagePicker _picker = ImagePicker();
  final R2StorageService _r2Service = R2StorageService();
  final TextEditingController _captionController = TextEditingController();
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;

  File? _selectedFile;
  bool _isUploading = false;

  Future<void> _pickImage(ImageSource source) async {
    final picked = await _picker.pickImage(source: source, imageQuality: 80);
    if (picked != null) {
      setState(() {
        _selectedFile = File(picked.path);
      });
    }
  }

  Future<void> _publishStory(UserProvider userProvider) async {
    if (_selectedFile == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('សូមជ្រើសរើសរូបភាពដើម្បីបង្ហោះរឿងរបស់អ្នក!', style: GoogleFonts.kantumruyPro()),
          backgroundColor: Colors.orangeAccent,
        ),
      );
      return;
    }

    setState(() => _isUploading = true);

    try {
      final String? mediaUrl = await _r2Service.uploadMedia(
        file: _selectedFile!,
        folder: 'stories',
      );

      if (mediaUrl != null) {
        final now = DateTime.now();
        await _firestore.collection('stories').add({
          'userId': userProvider.employeeId ?? '',
          'userName': userProvider.name ?? 'User',
          'userPhoto': userProvider.avatar ?? '',
          'mediaUrl': mediaUrl,
          'caption': _captionController.text.trim(),
          'createdAt': FieldValue.serverTimestamp(),
          'expiresAt': now.add(const Duration(hours: 24)),
        });

        if (mounted) {
          Navigator.pop(context);
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('បានបង្ហោះរឿងរបស់អ្នកដោយជោគជ័យ! (24h)', style: GoogleFonts.kantumruyPro()),
              backgroundColor: const Color(0xFF10B981),
            ),
          );
        }
      } else {
        throw Exception('Upload media failed');
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isUploading = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('បរាជ័យក្នុងការបង្ហោះរឿង: $e', style: GoogleFonts.kantumruyPro()),
            backgroundColor: Colors.redAccent,
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final userProvider = Provider.of<UserProvider>(context);

    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.close_rounded, color: Colors.white, size: 24),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          'បង្កើតរឿង (Add Story)',
          style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 18),
        ),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12, top: 10, bottom: 10),
            child: ElevatedButton(
              onPressed: _isUploading ? null : () => _publishStory(userProvider),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF007AFF),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
              ),
              child: _isUploading
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                    )
                  : Text('បង្ហោះ (Post)', style: GoogleFonts.kantumruyPro(color: Colors.white, fontWeight: FontWeight.bold)),
            ),
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            Expanded(
              child: Container(
                margin: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(24),
                  border: Border.all(color: const Color(0xFF334155)),
                ),
                child: _selectedFile != null
                    ? ClipRRect(
                        borderRadius: BorderRadius.circular(24),
                        child: Image.file(_selectedFile!, fit: BoxFit.cover, width: double.infinity),
                      )
                    : Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          const Icon(Icons.add_photo_alternate_rounded, size: 64, color: Colors.white38),
                          const SizedBox(height: 16),
                          Text(
                            'ជ្រើសរើសរូបភាពសម្រាប់រឿងរបស់អ្នក',
                            style: GoogleFonts.kantumruyPro(color: Colors.white70, fontSize: 15),
                          ),
                          const SizedBox(height: 24),
                          Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              ElevatedButton.icon(
                                onPressed: () => _pickImage(ImageSource.gallery),
                                icon: const Icon(Icons.photo_library_rounded, color: Colors.white),
                                label: Text('Album', style: GoogleFonts.kantumruyPro(color: Colors.white)),
                                style: ElevatedButton.styleFrom(
                                  backgroundColor: const Color(0xFF007AFF),
                                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
                                ),
                              ),
                              const SizedBox(width: 16),
                              ElevatedButton.icon(
                                onPressed: () => _pickImage(ImageSource.camera),
                                icon: const Icon(Icons.camera_alt_rounded, color: Colors.white),
                                label: Text('Camera', style: GoogleFonts.kantumruyPro(color: Colors.white)),
                                style: ElevatedButton.styleFrom(
                                  backgroundColor: const Color(0xFF10B981),
                                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: TextField(
                controller: _captionController,
                style: GoogleFonts.kantumruyPro(color: Colors.white),
                decoration: InputDecoration(
                  hintText: 'សរសេររឿង ឬ Caption...',
                  hintStyle: GoogleFonts.kantumruyPro(color: Colors.white38),
                  filled: true,
                  fillColor: const Color(0xFF1E293B),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: const BorderSide(color: Color(0xFF334155)),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: const BorderSide(color: Color(0xFF007AFF), width: 1.5),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
