import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:photo_view/photo_view.dart';

class ImageViewerPage extends StatelessWidget {
  final String base64Image;
  const ImageViewerPage({super.key, required this.base64Image});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        elevation: 0,
        iconTheme: const IconThemeData(color: Colors.white),
      ),
      body: FutureBuilder<Uint8List>(
        future: computeDecode(base64Image),
        builder: (context, snapshot) {
          if (!snapshot.hasData) {
            return const Center(child: CircularProgressIndicator(color: Colors.white));
          }
          return PhotoView(
            imageProvider: MemoryImage(snapshot.data!),
            backgroundDecoration: const BoxDecoration(color: Colors.black),
            minScale: PhotoViewComputedScale.contained * 1.0,
            maxScale: PhotoViewComputedScale.covered * 2.5,
          );
        },
      ),
    );
  }
}

Future<Uint8List> computeDecode(String b64) async {
  return base64Decode(b64);
}
