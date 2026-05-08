import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:signature/signature.dart';
import 'package:image_picker/image_picker.dart';
import 'package:image/image.dart' as img;
import 'dart:typed_data';
import '../services/api_service.dart';
import '../utils/app_theme.dart';

class DeptHeadSelector extends StatefulWidget {
  final Function(String name, String? signature) onSelected;
  final String? initialName;
  final String? initialSignature;

  const DeptHeadSelector({
    super.key,
    required this.onSelected,
    this.initialName,
    this.initialSignature,
  });

  @override
  State<DeptHeadSelector> createState() => _DeptHeadSelectorState();
}

class _DeptHeadSelectorState extends State<DeptHeadSelector> {
  final ApiService _api = ApiService();
  String? _selectedName;
  String? _selectedSignature;
  List<dynamic> _heads = [];
  bool _isLoading =
      false; // Changed to non-final as it might be used for loading states

  @override
  void initState() {
    super.initState();
    _selectedName = widget.initialName;
    _selectedSignature = widget.initialSignature;
    _loadHeads();
  }

  Future<void> _loadHeads() async {
    setState(() => _isLoading = true);
    try {
      final res = await _api.fetchDeptHeads();
      if (!mounted) return;
      if (res['success'] == true) {
        setState(() {
          _heads = res['data'] ?? [];
          if (_selectedName != null && _selectedSignature == null) {
            final match = _heads.firstWhere(
              (h) => h['full_name'] == _selectedName,
              orElse: () => null,
            );
            if (match != null) {
              _selectedSignature = match['signature'];
            }
          }
          _isLoading = false;
        });
      } else {
        setState(() => _isLoading = false);
      }
    } catch (e) {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  void _showSelectionDialog() {
    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (context, setDialogState) {
          return AlertDialog(
            backgroundColor: AppTheme.bgCard,
            elevation: 0,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(28),
              side: BorderSide(
                color: AppTheme.textPrimary.withValues(alpha: 0.08),
              ),
            ),
            title: Row(
              children: [
                Icon(
                  Icons.person_pin_rounded,
                  color: AppTheme.primary,
                  size: 28,
                ),
                const SizedBox(width: 12),
                Text(
                  "ជ្រើសរើសអ្នកអនុម័ត",
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontWeight: FontWeight.bold,
                    fontSize: 18,
                  ),
                ),
              ],
            ),
            content: Container(
              width: double.maxFinite,
              constraints: const BoxConstraints(maxHeight: 400),
              child: _isLoading
                  ? const Center(child: CircularProgressIndicator())
                  : Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        if (_heads.isEmpty)
                          Padding(
                            padding: const EdgeInsets.symmetric(vertical: 40),
                            child: Column(
                              children: [
                                Icon(
                                  Icons.group_off_rounded,
                                  color: AppTheme.textPrimary.withValues(
                                    alpha: 0.24,
                                  ),
                                  size: 48,
                                ),
                                const SizedBox(height: 12),
                                Text(
                                  "មិនទាន់មានទិន្នន័យនៅឡើយ",
                                  style: GoogleFonts.kantumruyPro(
                                    color: AppTheme.textPrimary.withValues(
                                      alpha: 0.54,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          )
                        else
                          Flexible(
                            child: ListView.builder(
                              shrinkWrap: true,
                              itemCount: _heads.length,
                              itemBuilder: (context, index) {
                                final head = _heads[index];
                                final bool isSelected =
                                    head['full_name'] == _selectedName;

                                return Container(
                                  margin: const EdgeInsets.only(bottom: 8),
                                  decoration: BoxDecoration(
                                    color: isSelected
                                        ? AppTheme.primary.withValues(
                                            alpha: 0.15,
                                          )
                                        : AppTheme.textPrimary.withValues(
                                            alpha: 0.03,
                                          ),
                                    borderRadius: BorderRadius.circular(16),
                                    border: Border.all(
                                      color: isSelected
                                          ? AppTheme.primary.withValues(
                                              alpha: 0.5,
                                            )
                                          : Colors.transparent,
                                    ),
                                  ),
                                  child: ListTile(
                                    contentPadding: const EdgeInsets.symmetric(
                                      horizontal: 16,
                                      vertical: 4,
                                    ),
                                    leading: CircleAvatar(
                                      backgroundColor: AppTheme.primary
                                          .withValues(alpha: 0.1),
                                      child: Text(
                                        head['full_name'].isNotEmpty
                                            ? head['full_name'][0].toUpperCase()
                                            : '?',
                                        style: TextStyle(
                                          color: AppTheme.primary,
                                          fontWeight: FontWeight.bold,
                                        ),
                                      ),
                                    ),
                                    title: Text(
                                      head['full_name'],
                                      style: GoogleFonts.kantumruyPro(
                                        color: AppTheme.textPrimary,
                                        fontWeight: isSelected
                                            ? FontWeight.bold
                                            : FontWeight.normal,
                                      ),
                                    ),
                                    subtitle: head['signature'] != null
                                        ? Text(
                                            "មានហត្ថលេខារួចរាល់",
                                            style: GoogleFonts.kantumruyPro(
                                              color: Colors.greenAccent,
                                              fontSize: 11,
                                            ),
                                          )
                                        : null,
                                    onTap: () {
                                      setState(() {
                                        _selectedName = head['full_name'];
                                        _selectedSignature = head['signature'];
                                      });
                                      widget.onSelected(
                                        _selectedName!,
                                        _selectedSignature,
                                      );
                                      Navigator.pop(context);
                                    },
                                    trailing: Row(
                                      mainAxisSize: MainAxisSize.min,
                                      children: [
                                        IconButton(
                                          icon: Icon(
                                            Icons.edit_note_rounded,
                                            color: AppTheme.textPrimary
                                                .withValues(alpha: 0.38),
                                            size: 22,
                                          ),
                                          onPressed: () => _showAddHeadDialog(
                                            setDialogState,
                                            existingHead: head,
                                          ),
                                        ),
                                        IconButton(
                                          icon: const Icon(
                                            Icons.delete_outline_rounded,
                                            color: Colors.redAccent,
                                            size: 20,
                                          ),
                                          onPressed: () => _confirmDelete(
                                            context,
                                            head,
                                            setDialogState,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                );
                              },
                            ),
                          ),
                        const SizedBox(height: 16),
                        SizedBox(
                          width: double.infinity,
                          child: ElevatedButton.icon(
                            onPressed: () => _showAddHeadDialog(setDialogState),
                            icon: const Icon(
                              Icons.add_circle_outline_rounded,
                              size: 20,
                            ),
                            label: Text(
                              "បន្ថែមអ្នកថ្មី",
                              style: GoogleFonts.kantumruyPro(
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: AppTheme.primary,
                              foregroundColor: AppTheme.textPrimary,
                              padding: const EdgeInsets.symmetric(vertical: 12),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(16),
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
            ),
          );
        },
      ),
    );
  }

  void _confirmDelete(
    BuildContext context,
    dynamic head,
    StateSetter setDialogState,
  ) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        title: Text(
          "លុបអ្នកអនុម័ត",
          style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary),
        ),
        content: Text(
          "តើអ្នកពិតជាចង់លុប '${head['full_name']}' មែនទេ?",
          style: GoogleFonts.kantumruyPro(
            color: AppTheme.textPrimary.withValues(alpha: 0.70),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text(
              "បោះបង់",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary.withValues(alpha: 0.38),
              ),
            ),
          ),
          TextButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final res = await _api.deleteDeptHead(int.parse(head['id']));
              if (res['success'] == true) {
                await _loadHeads();
                setDialogState(() {});
              }
            },
            child: Text(
              "លុប",
              style: GoogleFonts.kantumruyPro(color: Colors.redAccent),
            ),
          ),
        ],
      ),
    );
  }

  Future<Uint8List?> _processRemoveBackground(Uint8List imageBytes) async {
    try {
      final img.Image? originalImage = img.decodeImage(imageBytes);
      if (originalImage == null) return null;

      // 1. Convert to a 32-bit image with Alpha channel
      final img.Image processedImage = originalImage.convert(
        format: img.Format.uint8,
        numChannels: 4,
      );

      // 2. Advanced Background Removal using Luminance
      for (final frame in processedImage.frames) {
        for (final pixel in frame) {
          final double r = pixel.r.toDouble();
          final double g = pixel.g.toDouble();
          final double b = pixel.b.toDouble();

          // Calculate Perceived Brightness (Luminance)
          // Using standard weightings for R, G, B
          final double luminance = (0.299 * r + 0.587 * g + 0.114 * b);

          // Algorithm logic:
          // If luminance is high (white/bright paper), make it transparent.
          // We use a threshold transition for smoother edges.

          const double lowerThreshold =
              140.0; // Darker than this is definitely ink
          const double upperThreshold =
              200.0; // Brighter than this is definitely paper

          if (luminance >= upperThreshold) {
            // Full paper area
            pixel.a = 0;
          } else if (luminance > lowerThreshold) {
            // Edge/Shadow transition: Partial transparency
            // Calculate transparency amount based on brightness
            final double ratio =
                (upperThreshold - luminance) /
                (upperThreshold - lowerThreshold);
            // Squaring the ratio makes the ink stand out more against light shadows
            pixel.a = (ratio * ratio * 255).toInt();

            // Optional: Brighten the foreground slightly to hide paper texture
            pixel.r = (r * (1 + (1 - ratio) * 0.2)).clamp(0, 255).toInt();
            pixel.g = (g * (1 + (1 - ratio) * 0.2)).clamp(0, 255).toInt();
            pixel.b = (b * (1 + (1 - ratio) * 0.2)).clamp(0, 255).toInt();
          } else {
            // Solid ink area
            pixel.a = 255;

            // Enhance contrast: Make the ink slightly darker for a cleaner look
            pixel.r = (r * 0.9).toInt();
            pixel.g = (g * 0.9).toInt();
            pixel.b = (b * 0.9).toInt();
          }
        }
      }

      // Encode back to PNG to maintain transparency
      return Uint8List.fromList(img.encodePng(processedImage));
    } catch (e) {
      debugPrint("Error removing background: $e");
      return imageBytes;
    }
  }

  void _showAddHeadDialog(StateSetter setDialogState, {dynamic existingHead}) {
    final nameController = TextEditingController(
      text: existingHead?['full_name'],
    );
    final SignatureController sigController = SignatureController(
      penStrokeWidth: 4,
      penColor: Colors.black,
      exportBackgroundColor: Colors.transparent,
    );
    String? capturedSig = existingHead?['signature'];
    bool isProcessing = false;

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (context, setLocalState) {
          return AlertDialog(
            backgroundColor: AppTheme.bgCard,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(28),
              side: BorderSide(
                color: AppTheme.textPrimary.withValues(alpha: 0.1),
              ),
            ),
            title: Text(
              existingHead != null
                  ? "កែប្រែអ្នកអនុម័ត"
                  : "បន្ថែមអ្នកអនុម័តថ្មី",
              style: GoogleFonts.kantumruyPro(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.bold,
              ),
            ),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    "ឈ្មោះពេញ",
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary.withValues(alpha: 0.70),
                      fontSize: 13,
                    ),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: nameController,
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textPrimary,
                    ),
                    decoration: InputDecoration(
                      hintText: "បញ្ចូលឈ្មោះ...",
                      hintStyle: TextStyle(
                        color: AppTheme.textPrimary.withValues(alpha: 0.24),
                      ),
                      filled: true,
                      fillColor: AppTheme.textPrimary.withValues(alpha: 0.05),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(16),
                        borderSide: BorderSide.none,
                      ),
                      contentPadding: const EdgeInsets.symmetric(
                        horizontal: 16,
                        vertical: 14,
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        "ហត្ថលេខា",
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary.withValues(alpha: 0.70),
                          fontSize: 13,
                        ),
                      ),
                      Row(
                        children: [
                          IconButton(
                            icon: Icon(
                              Icons.image_search_rounded,
                              color: AppTheme.accent,
                              size: 20,
                            ),
                            onPressed: () async {
                              final picker = ImagePicker();
                              final picked = await picker.pickImage(
                                source: ImageSource.gallery,
                              );
                              if (picked != null) {
                                setLocalState(() => isProcessing = true);
                                final bytes = await picked.readAsBytes();
                                final processed =
                                    await _processRemoveBackground(bytes);
                                if (!mounted) return;
                                if (processed != null) {
                                  setLocalState(() {
                                    capturedSig = base64Encode(processed);
                                    isProcessing = false;
                                  });
                                } else {
                                  setLocalState(() {
                                    capturedSig = base64Encode(bytes);
                                    isProcessing = false;
                                  });
                                }
                              }
                            },
                            tooltip: "Upload From Gallery",
                          ),
                          IconButton(
                            icon: Icon(
                              Icons.camera_alt_rounded,
                              color: AppTheme.primaryLight,
                              size: 20,
                            ),
                            onPressed: () async {
                              final picker = ImagePicker();
                              final picked = await picker.pickImage(
                                source: ImageSource.camera,
                              );
                              if (picked != null) {
                                setLocalState(() => isProcessing = true);
                                final bytes = await picked.readAsBytes();
                                final processed =
                                    await _processRemoveBackground(bytes);
                                if (!mounted) return;
                                if (processed != null) {
                                  setLocalState(() {
                                    capturedSig = base64Encode(processed);
                                    isProcessing = false;
                                  });
                                } else {
                                  setLocalState(() {
                                    capturedSig = base64Encode(bytes);
                                    isProcessing = false;
                                  });
                                }
                              }
                            },
                            tooltip: "Take Photo",
                          ),
                        ],
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  if (capturedSig != null)
                    Container(
                      height: 150,
                      width: double.infinity,
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: AppTheme.textPrimary,
                        borderRadius: BorderRadius.circular(16),
                        border: Border.all(
                          color: AppTheme.primary.withValues(alpha: 0.3),
                        ),
                      ),
                      child: Stack(
                        children: [
                          Center(
                            child: Image.memory(
                              base64Decode(
                                capturedSig!.contains(',')
                                    ? capturedSig!.split(',').last
                                    : capturedSig!,
                              ),
                              fit: BoxFit.contain,
                            ),
                          ),
                          Positioned(
                            right: 0,
                            top: 0,
                            child: IconButton(
                              icon: const Icon(Icons.cancel, color: Colors.red),
                              onPressed: () =>
                                  setLocalState(() => capturedSig = null),
                            ),
                          ),
                        ],
                      ),
                    )
                  else
                    Container(
                      decoration: BoxDecoration(
                        color: AppTheme.textPrimary,
                        borderRadius: BorderRadius.circular(16),
                        border: Border.all(
                          color: AppTheme.textPrimary.withValues(alpha: 0.10),
                        ),
                      ),
                      child: Column(
                        children: [
                          Signature(
                            controller: sigController,
                            height: 150,
                            backgroundColor: AppTheme.textPrimary,
                          ),
                          Container(
                            color: Colors.grey[100],
                            child: Row(
                              mainAxisAlignment: MainAxisAlignment.end,
                              children: [
                                TextButton.icon(
                                  onPressed: () => sigController.clear(),
                                  icon: const Icon(
                                    Icons.refresh_rounded,
                                    size: 16,
                                    color: Colors.redAccent,
                                  ),
                                  label: Text(
                                    "សម្អាត",
                                    style: GoogleFonts.kantumruyPro(
                                      color: Colors.redAccent,
                                      fontSize: 12,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  if (isProcessing)
                    const Padding(
                      padding: EdgeInsets.only(top: 10),
                      child: Center(child: LinearProgressIndicator()),
                    ),
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: Text(
                  "បោះបង់",
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary.withValues(alpha: 0.54),
                  ),
                ),
              ),
              ElevatedButton(
                onPressed: (isProcessing)
                    ? null
                    : () async {
                        if (nameController.text.isEmpty) return;

                        String? sigBase64 = capturedSig;
                        if (sigBase64 == null && sigController.isNotEmpty) {
                          final bytes = await sigController.toPngBytes();
                          if (bytes != null) {
                            sigBase64 = base64Encode(bytes);
                          }
                        }

                        final res = await _api.saveDeptHead(
                          id: existingHead != null
                              ? int.parse(existingHead['id'])
                              : null,
                          fullName: nameController.text,
                          signature: sigBase64,
                        );

                        if (!mounted) return;
                        if (res['success'] == true) {
                          await _loadHeads();
                          if (!mounted || !ctx.mounted) return;
                          Navigator.of(ctx).pop();
                        }
                      },
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppTheme.primary,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                  padding: const EdgeInsets.symmetric(
                    horizontal: 24,
                    vertical: 12,
                  ),
                ),
                child: Text(
                  "រក្សាទុក",
                  style: GoogleFonts.kantumruyPro(
                    color: AppTheme.textPrimary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        InkWell(
          onTap: _showSelectionDialog,
          borderRadius: BorderRadius.circular(16),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 300),
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
            decoration: BoxDecoration(
              color: AppTheme.textPrimary.withValues(alpha: 0.05),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: AppTheme.textPrimary.withValues(alpha: 0.12),
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.2),
                  blurRadius: 10,
                  offset: const Offset(0, 4),
                ),
              ],
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Expanded(
                  child: Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: AppTheme.primary.withValues(alpha: 0.1),
                          shape: BoxShape.circle,
                        ),
                        child: Icon(
                          _selectedName != null
                              ? Icons.how_to_reg_rounded
                              : Icons.person_search_rounded,
                          color: AppTheme.primaryLight,
                          size: 20,
                        ),
                      ),
                      const SizedBox(width: 12),
                      Text(
                        _selectedName ?? "ជ្រើសរើសអ្នកអនុម័ត...",
                        style: GoogleFonts.kantumruyPro(
                          color: _selectedName != null
                              ? AppTheme.textPrimary
                              : AppTheme.textPrimary.withValues(alpha: 0.30),
                          fontSize: 14,
                          fontWeight: _selectedName != null
                              ? FontWeight.bold
                              : FontWeight.normal,
                        ),
                      ),
                    ],
                  ),
                ),
                Icon(
                  Icons.keyboard_arrow_right_rounded,
                  color: AppTheme.primaryLight.withValues(alpha: 0.5),
                ),
              ],
            ),
          ),
        ),
        if (_selectedSignature != null && _selectedSignature!.isNotEmpty) ...[
          const SizedBox(height: 16),
          TweenAnimationBuilder<double>(
            tween: Tween(begin: 0, end: 1),
            duration: const Duration(milliseconds: 500),
            builder: (context, value, child) {
              return Opacity(
                opacity: value,
                child: Transform.translate(
                  offset: Offset(0, 20 * (1 - value)),
                  child: child,
                ),
              );
            },
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: AppTheme.textPrimary,
                borderRadius: BorderRadius.circular(20),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.3),
                    blurRadius: 15,
                    offset: const Offset(0, 8),
                  ),
                ],
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Row(
                        children: [
                          const Icon(
                            Icons.verified_rounded,
                            color: Colors.green,
                            size: 18,
                          ),
                          const SizedBox(width: 8),
                          Text(
                            "ហត្ថលេខាត្រូវបានភ្ជាប់",
                            style: GoogleFonts.kantumruyPro(
                              color: Colors.black87,
                              fontSize: 13,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ],
                      ),
                      GestureDetector(
                        onTap: () {
                          setState(() {
                            _selectedName = null;
                            _selectedSignature = null;
                          });
                          widget.onSelected("", null);
                        },
                        child: const Icon(
                          Icons.close_rounded,
                          color: Colors.black26,
                          size: 20,
                        ),
                      ),
                    ],
                  ),
                  const Divider(height: 24, thickness: 0.5),
                  Center(
                    child: ConstrainedBox(
                      constraints: const BoxConstraints(maxHeight: 120),
                      child: Image.memory(
                        base64Decode(
                          _selectedSignature!.contains(',')
                              ? _selectedSignature!.split(',').last
                              : _selectedSignature!,
                        ),
                        fit: BoxFit.contain,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ],
    );
  }
}
