import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:animate_do/animate_do.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../utils/app_theme.dart';
import '../services/api_service.dart';

class ChatCreateGroupScreen extends StatefulWidget {
  final List<dynamic> allUsers;
  final String currentUserId;
  const ChatCreateGroupScreen({
    super.key,
    required this.allUsers,
    required this.currentUserId,
  });

  @override
  State<ChatCreateGroupScreen> createState() => _ChatCreateGroupScreenState();
}

class _ChatCreateGroupScreenState extends State<ChatCreateGroupScreen> {
  final TextEditingController _nameController = TextEditingController();
  final Set<String> _selectedUserIds = {};
  bool _isCreating = false;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        title: Text(
          'បង្កើតក្រុមថ្មី',
          style: GoogleFonts.kantumruyPro(fontWeight: FontWeight.bold),
        ),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: Container(
        decoration: BoxDecoration(color: AppTheme.bgSurface),
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(20),
              child: Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 20,
                  vertical: 5,
                ),
                decoration: BoxDecoration(
                  color: AppTheme.bgCard.withValues(alpha: 0.5),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                    color: AppTheme.primary.withValues(alpha: 0.2),
                  ),
                ),
                child: TextField(
                  controller: _nameController,
                  style: GoogleFonts.kantumruyPro(color: AppTheme.textPrimary),
                  decoration: InputDecoration(
                    hintText: "ឈ្មោះក្រុម...",
                    hintStyle: GoogleFonts.kantumruyPro(
                      color: AppTheme.textMuted,
                    ),
                    border: InputBorder.none,
                  ),
                ),
              ),
            ),

            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Row(
                children: [
                  Text(
                    "ជ្រើសរើសសមាជិក",
                    style: GoogleFonts.kantumruyPro(
                      color: AppTheme.textSecondary,
                      fontSize: 13,
                    ),
                  ),
                  const Spacer(),
                  Text(
                    "${_selectedUserIds.length} នាក់",
                    style: GoogleFonts.inter(
                      color: AppTheme.primaryLight,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 10),

            Expanded(
              child: ListView.builder(
                padding: const EdgeInsets.symmetric(horizontal: 10),
                itemCount: widget.allUsers.length,
                itemBuilder: (context, index) {
                  final user = widget.allUsers[index];
                  final String id = user['employee_id'] ?? '';
                  if (id == widget.currentUserId) {
                    return const SizedBox.shrink();
                  }

                  final bool isSelected = _selectedUserIds.contains(id);

                  return FadeInUp(
                    delay: Duration(milliseconds: (index * 20).clamp(0, 400)),
                    child: CheckboxListTile(
                      value: isSelected,
                      onChanged: (val) {
                        setState(() {
                          if (val == true) {
                            _selectedUserIds.add(id);
                          } else {
                            _selectedUserIds.remove(id);
                          }
                        });
                      },
                      activeColor: AppTheme.primary,
                      checkColor: Colors.white,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(15),
                      ),
                      title: Text(
                        user['name'] ?? 'Unknown',
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textPrimary,
                          fontSize: 15,
                        ),
                      ),
                      subtitle: Text(
                        user['position'] ?? 'Employee',
                        style: GoogleFonts.kantumruyPro(
                          color: AppTheme.textMuted,
                          fontSize: 11,
                        ),
                      ),
                      secondary: _buildAvatar(
                        id,
                        user['name'] ?? '',
                        user['avatar'] ?? '',
                      ),
                    ),
                  );
                },
              ),
            ),

            Padding(
              padding: const EdgeInsets.fromLTRB(20, 10, 20, 30),
              child: SizedBox(
                width: double.infinity,
                height: 54,
                child: ElevatedButton(
                  onPressed: _selectedUserIds.isEmpty || _isCreating
                      ? null
                      : _createGroup,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.primary,
                    foregroundColor: Colors.white,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(18),
                    ),
                    elevation: 5,
                    shadowColor: AppTheme.primary.withValues(alpha: 0.4),
                  ),
                  child: _isCreating
                      ? const SizedBox(
                          width: 24,
                          height: 24,
                          child: CircularProgressIndicator(
                            color: Colors.white,
                            strokeWidth: 3,
                          ),
                        )
                      : Text(
                          'បង្កើត Group',
                          style: GoogleFonts.kantumruyPro(
                            fontWeight: FontWeight.bold,
                            fontSize: 16,
                          ),
                        ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildAvatar(String employeeId, String name, String photoName) {
    final String photoUrl = ApiService.getFullImageUrl(
      photoName.isNotEmpty ? photoName : "$employeeId.jpg",
    );
    return Container(
      width: 40,
      height: 40,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        border: Border.all(color: AppTheme.primary.withValues(alpha: 0.1)),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(20),
        child: Image.network(
          photoUrl,
          fit: BoxFit.cover,
          errorBuilder: (context, error, stackTrace) => Center(
            child: Text(
              name.isNotEmpty ? name.substring(0, 1).toUpperCase() : 'U',
              style: GoogleFonts.inter(
                fontWeight: FontWeight.bold,
                color: AppTheme.textPrimary,
              ),
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _createGroup() async {
    final name = _nameController.text.trim();
    if (name.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('សូមបញ្ចូលឈ្មោះក្រុម')));
      return;
    }

    setState(() => _isCreating = true);

    try {
      final firestore = FirebaseFirestore.instance;

      // Member statuses: creator is 'accepted', others are 'pending'
      final Map<String, String> members = {widget.currentUserId: 'accepted'};
      for (var id in _selectedUserIds) {
        members[id] = 'pending';
      }

      await firestore.collection('groups').add({
        'name': name,
        'members': members,
        'participantIds': [
          widget.currentUserId,
          ..._selectedUserIds,
        ], // for easier querying
        'createdBy': widget.currentUserId,
        'createdAt': FieldValue.serverTimestamp(),
        'lastMessage': 'ក្រុមត្រូវបានបង្កើត',
        'lastTimestamp': FieldValue.serverTimestamp(),
      });

      if (mounted) {
        Navigator.pop(context, true); // Return success
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isCreating = false);
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Error: $e')));
      }
    }
  }
}
