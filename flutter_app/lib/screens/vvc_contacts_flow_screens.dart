import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import '../services/api_service.dart';
import '../widgets/app_widgets.dart';

// ============================================================================
// VVC DARK THEME DESIGN TOKENS
// ============================================================================
class VvcTheme {
  static const Color primaryBg = Color(0xFF1C1C1E);
  static const Color cardBg = Color(0xFF2C2C2E);
  static const Color accent = Color(0xFF3388FF);
  static const Color mutedText = Color(0xFF8E8E93);
  static const Color textPrimary = Color(0xFFFFFFFF);
  static const Color dividerColor = Color(0x1AFFFFFF);
  static const Color onlineGreen = Color(0xFF34C759);
  static const Color dangerRed = Color(0xFFFF453A);
}

// ============================================================================
// PART 1 - SCREEN 1: NEW MESSAGE / CONTACT LIST SCREEN
// ============================================================================
class VvcNewMessageContactListScreen extends StatefulWidget {
  final List<Map<String, dynamic>>? contacts;
  final Function(Map<String, dynamic> contact)? onSelectContact;
  final VoidCallback? onNewGroupTap;
  final VoidCallback? onNewContactTap;
  final VoidCallback? onNewChannelTap;

  const VvcNewMessageContactListScreen({
    super.key,
    this.contacts,
    this.onSelectContact,
    this.onNewGroupTap,
    this.onNewContactTap,
    this.onNewChannelTap,
  });

  @override
  State<VvcNewMessageContactListScreen> createState() => _VvcNewMessageContactListScreenState();
}

class _VvcNewMessageContactListScreenState extends State<VvcNewMessageContactListScreen> {
  final TextEditingController _searchController = TextEditingController();
  String _searchQuery = '';
  String _selectedLetter = '';

  @override
  void initState() {
    super.initState();
    _searchController.addListener(() {
      setState(() {
        _searchQuery = _searchController.text.trim().toLowerCase();
      });
    });
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');

    return Scaffold(
      backgroundColor: VvcTheme.primaryBg,
      appBar: VvcAppBar(
        backgroundColor: VvcTheme.primaryBg,
        elevation: 0,
        leading: TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(
            'Close',
            style: GoogleFonts.inter(
              color: VvcTheme.accent,
              fontSize: 16,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
        leadingWidth: 80,
        centerTitle: true,
        title: Text(
          'New Message',
          style: GoogleFonts.inter(
            color: VvcTheme.textPrimary,
            fontSize: 17,
            fontWeight: FontWeight.bold,
          ),
        ),
      ),
      body: Stack(
        children: [
          Column(
            children: [
              // Search Bar (#2C2C2E)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
                child: Container(
                  height: 38,
                  decoration: BoxDecoration(
                    color: VvcTheme.cardBg,
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: TextField(
                    controller: _searchController,
                    style: GoogleFonts.inter(color: Colors.white, fontSize: 15),
                    decoration: InputDecoration(
                      hintText: 'Search contacts',
                      hintStyle: GoogleFonts.inter(color: VvcTheme.mutedText, fontSize: 14.5),
                      prefixIcon: const Icon(Icons.search_rounded, color: VvcTheme.mutedText, size: 20),
                      border: InputBorder.none,
                      contentPadding: const EdgeInsets.symmetric(vertical: 8),
                    ),
                  ),
                ),
              ),

              Expanded(
                child: StreamBuilder<QuerySnapshot>(
                  stream: FirebaseFirestore.instance.collection('users').snapshots(),
                  builder: (context, snapshot) {
                    if (!snapshot.hasData) {
                      return const Center(child: CircularProgressIndicator(color: VvcTheme.accent));
                    }

                    final realContacts = snapshot.data!.docs.where((doc) {
                      final d = doc.data() as Map<String, dynamic>;
                      final role = (d['role'] ?? '').toString().toLowerCase();
                      final email = (d['email'] ?? '').toString().toLowerCase();
                      if (role == 'admin' || role == 'admin_panel' || d['isAdminPanel'] == true || email.contains('admin')) {
                        return false;
                      }
                      return true;
                    }).map((doc) {
                      final d = doc.data() as Map<String, dynamic>;
                      return {
                        'id': doc.id,
                        'name': d['name'] ?? d['username'] ?? 'User',
                        'subtitle': d['position'] ?? d['department'] ?? 'last seen recently',
                        'avatar': d['avatar'] ?? d['photoUrl'] ?? '',
                        'phone': d['phone'] ?? d['phoneNumber'] ?? '',
                        'isOnline': d['isOnline'] == true,
                      };
                    }).toList();

                    final filtered = _searchQuery.isEmpty
                        ? realContacts
                        : realContacts.where((c) => (c['name'] ?? '').toString().toLowerCase().contains(_searchQuery)).toList();

                    final Map<String, List<Map<String, dynamic>>> grouped = {};
                    for (var c in filtered) {
                      final name = (c['name'] ?? '').toString();
                      final letter = name.isNotEmpty ? name[0].toUpperCase() : '#';
                      grouped.putIfAbsent(letter, () => []).add(c);
                    }

                    return ListView(
                      physics: const BouncingScrollPhysics(),
                      children: [
                        // Action Items
                        if (_searchQuery.isEmpty) ...[
                          _buildActionRow(
                            icon: Icons.people_outline_rounded,
                            title: 'New Group',
                            onTap: () {
                              if (widget.onNewGroupTap != null) {
                                widget.onNewGroupTap!();
                              } else {
                                Navigator.push(
                                  context,
                                  MaterialPageRoute(builder: (_) => const VvcNewGroupMemberSelectionScreen()),
                                );
                              }
                            },
                          ),
                          _buildActionRow(
                            icon: Icons.person_add_alt_1_outlined,
                            title: 'New Contact',
                            onTap: () {
                              if (widget.onNewContactTap != null) {
                                widget.onNewContactTap!();
                              } else {
                                Navigator.push(
                                  context,
                                  MaterialPageRoute(builder: (_) => const VvcNewContactFormScreen()),
                                );
                              }
                            },
                          ),
                          _buildActionRow(
                            icon: Icons.campaign_outlined,
                            title: 'New Channel',
                            onTap: () => widget.onNewChannelTap?.call(),
                          ),
                          const SizedBox(height: 12),
                        ],

                        // Grouped Real Contacts List
                        ...grouped.entries.map((entry) {
                          final letter = entry.key;
                          final list = entry.value;

                          return Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
                                width: double.infinity,
                                color: const Color(0xFF141416),
                                child: Text(
                                  letter,
                                  style: GoogleFonts.inter(
                                    color: VvcTheme.mutedText,
                                    fontSize: 13,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              ),
                              ...list.map((c) => _buildContactTile(c)),
                            ],
                          );
                        }),
                      ],
                    );
                  },
                ),
              ),
            ],
          ),

          // Right-Side A-Z Index Sidebar
          if (_searchQuery.isEmpty)
            Positioned(
              right: 2,
              top: 70,
              bottom: 20,
              child: Container(
                width: 20,
                alignment: Alignment.center,
                child: SingleChildScrollView(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: alphabet.map((letter) {
                      final isSelected = _selectedLetter == letter;
                      return GestureDetector(
                        onTap: () {
                          setState(() => _selectedLetter = letter);
                        },
                        child: Padding(
                          padding: const EdgeInsets.symmetric(vertical: 1.0),
                          child: Text(
                            letter,
                            style: GoogleFonts.inter(
                              color: isSelected ? VvcTheme.accent : VvcTheme.mutedText,
                              fontSize: 10.5,
                              fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                            ),
                          ),
                        ),
                      );
                    }).toList(),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildActionRow({
    required IconData icon,
    required String title,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 11.0),
        child: Row(
          children: [
            Container(
              width: 36,
              height: 36,
              decoration: const BoxDecoration(
                color: VvcTheme.cardBg,
                shape: BoxShape.circle,
              ),
              child: Icon(icon, color: VvcTheme.accent, size: 20),
            ),
            const SizedBox(width: 14),
            Text(
              title,
              style: GoogleFonts.inter(
                color: VvcTheme.accent,
                fontSize: 16,
                fontWeight: FontWeight.w500,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildContactTile(Map<String, dynamic> c) {
    final String name = c['name'] ?? '';
    final String subtitle = c['subtitle'] ?? '';
    final bool isOnline = c['isOnline'] == true;

    return InkWell(
      onTap: () => widget.onSelectContact?.call(c),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
        child: Row(
          children: [
            Stack(
              children: [
                CircleAvatar(
                  radius: 22,
                  backgroundColor: VvcTheme.accent,
                  child: Text(
                    name.isNotEmpty ? name[0].toUpperCase() : 'C',
                    style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16),
                  ),
                ),
                if (isOnline)
                  Positioned(
                    right: 0,
                    bottom: 0,
                    child: Container(
                      width: 12,
                      height: 12,
                      decoration: BoxDecoration(
                        color: VvcTheme.onlineGreen,
                        shape: BoxShape.circle,
                        border: Border.all(color: VvcTheme.primaryBg, width: 2),
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    name,
                    style: GoogleFonts.inter(
                      color: VvcTheme.textPrimary,
                      fontSize: 16,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    subtitle,
                    style: GoogleFonts.inter(
                      color: isOnline ? VvcTheme.accent : VvcTheme.mutedText,
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ============================================================================
// PART 1 - SCREEN 2: NEW GROUP MEMBER SELECTION SCREEN
// ============================================================================
class VvcNewGroupMemberSelectionScreen extends StatefulWidget {
  final List<Map<String, dynamic>>? availableContacts;
  final Function(List<Map<String, dynamic>> selected)? onNext;

  const VvcNewGroupMemberSelectionScreen({
    super.key,
    this.availableContacts,
    this.onNext,
  });

  @override
  State<VvcNewGroupMemberSelectionScreen> createState() => _VvcNewGroupMemberSelectionScreenState();
}

class _VvcNewGroupMemberSelectionScreenState extends State<VvcNewGroupMemberSelectionScreen> {
  final TextEditingController _searchController = TextEditingController();
  final Set<String> _selectedNames = {};
  String _searchQuery = '';

  late List<Map<String, dynamic>> _contacts;

  @override
  void initState() {
    super.initState();
    _contacts = widget.availableContacts ?? [
      {'name': 'អាយធី', 'subtitle': 'last seen 5m ago'},
      {'name': 'Super', 'subtitle': 'online'},
      {'name': 'ម៉ែត ពិសី', 'subtitle': 'last seen 1h ago'},
      {'name': 'Sarun', 'subtitle': 'online'},
      {'name': 'user', 'subtitle': 'last seen yesterday'},
      {'name': 'Vvc', 'subtitle': 'online'},
      {'name': 'ភុក សុម៉ារ៉ឌី', 'subtitle': 'last seen 20m ago'},
      {'name': 'តួ តាហេង', 'subtitle': 'last seen recently'},
    ];
    _searchController.addListener(() {
      setState(() => _searchQuery = _searchController.text.trim().toLowerCase());
    });
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _toggleSelect(String name) {
    setState(() {
      if (_selectedNames.contains(name)) {
        _selectedNames.remove(name);
      } else {
        _selectedNames.add(name);
      }
    });
  }

  void _goNext() {
    final selectedList = _contacts.where((c) => _selectedNames.contains(c['name'])).toList();
    if (widget.onNext != null) {
      widget.onNext!(selectedList);
    } else {
      Navigator.push(
        context,
        MaterialPageRoute(
          builder: (_) => VvcNewGroupDetailsScreen(selectedMembers: selectedList),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VvcTheme.primaryBg,
      appBar: VvcAppBar(
        backgroundColor: VvcTheme.primaryBg,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: VvcTheme.accent, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
        centerTitle: true,
        title: Column(
          children: [
            Text(
              'New Group',
              style: GoogleFonts.inter(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
            ),
            Text(
              '${_selectedNames.length}/200000',
              style: GoogleFonts.inter(color: VvcTheme.mutedText, fontSize: 11),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: _selectedNames.isNotEmpty ? _goNext : null,
            child: Text(
              'Next',
              style: GoogleFonts.inter(
                color: _selectedNames.isNotEmpty ? VvcTheme.accent : VvcTheme.mutedText,
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
      body: Column(
        children: [
          // Search Field: "Who would you like to add?"
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 8.0),
            child: Container(
              height: 38,
              decoration: BoxDecoration(
                color: VvcTheme.cardBg,
                borderRadius: BorderRadius.circular(10),
              ),
              child: TextField(
                controller: _searchController,
                style: GoogleFonts.inter(color: Colors.white, fontSize: 15),
                decoration: InputDecoration(
                  hintText: 'Who would you like to add?',
                  hintStyle: GoogleFonts.inter(color: VvcTheme.mutedText, fontSize: 14),
                  prefixIcon: const Icon(Icons.search_rounded, color: VvcTheme.mutedText, size: 20),
                  border: InputBorder.none,
                  contentPadding: const EdgeInsets.symmetric(vertical: 8),
                ),
              ),
            ),
          ),
          Expanded(
            child: StreamBuilder<QuerySnapshot>(
              stream: FirebaseFirestore.instance.collection('users').snapshots(),
              builder: (context, snapshot) {
                if (!snapshot.hasData) {
                  return const Center(child: CircularProgressIndicator(color: VvcTheme.accent));
                }

                final realUsers = snapshot.data!.docs.where((doc) {
                  final d = doc.data() as Map<String, dynamic>;
                  final role = (d['role'] ?? '').toString().toLowerCase();
                  final email = (d['email'] ?? '').toString().toLowerCase();
                  if (role == 'admin' || role == 'admin_panel' || d['isAdminPanel'] == true || email.contains('admin')) {
                    return false;
                  }
                  return true;
                }).map((doc) {
                  final d = doc.data() as Map<String, dynamic>;
                  return {
                    'id': doc.id,
                    'name': d['name'] ?? d['username'] ?? 'User',
                    'subtitle': d['position'] ?? d['department'] ?? 'last seen recently',
                    'avatar': d['avatar'] ?? d['photoUrl'] ?? '',
                    'isOnline': d['isOnline'] == true,
                  };
                }).toList();

                final filtered = _searchQuery.isEmpty
                    ? realUsers
                    : realUsers.where((c) => (c['name'] ?? '').toString().toLowerCase().contains(_searchQuery)).toList();

                return ListView.builder(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  itemCount: filtered.length,
                  itemBuilder: (context, idx) {
                    final c = filtered[idx];
                    final String name = c['name'] ?? '';
                    final String subtitle = c['subtitle'] ?? '';
                    final String avatar = c['avatar'] ?? '';
                    final bool isSelected = _selectedNames.contains(name);

                    return InkWell(
                      onTap: () => _toggleSelect(name),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                        child: Row(
                          children: [
                            Container(
                              width: 22,
                              height: 22,
                              decoration: BoxDecoration(
                                shape: BoxShape.circle,
                                color: isSelected ? VvcTheme.accent : Colors.transparent,
                                border: Border.all(
                                  color: isSelected ? VvcTheme.accent : VvcTheme.mutedText,
                                  width: 1.5,
                                ),
                              ),
                              child: isSelected
                                  ? const Icon(Icons.check_rounded, color: Colors.white, size: 14)
                                  : null,
                            ),
                            const SizedBox(width: 14),

                            CircleAvatar(
                              radius: 20,
                              backgroundImage: avatar.isNotEmpty ? NetworkImage(ApiService.getFullImageUrl(avatar)) : null,
                              backgroundColor: VvcTheme.accent.withValues(alpha: 0.8),
                              child: avatar.isEmpty
                                  ? Text(
                                      name.isNotEmpty ? name[0].toUpperCase() : 'U',
                                      style: GoogleFonts.inter(color: Colors.white, fontWeight: FontWeight.bold),
                                    )
                                  : null,
                            ),
                            const SizedBox(width: 14),

                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    name,
                                    style: GoogleFonts.inter(
                                      color: VvcTheme.textPrimary,
                                      fontSize: 16,
                                      fontWeight: FontWeight.w500,
                                    ),
                                  ),
                                  const SizedBox(height: 2),
                                  Text(
                                    subtitle,
                                    style: GoogleFonts.inter(
                                      color: VvcTheme.mutedText,
                                      fontSize: 13,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}

// ============================================================================
// PART 1 - SCREEN 3: NEW GROUP DETAILS SCREEN
// ============================================================================
class VvcNewGroupDetailsScreen extends StatefulWidget {
  final List<Map<String, dynamic>>? selectedMembers;
  final Function(String groupName, List<Map<String, dynamic>> members)? onCreate;

  const VvcNewGroupDetailsScreen({
    super.key,
    this.selectedMembers,
    this.onCreate,
  });

  @override
  State<VvcNewGroupDetailsScreen> createState() => _VvcNewGroupDetailsScreenState();
}

class _VvcNewGroupDetailsScreenState extends State<VvcNewGroupDetailsScreen> {
  final TextEditingController _nameController = TextEditingController();

  @override
  void dispose() {
    _nameController.dispose();
    super.dispose();
  }

  void _handleCreate() {
    final groupName = _nameController.text.trim();
    if (groupName.isEmpty) return;

    if (widget.onCreate != null) {
      widget.onCreate!(groupName, widget.selectedMembers ?? []);
    } else {
      Navigator.popUntil(context, (route) => route.isFirst);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('បានបង្កើតក្រុម "$groupName" រួចរាល់!'),
          backgroundColor: VvcTheme.accent,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VvcTheme.primaryBg,
      appBar: VvcAppBar(
        backgroundColor: VvcTheme.primaryBg,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, color: VvcTheme.accent, size: 20),
          onPressed: () => Navigator.pop(context),
        ),
        centerTitle: true,
        title: Text(
          'New Group',
          style: GoogleFonts.inter(color: Colors.white, fontSize: 17, fontWeight: FontWeight.bold),
        ),
        actions: [
          ValueListenableBuilder<TextEditingValue>(
            valueListenable: _nameController,
            builder: (context, val, _) {
              final canCreate = val.text.trim().isNotEmpty;
              return TextButton(
                onPressed: canCreate ? _handleCreate : null,
                child: Text(
                  'Create',
                  style: GoogleFonts.inter(
                    color: canCreate ? VvcTheme.accent : VvcTheme.mutedText,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              );
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
        child: Column(
          children: [
            // Profile Card: Circular camera button + Group Name input field
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: VvcTheme.cardBg,
                borderRadius: BorderRadius.circular(16),
              ),
              child: Row(
                children: [
                  Container(
                    width: 60,
                    height: 60,
                    decoration: const BoxDecoration(
                      color: VvcTheme.accent,
                      shape: BoxShape.circle,
                    ),
                    child: const Icon(Icons.camera_alt_rounded, color: Colors.white, size: 28),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: TextField(
                      controller: _nameController,
                      style: GoogleFonts.inter(color: Colors.white, fontSize: 16),
                      decoration: InputDecoration(
                        hintText: 'Group Name',
                        hintStyle: GoogleFonts.inter(color: VvcTheme.mutedText, fontSize: 16),
                        border: InputBorder.none,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),

            // Settings Card: Auto-Delete Messages
            Container(
              decoration: BoxDecoration(
                color: VvcTheme.cardBg,
                borderRadius: BorderRadius.circular(16),
              ),
              child: ListTile(
                leading: Container(
                  padding: const EdgeInsets.all(6),
                  decoration: const BoxDecoration(
                    color: Color(0xFFFF9500),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(Icons.timer_outlined, color: Colors.white, size: 18),
                ),
                title: Text(
                  'Auto-Delete Messages',
                  style: GoogleFonts.inter(color: Colors.white, fontSize: 15.5),
                ),
                trailing: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      'Off',
                      style: GoogleFonts.inter(color: VvcTheme.mutedText, fontSize: 15),
                    ),
                    const Icon(Icons.chevron_right_rounded, color: VvcTheme.mutedText, size: 20),
                  ],
                ),
                onTap: () {},
              ),
            ),
            const SizedBox(height: 8),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16.0),
              child: Text(
                'Automatically delete messages sent in this group after a set period of time.',
                style: GoogleFonts.inter(color: VvcTheme.mutedText, fontSize: 12.5),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ============================================================================
// PART 1 - SCREEN 4: NEW CONTACT FORM SCREEN
// ============================================================================
class VvcNewContactFormScreen extends StatefulWidget {
  final Function(Map<String, String> contactData)? onSave;

  const VvcNewContactFormScreen({
    super.key,
    this.onSave,
  });

  @override
  State<VvcNewContactFormScreen> createState() => _VvcNewContactFormScreenState();
}

class _VvcNewContactFormScreenState extends State<VvcNewContactFormScreen> {
  final TextEditingController _firstNameCtrl = TextEditingController();
  final TextEditingController _lastNameCtrl = TextEditingController();
  final TextEditingController _phoneCtrl = TextEditingController();

  final String _selectedCountry = 'Cambodia';
  final String _selectedFlag = '🇰🇭';
  final String _dialCode = '+855';
  bool _syncToPhone = true;

  @override
  void dispose() {
    _firstNameCtrl.dispose();
    _lastNameCtrl.dispose();
    _phoneCtrl.dispose();
    super.dispose();
  }

  void _saveContact() {
    final first = _firstNameCtrl.text.trim();
    if (first.isEmpty) return;

    final data = {
      'firstName': first,
      'lastName': _lastNameCtrl.text.trim(),
      'phone': '$_dialCode ${_phoneCtrl.text.trim()}',
      'country': _selectedCountry,
    };

    if (widget.onSave != null) {
      widget.onSave!(data);
    } else {
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('បានរក្សាទុកទំនាក់ទំនង "$first"!'),
          backgroundColor: VvcTheme.accent,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: VvcTheme.primaryBg,
      appBar: VvcAppBar(
        backgroundColor: VvcTheme.primaryBg,
        elevation: 0,
        leading: TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(
            'Cancel',
            style: GoogleFonts.inter(color: VvcTheme.accent, fontSize: 16),
          ),
        ),
        leadingWidth: 80,
        centerTitle: true,
        title: Text(
          'New Contact',
          style: GoogleFonts.inter(color: Colors.white, fontSize: 17, fontWeight: FontWeight.bold),
        ),
        actions: [
          ValueListenableBuilder<TextEditingValue>(
            valueListenable: _firstNameCtrl,
            builder: (context, val, _) {
              final canSave = val.text.trim().isNotEmpty;
              return IconButton(
                icon: Icon(
                  Icons.check_rounded,
                  color: canSave ? VvcTheme.accent : VvcTheme.mutedText,
                  size: 24,
                ),
                onPressed: canSave ? _saveContact : null,
              );
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
        child: Column(
          children: [
            // Name Inputs Card
            Container(
              decoration: BoxDecoration(
                color: VvcTheme.cardBg,
                borderRadius: BorderRadius.circular(16),
              ),
              child: Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                    child: TextField(
                      controller: _firstNameCtrl,
                      style: GoogleFonts.inter(color: Colors.white, fontSize: 16),
                      decoration: InputDecoration(
                        hintText: 'First Name',
                        hintStyle: GoogleFonts.inter(color: VvcTheme.mutedText, fontSize: 16),
                        border: InputBorder.none,
                      ),
                    ),
                  ),
                  const Divider(color: VvcTheme.dividerColor, height: 1),
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                    child: TextField(
                      controller: _lastNameCtrl,
                      style: GoogleFonts.inter(color: Colors.white, fontSize: 16),
                      decoration: InputDecoration(
                        hintText: 'Last Name',
                        hintStyle: GoogleFonts.inter(color: VvcTheme.mutedText, fontSize: 16),
                        border: InputBorder.none,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),

            // Phone Input Card: Country Selector + Dial Code
            Container(
              decoration: BoxDecoration(
                color: VvcTheme.cardBg,
                borderRadius: BorderRadius.circular(16),
              ),
              child: Column(
                children: [
                  // Country selector row
                  ListTile(
                    leading: Text(_selectedFlag, style: const TextStyle(fontSize: 20)),
                    title: Text(
                      _selectedCountry,
                      style: GoogleFonts.inter(color: Colors.white, fontSize: 16),
                    ),
                    trailing: const Icon(Icons.chevron_right_rounded, color: VvcTheme.mutedText),
                    onTap: () {},
                  ),
                  const Divider(color: VvcTheme.dividerColor, height: 1),
                  // Phone input row
                  Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                    child: Row(
                      children: [
                        Text(
                          _dialCode,
                          style: GoogleFonts.inter(color: VvcTheme.accent, fontSize: 16, fontWeight: FontWeight.bold),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: TextField(
                            controller: _phoneCtrl,
                            keyboardType: TextInputType.phone,
                            style: GoogleFonts.inter(color: Colors.white, fontSize: 16),
                            decoration: InputDecoration(
                              hintText: '00 000 000',
                              hintStyle: GoogleFonts.inter(color: VvcTheme.mutedText, fontSize: 16),
                              border: InputBorder.none,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),

            // Actions Card: Sync Contact to Phone + Add via QR Code
            Container(
              decoration: BoxDecoration(
                color: VvcTheme.cardBg,
                borderRadius: BorderRadius.circular(16),
              ),
              child: Column(
                children: [
                  SwitchListTile(
                    title: Text(
                      'Sync Contact to Phone',
                      style: GoogleFonts.inter(color: Colors.white, fontSize: 15.5),
                    ),
                    value: _syncToPhone,
                    activeThumbColor: VvcTheme.accent,
                    onChanged: (val) => setState(() => _syncToPhone = val),
                  ),
                  const Divider(color: VvcTheme.dividerColor, height: 1),
                  ListTile(
                    leading: const Icon(Icons.qr_code_scanner_rounded, color: VvcTheme.accent),
                    title: Text(
                      'Add via QR Code',
                      style: GoogleFonts.inter(color: VvcTheme.accent, fontSize: 15.5, fontWeight: FontWeight.w500),
                    ),
                    onTap: () {},
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
