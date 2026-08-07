import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Reusable VVC Dark Theme "New Poll" Modal Bottom Sheet Component
class VvcPollPickerBottomSheet extends StatefulWidget {
  final Function(Map<String, dynamic> pollData)? onSendPoll;
  final Function(String category)? onTabChanged;

  const VvcPollPickerBottomSheet({
    super.key,
    this.onSendPoll,
    this.onTabChanged,
  });

  static Future<T?> show<T>({
    required BuildContext context,
    Function(Map<String, dynamic> pollData)? onSendPoll,
    Function(String category)? onTabChanged,
  }) {
    return showModalBottomSheet<T>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => VvcPollPickerBottomSheet(
        onSendPoll: onSendPoll,
        onTabChanged: onTabChanged,
      ),
    );
  }

  @override
  State<VvcPollPickerBottomSheet> createState() => _VvcPollPickerBottomSheetState();
}

class _VvcPollPickerBottomSheetState extends State<VvcPollPickerBottomSheet> {
  final TextEditingController _questionController = TextEditingController();
  final TextEditingController _descriptionController = TextEditingController();
  
  final List<TextEditingController> _optionControllers = [
    TextEditingController(),
    TextEditingController(),
  ];

  // Settings Toggles
  bool _showWhoVoted = true;
  bool _allowMultipleAnswers = false;
  bool _allowAddingOptions = false;
  bool _allowRevoting = true;
  bool _shuffleOptions = false;

  // Theme Constants
  static const Color _bgColor = Color(0xFF1C1C1E);
  static const Color _cardColor = Color(0xFF2C2C2E);
  static const Color _accentColor = Color(0xFF3388FF);
  static const Color _dividerColor = Color(0x1FFFFFFF);
  static const Color _mutedColor = Color(0xFF8E8E93);
  static const Color _activeSwitchColor = Color(0xFF30D158);

  static const int _maxOptions = 10;

  @override
  void initState() {
    super.initState();
    _questionController.addListener(_updateState);
    for (var controller in _optionControllers) {
      controller.addListener(_updateState);
    }
  }

  void _updateState() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _questionController.dispose();
    _descriptionController.dispose();
    for (var controller in _optionControllers) {
      controller.dispose();
    }
    super.dispose();
  }

  bool get _canSend {
    final hasQuestion = _questionController.text.trim().isNotEmpty;
    final validOptionsCount = _optionControllers.where((c) => c.text.trim().isNotEmpty).length;
    return hasQuestion && validOptionsCount >= 2;
  }

  void _addOption() {
    if (_optionControllers.length < _maxOptions) {
      final controller = TextEditingController();
      controller.addListener(_updateState);
      setState(() {
        _optionControllers.add(controller);
      });
    }
  }

  void _removeOption(int index) {
    if (_optionControllers.length > 2) {
      setState(() {
        _optionControllers[index].dispose();
        _optionControllers.removeAt(index);
      });
    } else {
      _optionControllers[index].clear();
    }
  }

  void _submitPoll() {
    if (!_canSend) return;

    final question = _questionController.text.trim();
    final description = _descriptionController.text.trim();
    final options = _optionControllers
        .map((c) => c.text.trim())
        .where((text) => text.isNotEmpty)
        .toList();

    final pollData = {
      'question': question,
      'description': description,
      'options': options,
      'showWhoVoted': _showWhoVoted,
      'allowMultipleAnswers': _allowMultipleAnswers,
      'allowAddingOptions': _allowAddingOptions,
      'allowRevoting': _allowRevoting,
      'shuffleOptions': _shuffleOptions,
      'createdAt': DateTime.now().toIso8601String(),
    };

    Navigator.pop(context);
    widget.onSendPoll?.call(pollData);
  }

  @override
  Widget build(BuildContext context) {
    final double maxSheetHeight = MediaQuery.of(context).size.height * 0.90;
    final double bottomPadding = MediaQuery.of(context).viewInsets.bottom;

    return Container(
      constraints: BoxConstraints(maxHeight: maxSheetHeight),
      decoration: const BoxDecoration(
        color: _bgColor,
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: 10),
          Center(
            child: Container(
              width: 36,
              height: 4.5,
              decoration: BoxDecoration(
                color: const Color(0xFF48484A),
                borderRadius: BorderRadius.circular(2.5),
              ),
            ),
          ),
          const SizedBox(height: 8),

          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16.0, vertical: 4.0),
            child: _buildHeader(),
          ),
          const SizedBox(height: 12),

          Expanded(
            child: SingleChildScrollView(
              physics: const BouncingScrollPhysics(),
              padding: EdgeInsets.fromLTRB(16.0, 0.0, 16.0, bottomPadding + 20.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _buildSectionHeader('QUESTION'),
                  _buildQuestionCard(),
                  const SizedBox(height: 24),

                  _buildSectionHeader('POLL OPTIONS'),
                  _buildOptionsCard(),
                  const SizedBox(height: 6),
                  Padding(
                    padding: const EdgeInsets.only(left: 4.0),
                    child: Text(
                      'You can add ${_maxOptions - _optionControllers.length} more options.',
                      style: GoogleFonts.inter(color: _mutedColor, fontSize: 12.0),
                    ),
                  ),
                  const SizedBox(height: 24),

                  _buildSectionHeader('SETTINGS'),
                  _buildSettingsCard(),
                  const SizedBox(height: 24),
                ],
              ),
            ),
          ),
          _buildBottomNavBar(),
        ],
      ),
    );
  }

  Widget _buildBottomNavBar() {
    final categories = [
      {'label': 'Gallery', 'icon': Icons.photo_library_outlined, 'selectedIcon': Icons.photo_library_rounded},
      {'label': 'File', 'icon': Icons.insert_drive_file_outlined, 'selectedIcon': Icons.insert_drive_file_rounded},
      {'label': 'Location', 'icon': Icons.location_on_outlined, 'selectedIcon': Icons.location_on_rounded},
      {'label': 'Poll', 'icon': Icons.poll_outlined, 'selectedIcon': Icons.poll_rounded},
      {'label': 'Contact', 'icon': Icons.person_outline_rounded, 'selectedIcon': Icons.person_rounded},
    ];

    return Container(
      decoration: const BoxDecoration(
        color: Color(0xFF141416),
        border: Border(top: BorderSide(color: Color(0x1AFFFFFF), width: 0.5)),
      ),
      padding: EdgeInsets.only(
        top: 8,
        bottom: MediaQuery.of(context).padding.bottom > 0
            ? MediaQuery.of(context).padding.bottom + 4
            : 10,
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: categories.map((cat) {
          final String label = cat['label'] as String;
          final bool isSelected = label == 'Poll';

          return InkWell(
            onTap: () {
              if (label != 'Poll') {
                widget.onTabChanged?.call(label);
              }
            },
            borderRadius: BorderRadius.circular(16),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    padding: const EdgeInsets.all(6),
                    decoration: BoxDecoration(
                      color: isSelected ? _accentColor.withValues(alpha: 0.2) : Colors.transparent,
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      isSelected ? (cat['selectedIcon'] as IconData) : (cat['icon'] as IconData),
                      color: isSelected ? _accentColor : _mutedColor,
                      size: 22,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    label,
                    style: GoogleFonts.inter(
                      color: isSelected ? _accentColor : _mutedColor,
                      fontSize: 11,
                      fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                    ),
                  ),
                ],
              ),
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _buildHeader() {
    return SizedBox(
      height: 40,
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          IconButton(
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
            icon: const Icon(Icons.close_rounded, color: Colors.white, size: 24),
            onPressed: () => Navigator.pop(context),
          ),
          Text(
            'New Poll',
            style: GoogleFonts.inter(
              color: Colors.white,
              fontSize: 17,
              fontWeight: FontWeight.bold,
            ),
          ),
          InkWell(
            onTap: _canSend ? _submitPoll : null,
            borderRadius: BorderRadius.circular(16),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 200),
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
              decoration: BoxDecoration(
                color: _canSend ? _accentColor : const Color(0xFF3A3A3C),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Text(
                'Send',
                style: GoogleFonts.inter(
                  color: _canSend ? Colors.white : _mutedColor,
                  fontSize: 14.5,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionHeader(String title) {
    return Padding(
      padding: const EdgeInsets.only(left: 4.0, bottom: 8.0),
      child: Text(
        title,
        style: GoogleFonts.inter(
          color: _mutedColor,
          fontSize: 12.0,
          fontWeight: FontWeight.w600,
          letterSpacing: 0.5,
        ),
      ),
    );
  }

  Widget _buildQuestionCard() {
    return Container(
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
            child: TextField(
              controller: _questionController,
              style: GoogleFonts.inter(color: Colors.white, fontSize: 16),
              cursorColor: _accentColor,
              decoration: InputDecoration(
                hintText: 'Ask a Question',
                hintStyle: GoogleFonts.inter(color: _mutedColor, fontSize: 16),
                border: InputBorder.none,
                isDense: true,
                contentPadding: const EdgeInsets.symmetric(vertical: 12),
              ),
            ),
          ),
          const Divider(height: 1, color: _dividerColor, indent: 16),

          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _descriptionController,
                    style: GoogleFonts.inter(color: Colors.white, fontSize: 15),
                    cursorColor: _accentColor,
                    decoration: InputDecoration(
                      hintText: 'Add Description (optional)',
                      hintStyle: GoogleFonts.inter(color: _mutedColor, fontSize: 15),
                      border: InputBorder.none,
                      isDense: true,
                      contentPadding: const EdgeInsets.symmetric(vertical: 12),
                    ),
                  ),
                ),
                const Icon(
                  Icons.attach_file_rounded,
                  color: _mutedColor,
                  size: 22,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildOptionsCard() {
    return Container(
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          ...List.generate(_optionControllers.length, (index) {
            return Column(
              children: [
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 2),
                  child: Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: _optionControllers[index],
                          style: GoogleFonts.inter(color: Colors.white, fontSize: 15.5),
                          cursorColor: _accentColor,
                          decoration: InputDecoration(
                            hintText: 'Option ${index + 1}',
                            hintStyle: GoogleFonts.inter(color: _mutedColor, fontSize: 15.5),
                            border: InputBorder.none,
                            isDense: true,
                            contentPadding: const EdgeInsets.symmetric(vertical: 12),
                          ),
                        ),
                      ),
                      if (_optionControllers[index].text.isNotEmpty || _optionControllers.length > 2)
                        IconButton(
                          padding: EdgeInsets.zero,
                          constraints: const BoxConstraints(),
                          icon: const Icon(Icons.remove_circle_outline_rounded, color: _mutedColor, size: 20),
                          onPressed: () => _removeOption(index),
                        ),
                    ],
                  ),
                ),
                const Divider(height: 1, color: _dividerColor, indent: 16),
              ],
            );
          }),

          if (_optionControllers.length < _maxOptions)
            InkWell(
              onTap: _addOption,
              borderRadius: const BorderRadius.vertical(bottom: Radius.circular(16)),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                child: Row(
                  children: [
                    const Icon(Icons.add_rounded, color: _accentColor, size: 22),
                    const SizedBox(width: 10),
                    Text(
                      'Add an Option',
                      style: GoogleFonts.inter(
                        color: _accentColor,
                        fontSize: 15.5,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildSettingsCard() {
    return Container(
      decoration: BoxDecoration(
        color: _cardColor,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          _buildSwitchTile(
            icon: Icons.visibility_rounded,
            iconBgColor: const Color(0xFF0A84FF),
            title: 'Show Who Voted',
            subtitle: 'Votes are visible to everyone',
            value: _showWhoVoted,
            onChanged: (val) => setState(() => _showWhoVoted = val),
          ),
          const Divider(height: 1, color: _dividerColor, indent: 56),

          _buildSwitchTile(
            icon: Icons.checklist_rounded,
            iconBgColor: const Color(0xFFFF9F0A),
            title: 'Allow Multiple Answers',
            subtitle: 'Voters can select more than one answer',
            value: _allowMultipleAnswers,
            onChanged: (val) => setState(() => _allowMultipleAnswers = val),
          ),
          const Divider(height: 1, color: _dividerColor, indent: 56),

          _buildSwitchTile(
            icon: Icons.add_circle_outline_rounded,
            iconBgColor: const Color(0xFF30B0C7),
            title: 'Allow Adding Options',
            subtitle: 'Voters can add new options to the poll',
            value: _allowAddingOptions,
            onChanged: (val) => setState(() => _allowAddingOptions = val),
          ),
          const Divider(height: 1, color: _dividerColor, indent: 56),

          _buildSwitchTile(
            icon: Icons.autorenew_rounded,
            iconBgColor: const Color(0xFFBF5AF2),
            title: 'Allow Revoting',
            subtitle: 'Voters can change their vote later',
            value: _allowRevoting,
            onChanged: (val) => setState(() => _allowRevoting = val),
          ),
          const Divider(height: 1, color: _dividerColor, indent: 56),

          _buildSwitchTile(
            icon: Icons.shuffle_rounded,
            iconBgColor: const Color(0xFFFF375F),
            title: 'Shuffle Options',
            subtitle: 'Options will appear in random order',
            value: _shuffleOptions,
            onChanged: (val) => setState(() => _shuffleOptions = val),
          ),
        ],
      ),
    );
  }

  Widget _buildSwitchTile({
    required IconData icon,
    required Color iconBgColor,
    required String title,
    required String subtitle,
    required bool value,
    required ValueChanged<bool> onChanged,
  }) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 14.0, vertical: 10.0),
      child: Row(
        children: [
          Container(
            width: 32,
            height: 32,
            decoration: BoxDecoration(
              color: iconBgColor,
              shape: BoxShape.circle,
            ),
            child: Icon(icon, color: Colors.white, size: 18),
          ),
          const SizedBox(width: 12),

          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: GoogleFonts.inter(
                    color: Colors.white,
                    fontSize: 15,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  subtitle,
                  style: GoogleFonts.inter(
                    color: _mutedColor,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 8),

          Switch(
            value: value,
            activeThumbColor: Colors.white,
            activeTrackColor: _activeSwitchColor,
            inactiveThumbColor: const Color(0xFFE5E5EA),
            inactiveTrackColor: const Color(0xFF48484A),
            materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
            onChanged: onChanged,
          ),
        ],
      ),
    );
  }
}
