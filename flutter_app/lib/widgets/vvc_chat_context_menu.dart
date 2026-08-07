import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

// ============================================================================
// MESSAGE TYPE ENUM
// ============================================================================
enum ChatMessageType {
  voice,
  image,
  file,
  text,
}

// ============================================================================
// CONTEXT MENU ACTION ITEM MODEL
// ============================================================================
class ContextMenuItem {
  final String label;
  final String labelKhmer;
  final IconData icon;
  final VoidCallback onTap;
  final bool isDestructive;
  final bool isDivider;

  const ContextMenuItem({
    required this.label,
    required this.labelKhmer,
    required this.icon,
    required this.onTap,
    this.isDestructive = false,
    this.isDivider = false,
  });

  const ContextMenuItem.divider()
      : label = '',
        labelKhmer = '',
        icon = Icons.remove,
        onTap = _emptyFn,
        isDestructive = false,
        isDivider = true;

  static void _emptyFn() {}
}

// ============================================================================
// MAIN VVC CONTEXT MENU HELPER CLASS
// ============================================================================
class VvcChatContextMenu {
  /// Shows the VVC Dark Theme context menu overlay directly over the tapped widget
  static void show({
    required BuildContext context,
    required GlobalKey widgetKey,
    required ChatMessageType messageType,
    required Widget childWidget,
    List<String>? customEmojis,
    Function(String emoji)? onReactionSelected,
    VoidCallback? onReply,
    VoidCallback? onCopy,
    VoidCallback? onSave,
    VoidCallback? onEdit,
    VoidCallback? onPin,
    VoidCallback? onForward,
    VoidCallback? onDelete,
    VoidCallback? onSelect,
  }) {
    final renderBox = widgetKey.currentContext?.findRenderObject() as RenderBox?;
    if (renderBox == null) return;

    final targetOffset = renderBox.localToGlobal(Offset.zero);
    final targetSize = renderBox.size;

    late OverlayEntry overlayEntry;

    overlayEntry = OverlayEntry(
      builder: (ctx) {
        return _VvcContextMenuOverlay(
          targetOffset: targetOffset,
          targetSize: targetSize,
          messageType: messageType,
          childWidget: childWidget,
          customEmojis: customEmojis,
          onReactionSelected: (emoji) {
            overlayEntry.remove();
            onReactionSelected?.call(emoji);
          },
          onReply: () {
            overlayEntry.remove();
            onReply?.call();
          },
          onCopy: () {
            overlayEntry.remove();
            onCopy?.call();
          },
          onSave: () {
            overlayEntry.remove();
            onSave?.call();
          },
          onEdit: () {
            overlayEntry.remove();
            onEdit?.call();
          },
          onPin: () {
            overlayEntry.remove();
            onPin?.call();
          },
          onForward: () {
            overlayEntry.remove();
            onForward?.call();
          },
          onDelete: () {
            overlayEntry.remove();
            onDelete?.call();
          },
          onSelect: () {
            overlayEntry.remove();
            onSelect?.call();
          },
          onDismiss: () => overlayEntry.remove(),
        );
      },
    );

    Overlay.of(context).insert(overlayEntry);
  }
}

// ============================================================================
// VVC CONTEXT MENU WRAPPER WIDGET (EASY TO WRAP ANY MESSAGE BUBBLE)
// ============================================================================
class VvcMessageContextMenuWrapper extends StatelessWidget {
  final ChatMessageType messageType;
  final Widget child;
  final List<String>? customEmojis;
  final Function(String emoji)? onReactionSelected;
  final VoidCallback? onReply;
  final VoidCallback? onCopy;
  final VoidCallback? onSave;
  final VoidCallback? onEdit;
  final VoidCallback? onPin;
  final VoidCallback? onForward;
  final VoidCallback? onDelete;
  final VoidCallback? onSelect;

  VvcMessageContextMenuWrapper({
    super.key,
    required this.messageType,
    required this.child,
    this.customEmojis,
    this.onReactionSelected,
    this.onReply,
    this.onCopy,
    this.onSave,
    this.onEdit,
    this.onPin,
    this.onForward,
    this.onDelete,
    this.onSelect,
  });

  final GlobalKey _key = GlobalKey();

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      key: _key,
      onLongPress: () {
        VvcChatContextMenu.show(
          context: context,
          widgetKey: _key,
          messageType: messageType,
          childWidget: child,
          customEmojis: customEmojis,
          onReactionSelected: onReactionSelected,
          onReply: onReply,
          onCopy: onCopy,
          onSave: onSave,
          onEdit: onEdit,
          onPin: onPin,
          onForward: onForward,
          onDelete: onDelete,
          onSelect: onSelect,
        );
      },
      child: child,
    );
  }
}

// ============================================================================
// OVERLAY WIDGET IMPLEMENTATION WITH BLUR & DYNAMIC POSITIONING
// ============================================================================
class _VvcContextMenuOverlay extends StatefulWidget {
  final Offset targetOffset;
  final Size targetSize;
  final ChatMessageType messageType;
  final Widget childWidget;
  final List<String>? customEmojis;
  final Function(String emoji) onReactionSelected;
  final VoidCallback onReply;
  final VoidCallback onCopy;
  final VoidCallback onSave;
  final VoidCallback onEdit;
  final VoidCallback onPin;
  final VoidCallback onForward;
  final VoidCallback onDelete;
  final VoidCallback onSelect;
  final VoidCallback onDismiss;

  const _VvcContextMenuOverlay({
    required this.targetOffset,
    required this.targetSize,
    required this.messageType,
    required this.childWidget,
    this.customEmojis,
    required this.onReactionSelected,
    required this.onReply,
    required this.onCopy,
    required this.onSave,
    required this.onEdit,
    required this.onPin,
    required this.onForward,
    required this.onDelete,
    required this.onSelect,
    required this.onDismiss,
  });

  @override
  State<_VvcContextMenuOverlay> createState() => _VvcContextMenuOverlayState();
}

class _VvcContextMenuOverlayState extends State<_VvcContextMenuOverlay>
    with SingleTickerProviderStateMixin {
  late AnimationController _animController;
  late Animation<double> _scaleAnim;
  late Animation<double> _fadeAnim;

  static const Color _cardBg = Color(0xFF2C2C2E);
  static const Color _accentColor = Color(0xFF3388FF);
  static const Color _dangerColor = Color(0xFFFF453A);
  static const Color _dividerColor = Color(0x1AFFFFFF);

  final List<String> _defaultEmojis = const ['⭐', '✏️', '💡', '📅', '🔥', '⚡', '👍', '❤️', '😆'];

  @override
  void initState() {
    super.initState();
    _animController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 220),
    );
    _scaleAnim = CurvedAnimation(parent: _animController, curve: Curves.easeOutBack);
    _fadeAnim = CurvedAnimation(parent: _animController, curve: Curves.easeOut);

    _animController.forward();
  }

  @override
  void dispose() {
    _animController.dispose();
    super.dispose();
  }

  void _dismissWithAnimation() {
    _animController.reverse().then((_) => widget.onDismiss());
  }

  List<ContextMenuItem> _buildMenuItems() {
    final List<ContextMenuItem> items = [];

    // 1. Reply (Always present)
    items.add(
      ContextMenuItem(
        label: 'Reply',
        labelKhmer: 'ឆ្លើយតប',
        icon: Icons.reply_rounded,
        onTap: widget.onReply,
      ),
    );

    // 2. Copy (Only for text and image)
    if (widget.messageType == ChatMessageType.image || widget.messageType == ChatMessageType.text) {
      items.add(
        ContextMenuItem(
          label: 'Copy',
          labelKhmer: 'ចម្លង (Copy)',
          icon: Icons.copy_rounded,
          onTap: widget.onCopy,
        ),
      );
    }

    // 3. Save Option (Conditional based on MessageType)
    if (widget.messageType == ChatMessageType.image) {
      items.add(
        ContextMenuItem(
          label: 'Save Image',
          labelKhmer: 'រក្សាទុករូបភាព (Save Image)',
          icon: Icons.download_rounded,
          onTap: widget.onSave,
        ),
      );
    } else if (widget.messageType == ChatMessageType.file) {
      items.add(
        ContextMenuItem(
          label: 'Save to Files',
          labelKhmer: 'រក្សាទុកក្នុង Files (Save to Files)',
          icon: Icons.folder_open_rounded,
          onTap: widget.onSave,
        ),
      );
    }

    // 4. Edit
    items.add(
      ContextMenuItem(
        label: 'Edit',
        labelKhmer: 'កែប្រែ (Edit)',
        icon: Icons.edit_outlined,
        onTap: widget.onEdit,
      ),
    );

    // 5. Pin
    items.add(
      ContextMenuItem(
        label: 'Pin',
        labelKhmer: 'ប៊ិនទុក (Pin)',
        icon: Icons.push_pin_outlined,
        onTap: widget.onPin,
      ),
    );

    // 6. Forward
    items.add(
      ContextMenuItem(
        label: 'Forward',
        labelKhmer: 'បញ្ជូនបន្ត (Forward)',
        icon: Icons.shortcut_rounded,
        onTap: widget.onForward,
      ),
    );

    // 7. Delete (Destructive red)
    items.add(
      ContextMenuItem(
        label: 'Delete',
        labelKhmer: 'លុបសារ (Delete)',
        icon: Icons.delete_outline_rounded,
        onTap: widget.onDelete,
        isDestructive: true,
      ),
    );

    // 8. Separator Divider
    items.add(const ContextMenuItem.divider());

    // 9. Select
    items.add(
      ContextMenuItem(
        label: 'Select',
        labelKhmer: 'ជ្រើសរើស (Select)',
        icon: Icons.check_circle_outline_rounded,
        onTap: widget.onSelect,
      ),
    );

    return items;
  }

  @override
  Widget build(BuildContext context) {
    final screenSize = MediaQuery.of(context).size;
    final menuItems = _buildMenuItems();

    final bool isImage = widget.messageType == ChatMessageType.image;
    final bool isMineRight = widget.targetOffset.dx > screenSize.width * 0.4;
    final double containerWidth = widget.targetSize.width.clamp(250.0, screenSize.width * 0.78);

    // Compute left position so menu card NEVER clips off screen left or right
    double computedLeft = widget.targetOffset.dx;
    if (computedLeft + containerWidth > screenSize.width - 16.0) {
      computedLeft = screenSize.width - containerWidth - 16.0;
    }
    if (computedLeft < 16.0) {
      computedLeft = 16.0;
    }

    final double topSafeArea = MediaQuery.of(context).padding.top + 12.0;
    final double bottomSafeArea = MediaQuery.of(context).padding.bottom + 16.0;

    // Max height for preview image/widget to leave ample room for menu actions
    final double maxPreviewHeight = isImage ? screenSize.height * 0.28 : 160.0;
    final double menuCardEstimatedHeight = (menuItems.length * 44.0) + 16.0;
    final double totalEstimatedOverlayHeight = maxPreviewHeight + 8.0 + menuCardEstimatedHeight;

    // Calculate maximum allowed top offset so the bottom NEVER overflows screen
    final double maxTopAllowed = (screenSize.height - bottomSafeArea - totalEstimatedOverlayHeight)
        .clamp(topSafeArea, screenSize.height - 100.0);

    // Calculate safe top position for overlay
    double computedTop = widget.targetOffset.dy;
    if (computedTop + totalEstimatedOverlayHeight > screenSize.height - bottomSafeArea) {
      computedTop = maxTopAllowed;
    } else {
      computedTop = computedTop.clamp(topSafeArea, maxTopAllowed);
    }

    Widget constrainedChild = ConstrainedBox(
      constraints: BoxConstraints(
        maxHeight: maxPreviewHeight,
        maxWidth: containerWidth,
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(16.0),
        child: FittedBox(
          fit: BoxFit.scaleDown,
          alignment: isMineRight ? Alignment.topRight : Alignment.topLeft,
          child: widget.childWidget,
        ),
      ),
    );

    return Stack(
      children: [
        // A. Darkened / Blurred Backdrop
        Positioned.fill(
          child: GestureDetector(
            onTap: _dismissWithAnimation,
            child: FadeTransition(
              opacity: _fadeAnim,
              child: BackdropFilter(
                filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
                child: Container(
                  color: Colors.black.withValues(alpha: 0.55),
                ),
              ),
            ),
          ),
        ),

        // B. Target Bubble + Clean Context Action Menu (Wrapped in Material)
        Positioned(
          left: computedLeft,
          top: computedTop,
          width: containerWidth,
          child: Material(
            color: Colors.transparent,
            child: AnimatedBuilder(
              animation: _animController,
              builder: (context, _) {
                return ScaleTransition(
                  scale: _scaleAnim,
                  alignment: isMineRight ? Alignment.topRight : Alignment.topLeft,
                  child: ConstrainedBox(
                    constraints: BoxConstraints(
                      maxHeight: screenSize.height - topSafeArea - bottomSafeArea,
                    ),
                    child: SingleChildScrollView(
                      physics: const BouncingScrollPhysics(),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        crossAxisAlignment: isMineRight ? CrossAxisAlignment.end : CrossAxisAlignment.start,
                        children: [
                          // 1. Focused Target Message Bubble Preview
                          constrainedChild,
                          const SizedBox(height: 8.0),
                          // 2. Clean Context Action Menu Card (#2C2C2E)
                          _buildContextMenuCard(menuItems),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildReactionPillBar(List<String> emojis) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: _cardBg,
        borderRadius: BorderRadius.circular(30),
        border: Border.all(color: Colors.white.withValues(alpha: 0.12), width: 0.8),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.4),
            blurRadius: 16,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        physics: const BouncingScrollPhysics(),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: emojis.map((emoji) {
            return InkWell(
              onTap: () {
                _dismissWithAnimation();
                widget.onReactionSelected(emoji);
              },
              borderRadius: BorderRadius.circular(20),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                child: Text(
                  emoji,
                  style: const TextStyle(fontSize: 22),
                ),
              ),
            );
          }).toList(),
        ),
      ),
    );
  }

  Widget _buildContextMenuCard(List<ContextMenuItem> items) {
    return Container(
      width: 250,
      decoration: BoxDecoration(
        color: _cardBg,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.white.withValues(alpha: 0.12), width: 0.8),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.4),
            blurRadius: 20,
            offset: const Offset(0, 6),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: items.map((item) {
          if (item.isDivider) {
            return const Divider(height: 1, color: _dividerColor);
          }

          final Color textColor = item.isDestructive ? _dangerColor : Colors.white;
          final Color iconColor = item.isDestructive ? _dangerColor : _accentColor;

          return InkWell(
            onTap: () {
              _dismissWithAnimation();
              item.onTap();
            },
            borderRadius: BorderRadius.circular(12),
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: Row(
                children: [
                  Icon(item.icon, color: iconColor, size: 20),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Text(
                      item.labelKhmer,
                      style: GoogleFonts.kantumruyPro(
                        color: textColor,
                        fontSize: 14.5,
                        fontWeight: item.isDestructive ? FontWeight.bold : FontWeight.w500,
                      ),
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
}
