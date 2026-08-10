import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class VvcDropdown<T> extends StatelessWidget {
  final T? value;
  final List<VvcDropdownItem<T>> items;
  final ValueChanged<T?> onChanged;
  final String? label;
  final String? hint;
  final IconData? prefixIcon;
  final bool isExpanded;
  final double? height;
  final EdgeInsetsGeometry? padding;
  final BoxDecoration? decoration;

  const VvcDropdown({
    super.key,
    required this.value,
    required this.items,
    required this.onChanged,
    this.label,
    this.hint,
    this.prefixIcon,
    this.isExpanded = true,
    this.height,
    this.padding,
    this.decoration,
  });

  @override
  Widget build(BuildContext meContext) {
    final selectedItem = items.firstWhere(
      (item) => item.value == value,
      orElse: () => items.isNotEmpty ? items.first : VvcDropdownItem<T>(value: value as T, label: hint ?? ''),
    );

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (label != null) ...[
          Text(
            label!,
            style: GoogleFonts.kantumruyPro(
              color: Colors.white70,
              fontSize: 13,
              fontWeight: FontWeight.w500,
            ),
          ),
          const SizedBox(height: 6),
        ],
        InkWell(
          onTap: () => _showPickerBottomSheet(meContext),
          borderRadius: BorderRadius.circular(14),
          child: Container(
            height: height ?? 46,
            padding: padding ?? const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
            decoration: decoration ??
                BoxDecoration(
                  color: const Color(0xFF1E1E2C),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(
                    color: Colors.white.withValues(alpha: 0.12),
                    width: 1,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: 0.2),
                      blurRadius: 8,
                      offset: const Offset(0, 3),
                    ),
                  ],
                ),
            child: Row(
              mainAxisSize: isExpanded ? MainAxisSize.max : MainAxisSize.min,
              children: [
                if (prefixIcon != null) ...[
                  Icon(prefixIcon, size: 18, color: Colors.amberAccent),
                  const SizedBox(width: 10),
                ],
                Expanded(
                  child: Text(
                    selectedItem.label.isNotEmpty ? selectedItem.label : (hint ?? ''),
                    style: GoogleFonts.kantumruyPro(
                      color: selectedItem.label.isNotEmpty ? Colors.white : Colors.white38,
                      fontSize: 13.5,
                      fontWeight: FontWeight.w500,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.all(4),
                  decoration: BoxDecoration(
                    color: Colors.amberAccent.withValues(alpha: 0.12),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(
                    Icons.unfold_more_rounded,
                    size: 16,
                    color: Colors.amberAccent,
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  void _showPickerBottomSheet(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (ctx) {
        return Container(
          constraints: BoxConstraints(
            maxHeight: MediaQuery.of(context).size.height * 0.7,
          ),
          decoration: const BoxDecoration(
            color: Color(0xFF161622),
            borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
            boxShadow: [
              BoxShadow(
                color: Colors.black54,
                blurRadius: 20,
                offset: Offset(0, -5),
              ),
            ],
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const SizedBox(height: 12),
              // Drag Handle
              Container(
                width: 42,
                height: 4.5,
                decoration: BoxDecoration(
                  color: Colors.white24,
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
              const SizedBox(height: 16),
              // Header Title
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: Row(
                  children: [
                    if (prefixIcon != null) ...[
                      Icon(prefixIcon, size: 22, color: Colors.amberAccent),
                      const SizedBox(width: 10),
                    ],
                    Text(
                      label ?? hint ?? 'ជ្រើសរើសជម្រើស',
                      style: GoogleFonts.kantumruyPro(
                        color: Colors.white,
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.close_rounded, color: Colors.white54, size: 20),
                      onPressed: () => Navigator.pop(ctx),
                    ),
                  ],
                ),
              ),
              const Divider(color: Colors.white10, height: 20),
              // Items List
              Flexible(
                child: ListView.separated(
                  padding: const EdgeInsets.fromLTRB(16, 4, 16, 24),
                  shrinkWrap: true,
                  itemCount: items.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 8),
                  itemBuilder: (context, index) {
                    final item = items[index];
                    final isSelected = item.value == value;

                    return InkWell(
                      onTap: () {
                        Navigator.pop(ctx);
                        onChanged(item.value);
                      },
                      borderRadius: BorderRadius.circular(14),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 13),
                        decoration: BoxDecoration(
                          color: isSelected
                              ? Colors.amberAccent.withValues(alpha: 0.15)
                              : Colors.white.withValues(alpha: 0.04),
                          borderRadius: BorderRadius.circular(14),
                          border: Border.all(
                            color: isSelected
                                ? Colors.amberAccent.withValues(alpha: 0.5)
                                : Colors.white.withValues(alpha: 0.06),
                            width: isSelected ? 1.5 : 1,
                          ),
                        ),
                        child: Row(
                          children: [
                            if (item.icon != null) ...[
                              Icon(
                                item.icon,
                                size: 20,
                                color: isSelected ? Colors.amberAccent : Colors.white70,
                              ),
                              const SizedBox(width: 12),
                            ],
                            Expanded(
                              child: Text(
                                item.label,
                                style: GoogleFonts.kantumruyPro(
                                  color: isSelected ? Colors.amberAccent : Colors.white,
                                  fontSize: 14,
                                  fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                                ),
                              ),
                            ),
                            if (isSelected)
                              const Icon(
                                Icons.check_circle_rounded,
                                size: 20,
                                color: Colors.amberAccent,
                              ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class VvcPopupMenuDropdown<T> extends StatelessWidget {
  final T? value;
  final List<VvcDropdownItem<T>> items;
  final ValueChanged<T?> onChanged;
  final String? hint;
  final double? height;
  final IconData? prefixIcon;

  const VvcPopupMenuDropdown({
    super.key,
    required this.value,
    required this.items,
    required this.onChanged,
    this.hint,
    this.height,
    this.prefixIcon,
  });

  @override
  Widget build(BuildContext context) {
    final selectedItem = items.firstWhere(
      (item) => item.value == value,
      orElse: () => items.isNotEmpty ? items.first : VvcDropdownItem<T>(value: value as T, label: hint ?? ''),
    );

    return PopupMenuButton<T>(
      initialValue: value,
      onSelected: onChanged,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(18),
        side: BorderSide(color: Colors.amberAccent.withValues(alpha: 0.3), width: 1.2),
      ),
      color: const Color(0xFF1E1E2E),
      elevation: 16,
      shadowColor: Colors.black.withValues(alpha: 0.6),
      offset: const Offset(0, 42),
      child: Container(
        height: height ?? 38,
        padding: const EdgeInsets.symmetric(horizontal: 12),
        decoration: BoxDecoration(
          color: const Color(0xFF252536),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: Colors.amberAccent.withValues(alpha: 0.3),
            width: 1,
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.3),
              blurRadius: 8,
              offset: const Offset(0, 3),
            ),
          ],
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (prefixIcon != null) ...[
              Icon(prefixIcon, size: 15, color: Colors.amberAccent),
              const SizedBox(width: 6),
            ],
            Flexible(
              child: Text(
                selectedItem.label.isNotEmpty ? selectedItem.label : (hint ?? ''),
                style: GoogleFonts.kantumruyPro(
                  color: Colors.white,
                  fontSize: 12.5,
                  fontWeight: FontWeight.w600,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
            const SizedBox(width: 6),
            const Icon(
              Icons.keyboard_arrow_down_rounded,
              size: 18,
              color: Colors.amberAccent,
            ),
          ],
        ),
      ),
      itemBuilder: (context) {
        return items.map((item) {
          final isSelected = item.value == value;
          return PopupMenuItem<T>(
            value: item.value,
            height: 42,
            padding: const EdgeInsets.symmetric(horizontal: 8),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              decoration: BoxDecoration(
                color: isSelected ? Colors.amberAccent.withValues(alpha: 0.18) : Colors.transparent,
                borderRadius: BorderRadius.circular(10),
                border: isSelected
                    ? Border.all(color: Colors.amberAccent.withValues(alpha: 0.4), width: 1)
                    : null,
              ),
              child: Row(
                children: [
                  if (item.icon != null) ...[
                    Icon(item.icon, size: 16, color: isSelected ? Colors.amberAccent : Colors.white70),
                    const SizedBox(width: 8),
                  ],
                  Expanded(
                    child: Text(
                      item.label,
                      style: GoogleFonts.kantumruyPro(
                        color: isSelected ? Colors.amberAccent : Colors.white,
                        fontSize: 13,
                        fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
                      ),
                    ),
                  ),
                  if (isSelected)
                    const Icon(
                      Icons.check_rounded,
                      size: 16,
                      color: Colors.amberAccent,
                    ),
                ],
              ),
            ),
          );
        }).toList();
      },
    );
  }
}

class VvcDropdownItem<T> {
  final T value;
  final String label;
  final IconData? icon;

  const VvcDropdownItem({
    required this.value,
    required this.label,
    this.icon,
  });
}
