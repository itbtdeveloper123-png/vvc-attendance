import 'dart:io';
import 'package:flutter/material.dart';

/// Filter selection widget with visual previews
/// 
/// Features:
/// - Visual thumbnails for each filter
/// - Animated selection indicator
/// - Customizable filter options
/// - Loading state support
class FilterSelectionWidget extends StatelessWidget {
  final String baseImagePath;
  final String selectedFilter;
  final List<FilterOption> filters;
  final Function(String) onFilterSelected;
  final bool isLoading;

  const FilterSelectionWidget({
    Key? key,
    required this.baseImagePath,
    required this.selectedFilter,
    required this.filters,
    required this.onFilterSelected,
    this.isLoading = false,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 120,
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: isLoading
          ? const Center(
              child: CircularProgressIndicator(),
            )
          : ListView.builder(
              scrollDirection: Axis.horizontal,
              padding: const EdgeInsets.symmetric(horizontal: 8),
              itemCount: filters.length,
              itemBuilder: (context, index) {
                final filter = filters[index];
                final isSelected = selectedFilter == filter.id;

                return Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 4),
                  child: _FilterChip(
                    filter: filter,
                    isSelected: isSelected,
                    baseImagePath: baseImagePath,
                    onTap: () => onFilterSelected(filter.id),
                  ),
                );
              },
            ),
    );
  }
}

/// Individual filter chip widget
class _FilterChip extends StatelessWidget {
  final FilterOption filter;
  final bool isSelected;
  final String baseImagePath;
  final VoidCallback onTap;

  const _FilterChip({
    Key? key,
    required this.filter,
    required this.isSelected,
    required this.baseImagePath,
    required this.onTap,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        width: 80,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: isSelected
                ? Theme.of(context).primaryColor
                : Colors.grey[300]!,
            width: isSelected ? 3 : 1,
          ),
          boxShadow: isSelected
              ? [
                  BoxShadow(
                    color: Theme.of(context).primaryColor.withOpacity(0.3),
                    blurRadius: 8,
                    spreadRadius: 2,
                  ),
                ]
              : null,
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Filter thumbnail
            Expanded(
              child: ClipRRect(
                borderRadius: const BorderRadius.vertical(
                  top: Radius.circular(8),
                ),
                child: Stack(
                  fit: StackFit.expand,
                  children: [
                    Image.file(
                      File(baseImagePath),
                      fit: BoxFit.cover,
                      errorBuilder: (context, error, stackTrace) {
                        return Container(
                          color: Colors.grey[200],
                          child: const Icon(Icons.broken_image),
                        );
                      },
                    ),
                    // Filter overlay
                    if (filter.overlayColor != null)
                      Container(
                        color: filter.overlayColor,
                      ),
                  ],
                ),
              ),
            ),
            // Filter label
            Container(
              padding: const EdgeInsets.symmetric(vertical: 4),
              decoration: BoxDecoration(
                color: isSelected
                    ? Theme.of(context).primaryColor
                    : Colors.grey[100],
                borderRadius: const BorderRadius.vertical(
                  bottom: Radius.circular(8),
                ),
              ),
              child: Text(
                filter.label,
                style: TextStyle(
                  fontSize: 10,
                  fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                  color: isSelected ? Colors.white : Colors.black87,
                ),
                textAlign: TextAlign.center,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Filter option data class
class FilterOption {
  final String id;
  final String label;
  final String description;
  final Color? overlayColor;
  final IconData? icon;

  const FilterOption({
    required this.id,
    required this.label,
    required this.description,
    this.overlayColor,
    this.icon,
  });

  /// Predefined filter options for document scanning
  static const List<FilterOption> documentFilters = [
    FilterOption(
      id: 'original',
      label: 'Original',
      description: 'No filter applied',
      icon: Icons.image,
    ),
    FilterOption(
      id: 'magic_color',
      label: 'Magic Color',
      description: 'Enhanced contrast and clean background',
      overlayColor: Color.fromRGBO(255, 255, 255, 0.1),
      icon: Icons.auto_fix_high,
    ),
    FilterOption(
      id: 'bw',
      label: 'B&W',
      description: 'Pure black and white',
      overlayColor: Color.fromRGBO(0, 0, 0, 0.3),
      icon: Icons.filter_b_and_w,
    ),
    FilterOption(
      id: 'enhanced',
      label: 'Enhanced',
      description: 'Improved brightness and contrast',
      overlayColor: Color.fromRGBO(255, 255, 0, 0.1),
      icon: Icons.brightness_6,
    ),
  ];
}

/// Filter selection dialog for advanced options
class FilterSelectionDialog extends StatelessWidget {
  final String selectedFilter;
  final List<FilterOption> filters;
  final Function(String) onFilterSelected;

  const FilterSelectionDialog({
    Key? key,
    required this.selectedFilter,
    required this.filters,
    required this.onFilterSelected,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Select Filter'),
      content: SizedBox(
        width: double.maxFinite,
        child: ListView.builder(
          shrinkWrap: true,
          itemCount: filters.length,
          itemBuilder: (context, index) {
            final filter = filters[index];
            final isSelected = selectedFilter == filter.id;

            return ListTile(
              leading: filter.icon != null
                  ? Icon(filter.icon)
                  : const Icon(Icons.filter),
              title: Text(filter.label),
              subtitle: Text(filter.description),
              trailing: isSelected
                  ? Icon(
                      Icons.check_circle,
                      color: Theme.of(context).primaryColor,
                    )
                  : null,
              selected: isSelected,
              onTap: () {
                onFilterSelected(filter.id);
                Navigator.of(context).pop();
              },
            );
          },
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
      ],
    );
  }

  /// Show the filter selection dialog
  static Future<String?> show(
    BuildContext context, {
    required String selectedFilter,
    List<FilterOption>? filters,
  }) {
    return showDialog<String>(
      context: context,
      builder: (context) => FilterSelectionDialog(
        selectedFilter: selectedFilter,
        filters: filters ?? FilterOption.documentFilters,
        onFilterSelected: (filter) => filter,
      ),
    );
  }
}
