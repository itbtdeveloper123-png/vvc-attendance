import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../utils/app_theme.dart';

/// A5 Paper Format Widget for Request Forms
/// Simulates A5 paper size (148mm x 210mm) with proper styling
class A5PaperForm extends StatelessWidget {
  final Widget child;
  final String title;
  final String? subtitle;
  final VoidCallback? onPrint;
  final VoidCallback? onBack;

  const A5PaperForm({
    super.key,
    required this.child,
    required this.title,
    this.subtitle,
    this.onPrint,
    this.onBack,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(8),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.1),
            blurRadius: 10,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          _buildHeader(context),
          
          // Content
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: child,
            ),
          ),
          
          // Footer with signature section
          _buildFooter(),
        ],
      ),
    );
  }

  Widget _buildHeader(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [AppTheme.primary, AppTheme.primary.withValues(alpha: 0.8)],
        ),
        borderRadius: const BorderRadius.only(
          topLeft: Radius.circular(8),
          topRight: Radius.circular(8),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: GoogleFonts.koulen(
                        fontSize: 20,
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    if (subtitle != null) ...[
                      const SizedBox(height: 4),
                      Text(
                        subtitle!,
                        style: GoogleFonts.battambang(
                          fontSize: 12,
                          color: Colors.white.withValues(alpha: 0.9),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
              if (onPrint != null || onBack != null)
                Row(
                  children: [
                    if (onBack != null)
                      IconButton(
                        icon: const Icon(Icons.arrow_back, color: Colors.white),
                        onPressed: onBack,
                      ),
                    if (onPrint != null)
                      IconButton(
                        icon: const Icon(Icons.print, color: Colors.white),
                        onPressed: onPrint,
                      ),
                  ],
                ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildFooter() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.grey.withValues(alpha: 0.05),
        border: Border(
          top: BorderSide(color: Colors.grey.withValues(alpha: 0.2)),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'ហត្ថលេខា (Signatures)',
            style: GoogleFonts.koulen(
              fontSize: 14,
              color: AppTheme.textPrimary,
            ),
          ),
          const SizedBox(height: 12),
          const Row(
            children: [
              Expanded(
                child: _SignatureBox(
                  label: 'បុគ្គលិក (Employee)',
                ),
              ),
              SizedBox(width: 12),
              Expanded(
                child: _SignatureBox(
                  label: 'អ្នកគ្រប់គ្រង (Manager)',
                ),
              ),
              SizedBox(width: 12),
              Expanded(
                child: _SignatureBox(
                  label: 'ធនាគារ (HR)',
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _SignatureBox extends StatelessWidget {
  final String label;

  const _SignatureBox({required this.label});

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Container(
          height: 40,
          decoration: BoxDecoration(
            border: Border(
              bottom: BorderSide(color: Colors.grey.withValues(alpha: 0.3)),
            ),
          ),
        ),
        const SizedBox(height: 4),
        Text(
          label,
          style: GoogleFonts.battambang(
            fontSize: 10,
            color: AppTheme.textSecondary,
          ),
          textAlign: TextAlign.center,
        ),
      ],
    );
  }
}

/// A5 Form Section Widget
class A5FormSection extends StatelessWidget {
  final String title;
  final IconData? icon;
  final List<Widget> children;
  final bool isRequired;

  const A5FormSection({
    super.key,
    required this.title,
    this.icon,
    required this.children,
    this.isRequired = false,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Section title
          Row(
            children: [
              if (icon != null) ...[
                Icon(
                  icon,
                  size: 16,
                  color: AppTheme.primary,
                ),
                const SizedBox(width: 8),
              ],
              Text(
                title + (isRequired ? ' *' : ''),
                style: GoogleFonts.koulen(
                  fontSize: 14,
                  color: AppTheme.primary,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          
          // Section content
          ...children,
        ],
      ),
    );
  }
}

/// A5 Form Row Widget
class A5FormRow extends StatelessWidget {
  final List<Widget> children;
  final CrossAxisAlignment crossAxisAlignment;

  const A5FormRow({
    super.key,
    required this.children,
    this.crossAxisAlignment = CrossAxisAlignment.start,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: crossAxisAlignment,
      children: List.generate(children.length, (index) {
        final isLast = index == children.length - 1;
        return Expanded(
          child: Padding(
            padding: EdgeInsets.only(right: isLast ? 0 : 12),
            child: children[index],
          ),
        );
      }),
    );
  }
}

/// A5 Form Field Widget
class A5FormField extends StatelessWidget {
  final String label;
  final Widget child;
  final bool isRequired;

  const A5FormField({
    super.key,
    required this.label,
    required this.child,
    this.isRequired = false,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label + (isRequired ? ' *' : ''),
          style: GoogleFonts.battambang(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: AppTheme.textPrimary,
          ),
        ),
        const SizedBox(height: 6),
        child,
      ],
    );
  }
}

/// A5 Text Value Widget
class A5TextValue extends StatelessWidget {
  final String text;
  final String? placeholder;
  final double? height;
  final int? maxLines;

  const A5TextValue({
    super.key,
    required this.text,
    this.placeholder,
    this.height,
    this.maxLines,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      height: height,
      constraints: maxLines != null
          ? null
          : BoxConstraints(
              minHeight: height ?? 40,
            ),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: AppTheme.fieldFill,
        border: Border.all(color: AppTheme.fieldBorder),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        text.isNotEmpty ? text : (placeholder ?? ''),
        style: GoogleFonts.battambang(
          fontSize: 12,
          color: text.isNotEmpty ? AppTheme.textPrimary : AppTheme.helperTextColor,
        ),
        maxLines: maxLines,
        overflow: TextOverflow.ellipsis,
      ),
    );
  }
}

/// A5 Status Badge Widget
class A5StatusBadge extends StatelessWidget {
  final String status;

  const A5StatusBadge({super.key, required this.status});

  @override
  Widget build(BuildContext context) {
    Color backgroundColor;
    Color textColor;

    switch (status.toLowerCase()) {
      case 'pending':
        backgroundColor = const Color(0xFFFEF08A);
        textColor = const Color(0xFF854D0E);
        break;
      case 'approved':
        backgroundColor = const Color(0xFFBBF7D0);
        textColor = const Color(0xFF166534);
        break;
      case 'rejected':
        backgroundColor = const Color(0xFFFECACA);
        textColor = const Color(0xFF991B1B);
        break;
      default:
        backgroundColor = Colors.grey.withValues(alpha: 0.2);
        textColor = AppTheme.textPrimary;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: backgroundColor,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Text(
        status,
        style: GoogleFonts.battambang(
          fontSize: 10,
          color: textColor,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}

/// A5 Request Type Checkbox Widget
class A5RequestTypeCheckbox extends StatelessWidget {
  final String value;
  final String label;
  final IconData? icon;
  final bool isSelected;
  final ValueChanged<bool?>? onChanged;

  const A5RequestTypeCheckbox({
    super.key,
    required this.value,
    required this.label,
    this.icon,
    required this.isSelected,
    this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: () => onChanged?.call(!isSelected),
      borderRadius: BorderRadius.circular(6),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: isSelected ? AppTheme.primary : Colors.white,
          border: Border.all(
            color: isSelected ? AppTheme.primary : AppTheme.fieldBorder,
          ),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(
          children: [
            Checkbox(
              value: isSelected,
              onChanged: onChanged,
              materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
              visualDensity: VisualDensity.compact,
              activeColor: AppTheme.primary,
            ),
            if (icon != null) ...[
              const SizedBox(width: 8),
              Icon(
                icon,
                size: 16,
                color: isSelected ? Colors.white : AppTheme.primary,
              ),
              const SizedBox(width: 8),
            ],
            Expanded(
              child: Text(
                label,
                style: GoogleFonts.battambang(
                  fontSize: 12,
                  color: isSelected ? Colors.white : AppTheme.textPrimary,
                  fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// A5 Request Type Checkbox Group Widget
class A5RequestTypeCheckboxGroup extends StatelessWidget {
  final String selectedValue;
  final ValueChanged<String> onChanged;

  const A5RequestTypeCheckboxGroup({
    super.key,
    required this.selectedValue,
    required this.onChanged,
  });

  static const Map<String, _RequestTypeInfo> _requestTypes = {
    'leave': _RequestTypeInfo(
      value: 'leave',
      label: 'ច្បាប់ (Leave)',
      icon: Icons.calendar_today,
    ),
    'late': _RequestTypeInfo(
      value: 'late',
      label: 'មកយឺត (Late)',
      icon: Icons.access_time,
    ),
    'forgotten_scan': _RequestTypeInfo(
      value: 'forgotten_scan',
      label: 'ភ្លេចស្កេន (Forgotten Scan)',
      icon: Icons.fingerprint,
    ),
    'deo': _RequestTypeInfo(
      value: 'deo',
      label: 'ដេអូស (DEO)',
      icon: Icons.exit_to_app,
    ),
  };

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTheme.fieldFill,
        border: Border.all(color: AppTheme.fieldBorder),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'ប្រភេទសំណើ (Request Type)',
            style: GoogleFonts.koulen(
              fontSize: 12,
              color: AppTheme.primary,
            ),
          ),
          const SizedBox(height: 8),
          GridView.count(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            crossAxisCount: 2,
            mainAxisSpacing: 8,
            crossAxisSpacing: 8,
            childAspectRatio: 2.5,
            children: _requestTypes.entries.map((entry) {
              final info = entry.value;
              return A5RequestTypeCheckbox(
                value: info.value,
                label: info.label,
                icon: info.icon,
                isSelected: selectedValue == info.value,
                onChanged: (isSelected) {
                  if (isSelected == true) {
                    onChanged(info.value);
                  }
                },
              );
            }).toList(),
          ),
        ],
      ),
    );
  }
}

class _RequestTypeInfo {
  final String value;
  final String label;
  final IconData icon;

  const _RequestTypeInfo({
    required this.value,
    required this.label,
    required this.icon,
  });
}