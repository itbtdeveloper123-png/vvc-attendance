import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../providers/user_provider.dart';
import 'app_theme.dart';

/// Resolves branch for request forms: saved request data first, then user profile.
String resolveRequestBranch({
  Map<String, dynamic>? initialData,
  required UserProvider user,
}) {
  if (initialData != null) {
    final saved = (initialData['branch'] ?? '').toString().trim();
    if (saved.isNotEmpty) return saved;
  }
  return (user.branch ?? '').trim();
}

void applyUserBranch({
  required TextEditingController controller,
  Map<String, dynamic>? initialData,
  required UserProvider user,
}) {
  controller.text = resolveRequestBranch(initialData: initialData, user: user);
}

Widget buildReadOnlyBranchField(
  TextEditingController controller, {
  InputDecoration? decoration,
}) {
  return TextFormField(
    controller: controller,
    readOnly: true,
    style: GoogleFonts.inter(
      color: AppTheme.textPrimary,
      fontSize: 14,
    ),
    decoration: decoration ??
        InputDecoration(
          filled: true,
          fillColor: AppTheme.fieldFill,
          hintText: controller.text.isEmpty
              ? 'មិនទាន់កំណត់សាខា — សូមទាក់ទង Admin'
              : null,
          hintStyle: GoogleFonts.kantumruyPro(
            color: AppTheme.helperTextColor,
            fontSize: 13,
          ),
          contentPadding: const EdgeInsets.symmetric(
            horizontal: 16,
            vertical: 16,
          ),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(16),
            borderSide: BorderSide(color: AppTheme.fieldBorder),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(16),
            borderSide: BorderSide(color: AppTheme.fieldBorder),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(16),
            borderSide: BorderSide(color: AppTheme.primary.withValues(alpha: 0.5)),
          ),
        ),
    validator: (v) => (v == null || v.trim().isEmpty)
        ? 'សូមទាក់ទង Admin ដើម្បីកំណត់សាខាក្នុងប្រព័ន្ធ'
        : null,
  );
}
