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

String resolveRequestPosition({
  Map<String, dynamic>? initialData,
  required UserProvider user,
}) {
  if (initialData != null) {
    final saved = (initialData['position'] ?? '').toString().trim();
    if (saved.isNotEmpty) return saved;
  }
  final p = (user.position ?? '').trim();
  return p.isNotEmpty ? p : 'ព័ត៌មានវិទ្យា (IT)';
}

String resolveRequestDepartment({
  Map<String, dynamic>? initialData,
  required UserProvider user,
}) {
  if (initialData != null) {
    final saved = (initialData['department'] ?? '').toString().trim();
    if (saved.isNotEmpty) return saved;
  }
  final d = (user.department ?? '').trim();
  return d.isNotEmpty ? d : 'IT';
}

void applyUserPositionAndDepartment({
  required TextEditingController positionController,
  required TextEditingController departmentController,
  Map<String, dynamic>? initialData,
  required UserProvider user,
}) {
  positionController.text = resolveRequestPosition(initialData: initialData, user: user);
  departmentController.text = resolveRequestDepartment(initialData: initialData, user: user);
}

Widget buildReadOnlyUserField(
  TextEditingController controller, {
  String placeholder = 'មិនទាន់កំណត់ — សូមទាក់ទង Admin',
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
          hintText: controller.text.isEmpty ? placeholder : null,
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
    validator: (v) => (v == null || v.trim().isEmpty) ? placeholder : null,
  );
}

Widget buildReadOnlyBranchField(
  TextEditingController controller, {
  InputDecoration? decoration,
}) {
  return buildReadOnlyUserField(
    controller,
    placeholder: 'មិនទាន់កំណត់សាខា — សូមទាក់ទង Admin',
    decoration: decoration,
  );
}
