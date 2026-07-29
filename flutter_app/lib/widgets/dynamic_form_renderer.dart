import 'package:flutter/material.dart' hide FormField;
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:signature/signature.dart';
import '../models/form_template.dart';
import '../utils/app_theme.dart';
import '../providers/user_provider.dart';
import 'package:provider/provider.dart';
import 'package:image_picker/image_picker.dart';
import 'dart:io';
import 'a5_paper_form.dart';

class DynamicFormRenderer extends StatefulWidget {
  final FormTemplate template;
  final Map<String, dynamic>? initialData;
  final Function(Map<String, dynamic>) onSubmit;

  const DynamicFormRenderer({
    super.key,
    required this.template,
    this.initialData,
    required this.onSubmit,
  });

  @override
  State<DynamicFormRenderer> createState() => _DynamicFormRendererState();
}

class _DynamicFormRendererState extends State<DynamicFormRenderer> {
  final _formKey = GlobalKey<FormState>();
  final Map<String, dynamic> _formData = {};
  final Map<String, SignatureController> _signatureControllers = {};
  final Map<String, File?> _fileValues = {};
  final ImagePicker _imagePicker = ImagePicker();

  @override
  void initState() {
    super.initState();
    if (widget.initialData != null) {
      _formData.addAll(widget.initialData!);
    }
  }

  @override
  void dispose() {
    _signatureControllers.forEach((key, controller) => controller.dispose());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Form(
      key: _formKey,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Form header
          _buildFormHeader(),
          const SizedBox(height: 20),
          
          // Form fields
          ...widget.template.fields.map((field) => _buildField(field)),
          
          const SizedBox(height: 20),
          
          // Submit button
          _buildSubmitButton(),
        ],
      ),
    );
  }

  Widget _buildFormHeader() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [AppTheme.primary, AppTheme.primary.withValues(alpha: 0.8)],
        ),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            widget.template.name,
            style: GoogleFonts.koulen(
              fontSize: 24,
              color: Colors.white,
              fontWeight: FontWeight.bold,
            ),
          ),
          if (widget.template.description.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(
              widget.template.description,
              style: GoogleFonts.battambang(
                fontSize: 14,
                color: Colors.white.withValues(alpha: 0.9),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildField(FormField field) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: _buildFieldByType(field),
    );
  }

  Widget _buildFieldByType(FormField field) {
    switch (field.fieldType) {
      case 'text':
      case 'email':
      case 'number':
        return _buildTextField(field);
      case 'date':
        return _buildDateField(field);
      case 'select':
        return _buildSelectField(field);
      case 'textarea':
        return _buildTextareaField(field);
      case 'checkbox':
        return _buildCheckboxField(field);
      case 'file':
        return _buildFileField(field);
      case 'signature':
        return _buildSignatureField(field);
      case 'branch':
        return _buildBranchField(field);
      case 'department':
        return _buildDepartmentField(field);
      case 'position':
        return _buildPositionField(field);
      case 'request_type':
        return _buildRequestTypeField(field);
      default:
        return _buildTextField(field);
    }
  }

  Widget _buildTextField(FormField field) {
    final keyboardType = field.fieldType == 'email'
        ? TextInputType.emailAddress
        : field.fieldType == 'number'
            ? TextInputType.number
            : TextInputType.text;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          field.fieldLabel + (field.required ? ' *' : ''),
          style: GoogleFonts.battambang(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            color: AppTheme.textPrimary,
          ),
        ),
        const SizedBox(height: 8),
        TextFormField(
          initialValue: _formData[field.fieldName]?.toString(),
          keyboardType: keyboardType,
          decoration: InputDecoration(
            hintText: field.placeholder,
            filled: true,
            fillColor: AppTheme.fieldFill,
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: AppTheme.fieldBorder),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: AppTheme.fieldBorder),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: AppTheme.primary.withValues(alpha: 0.5)),
            ),
          ),
          style: GoogleFonts.battambang(
            fontSize: 14,
            color: AppTheme.textPrimary,
          ),
          validator: (value) {
            if (field.required && (value == null || value.isEmpty)) {
              return 'សូមបំពេញ ${field.fieldLabel}';
            }
            if (field.fieldType == 'email' && value != null && value.isNotEmpty) {
              if (!RegExp(r'^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$').hasMatch(value)) {
                return 'សូមបញ្ចូល email ត្រឹមត្រូវ';
              }
            }
            return null;
          },
          onSaved: (value) {
            _formData[field.fieldName] = value ?? '';
          },
        ),
      ],
    );
  }

  Widget _buildDateField(FormField field) {
    DateTime? selectedDate;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          field.fieldLabel + (field.required ? ' *' : ''),
          style: GoogleFonts.battambang(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            color: AppTheme.textPrimary,
          ),
        ),
        const SizedBox(height: 8),
        InkWell(
          onTap: () async {
            final DateTime? picked = await showDatePicker(
              context: context,
              initialDate: selectedDate ?? DateTime.now(),
              firstDate: DateTime(2000),
              lastDate: DateTime(2101),
            );
            if (picked != null && mounted) {
              setState(() {
                selectedDate = picked;
                _formData[field.fieldName] = picked.toIso8601String();
              });
            }
          },
          child: Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.fieldFill,
              border: Border.all(color: AppTheme.fieldBorder),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                Icon(Icons.calendar_today, color: AppTheme.primary),
                const SizedBox(width: 12),
                Text(
                  selectedDate != null
                      ? '${selectedDate!.day}/${selectedDate!.month}/${selectedDate!.year}'
                      : field.placeholder,
                  style: GoogleFonts.battambang(
                    fontSize: 14,
                    color: selectedDate != null
                        ? AppTheme.textPrimary
                        : AppTheme.helperTextColor,
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildSelectField(FormField field) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          field.fieldLabel + (field.required ? ' *' : ''),
          style: GoogleFonts.battambang(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            color: AppTheme.textPrimary,
          ),
        ),
        const SizedBox(height: 8),
        DropdownButtonFormField<String>(
          initialValue: _formData[field.fieldName]?.toString(),
          decoration: InputDecoration(
            filled: true,
            fillColor: AppTheme.fieldFill,
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: AppTheme.fieldBorder),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: AppTheme.fieldBorder),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: AppTheme.primary.withValues(alpha: 0.5)),
            ),
          ),
          style: GoogleFonts.battambang(
            fontSize: 14,
            color: AppTheme.textPrimary,
          ),
          items: field.options?.map((option) {
                return DropdownMenuItem<String>(
                  value: option.value,
                  child: Text(
                    option.label,
                    style: GoogleFonts.battambang(fontSize: 14),
                  ),
                );
              }).toList() ??
              [],
          onChanged: (value) {
            setState(() {
              _formData[field.fieldName] = value;
            });
          },
          validator: (value) {
            if (field.required && (value == null || value.isEmpty)) {
              return 'សូមជ្រើសរើស ${field.fieldLabel}';
            }
            return null;
          },
        ),
      ],
    );
  }

  Widget _buildTextareaField(FormField field) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          field.fieldLabel + (field.required ? ' *' : ''),
          style: GoogleFonts.battambang(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            color: AppTheme.textPrimary,
          ),
        ),
        const SizedBox(height: 8),
        TextFormField(
          initialValue: _formData[field.fieldName]?.toString(),
          maxLines: 4,
          decoration: InputDecoration(
            hintText: field.placeholder,
            filled: true,
            fillColor: AppTheme.fieldFill,
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: AppTheme.fieldBorder),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: AppTheme.fieldBorder),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: BorderSide(color: AppTheme.primary.withValues(alpha: 0.5)),
            ),
          ),
          style: GoogleFonts.battambang(
            fontSize: 14,
            color: AppTheme.textPrimary,
          ),
          validator: (value) {
            if (field.required && (value == null || value.isEmpty)) {
              return 'សូមបំពេញ ${field.fieldLabel}';
            }
            return null;
          },
          onSaved: (value) {
            _formData[field.fieldName] = value ?? '';
          },
        ),
      ],
    );
  }

  Widget _buildCheckboxField(FormField field) {
    return CheckboxListTile(
      title: Text(
        field.fieldLabel,
        style: GoogleFonts.battambang(
          fontSize: 14,
          color: AppTheme.textPrimary,
        ),
      ),
      value: _formData[field.fieldName] ?? false,
      onChanged: (value) {
        setState(() {
          _formData[field.fieldName] = value ?? false;
        });
      },
      activeColor: AppTheme.primary,
    );
  }

  Widget _buildFileField(FormField field) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          field.fieldLabel + (field.required ? ' *' : ''),
          style: GoogleFonts.battambang(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            color: AppTheme.textPrimary,
          ),
        ),
        const SizedBox(height: 8),
        InkWell(
          onTap: () async {
            final XFile? image = await _imagePicker.pickImage(
              source: ImageSource.gallery,
            );
            if (image != null) {
              setState(() {
                _fileValues[field.fieldName] = File(image.path);
                _formData[field.fieldName] = image.path;
              });
            }
          },
          child: Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: AppTheme.fieldFill,
              border: Border.all(color: AppTheme.fieldBorder),
              borderRadius: BorderRadius.circular(8),
            ),
            child: _fileValues[field.fieldName] != null
                ? Column(
                    children: [
                      Image.file(
                        _fileValues[field.fieldName]!,
                        height: 150,
                        width: double.infinity,
                        fit: BoxFit.cover,
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'ចុចដើម្បីផ្លាស់ប្តូរ',
                        style: GoogleFonts.battambang(
                          fontSize: 12,
                          color: AppTheme.primary,
                        ),
                      ),
                    ],
                  )
                : Column(
                    children: [
                      Icon(Icons.cloud_upload, size: 40, color: AppTheme.primary),
                      const SizedBox(height: 8),
                      Text(
                        field.placeholder.isNotEmpty
                            ? field.placeholder
                            : 'ចុចដើម្បីដាក់ឯកសារ',
                        style: GoogleFonts.battambang(
                          fontSize: 14,
                          color: AppTheme.helperTextColor,
                        ),
                      ),
                    ],
                  ),
          ),
        ),
      ],
    );
  }

  Widget _buildSignatureField(FormField field) {
    if (!_signatureControllers.containsKey(field.fieldName)) {
      _signatureControllers[field.fieldName] = SignatureController(
        penStrokeWidth: 2,
        penColor: Colors.black,
      );
    }

    final controller = _signatureControllers[field.fieldName]!;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          field.fieldLabel + (field.required ? ' *' : ''),
          style: GoogleFonts.battambang(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            color: AppTheme.textPrimary,
          ),
        ),
        const SizedBox(height: 8),
        Container(
          height: 150,
          decoration: BoxDecoration(
            color: Colors.white,
            border: Border.all(color: AppTheme.fieldBorder),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Stack(
            children: [
              Signature(
                controller: controller,
                height: 150,
                backgroundColor: Colors.white,
              ),
              Positioned(
                top: 8,
                right: 8,
                child: Row(
                  children: [
                    IconButton(
                      icon: const Icon(Icons.clear, size: 20),
                      onPressed: () {
                        controller.clear();
                        setState(() {});
                      },
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildBranchField(FormField field) {
    final user = Provider.of<UserProvider>(context, listen: false);
    return _buildReadOnlyField(
      field.fieldLabel,
      user.branch ?? 'មិនទាន់កំណត់',
      field.required,
    );
  }

  Widget _buildDepartmentField(FormField field) {
    final user = Provider.of<UserProvider>(context, listen: false);
    return _buildReadOnlyField(
      field.fieldLabel,
      user.department ?? 'មិនទាន់កំណត់',
      field.required,
    );
  }

  Widget _buildPositionField(FormField field) {
    final user = Provider.of<UserProvider>(context, listen: false);
    return _buildReadOnlyField(
      field.fieldLabel,
      user.position ?? 'មិនទាន់កំណត់',
      field.required,
    );
  }

  Widget _buildRequestTypeField(FormField field) {
    String selectedValue = _formData[field.fieldName]?.toString() ?? '';

    return A5FormSection(
      title: field.fieldLabel,
      icon: Icons.list_check,
      isRequired: field.required,
      children: [
        A5RequestTypeCheckboxGroup(
          selectedValue: selectedValue,
          onChanged: (value) {
            setState(() {
              _formData[field.fieldName] = value;
            });
          },
        ),
      ],
    );
  }

  Widget _buildReadOnlyField(String label, String value, bool required) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label + (required ? ' *' : ''),
          style: GoogleFonts.battambang(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            color: AppTheme.textPrimary,
          ),
        ),
        const SizedBox(height: 8),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: AppTheme.fieldFill,
            border: Border.all(color: AppTheme.fieldBorder),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Text(
            value,
            style: GoogleFonts.battambang(
              fontSize: 14,
              color: AppTheme.textPrimary,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildSubmitButton() {
    return ElevatedButton(
      onPressed: _handleSubmit,
      style: ElevatedButton.styleFrom(
        backgroundColor: AppTheme.primary,
        padding: const EdgeInsets.symmetric(vertical: 16),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
      ),
      child: Text(
        'ដាក់ស្នើ',
        style: GoogleFonts.koulen(
          fontSize: 16,
          color: Colors.white,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }

  void _handleSubmit() {
    if (_formKey.currentState!.validate()) {
      _formKey.currentState!.save();

      // Add signature data
      _signatureControllers.forEach((fieldName, controller) {
        if (controller.isNotEmpty) {
          _formData[fieldName] = controller.toPngBytes();
        }
      });

      widget.onSubmit(_formData);
    }
  }
}
