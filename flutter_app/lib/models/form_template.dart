class FormTemplate {
  final int id;
  final String name;
  final String description;
  final String category;
  final String status;
  final List<FormField> fields;
  final DateTime createdAt;
  final DateTime updatedAt;

  FormTemplate({
    required this.id,
    required this.name,
    required this.description,
    required this.category,
    required this.status,
    required this.fields,
    required this.createdAt,
    required this.updatedAt,
  });

  factory FormTemplate.fromJson(Map<String, dynamic> json) {
    List<FormField> fields = [];
    if (json['fields'] != null) {
      fields = (json['fields'] as List)
          .map((field) => FormField.fromJson(field))
          .toList();
    }

    return FormTemplate(
      id: json['id'] ?? 0,
      name: json['name'] ?? '',
      description: json['description'] ?? '',
      category: json['category'] ?? 'request',
      status: json['status'] ?? 'active',
      fields: fields,
      createdAt: DateTime.parse(json['created_at'] ?? DateTime.now().toIso8601String()),
      updatedAt: DateTime.parse(json['updated_at'] ?? DateTime.now().toIso8601String()),
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'description': description,
      'category': category,
      'status': status,
      'fields': fields.map((field) => field.toJson()).toList(),
      'created_at': createdAt.toIso8601String(),
      'updated_at': updatedAt.toIso8601String(),
    };
  }
}

class FormField {
  final int id;
  final String fieldType;
  final String fieldName;
  final String fieldLabel;
  final String placeholder;
  final bool required;
  final List<FieldOption>? options;
  final Map<String, dynamic>? validationRules;
  final int displayOrder;

  FormField({
    required this.id,
    required this.fieldType,
    required this.fieldName,
    required this.fieldLabel,
    required this.placeholder,
    required this.required,
    this.options,
    this.validationRules,
    required this.displayOrder,
  });

  factory FormField.fromJson(Map<String, dynamic> json) {
    List<FieldOption>? options;
    if (json['options'] != null) {
      options = (json['options'] as List)
          .map((option) => FieldOption.fromJson(option))
          .toList();
    }

    return FormField(
      id: json['id'] ?? 0,
      fieldType: json['field_type'] ?? 'text',
      fieldName: json['field_name'] ?? '',
      fieldLabel: json['field_label'] ?? '',
      placeholder: json['placeholder'] ?? '',
      required: json['required'] ?? false,
      options: options,
      validationRules: json['validation_rules'] != null
          ? Map<String, dynamic>.from(json['validation_rules'])
          : null,
      displayOrder: json['display_order'] ?? 0,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'field_type': fieldType,
      'field_name': fieldName,
      'field_label': fieldLabel,
      'placeholder': placeholder,
      'required': required,
      'options': options?.map((option) => option.toJson()).toList(),
      'validation_rules': validationRules,
      'display_order': displayOrder,
    };
  }
}

class FieldOption {
  final String value;
  final String label;

  FieldOption({
    required this.value,
    required this.label,
  });

  factory FieldOption.fromJson(Map<String, dynamic> json) {
    return FieldOption(
      value: json['value'] ?? '',
      label: json['label'] ?? '',
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'value': value,
      'label': label,
    };
  }
}

class FormSubmission {
  final int id;
  final int templateId;
  final int? userId;
  final Map<String, dynamic> submissionData;
  final String status;
  final DateTime submittedAt;
  final int? reviewedBy;
  final DateTime? reviewedAt;
  final String? reviewNotes;

  FormSubmission({
    required this.id,
    required this.templateId,
    this.userId,
    required this.submissionData,
    required this.status,
    required this.submittedAt,
    this.reviewedBy,
    this.reviewedAt,
    this.reviewNotes,
  });

  factory FormSubmission.fromJson(Map<String, dynamic> json) {
    return FormSubmission(
      id: json['id'] ?? 0,
      templateId: json['template_id'] ?? 0,
      userId: json['user_id'],
      submissionData: json['submission_data'] != null
          ? Map<String, dynamic>.from(json['submission_data'])
          : {},
      status: json['status'] ?? 'pending',
      submittedAt: DateTime.parse(json['submitted_at'] ?? DateTime.now().toIso8601String()),
      reviewedBy: json['reviewed_by'],
      reviewedAt: json['reviewed_at'] != null
          ? DateTime.parse(json['reviewed_at'])
          : null,
      reviewNotes: json['review_notes'],
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'template_id': templateId,
      'user_id': userId,
      'submission_data': submissionData,
      'status': status,
      'submitted_at': submittedAt.toIso8601String(),
      'reviewed_by': reviewedBy,
      'reviewed_at': reviewedAt?.toIso8601String(),
      'review_notes': reviewNotes,
    };
  }
}
