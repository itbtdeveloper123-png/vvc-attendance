import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/form_template.dart';

class FormBuilderService {
  final String baseUrl;
  final String? token;

  FormBuilderService({
    required this.baseUrl,
    this.token,
  });

  Map<String, String> get headers {
    final Map<String, String> header = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    
    if (token != null) {
      header['Authorization'] = 'Bearer $token';
    }
    
    return header;
  }

  // Get all form templates
  Future<List<FormTemplate>> getTemplates({
    String? category,
    String status = 'active',
  }) async {
    try {
      String url = '$baseUrl/form_builder_api.php?action=get_templates&status=$status';
      if (category != null) {
        url += '&category=$category';
      }

      final response = await http.get(
        Uri.parse(url),
        headers: headers,
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (data['success'] == true) {
          return (data['data'] as List)
              .map((template) => FormTemplate.fromJson(template))
              .toList();
        } else {
          throw Exception(data['message'] ?? 'Failed to load templates');
        }
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to load templates: $e');
    }
  }

  // Get single template with fields
  Future<FormTemplate> getTemplate(int id) async {
    try {
      final response = await http.get(
        Uri.parse('$baseUrl/form_builder_api.php?action=get_template&id=$id'),
        headers: headers,
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (data['success'] == true) {
          return FormTemplate.fromJson(data['data']);
        } else {
          throw Exception(data['message'] ?? 'Failed to load template');
        }
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to load template: $e');
    }
  }

  // Create new template
  Future<Map<String, dynamic>> createTemplate({
    required String name,
    String description = '',
    String category = 'request',
    String status = 'active',
  }) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/form_builder_api.php?action=create_template'),
        headers: headers,
        body: json.encode({
          'name': name,
          'description': description,
          'category': category,
          'status': status,
        }),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (data['success'] == true) {
          return data['data'];
        } else {
          throw Exception(data['message'] ?? 'Failed to create template');
        }
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to create template: $e');
    }
  }

  // Update template
  Future<bool> updateTemplate({
    required int id,
    String? name,
    String? description,
    String? category,
    String? status,
  }) async {
    try {
      final body = <String, dynamic>{'id': id};
      if (name != null) body['name'] = name;
      if (description != null) body['description'] = description;
      if (category != null) body['category'] = category;
      if (status != null) body['status'] = status;

      final response = await http.put(
        Uri.parse('$baseUrl/form_builder_api.php?action=update_template'),
        headers: headers,
        body: json.encode(body),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        return data['success'] == true;
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to update template: $e');
    }
  }

  // Delete template
  Future<bool> deleteTemplate(int id) async {
    try {
      final response = await http.delete(
        Uri.parse('$baseUrl/form_builder_api.php?action=delete_template&id=$id'),
        headers: headers,
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        return data['success'] == true;
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to delete template: $e');
    }
  }

  // Get fields for a template
  Future<List<FormField>> getFields(int templateId) async {
    try {
      final response = await http.get(
        Uri.parse('$baseUrl/form_builder_api.php?action=get_fields&template_id=$templateId'),
        headers: headers,
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (data['success'] == true) {
          return (data['data'] as List)
              .map((field) => FormField.fromJson(field))
              .toList();
        } else {
          throw Exception(data['message'] ?? 'Failed to load fields');
        }
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to load fields: $e');
    }
  }

  // Create field
  Future<Map<String, dynamic>> createField({
    required int templateId,
    required String fieldType,
    required String fieldName,
    required String fieldLabel,
    String placeholder = '',
    bool required = false,
    List<FieldOption>? options,
    Map<String, dynamic>? validationRules,
    int displayOrder = 0,
  }) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/form_builder_api.php?action=create_field'),
        headers: headers,
        body: json.encode({
          'template_id': templateId,
          'field_type': fieldType,
          'field_name': fieldName,
          'field_label': fieldLabel,
          'placeholder': placeholder,
          'required': required,
          'options': options?.map((o) => o.toJson()).toList(),
          'validation_rules': validationRules,
          'display_order': displayOrder,
        }),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (data['success'] == true) {
          return data['data'];
        } else {
          throw Exception(data['message'] ?? 'Failed to create field');
        }
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to create field: $e');
    }
  }

  // Update field
  Future<bool> updateField({
    required int id,
    String? fieldType,
    String? fieldName,
    String? fieldLabel,
    String? placeholder,
    bool? required,
    List<FieldOption>? options,
    Map<String, dynamic>? validationRules,
    int? displayOrder,
  }) async {
    try {
      final body = <String, dynamic>{'id': id};
      if (fieldType != null) body['field_type'] = fieldType;
      if (fieldName != null) body['field_name'] = fieldName;
      if (fieldLabel != null) body['field_label'] = fieldLabel;
      if (placeholder != null) body['placeholder'] = placeholder;
      if (required != null) body['required'] = required;
      if (options != null) body['options'] = options.map((o) => o.toJson()).toList();
      if (validationRules != null) body['validation_rules'] = validationRules;
      if (displayOrder != null) body['display_order'] = displayOrder;

      final response = await http.put(
        Uri.parse('$baseUrl/form_builder_api.php?action=update_field'),
        headers: headers,
        body: json.encode(body),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        return data['success'] == true;
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to update field: $e');
    }
  }

  // Delete field
  Future<bool> deleteField(int id) async {
    try {
      final response = await http.delete(
        Uri.parse('$baseUrl/form_builder_api.php?action=delete_field&id=$id'),
        headers: headers,
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        return data['success'] == true;
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to delete field: $e');
    }
  }

  // Create form submission
  Future<Map<String, dynamic>> createSubmission({
    required int templateId,
    int? userId,
    required Map<String, dynamic> submissionData,
  }) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/form_builder_api.php?action=create_submission'),
        headers: headers,
        body: json.encode({
          'template_id': templateId,
          'user_id': userId,
          'submission_data': submissionData,
        }),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (data['success'] == true) {
          return data['data'];
        } else {
          throw Exception(data['message'] ?? 'Failed to create submission');
        }
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to create submission: $e');
    }
  }

  // Get form submissions
  Future<List<FormSubmission>> getSubmissions({
    int? templateId,
    String? status,
    int limit = 50,
  }) async {
    try {
      String url = '$baseUrl/form_builder_api.php?action=get_submissions&limit=$limit';
      if (templateId != null) url += '&template_id=$templateId';
      if (status != null) url += '&status=$status';

      final response = await http.get(
        Uri.parse(url),
        headers: headers,
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        if (data['success'] == true) {
          return (data['data'] as List)
              .map((submission) => FormSubmission.fromJson(submission))
              .toList();
        } else {
          throw Exception(data['message'] ?? 'Failed to load submissions');
        }
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to load submissions: $e');
    }
  }

  // Update submission status
  Future<bool> updateSubmissionStatus({
    required int id,
    required String status,
    String? reviewNotes,
  }) async {
    try {
      final response = await http.put(
        Uri.parse('$baseUrl/form_builder_api.php?action=update_submission_status'),
        headers: headers,
        body: json.encode({
          'id': id,
          'status': status,
          'review_notes': reviewNotes,
        }),
      );

      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        return data['success'] == true;
      } else {
        throw Exception('Server error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Failed to update submission status: $e');
    }
  }
}
