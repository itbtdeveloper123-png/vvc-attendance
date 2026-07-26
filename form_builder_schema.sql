-- Form Builder Database Schema
-- This schema supports dynamic form creation with drag & drop functionality

-- Form Templates Table
CREATE TABLE IF NOT EXISTS form_templates (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  category ENUM('request', 'mission', 'other') DEFAULT 'request',
  status ENUM('active', 'inactive') DEFAULT 'active',
  created_by INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_category (category),
  INDEX idx_status (status),
  INDEX idx_created_by (created_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Form Fields Table
CREATE TABLE IF NOT EXISTS form_fields (
  id INT AUTO_INCREMENT PRIMARY KEY,
  template_id INT NOT NULL,
  field_type ENUM('text', 'number', 'email', 'date', 'time', 'select', 'textarea', 'checkbox', 'file', 'signature', 'branch', 'department', 'position') NOT NULL,
  field_name VARCHAR(255) NOT NULL,
  field_label VARCHAR(255) NOT NULL,
  placeholder VARCHAR(255),
  required BOOLEAN DEFAULT FALSE,
  options JSON, -- For select fields: [{"value": "option1", "label": "Option 1"}, ...]
  validation_rules JSON, -- {"min_length": 5, "max_length": 100, "pattern": "regex"}
  display_order INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (template_id) REFERENCES form_templates(id) ON DELETE CASCADE,
  INDEX idx_template_id (template_id),
  INDEX idx_field_type (field_type),
  INDEX idx_display_order (display_order)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Form Submissions Table
CREATE TABLE IF NOT EXISTS form_submissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  template_id INT NOT NULL,
  user_id INT,
  submission_data JSON NOT NULL,
  status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
  submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  reviewed_by INT,
  reviewed_at TIMESTAMP NULL,
  review_notes TEXT,
  FOREIGN KEY (template_id) REFERENCES form_templates(id) ON DELETE CASCADE,
  INDEX idx_template_id (template_id),
  INDEX idx_user_id (user_id),
  INDEX idx_status (status),
  INDEX idx_submitted_at (submitted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert sample form templates for migration from existing forms
INSERT INTO form_templates (name, description, category, status) VALUES
('សំណើសុំច្បាប់ឈប់សម្រាក', 'សំណើសុំច្បាប់ឈប់សម្រាកប្រចាំឆ្នាំ, ជំងឺ, មាតុភាព', 'request', 'active'),
('សំណើសុំថែមម៉ោង', 'សំណើសុំធ្វើការថែមម៉ោង (OT)', 'request', 'active'),
('សំណើសុំមកយឺត', 'សំណើសុំមកយឺតការងារ', 'request', 'active'),
('សំណើសុំភ្លេចស្កេនមេដៃ', 'សំណើសុំភ្លេចស្កេនមេដៃចូល/ចេញ', 'request', 'active'),
('លិខិតបេសកម្ម', 'លិខិតបេសកម្មការងារ', 'mission', 'active');

-- Insert sample fields for leave request form
INSERT INTO form_fields (template_id, field_type, field_name, field_label, placeholder, required, display_order) VALUES
(1, 'text', 'requester_name', 'ឈ្មោះអ្នកស្នើសុំ', '', TRUE, 1),
(1, 'department', 'department', 'ផ្នែក/មុខតំណែង', '', TRUE, 2),
(1, 'position', 'position', 'មុខតំណែង', '', TRUE, 3),
(1, 'branch', 'branch', 'សាខា', '', TRUE, 4),
(1, 'date', 'request_date', 'ថ្ងៃខែឆ្នាំសុំឈប់', '', TRUE, 5),
(1, 'date', 'return_date', 'ថ្ងៃចូលធ្វើការវិញ', '', TRUE, 6),
(1, 'number', 'number_of_days', 'ចំនួនថ្ងៃ', '', TRUE, 7),
(1, 'textarea', 'reason', 'មូលហេតុ', 'សូមបញ្ជាក់មូលហេតុ...', TRUE, 8),
(1, 'text', 'location', 'ទីកន្លែងអំឡុងពេលឈប់', '', FALSE, 9),
(1, 'text', 'contact_number', 'ទំនាក់ទំនងបន្ទាន់', '', TRUE, 10),
(1, 'text', 'assigned_to', 'ប្រគល់ការងារឱ្យ', '', FALSE, 11),
(1, 'signature', 'signature', 'ហត្ថលេខាអ្នកស្នើសុំ', '', TRUE, 12);
