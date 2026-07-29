-- Fix Khmer Text Encoding for Form Builder Templates
-- Run this SQL script in your database to fix UTF-8 encoding issues

-- 1. Check current database charset
-- SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'samann1_hrm_db';

-- 2. Fix database charset (if needed)
-- ALTER DATABASE samann1_hrm_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 3. Fix form_templates table charset
ALTER TABLE form_templates CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 4. Fix form_fields table charset
ALTER TABLE form_fields CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 5. Fix form_submissions table charset
ALTER TABLE form_submissions CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 6. Check if data needs re-encoding (run this to see the current state)
-- SELECT id, name, HEX(name) as hex_name FROM form_templates LIMIT 5;

-- Note: If the stored data is already corrupted, you may need to manually update the records
-- Example: UPDATE form_templates SET name = 'សំណើសុំច្បាប់ឈប់សម្រាក' WHERE id = 6;