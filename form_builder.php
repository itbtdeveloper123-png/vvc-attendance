<?php
// Form Builder UI - Drag & Drop Form Builder
// This page provides a visual interface for creating and managing form templates

if (!headers_sent()) {
    header('Content-Type: text/html; charset=UTF-8');
}
ini_set('default_charset', 'UTF-8');
mb_internal_encoding('UTF-8');

// Only use mb_http functions if available
if (function_exists('mb_http_output')) {
    mb_http_output('UTF-8');
}
if (function_exists('mb_http_input')) {
    mb_http_input('UTF-8');
}

session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('error_log', __DIR__ . '/php_debug.log');

try {
    require_once __DIR__ . '/config.php';
    // Skip vendor/autoload.php if it causes issues
    // require_once __DIR__ . '/vendor/autoload.php';
} catch (Exception $e) {
    error_log("Form Builder: Error loading config: " . $e->getMessage());
    die('Error loading required files. Please check system configuration.');
}

// Check authentication
if (!isset($_SESSION['admin_id'])) {
    error_log("Form Builder: No admin_id in session");
    header('Location: admin_attendance.php');
    exit;
}

error_log("Form Builder: Admin authenticated - admin_id: " . $_SESSION['admin_id']);

// Get current admin info
$current_admin_id = $_SESSION['admin_id'] ?? ($_SESSION['sub_user_parent_id'] ?? ($_SESSION['sub_user_id'] ?? 'SYSTEM_WIDE'));
$is_super_admin = !empty($_SESSION['is_super_admin']);

// Page title
$page_title = 'Form Builder - កម្មវិធីបង្កើតសំណើ';

error_log("Form Builder: Starting page load for admin_id: " . $current_admin_id);
?>
<!DOCTYPE html>
<html lang="km">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Koulen&family=Battambang:wght@100;300;400;700;900&family=Kantumruy+Pro:ital,wght@0,100..700;1,100..700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/form_print.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Battambang', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .header {
            background: white;
            padding: 20px 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-family: 'Koulen', cursive;
            font-size: 28px;
            color: #667eea;
        }
        
        .header-actions button {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-family: 'Battambang', sans-serif;
            font-size: 14px;
            margin-left: 10px;
        }
        
        .header-actions button:hover {
            background: #5568d3;
        }
        
        .container {
            display: flex;
            height: calc(100vh - 80px);
            padding: 20px;
            gap: 20px;
        }
        
        .sidebar {
            width: 300px;
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            overflow-y: auto;
        }
        
        .sidebar h2 {
            font-family: 'Koulen', cursive;
            font-size: 20px;
            color: #333;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .field-types {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }
        
        .field-type {
            background: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
            cursor: grab;
            transition: all 0.3;
        }
        
        .field-type:hover {
            border-color: #667eea;
            background: #f0f4ff;
            transform: translateY(-2px);
        }
        
        .field-type i {
            font-size: 24px;
            color: #667eea;
            margin-bottom: 8px;
        }
        
        .field-type span {
            display: block;
            font-size: 12px;
            color: #666;
        }
        
        /* Request Type Checkbox Group Styles */
        .request-type-checkbox-group {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-bottom: 15px;
            padding: 15px;
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
        }
        
        .request-type-checkbox-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px;
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .request-type-checkbox-item:hover {
            border-color: #667eea;
            background: #f0f4ff;
        }
        
        .request-type-checkbox-item input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: #667eea;
        }
        
        .request-type-checkbox-item.checked {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }
        
        .request-type-checkbox-item.checked span {
            color: white;
        }
        
        .templates-list {
            margin-top: 20px;
        }
        
        .template-item {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .template-item:hover {
            border-color: #667eea;
            background: #f0f4ff;
        }
        
        .template-item.active {
            border-color: #667eea;
            background: #e0e7ff;
        }
        
        .template-item h3 {
            font-family: 'Koulen', cursive;
            font-size: 16px;
            color: #333;
            margin-bottom: 5px;
        }
        
        .template-item p {
            font-size: 12px;
            color: #666;
        }
        
        .main-content {
            flex: 1;
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            overflow-y: auto;
        }
        
        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e9ecef;
        }
        
        .toolbar h2 {
            font-family: 'Koulen', cursive;
            font-size: 24px;
            color: #333;
        }
        
        .toolbar-actions {
            display: flex;
            gap: 10px;
        }
        
        .toolbar-actions button {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-family: 'Battambang', sans-serif;
            font-size: 14px;
        }
        
        .toolbar-actions button.secondary {
            background: #6c757d;
        }
        
        .toolbar-actions button.danger {
            background: #dc3545;
        }
        
        .form-canvas {
            min-height: 400px;
            border: 2px dashed #e9ecef;
            border-radius: 8px;
            padding: 20px;
            background: #f8f9fa;
        }
        
        .form-canvas.drag-over {
            border-color: #667eea;
            background: #f0f4ff;
        }
        
        .form-field {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            position: relative;
            transition: all 0.3s;
        }
        
        .form-field:hover {
            border-color: #667eea;
            box-shadow: 0 2px 8px rgba(102, 126, 234, 0.1);
        }
        
        .form-field.dragging {
            opacity: 0.5;
            transform: scale(0.95);
        }
        
        .field-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .field-header h3 {
            font-family: 'Koulen', cursive;
            font-size: 16px;
            color: #333;
        }
        
        .field-actions {
            display: flex;
            gap: 5px;
        }
        
        .field-actions button {
            background: none;
            border: none;
            cursor: pointer;
            padding: 5px;
            color: #666;
            transition: color 0.3s;
        }
        
        .field-actions button:hover {
            color: #667eea;
        }
        
        .field-content {
            background: #f8f9fa;
            border-radius: 6px;
            padding: 15px;
        }
        
        .field-preview {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .field-preview label {
            font-family: 'Battambang', sans-serif;
            font-size: 14px;
            color: #333;
            font-weight: 600;
        }
        
        .field-preview input,
        .field-preview select,
        .field-preview textarea {
            padding: 10px;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            font-family: 'Battambang', sans-serif;
            font-size: 14px;
        }
        
        .field-properties {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e9ecef;
        }
        
        .property-group {
            margin-bottom: 10px;
        }
        
        .property-group label {
            display: block;
            font-family: 'Battambang', sans-serif;
            font-size: 12px;
            color: #666;
            margin-bottom: 5px;
        }
        
        .property-group input,
        .property-group select {
            width: 100%;
            padding: 8px;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            font-family: 'Battambang', sans-serif;
            font-size: 14px;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: white;
            border-radius: 12px;
            padding: 30px;
            width: 500px;
            max-width: 90%;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .modal-header h2 {
            font-family: 'Koulen', cursive;
            font-size: 24px;
            color: #333;
        }
        
        .modal-close {
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: #666;
        }
        
        .modal-body {
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            font-family: 'Battambang', sans-serif;
            font-size: 14px;
            color: #333;
            margin-bottom: 5px;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            font-family: 'Battambang', sans-serif;
            font-size: 14px;
        }
        
        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-family: 'Battambang', sans-serif;
            font-size: 14px;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .empty-state i {
            font-size: 48px;
            color: #e9ecef;
            margin-bottom: 15px;
        }
        
        .required-mark {
            color: #dc3545;
            margin-left: 2px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📝 Form Builder - កម្មវិធីបង្កើតសំណើ</h1>
        <div class="header-actions">
            <button onclick="openImportModal()">
                <i class="fas fa-file-import"></i> នាំចូល Form
            </button>
            <button onclick="openTemplateModal()">
                <i class="fas fa-plus"></i> បង្កើត Template ថ្មី
            </button>
            <button onclick="window.location.href='admin_attendance.php?page=dashboard'">
                <i class="fas fa-arrow-left"></i> ត្រឡប់ក្រុម Dashboard
            </button>
        </div>
    </div>
    
    <div class="container">
        <div class="sidebar">
            <h2>📋 ប្រភេទ Field</h2>
            <div class="field-types">
                <div class="field-type" draggable="true" data-type="text">
                    <i class="fas fa-font"></i>
                    <span>Text</span>
                </div>
                <div class="field-type" draggable="true" data-type="number">
                    <i class="fas fa-hashtag"></i>
                    <span>Number</span>
                </div>
                <div class="field-type" draggable="true" data-type="email">
                    <i class="fas fa-envelope"></i>
                    <span>Email</span>
                </div>
                <div class="field-type" draggable="true" data-type="date">
                    <i class="fas fa-calendar"></i>
                    <span>Date</span>
                </div>
                <div class="field-type" draggable="true" data-type="time">
                    <i class="fas fa-clock"></i>
                    <span>Time</span>
                </div>
                <div class="field-type" draggable="true" data-type="select">
                    <i class="fas fa-list"></i>
                    <span>Select</span>
                </div>
                <div class="field-type" draggable="true" data-type="textarea">
                    <i class="fas fa-align-left"></i>
                    <span>Textarea</span>
                </div>
                <div class="field-type" draggable="true" data-type="checkbox">
                    <i class="fas fa-check-square"></i>
                    <span>Checkbox</span>
                </div>
                <div class="field-type" draggable="true" data-type="file">
                    <i class="fas fa-file-upload"></i>
                    <span>File</span>
                </div>
                <div class="field-type" draggable="true" data-type="signature">
                    <i class="fas fa-signature"></i>
                    <span>Signature</span>
                </div>
                <div class="field-type" draggable="true" data-type="branch">
                    <i class="fas fa-building"></i>
                    <span>Branch</span>
                </div>
                <div class="field-type" draggable="true" data-type="department">
                    <i class="fas fa-sitemap"></i>
                    <span>Department</span>
                </div>
                <div class="field-type" draggable="true" data-type="position">
                    <i class="fas fa-user-tie"></i>
                    <span>Position</span>
                </div>
                <div class="field-type" draggable="true" data-type="request_type">
                    <i class="fas fa-list-check"></i>
                    <span>Request Type</span>
                </div>
            </div>
            
            <div class="templates-list">
                <h2>📁 Templates</h2>
                <div id="templates-container">
                    <div class="empty-state">
                        <i class="fas fa-folder-open"></i>
                        <p>មិនមាន Templates ទេ</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="main-content">
            <div class="toolbar">
                <h2 id="template-title">ជ្រើសរើស Template ឬបង្កើតថ្មី</h2>
                <div class="toolbar-actions">
                    <button class="secondary" onclick="previewForm()">
                        <i class="fas fa-eye"></i> មើលជាមុន
                    </button>
                    <button class="primary" onclick="saveTemplate()">
                        <i class="fas fa-save"></i> រក្សាទុក
                    </button>
                    <button class="danger" onclick="deleteTemplate()">
                        <i class="fas fa-trash"></i> លុប
                    </button>
                </div>
            </div>
            
            <div class="form-canvas" id="form-canvas">
                <div class="empty-state">
                    <i class="fas fa-mouse-pointer"></i>
                    <p>ទាញ Field ពី sidebar មកដាក់នៅទីនេះ</p>
                    <p>ឬជ្រើសរើស Template ពីខាងឆ្វេង</p>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Template Modal -->
    <div class="modal" id="template-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>បង្កើត Template ថ្មី</h2>
                <button class="modal-close" onclick="closeTemplateModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label>ឈ្មោះ Template *</label>
                    <input type="text" id="template-name" placeholder="ឧ: សំណើសុំច្បាប់ឈប់សម្រាក">
                </div>
                <div class="form-group">
                    <label>ការពិពណ៌នា</label>
                    <textarea id="template-description" rows="3" placeholder="ការពិពណ៌នាអំពី Template..."></textarea>
                </div>
                <div class="form-group">
                    <label>ប្រភេទ</label>
                    <select id="template-category">
                        <option value="request">សំណើ (Request)</option>
                        <option value="mission">លិខិតបេសកម្ម (Mission)</option>
                        <option value="other">ផ្សេងៗ (Other)</option>
                    </select>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeTemplateModal()">បោះបង់</button>
                <button class="btn btn-primary" onclick="createTemplate()">បង្កើត</button>
            </div>
        </div>
    </div>
    
    <!-- Import Modal -->
    <div class="modal" id="import-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>នាំចូល Form ពី Flutter App</h2>
                <button class="modal-close" onclick="closeImportModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label>ជ្រើសរើស Form ដែលត្រូវនាំចូល</label>
                    <select id="import-form-select">
                        <option value="">-- ជ្រើសរើស Form --</option>
                        <option value="leave_request">សំណើសុំច្បាប់ឈប់សម្រាក (Leave Request)</option>
                        <option value="ot_request">សំណើសុំថែមម៉ោង (OT Request)</option>
                        <option value="late_request">សំណើសុំមកយឺត (Late Request)</option>
                    </select>
                </div>
                <div class="info-text" style="color: #666; font-size: 14px; margin-top: 10px;">
                    <i class="fas fa-info-circle"></i> នេះនឹងបង្កើត Template ដោយផ្លាស់ប្តូរ field structure ពី Flutter Form ដែលមានស្រាប់
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeImportModal()">បោះបង់</button>
                <button class="btn btn-primary" onclick="importForm()">នាំចូល</button>
            </div>
        </div>
    </div>
    
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Sortable/1.14.0/Sortable.min.js"></script>
    <script>
        let currentTemplate = null;
        let formFields = [];
        let fieldCounter = 0;
        
        // Initialize drag and drop
        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM Content Loaded - Initializing Form Builder');
            initDragAndDrop();
            console.log('Loading templates...');
            loadTemplates();
        });
        
        function initDragAndDrop() {
            console.log('Initializing drag and drop...');
            
            // Field types drag start
            const fieldTypes = document.querySelectorAll('.field-type');
            console.log('Found field types:', fieldTypes.length);
            
            fieldTypes.forEach(field => {
                field.addEventListener('dragstart', function(e) {
                    e.dataTransfer.setData('fieldType', this.dataset.type);
                });
            });
            
            // Form canvas drag events
            const canvas = document.getElementById('form-canvas');
            
            if (!canvas) {
                console.error('Form canvas not found!');
                return;
            }
            
            console.log('Form canvas found, setting up drag events');
            
            canvas.addEventListener('dragover', function(e) {
                e.preventDefault();
                this.classList.add('drag-over');
            });
            
            canvas.addEventListener('dragleave', function(e) {
                this.classList.remove('drag-over');
            });
            
            canvas.addEventListener('drop', function(e) {
                e.preventDefault();
                this.classList.remove('drag-over');
                
                const fieldType = e.dataTransfer.getData('fieldType');
                if (fieldType) {
                    addField(fieldType);
                }
            });
            
            // Initialize sortable for form fields
            try {
                new Sortable(canvas, {
                    animation: 150,
                    handle: '.field-header',
                    ghostClass: 'dragging',
                    onEnd: function(evt) {
                        updateFieldOrder();
                    }
                });
                console.log('Sortable initialized successfully');
            } catch (e) {
                console.error('Failed to initialize Sortable:', e);
            }
        }
        
        function addField(type) {
            fieldCounter++;
            const fieldId = 'field_' + fieldCounter;
            
            const field = {
                id: fieldId,
                type: type,
                name: 'field_' + fieldCounter,
                label: 'Field ' + fieldCounter,
                placeholder: '',
                required: false,
                options: [],
                validation: {}
            };
            
            formFields.push(field);
            renderField(field);
            removeEmptyState();
        }
        
        function renderField(field) {
            const canvas = document.getElementById('form-canvas');
            const fieldHtml = createFieldHTML(field);
            canvas.insertAdjacentHTML('beforeend', fieldHtml);
        }
        
        function createFieldHTML(field) {
            const fieldLabels = {
                text: 'Text Field',
                number: 'Number Field',
                email: 'Email Field',
                date: 'Date Field',
                time: 'Time Field',
                select: 'Select Field',
                textarea: 'Textarea',
                checkbox: 'Checkbox',
                file: 'File Upload',
                signature: 'Signature',
                branch: 'Branch',
                department: 'Department',
                position: 'Position',
                request_type: 'Request Type Checkboxes'
            };
            
            const icons = {
                text: 'fa-font',
                number: 'fa-hashtag',
                email: 'fa-envelope',
                date: 'fa-calendar',
                time: 'fa-clock',
                select: 'fa-list',
                textarea: 'fa-align-left',
                checkbox: 'fa-check-square',
                file: 'fa-file-upload',
                signature: 'fa-signature',
                branch: 'fa-building',
                department: 'fa-sitemap',
                position: 'fa-user-tie',
                request_type: 'fa-list-check'
            };
            
            return `
                <div class="form-field" id="${field.id}" data-field-id="${field.id}">
                    <div class="field-header">
                        <h3><i class="fas ${icons[field.type] || 'fa-font'}"></i> ${fieldLabels[field.type] || 'Field'}</h3>
                        <div class="field-actions">
                            <button onclick="moveFieldUp('${field.id}')"><i class="fas fa-arrow-up"></i></button>
                            <button onclick="moveFieldDown('${field.id}')"><i class="fas fa-arrow-down"></i></button>
                            <button onclick="duplicateField('${field.id}')"><i class="fas fa-copy"></i></button>
                            <button onclick="deleteField('${field.id}')"><i class="fas fa-trash"></i></button>
                        </div>
                    </div>
                    <div class="field-content">
                        <div class="field-preview">
                            <label>${field.label} ${field.required ? '<span class="required-mark">*</span>' : ''}</label>
                            ${createFieldPreview(field)}
                        </div>
                        <div class="field-properties">
                            <div class="property-group">
                                <label>Label</label>
                                <input type="text" value="${field.label || ''}" onchange="updateFieldProperty('${field.id}', 'label', this.value)">
                            </div>
                            <div class="property-group">
                                <label>Field Name</label>
                                <input type="text" value="${field.name || ''}" onchange="updateFieldProperty('${field.id}', 'name', this.value)">
                            </div>
                            <div class="property-group">
                                <label>Placeholder</label>
                                <input type="text" value="${field.placeholder || ''}" onchange="updateFieldProperty('${field.id}', 'placeholder', this.value)">
                            </div>
                            <div class="property-group">
                                <label>
                                    <input type="checkbox" ${field.required ? 'checked' : ''} onchange="updateFieldProperty('${field.id}', 'required', this.checked)">
                                    Required
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        function createFieldPreview(field) {
            const fieldType = field.type || 'text';
            const placeholder = field.placeholder || '';
            
            switch(fieldType) {
                case 'text':
                case 'email':
                case 'number':
                    return `<input type="${fieldType}" placeholder="${placeholder}" disabled>`;
                case 'date':
                    return `<input type="date" disabled>`;
                case 'time':
                    return `<input type="time" disabled>`;
                case 'select':
                    return `<select disabled><option>Select option...</option></select>`;
                case 'textarea':
                    return `<textarea rows="3" placeholder="${placeholder}" disabled></textarea>`;
                case 'checkbox':
                    return `<input type="checkbox" disabled> ${placeholder}`;
                case 'file':
                    return `<input type="file" disabled>`;
                case 'signature':
                    return `<div style="border: 1px dashed #ccc; padding: 20px; text-align: center; color: #999;">Signature Area</div>`;
                case 'branch':
                case 'department':
                case 'position':
                    return `<select disabled><option>Select ${fieldType}...</option></select>`;
                case 'request_type':
                    return `
                        <div class="request-type-checkbox-group">
                            <label class="request-type-checkbox-item">
                                <input type="checkbox" disabled> ច្បាប់ (Leave)
                            </label>
                            <label class="request-type-checkbox-item">
                                <input type="checkbox" disabled> មកយឺត (Late)
                            </label>
                            <label class="request-type-checkbox-item">
                                <input type="checkbox" disabled> ភ្លេចស្កេន (Forgotten Scan)
                            </label>
                            <label class="request-type-checkbox-item">
                                <input type="checkbox" disabled> ដេអូស (DEO)
                            </label>
                        </div>
                    `;
                default:
                    return `<input type="text" placeholder="${placeholder}" disabled>`;
            }
        }
        
        function updateFieldProperty(fieldId, property, value) {
            const field = formFields.find(f => f.id === fieldId);
            if (field) {
                field[property] = value;
                // Re-render field to show changes
                const fieldElement = document.getElementById(fieldId);
                if (fieldElement) {
                    fieldElement.outerHTML = createFieldHTML(field);
                }
            }
        }
        
        function deleteField(fieldId) {
            if (confirm('តើអ្នកប្រាកដជាចង់លុប field នេះ?')) {
                formFields = formFields.filter(f => f.id !== fieldId);
                document.getElementById(fieldId).remove();
                
                if (formFields.length === 0) {
                    showEmptyState();
                }
            }
        }
        
        function duplicateField(fieldId) {
            const field = formFields.find(f => f.id === fieldId);
            if (field) {
                fieldCounter++;
                const newField = {
                    ...field,
                    id: 'field_' + fieldCounter,
                    name: 'field_' + fieldCounter
                };
                formFields.push(newField);
                renderField(newField);
            }
        }
        
        function moveFieldUp(fieldId) {
            const index = formFields.findIndex(f => f.id === fieldId);
            if (index > 0) {
                [formFields[index], formFields[index - 1]] = [formFields[index - 1], formFields[index]];
                reRenderAllFields();
            }
        }
        
        function moveFieldDown(fieldId) {
            const index = formFields.findIndex(f => f.id === fieldId);
            if (index < formFields.length - 1) {
                [formFields[index], formFields[index + 1]] = [formFields[index + 1], formFields[index]];
                reRenderAllFields();
            }
        }
        
        function updateFieldOrder() {
            const canvas = document.getElementById('form-canvas');
            const fieldElements = canvas.querySelectorAll('.form-field');
            const newOrder = [];
            
            fieldElements.forEach(element => {
                const fieldId = element.dataset.fieldId;
                const field = formFields.find(f => f.id === fieldId);
                if (field) {
                    newOrder.push(field);
                }
            });
            
            formFields = newOrder;
        }
        
        function reRenderAllFields() {
            const canvas = document.getElementById('form-canvas');
            canvas.innerHTML = '';
            formFields.forEach(field => renderField(field));
        }
        
        function removeEmptyState() {
            const canvas = document.getElementById('form-canvas');
            const emptyState = canvas.querySelector('.empty-state');
            if (emptyState) {
                emptyState.remove();
            }
        }
        
        function showEmptyState() {
            const canvas = document.getElementById('form-canvas');
            canvas.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-mouse-pointer"></i>
                    <p>ទាញ Field ពី sidebar មកដាក់នៅទីនេះ</p>
                    <p>ឬជ្រើសរើស Template ពីខាងឆ្វេង</p>
                </div>
            `;
        }
        
        function openTemplateModal() {
            document.getElementById('template-modal').classList.add('active');
        }
        
        function closeTemplateModal() {
            document.getElementById('template-modal').classList.remove('active');
        }
        
        function openImportModal() {
            document.getElementById('import-modal').classList.add('active');
        }
        
        function closeImportModal() {
            document.getElementById('import-modal').classList.remove('active');
        }
        
        function importForm() {
            const formKey = document.getElementById('import-form-select').value;
            
            if (!formKey) {
                alert('សូមជ្រើសរើស Form ដែលត្រូវនាំចូល');
                return;
            }
            
            // Redirect to import helper script
            window.open('form_import_helper.php?import=' + formKey, '_blank');
            closeImportModal();
        }
        
        function createTemplate() {
            const name = document.getElementById('template-name').value;
            const description = document.getElementById('template-description').value;
            const category = document.getElementById('template-category').value;
            
            console.log('Creating template:', { name, description, category });
            
            if (!name) {
                alert('សូមបញ្ចូលឈ្មោះ Template');
                return;
            }
            
            $.ajax({
                url: 'form_builder_api.php',
                method: 'POST',
                data: {
                    action: 'create_template',
                    name: name,
                    description: description,
                    category: category
                },
                success: function(response) {
                    console.log('Create template response:', response);
                    if (response.success) {
                        currentTemplate = {
                            id: response.data.id,
                            name: name,
                            description: description,
                            category: category
                        };
                        document.getElementById('template-title').textContent = name;
                        closeTemplateModal();
                        loadTemplates();
                        formFields = [];
                        showEmptyState();
                    } else {
                        alert('កំហុស: ' + response.message);
                    }
                },
                error: function() {
                    alert('កំហុសក្នុងការភ្ជាប់ Server');
                }
            });
        }
        
        function loadTemplates() {
            $.ajax({
                url: 'form_builder_api.php',
                method: 'GET',
                data: { action: 'get_templates' },
                success: function(response) {
                    if (response.success) {
                        renderTemplates(response.data);
                    } else {
                        console.error('API Error:', response.message);
                        alert('កំហុស: ' + (response.message || 'Failed to load templates'));
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Failed to load templates:', error);
                    console.error('Status:', status);
                    console.error('Response:', xhr.responseText);
                    alert('កំហុសក្នុងការភ្ជាប់ Server: ' + error);
                }
            });
        }
        
        function renderTemplates(templates) {
            const container = document.getElementById('templates-container');
            
            if (templates.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-folder-open"></i>
                        <p>មិនមាន Templates ទេ</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = templates.map(template => `
                <div class="template-item ${currentTemplate && currentTemplate.id === template.id ? 'active' : ''}" 
                     onclick="loadTemplate(${template.id})">
                    <h3>${template.name}</h3>
                    <p>${template.description || 'គ្មានការពិពណ៌នា'}</p>
                </div>
            `).join('');
        }
        
        function loadTemplate(templateId) {
            $.ajax({
                url: 'form_builder_api.php',
                method: 'GET',
                data: { action: 'get_template', id: templateId },
                success: function(response) {
                    if (response.success) {
                        currentTemplate = response.data;
                        document.getElementById('template-title').textContent = response.data.name;
                        
                        // Convert database fields to frontend format
                        formFields = (response.data.fields || []).map(field => ({
                            id: 'field_' + field.id,
                            type: field.field_type,
                            name: field.field_name,
                            label: field.field_label,
                            placeholder: field.placeholder || '',
                            required: field.required,
                            options: field.options || [],
                            validation: field.validation_rules || {},
                            displayOrder: field.display_order
                        }));
                        
                        // Update field counter to avoid conflicts
                        if (formFields.length > 0) {
                            const maxId = Math.max(...formFields.map(f => parseInt(f.id.replace('field_', '')) || 0));
                            fieldCounter = maxId + 1;
                        }
                        
                        reRenderAllFields();
                        loadTemplates(); // Refresh to show active state
                    }
                },
                error: function() {
                    alert('កំហុសក្នុងការផ្ទុក Template');
                }
            });
        }
        
        function saveTemplate() {
            if (!currentTemplate) {
                alert('សូមបង្កើត ឬជ្រើសរើស Template មុននឹងរក្សាទុក');
                return;
            }
            
            // Delete existing fields
            $.ajax({
                url: 'form_builder_api.php',
                method: 'GET',
                data: { action: 'get_fields', template_id: currentTemplate.id },
                success: function(response) {
                    if (response.success) {
                        // Delete existing fields
                        response.data.forEach(field => {
                            $.ajax({
                                url: 'form_builder_api.php',
                                method: 'DELETE',
                                data: { action: 'delete_field', id: field.id }
                            });
                        });
                        
                        // Create new fields
                        let savedCount = 0;
                        formFields.forEach((field, index) => {
                            $.ajax({
                                url: 'form_builder_api.php',
                                method: 'POST',
                                data: {
                                    action: 'create_field',
                                    template_id: currentTemplate.id,
                                    field_type: field.type,
                                    field_name: field.name,
                                    field_label: field.label,
                                    placeholder: field.placeholder,
                                    required: field.required,
                                    display_order: index
                                },
                                success: function(fieldResponse) {
                                    if (fieldResponse.success) {
                                        savedCount++;
                                        if (savedCount === formFields.length) {
                                            alert('បានរក្សាទុក Template ដោយជោគជ័យ!');
                                        }
                                    }
                                }
                            });
                        });
                    }
                },
                error: function() {
                    alert('កំហុសក្នុងការរក្សាទុក');
                }
            });
        }
        
        function deleteTemplate() {
            if (!currentTemplate) {
                alert('សូមជ្រើសរើស Template ដែលត្រូវលុប');
                return;
            }
            
            if (confirm('តើអ្នកប្រាកដជាចង់លុប Template នេះ?')) {
                $.ajax({
                    url: 'form_builder_api.php',
                    method: 'DELETE',
                    data: { action: 'delete_template', id: currentTemplate.id },
                    success: function(response) {
                        if (response.success) {
                            currentTemplate = null;
                            formFields = [];
                            document.getElementById('template-title').textContent = 'ជ្រើសរើស Template ឬបង្កើតថ្មី';
                            showEmptyState();
                            loadTemplates();
                            alert('បានលុប Template ដោយជោគជ័យ!');
                        } else {
                            alert('កំហុស: ' + response.message);
                        }
                    },
                    error: function() {
                        alert('កំហុសក្នុងការលុប Template');
                    }
                });
            }
        }
        
        function previewForm() {
            if (formFields.length === 0) {
                alert('មិនមាន fields សម្រាប់មើលជាមុនទេ');
                return;
            }
            
            // Simple preview - in production, this would open a modal with the actual form
            alert('មុខងារ Preview នឹងបន្ថែមក្នុង version ដើម');
        }
    </script>
</body>
</html>
