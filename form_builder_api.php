<?php
// Form Builder API
// This file handles all form builder related API operations

header('Content-Type: application/json; charset=UTF-8');
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('error_log', __DIR__ . '/php_debug.log');

require_once __DIR__ . '/config.php';

// Set CORS headers
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Get database connection
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

if ($mysqli->connect_error) {
    echo json_encode(['success' => false, 'message' => 'Database connection failed: ' . $mysqli->connect_error]);
    error_log('Form Builder API: Database connection failed - ' . $mysqli->connect_error);
    exit;
}

$mysqli->set_charset("utf8mb4");

// Check if required tables exist
$required_tables = ['form_templates', 'form_fields', 'form_submissions'];
foreach ($required_tables as $table) {
    $result = $mysqli->query("SHOW TABLES LIKE '$table'");
    if (!$result || $result->num_rows == 0) {
        echo json_encode(['success' => false, 'message' => "Required table '$table' does not exist"]);
        error_log("Form Builder API: Missing table '$table'");
        exit;
    }
}

// Helper function to send JSON response
function sendResponse($success, $message, $data = null) {
    $response = [
        'success' => $success,
        'message' => $message
    ];
    if ($data !== null) {
        $response['data'] = $data;
    }
    echo json_encode($response);
    exit;
}

// Get request method and action
$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        case 'get_templates':
            handleGetTemplates($mysqli);
            break;
        case 'get_template':
            handleGetTemplate($mysqli);
            break;
        case 'create_template':
            handleCreateTemplate($mysqli);
            break;
        case 'update_template':
            handleUpdateTemplate($mysqli);
            break;
        case 'delete_template':
            handleDeleteTemplate($mysqli);
            break;
        case 'get_fields':
            handleGetFields($mysqli);
            break;
        case 'create_field':
            handleCreateField($mysqli);
            break;
        case 'update_field':
            handleUpdateField($mysqli);
            break;
        case 'delete_field':
            handleDeleteField($mysqli);
            break;
        case 'reorder_fields':
            handleReorderFields($mysqli);
            break;
        case 'get_submissions':
            handleGetSubmissions($mysqli);
            break;
        case 'create_submission':
            handleCreateSubmission($mysqli);
            break;
        case 'update_submission_status':
            handleUpdateSubmissionStatus($mysqli);
            break;
        default:
            sendResponse(false, 'Invalid action');
    }
} catch (Exception $e) {
    sendResponse(false, 'Server error: ' . $e->getMessage());
}

// Handle GET /api/form_builder?action=get_templates
function handleGetTemplates($mysqli) {
    try {
        $category = $_GET['category'] ?? null;
        $status = $_GET['status'] ?? 'active';
        
        $sql = "SELECT id, name, description, category, status, created_by, created_at, updated_at 
                FROM form_templates 
                WHERE status = ?";
        $params = [$status];
        $types = 's';
        
        if ($category) {
            $sql .= " AND category = ?";
            $params[] = $category;
            $types .= 's';
        }
        
        $sql .= " ORDER BY created_at DESC";
        
        $stmt = $mysqli->prepare($sql);
        if (!$stmt) {
            throw new Exception("Failed to prepare statement: " . $mysqli->error);
        }
        
        $stmt->bind_param($types, ...$params);
        if (!$stmt->execute()) {
            throw new Exception("Failed to execute statement: " . $stmt->error);
        }
        
        $result = $stmt->get_result();
        
        $templates = [];
        while ($row = $result->fetch_assoc()) {
            $templates[] = $row;
        }
        
        $stmt->close();
        sendResponse(true, 'Templates retrieved successfully', $templates);
    } catch (Exception $e) {
        error_log('Form Builder API: Error in handleGetTemplates - ' . $e->getMessage());
        sendResponse(false, 'Error retrieving templates: ' . $e->getMessage());
    }
}

// Handle GET /api/form_builder?action=get_template&id=X
function handleGetTemplate($mysqli) {
    $id = $_GET['id'] ?? null;
    if (!$id) {
        sendResponse(false, 'Template ID is required');
    }
    
    // Get template details
    $stmt = $mysqli->prepare("SELECT * FROM form_templates WHERE id = ?");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $template = $result->fetch_assoc();
    
    if (!$template) {
        sendResponse(false, 'Template not found');
    }
    
    // Get template fields
    $stmt = $mysqli->prepare("SELECT * FROM form_fields WHERE template_id = ? ORDER BY display_order ASC");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $fields = [];
    while ($row = $result->fetch_assoc()) {
        // Parse JSON fields
        if ($row['options']) {
            $row['options'] = json_decode($row['options'], true);
        }
        if ($row['validation_rules']) {
            $row['validation_rules'] = json_decode($row['validation_rules'], true);
        }
        $fields[] = $row;
    }
    
    $template['fields'] = $fields;
    sendResponse(true, 'Template retrieved successfully', $template);
}

// Handle POST /api/form_builder?action=create_template
function handleCreateTemplate($mysqli) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $name = $data['name'] ?? null;
    $description = $data['description'] ?? '';
    $category = $data['category'] ?? 'request';
    $status = $data['status'] ?? 'active';
    $created_by = $_SESSION['admin_id'] ?? null;
    
    if (!$name) {
        sendResponse(false, 'Template name is required');
    }
    
    $stmt = $mysqli->prepare("INSERT INTO form_templates (name, description, category, status, created_by) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param('ssssi', $name, $description, $category, $status, $created_by);
    
    if ($stmt->execute()) {
        $template_id = $mysqli->insert_id;
        sendResponse(true, 'Template created successfully', ['id' => $template_id]);
    } else {
        throw new Exception("Failed to create template: " . $mysqli->error);
    }
}

// Handle PUT /api/form_builder?action=update_template
function handleUpdateTemplate($mysqli) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $id = $data['id'] ?? null;
    $name = $data['name'] ?? null;
    $description = $data['description'] ?? null;
    $category = $data['category'] ?? null;
    $status = $data['status'] ?? null;
    
    if (!$id) {
        sendResponse(false, 'Template ID is required');
    }
    
    $updates = [];
    $params = [];
    $types = '';
    
    if ($name) {
        $updates[] = "name = ?";
        $params[] = $name;
        $types .= 's';
    }
    if ($description !== null) {
        $updates[] = "description = ?";
        $params[] = $description;
        $types .= 's';
    }
    if ($category) {
        $updates[] = "category = ?";
        $params[] = $category;
        $types .= 's';
    }
    if ($status) {
        $updates[] = "status = ?";
        $params[] = $status;
        $types .= 's';
    }
    
    if (empty($updates)) {
        sendResponse(false, 'No fields to update');
    }
    
    $params[] = $id;
    $types .= 'i';
    
    $sql = "UPDATE form_templates SET " . implode(', ', $updates) . " WHERE id = ?";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param($types, ...$params);
    
    if ($stmt->execute()) {
        sendResponse(true, 'Template updated successfully');
    } else {
        throw new Exception("Failed to update template: " . $mysqli->error);
    }
}

// Handle DELETE /api/form_builder?action=delete_template
function handleDeleteTemplate($mysqli) {
    $id = $_GET['id'] ?? null;
    if (!$id) {
        sendResponse(false, 'Template ID is required');
    }
    
    $stmt = $mysqli->prepare("DELETE FROM form_templates WHERE id = ?");
    $stmt->bind_param('i', $id);
    
    if ($stmt->execute()) {
        sendResponse(true, 'Template deleted successfully');
    } else {
        throw new Exception("Failed to delete template: " . $mysqli->error);
    }
}

// Handle GET /api/form_builder?action=get_fields&template_id=X
function handleGetFields($mysqli) {
    $template_id = $_GET['template_id'] ?? null;
    if (!$template_id) {
        sendResponse(false, 'Template ID is required');
    }
    
    $stmt = $mysqli->prepare("SELECT * FROM form_fields WHERE template_id = ? ORDER BY display_order ASC");
    $stmt->bind_param('i', $template_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $fields = [];
    while ($row = $result->fetch_assoc()) {
        if ($row['options']) {
            $row['options'] = json_decode($row['options'], true);
        }
        if ($row['validation_rules']) {
            $row['validation_rules'] = json_decode($row['validation_rules'], true);
        }
        $fields[] = $row;
    }
    
    sendResponse(true, 'Fields retrieved successfully', $fields);
}

// Handle POST /api/form_builder?action=create_field
function handleCreateField($mysqli) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $template_id = $data['template_id'] ?? null;
    $field_type = $data['field_type'] ?? null;
    $field_name = $data['field_name'] ?? null;
    $field_label = $data['field_label'] ?? null;
    $placeholder = $data['placeholder'] ?? '';
    $required = $data['required'] ?? false;
    $options = $data['options'] ?? null;
    $validation_rules = $data['validation_rules'] ?? null;
    $display_order = $data['display_order'] ?? 0;
    
    if (!$template_id || !$field_type || !$field_name || !$field_label) {
        sendResponse(false, 'Missing required fields');
    }
    
    // Validate field type (allow time type now)
    $valid_types = ['text', 'number', 'email', 'date', 'time', 'select', 'textarea', 'checkbox', 'file', 'signature', 'branch', 'department', 'position'];
    if (!in_array($field_type, $valid_types)) {
        sendResponse(false, 'Invalid field type: ' . $field_type);
    }
    
    $options_json = $options ? json_encode($options) : null;
    $validation_json = $validation_rules ? json_encode($validation_rules) : null;
    
    $stmt = $mysqli->prepare("INSERT INTO form_fields (template_id, field_type, field_name, field_label, placeholder, required, options, validation_rules, display_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param('issssisii', $template_id, $field_type, $field_name, $field_label, $placeholder, $required, $options_json, $validation_json, $display_order);
    
    if ($stmt->execute()) {
        $field_id = $mysqli->insert_id;
        sendResponse(true, 'Field created successfully', ['id' => $field_id]);
    } else {
        throw new Exception("Failed to create field: " . $mysqli->error);
    }
}

// Handle PUT /api/form_builder?action=update_field
function handleUpdateField($mysqli) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $id = $data['id'] ?? null;
    $field_type = $data['field_type'] ?? null;
    $field_name = $data['field_name'] ?? null;
    $field_label = $data['field_label'] ?? null;
    $placeholder = $data['placeholder'] ?? null;
    $required = $data['required'] ?? null;
    $options = $data['options'] ?? null;
    $validation_rules = $data['validation_rules'] ?? null;
    $display_order = $data['display_order'] ?? null;
    
    if (!$id) {
        sendResponse(false, 'Field ID is required');
    }
    
    $updates = [];
    $params = [];
    $types = '';
    
    if ($field_type) {
        $updates[] = "field_type = ?";
        $params[] = $field_type;
        $types .= 's';
    }
    if ($field_name) {
        $updates[] = "field_name = ?";
        $params[] = $field_name;
        $types .= 's';
    }
    if ($field_label) {
        $updates[] = "field_label = ?";
        $params[] = $field_label;
        $types .= 's';
    }
    if ($placeholder !== null) {
        $updates[] = "placeholder = ?";
        $params[] = $placeholder;
        $types .= 's';
    }
    if ($required !== null) {
        $updates[] = "required = ?";
        $params[] = $required;
        $types .= 'i';
    }
    if ($options !== null) {
        $updates[] = "options = ?";
        $params[] = json_encode($options);
        $types .= 's';
    }
    if ($validation_rules !== null) {
        $updates[] = "validation_rules = ?";
        $params[] = json_encode($validation_rules);
        $types .= 's';
    }
    if ($display_order !== null) {
        $updates[] = "display_order = ?";
        $params[] = $display_order;
        $types .= 'i';
    }
    
    if (empty($updates)) {
        sendResponse(false, 'No fields to update');
    }
    
    $params[] = $id;
    $types .= 'i';
    
    $sql = "UPDATE form_fields SET " . implode(', ', $updates) . " WHERE id = ?";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param($types, ...$params);
    
    if ($stmt->execute()) {
        sendResponse(true, 'Field updated successfully');
    } else {
        throw new Exception("Failed to update field: " . $mysqli->error);
    }
}

// Handle DELETE /api/form_builder?action=delete_field
function handleDeleteField($mysqli) {
    $id = $_GET['id'] ?? null;
    if (!$id) {
        sendResponse(false, 'Field ID is required');
    }
    
    $stmt = $mysqli->prepare("DELETE FROM form_fields WHERE id = ?");
    $stmt->bind_param('i', $id);
    
    if ($stmt->execute()) {
        sendResponse(true, 'Field deleted successfully');
    } else {
        throw new Exception("Failed to delete field: " . $mysqli->error);
    }
}

// Handle POST /api/form_builder?action=reorder_fields
function handleReorderFields($mysqli) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $template_id = $data['template_id'] ?? null;
    $field_orders = $data['field_orders'] ?? []; // Array of ['id' => X, 'display_order' => Y]
    
    if (!$template_id || empty($field_orders)) {
        sendResponse(false, 'Template ID and field orders are required');
    }
    
    $mysqli->begin_transaction();
    
    try {
        foreach ($field_orders as $order) {
            $field_id = $order['id'] ?? null;
            $display_order = $order['display_order'] ?? null;
            
            if ($field_id && $display_order !== null) {
                $stmt = $mysqli->prepare("UPDATE form_fields SET display_order = ? WHERE id = ? AND template_id = ?");
                $stmt->bind_param('iii', $display_order, $field_id, $template_id);
                $stmt->execute();
            }
        }
        
        $mysqli->commit();
        sendResponse(true, 'Fields reordered successfully');
    } catch (Exception $e) {
        $mysqli->rollback();
        throw $e;
    }
}

// Handle GET /api/form_builder?action=get_submissions
function handleGetSubmissions($mysqli) {
    $template_id = $_GET['template_id'] ?? null;
    $status = $_GET['status'] ?? null;
    $limit = $_GET['limit'] ?? 50;
    
    $sql = "SELECT fs.*, ft.name as template_name, ft.category 
            FROM form_submissions fs
            JOIN form_templates ft ON fs.template_id = ft.id
            WHERE 1=1";
    $params = [];
    $types = '';
    
    if ($template_id) {
        $sql .= " AND fs.template_id = ?";
        $params[] = $template_id;
        $types .= 'i';
    }
    
    if ($status) {
        $sql .= " AND fs.status = ?";
        $params[] = $status;
        $types .= 's';
    }
    
    $sql .= " ORDER BY fs.submitted_at DESC LIMIT ?";
    $params[] = $limit;
    $types .= 'i';
    
    $stmt = $mysqli->prepare($sql);
    if (!$stmt) {
        throw new Exception("Failed to prepare statement: " . $mysqli->error);
    }
    
    $stmt->bind_param($types, ...$params);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $submissions = [];
    while ($row = $result->fetch_assoc()) {
        if ($row['submission_data']) {
            $row['submission_data'] = json_decode($row['submission_data'], true);
        }
        $submissions[] = $row;
    }
    
    sendResponse(true, 'Submissions retrieved successfully', $submissions);
}

// Handle POST /api/form_builder?action=create_submission
function handleCreateSubmission($mysqli) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $template_id = $data['template_id'] ?? null;
    $user_id = $data['user_id'] ?? null;
    $submission_data = $data['submission_data'] ?? null;
    
    if (!$template_id || !$submission_data) {
        sendResponse(false, 'Template ID and submission data are required');
    }
    
    $submission_json = json_encode($submission_data);
    
    $stmt = $mysqli->prepare("INSERT INTO form_submissions (template_id, user_id, submission_data) VALUES (?, ?, ?)");
    $stmt->bind_param('iis', $template_id, $user_id, $submission_json);
    
    if ($stmt->execute()) {
        $submission_id = $mysqli->insert_id;
        sendResponse(true, 'Submission created successfully', ['id' => $submission_id]);
    } else {
        throw new Exception("Failed to create submission: " . $mysqli->error);
    }
}

// Handle PUT /api/form_builder?action=update_submission_status
function handleUpdateSubmissionStatus($mysqli) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $id = $data['id'] ?? null;
    $status = $data['status'] ?? null;
    $reviewed_by = $_SESSION['admin_id'] ?? null;
    $review_notes = $data['review_notes'] ?? null;
    
    if (!$id || !$status) {
        sendResponse(false, 'Submission ID and status are required');
    }
    
    $stmt = $mysqli->prepare("UPDATE form_submissions SET status = ?, reviewed_by = ?, reviewed_at = NOW(), review_notes = ? WHERE id = ?");
    $stmt->bind_param('sisi', $status, $reviewed_by, $review_notes, $id);
    
    if ($stmt->execute()) {
        sendResponse(true, 'Submission status updated successfully');
    } else {
        throw new Exception("Failed to update submission status: " . $mysqli->error);
    }
}
