<?php
// Minimal version of api.php to identify the exact issue
http_response_code(200);
header('Content-Type: application/json; charset=UTF-8');

// Check if action parameter is being received
$actionSource = $_POST['action'] ?? $_GET['action'] ?? $_POST['ajax_action'] ?? $_GET['ajax_action'] ?? '';
$action = strtolower(trim($actionSource));

echo json_encode([
    'success' => true, 
    'message' => 'Minimal API working',
    'action_received' => $action,
    'action_source' => $actionSource,
    'post_vars' => $_POST,
    'get_vars' => $_GET,
    'server_method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown'
]);
exit;
?>