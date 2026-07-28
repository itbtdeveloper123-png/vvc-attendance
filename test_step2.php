<?php
// Step 2: Test config.php loading
http_response_code(200);
header('Content-Type: application/json; charset=UTF-8');

try {
    require_once __DIR__ . '/config.php';
    echo json_encode(['success' => true, 'message' => 'Step 2 working - config loaded']);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Step 2 failed: ' . $e->getMessage()]);
}
exit;
?>