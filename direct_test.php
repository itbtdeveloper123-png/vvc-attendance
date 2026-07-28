<?php
// Minimal test file with different name to avoid any server-side caching
http_response_code(200);
header('Content-Type: application/json; charset=UTF-8');
echo json_encode([
    'success' => true, 
    'message' => 'Direct test working',
    'time' => date('Y-m-d H:i:s')
]);
exit;
?>