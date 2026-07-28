<?php
// Step 1: Test basic PHP response
http_response_code(200);
header('Content-Type: application/json; charset=UTF-8');
echo json_encode(['success' => true, 'message' => 'Step 1 working']);
exit;
?>