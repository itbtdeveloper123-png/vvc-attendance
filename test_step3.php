<?php
// Step 3: Test database connection
http_response_code(200);
header('Content-Type: application/json; charset=UTF-8');

try {
    require_once __DIR__ . '/config.php';
    $mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if ($mysqli->connect_error) {
        echo json_encode(['success' => false, 'message' => 'DB connection failed: ' . $mysqli->connect_error]);
    } else {
        echo json_encode(['success' => true, 'message' => 'Step 3 working - DB connected']);
        $mysqli->close();
    }
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Step 3 failed: ' . $e->getMessage()]);
}
exit;
?>