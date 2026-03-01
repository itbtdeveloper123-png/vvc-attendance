<?php
header('Content-Type: application/json');
require 'config.php';

$input = json_decode(file_get_contents('php://input'), true);

if (!$input || !isset($input['endpoint'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid subscription data']);
    exit;
}

$conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

$endpoint = $conn->real_escape_string($input['endpoint']);
$p256dh = $conn->real_escape_string($input['keys']['p256dh']);
$auth = $conn->real_escape_string($input['keys']['auth']);
$user_id = isset($input['user_id']) ? $conn->real_escape_string($input['user_id']) : null;

// Check if subscription already exists
$checkSql = "SELECT id FROM push_subscriptions WHERE endpoint = '$endpoint'";
$result = $conn->query($checkSql);

if ($result->num_rows > 0) {
    // Update existing subscription
    $sql = "UPDATE push_subscriptions SET p256dh = '$p256dh', auth = '$auth', user_id = '$user_id' WHERE endpoint = '$endpoint'";
} else {
    // Save new subscription
    $sql = "INSERT INTO push_subscriptions (endpoint, p256dh, auth, user_id) VALUES ('$endpoint', '$p256dh', '$auth', '$user_id')";
}

if ($conn->query($sql) === TRUE) {
    echo json_encode(['success' => true]);
} else {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to save subscription: ' . $conn->error]);
}

$conn->close();
?>
