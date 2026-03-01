<?php
require 'config.php';
$conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);

$conn->query("DROP TABLE IF EXISTS push_subscriptions");
$sql = "CREATE TABLE push_subscriptions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id VARCHAR(64) NOT NULL,
    endpoint TEXT NOT NULL,
    p256dh VARCHAR(255) NOT NULL,
    auth VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY (endpoint(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

if ($conn->query($sql) === TRUE) {
    echo "Table push_subscriptions recreated correctly.\n";
} else {
    echo "Error: " . $conn->error . "\n";
}
$conn->close();
?>
