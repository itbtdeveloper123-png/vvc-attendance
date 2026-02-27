<?php
$mysqli = new mysqli('localhost', 'samann1_attendance_db', 'attendance@2025', 'samann1_attendance_db');
$sql = "CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INT AUTO_INCREMENT PRIMARY KEY, 
    employee_id VARCHAR(50) NOT NULL, 
    endpoint TEXT NOT NULL, 
    p256dh VARCHAR(255) NOT NULL, 
    auth VARCHAR(255) NOT NULL, 
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
    UNIQUE KEY (endpoint(255))
)";
if ($mysqli->query($sql)) {
    echo "Table created successfully\n";
} else {
    echo "Error: " . $mysqli->error . "\n";
}
