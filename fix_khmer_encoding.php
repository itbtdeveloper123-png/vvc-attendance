<?php
// Fix Khmer Text Encoding for Form Builder Templates
// This script will fix UTF-8 encoding issues in the database

header('Content-Type: text/html; charset=UTF-8');
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/config.php';

try {
    // Check database connection
    $mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    
    if ($mysqli->connect_error) {
        die('Database connection failed: ' . $mysqli->connect_error);
    }
    
    $mysqli->set_charset("utf8mb4");
    
    echo "<h2>Fix Khmer Text Encoding</h2>";
    echo "<p>Starting encoding fix process...</p>";
    
    // 1. Fix database charset
    echo "<h3>1. Fixing database charset...</h3>";
    $mysqli->query("ALTER DATABASE " . DB_NAME . " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    echo "<p>✅ Database charset updated to utf8mb4</p>";
    
    // 2. Fix form_templates table
    echo "<h3>2. Fixing form_templates table...</h3>";
    $mysqli->query("ALTER TABLE form_templates CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    echo "<p>✅ form_templates table charset updated</p>";
    
    // 3. Fix form_fields table
    echo "<h3>3. Fixing form_fields table...</h3>";
    $mysqli->query("ALTER TABLE form_fields CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    echo "<p>✅ form_fields table charset updated</p>";
    
    // 4. Fix form_submissions table
    echo "<h3>4. Fixing form_submissions table...</h3>";
    $mysqli->query("ALTER TABLE form_submissions CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    echo "<p>✅ form_submissions table charset updated</p>";
    
    // 5. Fix existing corrupted data (Template #6)
    echo "<h3>5. Fixing existing corrupted data...</h3>";
    
    // Fix Template #6 - Leave Request
    $update_stmt = $mysqli->prepare("UPDATE form_templates SET name = ?, description = ? WHERE id = 6");
    $update_stmt->bind_param('ss', 
        'សំណើសុំច្បាប់ឈប់សម្រាក (Leave Request)',
        'សំណើសុំច្បាប់ឈប់សម្រាកសម្រាប់បុគ្គលិក, ជំងឺ, ការធ្វើដំណើរ'
    );
    $update_stmt->execute();
    echo "<p>✅ Template #6 fixed</p>";
    
    // Check current data
    echo "<h3>6. Current data status:</h3>";
    $result = $mysqli->query("SELECT id, name FROM form_templates ORDER BY id");
    echo "<table border='1' style='border-collapse: collapse; margin: 20px 0;'>";
    echo "<tr><th>ID</th><th>Name</th></tr>";
    while ($row = $result->fetch_assoc()) {
        echo "<tr><td>" . $row['id'] . "</td><td>" . htmlspecialchars($row['name']) . "</td></tr>";
    }
    echo "</table>";
    
    echo "<h3>✅ Encoding fix completed successfully!</h3>";
    echo "<p><a href='form_builder.php'>Go to Form Builder</a></p>";
    
} catch (Exception $e) {
    echo "<p style='color: red;'>Error: " . $e->getMessage() . "</p>";
}
?>