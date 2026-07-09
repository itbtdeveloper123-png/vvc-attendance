<?php
mysqli_report(MYSQLI_REPORT_OFF);

// Test connection to both databases
$databases = ['samann1_attendance_db', 'samann1_hrm_db'];
foreach ($databases as $db) {
    echo "<h3>Testing database: $db</h3>";
    $mysqli = @new mysqli('localhost', 'samann1_hrm_db', 'hrm_db!@#', $db);
    if ($mysqli->connect_error) {
        $mysqli = @new mysqli('localhost', 'root', '', $db);
    }
    if ($mysqli->connect_error) {
        echo "Failed to connect to $db: " . $mysqli->connect_error . "<br/>";
        continue;
    }
    echo "Connected successfully!<br/>";
    
    // Set charset
    $mysqli->set_charset("utf8mb4");
    
    $res = $mysqli->query("SELECT employee_id, name, user_role, system_role FROM users WHERE employee_id = '0168'");
    if ($res && $row = $res->fetch_assoc()) {
        echo "Found user 0168:<br/>";
        echo "ID: " . $row['employee_id'] . "<br/>";
        echo "Name: " . $row['name'] . "<br/>";
        echo "Role: " . $row['user_role'] . "<br/>";
    } else {
        echo "User 0168 NOT found in this database.<br/>";
    }
    
    $mysqli->close();
}
?>
