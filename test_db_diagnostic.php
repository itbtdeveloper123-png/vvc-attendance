<?php
mysqli_report(MYSQLI_REPORT_OFF);
require_once 'config.php';

$mysqli = @new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}
echo "Database Connected successfully to: " . DB_NAME . "<br/><br/>";

// 1. Check and add global_max_tokens if missing
$res = $mysqli->query("SHOW COLUMNS FROM users LIKE 'global_max_tokens'");
if ($res && $res->num_rows > 0) {
    echo "Column 'global_max_tokens' exists.<br/>";
} else {
    echo "Column 'global_max_tokens' is MISSING! Adding it now...<br/>";
    $ok = $mysqli->query("ALTER TABLE users ADD COLUMN global_max_tokens INT DEFAULT 1");
    echo $ok ? "Successfully added 'global_max_tokens'!<br/>" : "Failed to add column: " . $mysqli->error . "<br/>";
}

// 2. Check and add system_role_label if missing
$res = $mysqli->query("SHOW COLUMNS FROM users LIKE 'system_role_label'");
if ($res && $res->num_rows > 0) {
    echo "Column 'system_role_label' exists.<br/>";
} else {
    echo "Column 'system_role_label' is MISSING! Adding it now...<br/>";
    $ok = $mysqli->query("ALTER TABLE users ADD COLUMN system_role_label VARCHAR(100) DEFAULT NULL");
    echo $ok ? "Successfully added 'system_role_label'!<br/>" : "Failed to add column: " . $mysqli->error . "<br/>";
}

// 3. Query for employee_id '0168'
$id = '0168';
$stmt = $mysqli->prepare("SELECT employee_id, name, user_role, system_role FROM users WHERE employee_id = ?");
if ($stmt) {
    $stmt->bind_param("s", $id);
    $stmt->execute();
    $res = $stmt->get_result()->fetch_assoc();
    echo "<br/>Querying user '0168' after column check:<br/><pre>";
    print_r($res);
    echo "</pre>";
    $stmt->close();
}

$mysqli->close();
?>
