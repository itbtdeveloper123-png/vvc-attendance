<?php
require_once 'config.php';
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}
echo "Database Connected successfully to: " . DB_NAME . "<br/><br/>";

// 1. Query for employee_id '0168'
$id = '0168';
$stmt = $mysqli->prepare("SELECT employee_id, name, user_role, system_role FROM users WHERE employee_id = ?");
if ($stmt) {
    $stmt->bind_param("s", $id);
    $stmt->execute();
    $res = $stmt->get_result()->fetch_assoc();
    echo "Querying exact VARCHAR match for '0168':<br/>";
    print_r($res);
    echo "<br/><br/>";
    $stmt->close();
}

// 2. Query for employee_id as numeric 168
$id_num = 168;
$stmt = $mysqli->prepare("SELECT employee_id, name, user_role, system_role FROM users WHERE employee_id = ?");
if ($stmt) {
    $stmt->bind_param("i", $id_num);
    $stmt->execute();
    $res = $stmt->get_result()->fetch_assoc();
    echo "Querying numeric match for 168:<br/>";
    print_r($res);
    echo "<br/><br/>";
    $stmt->close();
}

// 3. Let's dump all users to see what's in the table
echo "Listing first 10 users in database:<br/>";
$res_all = $mysqli->query("SELECT employee_id, name, user_role, system_role FROM users LIMIT 10");
if ($res_all) {
    while ($row = $res_all->fetch_assoc()) {
        echo "ID: [" . $row['employee_id'] . "] - Name: " . $row['name'] . " - Role: " . $row['user_role'] . "<br/>";
    }
}
?>
