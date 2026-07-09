<?php
mysqli_report(MYSQLI_REPORT_OFF);
require_once 'config.php';

$mysqli = @new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

echo "<h3>Columns in 'users' table:</h3>";
$res = $mysqli->query("SELECT * FROM users LIMIT 1");
if ($res) {
    $row = $res->fetch_assoc();
    if ($row) {
        echo "<pre>";
        print_r(array_keys($row));
        echo "</pre>";
    } else {
        echo "No users found in table.";
    }
} else {
    echo "Query failed: " . $mysqli->error;
}
$mysqli->close();
?>
