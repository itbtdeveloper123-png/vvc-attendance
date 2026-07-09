<?php
mysqli_report(MYSQLI_REPORT_OFF);
require_once 'config.php';

$mysqli = @new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

echo "<h3>Columns in 'users' table:</h3>";
$res = $mysqli->query("SHOW COLUMNS FROM users");
if ($res) {
    while ($row = $res->fetch_assoc()) {
        echo $row['Field'] . " (" . $row['Type'] . ")<br/>";
    }
} else {
    echo "Query failed: " . $mysqli->error;
}
$mysqli->close();
?>
