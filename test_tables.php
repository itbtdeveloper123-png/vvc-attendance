<?php
mysqli_report(MYSQLI_REPORT_OFF);
require_once 'config.php';

$mysqli = @new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

echo "<h3>Tables in DB: " . DB_NAME . "</h3>";
$res = $mysqli->query("SHOW TABLES");
if ($res) {
    while ($row = $res->fetch_row()) {
        echo $row[0] . "<br/>";
    }
} else {
    echo "Query failed: " . $mysqli->error;
}
$mysqli->close();
?>
