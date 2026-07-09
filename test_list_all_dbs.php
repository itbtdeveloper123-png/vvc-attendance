<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h3>Listing all MySQL Databases:</h3>";

try {
    $mysqli = @new mysqli('localhost', 'root', '', '');
    if ($mysqli->connect_error) {
        echo "Connection to server failed: " . $mysqli->connect_error . "<br/>";
    } else {
        echo "Connected successfully to MySQL server!<br/>";
        $res = $mysqli->query("SHOW DATABASES");
        if ($res) {
            echo "Databases found:<br/>";
            while ($row = $res->fetch_row()) {
                echo "- " . $row[0] . "<br/>";
            }
        } else {
            echo "Query failed: " . $mysqli->error . "<br/>";
        }
        $mysqli->close();
    }
} catch (Throwable $e) {
    echo "Exception: " . $e->getMessage() . "<br/>";
}
?>
