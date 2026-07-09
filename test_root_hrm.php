<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h3>Testing Root connection to samann1_hrm_db:</h3>";

try {
    $mysqli = @new mysqli('localhost', 'root', '', 'samann1_hrm_db');
    if ($mysqli->connect_error) {
        echo "Root connection failed: " . $mysqli->connect_error . "<br/>";
    } else {
        echo "Root connected successfully to samann1_hrm_db!<br/>";
        $res = $mysqli->query("SHOW TABLES");
        if ($res) {
            echo "Tables in samann1_hrm_db:<br/>";
            $count = 0;
            while ($row = $res->fetch_row()) {
                echo "- " . $row[0] . "<br/>";
                $count++;
            }
            if ($count == 0) {
                echo "No tables found in samann1_hrm_db.<br/>";
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
