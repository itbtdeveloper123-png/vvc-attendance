<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h3>Database Tables Diagnostic:</h3>";

try {
    $mysqli = @new mysqli('localhost', 'root', '', 'samann1_attendance_db');
    if ($mysqli->connect_error) {
        echo "Failed to connect to samann1_attendance_db: " . $mysqli->connect_error . "<br/>";
    } else {
        echo "Connected to samann1_attendance_db successfully!<br/>";
        $res = $mysqli->query("SHOW TABLES");
        if ($res) {
            echo "Tables in samann1_attendance_db:<br/>";
            while ($row = $res->fetch_row()) {
                echo "- " . $row[0] . "<br/>";
            }
        }
        $mysqli->close();
    }
} catch (Throwable $e) {
    echo "samann1_attendance_db Exception: " . $e->getMessage() . "<br/>";
}

echo "<hr/>";

try {
    $mysqli = @new mysqli('localhost', 'root', '', 'samann1_hrm_db');
    if ($mysqli->connect_error) {
        echo "Failed to connect to samann1_hrm_db: " . $mysqli->connect_error . "<br/>";
    } else {
        echo "Connected to samann1_hrm_db successfully!<br/>";
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
        }
        $mysqli->close();
    }
} catch (Throwable $e) {
    echo "samann1_hrm_db Exception: " . $e->getMessage() . "<br/>";
}
?>
