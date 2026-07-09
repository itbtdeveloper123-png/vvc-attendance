<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
mysqli_report(MYSQLI_REPORT_OFF);

echo "<h3>Testing connection to samann1_hrm_db:</h3>";

$conn = mysqli_connect('127.0.0.1', 'samann1_hrm_db', 'hrm_db!@#', 'samann1_hrm_db');
if (!$conn) {
    echo "Connection failed (127.0.0.1): " . mysqli_connect_error() . "<br/>";
    
    echo "Trying localhost...<br/>";
    $conn = mysqli_connect('localhost', 'samann1_hrm_db', 'hrm_db!@#', 'samann1_hrm_db');
}

if (!$conn) {
    echo "Connection failed (localhost): " . mysqli_connect_error() . "<br/>";
} else {
    echo "CONNECTED SUCCESSFULLY to samann1_hrm_db!<br/>";
    $res = mysqli_query($conn, "SHOW TABLES");
    if ($res) {
        echo "Tables in samann1_hrm_db:<br/>";
        $count = 0;
        while ($row = mysqli_fetch_row($res)) {
            echo "- " . $row[0] . "<br/>";
            $count++;
        }
        if ($count == 0) {
            echo "No tables found in database.<br/>";
        }
    } else {
        echo "Query failed: " . mysqli_error($conn) . "<br/>";
    }
    mysqli_close($conn);
}
?>
