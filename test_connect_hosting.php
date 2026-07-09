<?php
mysqli_report(MYSQLI_REPORT_OFF);
echo "<h3>Testing hosting credentials on samann1_attendance_db:</h3>";

$mysqli = @new mysqli('localhost', 'samann1_hrm_db', 'hrm_db!@#', 'samann1_attendance_db');
if ($mysqli->connect_error) {
    echo "Connection failed: " . $mysqli->connect_error;
} else {
    echo "CONNECTED SUCCESSFULLY to samann1_attendance_db using samann1_hrm_db credentials!";
    $mysqli->close();
}
?>
