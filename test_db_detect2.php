<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
mysqli_report(MYSQLI_REPORT_OFF);

$dbs = ['samann1_attendance_db', 'samann1_hrm_db'];
foreach ($dbs as $db) {
    echo "<h3>Testing $db</h3>";
    $m = new mysqli('127.0.0.1', 'samann1_hrm_db', 'hrm_db!@#', $db);
    if ($m->connect_error) {
        $m = new mysqli('localhost', 'samann1_hrm_db', 'hrm_db!@#', $db);
    }
    if ($m->connect_error) {
        $m = new mysqli('localhost', 'root', '', $db);
    }
    if ($m->connect_error) {
        echo "Connect error: " . $m->connect_error . "<br/>";
        continue;
    }
    echo "Connected successfully to $db!<br/>";
    $m->set_charset("utf8mb4");
    $r = $m->query("SELECT name FROM users WHERE employee_id='0168'");
    if ($r) {
        $row = $r->fetch_assoc();
        if ($row) {
            echo "User 0168 found! Name: " . $row['name'] . "<br/>";
        } else {
            echo "User 0168 NOT found in users table.<br/>";
        }
    } else {
        echo "Query error: " . $m->error . "<br/>";
    }
    $m->close();
}
?>
