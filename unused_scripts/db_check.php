<?php
require_once 'admin_attendance.php'; // To get DB connection
$res = $mysqli->query("SELECT * FROM push_subscriptions");
echo "Total subscriptions: " . $res->num_rows . "\n";
while($row = $res->fetch_assoc()){
    echo "ID: " . $row['id'] . " | EmpID: " . $row['employee_id'] . "\n";
}
