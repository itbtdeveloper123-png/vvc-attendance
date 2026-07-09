<?php
mysqli_report(MYSQLI_REPORT_OFF);
require_once 'config.php';

$mysqli = @new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}
$mysqli->set_charset("utf8mb4");

echo "<h3>Login Query Diagnostic for '0168'</h3>";

$eid = '0168';
$sql = "SELECT employee_id, name, user_role, avatar,
               COALESCE(system_role, 'Employee') AS system_role,
               COALESCE(system_role_label, '') AS system_role_label,
               COALESCE(department, '') AS department,
               COALESCE(position, '') AS position,
               COALESCE(phone, '') AS phone,
               COALESCE(email, '') AS email,
               password,
               COALESCE(created_by_admin_id, '') AS created_by_admin_id,
               global_max_tokens,
               COALESCE(is_verified, 0) AS is_verified
        FROM users WHERE employee_id = ? LIMIT 1";

$stmt = $mysqli->prepare($sql);
if (!$stmt) {
    die("Prepare failed: " . $mysqli->error);
}

$stmt->bind_param("s", $eid);
$stmt->execute();
$res = $stmt->get_result();

if ($res) {
    $row = $res->fetch_assoc();
    if ($row) {
        echo "User found!<br/>";
        echo "<pre>";
        print_r($row);
        echo "</pre>";
    } else {
        echo "User NOT found in database query result.<br/>";
    }
} else {
    // If mysqlnd is missing, let's try store_result
    echo "get_result() failed, trying store_result/bind_result fallback:<br/>";
    $stmt->store_result();
    echo "Num rows: " . $stmt->num_rows . "<br/>";
    if ($stmt->num_rows > 0) {
        $stmt->bind_result(
            $b_eid, $b_name, $b_role, $b_avatar, 
            $b_sys_role, $b_sys_label, $b_dept, $b_pos, 
            $b_phone, $b_email, $b_pass, $b_creator, 
            $b_max, $b_verified
        );
        $stmt->fetch();
        $base = [
            'employee_id' => $b_eid, 'name' => $b_name, 'user_role' => $b_role, 'avatar' => $b_avatar,
            'system_role' => $b_sys_role, 'system_role_label' => $b_sys_label, 'department' => $b_dept, 'position' => $b_pos,
            'phone' => $b_phone, 'email' => $b_email, 'password' => $b_pass,
            'created_by_admin_id' => $b_creator, 'global_max_tokens' => $b_max, 'is_verified' => $b_verified
        ];
        echo "<pre>";
        print_r($base);
        echo "</pre>";
    } else {
        echo "User NOT found in fallback method.<br/>";
    }
}
$stmt->close();
$mysqli->close();
?>
