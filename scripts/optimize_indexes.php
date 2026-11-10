<?php
/**
 * scripts/optimize_indexes.php
 * Automated Database Index Optimization Script for VVC-Attendance
 */
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../enterprise_helpers.php';

$mysqli = function_exists('get_unified_db_connection') ? get_unified_db_connection() : @new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if (!$mysqli || $mysqli->connect_error) {
    die("Database connection failed: " . ($mysqli ? $mysqli->connect_error : 'null') . "\n");
}

function safe_add_index($mysqli, $table, $indexName, $columns) {
    // Check if table exists
    $tCheck = $mysqli->query("SHOW TABLES LIKE '$table'");
    if (!$tCheck || $tCheck->num_rows === 0) {
        echo "[-] Table `$table` does not exist. Skipping index `$indexName`.\n";
        return;
    }
    $tCheck->close();

    // Check if index already exists
    $iCheck = $mysqli->query("SHOW INDEX FROM `$table` WHERE Key_name = '$indexName'");
    if ($iCheck && $iCheck->num_rows > 0) {
        $iCheck->close();
        echo "[=] Index `$indexName` on `$table` already exists.\n";
        return;
    }
    if ($iCheck && is_object($iCheck)) $iCheck->close();

    // Add index
    $sql = "ALTER TABLE `$table` ADD INDEX `$indexName` ($columns)";
    if ($mysqli->query($sql)) {
        echo "[+] Successfully created index `$indexName` on `$table` ($columns).\n";
    } else {
        echo "[!] Error creating index `$indexName` on `$table`: " . $mysqli->error . "\n";
    }
}

$indexes = [
    // 1. checkin_logs - Essential for Streak, Dashboard, History, Monthly & Daily attendance
    ['checkin_logs', 'idx_emp_datetime', 'employee_id, log_datetime'],
    ['checkin_logs', 'idx_datetime', 'log_datetime'],
    ['checkin_logs', 'idx_status', 'status'],
    ['checkin_logs', 'idx_action_type', 'action_type'],

    // 2. requests - Essential for pending badge & user history
    ['requests', 'idx_user_status', 'user_id, status'],
    ['requests', 'idx_requester_status', 'requester_name(64), status'],
    ['requests', 'idx_created_at', 'created_at'],

    // 3. active_tokens - Essential for token lookup & authentication on every request
    ['active_tokens', 'idx_auth_token', 'auth_token(64)'],
    ['active_tokens', 'idx_emp_id', 'employee_id'],
    ['active_tokens', 'idx_last_used', 'last_used'],

    // 4. attendance_rules - Essential for check-in rules validation
    ['attendance_rules', 'idx_emp_type_status', 'employee_id, type, status'],

    // 5. announcements - Essential for dashboard ordering
    ['announcements', 'idx_admin_active', 'admin_id, is_active'],

    // 6. user_notifications - Essential for unread notification count
    ['user_notifications', 'idx_emp_read', 'employee_id, is_read'],

    // 7. audit_logs - Essential for security audit log filtering
    ['audit_logs', 'idx_actor_action', 'actor_id, action'],
    ['audit_logs', 'idx_created_at', 'created_at'],

    // 8. employee_face_data - Face ID registration
    ['employee_face_data', 'idx_emp_face', 'employee_id'],

    // 9. employee_trips & trip_locations - GPS trip tracking
    ['employee_trips', 'idx_emp_status', 'employee_id, status'],
    ['trip_locations', 'idx_trip_recorded', 'trip_id, recorded_at'],
];

echo "=== VVC ATTENDANCE DATABASE INDEX OPTIMIZATION ===\n";
foreach ($indexes as $item) {
    safe_add_index($mysqli, $item[0], $item[1], $item[2]);
}
echo "=== OPTIMIZATION COMPLETE ===\n";

